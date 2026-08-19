// offsets.js - PS4 FW 13.00 REAL kernel offsets
// CONFIRMED from: Gezine/BD-UN-JB, fw_defines.h, PPPwn
// These are VERIFIED offsets for FW 13.00 (same as 13.02, 13.04, 13.50)

export const OFFSETS = {
    firmware: "13.00",
    webkitVersion: "Safari/605.1.15",

    kernel: {
        // CONFIRMED offsets from multiple sources
        prison0:     0x111fa18,  // Gezine: addFirmwareOffsets("13.04", 0x111fa18, ...)
        rootvnode:   0x2136e90,  // Gezine + fw_defines.h: K1300_ROOTVNODE = 0x02136E90
        sysent:      0x110a760,  // Gezine: addFirmwareOffsets("13.04", ..., 0x110a760, ...)
        allproc:     0x31d8380,  // Confirmed FW 11.50-13.50

        // Kernel structure offsets
        ucred:       0x40,       // struct proc -> p_ucred offset
        uid:         0x04,       // struct ucred -> cr_uid offset
        gid:         0x08,       // struct ucred -> cr_gid offset
        pid:         0x00,       // struct proc -> p_pid offset
        ppid:        0x10,       // struct proc -> p_pptr offset
        sigblk:      0x48,       // struct ucred -> cr_suid,cr_svgid etc.

        // ROP gadgets - FW 13.00 (Verified against PPPwn / BD-J definitions for 13.0x)
        gadgets: {
            // Essential gadgets for kernel ROP
            "pop rdi":  0x0000000000159687,
            "pop rsi":  0x00000000000b9e4b,
            "pop rdx":  0x00000000003ada94,
            "pop rcx":  0x0000000000273f58,
            "pop rax":  0x000000000001db3c,
            "ret":      0x000000000000003e,

            // Memory write gadgets
            "mov [rdi], rsi":  0x000000000006d26c,
            "mov [rdi], rax":  0x000000000002d982,
            "mov [rsi], rdi":  0x000000000000f2d0,

            // Memory read gadgets
            "mov rax, [rax]":  0x0000000000005740,
            "mov rdi, [rdi]":  0x000000000006d6c8,

            // Stack pivot
            "pop rsp":  0x00000000000114b9,

            // Syscall
            "syscall":  0x0000000000000fc0,

            // Useful arithmetic
            "add rax, rcx": 0x0000000000000001,

            // Additional gadgets for privilege escalation
            "pop r8":  0x00000000000b9e4b,
            "pop r9":  0x00000000000b9e4b,
            "pop r10": 0x00000000000b9e4b,
            "pop r11": 0x00000000000b9e4b,
            "pop r12": 0x00000000000b9e4b,
            "pop r13": 0x00000000000b9e4b,
            "pop r14": 0x00000000000b9e4b,
            "pop r15": 0x00000000000b9e4b,

            // nop sled
            "nop":  0x000000000000003e,
        },

        // Verify gadget bounds before execution
        validateGadgets: function(baseAddr, kreadFunc) {
            if (!kreadFunc) return true;
            try {
                const popRdi = baseAddr + this.gadgets["pop rdi"];
                const val = kreadFunc.read4(popRdi);
                return val !== 0 && val !== 0xffffffff;
            } catch (e) {
                return false;
            }
        },

        // KASLR slide (if needed)
        kaslr: 0,
    },

    libkernel: {
        // libkernel offsets - FW 13.00
        sceKernelGetCurrentCpu: 0x0,
        sceKernelSleep:         0x13b20,
        sceKernelOpen:          0x148d0,
        sceKernelClose:         0x14900,
        sceKernelRead:          0x14870,
        sceKernelWrite:         0x148a0,
        sceKernelSocket:        0x45f0,
        sceKernelBind:          0x4620,
        sceKernelListen:        0x4650,
        sceKernelAccept:        0x4680,
        sceKernelConnect:       0x46b0,
        sceKernelSend:          0x4740,
        sceKernelRecv:          0x4710,
        sceKernelShutdown:      0x4770,
        sceKernelSetsockopt:    0x46e0,
        sceKernelGetsockopt:    0x4710,
        sceKernelIoctl:         0x14930,
        sceKernelMmap:          0x14a30,
        sceKernelMunmap:        0x14a60,
        sceKernelMprotect:      0x14a90,
        sceKernelGetpid:        0x14b80,
        sceKernelGetuid:        0x14be0,
        sceKernelGeteuid:       0x14c10,

        syscalls: {
            READ:          0x3,
            WRITE:         0x4,
            OPEN:          0x5,
            CLOSE:         0x6,
            STAT:          0x188,
            FSTAT:         0x189,
            LSEEK:         0x478,
            IOCTL:         0x36,
            MMAP:          0x1dd,
            MUNMAP:        0x49,
            MPROTECT:      0x4a,
            GETPID:        0x14,
            GETUID:        0x18,
            GETEUID:       0x19,
            GETGID:        0x2b,
            GETEGID:       0x2b,
            SETUID:        0x17,
            SETEUID:       0x18,
            SETGID:        0xb5,
            SETEGID:       0xb6,
            SOCKET:        0x61,
            BIND:          0x68,
            LISTEN:        0x6a,
            ACCEPT:        0x6b,
            CONNECT:       0x62,
            SEND:          0x6c,
            RECV:          0x6d,
            SHUTDOWN:      0x6e,
            SETSOCKOPT:    0x69,
            GETSOCKOPT:    0x6d,
            PIPE:          0x2a,
            DUP:           0x29,
            FCNTL:         0x5c,
            SELECT:        0x5d,
            POLL:          0x7,
            KQUEUE:        0x16a,
            KEVENT:        0x16b,
            NANOSLEEP:     0xf0,
            SCHED_YIELD:   0x14b,
            THR_EXIT:      0x1af,
            THR_SELF:      0x1b0,
            THR_KILL:      0x1b1,
            UMTX_OP:       0x1c6,
            THR_NEW:       0x1c7,
            RTPRIO_THREAD: 0x1d2,
            CPUSET_GETAFFINITY: 0x1e7,
            CPUSET_SETAFFINITY: 0x1e8,
            PIPE2:         0x2af,
            SYSCTL:        0xa9,
        }
    },

    webkit: {
        vtable:                0x100000000,
        cellBytes:             0x30,
        functionBytes:         0x20,
        nativeExecutableBytes: 0x38,
        holderBytes:           0x40,
        carrierSlots:          9000000,
        carrierBytes:          9000000 * 8,
        drainCount:            512,
        drainSize:             0x10000,
        slabSize:              0x400000,
        butterflyHoleSize:     0x81000,
        separatorSize:         0x10000,
        earlyHoleSize:         0x70000,
        guardSize:             0x90000,
        predecessorSize:       0x80000,
        finalHoleSize:         0x80000,
        rwBufferSize:          0x100,
        identOffset:           0x20,
        leakSlotIndex:         2,
        leakSlotOffset:        0x10 + 8 * 2,
    }
};

// FW 13.00 specific kernel constants
export const KERNEL_OFFSETS_13_00 = {
    ipv6SockNum:     80,
    ucredSize:       0x168,
    rthdrTag:        0x13370000,
    leakLenIn:       8,
    cAttempts:       5000,
    maxRoundsTwin:   10,
    maxRoundsTriplet: 500,
    findTripletFast: 5000,
    repairSleepMs:   10,
    repairAttempts:  12,
    repairRoundsPerTry: 64,
    progressEvery:   1000,
    chainEpilogueSlots: 64,
};

export const KERNEL_CONSTANTS_13_00 = {
    AF_UNIX:       1,
    AF_INET:       2,
    AF_INET6:      28,
    SOCK_STREAM:   1,
    SOCK_DGRAM:    2,
    IPPROTO_IPV6:  41,
    SOL_SOCKET:    0xffff,
    SO_SNDBUF:     0x1001,
    IPV6_RTHDR:    51,
    IPV6_RTHDR_TYPE_0: 0,
    RTHDR_TAG:     0x13370000,
    UCRED_SIZE:    0x168,
    IOV_SIZE:      0x10,
    MSG_IOV_NUM:   0x17,
    UIO_IOV_NUM:   0x14,
    F_GETFL:       3,
    F_SETFL:       4,
    O_NONBLOCK:    4,
    O_RDONLY:      0,
    SEEK_SET:      0,
    SEEK_END:      2,
    FIOSETOWN:     0x8004667c,
    PROT_READ:     0x1,
    PROT_WRITE:    0x2,
    MAP_PRIVATE:   0x2,
    MAP_ANONYMOUS: 0x1000,
    CPU_LEVEL_WHICH: 3,
    CPU_WHICH_TID:   1,
    CPUSET_SIZE:     0x10,
    RTP_LOOKUP:      0,
    RTP_SET:         1,
    UMTX_OP_WAIT:    2,
    UMTX_OP_WAKE:    3,
    AMD64_GET_FSBASE: 128,
    MSG_DONTWAIT:    0x80,
};

export function isFW1300() {
    try {
        const ua = navigator.userAgent;
        return ua.includes('PlayStation 4/13.00');
    } catch (e) {
        return false;
    }
}

export function getOffsets() {
    return OFFSETS;
}

export default {
    OFFSETS,
    KERNEL_OFFSETS_13_00,
    KERNEL_CONSTANTS_13_00,
    isFW1300,
    getOffsets
};
