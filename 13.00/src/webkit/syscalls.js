// syscalls.js - System call wrappers for PS4 FW 13.00
// Provides syscall interface for kernel operations

import { int64 } from './int64.js';
import { validateAddress, validateSize, validatePort, validateString } from '../utils/validation.js';

export const SYS_SOCKET = 97;
export const SYS_BIND = 104;
export const SYS_CONNECT = 98;
export const SYS_CLOSE = 6;
export const SYS_WRITE = 4;
export const SYS_READ = 3;
export const SYS_SETSOCKOPT = 105;
export const SYS_GETSOCKOPT = 118;
export const SYS_NETGETIFLIST = 163;
export const SYS_IOCTL = 54;
export const SYS_FGETXATTR = 341;
export const SYS_FSETXATTR = 342;
export const SYS_GETEUID = 25;
export const SYS_GETEGID = 43;
export const SYS_GETPID = 20;
export const SYS_KQUEUE = 362;
export const SYS_PIPE = 42;
export const SYS_FCNTL = 92;
export const SYS_EVENTFD = 560;
export const SYS_KEQTLOOP = 561;
export const SYS_KEQTWAIT = 562;

const trackedFds = new Set();
const trackedMemory = new Set();
let syscallFunc = null;

export function setSyscallFunc(func) {
    validateFunction(func, 'syscallFunc');
    syscallFunc = func;
}

export function getSyscallFunc() {
    return syscallFunc;
}

function validateFunction(func, name) {
    if (typeof func !== 'function') {
        throw new TypeError(`${name}: expected function, got ${typeof func}`);
    }
    return func;
}

export async function sys(syscall, ...args) {
    if (!syscallFunc) {
        throw new Error('Syscall function not set');
    }

    try {
        const result = await syscallFunc(syscall, ...args);
        if (typeof result !== 'number') {
            throw new Error(`Syscall returned non-number: ${typeof result}`);
        }
        return {
            failed: result < 0,
            s32: result,
            hex: '0x' + (result >>> 0).toString(16)
        };
    } catch (error) {
        return {
            failed: true,
            s32: -1,
            hex: '0xffffffff',
            errText: error.message
        };
    }
}

export function track(fd) {
    if (typeof fd !== 'number' || !Number.isFinite(fd)) {
        throw new TypeError(`track: fd must be a number, got ${typeof fd}`);
    }
    trackedFds.add(fd);
}

export function untrack(fd) {
    trackedFds.delete(fd);
}

export async function closeAllTracked() {
    const fds = [...trackedFds];
    for (const fd of fds) {
        try {
            await sys(SYS_CLOSE, fd);
        } catch (e) { }
    }
    trackedFds.clear();
}

export function mem(size) {
    validateSize(size, 'size');
    if (size <= 0) {
        throw new RangeError(`mem: size must be positive, got ${size}`);
    }

    const buffer = new ArrayBuffer(size);
    const view = new Uint8Array(buffer);
    const i32 = new Int32Array(buffer);
    const u32 = new Uint32Array(buffer);
    const f32 = new Float32Array(buffer);
    const f64 = new Float64Array(buffer);

    const wrapper = {
        buffer,
        ptr: 0,
        view,
        u8: view,
        i32,
        u32,
        f32,
        f64,
        size,
        free() {
            trackedMemory.delete(wrapper);
        }
    };

    trackedMemory.add(wrapper);
    return wrapper;
}

export function freeAllTracked() {
    const memory = [...trackedMemory];
    for (const wrapper of memory) {
        try {
            wrapper.free();
        } catch (e) { }
    }
    trackedMemory.clear();
}

export function createSockaddr(port, ip = '127.0.0.1') {
    validatePort(port, 'port');
    validateString(ip, 'ip');

    const parts = ip.split('.').map(Number);
    if (parts.length !== 4 || parts.some(p => isNaN(p) || p < 0 || p > 255)) {
        throw new Error(`createSockaddr: invalid IP address ${ip}`);
    }

    const sockaddr = mem(0x10);
    sockaddr.u8[0] = 0x10; // sin_len
    sockaddr.u8[1] = 0x02; // sin_family (AF_INET)
    sockaddr.u8[2] = (port >> 8) & 0xff; // sin_port (big endian)
    sockaddr.u8[3] = port & 0xff;
    sockaddr.u8[4] = parts[0];
    sockaddr.u8[5] = parts[1];
    sockaddr.u8[6] = parts[2];
    sockaddr.u8[7] = parts[3];
    return sockaddr;
}

export default {
    SYS_SOCKET, SYS_BIND, SYS_CONNECT, SYS_CLOSE, SYS_WRITE, SYS_READ,
    SYS_SETSOCKOPT, SYS_GETSOCKOPT, SYS_NETGETIFLIST, SYS_IOCTL,
    SYS_FGETXATTR, SYS_FSETXATTR, SYS_GETEUID, SYS_GETEGID, SYS_GETPID,
    SYS_KQUEUE, SYS_PIPE, SYS_FCNTL, SYS_EVENTFD, SYS_KEQTLOOP, SYS_KEQTWAIT,
    sys, track, untrack, closeAllTracked, mem, freeAllTracked, createSockaddr,
    setSyscallFunc, getSyscallFunc
};
