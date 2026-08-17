// mem.js - Memory primitives for PS4 FW 13.00
// Based on SlopKit mem.js
// Provides read/write operations on top of the carrier object
// Includes addrof and fakeobj for type confusion

import { int64 } from './int64.js';
import { validateAddress, validateSize, validateInt64, ValidationError } from '../utils/validation.js';

let carrier = null;
let objectStore = [];
let objectStoreIndex = 0;

function toI64(x) {
    if (x instanceof int64) return x;
    if (typeof x === "number") {
        if (!Number.isFinite(x) || Math.floor(x) !== x || x < 0)
            throw new TypeError(`mem: bad numeric address ${x}`);
        const hi = Math.floor(x / 0x100000000);
        return new int64(x - hi * 0x100000000, hi);
    }
    if (x !== null && typeof x === "object" && "low" in x)
        return new int64(x.low, ("hi" in x) ? x.hi : x.high);
    throw new TypeError("mem: bad address");
}

function addrNumber(x) {
    const a = toI64(x);
    if (a.hi > 0xffff)
        throw new RangeError(`mem: non-canonical address 0x${a.toString()}`);
    return a.hi * 0x100000000 + a.low;
}

function aimFor(addrLike, size) {
    const address = addrNumber(addrLike);
    if (size > carrier.windowBytes)
        throw new RangeError(`mem: ${size} exceeds the ${carrier.windowBytes}-byte window`);
    carrier.aim(address);
    return address;
}

function valueLow32(value, who) {
    if (typeof value === "number") {
        if (!Number.isFinite(value) || Math.floor(value) !== value)
            throw new TypeError(`${who}: non-integer value ${value}`);
        return value >>> 0;
    }
    if (value instanceof int64) return value.low >>> 0;
    if (value !== null && typeof value === "object" && "low" in value)
        return toI64(value).low >>> 0;
    throw new TypeError(`${who}: value must be a number or an int64`);
}

export function read1(addr) {
    const address = validateAddress(addr, 'read1.address');
    aimFor(address, 1);
    try {
        return carrier.view[0];
    } finally {
        carrier.restore();
    }
}

export function read2(addr) {
    const address = validateAddress(addr, 'read2.address');
    aimFor(address, 2);
    try {
        const v = carrier.view;
        return v[0] | (v[1] << 8);
    } finally {
        carrier.restore();
    }
}

export function read4(addr) {
    const address = validateAddress(addr, 'read4.address');
    aimFor(address, 4);
    try {
        const v = carrier.view;
        return (v[0] | (v[1] << 8) | (v[2] << 16) | (v[3] << 24)) >>> 0;
    } finally {
        carrier.restore();
    }
}

export function read8(addr) {
    const address = validateAddress(addr, 'read8.address');
    let lo, hi;
    aimFor(address, 8);
    try {
        const v = carrier.view;
        lo = (v[0] | (v[1] << 8) | (v[2] << 16) | (v[3] << 24)) >>> 0;
        hi = (v[4] | (v[5] << 8) | (v[6] << 16) | (v[7] << 24)) >>> 0;
    } finally {
        carrier.restore();
    }
    return new int64(lo, hi);
}

export function write1(addr, value) {
    const address = validateAddress(addr, 'write1.address');
    const v = valueLow32(value, "mem.write1") & 0xff;
    aimFor(address, 1);
    try {
        carrier.view[0] = v;
    } finally {
        carrier.restore();
    }
}

export function write2(addr, value) {
    const address = validateAddress(addr, 'write2.address');
    const v = valueLow32(value, "mem.write2") & 0xffff;
    aimFor(address, 2);
    try {
        const view = carrier.view;
        view[0] = v & 0xff;
        view[1] = (v >>> 8) & 0xff;
    } finally {
        carrier.restore();
    }
}

export function write4(addr, value) {
    const address = validateAddress(addr, 'write4.address');
    const v = valueLow32(value, "mem.write4");
    aimFor(address, 4);
    try {
        const view = carrier.view;
        view[0] = v & 0xff;
        view[1] = (v >>> 8) & 0xff;
        view[2] = (v >>> 16) & 0xff;
        view[3] = (v >>> 24) & 0xff;
    } finally {
        carrier.restore();
    }
}

export function write8(addr, value) {
    const address = validateAddress(addr, 'write8.address');
    let lo, hi;
    if (value instanceof int64) {
        lo = value.low >>> 0;
        hi = value.hi >>> 0;
    } else if (typeof value === "number") {
        if (!Number.isFinite(value) || Math.floor(value) !== value)
            throw new TypeError(`mem.write8: non-integer value ${value}`);
        if (value < 0) {
            if (value < -0x80000000)
                throw new RangeError(`mem.write8: value ${value} below int32 range`);
            lo = value >>> 0;
            hi = 0xffffffff;
        } else if (value <= 0xffffffff) {
            lo = value >>> 0;
            hi = 0;
        } else {
            throw new RangeError(`mem.write8: ${value} exceeds 32 bits -- pass an int64`);
        }
    } else if (value !== null && typeof value === "object" && "low" in value) {
        const n = toI64(value);
        lo = n.low; hi = n.hi;
    } else {
        throw new TypeError("mem.write8: value must be int64 or number");
    }

    aimFor(address, 8);
    try {
        const view = carrier.view;
        view[0] = lo & 0xff;
        view[1] = (lo >>> 8) & 0xff;
        view[2] = (lo >>> 16) & 0xff;
        view[3] = (lo >>> 24) & 0xff;
        view[4] = hi & 0xff;
        view[5] = (hi >>> 8) & 0xff;
        view[6] = (hi >>> 16) & 0xff;
        view[7] = (hi >>> 24) & 0xff;
    } finally {
        carrier.restore();
    }
}

export function leakval(obj) {
    if (obj === null || (typeof obj !== "object" && typeof obj !== "function"))
        throw new TypeError("mem.leakval: not an object");

    carrier.setLeakSlot(obj);
    let lo, hi;
    try {
        aimFor(carrier.leakSlotAddress, 8);
        try {
            const v = carrier.view;
            lo = (v[0] | (v[1] << 8) | (v[2] << 16) | (v[3] << 24)) >>> 0;
            hi = (v[4] | (v[5] << 8) | (v[6] << 16) | (v[7] << 24)) >>> 0;
        } finally {
            carrier.restore();
        }
    } finally {
        carrier.clearLeakSlot();
    }

    if (hi > 0xffff || (lo === 0 && hi === 0) || (lo & 7) !== 0)
        throw new Error(`mem.leakval: implausible cell 0x${new int64(lo, hi).toString()}`);
    return new int64(lo, hi);
}

export function addrof(obj) {
    if (obj === null || (typeof obj !== "object" && typeof obj !== "function"))
        throw new TypeError("mem.addrof: not an object");

    const idx = objectStoreIndex;
    objectStore[idx] = obj;
    objectStoreIndex = (objectStoreIndex + 1) & 0x7fff;

    try {
        const addr = leakval(obj);
        return addr;
    } finally {
        objectStore[idx] = undefined;
    }
}

export function fakeobj(addr) {
    const address = addrNumber(addr);

    const scratch = new ArrayBuffer(8);
    const f64 = new Float64Array(scratch);
    const u32 = new Uint32Array(scratch);

    const lo = address >>> 0;
    const hi = Math.floor(address / 0x100000000) >>> 0;
    u32[0] = lo;
    u32[1] = hi;

    return f64[0];
}

export function readInto(dest, addr, count) {
    const base = addrNumber(addr);
    const totalCount = validateSize(count, 'count');
    let done = 0;
    while (done < totalCount) {
        const chunk = Math.min(totalCount - done, carrier.windowBytes);
        aimFor(base + done, chunk);
        try {
            for (let i = 0; i < chunk; ++i)
                dest[done + i] = carrier.view[i];
        } finally {
            carrier.restore();
        }
        done += chunk;
    }
    return dest;
}

export function readString(addr, length) {
    const bytes = new Uint8Array(length);
    readInto(bytes, addr, length);
    let str = '';
    for (let i = 0; i < length; i++) {
        if (bytes[i] === 0) break;
        str += String.fromCharCode(bytes[i]);
    }
    return str;
}

export function writeString(addr, str) {
    for (let i = 0; i < str.length; i++) {
        write1(addr + i, str.charCodeAt(i));
    }
    write1(addr + str.length, 0);
}

export function installWindowP(c, options = {}) {
    if (!c || typeof c.aim !== "function")
        throw new TypeError("mem: not a carrier");
    carrier = c;

    const prim = {
        read1, read2, read4, read8,
        write1, write2, write4, write8,
        leakval, addrof, fakeobj,
        readString, writeString, readInto
    };
    globalThis.p = prim;

    return prim;
}

export { toI64, addrNumber, int64 };
