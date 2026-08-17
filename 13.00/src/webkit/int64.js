// int64.js - 64-bit integer library for PS4 WebKit exploit
// Based on SlopKit int64.js

function zeroFill(number, width) {
    width -= number.toString().length;
    if (width > 0) {
        return new Array(width + (/\./.test(number) ? 2 : 1)).join('0') + number;
    }
    return number + "";
}

export class int64 {
    constructor(low, hi) {
        if (typeof low !== 'number' || typeof hi !== 'number')
            throw new TypeError('int64: constructor requires two numbers');
        this.low = low >>> 0;
        this.hi = hi >>> 0;
        this.backing = null;
    }

    equals(other) {
        if (other instanceof int64) {
            return this.low === other.low && this.hi === other.hi;
        }
        return false;
    }

    toHex() {
        return '0x' + this.toString(16).padStart(16, '0');
    }

    add32inplace(val) {
        if (typeof val !== 'number' || !Number.isFinite(val) || Math.floor(val) !== val)
            throw new TypeError(`int64.add32inplace: non-integer value ${val}`);
        if (val < 0 || val > 0xFFFFFFFF)
            throw new RangeError(`int64.add32inplace: value ${val} out of 32-bit range`);
        let new_lo = (((this.low >>> 0) + val) & 0xFFFFFFFF) >>> 0;
        let new_hi = (this.hi >>> 0);
        if (new_lo < this.low) {
            new_hi++;
        }
        this.hi = new_hi;
        this.low = new_lo;
        if (this.backing !== null) {
            if (this.backing.byteLength < val) {
                throw new Error("int64.add32inplace: overflow");
            }
            this.backing = new Uint8Array(this.backing.buffer, val, this.backing.byteLength - val);
        }
    }

    add32(val) {
        if (typeof val !== 'number' || !Number.isFinite(val) || Math.floor(val) !== val)
            throw new TypeError(`int64.add32: non-integer value ${val}`);
        if (val < 0 || val > 0xFFFFFFFF)
            throw new RangeError(`int64.add32: value ${val} out of 32-bit range`);
        let new_lo = (((this.low >>> 0) + val) & 0xFFFFFFFF) >>> 0;
        let new_hi = (this.hi >>> 0);
        if (new_lo < this.low) {
            new_hi++;
        }
        let ret = new int64(new_lo, new_hi);
        if (this.backing !== null) {
            if (this.backing.byteLength < val) {
                throw new Error("int64.add32: overflow");
            }
            ret.backing = new Uint8Array(this.backing.buffer, val, this.backing.byteLength - val);
        }
        return ret;
    }

    sub32(val) {
        if (typeof val !== 'number' || !Number.isFinite(val) || Math.floor(val) !== val)
            throw new TypeError(`int64.sub32: non-integer value ${val}`);
        if (val < 0 || val > 0xFFFFFFFF)
            throw new RangeError(`int64.sub32: value ${val} out of 32-bit range`);
        let new_lo = (((this.low >>> 0) - val) & 0xFFFFFFFF) >>> 0;
        let new_hi = (this.hi >>> 0);
        if (new_lo > (this.low & 0xFFFFFFFF)) {
            new_hi--;
        }
        return new int64(new_lo, new_hi);
    }

    sub32inplace(val) {
        if (typeof val !== 'number' || !Number.isFinite(val) || Math.floor(val) !== val)
            throw new TypeError(`int64.sub32inplace: non-integer value ${val}`);
        if (val < 0 || val > 0xFFFFFFFF)
            throw new RangeError(`int64.sub32inplace: value ${val} out of 32-bit range`);
        let new_lo = (((this.low >>> 0) - val) & 0xFFFFFFFF) >>> 0;
        let new_hi = (this.hi >>> 0);
        if (new_lo > (this.low & 0xFFFFFFFF)) {
            new_hi--;
        }
        this.hi = new_hi;
        this.low = new_lo;
    }

    and32(val) {
        if (typeof val !== 'number' || !Number.isFinite(val) || Math.floor(val) !== val)
            throw new TypeError(`int64.and32: non-integer value ${val}`);
        let new_lo = this.low & val;
        let new_hi = this.hi;
        return new int64(new_lo, new_hi);
    }

    and64(vallo, valhi) {
        if (typeof vallo !== 'number' || typeof valhi !== 'number')
            throw new TypeError('int64.and64: requires two numbers');
        let new_lo = this.low & vallo;
        let new_hi = this.hi & valhi;
        return new int64(new_lo, new_hi);
    }

    toString(radix = 16) {
        if (![2, 8, 10, 16].includes(radix))
            throw new RangeError(`int64.toString: unsupported radix ${radix}`);
        let lo_str = (this.low >>> 0).toString(radix);
        let hi_str = (this.hi >>> 0).toString(radix);
        if (this.hi == 0) {
            return lo_str;
        } else {
            const width = radix === 16 ? 8 : Math.ceil(32 / Math.log2(radix));
            lo_str = zeroFill(lo_str, width);
        }
        return hi_str + lo_str;
    }

    toNumber() {
        return this.hi * 0x100000000 + this.low;
    }
}

export default int64;
