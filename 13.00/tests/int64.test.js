// tests/int64.test.js - Unit tests for int64.js

import { int64 } from '../src/webkit/int64.js';

function assert(condition, message) {
    if (!condition) {
        throw new Error(`Assertion failed: ${message}`);
    }
}

function assertEqual(actual, expected, message) {
    if (actual !== expected) {
        throw new Error(`${message}: expected ${expected}, got ${actual}`);
    }
}

function assertThrows(fn, message) {
    try {
        fn();
        throw new Error(`${message}: expected function to throw`);
    } catch (e) {
        if (!(e instanceof Error)) throw e;
    }
}

export function testConstructor() {
    const a = new int64(0, 0);
    assert(a.low === 0, 'low should be 0');
    assert(a.hi === 0, 'hi should be 0');

    const b = new int64(0xffffffff, 0);
    assert(b.low === 0xffffffff, 'low should be 0xffffffff');
    assert(b.hi === 0, 'hi should be 0');

    const c = new int64(0, 1);
    assert(c.low === 0, 'low should be 0');
    assert(c.hi === 1, 'hi should be 1');

    assertThrows(() => new int64('a', 0), 'should throw on invalid low');
    assertThrows(() => new int64(0, 'b'), 'should throw on invalid hi');
    console.log('✓ constructor tests passed');
}

export function testToString() {
    assertEqual(new int64(0, 0).toString(), '0', 'toString(16) for zero');
    assertEqual(new int64(0xffffffff, 0).toString(), 'ffffffff', 'toString(16) for 32-bit');
    assertEqual(new int64(0, 1).toString(), '100000000', 'toString(16) for 33-bit');
    assertEqual(new int64(0x12345678, 0x9abc).toString(), '9abc12345678', 'toString(16) for large');

    assertThrows(() => new int64(0, 0).toString(3), 'should throw on unsupported radix');
    console.log('✓ toString tests passed');
}

export function testToHex() {
    assertEqual(new int64(0, 0).toHex(), '0x0000000000000000', 'toHex for zero');
    assertEqual(new int64(0xdeadbeef, 0xbaad).toHex(), '0x0000baaddeadbeef', 'toHex for large');
    console.log('✓ toHex tests passed');
}

export function testEquals() {
    const a = new int64(0x12345678, 0x9abc);
    const b = new int64(0x12345678, 0x9abc);
    const c = new int64(0x12345678, 0x9abd);
    const d = 5;

    assert(a.equals(b), 'same values should be equal');
    assert(!a.equals(c), 'different values should not be equal');
    assert(!a.equals(d), 'non-int64 should not be equal');
    console.log('✓ equals tests passed');
}

export function testAdd32() {
    const a = new int64(0xffffffff, 0);
    const b = a.add32(1);
    assert(b.low === 0, 'low should wrap to 0');
    assert(b.hi === 1, 'hi should be 1');

    const c = new int64(0, 1);
    const d = c.add32(0xffffffff);
    assert(d.low === 0xffffffff, 'low should be 0xffffffff');
    assert(d.hi === 1, 'hi should be 1');

    assertThrows(() => new int64(0, 0).add32('x'), 'should throw on non-number');
    assertThrows(() => new int64(0, 0).add32(-1), 'should throw on negative');
    assertThrows(() => new int64(0, 0).add32(0x100000000), 'should throw on > 32-bit');

    console.log('✓ add32 tests passed');
}

export function testAdd32Inplace() {
    const a = new int64(0xffffffff, 0);
    a.add32inplace(1);
    assert(a.low === 0, 'low should wrap to 0');
    assert(a.hi === 1, 'hi should be 1');

    assertThrows(() => { const b = new int64(0, 0); b.add32inplace('x'); }, 'should throw on non-number');
    console.log('✓ add32Inplace tests passed');
}

export function testSub32() {
    const a = new int64(0, 1);
    const b = a.sub32(1);
    assert(b.low === 0xffffffff, 'low should wrap');
    assert(b.hi === 0, 'hi should be 0');

    const c = new int64(0x12345678, 0);
    const d = c.sub32(0x12345678);
    assert(d.low === 0, 'low should be 0');
    assert(d.hi === 0, 'hi should be 0');

    assertThrows(() => new int64(0, 0).sub32('x'), 'should throw on non-number');
    console.log('✓ sub32 tests passed');
}

export function testSub32Inplace() {
    const a = new int64(0, 1);
    a.sub32inplace(1);
    assert(a.low === 0xffffffff, 'low should wrap');
    assert(a.hi === 0, 'hi should be 0');
    console.log('✓ sub32Inplace tests passed');
}

export function testAnd32() {
    const a = new int64(0xffffffff, 0xffffffff);
    const b = a.and32(0x00ff00ff);
    assert(b.low === 0x00ff00ff, 'low should be masked');
    assert(b.hi === 0xffffffff, 'hi should be unchanged');

    assertThrows(() => new int64(0, 0).and32('x'), 'should throw on non-number');
    console.log('✓ and32 tests passed');
}

export function testAnd64() {
    const a = new int64(0xffffffff, 0xffffffff);
    const b = a.and64(0x00ff00ff, 0x00ff00ff);
    assert(b.low === 0x00ff00ff, 'low should be masked');
    assert(b.hi === 0x00ff00ff, 'hi should be masked');

    assertThrows(() => new int64(0, 0).and64('x', 0), 'should throw on non-number');
    console.log('✓ and64 tests passed');
}

export function testToNumber() {
    assertEqual(new int64(0, 0).toNumber(), 0, 'toNumber for zero');
    assertEqual(new int64(0xffffffff, 0).toNumber(), 0xffffffff, 'toNumber for 32-bit');
    assertEqual(new int64(0, 1).toNumber(), 0x100000000, 'toNumber for 33-bit');
    console.log('✓ toNumber tests passed');
}

export function runAllTests() {
    console.log('Running int64 tests...\n');
    testConstructor();
    testToString();
    testToHex();
    testEquals();
    testAdd32();
    testAdd32Inplace();
    testSub32();
    testSub32Inplace();
    testAnd32();
    testAnd64();
    testToNumber();
    console.log('\n✓ All int64 tests passed!');
}

runAllTests();
