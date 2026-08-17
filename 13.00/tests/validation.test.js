// tests/validation.test.js - Unit tests for validation.js

import {
    validateAddress,
    validateSize,
    validatePort,
    validateString,
    clamp,
    sanitizeHex,
    isPowerOfTwo,
    ValidationError
} from '../src/utils/validation.js';

function assert(condition, message) {
    if (!condition) throw new Error(`Assertion failed: ${message}`);
}

function assertThrows(fn, message) {
    try {
        fn();
        throw new Error(`${message}: expected function to throw`);
    } catch (e) {
        if (!(e instanceof Error)) throw e;
    }
}

export function testValidateAddress() {
    assert(validateAddress(0x1000) === 0x1000, 'valid address should pass');
    assert(validateAddress(0xFFFFFFFFF0) === 0xFFFFFFFFF0, 'max canonical 8-byte aligned address should pass');
    assert(validateAddress(0x10) === 0x10, '8-byte aligned address should pass');

    assertThrows(() => validateAddress(-1), 'negative address should throw');
    assertThrows(() => validateAddress(0x10000000000000), 'out of range address should throw');
    assertThrows(() => validateAddress(1), 'non-aligned address should throw');
    assertThrows(() => validateAddress('abc'), 'string address should throw');
    assertThrows(() => validateAddress(NaN), 'NaN address should throw');

    console.log('✓ validateAddress tests passed');
}

export function testValidateSize() {
    assert(validateSize(100) === 100, 'valid size should pass');
    assert(validateSize(0) === 0, 'zero size should pass');

    assertThrows(() => validateSize(-1), 'negative size should throw');
    assertThrows(() => validateSize(1.5), 'non-integer size should throw');
    assertThrows(() => validateSize('abc'), 'string size should throw');
    assertThrows(() => validateSize(NaN), 'NaN size should throw');

    console.log('✓ validateSize tests passed');
}

export function testValidatePort() {
    assert(validatePort(80) === 80, 'valid port should pass');
    assert(validatePort(1) === 1, 'port 1 should pass');
    assert(validatePort(65535) === 65535, 'max port should pass');

    assertThrows(() => validatePort(0), 'port 0 should throw');
    assertThrows(() => validatePort(65536), 'port 65536 should throw');
    assertThrows(() => validatePort(-1), 'negative port should throw');
    assertThrows(() => validatePort('abc'), 'string port should throw');

    console.log('✓ validatePort tests passed');
}

export function testValidateString() {
    assert(validateString('hello') === 'hello', 'valid string should pass');

    assertThrows(() => validateString(''), 'empty string should throw');
    assertThrows(() => validateString(null), 'null should throw');
    assertThrows(() => validateString(123), 'number should throw');

    console.log('✓ validateString tests passed');
}

export function testClamp() {
    assert(clamp(5, 0, 10) === 5, 'value in range should pass');
    assert(clamp(-1, 0, 10) === 0, 'value below min should clamp');
    assert(clamp(15, 0, 10) === 10, 'value above max should clamp');

    assertThrows(() => clamp('a', 0, 10), 'string value should throw');
    assertThrows(() => clamp(5, 'a', 10), 'string min should throw');
    assertThrows(() => clamp(5, 0, 'a'), 'string max should throw');

    console.log('✓ clamp tests passed');
}

export function testSanitizeHex() {
    assert(sanitizeHex('0xABCD') === '0xABCD', 'valid hex should pass');
    assert(sanitizeHex('abcd') === '0xabcd', 'hex without prefix should pass');
    assert(sanitizeHex('0xAB CD EF') === '0xABCDEF', 'hex with spaces should pass');

    assertThrows(() => sanitizeHex(''), 'empty string should throw');
    assertThrows(() => sanitizeHex('xyz'), 'invalid hex should throw');

    console.log('✓ sanitizeHex tests passed');
}

export function testIsPowerOfTwo() {
    assert(isPowerOfTwo(1) === true, '1 is power of two');
    assert(isPowerOfTwo(2) === true, '2 is power of two');
    assert(isPowerOfTwo(4) === true, '4 is power of two');
    assert(isPowerOfTwo(3) === false, '3 is not power of two');
    assert(isPowerOfTwo(0) === false, '0 is not power of two');
    assert(isPowerOfTwo(-4) === false, 'negative is not power of two');

    console.log('✓ isPowerOfTwo tests passed');
}

export function runAllTests() {
    console.log('Running validation tests...\n');
    testValidateAddress();
    testValidateSize();
    testValidatePort();
    testValidateString();
    testClamp();
    testSanitizeHex();
    testIsPowerOfTwo();
    console.log('\n✓ All validation tests passed!');
}

runAllTests();
