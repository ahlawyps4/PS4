// utils/validation.js - Validation utilities for PS4 FW 13.00 exploit
// Provides comprehensive input validation and error handling

export class ValidationError extends Error {
    constructor(message, code) {
        super(message);
        this.name = 'ValidationError';
        this.code = code || 'VALIDATION_ERROR';
    }
}

export function validateAddress(addr, name = 'address') {
    if (typeof addr !== 'number' || !Number.isFinite(addr)) {
        throw new ValidationError(`${name}: expected finite number, got ${typeof addr}`, 'INVALID_ADDRESS');
    }
    if (addr < 0) {
        throw new ValidationError(`${name}: negative address ${addr}`, 'NEGATIVE_ADDRESS');
    }
    if (addr > 0xffffffffffff) {
        throw new ValidationError(`${name}: address ${addr} exceeds 48-bit canonical range`, 'ADDRESS_OUT_OF_RANGE');
    }
    if (addr % 8 !== 0) {
        throw new ValidationError(`${name}: address ${addr} is not 8-byte aligned`, 'MISALIGNED_ADDRESS');
    }
    return addr;
}

export function validateSize(size, name = 'size') {
    if (typeof size !== 'number' || !Number.isFinite(size)) {
        throw new ValidationError(`${name}: expected finite number, got ${typeof size}`, 'INVALID_SIZE');
    }
    if (size < 0) {
        throw new ValidationError(`${name}: negative size ${size}`, 'NEGATIVE_SIZE');
    }
    if (!Number.isInteger(size)) {
        throw new ValidationError(`${name}: expected integer, got ${size}`, 'NON_INTEGER_SIZE');
    }
    return size;
}

export function validateInt64(value, name = 'value') {
    if (value instanceof int64) {
        return value;
    }
    throw new ValidationError(`${name}: expected int64, got ${typeof value}`, 'INVALID_INT64');
}

export function validateArrayBuffer(buffer, name = 'buffer') {
    if (!(buffer instanceof ArrayBuffer)) {
        throw new ValidationError(`${name}: expected ArrayBuffer, got ${typeof buffer}`, 'INVALID_BUFFER');
    }
    if (buffer.byteLength === 0) {
        throw new ValidationError(`${name}: empty buffer`, 'EMPTY_BUFFER');
    }
    return buffer;
}

export function validateFunction(func, name = 'function') {
    if (typeof func !== 'function') {
        throw new ValidationError(`${name}: expected function, got ${typeof func}`, 'INVALID_FUNCTION');
    }
    return func;
}

export function validateObject(obj, name = 'object') {
    if (obj === null || typeof obj !== 'object') {
        throw new ValidationError(`${name}: expected object, got ${typeof obj}`, 'INVALID_OBJECT');
    }
    return obj;
}

export function validateString(str, name = 'string') {
    if (typeof str !== 'string') {
        throw new ValidationError(`${name}: expected string, got ${typeof str}`, 'INVALID_STRING');
    }
    if (str.length === 0) {
        throw new ValidationError(`${name}: empty string`, 'EMPTY_STRING');
    }
    return str;
}

export function validatePort(port) {
    if (typeof port !== 'number' || !Number.isFinite(port)) {
        throw new ValidationError(`port: expected number, got ${typeof port}`, 'INVALID_PORT');
    }
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
        throw new ValidationError(`port: ${port} is not a valid port number`, 'INVALID_PORT_RANGE');
    }
    return port;
}

export function validatePercentage(value) {
    if (typeof value !== 'number' || !Number.isFinite(value)) {
        throw new ValidationError(`percentage: expected number, got ${typeof value}`, 'INVALID_PERCENTAGE');
    }
    if (value < 0 || value > 100) {
        throw new ValidationError(`percentage: ${value} is out of range [0, 100]`, 'PERCENTAGE_OUT_OF_RANGE');
    }
    return value;
}

export function clamp(value, min, max) {
    if (typeof value !== 'number' || !Number.isFinite(value))
        throw new TypeError('clamp: value must be a finite number');
    if (typeof min !== 'number' || !Number.isFinite(min))
        throw new TypeError('clamp: min must be a finite number');
    if (typeof max !== 'number' || !Number.isFinite(max))
        throw new TypeError('clamp: max must be a finite number');
    return Math.max(min, Math.min(max, value));
}

export function sanitizeHex(hex) {
    if (typeof hex !== 'string')
        throw new TypeError('sanitizeHex: expected string');
    const cleaned = hex.replace(/^0x/i, '').replace(/[^0-9a-fA-F]/g, '');
    if (cleaned.length === 0)
        throw new Error('sanitizeHex: no valid hex characters found');
    return '0x' + cleaned;
}

export function isPowerOfTwo(value) {
    if (typeof value !== 'number' || !Number.isFinite(value) || value <= 0)
        return false;
    return (value & (value - 1)) === 0;
}

export function validateBufferSize(size, minSize, maxSize) {
    validateSize(size, 'size');
    if (typeof minSize === 'number' && size < minSize) {
        throw new ValidationError(`size: ${size} is below minimum ${minSize}`, 'SIZE_TOO_SMALL');
    }
    if (typeof maxSize === 'number' && size > maxSize) {
        throw new ValidationError(`size: ${size} exceeds maximum ${maxSize}`, 'SIZE_TOO_LARGE');
    }
    return size;
}

export function assert(condition, message, code = 'ASSERTION_FAILED') {
    if (!condition) {
        throw new ValidationError(message || 'Assertion failed', code);
    }
}

export default {
    ValidationError,
    validateAddress,
    validateSize,
    validateInt64,
    validateArrayBuffer,
    validateFunction,
    validateObject,
    validateString,
    validatePort,
    validatePercentage,
    clamp,
    sanitizeHex,
    isPowerOfTwo,
    validateBufferSize,
    assert
};
