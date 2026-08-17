// config.js - Runtime configuration for PS4 FW 13.00 exploit
// Centralizes tunable parameters for easier testing and tuning

export const CONFIG = {
    exploit: {
        maxAttempts: 8,
        autoRetryDelayMs: 50,
        carrierSlots: 9000000,
        drainCount: 512,
        debugMode: false
    },
    kernel: {
        maxRetries: 10,
        retryDelayMs: 100,
        defaultNumSockets: 80,
        maxNumSockets: 1000,
        twinEngineAttempts: 100
    },
    payload: {
        port: 9021,
        goldhenUrl: './GoldHEN_v2.4b18.10.bin',
        goldhenVersion: 'v2.4b18.10'
    },
    webkit: {
        captureDelayMs: 50,
        composeDelayMs: 100,
        rwBufferSize: 0x100,
        identOffset: 0x20,
        leakSlotIndex: 2
    }
};

export function getExploitConfig() {
    return CONFIG.exploit;
}

export function getKernelConfig() {
    return CONFIG.kernel;
}

export function getPayloadConfig() {
    return CONFIG.payload;
}

export function getWebKitConfig() {
    return CONFIG.webkit;
}

export function updateConfig(path, value) {
    const parts = path.split('.');
    let target = CONFIG;
    for (let i = 0; i < parts.length - 1; i++) {
        if (!(parts[i] in target)) {
            throw new Error(`Invalid config path: ${path}`);
        }
        target = target[parts[i]];
    }
    if (!(parts[parts.length - 1] in target)) {
        throw new Error(`Invalid config key: ${path}`);
    }
    target[parts[parts.length - 1]] = value;
}

export default {
    CONFIG,
    getExploitConfig,
    getKernelConfig,
    getPayloadConfig,
    getWebKitConfig,
    updateConfig
};
