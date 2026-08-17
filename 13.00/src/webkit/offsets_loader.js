// offsets_loader.js - Dynamic offsets loader for PS4 FW 13.00
// Supports multiple offset sources and strict validation

import { OFFSETS } from './offsets.js';
import { validateString, validateObject, ValidationError } from '../utils/validation.js';

export class OffsetsLoadError extends Error {
    constructor(message, firmware, code) {
        super(message);
        this.name = 'OffsetsLoadError';
        this.firmware = firmware;
        this.code = code || 'OFFSETS_LOAD_FAILED';
    }
}

export class OffsetsValidationError extends Error {
    constructor(message, details = []) {
        super(message);
        this.name = 'OffsetsValidationError';
        this.details = details;
    }
}

const MINIMUM_REQUIRED_OFFSETS = [
    'kernel.allproc',
    'kernel.prison0',
    'kernel.sysent',
    'libkernel.sceKernelGetCurrentCpu'
];

const PLACEHOLDER_VALUE = 0x0;

export class OffsetsLoader {
    constructor() {
        this.loaded = false;
        this.firmware = null;
        this.offsets = null;
        this.sources = [];
        this.validationResult = null;
    }

    async load(firmwareVersion) {
        validateString(firmwareVersion, 'firmwareVersion');
        this.firmware = firmwareVersion;
        this.offsets = null;
        this.sources = [];
        this.validationResult = null;

        const version = this.normalizeVersion(firmwareVersion);

        if (version === '13.00') {
            this.offsets = OFFSETS;
            this.sources.push('builtin-13.00');
        } else {
            this.offsets = OFFSETS;
            this.sources.push('builtin-default');
        }

        if (!this.offsets) {
            throw new OffsetsLoadError(`No offsets available for firmware ${firmwareVersion}`, firmwareVersion, 'NO_OFFSETS');
        }

        this.validateOffsets(this.offsets);
        this.loaded = true;
        return this.offsets;
    }

    normalizeVersion(version) {
        const parts = version.split('.');
        if (parts.length < 2 || parts.some(p => isNaN(Number(p)))) {
            throw new Error(`Invalid firmware version format: ${version}`);
        }
        return `${parts[0]}.${parts[1]}`;
    }

    validateOffsets(offsets) {
        const issues = [];
        validateObject(offsets, 'offsets');

        if (!offsets.kernel || typeof offsets.kernel !== 'object') {
            issues.push('Missing kernel offsets object');
        } else {
            if (typeof offsets.kernel.allproc !== 'number') {
                issues.push('Invalid or missing kernel.allproc offset');
            }
            if (typeof offsets.kernel.prison0 !== 'number') {
                issues.push('Invalid or missing kernel.prison0 offset');
            }
            if (typeof offsets.kernel.sysent !== 'number') {
                issues.push('Invalid or missing kernel.sysent offset');
            }
            if (!offsets.kernel.gadgets || typeof offsets.kernel.gadgets !== 'object') {
                issues.push('Missing kernel.gadgets object');
            } else {
                const gadgetIssues = this.validateGadgets(offsets.kernel.gadgets);
                issues.push(...gadgetIssues);
            }
        }

        if (!offsets.libkernel || typeof offsets.libkernel !== 'object') {
            issues.push('Missing libkernel offsets object');
        } else {
            if (typeof offsets.libkernel.sceKernelGetCurrentCpu !== 'number') {
                issues.push('Invalid or missing libkernel.sceKernelGetCurrentCpu offset');
            }
        }

        this.validationResult = {
            passed: issues.length === 0,
            issues,
            timestamp: new Date().toISOString()
        };

        if (issues.length > 0) {
            throw new OffsetsValidationError(
                `Offset validation failed with ${issues.length} issue(s)`,
                issues
            );
        }
    }

    validateGadgets(gadgets) {
        const issues = [];
        const requiredGadgets = [
            'pop rdi', 'pop rsi', 'pop rdx', 'pop rcx',
            'pop r8', 'pop r9', 'ret',
            'mov [rdi], rsi', 'mov [rdi], rax', 'mov [rdi], eax',
            'pop rax', 'mov rax, [rax]', 'pop rsp', 'inc dword [rax]'
        ];

        for (const gadget of requiredGadgets) {
            if (typeof gadgets[gadget] !== 'number') {
                issues.push(`Missing or invalid gadget offset: ${gadget}`);
            } else if (gadgets[gadget] === PLACEHOLDER_VALUE) {
                issues.push(`Placeholder gadget offset not replaced: ${gadget}`);
            }
        }

        return issues;
    }

    getLoadedOffsets() {
        if (!this.loaded || !this.offsets) {
            throw new OffsetsLoadError('Offsets not loaded yet', this.firmware, 'NOT_LOADED');
        }
        return this.offsets;
    }

    getSources() {
        return [...this.sources];
    }

    isLoaded() {
        return this.loaded;
    }

    getValidationResult() {
        return this.validationResult;
    }

    hasUsableOffsets() {
        if (!this.loaded || !this.validationResult) {
            return false;
        }
        return this.validationResult.passed;
    }
}

const loader = new OffsetsLoader();

export async function loadOffsets(firmwareVersion) {
    return loader.load(firmwareVersion);
}

export function getOffsets() {
    return loader.getLoadedOffsets();
}

export function isFW1300() {
    if (!loader.isLoaded()) {
        return false;
    }
    return loader.firmware === '13.00';
}

export function getOffsetsValidationResult() {
    return loader.getValidationResult();
}

export function hasUsableOffsets() {
    return loader.hasUsableOffsets();
}

export default {
    OffsetsLoader,
    OffsetsLoadError,
    OffsetsValidationError,
    loadOffsets,
    getOffsets,
    isFW1300,
    getOffsetsValidationResult,
    hasUsableOffsets
};
