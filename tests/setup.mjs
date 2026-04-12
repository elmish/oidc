import { webcrypto } from 'node:crypto';

// jsdom provides window.crypto with getRandomValues but missing subtle.
// Patch both window.crypto and globalThis.crypto with Node's full webcrypto.
for (const target of [globalThis, typeof window !== 'undefined' ? window : null].filter(Boolean)) {
    try {
        Object.defineProperty(target, 'crypto', {
            value: webcrypto,
            writable: true,
            configurable: true,
            enumerable: true
        });
    } catch (_) {}
}
