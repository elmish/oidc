// Node.js ESM loader hook that intercepts native-only module imports during
// the React Native unit-test run. Tests use mock Navigation instances, so
// expo-web-browser is redirected to a no-op stub; react-native-quick-crypto
// is aliased to Node's built-in crypto (API-compatible) so the same
// createPublicKey + createVerify paths exercised on RN also run under Mocha.
import { resolve as resolvePath } from "node:path";
import { pathToFileURL } from "node:url";

const stubs = {
    "expo-web-browser": pathToFileURL(
        resolvePath(import.meta.dirname, "expo-web-browser-stub.mjs")
    ).href,
    "react-native-quick-crypto": pathToFileURL(
        resolvePath(import.meta.dirname, "rnqc-stub.mjs")
    ).href
};

export function resolve(specifier, context, nextResolve) {
    const stubUrl = stubs[specifier];
    if (stubUrl) {
        return { url: stubUrl, format: "module", shortCircuit: true };
    }
    return nextResolve(specifier, context);
}
