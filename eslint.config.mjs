// Flat ESLint config guarding the React Native-compiled output against
// APIs that are not available in the Hermes / React Native runtime.
//
// Fable [<Emit(...)>] calls compile to inline JS expressions, so we lint
// the generated JS under reactnative.tests/out/reactnative/ to catch
// accidental use of browser-only globals or unsupported crypto paths.
//
// Scope: library code only. Test helpers intentionally use crypto.subtle
// (key generation / signing) as a trusted test harness on Node.js.

const reactNativeMissingApis = [
    {
        // Flag `globalThis.crypto.subtle.*` — not available in the default
        // React Native runtime. Requires react-native-quick-crypto polyfill.
        selector:
            "MemberExpression[object.type='MemberExpression'][object.object.name='globalThis'][object.property.name='crypto'][property.name='subtle']",
        message:
            "globalThis.crypto.subtle is not available in the default React Native runtime. Install react-native-quick-crypto and register its polyfill at the app entry point. Library callers of this path must go through Elmish.OIDC.ReactNative.ensureCrypto () first."
    },
    {
        // Flag `String.fromCharCode.apply(null, <anything>)`. Hermes enforces a
        // much lower argument-count limit on Function.prototype.apply than V8/JSC,
        // so this pattern throws RangeError for typical JWT/JWKS payloads.
        // Use a chunked loop over subarray slices, or TextDecoder/atob/btoa directly.
        selector:
            "CallExpression[callee.type='MemberExpression'][callee.property.name='apply'][callee.object.type='MemberExpression'][callee.object.object.name='String'][callee.object.property.name='fromCharCode']",
        message:
            "String.fromCharCode.apply(null, bytes) is unsafe on Hermes — it enforces a low argument-count limit on Function.prototype.apply and throws RangeError for non-trivial byte arrays. Chunk the input in slices of 0x8000 or smaller."
    },
    {
        // Flag `subtle.verify('RSASSA-PKCS1-v1_5', ...)` and similar — the bare
        // string form is normalized by browsers/Node.js but rejected by
        // react-native-quick-crypto. Use the object form {name: '...'}.
        selector:
            "CallExpression[callee.type='MemberExpression'][callee.property.name='verify'][callee.object.property.name='subtle'] > Literal:first-child",
        message:
            "subtle.verify/sign/encrypt expect an algorithm object like {name: 'RSASSA-PKCS1-v1_5'}, not a bare string. react-native-quick-crypto rejects the string form even though browsers and Node.js normalize it."
    }
];

const browserOnlyGlobals = [
    { name: "window", message: "window is not available in React Native. Use React Native / Expo APIs instead." },
    { name: "document", message: "document is not available in React Native." },
    { name: "localStorage", message: "localStorage is not available in React Native. Use AsyncStorage or similar." },
    { name: "sessionStorage", message: "sessionStorage is not available in React Native." },
    { name: "location", message: "location is not available in React Native. Use expo-linking / expo-web-browser." },
    { name: "history", message: "history is not available in React Native." }
];

export default [
    {
        files: ["reactnative.tests/out/reactnative/**/*.js"],
        languageOptions: {
            ecmaVersion: "latest",
            sourceType: "module"
        },
        rules: {
            "no-restricted-syntax": ["error", ...reactNativeMissingApis],
            "no-restricted-globals": ["error", ...browserOnlyGlobals]
        }
    }
];
