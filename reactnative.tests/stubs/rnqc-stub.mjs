// Node.js test-time shim for `react-native-quick-crypto`.
// The library is a near drop-in replacement for Node's `crypto` module, so in
// Node tests we alias the specifier to the built-in. This lets the same
// createPublicKey + createVerify code path exercised on React Native also run
// under Mocha without installing the native module.
export * from "node:crypto";
import crypto from "node:crypto";
export default crypto;
