// Test-only stub for expo-web-browser. The unit test suite uses mock
// Navigation instances and never invokes these functions, but the
// compiled module graph imports the symbols, so they must exist.
export const openAuthSessionAsync = () => {
    throw new Error("expo-web-browser stub: openAuthSessionAsync is not callable in tests");
};
export const openBrowserAsync = () => {
    throw new Error("expo-web-browser stub: openBrowserAsync is not callable in tests");
};
