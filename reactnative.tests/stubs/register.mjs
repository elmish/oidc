// Registers the ESM loader hook that redirects `expo-web-browser` to
// a local test stub. Loaded via mocha's --import flag.
import { register } from "node:module";
import { pathToFileURL } from "node:url";

register("./loader.mjs", pathToFileURL(import.meta.filename));
