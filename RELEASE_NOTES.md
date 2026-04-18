### 1.0.0-beta.3

* React Native runtime hardening — validated against Expo Go (Hermes, RN 0.76)
  * RSA verification switched to `react-native-quick-crypto` Node-style API
    (`createPublicKey` + `createVerify`); RNQC v0.7 SubtleCrypto has RSA
    commented out and only ECDSA works there
  * `ReactNative.ensureCrypto ()` helper — actionable error when the
    Web Crypto polyfill isn't installed
* Pure F# `Crypto.Base64Url` and `Crypto.Utf8` — no longer depend on
  `btoa`/`atob` or `TextEncoder`/`TextDecoder`; `TextDecoder` only landed
  in Hermes in RN 0.85 (not yet shipped), so this was a latent crash on
  current React Native / Expo SDK when decoding JWT header/payload JSON
* **Breaking:** `EncodingProvider` removed from `Platform`; `Jwt.decode`
  and `CodeChallenge.compute` no longer take an encoding provider
* ESLint flat config + suppressions baseline guarding the Fable-compiled
  RN output against mobile-unsafe APIs (`subtle.digest`, `TextDecoder`,
  `String.fromCharCode.apply`, `require`, `eval`)

### 1.0.0-beta.2

* Multi-platform support — platform abstraction layer for Browser, .NET, and React Native
* New packages: `Elmish.OIDC` (.NET/WPF/MAUI) and `Fable.Elmish.OIDC.ReactNative` (Expo/RN)
* .NET platform: `System.Security.Cryptography` RSA/SHA256, `HttpListener` loopback redirect (RFC 8252), refresh token renewal
* React Native platform: Web Crypto API, `expo-web-browser` auth session + deep link navigation, refresh token renewal
* `Token.exchangeRefreshToken` for refresh_token grant (used by .NET and RN renewal strategies)
* `AuthCallback` message for native platform callback flows (loopback, deep link, auth session)
* Oidc `Api`: `init`, `update`, `subscribe`
* Comprehensive tests across 3 platforms

### 1.0.0-alpha.1

* **Breaking:** Complete rewrite — Authorization Code Flow with PKCE replaces deprecated Implicit Flow
* **Breaking:** Requires Fable 4+, Fable.Elmish 5+, Fable.Browser.Dom 2+, Thoth.Json 6+
* **Breaking:** New type definitions — `Model<'info>`, `Msg<'info>`, `Session<'info>`, `Options` replace old types
* OIDC Discovery — automatic endpoint resolution via `.well-known/openid-configuration` with issuer validation
* Client-side JWT validation — RS256 signature verification via Web Crypto API with configurable algorithm allowlist
* PKCE (RFC 7636) — code_verifier/code_challenge generation using `crypto.getRandomValues` and `crypto.subtle`
* Silent token renewal — hidden iframe with `prompt=none`, postMessage origin validation, 10s timeout
* Elmish subscription — automatic `Tick`-based expiry monitoring when authenticated
* Configurable clock skew tolerance and renewal timing
* Session resume — stored tokens revalidated on page load (signature + expiry, nonce skipped)
* Proper state/nonce separation (independent random values)
* Auth code stripped from URL via `history.replaceState` after callback
* `IStorage` interface with `SessionStorage` and `LocalStorage` implementations
* Consumer-provided `getUserInfo` callback replaces hardcoded decoder
* Public API: `Oidc.init`, `Oidc.update`, `Oidc.subscribe`, `Oidc.tryGetSession`, `Oidc.isAuthenticated`


### 0.1.0-alpha.9

* Initial OIDC release
