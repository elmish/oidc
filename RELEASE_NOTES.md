### 1.0.0-alpha.3

* Multi-platform support — platform abstraction layer for Browser, .NET, and React Native
* New packages: `Elmish.OIDC` (.NET/WPF/MAUI) and `Fable.Elmish.OIDC.ReactNative` (Expo/RN)
* .NET platform: `System.Security.Cryptography` RSA/SHA256, `HttpListener` loopback redirect (RFC 8252), refresh token renewal
* React Native platform: Web Crypto API, `expo-web-browser` auth session + deep link navigation, refresh token renewal
* Platform-aware API: `Oidc.initPlatform`, `Oidc.updatePlatform`, `Oidc.subscribePlatform`
* `Token.exchangeRefreshToken` for refresh_token grant (used by .NET and RN renewal strategies)
* `AuthCallback` message for native platform callback flows (loopback, deep link, auth session)
* Browser backward-compatible API preserved: `Oidc.init`, `Oidc.update`, `Oidc.subscribe`
* 189 tests across 3 platforms (61 browser, 66 .NET, 62 React Native)

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
