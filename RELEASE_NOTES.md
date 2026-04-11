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
