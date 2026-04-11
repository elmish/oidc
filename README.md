Elmish-OIDC
=======
[Authorization Code Flow with PKCE](https://oauth.net/2/pkce/) component for [Elmish](https://github.com/elmish/elmish) applications.

Requires HTTPS (or localhost) — uses the [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API) for PKCE challenge generation and JWT signature verification.

## Features

- **Authorization Code + PKCE** (OAuth 2.1) — Implicit Flow is not supported
- **OIDC Discovery** — endpoints resolved automatically from `.well-known/openid-configuration`
- **Client-side JWT validation** — RS256 signature verification, issuer/audience/expiry/nonce claim checks
- **Silent token renewal** — hidden iframe with `prompt=none`, automatic expiry monitoring via Elmish subscription
- **Session resume** — stored tokens revalidated on page load
- **Configurable** — clock skew tolerance, algorithm allowlist, custom storage, renewal timing

## Requirements

- Fable 4+
- Fable.Elmish 5+
- Fable.Browser.Dom 2+
- Thoth.Json 6+

## Installation

```shell
dotnet add package Fable.Elmish.OIDC
```

## Usage

### Configuration

```fsharp
let oidcOptions : Elmish.OIDC.Types.Options =
    { clientId = "my-app"
      authority = "https://idp.example.com"
      scopes = [ "openid"; "profile"; "email" ]
      redirectUri = "https://myapp.com/callback"
      postLogoutRedirectUri = Some "https://myapp.com"
      silentRedirectUri = Some "https://myapp.com/silent-renew.html"
      renewBeforeExpirySeconds = 300
      clockSkewSeconds = 300
      allowedAlgorithms = [ "RS256" ] }
```

### Integration

```fsharp
open Elmish
open Elmish.OIDC

type UserInfo = { name: string; email: string }

type Model = { oidc: Model<UserInfo>; (* your app state *) }
type Msg = OidcMsg of Msg<UserInfo> | (* your app messages *)

let getUserInfo (userinfoEndpoint: string) (accessToken: string) : Fable.Core.JS.Promise<UserInfo> =
    // fetch userinfoEndpoint with Bearer accessToken, decode the response
    failwith "implement"

let init () =
    let oidcModel, oidcCmd = Oidc.init oidcOptions
    { oidc = oidcModel }, Cmd.map OidcMsg oidcCmd

let update msg model =
    match msg with
    | OidcMsg m ->
        let m', c = Oidc.update oidcOptions getUserInfo m model.oidc
        { model with oidc = m' }, Cmd.map OidcMsg c
    | (* handle your messages *)

let subscribe model =
    Oidc.subscribe model.oidc |> Sub.map "oidc" OidcMsg

let view model dispatch =
    match Oidc.tryGetSession model.oidc with
    | Some session ->
        // authenticated — session.accessToken, session.claims, session.userInfo available
        // dispatch (OidcMsg LogOut) to log out
        ()
    | None ->
        // not authenticated — dispatch (OidcMsg LogIn) to start login
        ()
```

### Silent Renewal

For silent token renewal, host a page at your `silentRedirectUri` with:

```html
<!DOCTYPE html>
<html>
<body>
<script>parent.postMessage(location.search, location.origin)</script>
</body>
</html>
```

### API

| Function | Signature | Description |
|---|---|---|
| `Oidc.init` | `Options -> Model<'info> * Cmd<Msg<'info>>` | Initialize with session storage |
| `Oidc.initWith` | `Options -> IStorage -> Model<'info> * Cmd<Msg<'info>>` | Initialize with custom storage |
| `Oidc.update` | `Options -> (string -> string -> Promise<'info>) -> Msg<'info> -> Model<'info> -> Model<'info> * Cmd<Msg<'info>>` | Update with session storage |
| `Oidc.updateWith` | `Options -> IStorage -> (string -> string -> Promise<'info>) -> Msg<'info> -> Model<'info> -> Model<'info> * Cmd<Msg<'info>>` | Update with custom storage |
| `Oidc.subscribe` | `Model<'info> -> Sub<Msg<'info>>` | Renewal timer subscription |
| `Oidc.tryGetSession` | `Model<'info> -> Session<'info> option` | Get session if authenticated |
| `Oidc.isAuthenticated` | `Model<'info> -> bool` | Check auth status |
| `Oidc.tryGetAccessToken` | `Model<'info> -> string option` | Get access token |

### Messages

The consumer dispatches `LogIn` and `LogOut`. All other messages are internal:

| Message | Trigger |
|---|---|
| `LogIn` | User initiates login — redirects to IdP |
| `LogOut` | User initiates logout — clears session, redirects to end session endpoint |
