Elmish-OIDC
=======
[![Build](https://github.com/elmish/OIDC/actions/workflows/ci.yml/badge.svg)](https://github.com/elmish/OIDC/actions/workflows/ci.yml)
[![NuGet](https://img.shields.io/nuget/v/Fable.Elmish.OIDC.svg)](https://www.nuget.org/packages/Fable.Elmish.OIDC)

[Authorization Code Flow with PKCE](https://oauth.net/2/pkce/) component for [Elmish](https://github.com/elmish/elmish) applications — **browser, .NET, and React Native**.

## Packages

| Package | Platform | NuGet |
|---------|----------|-------|
| `Fable.Elmish.OIDC` | Browser (Fable) | [![NuGet](https://img.shields.io/nuget/v/Fable.Elmish.OIDC.svg)](https://www.nuget.org/packages/Fable.Elmish.OIDC) |
| `Elmish.OIDC` | .NET (WPF/MAUI) | [![NuGet](https://img.shields.io/nuget/v/Elmish.OIDC.svg)](https://www.nuget.org/packages/Elmish.OIDC) |
| `Fable.Elmish.OIDC.ReactNative` | React Native (Expo/Fable) | [![NuGet](https://img.shields.io/nuget/v/Fable.Elmish.OIDC.ReactNative.svg)](https://www.nuget.org/packages/Fable.Elmish.OIDC.ReactNative) |

## Features

- **Authorization Code + PKCE** (OAuth 2.1) — Implicit Flow is not supported
- **OIDC Discovery** — endpoints resolved automatically from `.well-known/openid-configuration`
- **Client-side JWT validation** — RS256 signature verification, issuer/audience/expiry/nonce claim checks
- **Silent token renewal** — iframe (browser), refresh token (native)
- **Session resume** — stored tokens revalidated on app start
- **Configurable** — clock skew tolerance, algorithm allowlist, custom storage, renewal timing

## Installation

```shell
# Browser (Fable)
dotnet add package Fable.Elmish.OIDC

# .NET (WPF/MAUI)
dotnet add package Elmish.OIDC

# React Native (Expo)
dotnet add package Fable.Elmish.OIDC.ReactNative
```

## Usage

### Configuration

```fsharp
open Elmish.OIDC.Types

let oidcOptions : Options =
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

### Browser (Fable)

Uses the convenience API — platform is created automatically with Web Crypto and iframe renewal.

```fsharp
open Elmish
open Elmish.OIDC

type Model = { oidc: Model<UserInfo> }
type Msg = OidcMsg of Msg<UserInfo>

let init () =
    let m, c = Oidc.init oidcOptions
    { oidc = m }, Cmd.map OidcMsg c

let update msg model =
    match msg with
    | OidcMsg m ->
        let m', c = Oidc.update oidcOptions getUserInfo m model.oidc
        { model with oidc = m' }, Cmd.map OidcMsg c

let subscribe model =
    Oidc.subscribe model.oidc |> Sub.map "oidc" OidcMsg
```

Host a silent renewal page at `silentRedirectUri`:

```html
<!DOCTYPE html>
<html><body>
<script>parent.postMessage(location.search, location.origin)</script>
</body></html>
```

### .NET (WPF/MAUI)

Uses the platform-aware API with loopback redirect ([RFC 8252](https://tools.ietf.org/html/rfc8252)) and refresh token renewal.

```fsharp
open Elmish
open Elmish.OIDC
open Elmish.OIDC.Types

let nav = DotNetNavigation.loopback 8912
let storage = DotNet.memoryStorage ()

let platform =
    let p = { crypto = DotNet.crypto; encoding = DotNet.encoding
              http = DotNet.http; navigation = nav
              renewal = Unchecked.defaultof<RenewalStrategy>
              storage = storage; timer = DotNet.timer }
    { p with renewal = DotNetRenewal.refreshToken p }

let init () =
    let m, c = Oidc.initPlatform platform oidcOptions
    { oidc = m }, Cmd.map OidcMsg c

let update msg model =
    match msg with
    | OidcMsg m ->
        let m', c = Oidc.updatePlatform platform oidcOptions getUserInfo m model.oidc
        { model with oidc = m' }, Cmd.map OidcMsg c

let subscribe model =
    Oidc.subscribePlatform platform model.oidc |> Sub.map "oidc" OidcMsg
```

### React Native (Expo)

Uses `expo-web-browser` for in-app authentication and refresh token renewal.

```fsharp
open Elmish
open Elmish.OIDC
open Elmish.OIDC.Types

let nav = ReactNativeNavigation.authSession oidcOptions.redirectUri
let storage = ReactNative.memoryStorage ()

let platform =
    let p = { crypto = ReactNative.crypto; encoding = ReactNative.encoding
              http = ReactNative.http; navigation = nav
              renewal = Unchecked.defaultof<RenewalStrategy>
              storage = storage; timer = ReactNative.timer }
    { p with renewal = ReactNativeRenewal.refreshToken p }

let init () =
    let m, c = Oidc.initPlatform platform oidcOptions
    { oidc = m }, Cmd.map OidcMsg c

let update msg model =
    match msg with
    | OidcMsg m ->
        let m', c = Oidc.updatePlatform platform oidcOptions getUserInfo m model.oidc
        { model with oidc = m' }, Cmd.map OidcMsg c

let subscribe model =
    Oidc.subscribePlatform platform model.oidc |> Sub.map "oidc" OidcMsg
```

### API

#### Platform-aware (all platforms)

| Function | Description |
|---|---|
| `Oidc.initPlatform platform opts` | Initialize with explicit platform |
| `Oidc.updatePlatform platform opts getUserInfo msg model` | Update with explicit platform |
| `Oidc.subscribePlatform platform model` | Renewal timer subscription |

#### Browser convenience (backward compat)

| Function | Description |
|---|---|
| `Oidc.init opts` | Initialize with browser defaults |
| `Oidc.update opts getUserInfo msg model` | Update with browser defaults |
| `Oidc.subscribe model` | Renewal timer subscription |

#### Model queries (all platforms)

| Function | Description |
|---|---|
| `Oidc.tryGetSession model` | Get session if authenticated |
| `Oidc.isAuthenticated model` | Check auth status |
| `Oidc.tryGetAccessToken model` | Get access token |

### Messages

| Message | Trigger |
|---|---|
| `LogIn` | User initiates login — redirects to IdP |
| `LogOut` | User initiates logout — clears session |

## Project structure

Shared source files live in `src/` and are symlinked into platform-specific directories (`netstandard/`, `reactnative/`). This ensures Fable's NuGet package cracker resolves sources correctly when consuming packages.

```
src/              — shared sources (types, crypto, discovery, token, etc.)
netstandard/      — .NET platform (symlinks to src/ + dotnet-specific files)
reactnative/      — React Native platform (symlinks to src/ + RN-specific files)
```

Symlinks are checked into git (via `.gitattributes`). On a fresh clone they should work on macOS/Linux. On Windows, enable Developer Mode or run `git config core.symlinks true` before cloning.
