namespace Elmish.OIDC

open Elmish

module Oidc =

    let createBrowserPlatform () : Platform =
        let platform =
            { crypto = BrowserCrypto
              encoding = BrowserEncoding
              http = BrowserHttp
              navigation = BrowserNavigation
              renewal = Unchecked.defaultof<IRenewalStrategy>
              storage = BrowserSessionStorage
              timer = BrowserTimer }
        { platform with renewal = BrowserRenewal platform }

    let createBrowserPlatformWith (storage: IStorage) : Platform =
        let platform =
            { crypto = BrowserCrypto
              encoding = BrowserEncoding
              http = BrowserHttp
              navigation = BrowserNavigation
              renewal = Unchecked.defaultof<IRenewalStrategy>
              storage = storage
              timer = BrowserTimer }
        { platform with renewal = BrowserRenewal platform }

    // Platform-aware API

    let initPlatform (platform: Platform) (opts: Options) : Model<'info> * Cmd<Msg<'info>> =
        State.init platform opts

    let updatePlatform (platform: Platform) (opts: Options) (getUserInfo: string -> string -> Async<'info>) (msg: Msg<'info>) (model: Model<'info>) : Model<'info> * Cmd<Msg<'info>> =
        State.update platform opts getUserInfo msg model

    let subscribePlatform (platform: Platform) (model: Model<'info>) : Sub<Msg<'info>> =
        match model with
        | Ready (_, _, Authenticated _)
        | Ready (_, _, Renewing _) ->
            [ ["oidc"; "renewal"], tokenExpirySubscription platform.timer ]
        | _ -> []

    // Browser convenience API (backward compat)

    let init (opts: Options) : Model<'info> * Cmd<Msg<'info>> =
        initPlatform (createBrowserPlatform ()) opts

    let initWith (opts: Options) (storage: IStorage) : Model<'info> * Cmd<Msg<'info>> =
        initPlatform (createBrowserPlatformWith storage) opts

    let update (opts: Options) (getUserInfo: string -> string -> Async<'info>) (msg: Msg<'info>) (model: Model<'info>) : Model<'info> * Cmd<Msg<'info>> =
        updatePlatform (createBrowserPlatform ()) opts getUserInfo msg model

    let updateWith (opts: Options) (storage: IStorage) (getUserInfo: string -> string -> Async<'info>) (msg: Msg<'info>) (model: Model<'info>) : Model<'info> * Cmd<Msg<'info>> =
        updatePlatform (createBrowserPlatformWith storage) opts getUserInfo msg model

    let subscribe (model: Model<'info>) : Sub<Msg<'info>> =
        subscribePlatform (createBrowserPlatform ()) model

    // Model query helpers (platform-independent)

    let tryGetSession (model: Model<'info>) : Session<'info> option =
        match model with
        | Ready (_, _, Authenticated session)
        | Ready (_, _, Renewing session) -> Some session
        | _ -> None

    let isAuthenticated (model: Model<'info>) : bool =
        tryGetSession model |> Option.isSome

    let tryGetAccessToken (model: Model<'info>) : string option =
        tryGetSession model |> Option.map (fun s -> s.accessToken)

