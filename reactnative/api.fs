namespace Elmish.OIDC

open Elmish
open Elmish.OIDC.Types

module Oidc =

    // Platform-aware API

    let initPlatform (platform: Platform) (opts: Options) : Model<'info> * Cmd<Msg<'info>> =
        State.init platform opts

    let updatePlatform (platform: Platform) (opts: Options) (getUserInfo: string -> string -> Async<'info>) (msg: Msg<'info>) (model: Model<'info>) : Model<'info> * Cmd<Msg<'info>> =
        State.update platform opts getUserInfo msg model

    let subscribePlatform (platform: Platform) (model: Model<'info>) : Sub<Msg<'info>> =
        match model with
        | Ready (_, _, Authenticated _)
        | Ready (_, _, Renewing _) ->
            [ ["oidc"; "renewal"], Renewal.expirySubscription platform.timer ]
        | _ -> []

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
