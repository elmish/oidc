module Elmish.OIDC

open Fable.Core
open Elmish

module Oidc =

    let init (opts: Options) : Model<'info> * Cmd<Msg<'info>> =
        State.init opts SessionStorage

    let initWith (opts: Options) (storage: IStorage) : Model<'info> * Cmd<Msg<'info>> =
        State.init opts storage

    let update (opts: Options) (getUserInfo: string -> string -> JS.Promise<'info>) (msg: Msg<'info>) (model: Model<'info>) : Model<'info> * Cmd<Msg<'info>> =
        State.update opts SessionStorage getUserInfo msg model

    let updateWith (opts: Options) (storage: IStorage) (getUserInfo: string -> string -> JS.Promise<'info>) (msg: Msg<'info>) (model: Model<'info>) : Model<'info> * Cmd<Msg<'info>> =
        State.update opts storage getUserInfo msg model

    let subscribe (model: Model<'info>) : Sub<Msg<'info>> =
        match model with
        | Ready (_, _, Authenticated _)
        | Ready (_, _, Renewing _) ->
            [ ["oidc"; "renewal"], tokenExpirySubscription ]
        | _ -> []

    let tryGetSession (model: Model<'info>) : Session<'info> option =
        match model with
        | Ready (_, _, Authenticated session)
        | Ready (_, _, Renewing session) -> Some session
        | _ -> None

    let isAuthenticated (model: Model<'info>) : bool =
        tryGetSession model |> Option.isSome

    let tryGetAccessToken (model: Model<'info>) : string option =
        tryGetSession model |> Option.map (fun s -> s.accessToken)

