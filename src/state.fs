[<AutoOpen>]
module Elmish.OIDC.State

open Types
open Elmish

let init (cmd:Commands<_>) (hash:string option) =
    let model = 
        match hash with
        | Some hash -> Callback hash
        | _ -> Resuming
    model, cmd.loadState()

let update (cmd:Commands<_>) (mkStatus:Status<_>) model msg =
    match model, msg with
    | Callback hash, StateLoaded state -> 
        NewSession state, cmd.parseResponse hash

    | Resuming, StateLoaded state -> 
        NewSession state, cmd.loadResponse()

    | NewSession state, Response response -> 
        Validating, cmd.validateResponse state response 

    | Validating, Response response ->
        Validated response,
        Cmd.batch [ cmd.storeResponse response
                    cmd.getInfo response ]

    | Validated response, UserInfo info ->
        InfoLoaded (response,info), Cmd.none

    | _, LogIn ->
        Unauthenticated, cmd.login()
    
    | _, LogOut ->
        Unauthenticated, cmd.logout()

    | _, NoState
    | _, LoggedOut -> 
        Unauthenticated, Cmd.none

    | _, UserInfoError _ ->
        model, Cmd.none

    | _, ResponseError _ -> 
        Unauthenticated, Cmd.none

    | _, Status _ -> 
        model, Cmd.none

    | _, _ ->
        model, Cmd.ofMsg (sprintf "Invalid operation: %A (in %A state)" msg model |> mkStatus.warn |> Status)

[<Literal>]
let internal StateKey = "oidc:state"

[<Literal>]
let internal ResponseKey = "oidc:response"

/// Default constructor for `init` and `update` functions, and `Commands` API.
/// options: oAuth2/OIDC authorization options
/// mkStatus: constructors for Status messages
/// infoDecoder: Thoth.Json decoder for your 'info type
let mkDefault 
        (opt:Options)
        (mkStatus:Status<'status>)
        (infoDecoder:Thoth.Json.Decode.Decoder<'info>)
        : (string option -> Model<'info>*Cmd<Msg<'status,'info>>)
           * (Model<'info> -> Msg<'status,'info> -> Model<'info>*Cmd<Msg<'status,'info>>)
           * Commands<Msg<'status,'info>> =
    
    let ofResponseResult ok r = 
        match r with
        | Ok response -> ok response
        | Error err -> ResponseError err

    let ofStateOption r = 
        match r with
        | Some state -> StateLoaded state
        | _ -> NoState
    
    let cmd =
        { getInfo = fun response -> 
            Cmd.ofPromise (Authority.Info.get infoDecoder opt.authority) response UserInfo UserInfoError 

          logout = fun _ -> 
            Cmd.ofFunc
                (fun _ -> 
                    Storage.clear StateKey
                    Storage.clear ResponseKey)
                ()
                (fun _ -> LoggedOut)
                (mkStatus.failure >> Status)

          login = fun _ -> 
            Cmd.attemptFunc 
                (fun location ->
                    let state = Response.nextState()
                    Storage.State.set StateKey state
                    Authority.Id.login opt state location)
                Fable.Import.Browser.window.location.href
                (mkStatus.failure >> Status)

          loadResponse = fun _ ->
            Cmd.ofFunc (Storage.Response.get Response.parse) ResponseKey (ofResponseResult Response) (mkStatus.failure >> Status) 

          storeResponse = fun response -> 
            Cmd.attemptFunc (Storage.Response.set Response.concat ResponseKey) response (mkStatus.failure >> Status) 

          parseResponse = fun hash ->
            Cmd.ofFunc Response.parse hash (ofResponseResult Response) (mkStatus.failure >> Status)

          validateResponse = fun state response ->
            Cmd.ofFunc (Response.validate System.DateTime.Now state) response (ofResponseResult ValidToken) (mkStatus.failure >> Status) 

          loadState = fun _ ->
            Cmd.ofFunc Storage.State.get StateKey ofStateOption (mkStatus.failure >> Status) }
    
    init cmd, update cmd mkStatus, cmd    