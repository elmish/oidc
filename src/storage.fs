[<AutoOpen>]
module Elmish.OIDC.Storage

open Fable.Core.JsInterop
open Thoth.Json

type IStorage =
    abstract getItem: string -> string option
    abstract setItem: string -> string -> unit
    abstract removeItem: string -> unit

let SessionStorage =
    { new IStorage with
        member _.getItem key =
            let storage = Browser.Dom.window?sessionStorage
            let value: string = storage?getItem(key)
            if isNullOrUndefined value then None else Some value
        member _.setItem key value =
            let storage = Browser.Dom.window?sessionStorage
            storage?setItem(key, value)
        member _.removeItem key =
            let storage = Browser.Dom.window?sessionStorage
            storage?removeItem(key) }

let LocalStorage =
    { new IStorage with
        member _.getItem key =
            let storage = Browser.Dom.window?localStorage
            let value: string = storage?getItem(key)
            if isNullOrUndefined value then None else Some value
        member _.setItem key value =
            let storage = Browser.Dom.window?localStorage
            storage?setItem(key, value)
        member _.removeItem key =
            let storage = Browser.Dom.window?localStorage
            storage?removeItem(key) }

[<Literal>]
let AuthStateKey = "oidc:auth_state"

[<Literal>]
let SessionKey = "oidc:session"

let private encodeAuthState (authState: AuthState) =
    Encode.object
        [ "state", Encode.string authState.state
          "nonce", Encode.string authState.nonce
          "codeVerifier", Encode.string authState.codeVerifier
          "redirectUri", Encode.string authState.redirectUri ]
    |> Encode.toString 0

let private authStateDecoder: Decoder<AuthState> =
    Decode.object (fun get ->
        { state = get.Required.Field "state" Decode.string
          nonce = get.Required.Field "nonce" Decode.string
          codeVerifier = get.Required.Field "codeVerifier" Decode.string
          redirectUri = get.Required.Field "redirectUri" Decode.string })

let private encodeSession (response: TokenResponse) =
    Encode.object
        [ "accessToken", Encode.string response.accessToken
          "idToken", Encode.string response.idToken
          "tokenType", Encode.string response.tokenType
          "expiresIn", Encode.int response.expiresIn
          "scope", Encode.string response.scope ]
    |> Encode.toString 0

let private sessionDecoder: Decoder<TokenResponse> =
    Decode.object (fun get ->
        { accessToken = get.Required.Field "accessToken" Decode.string
          idToken = get.Required.Field "idToken" Decode.string
          tokenType = get.Required.Field "tokenType" Decode.string
          expiresIn = get.Required.Field "expiresIn" Decode.int
          scope = get.Required.Field "scope" Decode.string })

let saveAuthState (storage: IStorage) (authState: AuthState) =
    storage.setItem AuthStateKey (encodeAuthState authState)

let loadAuthState (storage: IStorage) : AuthState option =
    storage.getItem AuthStateKey
    |> Option.bind (fun json ->
        storage.removeItem AuthStateKey
        match Decode.fromString authStateDecoder json with
        | Ok authState -> Some authState
        | Error _ -> None)

let saveSession (storage: IStorage) (response: TokenResponse) =
    storage.setItem SessionKey (encodeSession response)

let loadSession (storage: IStorage) : TokenResponse option =
    storage.getItem SessionKey
    |> Option.bind (fun json ->
        match Decode.fromString sessionDecoder json with
        | Ok response -> Some response
        | Error _ -> None)

let clearAll (storage: IStorage) =
    storage.removeItem AuthStateKey
    storage.removeItem SessionKey
