[<RequireQualifiedAccess>]
module Elmish.OIDC.Storage

open Elmish.OIDC.Types

#if FABLE_COMPILER
open Thoth.Json
#else
open Thoth.Json.Net
#endif

module AuthState =

    [<Literal>]
    let Key = "oidc:auth_state"

    let private encode (authState: AuthState) =
        Encode.object
            [ "state", Encode.string authState.state
              "nonce", Encode.string authState.nonce
              "codeVerifier", Encode.string authState.codeVerifier
              "redirectUri", Encode.string authState.redirectUri ]
        |> Encode.toString 0

    let private decoder: Decoder<AuthState> =
        Decode.object (fun get ->
            { state = get.Required.Field "state" Decode.string
              nonce = get.Required.Field "nonce" Decode.string
              codeVerifier = get.Required.Field "codeVerifier" Decode.string
              redirectUri = get.Required.Field "redirectUri" Decode.string })

    let save (storage: Storage) (authState: AuthState) =
        storage.setItem Key (encode authState)

    let load (storage: Storage) : AuthState option =
        storage.getItem Key
        |> Option.bind (fun json ->
            storage.removeItem Key
            match Decode.fromString decoder json with
            | Ok authState -> Some authState
            | Error _ -> None)

module StoredSession =

    [<Literal>]
    let Key = "oidc:session"

    let private encode (response: TokenResponse) =
        Encode.object
            [ "accessToken", Encode.string response.accessToken
              "idToken", Encode.string response.idToken
              "tokenType", Encode.string response.tokenType
              "expiresIn", Encode.int response.expiresIn
              "scope", Encode.string response.scope
              yield! (match response.refreshToken with
                      | Some rt -> [ "refreshToken", Encode.string rt ]
                      | None -> []) ]
        |> Encode.toString 0

    let private decoder: Decoder<TokenResponse> =
        Decode.object (fun get ->
            { accessToken = get.Required.Field "accessToken" Decode.string
              idToken = get.Required.Field "idToken" Decode.string
              tokenType = get.Required.Field "tokenType" Decode.string
              expiresIn = get.Required.Field "expiresIn" Decode.int
              scope = get.Required.Field "scope" Decode.string
              refreshToken = get.Optional.Field "refreshToken" Decode.string })

    let save (storage: Storage) (response: TokenResponse) =
        storage.setItem Key (encode response)

    let load (storage: Storage) : TokenResponse option =
        storage.getItem Key
        |> Option.bind (fun json ->
            match Decode.fromString decoder json with
            | Ok response -> Some response
            | Error _ -> None)

let clearAll (storage: Storage) =
    storage.removeItem AuthState.Key
    storage.removeItem StoredSession.Key
