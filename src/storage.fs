[<AutoOpen>]
module Elmish.OIDC.Storage

open Thoth.Json

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
          "scope", Encode.string response.scope
          yield! (match response.refreshToken with
                  | Some rt -> [ "refreshToken", Encode.string rt ]
                  | None -> []) ]
    |> Encode.toString 0

let private sessionDecoder: Decoder<TokenResponse> =
    Decode.object (fun get ->
        { accessToken = get.Required.Field "accessToken" Decode.string
          idToken = get.Required.Field "idToken" Decode.string
          tokenType = get.Required.Field "tokenType" Decode.string
          expiresIn = get.Required.Field "expiresIn" Decode.int
          scope = get.Required.Field "scope" Decode.string
          refreshToken = get.Optional.Field "refreshToken" Decode.string })

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
