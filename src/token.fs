[<RequireQualifiedAccess>]
module Elmish.OIDC.Token

open Elmish.OIDC.Types

#if FABLE_COMPILER
open Thoth.Json
#else
open Thoth.Json.Net
#endif

let private responseDecoder : Decoder<TokenResponse> =
    Decode.object (fun get ->
        { accessToken = get.Required.Field "access_token" Decode.string
          idToken = get.Required.Field "id_token" Decode.string
          tokenType = get.Required.Field "token_type" Decode.string
          expiresIn = get.Required.Field "expires_in" Decode.int
          scope = get.Required.Field "scope" Decode.string
          refreshToken = get.Optional.Field "refresh_token" Decode.string })

let private errorDecoder : Decoder<string> =
    Decode.object (fun get ->
        let error = get.Required.Field "error" Decode.string
        let desc = get.Optional.Field "error_description" Decode.string
        match desc with
        | Some d -> $"{error}: {d}"
        | None -> error)

module Code =

    let exchange (platform: Platform) (doc: DiscoveryDocument) (clientId: string) (code: string) (codeVerifier: string) (redirectUri: string) : Async<TokenResponse> =
        let encode = platform.navigation.encodeURIComponent
        let body =
            [ "grant_type", "authorization_code"
              "code", code
              "client_id", clientId
              "code_verifier", codeVerifier
              "redirect_uri", redirectUri ]
            |> List.map (fun (k, v) -> $"{encode k}={encode v}")
            |> String.concat "&"

        async {
            let! text = platform.http.postForm doc.tokenEndpoint body
            match Decode.fromString errorDecoder text with
            | Ok errMsg -> return failwith errMsg
            | Error _ ->
                match Decode.fromString responseDecoder text with
                | Ok resp -> return resp
                | Error err -> return failwith $"Failed to decode token response: {err}"
        }

module Jwks =

    let private keyDecoder : Decoder<JwksKey> =
        Decode.object (fun get ->
            { kty = get.Required.Field "kty" Decode.string
              kid = get.Required.Field "kid" Decode.string
              n = get.Required.Field "n" Decode.string
              e = get.Required.Field "e" Decode.string
              alg = get.Optional.Field "alg" Decode.string |> Option.defaultValue "RS256"
              ``use`` = get.Optional.Field "use" Decode.string })

    let private decoder : Decoder<Jwks> =
        Decode.object (fun get ->
            { keys = get.Required.Field "keys" (Decode.list keyDecoder) })

    let fetch (http: HttpClient) (jwksUri: string) : Async<Jwks> =
        async {
            let! text = http.getText jwksUri
            match Decode.fromString decoder text with
            | Ok jwks -> return jwks
            | Error err -> return failwith $"Failed to decode JWKS: {err}"
        }

module RefreshToken =

    let exchange (platform: Platform) (doc: DiscoveryDocument) (clientId: string) (refreshToken: string) : Async<TokenResponse> =
        let encode = platform.navigation.encodeURIComponent
        let body =
            [ "grant_type", "refresh_token"
              "refresh_token", refreshToken
              "client_id", clientId ]
            |> List.map (fun (k, v) -> $"{encode k}={encode v}")
            |> String.concat "&"

        async {
            let! text = platform.http.postForm doc.tokenEndpoint body
            match Decode.fromString errorDecoder text with
            | Ok errMsg -> return failwith errMsg
            | Error _ ->
                match Decode.fromString responseDecoder text with
                | Ok resp -> return resp
                | Error err -> return failwith $"Failed to decode token response: {err}"
        }

module Jwt =

    let private headerDecoder : Decoder<JwtHeader> =
        Decode.object (fun get ->
            { alg = get.Required.Field "alg" Decode.string
              kid = get.Required.Field "kid" Decode.string })

    let private audDecoder : Decoder<string list> =
        Decode.oneOf
            [ Decode.list Decode.string
              Decode.string |> Decode.map (fun s -> [ s ]) ]

    let private payloadDecoder : Decoder<JwtPayload> =
        Decode.object (fun get ->
            { iss = get.Required.Field "iss" Decode.string
              sub = get.Required.Field "sub" Decode.string
              aud = get.Required.Field "aud" audDecoder
              exp = get.Required.Field "exp" Decode.int64
              iat = get.Required.Field "iat" Decode.int64
              nonce = get.Optional.Field "nonce" Decode.string })

    let decode (jwt: string) : Result<JwtHeader * JwtPayload, string> =
        let parts = jwt.Split('.')

        if parts.Length <> 3 then
            Error "JWT must have exactly 3 parts"
        else
            let headerJson = parts.[0] |> Crypto.Base64Url.decode |> Crypto.Utf8.decode
            let payloadJson = parts.[1] |> Crypto.Base64Url.decode |> Crypto.Utf8.decode

            match Decode.fromString headerDecoder headerJson, Decode.fromString payloadDecoder payloadJson with
            | Ok header, Ok payload -> Ok(header, payload)
            | Error err, _ -> Error $"Failed to decode JWT header: {err}"
            | _, Error err -> Error $"Failed to decode JWT payload: {err}"

module Signature =

    let verify (platform: Platform) (alg: string) (key: obj) (jwt: string) : Async<bool> =
        let parts = jwt.Split('.')
        let signedData = parts.[0] + "." + parts.[1]
        let signatureBytes = Crypto.Base64Url.decode parts.[2]
        let dataBytes = Crypto.Utf8.encode signedData
        platform.crypto.rsaVerify alg key signatureBytes dataBytes

module Claims =

    let validate
        (opts: Options)
        (issuer: string)
        (nonce: string option)
        (nowEpoch: int64)
        (header: JwtHeader)
        (payload: JwtPayload)
        : Result<unit, string> =
        if not (opts.allowedAlgorithms |> List.contains header.alg) then
            Error $"Algorithm '{header.alg}' is not allowed. Allowed: {opts.allowedAlgorithms}"
        elif payload.iss <> issuer.TrimEnd('/') then
            Error $"Issuer mismatch: expected '{issuer.TrimEnd('/')}', got '{payload.iss}'"
        elif not (payload.aud |> List.contains opts.clientId) then
            Error $"Audience does not contain '{opts.clientId}'"
        elif payload.exp + int64 opts.clockSkewSeconds <= nowEpoch then
            Error "Token has expired"
        elif payload.iat - int64 opts.clockSkewSeconds > nowEpoch then
            Error "Token issued in the future"
        else
            match nonce with
            | Some n when payload.nonce <> Some n ->
                Error $"Nonce mismatch: expected '{n}'"
            | _ -> Ok()

module IdToken =

    let private validateAndVerify
        (platform: Platform)
        (opts: Options)
        (issuer: string)
        (nonce: string option)
        (nowEpoch: int64)
        (jwks: Jwks)
        (jwt: string)
        : Async<Result<JwtPayload, string>> =
        match Jwt.decode jwt with
        | Error err -> async { return Error err }
        | Ok(header, payload) ->
            match Claims.validate opts issuer nonce nowEpoch header payload with
            | Error err -> async { return Error err }
            | Ok() ->
                match jwks.keys |> List.tryFind (fun k -> k.kid = header.kid && k.``use`` <> Some "enc") with
                | None -> async { return Error $"No signing key found for kid '{header.kid}'" }
                | Some jwkKey ->
                    async {
                        let! cryptoKey = platform.crypto.importRsaKey jwkKey
                        let! valid = Signature.verify platform header.alg cryptoKey jwt
                        if valid then return Ok payload
                        else return Error "Signature verification failed"
                    }

    let validate (platform: Platform) (opts: Options) (issuer: string) (nonce: string) (nowEpoch: int64) (jwks: Jwks) (jwt: string) : Async<Result<JwtPayload, string>> =
        validateAndVerify platform opts issuer (Some nonce) nowEpoch jwks jwt

    let revalidateStored (platform: Platform) (opts: Options) (issuer: string) (nowEpoch: int64) (jwks: Jwks) (jwt: string) : Async<Result<JwtPayload, string>> =
        validateAndVerify platform opts issuer None nowEpoch jwks jwt
