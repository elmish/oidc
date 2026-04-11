[<AutoOpen>]
module Elmish.OIDC.Discovery

open Fable.Core
open Thoth.Json

let private discoveryDecoder : Decoder<DiscoveryDocument> =
    Decode.object (fun get ->
        { issuer = get.Required.Field "issuer" Decode.string
          authorizationEndpoint = get.Required.Field "authorization_endpoint" Decode.string
          tokenEndpoint = get.Required.Field "token_endpoint" Decode.string
          userinfoEndpoint = get.Required.Field "userinfo_endpoint" Decode.string
          jwksUri = get.Required.Field "jwks_uri" Decode.string
          endSessionEndpoint = get.Optional.Field "end_session_endpoint" Decode.string })

let fetchDiscovery (authority: string) : JS.Promise<DiscoveryDocument> =
    let authority = authority.TrimEnd('/')
    let url = authority + "/.well-known/openid-configuration"

    Interop.Http.get url
    |> Promise.bind (fun response -> response.text())
    |> Promise.map (fun text ->
        match Decode.fromString discoveryDecoder text with
        | Ok doc ->
            if doc.issuer <> authority then
                failwith $"Issuer mismatch: expected '{authority}' but got '{doc.issuer}'"
            doc
        | Error err ->
            failwith $"Failed to decode discovery document: {err}")
