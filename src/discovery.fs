[<RequireQualifiedAccess>]
module Elmish.OIDC.Discovery

open Elmish.OIDC.Types

#if FABLE_COMPILER
open Thoth.Json
#else
open Thoth.Json.Net
#endif

let private decoder : Decoder<DiscoveryDocument> =
    Decode.object (fun get ->
        { issuer = get.Required.Field "issuer" Decode.string
          authorizationEndpoint = get.Required.Field "authorization_endpoint" Decode.string
          tokenEndpoint = get.Required.Field "token_endpoint" Decode.string
          userinfoEndpoint = get.Required.Field "userinfo_endpoint" Decode.string
          jwksUri = get.Required.Field "jwks_uri" Decode.string
          endSessionEndpoint = get.Optional.Field "end_session_endpoint" Decode.string })

let fetch (http: HttpClient) (authority: string) : Async<DiscoveryDocument> =
    let authority = authority.TrimEnd('/')
    let url = authority + "/.well-known/openid-configuration"

    async {
        let! text = http.getText url
        match Decode.fromString decoder text with
        | Ok doc -> return doc
        | Error err ->
            return failwith $"Failed to decode discovery document: {err}"
    }
