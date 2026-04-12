[<RequireQualifiedAccess>]
module Elmish.OIDC.ReactNativeRenewal

open System
open Elmish.OIDC.Types

let private nowEpoch () : int64 =
    DateTimeOffset.UtcNow.ToUnixTimeSeconds()

/// Renewal strategy using refresh_token grant.
let refreshToken (platform: Platform) =
    { new RenewalStrategy with
        member _.renew doc opts jwks storage =
            async {
                match Storage.loadSession storage with
                | None ->
                    return Error (InvalidToken "No stored session to renew")
                | Some storedResponse ->
                    match storedResponse.refreshToken with
                    | None ->
                        return Error (InvalidToken "No refresh token available")
                    | Some rt ->
                        try
                            let! response = Token.exchangeRefreshToken platform doc opts.clientId rt
                            let! result = Token.revalidateStoredToken platform opts (nowEpoch ()) response.idToken jwks
                            match result with
                            | Ok payload -> return Ok (payload, response)
                            | Error err -> return Error (InvalidToken err)
                        with ex ->
                            return Error (NetworkError ex)
            } }
