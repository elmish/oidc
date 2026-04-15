[<RequireQualifiedAccess>]
module Elmish.OIDC.Renewal

open Elmish.OIDC.Types
open System

let private nowEpoch () : int64 =
    DateTimeOffset.UtcNow.ToUnixTimeSeconds()

let expirySubscription (timer: TimerProvider) (dispatch: Msg<'info> -> unit) : IDisposable =
    timer.createInterval (fun () -> dispatch Tick) 30000

/// Renewal strategy using refresh_token grant.
let refreshToken (platform: Platform) =
    { new RenewalStrategy with
        member _.renew doc opts jwks storage =
            async {
                match Storage.StoredSession.load storage with
                | None ->
                    return Error (InvalidToken "No stored session to renew")
                | Some storedResponse ->
                    match storedResponse.refreshToken with
                    | None ->
                        return Error (InvalidToken "No refresh token available")
                    | Some rt ->
                        try
                            let! response = Token.RefreshToken.exchange platform doc opts.clientId rt
                            let! result = Token.IdToken.revalidateStored platform opts (nowEpoch ()) jwks response.idToken
                            match result with
                            | Ok payload -> return Ok (payload, response)
                            | Error err -> return Error (InvalidToken err)
                        with ex ->
                            return Error (NetworkError ex)
            } }
