[<RequireQualifiedAccess>]
module Elmish.OIDC.Renewal

open Elmish.OIDC.Types
open System

let private nowEpoch () : int64 =
    DateTimeOffset.UtcNow.ToUnixTimeSeconds()

let expirySubscription (timer: TimerProvider) (dispatch: Msg<'info> -> unit) : IDisposable =
    timer.createInterval (fun () -> dispatch Tick) 30000
