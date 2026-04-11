module Tests.RenewalTests

open Fable.Mocha
open Fable.Core
open Elmish.OIDC
open Tests.Helpers

let tests = testList "Renewal" [

    testCaseAsync "silentRenew returns error when silentRedirectUri is not configured" <|
        async {
            let opts = { testOptions with silentRedirectUri = None }
            let storage = MemoryStorage() :> IStorage
            let jwks : Jwks = { keys = [] }
            let! result = silentRenew testDiscoveryDoc opts jwks storage |> Async.AwaitPromise
            match result with
            | Error (InvalidToken msg) ->
                Expect.isTrue (msg.Contains("silentRedirectUri")) "should mention silentRedirectUri"
            | Error _ ->
                failwith "should be InvalidToken error"
            | Ok _ ->
                failwith "should fail when silentRedirectUri is None"
        }
]
