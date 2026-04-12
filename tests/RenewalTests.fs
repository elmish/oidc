module Tests.RenewalTests

open Fable.Mocha
open Elmish.OIDC
open Elmish.OIDC.Types
open Tests.Helpers

let tests = testList "Renewal" [

    testCaseAsync "Renewal.browser returns error when silentRedirectUri is not configured" <|
        async {
            let opts = { testOptions with silentRedirectUri = None }
            let storage = MemoryStorage() :> Storage
            let jwks : Jwks = { keys = [] }
            let plt = testPlatform storage
            let! result = plt.renewal.renew testDiscoveryDoc opts jwks storage
            match result with
            | Error (InvalidToken msg) ->
                Expect.isTrue (msg.Contains("silentRedirectUri")) "should mention silentRedirectUri"
            | Error _ ->
                failwith "should be InvalidToken error"
            | Ok _ ->
                failwith "should fail when silentRedirectUri is None"
        }
]
