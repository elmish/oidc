module Tests.Main

open Fable.Mocha

let allTests = testList "All" [
    CryptoTests.tests
    TokenTests.tests
    DiscoveryTests.tests
    StorageTests.tests
    StateTests.tests
    RenewalTests.tests
]

[<EntryPoint>]
let main _ = Mocha.runTests allTests
