namespace Elmish.OIDC

open Elmish.OIDC.Types

module Api =

    let createWith (storage: Storage) (opts: Options) =
        let p =
            { crypto = Browser.crypto
              http = Browser.http
              navigation = Browser.navigation
              renewal = Unchecked.defaultof<RenewalStrategy>
              storage = storage
              timer = Browser.timer }
        let platform = { p with renewal = Renewal.browser p }
        {|
            init = State.init platform opts
            update = State.update platform opts
            subscribe = State.subscribe platform
        |}

    let create (opts: Options) =
        createWith Browser.sessionStorage opts