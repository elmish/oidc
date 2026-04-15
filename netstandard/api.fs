namespace Elmish.OIDC

open Elmish.OIDC.Types

module Api =

    let create (navigation: Navigation) (storage: Storage) (opts: Options) =
        let p =
            { crypto = DotNet.crypto
              encoding = DotNet.encoding
              http = DotNet.http
              navigation = navigation
              renewal = Unchecked.defaultof<RenewalStrategy>
              storage = storage
              timer = DotNet.timer }
        let platform = { p with renewal = Renewal.refreshToken p }
        {|
            init = State.init platform opts
            update = State.update platform opts
            subscribe = State.subscribe platform
        |}

    let createWith (navigation: Navigation) (storage: Storage) (http: HttpClient) (opts: Options) =
        let p =
            { crypto = DotNet.crypto
              encoding = DotNet.encoding
              http = http
              navigation = navigation
              renewal = Unchecked.defaultof<RenewalStrategy>
              storage = storage
              timer = DotNet.timer }
        let platform = { p with renewal = Renewal.refreshToken p }
        {|
            init = State.init platform opts
            update = State.update platform opts
            subscribe = State.subscribe platform
        |}
