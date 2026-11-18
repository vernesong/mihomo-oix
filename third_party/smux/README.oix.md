# Local smux patch

Source: `github.com/metacubex/smux@v0.0.0-20260105030934-d0c8756d3141`

Copy frame payloads before handing them to the asynchronous sender. A timeout or session close can return before the sender finishes with the payload, so it must not retain caller-owned bytes. This adds one payload allocation/copy per data frame.

The root module selects this copy with a local `replace`. Runtime source, module metadata and licenses are retained. Upstream tests, fixtures, examples, illustrations and contribution guides are omitted; project integration tests and the local payload-lifetime regression cover this dependency. Compare against the pinned module before updating; remove this replacement once an upstream version contains an equivalent fix and the regression tests pass.

Verification from the repository root:

```sh
go test -race github.com/metacubex/smux -run TestWriteFramePayloadLifetime
SKIP_INTEROP_TEST=1 SKIP_CONCURRENT_TEST=1 go test -race ./listener/inbound
```
