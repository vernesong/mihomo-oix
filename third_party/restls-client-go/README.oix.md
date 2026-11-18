# Local restls-client-go patch

Source: `github.com/metacubex/restls-client-go@v0.1.9`

Use atomic counters for record sequence numbers that are also read by opposite-direction debug logging. Protocol framing, authentication and script behavior are unchanged.

The root module selects this copy with a local `replace`. Runtime source, module metadata and licenses are retained. Upstream tests, fixtures, examples, illustrations and contribution guides are omitted; project integration tests cover this dependency. Compare against the pinned module before updating; remove this replacement once an upstream version contains an equivalent fix and the regression tests pass.

Verification from the repository root:

```sh
SKIP_INTEROP_TEST=1 SKIP_CONCURRENT_TEST=1 go test -race ./listener/inbound -run Restls
```
