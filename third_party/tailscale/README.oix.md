# Local Tailscale patch

Source: `github.com/metacubex/tailscale v0.0.0-20260821153257-ff0ecd818181`, upstream commit
`ff0ecd81818198276db45f60d6912b4ef518fac4`, module checksum
`h1:hWsSSzuCHe+WvPV1zhoJ8gXTXbp/5nhpPKxtpqgIXu0=`.
The module is copied unchanged from the Go module cache, with its sources, tests and license.
The root `go.mod` replaces this dependency.

The only runtime change is in `derp/derphttp/derphttp_client.go`: `DialRegionTLS` closes the
connection when it fails. When STUN gets no answer, netcheck measures every DERP region over
HTTPS through this function. A handshake that fails (reset, EOF, refused certificate) used to
leave the socket open. Upstream Tailscale dials these probes with a plain `net.Dialer`, so a
finalizer eventually reclaims the socket. This fork routes them through `tsdial.Dialer.SystemDial`,
which keeps each connection in `activeSysConns` until it is closed, so the socket stayed open
for the life of the session and grew with every netcheck.

`derp/derphttp/dialregion_close_test.go` is the added regression:

```sh
go test -race -count=1 -run '^TestDialRegionTLSClosesConnOnFailure$' github.com/metacubex/tailscale/derp/derphttp
```

Retire this local replacement when a compatible upstream release includes the fix.
