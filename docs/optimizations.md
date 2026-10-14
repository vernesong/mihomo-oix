# Memory optimizations adapted from ProjectClash/Clash

Reference snapshot: [ProjectClash/Clash at 3891cc46092029c23f7fd0bfa1fe29e0e6e1dffb](https://github.com/ProjectClash/Clash/tree/3891cc46092029c23f7fd0bfa1fe29e0e6e1dffb).
Local baseline: `1c10bbc0`.

## Imported ideas and attribution

The adapted code is Copyright (C) 2026 The Clash Authors, licensed under
GPL-3.0-or-later, as recorded in the reference repository's
[NOTICE](https://github.com/ProjectClash/Clash/blob/3891cc46092029c23f7fd0bfa1fe29e0e6e1dffb/NOTICE).
The repository's GPL license is in [LICENSE](../LICENSE).

| Reference implementation | Local adaptation |
| --- | --- |
| `adapter/clash_history.go`, `adapter/clash_proxy_states.go` | Allocate history and the small per-URL state map only when a probe finishes. Use a bounded ring instead of the reference's queue, so insertion and eviction are atomic and steady-state recording does not reallocate the history arrays. |
| `adapter/outbound/clash_sudoku_tables.go` from `0a008c1` | Build immutable Sudoku tables on first use and share them by seed, normalized table type and ordered patterns. Keep only weak references in the global registry. |
| `transport/sudoku/clash_table_spec.go`, `transport/sudoku/obfs/sudoku/clash_table_spec.go` and the validator compatibility test | Validate layout settings before generating tables, preserving configuration-time errors. |
| `common/queue/queue.go` | Check emptiness under the same lock as access. Additionally clear consumed references and release the backing array when empty. |

The local table specification owns a normalized copy of the pattern slice. A
caller changing its options after construction cannot change what is built later
or make the cache key disagree with the generated tables. Concurrent first users
share one construction; different seeds and rotation orders remain isolated.

## Behavior and tradeoffs

- The most recent ten history records remain in insertion order. API history
  snapshots are independent copies and empty histories still serialize as `[]`.
- Unused Sudoku nodes retain settings only. The first use pays the existing table
  construction cost; subsequent uses and other live nodes with the same settings
  reuse the immutable table set. No wire format or cipher construction changes.
- A live node keeps its table set available. Once its owners are unreachable,
  garbage collection can reclaim the set and remove its registry key. This is
  GC-driven reclamation, not immediate eviction when `Close` returns.
- TCP, UDP-over-TCP and multiplex session creation all receive populated tables,
  including multiplex reconnection through the base dialer.

The reference's Apple runtime stack policy, global memory admission limits,
compiled provider/node catalogs, mmap rule formats and vendored dependency
changes were not imported. They depend on a substantially different runtime and
resource lifecycle. Its global TLS session-cache sharing was also left out: this
fork already has explicit standard/uTLS caches and additional CA/ECH settings
that require their own isolation rules. These changes keep the existing public
configuration and upstream integration points intact.

## Local measurements

Measured on Apple M4, darwin/arm64, Go 1.27.1, three repetitions, default build.
These are **allocated bytes per operation**, not process RSS or a production
traffic benchmark. Sudoku construction uses the same key and default table mode
before and after; the old implementation built a fresh table for every node.

| Benchmark | Before, B/op | After, B/op | Allocation count before / after |
| --- | ---: | ---: | ---: |
| New proxy wrapper | 544 | 112 | 3 / 1 |
| Record probe history | 848 | 720 | 4 / 4 |
| Copy ten history records | 1,280 | 320 | 5 / 1 |
| Construct unused Sudoku node | 1,035,681–1,036,042 | 2,224 | 3,532 / 15 |

The recording benchmark uses an invalid URL to avoid network effects. Its
remaining allocations are URL parsing and escaped metadata; an allocation
profile confirmed that the two history arrays are allocated only on first use.

Reproduce on the same toolchain and build tags:

```sh
go test ./adapter ./adapter/outbound -run '^$' \
  -bench 'Benchmark(NewProxy|ProxyRecordHistory|ProxyDelayHistory|NewSudoku)$' \
  -benchmem -count=3
```

## Verification and review

Completed locally:

- Default and `with_gvisor` full suites with `SKIP_INTEROP_TEST=1` and
  `SKIP_CONCURRENT_TEST=1`; external VMess interoperability and the optional
  inbound stress case were excluded by those existing project switches.
- Linux amd64 `with_gvisor` cross-build with `CGO_ENABLED=0`.
- Race checks for `adapter`, `adapter/outbound`, `common/queue`,
  `transport/sudoku/...`, `component/oix/...`, `dns/...`, `hub/...`, `config/...`.
- Real loopback Sudoku TCP, UDP and multiplex handshake/data round trips with
  directional table rotation; construction-time validation against the eager
  builder; concurrent sharing, independent seeds/order, caller slice mutation,
  garbage collection and rebuilding after collection.
- History order, bounded concurrent recording, successful/failed probe state,
  empty JSON compatibility and snapshot independence. The old queue concurrency
  test bypassed the public methods; it now exercises `Put`, `Pop`, `Last`, `Copy`.
- Static review of the workspace diff reports no new issues. The nine previously
  reported diagnostics were fixed in the follow-up below; full-repository lint
  initially had separate pre-existing diagnostics in unchanged files, resolved
  by the full cleanup below.
- Manual review of lock ordering, API snapshots, publication of shared tables,
  weak-reference cleanup, configuration ownership and all three dial paths.

No production traffic/RSS measurement or live server deployment was performed.

## Follow-up: lint cleanup and second review

The nine originally reported diagnostics are fixed: import/variable formatting,
MASQUE's trailing error newline, equivalent Shadowsocks plugin dispatch using a
switch, promoted method calls in SingMux/VMess, and HTTP-mask transport retry
classification without the deprecated `net.Error.Temporary()` method. Three
additional formatting diagnostics exposed on the next run were also fixed in
`adapter/outbound/zerotier.go`, `adapter/outboundgroup/parser.go`, and
`transport/sudoku/obfs/sudoku/table.go`.

Retry classification now explicitly handles interrupted syscalls, descriptor
exhaustion, transient DNS failures and timeouts alongside the existing EOF,
connection-reset and HTTP-status handling. Cancellation and context deadline
errors take precedence. Regression tests cover both direct and wrapped errors,
and verify that a persistent retry reaches a permanent failure and stops.

The second review used golangci-lint 2.14.0 and Go 1.27.1. With both issue limits
disabled, the full repository reports **391 other diagnostics** (62 gci, 124
gofumpt, 4 govet, 201 staticcheck), all in unchanged files. The earlier nine-item
report was limited to selected package trees and also subject to the tool's
repeated-message output cap; it was not a complete repository inventory.

```sh
golangci-lint run --max-issues-per-linter=0 --max-same-issues=0 ./...
golangci-lint run --max-issues-per-linter=0 --max-same-issues=0 --new-from-rev=HEAD ./...
```

The second command reports zero issues. The unfiltered report was also checked
against all modified and added paths: none were reported. The other diagnostics
were left outside that targeted cleanup and are handled in the next section.

Default and `with_gvisor` full tests passed again with the same documented skip
switches. Race tests passed for `adapter/...`, `common/queue`, and
`transport/sudoku/...`. The HTTP-mask tests also cross-compiled successfully for
Linux amd64 and Windows amd64 with CGO disabled; those cross-platform binaries
were not executed. Manual review confirmed unchanged plugin branch behavior,
no recursive promoted-method calls, and correct error-chain/cancellation handling.


## Follow-up: all 391 baseline diagnostics and final review

The original unrestricted baseline contained 391 reported items. After the
exception re-review, 386 are resolved by source changes and five original items
remain as narrowly scoped compatibility exceptions. Nine of the earlier 14
exceptions have now been fixed in code and their exclusions removed. Default and `with_gvisor`
whole-repository lint both report **zero issues** on darwin/arm64 with
Go 1.27.1 and golangci-lint 2.14.0; no linter was disabled globally.

The source changes consist primarily of configured gci/gofumpt formatting,
equivalent selectors/conditions/declarations, removal of unused assignments,
and replacing bbolt's deprecated aliases with the identical error objects from
its `errors` package. Additional corrections include:

- Hysteria's UDP hop buffer pool now stores array pointers instead of boxing
  slices on each return, and returns the borrowed buffer on receive failure.
  Datagram contents, truncation, queue drops, source-address behavior, and
  reception on both the current and previous hop remain unchanged.
- DoQ rejects malformed or out-of-range remote ports before opening a packet
  socket, rather than overwriting the parse error.
- Ordered-map fuzz assertions keep both type-assertion results. Existing map,
  rule-parser and XHTTP queue tests now check previously overwritten results.
- Dialer selection preserves caller-owned `net.Dialer` values by copying them,
  keeps custom dialers and their context intact, and preserves TFO's independent
  timeout for dialing at the first write.
- TUIC redundant interface assertions become nil checks, preserving the prior
  behavior for nil interfaces. Public error names and identities are unchanged.
- TAR validation uses the regular-file type produced by `archive/tar.Reader`,
  which normalizes legacy NUL type flags. Legacy archive support is retained.

### Re-review of the 14 exceptions

| Original items | Final resolution |
| --- | --- |
| 7 AnyTLS style findings | Fixed the four equivalent promoted selectors and formatted the three files. Removed every AnyTLS-specific lint/formatter exclusion. This narrow cleanup follows the explicit request to fix the exceptions; protocol, padding, session lifecycle and business behavior are unchanged. |
| 2 TUIC error-name findings | Added canonical `ErrClientClosed` / `ErrTooManyOpenStreams` names, migrated internal uses and retained the old exported names as compatibility aliases to the same sentinel values. Removed both suppressions. Equality, error messages and wrapped `errors.Is` matching are regression-tested. |
| 3 CFB deprecations | Retained: legacy VMess request/response headers and Shadowsocks CFB suites require CFB ciphertext. CTR/AEAD would produce incompatible wire bytes; copying or hiding a CFB implementation would only conceal the same deprecated construction. NIST SP 800-38A vectors now cover encryption/decryption across partial writes. |
| 1 TLS state deprecation | Retained: `tlsConnectionState` supplies public `GetTLSConnectionState`, `VerifyConnection` and ECH rejection verification. Dropping `NegotiatedProtocolIsMutual` changes an observable field to its zero value. A regression checks both legacy boolean states through the public serialized state. |
| 1 Hysteria retry deprecation | Retained: the pinned quic-go send queue calls `destroyImpl(err)` on a `PacketConn.WriteTo` failure. Its immediate-close path passes that error to the streams map unchanged. The direct `net.Error.Temporary()` assertion therefore supports custom transport errors, including temporary errors with `Timeout() == false`. Matching only QUIC types, using `Timeout()`, or unwrapping errors would change reconnect decisions. |

The retained CFB category has **four actual call sites**: two in VMess and two
in Shadowsocks. One Shadowsocks decryption diagnostic was exposed only after
formatting, so the original 391-item inventory counted three. There are six
remaining production suppression comments in total (four CFB, one TLS state,
one Hysteria retry), corresponding to five items in the original inventory.
There are no AnyTLS/TUIC exclusions or new test-file suppression comments, and
`.golangci.yaml` is back to its original rules.

The Hysteria justification is tested with a real loopback QUIC connection and a
custom packet connection that injects a write failure. A temporary failure is
returned without redialing; a permanent failure attempts exactly one reconnect.
This verifies the dependency's actual propagation path as well as the client's
existing behavior, rather than testing only a stand-alone error classifier.

Final verification:

- Default full suite passed with `SKIP_INTEROP_TEST=0`, including real local
  V2Ray MKCP, Mekya and TLSMirror interoperability in both directions.
- `with_gvisor` full suite passed with `SKIP_INTEROP_TEST=1`; both full runs used
  `SKIP_CONCURRENT_TEST=1` to omit the optional inbound stress case.
- The full-cleanup race checks passed for `adapter/...`, queue/ordered-map/structure,
  dialer, updater, oix, DNS, hub, config, Hysteria, TUIC and XHTTP. This exception
  re-review additionally passed race tests for the real QUIC retry regression,
  TUIC legacy aliases, CFB known-answer vectors and TLS state conversion.
- New focused regressions passed for default/custom/copied dialers, a delayed
  TFO write after cancellation of the original dial context, UDP hop round trips,
  truncation, previous-hop delivery and close unblocking, and legacy NUL-type
  TAR files/directories including empty and escaping targets.
- The first default run encountered a Snell HTTP/3 fixture handshake timeout.
  Its isolated test passed three consecutive runs; the subsequent complete
  default and `with_gvisor` runs passed without changing the fixture or timeout.
- Linux amd64 and Windows amd64 `with_gvisor` builds passed with CGO disabled.
- Manual review covered all semantic changes, especially dialer variable scopes,
  promoted methods, nil checks, buffer ownership, sentinel identity, retry
  policy and protocol encoding. The exception re-review also checked the pinned
  dependency's error propagation, legacy public symbols and every removed
  exclusion. No outstanding regression was found.

Cross-platform binaries are compilation checks only; local loopback tests do not
constitute production traffic or remote deployment validation.

### Release verification follow-up

The Linux default CI suite exposed two existing HTTP/3 fixture races. The
rejection helper now prevents `HTTPStream()` from implicitly flushing a 200
response before sending `H3_REQUEST_REJECTED`; the retry-limit test also checks
the exact peer reset. The GOAWAY test waits for the asynchronous connection-map
cleanup before asserting its remaining references. Production code is unchanged.

The original cleanup failure reproduced locally. After the fixture correction,
a concurrent stress run reached a connection deadline once; an isolated run of
all three retry regressions passed 100 iterations each with the race detector.
The complete Snell package passed race and `with_gvisor` tests, and both lint
configurations remained clean.
