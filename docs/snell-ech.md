# Snell ECH

Use the node configuration supplied by your provider. Snell ECH requires a compatible server, a valid ECH configuration, and certificate verification. Keep the supplied security settings unchanged.

`obfs-opts.transport` defaults to `tcp`. Use `h3` only when the server supports HTTP/3 and the network allows UDP, or `auto` to allow automatic selection between HTTP/3 and TCP. See [the configuration example](config.yaml).

After upgrading the installed core, refresh the subscription to obtain compatible settings. For coordinated upgrades, update the server first, then the panel and clients. Source changes alone do not update installed cores.

If a connection fails, refresh the subscription and check server availability, certificate validity, and support for the selected transport. If HTTP/3 is unavailable on the network, use `tcp` or `auto`. Do not disable certificate verification.
