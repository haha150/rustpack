# CA Certificates

Place your corporate CA certificates (`.crt`, `.pem`, `.cer`) in this directory
if your network uses TLS-intercepting proxies.

These are injected into the Docker image at build time via `update-ca-certificates`
so that `cargo` and `rustup` can reach crate registries through the proxy.

If your network does not use TLS inspection, this directory can remain empty.
