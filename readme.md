# tailnet-certbot

A client and server that allow a tailnet to automatically renew its certs against a self-signed cert internally.
Built using Podman Quadlets for containerized deployment on a timer.

This server is meant for usage within a secure tailnet and is only as secure as the tailnet.
It provides almost no safeguards against malicious use coming from inside the tailnet.

## tooling

This project uses Axum, Rustls, and rcgen. This allows it to be statically compiled with the musl target and deployed distroless.

## how it works

The protocol uses HTTP (not HTTPS) as all data should be going over an encrypted tailnet.

The server has the following files in `/data` -
* `config.toml` - The config file for the server
* `root-ca.crt` - The root CA certificate
* `root-ca.srl` - The root CA serial number (only file that will be mutated during processing)
* `root-ca.key` - The root CA key

The client has the following files in `/data` -
* `config.toml` - The config file for the client
* `server.csr` - The CSR to be signed
* `server.crt` - The server certificate (generated during processing)

The actual interaction simply works as follows -
1. Client posts `server.csr` along with some other essential info as outlined in its config to HTTP endpoint `/`
2. Server processes it and returns `server.crt`
3. Client saves `server.crt`

The post request is structured as -
```
{
    "csr": "<CSR HERE>",
    "alt-dns": [ <DNS ALT NAMES> ]
    "alt-ips": [ <DNS ALT IPS> ],
    "valid-for": <SIGN DAYS>
}
```

The response is simply the raw certificate.

The certificate implicitly has the following extensions as well -
```
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names
```
