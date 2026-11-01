<h1 align="center">
  castelnuovo/caddy-castelnuovo
</h1>

The Caddy image for Castelnuovo Solutions, published as `ghcr.io/castelnuovo/caddy-castelnuovo`.

## Installation

```sh
# Clone repository
git clone git@github.com:castelnuovo/caddy-castelnuovo.git && cd caddy-castelnuovo

# Install dependencies
go mod download

# Run tests
go test -race ./...

# Build image
docker build -t caddy-castelnuovo .
```

To build your own Caddy with the module instead, use [xcaddy](https://github.com/caddyserver/xcaddy):

```sh
xcaddy build --with github.com/castelnuovo/caddy-castelnuovo
```

## castelnuovo_auth

Protects a site with a login at `https://id.castelnuovo.eu`, which must run Pocket ID v2.19.0 or later. Without `client_certificate off`, the site also needs a client certificate.

```caddyfile
{
 acme_ca https://pki.castelnuovo.eu/acme/acme/directory
 acme_ca_root /etc/caddy/cs-pki-root.crt
}

example.castelnuovo.eu {
 castelnuovo_auth {
  client_id {env.EXAMPLE_CLIENT_ID}
  client_secret {env.EXAMPLE_CLIENT_SECRET}
  client_certificate off
 }

 reverse_proxy app:80
}

secure.example.castelnuovo.eu {
 tls {
  protocols tls1.3
  client_auth {
   mode require_and_verify
   trust_pool file /etc/caddy/cs-pki-root.crt
  }
 }

 castelnuovo_auth {
  client_id {env.SECURE_CLIENT_ID}
  client_secret {env.SECURE_CLIENT_SECRET}
 }

 reverse_proxy app:80
}
```

Put `castelnuovo_auth` directly in the site block, without a matcher and outside `handle` and `route`. It has to see every request, including those to `/.castelnuovo/login`, `/.castelnuovo/callback` and `/.castelnuovo/logout`. Otherwise those requests reach your app and nobody can log in.

A site that needs a client certificate must verify it, with `client_auth` mode `require_and_verify`. The certificate needs the URI `spiffe://castelnuovo.eu/yubikey/<serial>/owner/<user ID>`, and only that user can log in with it.

### Headers

Requests that reach the app carry these headers. The handler first removes every header the client sent whose name starts with `X-Auth-`, also when spelled with underscores. It also removes its own cookies and passes all other cookies on unchanged.

| Header          | Value                                  |
| --------------- | -------------------------------------- |
| `X-Auth-Sub`    | The user ID                            |
| `X-Auth-User`   | The username                           |
| `X-Auth-Name`   | The display name                       |
| `X-Auth-Email`  | The email address                      |
| `X-Auth-Groups` | The user's groups, separated by commas |

### Sessions

A session lives in an encrypted cookie, so it survives restarts and reloads of Caddy. The key comes from the client secret, so changing the secret logs everyone out. A session lasts 12 hours and only works on the host and with the client certificate it started with.

Every 5 minutes the handler refreshes the session at `id.castelnuovo.eu`. This picks up changes to the user's name, email and groups, and ends the session of a disabled user. While a refresh is due and `id.castelnuovo.eu` cannot be reached, requests get status 502.

A request without a session is redirected to the login when it loads a page, and gets status 401 otherwise. The cookie has to stay under 4096 bytes, which leaves room for about 35 groups with names of 16 characters. A user with more groups cannot log in.

### Logout

To log out, post a form to the logout endpoint:

```html
<form method="post" action="/.castelnuovo/logout"><button>Log out</button></form>
```

This also ends the login at `id.castelnuovo.eu` and then returns to `https://<host>/`. Only a POST from the site itself works, so other sites cannot log you out.

A copy of the session cookie keeps working after logout until its next refresh, so for at most 5 minutes.

### OIDC client

Create one OIDC client per site, with public client off and PKCE on:

| Setting             | Value                                  |
| ------------------- | -------------------------------------- |
| Callback URL        | `https://<host>/.castelnuovo/callback` |
| Logout Callback URL | `https://<host>/`                      |
