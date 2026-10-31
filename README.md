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

Protects a site with a login at `https://id.castelnuovo.eu`. Without `client_certificate off`, the site also needs a client certificate.

```caddyfile
{
 acme_ca https://pki.castelnuovo.eu/acme/acme/directory
 acme_ca_root /etc/caddy/cs-pki-root.crt
}

example.castelnuovo.eu {
 castelnuovo_auth {
  client_id {env.CLIENT_ID}
  client_secret {env.CLIENT_SECRET}
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
  client_id {env.CASTELNUOVO_CLIENT_ID}
  client_secret {env.CASTELNUOVO_CLIENT_SECRET}
 }

 reverse_proxy app:80
}
```

Requests that reach the app carry these headers. The handler first removes every header the client sent whose name starts with `X-Auth-`, also when spelled with underscores.

| Header          | Value                                  |
| --------------- | -------------------------------------- |
| `X-Auth-Sub`    | The user ID                            |
| `X-Auth-User`   | The username                           |
| `X-Auth-Name`   | The display name                       |
| `X-Auth-Email`  | The email address                      |
| `X-Auth-Groups` | The user's groups, separated by commas |

To log out, post a form to the logout endpoint:

```html
<form method="post" action="/.castelnuovo/logout"><button>Log out</button></form>
```

This also ends the login at `id.castelnuovo.eu` and then returns to `https://<host>/`. Only a POST from the site itself works, so other sites cannot log you out.

Sessions last at most 12 hours. Access you revoke at `id.castelnuovo.eu` stops working within 5 minutes. Sessions live in memory, so a config reload keeps them and a restart logs everyone out.

Denied requests become Caddy errors (400, 401, 403 or 405), so `handle_errors` can show your own error page.

### OIDC client

Create one OIDC client per site, with public client off and PKCE on:

| Setting             | Value                                  |
| ------------------- | -------------------------------------- |
| Callback URL        | `https://<host>/.castelnuovo/callback` |
| Logout Callback URL | `https://<host>/`                      |
