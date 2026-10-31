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

A site that needs a client certificate must verify it, with `client_auth` mode `require_and_verify` or `verify_if_given`. The certificate needs the URI `spiffe://castelnuovo.eu/yubikey/<serial>/owner/<user ID>`, and only that user can log in with it.

### Headers

Requests that reach the app carry these headers. The handler first removes every header the client sent whose name starts with `X-Auth-`, also when spelled with underscores. It also removes its own cookies and passes all other cookies on unchanged.

| Header          | Value                                  |
| --------------- | -------------------------------------- |
| `X-Auth-Sub`    | The user ID                            |
| `X-Auth-User`   | The username                           |
| `X-Auth-Name`   | The display name                       |
| `X-Auth-Email`  | The email address                      |
| `X-Auth-Groups` | The user's groups, separated by commas |

Identify users by `X-Auth-Sub`. Unless `ALLOW_OWN_ACCOUNT_EDIT` is off in Pocket ID, users can change their own name and email, and the email is not checked for verification. Header values are UTF-8, so frameworks that read headers as Latin 1 (such as WSGI) have to decode names with accents themselves. Since groups are separated by commas, group names should not contain one.

Make sure only Caddy can reach your app. Anyone who can reach it directly can send these headers themselves.

### Access

Only users in the allowed user groups of the site's OIDC client can log in. A client created in the Pocket ID admin UI starts with no groups, so nobody can log in until you pick some.

Each login has to come from an `id.castelnuovo.eu` session that started with a passkey. Users who signed in there with a login code get a 403, and have to sign out at `id.castelnuovo.eu` and sign in again with a passkey. A login also has to be at most 1 hour old, so `id.castelnuovo.eu` asks for the passkey again after an hour.

Without a valid session, page loads are redirected to the login. Other requests, such as `fetch` calls, WebSockets and anything other than GET, get a 401. To send users to the login yourself, link to `/.castelnuovo/login?rd=/path`.

Sessions last at most 12 hours. Every 5 minutes a session refreshes its tokens at `id.castelnuovo.eu`, which refuses the refresh once the user is disabled, deleted or no longer in an allowed group. The session then ends. If `id.castelnuovo.eu` cannot be reached, requests get a 502 and the session stays, so it works again once the refresh succeeds. When refreshes keep failing for 10 minutes, the session ends. Sessions live in memory, so a config reload keeps them as long as `client_id` stays the same, and a restart logs everyone out.

All `castelnuovo.eu` sites count as the same site for cookies, so the session cookie's `SameSite` setting does not stop requests coming from another `castelnuovo.eu` site. Your app needs its own CSRF protection for requests that change data.

Denied requests become Caddy errors (400, 401, 403, 405 or 502), so `handle_errors` can show your own error page.

### Logout

To log out, post a form to the logout endpoint:

```html
<form method="post" action="/.castelnuovo/logout"><button>Log out</button></form>
```

This also ends the login at `id.castelnuovo.eu` and then returns to `https://<host>/`. Only a POST from the site itself works, so other sites cannot log you out.

### OIDC client

Create one OIDC client per site, with public client off and PKCE on:

| Setting             | Value                                  |
| ------------------- | -------------------------------------- |
| Callback URL        | `https://<host>/.castelnuovo/callback` |
| Logout Callback URL | `https://<host>/`                      |
