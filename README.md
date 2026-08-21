# css-oidc-login

An additional login method for the [Community Solid Server](https://github.com/CommunitySolidServer/CommunitySolidServer): a person signs in to their pod at an external OpenID Connect provider — a company SSO, a self-hosted identity provider, a passkey-only provider — instead of, or alongside, the server's built-in email-and-password login.

## Status

Pre-1.0, not on npm, no external review, no security audit, no deployment its author knows of. What exists is the source, a test suite that runs the attacks these documents describe as failing cases, and the documents. None of it has been observed under load, under attack, or over time. Read [what is checked](docs/security.md#what-is-checked) and [what is not checked](docs/security.md#what-is-not-checked) before pointing it at accounts that matter.

## What it does

The method appears as a second entry in the server's list of login methods. Choosing it starts an authorization code flow with PKCE at the configured provider. On the way back the server exchanges the code for an ID token over a back-channel request, reads a WebID out of a claim, checks the profile behind that WebID for a grant, resolves the WebID to an account, and issues the session a password login would have issued — same cookie, same account, same rights. Password login keeps working beside it unless it is switched off.

It authenticates people who already have an account on this server. It never creates one, and it creates no pods.

## Identity brokering, not delegation

The server is a relying party to the external provider and remains the OpenID Provider to Solid clients. The access tokens a Solid client uses against a pod are still minted by the Community Solid Server, from its own keys, at its own issuer URL, and they are still DPoP-bound — each token only works alongside a fresh proof signed by the key that obtained it. That issuer URL is what a person's `solid:oidcIssuer` triple names, and nothing here changes it.

The external provider's ID token is consumed inside a single back-channel request, is never stored, and is never seen by a Solid client. What the provider is handed is authority over the login moment.

## Two-sided consent

A login needs two independent statements to agree:

1. the configured provider issues an ID token naming a WebID, for a subject at that provider;
2. the profile that WebID resolves to states that it accepts that subject at that provider.

The second is a grant the profile's owner writes — one node carrying an issuer and a subject identifier:

```turtle
<https://pod.example.com/alice/profile/card#me>
  <https://tophcodes.github.io/css-oidc-login/ns#externalLogin> [
    <https://tophcodes.github.io/css-oidc-login/ns#issuer> <https://id.example.com> ;
    <https://tophcodes.github.io/css-oidc-login/ns#subject> "b1e5c0de-4f2a-4c1e-9a77-1f0e2d3c4b5a"
  ] .
```

Neither half is sufficient alone. Configuring a provider grants it nothing until someone writes a grant naming it; naming a provider without pinning the subject would let anyone else who can obtain a token there ride on it. Removing the grant revokes external login for that person alone, immediately, with no administrator involved.

Which near misses the server refuses, and why the predicate is not `solid:oidcIssuer`, is in [the grant, in full](docs/security.md#the-grant-in-full).

## Requirements

Hard ones, each stated with the error it produces in [deployment requirements](docs/security.md#deployment-requirements).

- **HTTPS on both sides.** An `http://localhost` deployment cannot use this login method at all.
- **The account and its WebID link must already exist.** A WebID no account is linked to is refused; a WebID linked to several is refused too.
- **One login in flight per browser**, and pending logins live in process memory, so the server has to run a single worker.
- **The profile must be plain Turtle served at the WebID's own URL** to be able to carry a grant.
- **Keep password login enabled** unless the alternative has been thought through: it is the recovery path when somebody loses their only authentication device.
- **Community Solid Server 7.x**, developed against 7.2.

## Setting it up

Everything is wired in the server's JSON configuration: two handlers, the cookie mappings carrying a pending login between them, an entry in the login-method list, and two HTML templates this package deliberately does not ship. It is installed from a checkout and built first. See [Configuration](docs/configuration.md).

Per person, two things have to be arranged that this package does not write: their WebID in a claim at the provider, and the grant above in their profile. [Getting grants into profiles](docs/security.md#getting-grants-into-profiles) covers the second, which is the one that decides whether the package fits a deployment.

## Documentation

- [Configuration](docs/configuration.md) — the configuration block, every setting, the cookie wiring, the two pages, installing and building.
- [Security](docs/security.md) — the grant in full, deployment requirements, what is checked, error semantics, what is not checked.
- [Providers](docs/providers.md) — Pocket ID and Keycloak, each with its trap.

## License

MIT. See [LICENSE](./LICENSE).
