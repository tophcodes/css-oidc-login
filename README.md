# css-oidc-login

An additional login method for the [Community Solid Server](https://github.com/CommunitySolidServer/CommunitySolidServer): a person signs in to their pod through an external OpenID Connect provider — a company SSO, a self-hosted identity provider, a passkey-only provider — instead of, or alongside, the server's built-in email-and-password login.

## What it does

On a Community Solid Server, each account has a WebID linked to it, and the person behind it logs in with an email address and a password the server stores. This package adds a second login method, where that person authenticates at an external OpenID Connect provider instead: at an organisation's existing identity provider, or at a passkey-only provider so that nobody has a pod password at all.

The new method appears as a second entry in the server's list of login methods. Choosing it sends the person to the external provider, and when they come back the server gives them exactly the session it would have given them after a password login: the same session cookie, for the same account, with the same rights. Nothing else about the server changes, and password login keeps working next to it unless it is switched off.

Mechanically it is two handlers wired into the server's account API, plus two small pieces of cookie plumbing. One handler starts an authorization-code flow with PKCE and redirects the person to the provider. The other takes the callback, exchanges the code for an ID token in a direct back-channel request, reads a WebID out of that token, checks that the person named in the token is one the profile behind that WebID has agreed to, finds the account the WebID is linked to, and logs that account in.

This is not a way to create pods by signing in with an external provider. It authenticates people who already have an account here; it never creates one.

## Status

This package is pre-1.0 and is not published on npm. It has had no external review and no security audit, and its author knows of no deployment running it. What exists is the source, a test suite that includes the attacks described in these documents as failing cases, and the documents themselves. Everything they describe is behaviour that is implemented and tested; none of it describes behaviour that has been observed under load, under attack, or over time.

Read [what the server checks](docs/security.md#what-the-server-checks-before-it-logs-anyone-in) and [what is not checked](docs/security.md#what-is-not-checked) before pointing it at accounts that matter. There is no earlier deployment to lean on, so a first one is its own evaluation and not a confirmation of someone else's.

## Where authority stays

A common first misunderstanding: this does not replace the server's own OIDC layer, and it does not make the external provider the issuer of anything a Solid app sees.

The access tokens a Solid client uses to write to a pod are still minted by the Community Solid Server itself, from its own keys, at its own issuer URL. Those tokens are DPoP-bound — each one only works when presented together with a fresh proof signed by the private key of the client that obtained it — and issuing them is the server's job, not the external provider's. That issuer URL is what a person's `solid:oidcIssuer` triple points at, and none of this changes it. When the server links a WebID to an account it still tells the person to name the server itself as their OIDC issuer.

The external provider does one job: it tells the server which human is at the keyboard. Its ID token is consumed inside a single back-channel request, is never stored, and is never seen by a Solid client. Authority over pod access stays entirely with the server; what the external provider is handed is authority over the login moment, and nothing beyond it.

## Two-sided consent

A login needs two independent statements to agree.

1. The configured provider issues an ID token that names a WebID, for a subject at that provider.
2. The document that WebID resolves to says, in its own words, that it accepts authentication of that particular subject at that particular provider.

Neither half is sufficient. Adding a provider to the server configuration grants that provider nothing on its own: until a person writes a grant into their own profile, a token from it logs nobody in. Naming the provider in a profile is not sufficient either, because a grant is about a person and not about a provider — everyone else who can obtain a token from the same provider is a stranger to it, including whoever arranged for someone else's WebID to appear in their own token.

The grant a person adds to their WebID profile document is one node carrying two statements:

```turtle
<https://pod.example.com/alice/profile/card#me>
  <https://tophcodes.github.io/css-oidc-login/ns#externalLogin> [
    <https://tophcodes.github.io/css-oidc-login/ns#issuer> <https://id.example.com> ;
    <https://tophcodes.github.io/css-oidc-login/ns#subject> "b1e5c0de-4f2a-4c1e-9a77-1f0e2d3c4b5a"
  ] .
```

The subject of the statement is the person's own WebID. The object is a grant node — blank here, but a named node works the same way — that names the configured issuer and the subject identifier that provider assigns to this person. Removing the grant revokes external login for that person alone, immediately, without touching the server: the next callback for that WebID is refused. No administrator has to be involved and nobody else is affected.

The pairing of an issuer and a subject in one node is load-bearing rather than decorative, and the server is strict about what counts as a grant. The strictness rules, the near misses they refuse, and why the predicate is not `solid:oidcIssuer` are in [Two-sided consent, in full](docs/security.md#two-sided-consent-in-full).

## Before you deploy

These are hard requirements. Each one is stated in full, with the errors it produces, in [Before you deploy](docs/security.md#before-you-deploy).

- **Both sides must be served over HTTPS**, this server and the provider. An `http://localhost` deployment cannot use this login method at all.
- **The account must already exist, with its WebID already linked.** A token naming a WebID no account here is linked to is refused and nothing is created; a WebID linked to more than one account is refused too.
- **One login can be in flight per browser**, and pending logins live in the process's memory, so the server has to run with a single worker.
- **A profile that is not plain Turtle at its own URL cannot carry a grant.**
- **Keep password login enabled unless you have thought about the alternative.** It is the recovery path when somebody loses their only authentication device.
- **The package targets Community Solid Server 7.x**, and is developed against 7.2.

## Setting it up

The server assembles itself at startup from JSON configuration, so all of this is wired in a file: the two handlers, the cookie mappings that carry a pending login between them, an entry in the server's list of login methods, and two small HTML templates this package deliberately does not ship. It is not on npm either, so it is installed from a checkout and built first — what a server loads is the compiled `dist/`. [Configuration](docs/configuration.md) has the complete setup on top of the stock config.

Each person also needs two things arranged that nothing in this package writes: their WebID in a claim at the provider, which is administrator work, once per person, and the grant above in their profile document, which is RDF that someone has to write into a document on the pod. For a household or a team of five that is a one-paragraph instruction per person; for forty members with mixed technical confidence it takes an onboarding step that somebody has to build and operate, and without one the package does not fit. [Getting the grant into people's profiles](docs/security.md#getting-the-grant-into-peoples-profiles) is blunt about which of the two is the wall.

## Documentation

- [Configuration](docs/configuration.md) — the complete configuration block and every setting in it, the cookie wiring, the two pages the browser needs, and installing, building and testing.
- [Security](docs/security.md) — what the server checks before it logs anyone in, what is not checked and why, the consent model in full, and every deployment constraint that exists for a security reason.
- [Providers](docs/providers.md) — walkthroughs for Pocket ID and Keycloak, each with its trap.

## License

MIT. See [LICENSE](./LICENSE).
