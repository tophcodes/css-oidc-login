# Security

## The grant, in full

The [README](../README.md#two-sided-consent) states the model in short: the configured provider issues an ID token naming a WebID for a subject, and the profile that WebID resolves to has to accept that subject at that issuer. This is the whole of it.

Pairing the issuer and the subject in one node is load-bearing. As two separate triples hanging off the WebID, a profile that opts in to two providers would cross-match — the subject recorded for one would satisfy a token from the other, which is a way in at any provider whose subject identifier is a username or an email address and which anyone can register with. Two grants are therefore two nodes:

```turtle
<https://pod.example.com/alice/profile/card#me>
  <https://tophcodes.github.io/css-oidc-login/ns#externalLogin> [
    <https://tophcodes.github.io/css-oidc-login/ns#issuer> <https://id.example.com> ;
    <https://tophcodes.github.io/css-oidc-login/ns#subject> "b1e5c0de-4f2a-4c1e-9a77-1f0e2d3c4b5a"
  ], [
    <https://tophcodes.github.io/css-oidc-login/ns#issuer> <https://sso.example.org> ;
    <https://tophcodes.github.io/css-oidc-login/ns#subject> "alice@example.org"
  ] .
```

The grant node may be a blank node or a named one. What counts as a grant is strict, because an implementation that merely searched the document for the issuer's name would accept every one of the near misses below — each of which has a test:

- The profile is fetched from the WebID's own URL with `Accept: text/turtle`, and redirects are not followed. A document at the end of a redirect chain is a document somewhere else.
- It must be served as `text/turtle` and must parse. No other serialisation is read.
- The grant must hang off the WebID itself, in the document's default graph. A statement about somebody else, or one parked in a named graph, is content near the WebID rather than an assertion by it.
- On the grant node, the issuer must be an IRI and the subject must be a literal. A quoted issuer is not an identifier; a subject written as an IRI is a claim about a different kind of thing.
- The subject is compared verbatim, byte for byte. Issuers are compared ignoring trailing slashes, on both sides.
- The fetch carries no credentials, so the profile must be readable unauthenticated. On a pod this server created, the profile document is public-read by default.

The predicate carrying the grant is configurable (`trustPredicate`); the two predicates read *on* the grant node are fixed, so no configuration can produce a grant that names an issuer and no subject.

### Why not `solid:oidcIssuer`

`solid:oidcIssuer` exists and looks like it means what is needed here. It does not: it means "this issuer mints my Solid access tokens", and Solid clients act on it. A client reading it would go to the external provider to obtain the DPoP-bound access tokens described in the [README](../README.md#identity-brokering-not-delegation), which that provider does not issue. Reusing it to mean "I am willing to log in through this provider" would break every Solid client that reads the profile, and in some deployments would additionally say that the provider may mint tokens for that identity.

The package's own term means only "this server may accept an authentication of me, as this subject, at this issuer". The IRI is an identifier and nothing more — compared as a string, never dereferenced — which is why `trustPredicate` accepts any absolute IRI under any scheme.

## Getting grants into profiles

Two things have to be arranged per person, and only one belongs to whoever runs the server. At the provider, the WebID has to be in a claim: administrator work in the provider's console, once per person. In the profile, the grant has to exist: RDF that someone writes into a document on the pod.

Nothing here writes it — no page in the server, no command-line tool, no import format. For someone comfortable editing their own profile it is a copy-paste; for everyone else it is a wall and a support request.

The awkward half is the subject identifier: opaque, assigned by the provider, usually neither the username nor the email address. The reliable way to obtain it is to let the login fail once, because the refusal names the exact string — *The profile at &lt;webid&gt; does not accept &lt;subject&gt; as its subject at &lt;issuer&gt;; its owner has to name that subject in the grant before this login can be completed.* It can be pasted straight into the grant, and disclosing it is safe: it is never anybody else's.

The write can be scripted. The profile is an ordinary pod resource — its owner can `PUT` it or `PATCH` it in N3 Patch or SPARQL Update form, and an operator holding write access to each profile can add grants in bulk. No such script ships here.

For a household or a team of five this is a one-paragraph instruction per person. For forty members with mixed technical confidence it takes an onboarding step that somebody has to build and operate, and without one the package does not fit.

## Deployment requirements

**This server must be served over HTTPS.** The cookie binding a login to one browser carries the `__Host-` prefix, which a browser only stores over HTTPS. Rather than let every login die at the callback with a cookie that was never set, the start route refuses on the first attempt, before the person leaves for the provider: *The pending-login cookie &lt;name&gt; is only stored by a browser over HTTPS, but the callback URL &lt;url&gt; is not. Serve this server over HTTPS; logging in through an external provider cannot be made safe over plain HTTP.* An `http://localhost` deployment cannot use this login method. That is a trade rather than an oversight — the server's own account cookie omits `Secure` precisely so localhost keeps working, and this one does not.

**The provider must be served over HTTPS.** The configured `issuer` must be an absolute `https:` URL, and so must the `authorization_endpoint` and `token_endpoint` its discovery document names. Otherwise the token exchange would put the client secret and the authorization code in clear, and the authorization endpoint is handed to a browser as an address to navigate to. An issuer that is not `https:` fails as this server's own configuration: *The configured issuer &lt;issuer&gt; is not an absolute HTTPS URL, so this server cannot look up the discovery document that every later check hangs off.* An endpoint that is not fails as the provider's: *Discovery for &lt;issuer&gt; names a token_endpoint that is not an absolute HTTPS URL.* Both land on the first login attempt. An identity provider running plain HTTP inside a private network needs a certificate before it can be used from here.

**One login can be in flight per browser.** One cookie name means one handle per browser: a second login started in the same browser overwrites the first one's cookie, after which the first can no longer be completed and is left to expire. Several at once would need a cookie name per login, which neither the `__Host-` prefix nor the fixed name in the cookie-parser mapping allows.

**The account must already exist, with its WebID linked.** The link is made through the server's own account API, which refuses to link a WebID to an account with no login method — so set the account up the ordinary way first. A token naming an unlinked WebID is refused and nothing is created. A WebID linked to more than one account is refused too: the token says who the person is, not which account they meant, and the storage promises no order, so picking one would be guessing whose session to hand out.

**Keep password login enabled unless the alternative has been thought through.** If somebody's only authentication device is a passkey and they lose it, a provider that can no longer identify them leaves an account nobody can reach. The server's email-and-password login, left switched on beside this one, is the recovery path.

**A profile that is not plain Turtle at its own URL cannot carry a grant.** Static hosts serving `.ttl` as `text/plain`, WebIDs redirecting to a profile elsewhere, profiles offered only as JSON-LD, profiles needing authentication, profiles slower than five seconds and profiles past a megabyte are all refused. Pods on this server are fine, as is any host that can be configured to serve a profile that way.

**Pending logins live in process memory.** They do not survive a restart and are not shared between workers, so the server has to run a single worker — its default, but worth checking wherever that default has been raised. An abandoned attempt holds an entry until its TTL passes; expired entries are reclaimed by the next login needing the room. The store holds at most `maxPending` logins at once, ten thousand by default; past that, further logins are refused with a 503 and a `Retry-After` naming the TTL. Nothing already in progress is ever evicted, because the route that fills the store is unauthenticated and eviction would let whoever floods it decide whose login is thrown away. Size `maxPending` for the deployment.

## What is checked

Per callback, in order:

- **The pending-login cookie** must be present exactly once, and must match the login the state names. The state travels through the provider and is therefore known to anyone who sees the callback URL, a proxy log or a `Referer` header; the handle in this cookie — 32 random bytes — only ever travels between this server and one browser, and is compared in constant time. This is what refuses a stolen state and code replayed by somebody else, and what refuses a cross-site form submission that would otherwise log a victim into the attacker's account with a perfectly valid state. The cookie is `HttpOnly`, `Secure`, `SameSite=Strict`, `__Host-`-prefixed, and cleared once the login is redeemed.
- **The state** must be one this server issued and has not yet redeemed, and expires with the pending login's TTL. It is consumed only *after* the cookie matches, so a caller who cannot produce the handle leaves somebody else's login in progress intact and a failed callback spends nothing.
- **PKCE** is on every flow. The verifier is 32 random bytes per login, never leaves the server, and is sent only in the token exchange; the provider sees only its SHA-256 challenge, so an intercepted authorization code is not redeemable without it.
- **The issuer**: the ID token's `iss` must equal the configured issuer, ignoring trailing slashes.
- **The audience**: `aud` must contain the configured client ID. Without this, any other client at the same provider could obtain a token this server would accept.
- **The authorized party**: if `azp` is present it must name this client, and a token naming several audiences must carry it. Both halves are needed — membership in `aud` alone would let another client mint itself a token that also lists this one, and checking `azp` only for multi-audience tokens would let it mint one addressed solely here.
- **The WebID claim** (`webIdClaim`, default `webid`) must be present and an absolute `http:` or `https:` URL with no control characters. It is a string chosen at the provider — for a mapped attribute, by whoever holds the account there — and it ends up in a `fetch`, in a message handed back, and in a log line.
- **The subject**: `sub` must be present and non-empty, as OIDC Core 2 requires of every ID token.
- **The account**: the WebID must resolve to exactly one account on this server.
- **The grant**: the profile must carry a grant naming both the configured issuer and that exact subject, under the conditions in [the grant, in full](#the-grant-in-full).

The token exchange is a direct back-channel POST to the endpoint discovery named, over TLS, refusing to follow redirects — a `307` or `308` would replay that body, client secret and code and PKCE verifier included, at whatever host the response named. It gives up after five seconds and stops reading past a megabyte, as do the discovery and profile fetches, so no unresponsive or endless host can occupy the server's single worker indefinitely.

## Error semantics

Every failure leaves as a status and a `message` in the JSON body, which is what the [callback page](./configuration.md#the-two-pages) displays. What decides the status is whose failure it is.

- **400** — the caller's: no state, no code, a body that is no object, an unknown or expired state, no pending-login cookie or several, a cookie belonging to another login, or the provider's `invalid_grant`.
- **403** — permission: the profile carries no grant for the configured issuer, or none for this subject, or the WebID is linked to no account here. Whoever reads it is the one who can grant it.
- **405** — anything but POST, on either route. Both routes act, so neither has a safe reading.
- **409** — the WebID is linked to several accounts here: this server's own account data is ambiguous about who is logging in.
- **502** — the provider or the profile's host answered in a way that is no answer: unreachable, redirecting, a non-2xx status, the wrong media type, unreadable, past the cap, a token response or ID token this server cannot make sense of, or claims naming another issuer, another client, no subject or no WebID.
- **503** — the pending-login store is full, on the start route; `Retry-After` says when to come back.
- **504** — the discovery document, the token endpoint or the profile host did not answer inside five seconds, including one that answers and then trickles.
- **500** — this deployment's own configuration: a callback URL that is not absolute or not `https:`, or an issuer that is not `https:`.

A trust predicate that could never be a predicate is caught earlier still: the handler refuses to be constructed, so the server fails to start rather than refusing every login as if its owner had granted nothing.

RFC 6749 §5.2 gives a provider one way to say something about the exchange: a 400 — or a 401 for a client it will not authenticate — carrying a JSON object whose `error` names what was wrong. Only that shape is read as a verdict, and of its codes only `invalid_grant` is a verdict on the caller: a code already spent, expired, issued to someone else, or not matching this verifier or redirect URI. Everything else is the provider's, `invalid_client` above all, which is what a wrong client secret comes back as. So is a 400 or 401 with no well-formed error body, which carries the status the protocol attaches meaning to but not the statement that gives it that meaning. The cost is that a provider refusing a spent code without an error body has its refusals reported as its own; the cost of the alternative is telling a person their login was malformed when this server's client secret is wrong.

## What is not checked

**The ID token's signature is not verified.** OIDC Core 3.1.3.7 permits this for a token obtained this way: "the TLS server validation MAY be used to validate the issuer in place of checking the token signature". The token is never accepted from a browser or a client, and the endpoint it is fetched from is checked rather than assumed — the discovery document must come from the issuer without a redirect and must name that issuer itself, and the token endpoint must not redirect either. The same section does not excuse the `iss`, `aud` and `azp` checks, which is why those are unconditional and have tests of their own.

The residual risk is real. Everything rests on TLS server validation, so anything that can present a certificate this server's trust store accepts for the provider's host can mint a token this server accepts: a mis-issued or fraudulently obtained certificate, a compromised or coerced CA, or a TLS-intercepting proxy whose root is installed on the server — a normal fixture of exactly the corporate networks an SSO login gets deployed into. A signature check would cover all three. The two-sided grant would still stand between such a token and an account, since the profile must already name that subject. Verifying signatures is not offered here; where it is needed, this is the gap to close first.

**`exp` and `iat` are not read.** The token is used once, in the request that fetched it, and discarded, so it is as fresh as the exchange that produced it. A provider issuing a stale token for a live code would not be caught here.

**No `nonce` is sent.** In an authorization code flow the binding it would provide is carried by the single-use state, the PKCE verifier and the browser handle, none of which leave this server or this browser.

**Nothing is re-checked after login.** The session is the server's ordinary account session; revoking a grant, or disabling the account at the provider, refuses the *next* login rather than ending sessions already issued.
