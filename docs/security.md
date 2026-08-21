# Security

## Two-sided consent, in full

The [README](../README.md#two-sided-consent) states the model in short: a login needs the configured provider to issue an ID token naming a WebID, and the document that WebID resolves to has to say, in its own words, that it accepts authentication of that particular subject at that particular provider. This is the whole of it.

The pairing is load-bearing rather than decorative. If the issuer and the subject were two separate triples hanging off the WebID, a profile that opts in to two providers would cross-match: the subject recorded for one would satisfy a token from the other. At providers whose subject identifier is a username or an email address, and which anyone can register with, that is a way in. So a profile with two grants carries two nodes:

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

Because this is a grant, the server is strict about what counts as one:

- The profile is fetched from the WebID's own URL and redirects are not followed. A document at the end of a redirect chain is a document somewhere else, not the document at the WebID.
- It must be served as `text/turtle`, and it must parse. Nothing else is read.
- The grant must be in the document's default graph, attached to the WebID itself. A statement about somebody else, or one parked in a named graph, is content that appears near the WebID rather than an assertion by it.
- On the grant node, the issuer must be an IRI and the subject must be a literal. An issuer written as a quoted string is not an identifier, and a subject written as an IRI is a claim about a different kind of thing; the subject is compared verbatim, byte for byte.
- Trailing slashes are ignored when issuers are compared, on both sides.
- The fetch carries no credentials, so the profile has to be readable without authentication. On a pod this server created, the profile document is public-read by default, which is what makes this work.

The tests are written around exactly these near misses, because an implementation that merely searched the document for the issuer's name would accept every one of them.

## Getting the grant into people's profiles

This is the part that decides whether the package fits your deployment, so it is worth being blunt about.

Each person needs two things arranged, and only one of them is yours to do. At the provider, their WebID has to be in a claim, which is administrator work you do once per person in a console you already use. In their profile, the grant above has to exist, which is RDF that someone has to write into a document on the pod.

Nothing in this package writes it. There is no page in the server for it, no command-line tool here, and no import format. For a person who is comfortable editing their own profile document, it is a copy-paste. For everyone else, it is a wall, and a support request that lands on you.

The awkward half is the subject identifier. It is opaque, assigned by the provider, and usually neither the username nor the email address — so the person generally cannot look it up, and telling them to find it in the provider's admin console means giving them the admin console. The reliable way to obtain it is to let the login fail once: with the grant absent or its subject wrong, the callback refuses with a message that names the exact string: `The profile at <webid> does not accept <subject> as its subject at <issuer>; its owner has to name that subject in the grant before this login can be completed.` That string is the caller's own subject identifier, and can be pasted straight into the grant. Disclosing it is safe — it is never anybody else's.

The write itself can be scripted, because the profile document is an ordinary pod resource: its owner can write it, and the server accepts a full `PUT` as well as a `PATCH` in N3 Patch or SPARQL Update form. An operator holding a credential with write access to each profile can therefore add grants in bulk. That script is yours to write.

So: for a household or a team of five, this is a one-paragraph instruction per person. For forty members with mixed technical confidence, plan for an onboarding step you build and operate — or decide against the package. Choosing it and hoping the grant "will just be a step in the signup email" is how this ends up half-deployed.

## Why the predicate is not `solid:oidcIssuer`

`solid:oidcIssuer` already exists and looks like it means what is needed here. It does not. It means "this issuer mints my Solid access tokens", and Solid clients act on it: a client reading it goes to that issuer to obtain the DPoP-bound tokens described in the [README](../README.md#where-authority-stays). An external OIDC provider mints no access tokens for your pod, so a person who reused `solid:oidcIssuer` to express "I am willing to log in through this provider" would be sending every Solid client that reads their profile to a provider that cannot serve it — while also, in some deployments, saying that this provider may mint tokens for their identity.

So the grant uses a term of this package's own, which means only "this server may accept an authentication of me, as this subject, at this issuer". The IRI is an identifier and nothing more: the server compares it as a string and never dereferences it. If you would rather use a term of your own for the predicate that carries the grant, `trustPredicate` takes any absolute IRI, under whatever scheme, and once set the default term is no longer accepted. The two predicates read *on* the grant node are fixed, so no configuration can produce a grant that names an issuer and no subject.

## Before you deploy

**Your server must be served over HTTPS.** The cookie that binds a login to one browser carries the `__Host-` prefix, and a browser does not store such a cookie over plain HTTP. Rather than let every login fail at the callback with a cookie that was never set, the login refuses at the start — on the first attempt, before the person leaves for the provider — with an error naming the cookie, the offending callback URL, and the remedy. An `http://localhost` deployment cannot use this login method at all. This is deliberate: an external login cannot be made safe over plain HTTP, and it is a trade, not an oversight — the server's own account cookie omits `Secure` precisely so that localhost keeps working, and this cookie does not.

**The provider must be served over HTTPS as well.** The configured `issuer` has to be an absolute `https:` URL, and so do the `authorization_endpoint` and the `token_endpoint` its discovery document names. A provider reachable only over plain HTTP is refused rather than used: the token exchange would put the client secret and the authorization code on the wire in clear, and the authorization endpoint is handed to a browser as an address to navigate to. Both refusals land on the first login attempt, before the person leaves for the provider. An issuer that is not `https:` is a 500 naming the setting: *The configured issuer <issuer> is not an absolute HTTPS URL, so this server cannot look up the discovery document that every later check hangs off.* An endpoint that is not is a 502: *Discovery for <issuer> names a token_endpoint that is not an absolute HTTPS URL.* An identity provider that runs over plain HTTP inside your network — the ordinary case in exactly the deployments this package is for — has to be given a certificate before it can be used from here.

**One login can be in flight per browser.** There is one cookie name, so there is one handle per browser. A second login started in the same browser overwrites the first one's cookie, and the first can then no longer be completed; it is left to expire rather than being spent. Supporting two would mean a cookie per login, which means a cookie name per login, which neither the `__Host-` prefix nor the fixed name in the cookie-parser mapping allows.

**The account must already exist, with its WebID already linked.** The link is made through the server's own account API, which in turn refuses to link a WebID to an account that has no login method at all — so set the account up the ordinary way first. A token naming a WebID no account here is linked to is refused and nothing is created. A WebID linked to more than one account is refused too, deliberately: the token says who the person is, not which of their accounts they meant, and the storage promises no order, so picking one would be guessing whose session to hand out. Unlink it from all but one.

**Keep password login enabled unless you have thought about the alternative.** If a person's only authentication device is a passkey and they lose it, a provider that can no longer identify them leaves an account nobody can reach. The server's own email-and-password login, left switched on beside this one, is the recovery path.

**A profile that is not plain Turtle at its own URL cannot carry a grant.** Static hosts that serve `.ttl` as `text/plain`, WebIDs that redirect to a profile elsewhere, profiles offered only as JSON-LD, profiles that need authentication to read, profiles that do not answer within five seconds and profiles larger than a megabyte are all refused. Pods on this server are fine, and so is any host you can configure.

**Pending logins live in the process's memory.** They do not survive a restart and they are not shared between workers, so the server has to run with a single worker — which is its default, but worth checking if you have raised it. An abandoned attempt occupies an entry until its TTL passes; expired entries are reclaimed by the next login that needs the room, and the store holds at most `maxPending` logins in progress — ten thousand by default — however fast they arrive. The route that creates them is reachable without authentication, so a full store is reachable too: past the cap, further logins are refused with a 503 and a `Retry-After` naming the TTL, until room appears. No login already in progress is ever evicted to make space for a new one, because whoever can fill the store would otherwise decide whose login gets thrown away. Size `maxPending` for the deployment.

## What the server checks before it logs anyone in

For each callback, in order:

- **The pending-login cookie** must be present and must match the login the state names. The state travels through the provider and is therefore known to anyone who sees the callback URL, a proxy log or a `Referer` header; the handle in this cookie — 32 random bytes — only ever travels between this server and one browser. It is compared in constant time. This is what refuses a stolen code and state replayed by somebody else, and what refuses a cross-site form submission that would otherwise log a victim into the attacker's account with a perfectly valid state. The cookie is `HttpOnly`, `Secure`, `SameSite=Strict`, `__Host-`-prefixed and cleared once the login is redeemed.
- **The state** must be one this server issued and has not yet redeemed, and it expires with the pending login's TTL. It is consumed only *after* the cookie has been checked, so a caller who cannot produce the matching handle leaves somebody else's login in progress intact, and a failed callback spends nothing.
- **PKCE** is on every flow. The verifier is generated per login from 32 random bytes, never leaves the server, and is sent only in the token exchange; the provider receives only its SHA-256 challenge. An authorization code intercepted on its way back is not redeemable at the provider without it.
- **The issuer**: the ID token's `iss` claim must be the configured issuer, compared ignoring trailing slashes.
- **The audience**: `aud` — the claim naming the clients a token was minted for — must contain the configured client ID. Without this, any other client registered at the same provider could obtain a token this server would accept.
- **The authorized party**: `azp` names the single client that asked for the token. If it is present it must name this client, and if the token names several audiences it must be present. Both halves are needed: membership in `aud` alone would let another client of the same provider mint itself a token that also lists this one, and checking `azp` only for multi-audience tokens would let it mint one addressed solely here.
- **The WebID claim** must be present, and must be an absolute `http:` or `https:` URL with no control characters in it. It is a string chosen at the provider — for a mapped attribute, chosen by whoever holds the account there — and it ends up in a `fetch`, in a message handed back, and in a log line, so a value outside that is refused rather than passed on.
- **The subject**: the token must carry a non-empty `sub`.
- **The account**: that WebID must resolve to exactly one account on this server.
- **The grant**: the profile that WebID resolves to must carry a grant naming both the configured issuer and that exact subject, under the conditions described in [Two-sided consent](#two-sided-consent-in-full).

The token exchange itself is bounded and pinned. It is a direct back-channel POST to the endpoint the discovery document named, over TLS, refusing to follow a redirect — a `307` or `308` would replay that POST body, client secret and authorization code and PKCE verifier included, at whatever host the response named. It gives up after five seconds and stops reading past a megabyte, as do the discovery and profile fetches, so no single unresponsive or endless host can occupy the server's one worker indefinitely.

What comes back out of that exchange is attributed rather than lumped together. Only a 400 or 401 carrying `invalid_grant` is read as a verdict on the callback this caller brought — a code already spent, expired, issued to somebody else, or not matching this verifier or redirect URI — and only that reaches them as a 400. Every other refusal is the provider's: another status, another code, `invalid_client` above all, which is what a wrong client secret comes back as, and a 400 that carries no well-formed error body at all. So is everything the provider composes after saying yes — a token response that is not JSON, one carrying no ID token, an ID token that is not a well-formed JWT, and claims naming another issuer, another client or no subject.

**What a refusal looks like.** Every failure leaves as a status and a `message` in the JSON body, which is what the [callback page](./configuration.md#the-two-pages-the-browser-needs) displays:

- **400** — the callback itself: no state, no code, an unknown or expired state, no pending-login cookie or more than one of them, a cookie that does not belong to this login, or the provider's `invalid_grant`.
- **403** — permission: the profile carries no grant naming the configured issuer, or none naming this subject, or the WebID is linked to no account here. Whoever reads it is the one who can grant it.
- **409** — the WebID is linked to more than one account here, which is this server's own account data being ambiguous about who is logging in.
- **405** — anything but POST, on either route.
- **502** — the provider or the profile's host answered in a way that is no answer: unreachable, redirecting, a non-2xx status, the wrong media type, unreadable, past the cap, or a token this server was not the audience of.
- **504** — one of those two hosts did not answer within the five seconds.
- **503** — no room for another login in progress; `Retry-After` says when to come back.
- **500** — this deployment's own configuration, named as such rather than reported as somebody's bad request: a callback URL that is not absolute or not `https:`, an issuer that is not `https:`. A trust predicate that is not an absolute IRI is caught earlier still, when the server builds the handler.

## What is not checked

**The ID token's signature is not verified.** OIDC Core 3.1.3.7 permits this for a token obtained the way this one is: "the TLS server validation MAY be used to validate the issuer in place of checking the token signature". The token is never accepted from a browser or a client; it is fetched by this server in the direct back-channel request described above, and the endpoint it is fetched from is itself checked rather than assumed — the discovery document must come from the issuer without a redirect and must name that issuer itself, and the token endpoint must not redirect either. What that section does not excuse are the issuer, audience and authorized-party checks, which is why those are unconditional and have tests of their own.

The residual risk is real and worth stating rather than deflecting. Everything then rests on TLS server validation, so anything that can present a certificate your server's trust store accepts for the provider's host can mint a token this server will accept: a mis-issued or fraudulently obtained certificate, a compromised or coerced CA, or a TLS-intercepting proxy whose root is installed on the server — which is a normal fixture of exactly the corporate networks an SSO login gets deployed into. A signature check would cover all three, and the two-sided grant would still stand between such a token and an account, because the profile must already name that subject. Verifying signatures is a choice this package does not currently offer; if you need it, this is the gap to close first.

**`exp` and `iat` are not looked at.** The token is read once, in the same request that fetched it, and then discarded, so it is as fresh as the exchange that produced it. A provider that issues a stale token to a live code would not be caught here.

**No `nonce` is sent.** In an authorization-code flow the binding it would provide is carried by the single-use state, the PKCE verifier and the browser handle, none of which leave this server or this browser.

**Nothing about the person is re-checked afterwards.** The session this creates is the server's ordinary account session; revoking a grant, or disabling the account at the provider, refuses the *next* login rather than ending sessions already issued.
