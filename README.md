# css-oidc-login

An additional login method for the [Community Solid Server](https://github.com/CommunitySolidServer/CommunitySolidServer): a person signs in to their pod through an external OpenID Connect provider — your company SSO, a self-hosted identity provider, a passkey-only provider — instead of, or alongside, the server's built-in email-and-password login.

## What it does

You run a Community Solid Server. People have accounts on it, each with a WebID linked to the account, and today they log in with an email address and a password your server stores. You would rather they authenticated somewhere else: at the identity provider your organisation already runs, or at a passkey-only provider so that nobody has a pod password at all.

This package adds a second entry to the server's list of login methods. Choosing it sends the person to the external provider, and when they come back the server gives them exactly the session it would have given them after a password login: the same session cookie, for the same account, with the same rights. Nothing else about the server changes, and password login keeps working next to it unless you switch it off.

Mechanically it is two handlers wired into the server's account API, plus two small pieces of cookie plumbing. One handler starts an authorization-code flow with PKCE and redirects the person to the provider. The other takes the callback, exchanges the code for an ID token in a direct back-channel request, reads a WebID out of that token, checks that the person named in the token is one the profile behind that WebID has agreed to, finds the account the WebID is linked to, and logs that account in.

If you are looking for something that lets people create pods by signing in with an external provider, this is not it. It authenticates people who already have an account here; it never creates one.

## Status

This package is pre-1.0 and is not published on npm. It has had no external review and no security audit, and its author knows of no deployment running it. What exists is the source, a test suite that includes the attacks described in this document as failing cases, and this file. Everything below describes behaviour that is implemented and tested; none of it describes behaviour that has been observed under load, under attack, or over time.

Read the sections on what is checked and what is not before pointing it at accounts you care about, and treat the first deployment as your own evaluation rather than someone else's.

## Where authority stays

A common first misunderstanding: this does not replace your server's own OIDC layer, and it does not make the external provider the issuer of anything a Solid app sees.

The access tokens a Solid client uses to write to a pod are still minted by your Community Solid Server, from its own keys, at its own issuer URL. Those tokens are DPoP-bound — each one only works when presented together with a fresh proof signed by the private key of the client that obtained it — and issuing them is your server's job, not the external provider's. That issuer URL is what a person's `solid:oidcIssuer` triple points at, and none of this changes it. When the server links a WebID to an account it still tells the person to name the server itself as their OIDC issuer.

The external provider does one job: it tells your server which human is at the keyboard. Its ID token is consumed inside a single back-channel request, is never stored, and is never seen by a Solid client. Authority over pod access stays entirely with your server; authority over the login moment is what you are delegating.

## Two-sided consent

A login needs two independent statements to agree.

1. The configured provider issues an ID token that names a WebID, for a subject at that provider.
2. The document that WebID resolves to says, in its own words, that it accepts authentication of that particular subject at that particular provider.

Neither half is sufficient. Adding a provider to your server configuration grants that provider nothing on its own: until a person writes a grant into their own profile, a token from it logs nobody in. Naming the provider in a profile is not sufficient either, because a grant is about a person and not about a provider — everyone else who can obtain a token from the same provider is a stranger to it, including whoever arranged for someone else's WebID to appear in their own token.

The grant a person adds to their WebID profile document is one node carrying two statements:

```turtle
<https://pod.example.com/alice/profile/card#me>
  <https://tophcodes.github.io/css-oidc-login/ns#externalLogin> [
    <https://tophcodes.github.io/css-oidc-login/ns#issuer> <https://id.example.com> ;
    <https://tophcodes.github.io/css-oidc-login/ns#subject> "b1e5c0de-4f2a-4c1e-9a77-1f0e2d3c4b5a"
  ] .
```

The subject of the statement is the person's own WebID. The object is a grant node — blank here, but a named node works the same way — that names the issuer you configured and the subject identifier that provider assigns to this person. Removing the grant revokes external login for that person alone, immediately, without touching the server: the next callback for that WebID is refused. No administrator has to be involved and nobody else is affected.

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

`solid:oidcIssuer` already exists and looks like it means what is needed here. It does not. It means "this issuer mints my Solid access tokens", and Solid clients act on it: a client reading it goes to that issuer to obtain the DPoP-bound tokens described above. An external OIDC provider mints no access tokens for your pod, so a person who reused `solid:oidcIssuer` to express "I am willing to log in through this provider" would be sending every Solid client that reads their profile to a provider that cannot serve it — while also, in some deployments, saying that this provider may mint tokens for their identity.

So the grant uses a term of this package's own, which means only "this server may accept an authentication of me, as this subject, at this issuer". The IRI is an identifier and nothing more: the server compares it as a string and never dereferences it. If you would rather use a term of your own for the predicate that carries the grant, `trustPredicate` takes any absolute IRI, under whatever scheme, and once set the default term is no longer accepted. The two predicates read *on* the grant node are fixed, so no configuration can produce a grant that names an issuer and no subject.

## Before you deploy

**Your server must be served over HTTPS.** The cookie that binds a login to one browser carries the `__Host-` prefix, and a browser does not store such a cookie over plain HTTP. Rather than let every login fail at the callback with a cookie that was never set, the login refuses at the start — on the first attempt, before the person leaves for the provider — with an error naming the cookie, the offending callback URL, and the remedy. An `http://localhost` deployment cannot use this login method at all. This is deliberate: an external login cannot be made safe over plain HTTP, and it is a trade, not an oversight — the server's own account cookie omits `Secure` precisely so that localhost keeps working, and this cookie does not.

**The provider must be served over HTTPS as well.** The configured `issuer` has to be an absolute `https:` URL, and so do the `authorization_endpoint` and the `token_endpoint` its discovery document names. A provider reachable only over plain HTTP is refused rather than used: the token exchange would put the client secret and the authorization code on the wire in clear, and the authorization endpoint is handed to a browser as an address to navigate to. Both refusals land on the first login attempt, before the person leaves for the provider. An issuer that is not `https:` is a 500 naming the setting: *The configured issuer <issuer> is not an absolute HTTPS URL, so this server cannot look up the discovery document that every later check hangs off.* An endpoint that is not is a 502: *Discovery for <issuer> names a token_endpoint that is not an absolute HTTPS URL.* An identity provider that runs over plain HTTP inside your network — the ordinary case in exactly the deployments this package is for — has to be given a certificate before it can be used from here.

**One login can be in flight per browser.** There is one cookie name, so there is one handle per browser. A second login started in the same browser overwrites the first one's cookie, and the first can then no longer be completed; it is left to expire rather than being spent. Supporting two would mean a cookie per login, which means a cookie name per login, which neither the `__Host-` prefix nor the fixed name in the cookie-parser mapping allows.

**The account must already exist, with its WebID already linked.** The link is made through the server's own account API, which in turn refuses to link a WebID to an account that has no login method at all — so set the account up the ordinary way first. A token naming a WebID no account here is linked to is refused and nothing is created. A WebID linked to more than one account is refused too, deliberately: the token says who the person is, not which of their accounts they meant, and the storage promises no order, so picking one would be guessing whose session to hand out. Unlink it from all but one.

**Keep password login enabled unless you have thought about the alternative.** If a person's only authentication device is a passkey and they lose it, a provider that can no longer identify them leaves an account nobody can reach. The server's own email-and-password login, left switched on beside this one, is the recovery path.

**A profile that is not plain Turtle at its own URL cannot carry a grant.** Static hosts that serve `.ttl` as `text/plain`, WebIDs that redirect to a profile elsewhere, profiles offered only as JSON-LD, profiles that need authentication to read, profiles that do not answer within five seconds and profiles larger than a megabyte are all refused. Pods on this server are fine, and so is any host you can configure.

**Pending logins live in the process's memory.** They do not survive a restart and they are not shared between workers, so the server has to run with a single worker — which is its default, but worth checking if you have raised it. An abandoned attempt occupies an entry until its TTL passes; expired entries are reclaimed by the next login that needs the room, and the store holds at most `maxPending` logins in progress — ten thousand by default — however fast they arrive. The route that creates them is reachable without authentication, so a full store is reachable too: past the cap, further logins are refused with a 503 and a `Retry-After` naming the TTL, until room appears. No login already in progress is ever evicted to make space for a new one, because whoever can fill the store would otherwise decide whose login gets thrown away. Size `maxPending` for the deployment.

**Discovery is fetched once and cached for the life of the process.** A provider that moves its endpoints needs a restart here.

**The package targets Community Solid Server 7.x**, which it declares as a peer dependency, and it is developed against 7.2.

## Configuration

The Community Solid Server assembles itself at startup from JSON configuration read by [Components.js](https://componentsjs.readthedocs.io/): each object in the graph names a class and the arguments its constructor gets, under an identifier. Your own configuration file imports the server's stock configuration and then adds objects of its own — and where it reuses an identifier the stock configuration already defines, the values it supplies are added to the ones already there. That is how the entries below hang new handlers, controls, templates and cookie mappings off components the server has already built, without copying the stock configuration.

This package ships the Components.js metadata that lets a configuration name its classes, so everything is wired in a file. The following is a complete setup on top of the stock config:

```json
{
  "@context": [
    "https://linkedsoftwaredependencies.org/bundles/npm/@solid/community-server/^7.0.0/components/context.jsonld",
    "https://linkedsoftwaredependencies.org/bundles/npm/css-oidc-login/^0.0.0/components/context.jsonld"
  ],
  "import": [ "css:config/default.json" ],
  "@graph": [
    {
      "@id": "urn:css-oidc-login:default:PendingLoginStore",
      "@type": "PendingLoginStore",
      "ttlMs": 600000
    },
    {
      "@id": "urn:css-oidc-login:default:Discovery",
      "@type": "OidcDiscovery",
      "issuer": "https://id.example.com"
    },

    {
      "@id": "urn:css-oidc-login:default:StartRouter",
      "@type": "InteractionRouteHandler",
      "route": {
        "@id": "urn:css-oidc-login:default:StartRoute",
        "@type": "RelativePathInteractionRoute",
        "base": { "@id": "urn:solid-server:default:LoginRoute" },
        "relativePath": "oidc/"
      },
      "source": {
        "@type": "OidcRedirectHandler",
        "store": { "@id": "urn:css-oidc-login:default:PendingLoginStore" },
        "discovery": { "@id": "urn:css-oidc-login:default:Discovery" },
        "clientId": "solid-pod",
        "callbackUrl": "https://pod.example.com/.account/login/oidc/callback/",
        "scopes": "openid profile"
      }
    },
    {
      "@id": "urn:css-oidc-login:default:CallbackRouter",
      "@type": "InteractionRouteHandler",
      "route": {
        "@id": "urn:css-oidc-login:default:CallbackRoute",
        "@type": "RelativePathInteractionRoute",
        "base": { "@id": "urn:css-oidc-login:default:StartRoute" },
        "relativePath": "callback/"
      },
      "source": {
        "@type": "OidcCallbackHandler",
        "accountStore": { "@id": "urn:solid-server:default:AccountStore" },
        "cookieStore": { "@id": "urn:solid-server:default:CookieStore" },
        "store": { "@id": "urn:css-oidc-login:default:PendingLoginStore" },
        "storage": { "@id": "urn:solid-server:default:AccountStorage" },
        "discovery": { "@id": "urn:css-oidc-login:default:Discovery" },
        "issuer": "https://id.example.com",
        "clientId": "solid-pod",
        "clientSecret": "the-client-secret",
        "callbackUrl": "https://pod.example.com/.account/login/oidc/callback/",
        "webIdClaim": "webid"
      }
    },

    {
      "@id": "urn:solid-server:default:CookieParser",
      "@type": "CookieParser",
      "cookieMap": [{
        "CookieParser:_cookieMap_key": "__Host-css-oidc-login-pending",
        "CookieParser:_cookieMap_value": "urn:css-oidc-login:http:pendingLoginCookie"
      }]
    },
    {
      "@id": "urn:solid-server:default:MetadataWriter_Mapped",
      "@type": "MappedMetadataWriter",
      "headerMap": [{
        "MappedMetadataWriter:_headerMap_key": "urn:css-oidc-login:http:setPendingLoginCookie",
        "MappedMetadataWriter:_headerMap_value": "Set-Cookie"
      }, {
        "MappedMetadataWriter:_headerMap_key": "urn:css-oidc-login:http:retryAfter",
        "MappedMetadataWriter:_headerMap_value": "Retry-After"
      }]
    },

    {
      "@id": "urn:solid-server:default:InteractionRouteHandler",
      "@type": "WaterfallHandler",
      "handlers": [
        { "@id": "urn:css-oidc-login:default:StartRouter" },
        { "@id": "urn:css-oidc-login:default:CallbackRouter" }
      ]
    },
    {
      "@id": "urn:solid-server:default:LoginHandler",
      "@type": "ControlHandler",
      "controls": [{
        "ControlHandler:_controls_key": "External OpenID Connect provider",
        "ControlHandler:_controls_value": { "@id": "urn:css-oidc-login:default:StartRoute" }
      }]
    },
    {
      "@id": "urn:solid-server:default:HtmlViewHandler",
      "@type": "HtmlViewHandler",
      "templates": [
        {
          "@id": "urn:css-oidc-login:default:StartHtml",
          "@type": "HtmlViewEntry",
          "filePath": "/etc/css/templates/oidc-start.html.ejs",
          "route": { "@id": "urn:css-oidc-login:default:StartRoute" }
        },
        {
          "@id": "urn:css-oidc-login:default:CallbackHtml",
          "@type": "HtmlViewEntry",
          "filePath": "/etc/css/templates/oidc-callback.html.ejs",
          "route": { "@id": "urn:css-oidc-login:default:CallbackRoute" }
        }
      ]
    }
  ]
}
```

### The cookie wiring is not optional

The two entries reusing `urn:solid-server:default:CookieParser` and `urn:solid-server:default:MetadataWriter_Mapped` are what carry the pending-login cookie in and out. Without the parser entry the handle never reaches the callback handler; without the writer entry the cookie is never set in the first place. Either omission makes every login fail, with the callback refusing because it carried no cookie. That is by design — the failure is loud and total rather than a deployment that silently runs without the protection — but it does mean a configuration that names only the two handlers cannot log anyone in.

The `Set-Cookie` value is serialised by this package and handed to the server's generic predicate-to-header writer, which is already wired in the stock configuration. **Do not route it through the server's cookie writer instead.** `CookieMetadataWriter` builds the attributes itself and hardcodes `SameSite=Lax` and `Path=/`, with no way to override either, and sets neither `HttpOnly` nor `Secure`. `SameSite=Strict` is the attribute that makes the cross-site form submission fail, and it is the reason this cookie exists; the substitution would look like it worked and would reopen the login-CSRF hole in silence.

The second `headerMap` entry is not in that class. `urn:css-oidc-login:http:retryAfter` carries the `Retry-After` of a login refused because the store is full; left unmapped, the refusal still happens and the caller is simply not told when to come back. It costs a header, not a login.

The store's `cookieName` is the single field deciding both what is written and what has to be mapped, so a deployment can rename the cookie in one place. One wrinkle: the store applies the `__Host-` prefix itself, so a configured name of `pod-pending-login` produces the cookie `__Host-pod-pending-login`, and that prefixed form is what the cookie-parser entry has to name.

### The rest of it

**The pending-login store** holds the logins in progress: for each, the PKCE code verifier and the opaque handle that belongs to the browser that started it, keyed by the state sent to the provider. It also owns the cookie's name and serialisation, and the three metadata predicates above. Both handlers must be given the *same* instance — if each gets its own, the callback never finds the login that started, and no login can succeed. `ttlMs` is how long a person may take between arriving at the provider and coming back, and is also the cookie's lifetime; it defaults to ten minutes, which is generous for a passkey and tight enough that an abandoned attempt does not stay redeemable all day. `maxPending` is the most logins that may be in progress at once, ten thousand by default; past it a login is refused with the 503 described above rather than an existing one being evicted for it.

**The discovery object** takes the provider's issuer identifier and reads `authorization_endpoint` and `token_endpoint` from `<issuer>/.well-known/openid-configuration`. It refuses to follow a redirect away from the issuer, refuses a document that is not a JSON object, refuses one whose own `issuer` field names a different provider — every later check hangs off what this document says, so a document from elsewhere would be a document about somebody else — and refuses one whose `authorization_endpoint` or `token_endpoint` is not an absolute `https:` URL. The fetch gives up after five seconds and stops reading past a megabyte. The answer is cached for the life of the process. Share one instance, as above; two would only mean two fetches of the same document.

**The two routes** are ordinary account-API routes, so their URLs follow from where you hang them. As written, the start route is `/.account/login/oidc/` — under the server's login route, which is where the login-method list lives — and the callback is `/.account/login/oidc/callback/` beneath it. Any other path works as long as `callbackUrl` agrees with it. Both answer only POST, and refuse anything else with a 405: each of them acts — one hands out a cookie, the other spends it — so neither has a safe reading. The two pages below and the direct-client walkthrough already post to both.

**`callbackUrl`** must be the absolute URL the callback route resolves to, and it appears twice on purpose: it is sent as `redirect_uri` in the authorization request and again in the token exchange, and the provider compares the two. Register it at the provider verbatim, trailing slash included. It must be `https:`, as described above.

**`scopes`** defaults to `openid profile`. Keep `profile` unless you are certain your provider does not need it — see the Pocket ID notes below, where dropping it silently costs you the WebID claim.

**`clientId` and `clientSecret`** identify a confidential client at the provider. The token exchange sends both in the request body, so the provider must accept `client_secret_post`; both providers below do.

**`issuer`** on the callback handler is what an ID token's `iss` claim is compared against. It is stated separately from the discovery object rather than derived from it, because these are two different assertions: one is where to go asking, the other is whose tokens are acceptable. The discovery object's `issuer` has to be an absolute `https:` URL, as described above; this one is only ever compared as a string, so write the two identically.

**`accountStore` and `cookieStore`** are the server's own, and are what turn a successful check into a session cookie. **`storage`** is the indexed storage the server keeps its WebID links in; the handler reads it to resolve a WebID to an account and never writes to it.

**`webIdClaim`** names the claim the WebID is read from, defaulting to `webid` — the claim Solid-OIDC itself defines, which some providers already emit. Anything else, and you name it here.

**`trustPredicate`** is optional and defaults to the term described above. Set it only if you want a term of your own; once set, the default term is no longer accepted. A value has to be an absolute IRI: a scheme, and after it only what a Turtle document could carry inside one — no space, no control character, none of `<>"{}|^`, no backtick and no backslash. Any scheme will do, since the predicate is compared as a string and never dereferenced. Anything else could never appear as a predicate in a parsed profile, so it would match every profile alike — not at all — and every login would end as a refusal blaming a person for a grant they did write. It is refused where it is configured instead: the handler will not be constructed, so the server stops at startup with a 500 naming the setting and its value, *The configured trust predicate <value> is not an absolute IRI, so no profile can carry a grant under it and every login would be refused as if its owner had granted nothing.*

### Where the client secret belongs

The example above has the secret inline, which is fine for reading and wrong for deploying. Components.js reads this file at startup, so whatever the value is, it lives in a file on disk that the server user can read: at minimum, keep it out of the repository that holds the rest of your configuration, and give it file permissions that match its contents.

The server does have a mechanism for values supplied at startup — its own command-line parameters are declared as variables and can be filled from `CSS_`-prefixed environment variables — but the set of those parameters is itself configuration. Extending it to a parameter of your own means declaring a variable, adding an option to the server's CLI extractor and a resolver entry for it, and then referencing the variable here. That mechanism exists; this package does not ship it, and neither the package nor this document has been exercised that way.

## The two pages the browser needs

The account API takes its input from JSON request bodies, and the stock request parsing strips the query string before a request reaches a handler. The provider, though, sends the person back with `?code=…&state=…` in the URL. Something has to bridge that, and this package deliberately ships no HTML: templates are yours to style, and the server already has a mechanism for registering them.

The two files referenced from the configuration above are ordinary server templates, rendered inside the server's page frame, which already loads the helper script used below.

`oidc-start.html.ejs` asks its own URL for the authorization URL and sends the person on:

```html
<h1>Redirecting to the external provider</h1>
<p class="error" id="error"></p>
<script>
  (async() => {
    try {
      const response = await postJson('', {});
      const body = await response.json();
      if (body.location) {
        location.href = body.location;
      } else {
        setError(body.message ?? 'The server returned no location.');
      }
    } catch (error) {
      setError(error.message);
    }
  })();
</script>
```

`oidc-callback.html.ejs` turns the provider's query parameters into the JSON body the callback handler reads:

```html
<h1>Completing the login</h1>
<p class="error" id="error"></p>
<script>
  (async() => {
    const params = new URLSearchParams(location.search);
    try {
      const response = await postJson('', { state: params.get('state'), code: params.get('code') });
      const body = await response.json();
      if (response.status >= 400) {
        setError(body.message);
      } else {
        location.href = body.location ?? '<%= idpIndex %>';
      }
    } catch (error) {
      setError(error.message);
    }
  })();
</script>
```

That the callback page posts to the server rather than letting the provider's redirect do the work is load-bearing. The navigation back from the provider is a cross-site one, and a `SameSite=Strict` cookie is not sent with it; the request the page then makes to its own origin is same-site, and carries the cookie. A callback handled by anything other than a same-origin request from a page on this server will not find one.

The `location` field in the successful response appears when the login happened inside an active Solid authorization request — the usual case, where a Solid app sent the person here to log in. It points at the place that flow resumes. Without it, there is nothing left to do but go back to the account page.

A client that speaks the account API directly needs neither page, but does need a cookie jar: POST to the start route, keep the `Set-Cookie` from that response, follow the `location` you got back, POST `{"state":…,"code":…}` to the callback route **with that cookie**, and use the `authorization` value from the response as the session credential. A client that discards the cookie is refused, exactly as a browser without one would be.

## Setting up the provider

### Pocket ID (WebID in a custom claim)

[Pocket ID](https://pocket-id.org/) is passkey-only, which makes it a good fit for a pod that should have no password anywhere. It has no notion of a WebID, so the WebID travels in a custom claim.

Create an OIDC client for the pod. Set its callback URL to your `callbackUrl`, exactly. Note the client ID and secret. If you use the client's group restriction, make sure the people who should be able to log in are in an allowed group.

For each person, add a custom claim on their user: key `webid`, value their WebID. Pocket ID also allows custom claims on groups, which is the wrong tool here — a WebID identifies one person, and a group claim would hand the same WebID to everyone in the group.

The trap: **Pocket ID only emits custom claims when the client requests the `profile` scope.** With `"scopes": "openid"` the flow completes, the token arrives, and the login fails with *The ID token carries no webid claim (webid). A provider emits it only for a client whose registered scopes and claim mapping ask for it.* — which reads like a misconfigured claim and is in fact a missing scope. It arrives as a 502, because a token minted without the claim is the provider answering what this deployment asked of it, and nobody at the browser can do anything about it. The default `openid profile` is correct; do not narrow it.

`issuer` is the base URL of your Pocket ID instance. For the subject identifier each person needs in their grant, use the failed-login message described above rather than guessing at a field in the admin interface.

### Keycloak (WebID from a user attribute)

Create a client in your realm with client authentication enabled — a confidential client — with the standard flow on and your `callbackUrl` as a valid redirect URI. PKCE is sent regardless; setting the client's challenge method to S256 in its advanced settings makes it mandatory rather than merely used.

The WebID comes from a user attribute. Set an attribute named `webid` on each user, and add a dedicated protocol mapper on the client of type *User Attribute*, with user attribute `webid`, token claim name `webid`, and *Add to ID token* switched on. Without that mapper the attribute exists but never leaves Keycloak.

The trap here is one level earlier: since Keycloak 24, unmanaged attributes are disabled for new realms, so the *Attributes* tab on a user is not even shown and there is nowhere to put the WebID. Either declare `webid` in the realm's user profile — the tidier option, and it gives you validation — or set *Unmanaged Attributes* in the realm's general settings to *Admin can edit*.

`issuer` is `https://keycloak.example.com/realms/<realm>`, the same URL whose `.well-known/openid-configuration` you can fetch. Keycloak always sets `azp` to the client, so the authorized-party check below is satisfied without further configuration.

Keycloak's subject identifier is its own internal identifier for the user, not the username or the email address, and a protocol mapper can change it — so here too, read the subject out of the refusal message rather than assuming which field it is.

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
- **The grant**: the profile that WebID resolves to must carry a grant naming both the configured issuer and that exact subject, under the conditions described earlier.

The token exchange itself is bounded and pinned. It is a direct back-channel POST to the endpoint the discovery document named, over TLS, refusing to follow a redirect — a `307` or `308` would replay that POST body, client secret and authorization code and PKCE verifier included, at whatever host the response named. It gives up after five seconds and stops reading past a megabyte, as do the discovery and profile fetches, so no single unresponsive or endless host can occupy the server's one worker indefinitely.

What comes back out of that exchange is attributed rather than lumped together. Only a 400 or 401 carrying `invalid_grant` is read as a verdict on the callback this caller brought — a code already spent, expired, issued to somebody else, or not matching this verifier or redirect URI — and only that reaches them as a 400. Every other refusal is the provider's: another status, another code, `invalid_client` above all, which is what a wrong client secret comes back as, and a 400 that carries no well-formed error body at all. So is everything the provider composes after saying yes — a token response that is not JSON, one carrying no ID token, an ID token that is not a well-formed JWT, and claims naming another issuer, another client or no subject.

**What a refusal looks like.** Every failure leaves as a status and a `message` in the JSON body, which is what the callback page above displays:

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

## Installing, building, testing

**It is not on npm.** Install it from a checkout — a `file:` dependency, `npm link`, or a copy into the server's `node_modules` — and build it first, since what a server loads is the compiled `dist/` directory, which also carries the metadata that lets a configuration name these classes:

```bash
npm install
npm run build
```

The build compiles `src/` with `tsc` and then generates the component descriptions into `dist/components/`. The `@context` URL in your configuration must match the one that generation stamps into `dist/components/context.jsonld`; it tracks the package's major version, which is why a 0.x release is `^0.0.0`.

Components.js discovers the package by scanning `node_modules` from the module path the server was started with, so nothing needs registering by hand once it is installed there.

**In a container**, that scan is the whole story. The published server image contains the server and its own dependencies and nothing else, so a third-party handler means an image built on top of it: install this package where Components.js will find it, and add your configuration file and the two templates. Neither a Dockerfile nor a tested recipe for that ships here, and the author has not run it in a container — if you deploy that way, expect to work out the layout yourself, and confirm afterwards that the new entry actually appears in the server's list of login methods.

Tests are Node's own runner over the TypeScript sources, with no test framework:

```bash
npm test
```

That needs Node 22.7 or newer, for the type stripping that lets `node --test` read `.ts` files directly. 22.6 is the release that accepts the flag, but its stripper does not erase accessibility modifiers, and every class here declares a `public constructor` — so the suite dies on the first source file it loads rather than failing a test.

Both floors are declared in the manifest and both are checked by the suite itself: `engines` says Node 18 or newer, which is what the published `dist/` needs and all it needs, and `devEngines` says 22.7 or newer, which is what running the tests from source needs.

## License

MIT. See [LICENSE](./LICENSE).
