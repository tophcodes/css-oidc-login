# Configuration

This assumes the [deployment requirements](./security.md#deployment-requirements) are met: HTTPS on both sides, an account that already exists with its WebID linked, a single worker, and a profile document that can carry a grant.

The Community Solid Server assembles itself at startup from JSON read by [Components.js](https://componentsjs.readthedocs.io/): each object names a class and its constructor arguments under an identifier, and an object reusing an identifier the stock configuration defines adds its values to the ones already there. That is how the entries below hang new handlers, controls, templates and cookie mappings off components the server has already built. This package ships the Components.js metadata that lets a configuration name its classes.

A complete setup on top of the stock config:

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

## Cookie wiring

The two entries reusing `urn:solid-server:default:CookieParser` and `urn:solid-server:default:MetadataWriter_Mapped` carry the pending-login cookie in and out. Without the parser entry the handle never reaches the callback handler; without the writer entry the cookie is never set. Either way every login fails at the callback for want of a cookie — loud and total by design, but it means a configuration naming only the two handlers logs nobody in.

The `Set-Cookie` value is serialised by this package and handed to the server's generic predicate-to-header writer, already wired in the stock configuration. **Do not route it through `CookieMetadataWriter` instead.** That class builds the attributes itself: `SameSite=Lax` and `Path=/` hardcoded with no override, and neither `HttpOnly` nor `Secure`. `SameSite=Strict` is what makes the cross-site form submission fail, and it is the reason this cookie exists; the substitution would look like it worked and reopen the login-CSRF hole in silence.

`urn:css-oidc-login:http:retryAfter` is the milder of the two mappings: it carries the `Retry-After` of a login refused because the store is full. Unmapped, the refusal still happens and the caller is simply not told when to come back.

The store's `cookieName` decides both what is written and what has to be mapped, so a deployment can rename the cookie in one place. The store applies the `__Host-` prefix itself, so a configured `pod-pending-login` produces `__Host-pod-pending-login`, and that prefixed form is what the cookie-parser entry has to name.

## Settings

**`PendingLoginStore`** holds the logins in progress — for each, the PKCE code verifier and the opaque handle belonging to the browser that started it, keyed by the state sent to the provider — and owns the cookie's name and serialisation and the three metadata predicates above. Both handlers must be given the *same* instance; separate ones mean the callback never finds the login that started. `ttlMs` is how long a person may take between arriving at the provider and coming back, and is also the cookie's lifetime: ten minutes by default, generous for a passkey and tight enough that an abandoned attempt is not redeemable all day. `maxPending` is the most logins in progress at once, ten thousand by default; past it a login is refused with a 503 rather than an existing one being evicted.

**`OidcDiscovery`** takes the issuer identifier and reads `authorization_endpoint` and `token_endpoint` from `<issuer>/.well-known/openid-configuration`. It refuses to follow a redirect away from the issuer, refuses a document that is not a JSON object, refuses one whose own `issuer` names a different provider, and refuses endpoints that are not absolute `https:` URLs. The fetch gives up after five seconds and stops reading past a megabyte. A successful lookup is cached for the life of the process, so a provider that moves its endpoints needs a restart here. Share one instance; two would only mean two fetches of the same document.

**The two routes** are ordinary account-API routes, so their URLs follow from where the configuration hangs them: as written, `/.account/login/oidc/` under the server's login route, where the login-method list lives, and `/.account/login/oidc/callback/` beneath it. Any other path works as long as `callbackUrl` agrees. Both answer only POST and refuse anything else with a 405.

**`callbackUrl`** is the absolute URL the callback route resolves to. It appears twice on purpose — sent as `redirect_uri` in the authorization request and again in the token exchange, which the provider compares — and must be registered at the provider verbatim, trailing slash included. It must be `https:`.

**`scopes`** defaults to `openid profile`. Keep `profile` unless the provider is known not to need it: see the [Pocket ID notes](./providers.md#pocket-id), where dropping it silently costs the WebID claim.

**`clientId` and `clientSecret`** identify a confidential client at the provider. The exchange sends both in the request body, so the provider must accept `client_secret_post`; both providers in [the walkthroughs](./providers.md) do.

**`issuer`** on the callback handler is what an ID token's `iss` is compared against. It is stated separately from the discovery object rather than derived from it because the two are different assertions — where to go asking, and whose tokens are acceptable. Discovery's `issuer` must be an absolute `https:` URL; this one is only ever compared as a string, so write the two identically.

**`accountStore` and `cookieStore`** are the server's own, and are what turn a passed check into a session cookie. **`storage`** is the indexed storage holding the server's WebID links; the handler reads it to resolve a WebID to an account and never writes to it.

**`webIdClaim`** names the claim the WebID is read from, defaulting to `webid`, the claim Solid-OIDC defines and some providers already emit.

**`trustPredicate`** is the predicate a grant hangs off the WebID under, defaulting to `https://tophcodes.github.io/css-oidc-login/ns#externalLogin` (see [why not `solid:oidcIssuer`](./security.md#why-not-solidoidcissuer)). Once set, the default term is no longer accepted. The value must be an absolute IRI — a scheme, then only what a Turtle document may carry inside one: no space, no control character, none of `<>"{}|^`, no backtick and no backslash — under any scheme, since the predicate is compared as a string and never dereferenced. Anything else could never appear as a predicate in a parsed profile, so it would match nothing anywhere and turn every login into a refusal. It is caught where it is configured instead: the handler will not be constructed, and the server fails to start with *The configured trust predicate &lt;value&gt; is not an absolute IRI, so no profile can carry a grant under it and every login would be refused as if its owner had granted nothing.*

## The client secret

The example has the secret inline, which is fine for reading and wrong for deploying. Components.js reads this file at startup, so the value lives in a file the server user can read: at minimum keep it out of the repository holding the rest of the configuration, and give it permissions matching its contents.

The server does have a mechanism for startup-supplied values — its CLI parameters are declared as variables and can be filled from `CSS_`-prefixed environment variables — but the set of those parameters is itself configuration. Extending it means declaring a variable, adding an option to the server's CLI extractor and a resolver entry for it, then referencing the variable here. This package does not ship that, and neither the package nor this document has been exercised that way.

## The two pages

The account API takes its input from JSON request bodies, and the stock request parsing strips the query string before a request reaches a handler — but the provider sends the person back with `?code=…&state=…` in the URL. Something has to bridge that, and this package deliberately ships no HTML: styling is left to the deployment. The two files referenced above are ordinary server templates, rendered inside the server's page frame, which already loads the helper functions used below.

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

That the callback page posts to the server rather than letting the provider's redirect do the work is load-bearing. The navigation back from the provider is cross-site, and a `SameSite=Strict` cookie is not sent with it; the request the page then makes to its own origin is same-site and carries the cookie. A callback handled by anything other than a same-origin request from a page on this server will not find one.

The `location` field in a successful response appears when the login happened inside an active Solid authorization request — the usual case, where a Solid app sent the person here to log in — and points at where that flow resumes. Without it there is nothing left to do but return to the account page.

A client speaking the account API directly needs neither page, but does need a cookie jar: POST to the start route, keep the `Set-Cookie`, follow the `location` it returned, POST `{"state":…,"code":…}` to the callback route **with that cookie**, and use the `authorization` value from the response as the session credential. A client that discards the cookie is refused, exactly as a browser without one would be.

## Installing and building

**The package targets Community Solid Server 7.x**, which it declares as a peer dependency, and is developed against 7.2.

**It is not on npm.** Install it from a checkout — a `file:` dependency, `npm link`, or a copy into the server's `node_modules` — and build it first, since what a server loads is the compiled `dist/`, which also carries the metadata letting a configuration name these classes:

```bash
npm install
npm run build
```

The build compiles `src/` with `tsc` and generates the component descriptions into `dist/components/`. The `@context` URL in the configuration must match the one that generation stamps into `dist/components/context.jsonld`; it tracks the package's major version, which is why a 0.x release is `^0.0.0`.

**The build emits CommonJS**, and has to. Components.js constructs every class it is given with `require()`, so an ES module build gets discovered, registered and parsed exactly as a working one does, and then dies at the moment the first class is constructed. The sources are written as ES modules and the suite runs them that way; only what is published is CommonJS.

**The descriptions are generated against the Components.js line the server runs**, not the newest one. Every generated file names the context of the version it was generated with, and a context the server has never heard of is not resolvable from `node_modules` — it is fetched over the network instead, which the server warns about and which fails outright in a deployment without egress.

Components.js discovers the package by scanning `node_modules` from the module path the server was started with, so nothing needs registering by hand once it is installed there.

**In a container**, that scan is the whole story. The published server image holds the server and its own dependencies and nothing else, so a third-party handler means an image built on top of it: install this package where Components.js will find it, and add the configuration file and the two templates. No Dockerfile or tested recipe ships here and the author has not run it in a container — deploying that way means working the layout out from scratch and confirming afterwards that the new entry appears in the login-method list.

Tests are Node's own runner over the TypeScript sources, with no test framework:

```bash
npm test
```

That needs Node 22.7 or newer, for the type stripping that lets `node --test` read `.ts` files directly. 22.6 accepts the flag, but its stripper does not erase accessibility modifiers, and every class here declares a `public constructor` — so the suite dies on the first source file it loads rather than failing a test. Both floors are declared in the manifest and checked by the suite itself: `engines` says Node 18 or newer, which is what the published `dist/` needs, and `devEngines` says 22.7 or newer, which is what running the tests from source needs.
