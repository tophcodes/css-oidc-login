# Setting up the provider

The settings named here — `callbackUrl`, `issuer`, `clientId`, `clientSecret` and `scopes` — are the ones in [Configuration](./configuration.md#settings).

## Pocket ID

[Pocket ID](https://pocket-id.org/) is passkey-only, which suits a pod that should have no password anywhere. It has no notion of a WebID, so the WebID travels in a custom claim.

Create an OIDC client for the pod, with the configured `callbackUrl` as its callback URL, exactly. Note the client ID and secret. Where the client's group restriction is in use, the people who should be able to log in have to be in an allowed group.

For each person, add a custom claim on their user: key `webid`, value their WebID. Pocket ID also allows custom claims on groups, which is the wrong tool here — a WebID identifies one person, and a group claim would hand the same WebID to everyone in the group.

The trap: **Pocket ID only emits custom claims when the client requests the `profile` scope.** With `"scopes": "openid"` the flow completes, the token arrives, and the login fails with *The ID token carries no webid claim (webid). A provider emits it only for a client whose registered scopes and claim mapping ask for it.* — which reads like a broken claim mapping and is a missing scope. It arrives as a 502, since a token minted without the claim is the provider answering what this deployment asked of it. The default `openid profile` is correct; do not narrow it.

`issuer` is the base URL of the Pocket ID instance. For the subject identifier each person needs in their grant, use the failed-login message described in [getting grants into profiles](./security.md#getting-grants-into-profiles) rather than guessing at a field in the admin interface.

## Keycloak

Create a client in the realm with client authentication enabled — a confidential client — with the standard flow on and the configured `callbackUrl` as a valid redirect URI. PKCE is sent regardless; setting the client's challenge method to S256 in its advanced settings makes it mandatory rather than merely used.

The WebID comes from a user attribute. Set an attribute named `webid` on each user, and add a dedicated protocol mapper on the client of type *User Attribute*, with user attribute `webid`, token claim name `webid`, and *Add to ID token* switched on. Without the mapper the attribute exists but never leaves Keycloak.

The trap is one level earlier: since Keycloak 24, unmanaged attributes are disabled for new realms, so the *Attributes* tab on a user is not shown and there is nowhere to put the WebID. Either declare `webid` in the realm's user profile — the tidier option, and it brings validation with it — or set *Unmanaged Attributes* in the realm's general settings to *Admin can edit*.

`issuer` is `https://keycloak.example.com/realms/<realm>`, the same URL that serves `.well-known/openid-configuration`. Keycloak always sets `azp` to the client, so the [authorized-party check](./security.md#what-is-checked) passes without further configuration.

Keycloak's subject identifier is its own internal identifier for the user, not the username or the email address, and a protocol mapper can change it — so here too, read the subject out of the refusal message rather than assuming which field it is.
