# Software passkeys

Hush 0.8 adds encrypted, persistent software passkeys for explicitly authorized
agent workflows. A passkey has an RSA-2048 RS256 signing key, a random 32-byte
credential ID, an independent random 32-byte PRF key, a user handle, a monotonic
signature counter, and an exact origin/RP binding. Private material is serialized
only inside the existing age vault. Public metadata identifies the provider as
`hush-software-v1`.

This is a software authenticator, not a hardware token, OS biometric authenticator,
FIDO-certified device, browser extension, or synchronization service. It does not
add passkeys to Bitwarden. The opt-in Playwright adapter replaces credential
methods only in the context explicitly given to it; it is not Chromium's native
WebAuthn implementation. A normal browser without that adapter continues to use
its existing authenticators. Applications must accept RS256 (`alg: -257`).

## Create and manage

Generate a separate verification secret without displaying it, then authorize
creation by injecting that secret by name:

```sh
hush generate AGENT_PASSKEY_PIN --password --json
hush run --name AGENT_PASSKEY_PIN --env HUSH_PASSKEY_PIN --redact -- \
  hush passkey create SERVICE_PASSKEY --rp-id service.example \
  --origin https://service.example --pin-secret AGENT_PASSKEY_PIN --json
hush passkey list --json
hush passkey info SERVICE_PASSKEY --json
```

Creation refuses an existing name; it never rotates or replaces a credential.
The PIN must contain at least eight bytes. Hush compares it without a
variable-time string comparison and never includes it in a receipt. The exact
HTTPS origin must match the RP hostname; HTTP is allowed only on loopback.
Subdomain RP delegation is deliberately unsupported. Use a different passkey
name for each service/account/registration.

## Use with a trusted browser worker

```sh
hush run --name AGENT_PASSKEY_PIN --env HUSH_PASSKEY_PIN --redact -- \
  hush passkey run --name SERVICE_PASSKEY -- node browser-worker.mjs
```

The worker imports `attachHushPasskeys` from `browser/playwright.mjs`, creates a
Playwright browser context, and calls `await attachHushPasskeys(context)` before
opening pages. Call the returned `close()` after closing the browser. Import
Playwright from the application's existing installation; Hush adds no npm
packages. Do not print worker logs to stdout: stdout is the protocol channel.
Hush suppresses raw worker stderr and emits only a metadata receipt. Save only
explicitly selected, nonsensitive test results if diagnostics are needed.

The trusted adapter takes the origin from Playwright's actual calling frame,
rejects subframes, and sends browser options to Hush. The page never receives the
PIN or private signing/PRF keys. As with all WebAuthn PRF providers, the authorized
page receives the *derived PRF result* and must keep it out of logs and storage.
Treat the worker and the page at the allowed origin as trusted consumers; Hush
cannot prevent them from intentionally exfiltrating data they receive.

The supplied PIN is verified at session start and on every request. It is removed
from the worker environment along with Bitwarden credentials. Successful
operations set UP and UV for the explicitly authorized, PIN-verified software
session. These flags do **not** establish a physical touch, biometric check or
independent human presence. Do not use this provider to satisfy policies requiring
those properties. The PIN lives in the same vault as the key; it does not protect
against compromise of that vault or the agent's OS account.

Registration uses attestation `none` with a real COSE RSA public key and a retained
user handle. Assertions sign `authenticatorData || SHA256(clientDataJSON)` using
RSASSA-PKCS1-v1_5 with SHA-256. Exact origins, RP IDs, credential allow/exclude
lists, supported algorithms and challenge sizes are checked. Registration of the
same credential twice is refused. The relying party must still verify its own
challenge freshness, expiry, origin, RP hash, signature and counter.

PRF uses HMAC-SHA-256 with the independent stored PRF key over
`SHA256("WebAuthn PRF" || 0x00 || input)`, following the input domain separation in
the [WebAuthn PRF specification](https://www.w3.org/TR/webauthn-3/#prf-extension).
Both `eval` values and `evalByCredential` are supported. The same credential and
input yield the same result after process/browser restarts. Different keys or
inputs yield independent results. Raw PRF results travel only over the private
worker pipe, never normal CLI output. Generic `hush run` and `hush send` refuse a
stored passkey, so they cannot export its serialized private material.

## Private worker protocol

Workers send one JSON object per line on stdout and read one response from stdin:

```json
{"op":"get","origin":"https://service.example","publicKey":{"challenge":"BASE64URL_CHALLENGE","rpId":"service.example","allowCredentials":[{"type":"public-key","id":"PUBLIC_CREDENTIAL_ID"}],"extensions":{"prf":{"eval":{"first":"PUBLIC_SALT"}}}}}
```

`create` uses the WebAuthn JSON creation options instead. Binary values use
canonical, unpadded base64url. Success is `{"ok":true,"credential":...}` using
WebAuthn JSON fields; refusal is the fixed `{"ok":false,"error":"NotAllowedError"}`.
Never run a protocol worker directly in an agent-visible terminal. Request size
is bounded to 128 KiB, sessions to 1,024 requests, and idle reads to 300 seconds.
Only one broker session may use a given credential at once. A crash leaves a
`.passkey-lock` marker and fails closed: after confirming that no matching broker
or worker is alive, remove only that credential's stale lock marker, never vault
ciphertext or identity files.

## Removal and recovery

```sh
hush passkey rm SERVICE_PASSKEY
```

Removal deletes this local credential; it does not revoke the website's stored
public key. Remove the corresponding method on the website too. Keep a separately
verified password/recovery method before deleting a passkey used for encryption.
Loss of the encrypted vault or PRF key makes PRF-wrapped data unrecoverable unless
another wrapping method exists. A copied vault preserves the same credential;
Hush provides no cross-machine counter synchronization or passkey backup protocol.
