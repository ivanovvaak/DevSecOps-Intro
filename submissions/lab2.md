# Lab 2 — Threat Modeling: STRIDE on Juice Shop with Threagile

Threagile `0.9.1` (the binary inside reports 1.0.0), run on the baseline model
`labs/lab2/threagile-model.yaml` from the Lab 1 deployment.

## Task 1

### Severity table (baseline)

```bash
$ jq 'length' labs/lab2/output/risks.json
23

$ jq '[.[].severity] | group_by(.) | map({severity: .[0], count: length})' labs/lab2/output/risks.json
[{"severity":"elevated","count":4},{"severity":"low","count":5},{"severity":"medium","count":14}]
```

| Severity | Count |
|---|---:|
| critical | 0 |
| high | 0 |
| elevated | 4 |
| medium | 14 |
| low | 5 |
| **Total** | **23** |

`stats.json` agrees and adds that all 23 sit in risk status `unchecked` — nothing has been triaged yet, which is the honest starting state of a model nobody has worked through.

### Top five, ranked explicitly

```bash
$ jq -r '["critical","high","elevated","medium","low"] as $order
  | [.[] | {sev: .severity, rule: .category, asset: .most_relevant_technical_asset}]
  | sort_by(.sev as $s | $order | index($s))
  | .[:5][] | "\(.sev)\t\(.rule)\t\(.asset)"' labs/lab2/output/risks.json

elevated	missing-authentication	juice-shop
elevated	cross-site-scripting	juice-shop
elevated	unencrypted-communication	user-browser
elevated	unencrypted-communication	reverse-proxy
medium	missing-authentication-second-factor	juice-shop
```

### STRIDE mapping

| # | Rule | Asset | STRIDE | Why |
|--:|---|---|---|---|
| 1 | `missing-authentication` | juice-shop | **S** — Spoofing | The `To App` link from the reverse proxy declares `authentication: none`, so the application cannot tell a forwarded request from anything else that reaches port 3000 and can be impersonated by any process on the host network. |
| 2 | `cross-site-scripting` | juice-shop | **T** — Tampering | XSS lets an attacker rewrite the page and the requests the victim's browser issues, tampering with data in flight inside an otherwise legitimate session. |
| 3 | `unencrypted-communication` | user-browser | **I** — Information Disclosure | `Direct to App (no proxy)` carries `tokens-sessions` over plain `http`, so anything on the path reads the session token off the wire. |
| 4 | `unencrypted-communication` | reverse-proxy | **I** — Information Disclosure | The proxy re-emits the same session data to the app over plain `http`; TLS is terminated and never resumed, so the internal hop leaks what the external hop protected. |
| 5 | `missing-authentication-second-factor` | juice-shop | **E** — Elevation of Privilege | With a single factor, one stolen or guessed password is the whole authentication decision, and a normal user's stolen credential becomes whatever privilege that account holds. |

### One trust-boundary crossing

The arrow **`Direct to App (no proxy)`**, from **User Browser** to **Juice Shop Application**, labelled `http` in `data-flow-diagram.png`.

It crosses two nested boundaries in one hop: out of **Internet**, straight through **Host**, and into **Container Network** — visible in the diagram as the line that runs past the Reverse Proxy node without touching it. That is exactly why it is worth an attacker's time. Every control the architecture places at the edge lives on the *other* arrow: TLS termination, security headers, and whatever the proxy would add all sit on the `https` path through Reverse Proxy. This link bypasses all of them, carries `tokens-sessions` in cleartext, and lands directly on the application inside the innermost boundary. It is the reason risks 3 and 5 both point at it, and it is the architectural twin of the Lab 1 finding that a bare `-p 3000:3000` would publish that same port to the whole network.

## Task 2

### Hardening applied

`labs/lab2/threagile-model-secure.yaml`, three changes, four fields:

| # | Requirement | Field change |
|--:|---|---|
| 1 | No clear text into the application | `User Browser → Direct to App (no proxy)`: `protocol: http` → `https` |
| 2 | No clear text into the application | `Reverse Proxy → To App`: `protocol: http` → `https` |
| 3 | Proxy-to-app link declares how it authenticates | `Reverse Proxy → To App`: `authentication: none` → `client-certificate`, `authorization: none` → `technical-user` |
| 4 | Encryption at rest | `juice-shop` and `persistent-storage`: `encryption: none` → `data-with-symmetric-shared-key` |

One false start worth recording: `-list-types` lists `reverse-proxy-web-protocol-encrypted` as a valid Protocol, but the parser rejects it —
`unknown 'protocol' of technical asset 'Reverse Proxy' communication link 'To App': reverse-proxy-web-protocol-encrypted` —
and writes no output at all. `https` is accepted. The printed enum list and the accepted enum list are not the same list.

### Baseline vs secure

```bash
$ jq 'length' labs/lab2/output-secure/risks.json
18
$ jq -c '[.[].severity] | group_by(.) | map({severity: .[0], count: length})' labs/lab2/output-secure/risks.json
[{"severity":"elevated","count":1},{"severity":"low","count":5},{"severity":"medium","count":12}]
```

| Severity | Baseline | Secure | Delta |
|---|---:|---:|---:|
| critical | 0 | 0 | 0 |
| high | 0 | 0 | 0 |
| elevated | 4 | 1 | **−3** |
| medium | 14 | 12 | **−2** |
| low | 5 | 5 | 0 |
| **Total** | **23** | **18** | **−5 (−22 %)** |

The whole reduction lands in the two top severity bands; the `low` band does not move at all.

### Rules that disappeared

```bash
$ echo "gone:"; comm -23 /tmp/base-rules.txt /tmp/secure-rules.txt
gone:
missing-authentication
unencrypted-asset
unencrypted-communication

$ echo "new:"; comm -13 /tmp/base-rules.txt /tmp/secure-rules.txt
new:
```

| Rule ID | Field change that removed it |
|---|---|
| `missing-authentication` | `authentication: none` → `client-certificate` on `Reverse Proxy → To App` (with `authorization: technical-user`) |
| `unencrypted-communication` | `protocol: http` → `https` on both `Direct to App (no proxy)` and `To App` (2 instances removed) |
| `unencrypted-asset` | `encryption: none` → `data-with-symmetric-shared-key` on `juice-shop` and `persistent-storage` (2 instances removed) |

Nothing new appeared, which is the check that the edits changed existing assets rather than adding any.

### Two rules that still fire

- **`cross-site-scripting` (elevated, juice-shop)** — the only elevated risk left. It is triggered by the asset being a `web-server` with `custom_developed_parts: true` that accepts `json` from an internet-facing client. No transport or storage field describes output encoding, a CSP, or a templating engine, so no YAML edit can tell Threagile this is handled. Only the code, or a control the model can express such as a WAF, changes it.
- **`container-baseimage-backdooring` (medium, juice-shop)** — fires because `machine: container` and there is no build pipeline or artifact registry asset in the model. The rule is about provenance of the image, which is not a property of any field on the running asset. Closing it means modelling the pipeline that produces the image, which is Lab 4's SBOM and Lab 8's signing, not an attribute edit here.

### What is left, and what it would take

The 18 remaining risks are almost entirely *design and operations* risks rather than *configuration* risks, and that is the point the diff makes. Transport and storage are attributes of a link or an asset, so declaring `https` or an encryption mode genuinely removes them from the model. What stays is of three kinds: missing components the model does not contain (`missing-vault`, `missing-waf`, `missing-identity-store`, `missing-build-infrastructure` — each closed only by adding the real component, not by a field), properties of the application's own code (`cross-site-scripting`, `cross-site-request-forgery`, `server-side-request-forgery`), and process risks around how the artifact was built and hardened (`container-baseimage-backdooring`, `missing-hardening`).

The one **no YAML edit can close is `cross-site-scripting`**. Juice Shop is vulnerable by design: the XSS is in the source code, and a threat model edit that made the rule disappear would be a lie about the system, not a fix. Closing it takes a code change plus the evidence that the change works — which is precisely why Lab 5 points SAST and DAST at this same application.

## Bonus

`labs/lab2/threagile-model-auth.yaml`, written from `-create-stub-model`: 6 technical assets (User Browser, Login Endpoint, Token Service, Credential Store, Secret Store, Admin Endpoint), 6 communication links, 5 data assets. The JWT signing key is its own data asset (`jwt-signing-key`, strictly-confidential, mission-critical integrity), stored in a dedicated `Secret Store` rather than inside the application. Every link carries an explicit `authentication` and `authorization`. The admin endpoint's authorisation check is the `Verify Token And Role` link (`authentication: token`, `authorization: technical-user`): the endpoint sends the presented JWT to the token service and refuses the call unless the returned role claim is the administrative one.

### Severity table (auth model)

| Severity | Count |
|---|---:|
| critical | 0 |
| high | 1 |
| elevated | 8 |
| medium | 16 |
| low | 1 |
| **Total** | **26** |

26 risks from 6 assets, against 23 from the 5-asset architecture model — a narrower scope produced *more* findings, because the assets are specific enough for the rules to bite.

### Three risks the architecture model did not surface

```bash
$ comm -13 /tmp/base-rules.txt /tmp/auth-rules.txt
missing-identity-provider-isolation
missing-vault-isolation
sql-nosql-injection
unguarded-access-from-internet
```

| Rule ID | Severity / asset | STRIDE | Mitigation |
|---|---|---|---|
| `sql-nosql-injection` | high / login-endpoint | **T** — Tampering | Parameterise the credential lookup in `Verify Credentials`; the login query is the one query an unauthenticated attacker can always reach. |
| `missing-identity-provider-isolation` | elevated / token-service, credential-store | **E** — Elevation of Privilege | Move the token service and credential store into their own network segment so a compromise of a lower-protected neighbour cannot reach the identity components laterally. |
| `missing-vault-isolation` | medium / secret-store | **I** — Information Disclosure | Isolate the vault holding `jwt-signing-key` from the application segment, so reading the key requires crossing a boundary rather than just being inside the app network. |

(`unguarded-access-from-internet` on both endpoints is a fourth; it asks for a gateway or WAF in front of the two internet-reachable endpoints.)

### What the feature-level model showed that the architecture-level one could not

The architecture model has one `juice-shop` box, so every identity concern collapses into a single `missing-authentication` finding and the signing key is invisible — it is not an asset, so no rule can reason about it. Splitting that box into a login endpoint, a token service, a credential store and a vault made the *relationships* modellable, and that is where the interesting risks live: a high-severity injection on the one query an anonymous caller can reach, and two isolation risks that only exist because there is now something worth isolating from something else.
