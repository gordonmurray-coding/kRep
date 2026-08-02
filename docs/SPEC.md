# kRep + FabMesh — Protocol Spec v0.1

Two composable protocols on Kaspa L1:

- **kRep** — portable pseudonymous reputation from cryptographically anchored trade attestations
- **FabMesh** — permissionless manufacturing bounty market with covenant escrow

Design principle: FabMesh *generates* reputation as a settlement side effect; kRep *consumes* it. Neither requires a company, server of record, or legal identity anywhere in the loop.

---

## Part 1 — kRep

### 1.1 Identity

- A pseudonym is a secp256k1 keypair (same curve as Kaspa — reuse existing key tooling).
- Per-context derivation: one master seed, BIP32-style hardened path per marketplace/context (`m/rep'/fabmesh'/0'`), so contexts are unlinkable by default and linkable *by choice* (via ZK proof, later).

### 1.2 Attestation object

Emitted at escrow settlement, co-signed by both parties:

```json
{
  "v": 1,
  "escrow_outpoint": "<txid:index of settled escrow>",
  "role": "maker | buyer",
  "counterparty": "<pubkey>",
  "outcome": "success | default | disputed_resolved",
  "amount_bucket": "1 | 2 | 3 | 4",
  "prev": "<blake3 of this key's previous attestation, or null>",
  "index": 41,
  "ts": 1754000000,
  "sig_self": "...",
  "sig_counterparty": "..."
}
```

Key decisions:

- **`amount_bucket`, not amount** — coarse volume tiers (e.g. <10 / 10–100 / 100–1k / >1k kUSD) so reputation doesn't leak a full financial history.
- **`prev` + `index`** — each pseudonym maintains an append-only hash-linked personal chain. This is what makes "zero defaults" *provable* later: you can't silently drop a bad attestation without breaking the chain your counterparty also anchored.
- **Anchoring**: `blake3(attestation)` is committed in the payload of the escrow settlement transaction. An attestation is only valid if its hash appears in a real settled escrow tx. This is the Sybil defense — see 1.4.

### 1.3 Scoring (v1 — no ZK yet)

Reputation is client-side and algorithm-agnostic. A verifier fetches a pseudonym's attestation chain, checks:

1. Every attestation hash is anchored in a confirmed Kaspa tx
2. Chain links verify (prev/index monotone, sigs valid)
3. Escrow outpoints are real and match the covenant template

Then scores locally: trade count, default rate, volume-bucket distribution, chain age, counterparty diversity (Gini over counterparty pubkeys — catches wash-trading rings between two keys). Publishing the chain is opt-in per context; v1 pseudonyms are persistent-but-unlinked-to-legal-identity, which covers 90% of the value.

### 1.4 Sybil economics (the honest section)

ZK does not solve Sybil; **cost** does. Faking N successful trades requires N real escrow settlements: N × (tx fees + locked capital × time + maker bond). Reputation here is literally proof-of-burned-time-and-capital. Counterparty-diversity scoring raises the cost further (a ring of 2 keys is visible; a ring of 50 keys costs 50 funded wallets churning real escrows). This should be stated plainly in docs — overclaiming Sybil resistance is how reputation systems lose credibility.

### 1.5 v2 — ZK selective disclosure (later milestone)

Goal: prove statements like *"this fresh key controls a chain with ≥N successes and 0 defaults"* without revealing which chain.

- Circuit language: **Noir** (sane tooling, client-side proving, verification is P2P/off-chain — Kaspa L1 never needs to verify a SNARK; peers do).
- Statement: knowledge of `sk` whose pubkey chain, committed in a global Merkle root of all anchored attestations (maintained by anyone — it's reproducible from chain data), has `index ≥ N` and all outcomes = success.
- **Open problem, flagged now**: completeness of "0 defaults" depends on the counterparty anchoring the default attestation even when the defaulter refuses to co-sign. Solution: the escrow covenant itself must be able to emit a *unilateral* default attestation on the slash/timeout path — the covenant is the second signer of record. This is a covenant design requirement, not a circuit problem, and it's why the escrow (Part 2) must be built rep-aware from day one.

---

## Part 2 — FabMesh

### 2.1 Job bounty

```json
{
  "v": 1,
  "kind": "fab_job",
  "file_hash": "<blake3 of STL/STEP>",
  "file_ptr": "<encrypted blob URL — Blossom/IPFS>",
  "process": "fdm | sla | cnc | ...",
  "material": "petg",
  "tolerance_class": "standard | fine",
  "qty": 2,
  "reward": "<KAS or kUSD amount>",
  "maker_bond": "<required stake, e.g. 20% of reward>",
  "deadline": 1754600000,
  "ship_region": "<coarse: continent/country only>",
  "escrow_template": "<covenant template hash>",
  "buyer_rep_hint": "<optional kRep chain head>"
}
```

- File is published **encrypted**; decryption key goes only to the accepted maker via DM. The public sees a hash and a spec, not the design.
- Ship-to address is exchanged only after claim acceptance, via encrypted DM — never touches the public layer.

### 2.2 Transport: Nostr

Job board = Nostr events on public relays. No server to enjoin, no operator to subpoena, and you can still run your own relay + a nice Next.js client (reuse kaspa-app patterns) without *being* the market.

- Job post: parameterized replaceable event (kind `30402`-style, custom kind TBD)
- Claim: reply event carrying maker's kRep chain head + bond-funding txid
- Acceptance: buyer reply designating the winning maker
- Address/key exchange: NIP-17 encrypted DMs

### 2.3 Escrow covenant state machine

The heart of it. States and transitions:

```
OPEN ──claim (maker bonds stake)──▶ CLAIMED
CLAIMED ──maker attests tracking hash──▶ SHIPPED
CLAIMED ──deadline passes, no ship──▶ SLASH (bond → buyer, reward → buyer, unilateral default attestation vs maker)
SHIPPED ──buyer signs release──▶ SETTLED (reward + bond → maker, success attestation anchored)
SHIPPED ──T_auto elapses, no dispute──▶ SETTLED (auto-release: buyer silence ≠ maker hostage)
SHIPPED ──buyer disputes──▶ DISPUTED
DISPUTED ──2-of-3 with arbiter key──▶ SETTLED or SLASH (disputed_resolved attestation)
OPEN ──deadline, no claims──▶ REFUND (buyer reclaims)
```

Design notes:

- **Maker bond** is the anti-no-show mechanism and makes fake-trade farming expensive (feeds 1.4).
- **Auto-release after tracking attestation + timeout** protects makers from buyer griefing; the dispute window is the buyer's protection.
- **Arbiter is optional and per-job**: jobs can specify a mutually chosen arbiter pubkey or run pure-timeout mode (lower trust ceiling, zero third parties). Arbiters are just another reputation-bearing pseudonym in the system — arbitration is itself a FabMesh service.
- **Settlement tx payload carries the attestation hash** — this is the kRep integration point and it costs one line in the covenant.

### 2.4 Delivery verification roadmap

- v0: buyer-signed release + auto-release timer (bond-backed honesty)
- v1: carrier tracking-number hash attested at SHIPPED; anyone can verify delivery status out-of-band before disputing
- v2: oracle-signed delivery attestation (an oracle is just another pseudonymous service with a rep chain)

---

## Part 3 — Build order

| # | Milestone | Deliverable | Reuses |
|---|-----------|-------------|--------|
| M1 | Attestation lib + CLI | Rust crate: create/sign/verify/chain attestations, anchor + verify against testnet-10 | Kaspa key tooling |
| M2 | Escrow covenant | State machine above, on testnet-10, with unilateral-default path | kUSD covenant identity-model work |
| M3 | Job board client | Next.js Nostr client, post/claim/accept flow, encrypted file + DM handling | kaspa-app frontend, Vercel |
| M4 | Dogfood run | One real end-to-end job: second pseudonym posts, your printer claims, prints, ships, settles, attestation anchored | Your printer |
| M5 | Rep explorer | Web viewer: paste chain head → verified score breakdown | M1 |
| M6 | ZK layer | Noir circuit for selective disclosure (§1.5) | M1 chains as test data |

M4 is the real milestone — after that you have a functioning agorist manufacturing loop with exactly one node, and every subsequent maker is pure network growth.

## Part 4 — Threat model (abbreviated)

- **Wash trading** → cost per fake trade (fees + bond + capital lockup + time) + counterparty-diversity scoring
- **Buyer griefing (never release)** → auto-release timer after shipping attestation
- **Maker no-show** → bond slash + unilateral default attestation
- **Design piracy** → encrypted file delivery; hash-only public posting (residual risk: accepted maker leaks — reputational, not preventable)
- **Relay censorship** → multi-relay posting; anyone can run a relay
- **Deanonymization via shipping** → the irreducible physical-layer leak; coarse public regions, DM-only addresses, maker sees one address per job. Worth stating honestly: FabMesh is pseudonymous, not anonymous, at the point of delivery.
