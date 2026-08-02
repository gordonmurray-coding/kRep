# kRep — pseudonymous reputation anchored on Kaspa

Reputation = an append-only, hash-linked chain of co-signed trade attestations,
each anchored (blake3 id committed) in the payload of a real Kaspa settlement
transaction. No identity, no issuer, no server of record. Sybil resistance is
economic: every attestation costs a real settled trade (fees + locked capital +
time), not a signup form.

Spec: see [`docs/SPEC.md`](docs/SPEC.md) (Part 1).

## Build

```
cargo build --release
```

## Two-party demo, with mirrored chains

```bash
# party A (provider)
./krep keygen --out a.seed
A=$(./krep pubkey --seed a.seed --context demo)

# party B (client)
./krep keygen --out b.seed
B=$(./krep pubkey --seed b.seed --context demo)

# A records a successful trade with B
ANCHOR=<txid>:<index>
./krep create --seed a.seed --context demo --chain a.chain.json \
  --anchor "$ANCHOR" --role provider --counterparty "$B" \
  --outcome success --bucket 2 > partial.json

# B countersigns, and emits the role-flipped mirror for B's own chain
./krep countersign --seed b.seed --context demo \
  --mirror-out mirror.partial.json --mirror-chain b.chain.json \
  < partial.json > att.json

# each side completes its own chain
./krep append --chain a.chain.json < att.json
./krep countersign --seed a.seed --context demo < mirror.partial.json > mirror.att.json
./krep append --chain b.chain.json < mirror.att.json

# one settlement, one anchor tx, two ids (64-byte payload)
./krep anchor --wallet wallet.key --rpc grpc://node:16110 \
  --id $(./krep id < att.json) --id $(./krep id < mirror.att.json)   # add --submit to broadcast

# verification requires a node; --offline is possible but proves nothing
./krep verify --chain a.chain.json --rpc grpc://node:16110
./krep score  --chain b.chain.json --rpc grpc://node:16110
```

## What is real

| Component | Status |
|---|---|
| Attestation format, canonical encoding, domain-separated digests | done |
| Schnorr co-signing (secp256k1 x-only, Kaspa's curve) | done |
| Hash-linked chain verification + default scoring | done |
| Per-context pseudonym derivation from one seed | done |
| On-chain anchor verification (`KaspadAnchorVerifier`, wRPC or gRPC) | done |
| `krep anchor` — payload-carrying tx, one or two ids | builds + signs; `--submit` to broadcast |
| Mirror attestations — both sides accrue rep from one settlement | done |

`verify` and `score` require `--rpc` (or `$KREP_RPC`) and fail closed without
it. `--offline` skips anchoring entirely, prints a loud banner, and marks its
output `"anchor_status": "UNVERIFIED_OFFLINE"` — it is a debugging aid, not a
reputation check.

### How anchor verification works

kaspad has **no transaction index** — there is no `getTransaction(txid)` RPC.
So `txid -> (accepted?, payload)` is resolved by scanning the selected parent
chain forward with `get_virtual_chain_from_block` (which yields the acceptance
predicate directly) and descending into the accepting block's mergeset only on
a hit. One scan resolves a whole chain's anchors, not one per attestation.

Consequences, stated plainly:

- A pruning node cannot see anything before its pruning point. That is
  *unverifiable*, not *unanchored*, and the verifier returns an error rather
  than a negative verdict — a node outage must never read as a fraudulent
  chain. Old chains need an archival node.
- Measured on a synced mainnet node: a full pruning-point-to-tip scan is ~471
  batches / ~19s over LAN gRPC. `--max-batches` is a runaway guard, and
  exceeding it is reported as "ran out of budget", never as "not anchored".

## Known blocker: the anchor field is circular

`is_anchored` resolves `anchor.txid` and checks *that transaction's* payload
for the attestation id. That is verifiable but **not constructible**:

- the id is `H(body || signatures)`, and `body` contains `anchor.txid`
- the anchor tx's payload must contain the id
- a transaction's payload changes its txid

So committing the id requires knowing the txid, and the txid depends on the
payload that carries the id. There is no ordering that satisfies both, which
is why the demo above uses a placeholder anchor: every command works, but a
chain anchored this way cannot pass `verify` against a real node.

SPEC §1.2 names the field `escrow_outpoint` — "txid:index **of settled
escrow**" — which suggests the intended meaning is the outpoint the settlement
transaction *spends*, not the settlement transaction itself. Under that
reading the cycle disappears: the escrow outpoint exists before the settlement
tx, and verification becomes "find the accepted tx that spends this outpoint,
check its payload". That keeps the 36-byte layout and needs no domain-tag bump
— it changes only verifier semantics. Not implemented, because it contradicts
the current `is_anchored` contract; it needs a decision first.

## Next

1. Resolve the anchor-field question above, then re-verify end to end against
   a funded wallet on testnet-10.
2. Escrow covenant (M2), including the unilateral-default path — `Default`
   attestations deliberately have no co-signed mirror, since "the owner
   defaulted" has no honest role-flipped form.

## Deliberate design points (don't "fix" these)

- **Canonical bytes, not JSON, are signed.** JSON is transport only.
- **`prev`+`index` chain** exists so "zero defaults" is provable later (Noir
  milestone) — omitting a bad attestation breaks the chain.
- **Unanchored attestations are worthless by definition.** Anchoring is the
  entire Sybil-cost model; never score a chain that fails `verify_anchored`.
- **`amount_bucket` not amounts** — reputation shouldn't leak a ledger.
- **Unilateral default path** must come from the escrow covenant side (FabMesh
  M2): the covenant acts as counter-signer of record on slashes. The `Outcome::Default`
  variant is here waiting for it.
