# kRep — pseudonymous reputation anchored on Kaspa

Reputation = an append-only, hash-linked chain of co-signed trade attestations,
each anchored (blake3 id committed) in the payload of a real Kaspa settlement
transaction. No identity, no issuer, no server of record. Sybil resistance is
economic: every attestation costs a real settled trade (fees + locked capital +
time), not a signup form.

Spec: see `krep-fabmesh-spec.md` (Part 1).

## Build

```
cargo build --release
```

## Two-party demo (offline, anchoring stubbed)

```bash
# party A (provider)
./krep keygen --out a.seed
A=$(./krep pubkey --seed a.seed --context demo)

# party B (client)
./krep keygen --out b.seed
B=$(./krep pubkey --seed b.seed --context demo)

# A records a successful trade with B (fake anchor for the demo)
ANCHOR=$(printf '%064d' 0):0
./krep create --seed a.seed --context demo --chain a.chain.json \
  --anchor "$ANCHOR" --role provider --counterparty "$B" \
  --outcome success --bucket 2 > partial.json

# B countersigns
./krep countersign --seed b.seed --context demo < partial.json > att.json

# A appends and inspects
./krep append --chain a.chain.json < att.json
./krep verify --chain a.chain.json
./krep score  --chain a.chain.json
```

## What is real vs stubbed in M1

| Component | Status |
|---|---|
| Attestation format, canonical encoding, domain-separated digests | done |
| Schnorr co-signing (secp256k1 x-only, Kaspa's curve) | done |
| Hash-linked chain verification + default scoring | done |
| Per-context pseudonym derivation from one seed | done |
| **On-chain anchor verification** | **stubbed** (`TrustEverythingAnchor`) |

## Next (M1 completion)

1. `KaspadAnchorVerifier` implementing `AnchorVerifier` over kaspad wRPC:
   fetch `anchor.txid`, require chain acceptance, check the tx payload contains
   the 32-byte attestation id. Point it at testnet-10 first, mainnet via your
   own node after.
2. `krep anchor` subcommand: build + submit a payload-carrying tx committing an
   attestation id (fine for bootstrapping before escrow covenants exist — the
   anchor doesn't have to be an escrow, just a real accepted tx you paid for).
3. Mirror attestations: `countersign` should also emit the role-flipped body
   for the counterparty's own chain so both sides accrue reputation from one
   settlement (both ids can share one anchor tx payload: 64 bytes).

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
