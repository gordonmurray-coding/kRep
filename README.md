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

# pick the outpoint the settlement will spend — that IS the anchor
./krep wallet-utxos --wallet wallet.key --rpc grpc://node:16110
ANCHOR=<txid>:<index>

# A records a successful trade with B, naming that outpoint
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

# one settlement, one anchor tx, two ids (64-byte payload).
# --spend must be the same outpoint the attestations named.
./krep anchor --wallet wallet.key --rpc grpc://node:16110 --spend "$ANCHOR" \
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
| `krep anchor` — spends the anchor outpoint, commits one or two ids | builds + signs; `--submit` to broadcast |
| Mirror attestations — both sides accrue rep from one settlement | done |

`verify` and `score` require `--rpc` (or `$KREP_RPC`) and fail closed without
it. `--offline` skips anchoring entirely, prints a loud banner, and marks its
output `"anchor_status": "UNVERIFIED_OFFLINE"` — it is a debugging aid, not a
reputation check.

## What `anchor` means

`anchor` is the outpoint the settlement transaction **spends** — SPEC 1.2's
`escrow_outpoint`, "txid:index of settled escrow". It is *not* the id of the
transaction carrying the commitment.

That is forced, not stylistic. If `anchor` named the payload-carrying
transaction itself, the protocol would be unbuildable:

- the id is `H(body ‖ signatures)`, and `body` contains the anchor
- that transaction's payload must contain the id
- a transaction's payload changes its txid

Committing the id would require knowing the txid before choosing the payload
that determines it. Naming the *spent* outpoint breaks the cycle, because the
escrow output exists before the settlement that consumes it:

1. an escrow (or any funded output) `O` exists — `krep wallet-utxos`
2. both parties co-sign an attestation whose `anchor` is `O` → id
3. the settlement spends `O` and carries the id in its payload — `krep anchor --spend O`

The byte layout is unchanged (still a 36-byte outpoint), so no domain tags were
bumped.

### How verification works

kaspad has **no transaction index** — no `getTransaction(txid)`, and certainly
no "what spent this outpoint". So verification runs the flow above backwards,
in two bounded phases:

1. **Locate the escrow.** Find `anchor.txid` in the accepted-id stream from
   `get_virtual_chain_from_block`. This proves the outpoint's creating
   transaction was accepted, confirms it really has an output at that index,
   and gives phase 2 a start point — nothing can spend an output before it
   exists. One scan resolves a whole chain's anchors, not one per attestation.
2. **Find the spender.** Walk block bodies forward from there with
   `get_blocks`, looking for the transaction that consumes the outpoint, then
   confirm that candidate was itself accepted — of two conflicting spends only
   one can be — and check its payload commits the id.

Consequences, stated plainly:

- A pruning node cannot see anything before its pruning point. That is
  *unverifiable*, not *unanchored*, and the verifier returns an error rather
  than a negative verdict — a node outage must never read as a fraudulent
  chain. Old chains need an archival node.
- Measured on a synced mainnet node: a full pruning-point-to-tip scan is ~471
  batches / ~19s over LAN gRPC. `--max-batches` and `--max-spend-scan-blocks`
  are runaway guards, and exhausting either is reported as "ran out of budget",
  never as "not anchored".

## Proven on mainnet

The loop has been run end to end against a synced mainnet node (2026-08):

| | |
|---|---|
| anchor outpoint (spent) | `6a9d697c7bc95a26f71633b2133a89d51037fad39cf4f44ef758f5d4189f1358:0` |
| settlement tx | `330861aab9269ba031a3489397a8229f74cb1269c1d2064ef896ba649f5edfa5` |
| payload | 64 bytes = `id(A) ‖ id(B)`, two mirrored attestations |
| fee | 169,900 sompi (mass 1699 at feerate 100) |
| result | both chains `"anchor_status": "verified"`, one trade scored on each side |

The predicted txid matched the broadcast one exactly.

Both transports were exercised against this anchor:

| transport | node | verify time |
|---|---|---|
| `grpc://` | own node, LAN | ~25s |
| `wss://` (borsh wRPC) | unrelated public node | ~51s |

The verifier is separately confirmed on **testnet-10**, against real settlements
found on that chain — same two-phase spend-based path, same negative and
unresolvable verdicts.

The wRPC run matters beyond transport coverage: a node that has never seen any
of our data independently confirmed both chains. That is the entire claim of
portable pseudonymous reputation — anyone can check it, and checking needs
nothing but a Kaspa node.

Negative control, on both transports: an identically co-signed chain naming a
*real but unspent* outpoint is rejected with "attestation not anchored
on-chain" and exit code 1. Nothing spent it, so nothing anchors it — which is
the whole point.

Verification cost is dominated by the pruning-point-to-tip scan, and it scales
with block rate rather than with chain length:

| network | full scan | wall clock |
|---|---|---|
| mainnet | 471 batches | ~25s (LAN gRPC) |
| testnet-10 (10 BPS) | 493 batches | ~1m53s |

`--scan-from` with a recent chain block cuts that sharply when you know roughly
when the settlement happened; the 4096 `--max-batches` default is comfortable
on both networks.

Anchors are network-scoped in practice: a mainnet outpoint queried against
testnet-10 comes back *unresolvable*, not "unanchored" — the verifier will not
claim a negative about a transaction that may exist on a chain it cannot see.

## Next

1. Escrow covenant (M2), including the unilateral-default path — `Default`
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
