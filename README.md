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
  --id $(./krep id < att.json) --id $(./krep id < mirror.att.json) --out tx.json
./krep submit --tx tx.json --rpc grpc://node:16110   # sends exactly those bytes

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

## Review before you send

`krep anchor` prices the transaction from the node's **live** fee estimate,
which drifts. Two runs a minute apart pay different fees, return different
change, and therefore have different txids — so `--submit` on a second
invocation does not broadcast the transaction you just looked at. Observed on
testnet-10: reviewed `efc6a977…`, sent `a0eb0141…`.

Two workflows, both honest:

- `anchor --out tx.json` then `submit --tx tx.json` — review the exact bytes
  and send those. Verified: predicted and submitted txids match.
- `anchor --submit` — build and send atomically, no review gap.

Pinning `--fee-rate` also makes a build reproducible. Note this never
endangered an anchor: verification looks for whatever transaction *spends* the
anchor outpoint, so the settlement's own txid never has to be predicted or
recorded.

## Proven on-chain

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

The full loop was then repeated on **testnet-10** (node with 10 BPS): two
settlements anchored and submitted, a two-attestation chain with two distinct
anchors verifying, and `counterparty_diversity` correctly reporting 0.5 for a
chain whose trades share one counterparty — the wash-trading signal working on
real anchored data.

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

## M2 — escrow covenant

`krep-escrow` implements the SPEC 2.3 state machine as a native Kaspa covenant
(Toccata, KIP-16/17/20/21 — live on mainnet since DAA 474,165,565). Immutable
terms are baked into the script, so the escrow address commits to them; mutable
state lives in the transaction payload at fixed offsets.

Every branch — claim, ship, settle, auto-release, dispute, arbiter resolution,
slash, refund — is exercised against the real script VM, and all of them share
one address via a branch selector. Dispute paths are omitted entirely when no
arbiter is configured, rather than present-but-unresolvable.

### Driving an escrow

```bash
krep escrow new  --out job.json --wallet wallet.key \
  --reward 100000000 --bond 50000000 --deadline <daa> --file-hash <blake3>
krep escrow show --escrow job.json --network testnet

krep escrow open   --escrow job.json --wallet buyer.key --rpc <url> --submit   # buyer funds
krep escrow claim  --escrow job.json --wallet maker.key --rpc <url> --submit   # maker bonds
krep escrow ship   --escrow job.json --wallet maker.key --tracking <hash> --rpc <url> --submit
krep escrow settle --escrow job.json --wallet buyer.key --id <att> --id <att> --rpc <url> --submit
```

`dispute` / `resolve` and `slash` / `refund` replace `settle` on the failure
paths. Resolution takes two signatures — `--wallet` for the beneficiary and
`--arbiter-key` for the arbiter.

### Payment keys and pseudonyms are different identities

An escrow binds four identities: a payment key and a reputation pseudonym for
each side. The covenant pays the payment key and records the pseudonym; chain
entries belong to the pseudonym.

The separation is not decoration. If reputation accrued to the key the covenant
pays, a maker could take a fresh key for every job and never carry a default —
"0 defaults" would be unfalsifiable. It would also mean per-context pseudonyms
collapse into one linkable identity the moment you trade.

So the claim branch requires a signature **from the pseudonym being bound**.
That makes it neither optional (a zero key cannot sign, and the state
invariants reject an unnamed one) nor forgeable (a maker cannot bind a rival's
pseudonym and then default on their behalf).

### Reputation as a side effect

The escrow already knows every fact an attestation needs — who traded, in which
role, against which outpoint, for what size — so it derives them rather than
asking:

```bash
# both sides derive the same pair of bodies from the escrow, and co-sign.
# `attest` takes the pseudonym, not the key that paid.
krep escrow attest --escrow job.json --seed maker.seed --context fabmesh --chain m.chain.json > m.part.json
krep escrow attest --escrow job.json --seed buyer.seed --context fabmesh --chain b.chain.json > b.part.json
krep countersign --seed buyer.seed --context fabmesh < m.part.json > m.att.json
krep countersign --seed maker.seed --context fabmesh < b.part.json > b.att.json

krep escrow settle --escrow job.json --wallet buyer.key --att m.att.json --att b.att.json --submit
```

Nothing about the body is a free choice, so two parties settling the same escrow
derive the same pair — there is nothing to negotiate. `settle` refuses an
attestation anchored to a different outpoint than the one it is about to spend.

The slash path needs no cooperation at all, because the default carries no
signatures:

```bash
krep escrow slash --escrow job.json --wallet buyer.key --default-out default.json --submit
```

Both were run on testnet-10 with four genuinely distinct identities: a
settlement where each side's chain verified from the one transaction and landed
on their *pseudonyms*, and a slash whose derived default verified against the
maker's pseudonym — the identity they cannot swap out between jobs — rather than
the payment key they can. Without `--submit`
nothing is sent and the state file is left untouched, so a dry run cannot
desynchronise the client from the chain.

The client keeps an escrow state file because a covenant spend must prove which
state it is spending from, which means supplying the previous transaction's
bytes — and kaspad has no transaction index, so recovering those from the chain
would mean a full scan per command. Every participant already knows their own
escrow's history; the file is a cache of what they watched happen, and the chain
stays the authority.

Full happy path, run on testnet-10 through these commands:

| | |
|---|---|
| OPEN | `f324a61c5ac771405d40fb3a454d8f5414d64c38665fcf8964a5a937efe1ab72` |
| CLAIM | `2ad9984b8218fb70a3d7798da6414c82eb0afc37852374d1468753ba8cc8813a` |
| SHIP | `5812766cd8c2c131c479b7243619c4753b239cac12ac933c396285afaf9c7822` |
| SETTLE | `23b037e6f4e780bf1a95e16c760897f8b2dac361632e3bf9bac4ce3195fe2436` |

Every other branch has since been run on testnet-10 too: `refund` on an escrow
nobody claimed, and `dispute` → `resolve` on an arbitrated one. Together with
the slash run below, that is the entire state machine exercised against
consensus rather than only against the local VM.

Two things only the network could teach:

- **Script-unit budget.** An input commits a budget in sigop units (one unit
  buys 100,000 script units). A covenant input needs several, because the
  dispatcher scans past every earlier arm to reach the one being taken — cost
  grows with the whole script, not the branch. The arbitrated covenant's last
  arms measured ~205,000 units, so claim and ship succeeded on a budget that
  resolution was rejected for.
- **Lock-time finality.** A transaction whose lock time has not *passed* is not
  finalized and is rejected outright; equal to the current DAA score counts as
  not passed. `ship` records `shipped_at` slightly in the past for this reason.

### The unilateral default, driven on testnet-10

SPEC 1.5 flags "0 defaults" as an open problem: a defaulter will not co-sign
their own default. A covenant cannot produce a signature either — but it can
force bytes into the payload of the transaction that takes the bond. So a
covenant-witnessed attestation carries **no signatures at all**, and its
authority is the on-chain fact that the slash branch executed.

Run end to end on testnet-10:

| | |
|---|---|
| escrow | `kaspatest:pqgfeunqcau7xwcdxwd27kq6k3rre48fn3lrt0nhwc3vmajdwy4uxffen5qvg` |
| OPEN → CLAIM | `6e72a44178fdd4ada471da91479d9661eda6c4ac84fd0f854b2944a6a16f4415` |
| SLASH | `95e133823b340ad5347e777a075d55c3f931649e11bb01bc87c5da2e455e3ca0` |
| result | the maker carries a `Default` they never signed, verified from the chain alone |

The witness names the redeem script, the branch taken, and the offset at which
the covenant recorded *who* defaulted. That last field is load-bearing: without
it anyone able to drive a covenant of their own could mint defaults against
strangers. The live test asserts the same witness cannot be re-pointed at
another pseudonym.

A covenant witness may never carry a `Success` — otherwise driving your own
covenant would be a way to mint praise. It is only ever an answer to "the
subject would refuse to sign this".

## M3 — the job board

Postings, claims and acceptances are Nostr events. No server of record, nobody
to subpoena, anyone can run a relay.

```bash
export KREP_RELAYS=wss://nos.lol,wss://relay.damus.io

# the posting derives its terms from the escrow that backs it
krep job post --escrow job.json --seed buyer.seed --context fabmesh \
  --job-id my-bracket --process fdm --material petg --qty 2 --region EU \
  --file-ptr https://blossom.example/encrypted

krep job list
krep job claim  --job-addr <addr> --seed maker.seed --context fabmesh \
  --chain m.chain.json --payment <pk> --bond-txid <txid>
krep job claims --job-addr <addr>
krep job accept --job-addr <addr> --seed buyer.seed --context fabmesh \
  --claim-id <id> --escrow job.json --network testnet
krep job awarded --job-addr <addr>          # what a maker polls
krep job verify  --job-addr <addr> --escrow job.json
```

Kinds, which SPEC 2.2 left "TBD": **30402** postings (parameterized
replaceable, so editing a job replaces it under a stable `d` tag and claims stay
attached across edits), **1403** claims and **1404** acceptances. Those two are
deliberately *not* replaceable — their purpose is an immutable record of who
said what and when, and a rewritable claim could be altered after acceptance.

A kRep pseudonym is directly usable as a Nostr identity — same curve, same
schnorr primitive as attestations — so a chain head and the events advertising
it are provably the same person.

### Relays are untrusted

Every event has its id recomputed and its signature checked on arrival.
Replaceable events are de-duplicated locally rather than trusting the relay,
since an old revision resurfacing would show a stale reward. Acceptances from
anyone but the job's author are discarded — otherwise a stranger could redirect
a maker to an escrow they control. Publishing reports each relay separately,
because "one relay accepted it" and "the job is visible" are different claims.

`job post` derives reward, bond, deadline and file hash from the escrow, so a
posting cannot advertise terms the escrow will not honour, and `job verify`
re-checks that for the maker. The posting is words on a relay; the escrow
address is what holds the money.

Run against public relays: a posting, a claim carrying an anchored chain head,
and an acceptance pointing at a funded testnet escrow — published, read back and
verified. `relay.damus.io` returned 503 while `nos.lol` accepted, which is
exactly why publishing is multi-relay and reports per-relay verdicts.

## M4 — dogfood run (in progress)

A real job is live on testnet-10 and a public relay, and every digital step has
been run end to end:

| step | result |
|---|---|
| buyer funds escrow | `ac356778f0c3d2cb0365a942f8471d7d032486a4b6b21d865b2bbd0ddf8f0f20` |
| buyer posts job | `30402:c85c8b84…:fabmesh-bracket-1785733724` on `nos.lol` |
| maker verifies posting against the escrow | reward, bond, deadline, file hash all agree |
| **buyer scores the maker's chain** | `verified · 1 trade · 0 defaults · diversity 1.0` |
| buyer accepts | acceptance published, naming the funded escrow |
| maker bonds in | `1d9a11921a6bd13ea2d53aa614af0128ec6f40cd5f97a9d34f6b387e0acb0335` |

The escrow now holds reward + bond and names the maker's pseudonym. What
remains is physical: print `bracket.scad`, ship it, then `escrow ship` with the
real tracking number hashed, and `escrow settle` to mint both sides'
reputation.

That fourth row is the point of the whole project. The buyer chose a maker by
scoring a reputation chain anchored in Kaspa transactions the maker could not
forge, could not omit from, and did not have to be trusted about.

### What this run taught

The deadline was set to a DAA score that will never arrive. Refund and slash are
the buyer's only exits from an escrow nobody settles, and both are gated on the
deadline — so an unreachable one means the funds are locked permanently. There
is no covenant path out of that. `escrow open` now warns when a deadline is
implausibly far off, but the real lesson is that the deadline is a safety
parameter, not paperwork.

The shipping address had to be exchanged out of band. That gap is now closed —
see below.

### Private messages

The shipping address and the design file's decryption key are the two things
that genuinely cannot be public. They go over NIP-17, wrapped per NIP-59:

```bash
krep job dm    --seed buyer.seed --context fabmesh --to <maker pubkey> --message "Ship to: …"
krep job inbox --seed maker.seed --context fabmesh
```

Three layers, each hiding something different:

- **rumor** (kind 14) — the message, deliberately *unsigned*. A signed chat
  message is a transferable receipt of what you said; the recipient can read it
  but cannot prove to anyone else that you wrote it.
- **seal** (kind 13) — the rumor encrypted to the recipient and signed by the
  sender's real key. This is what establishes authorship, and only the
  recipient can open it.
- **gift wrap** (kind 1059) — the seal encrypted again and signed by a
  throwaway key generated fresh per message, so two messages from the same
  sender share no visible identifier.

A relay sees a wrap addressed to the recipient from a pubkey that has never
appeared before. It learns who is receiving and roughly when — timestamps are
jittered by up to two days — and nothing else.

Encryption is NIP-44 v2: ChaCha20, HMAC-SHA256, HKDF over an ECDH secret,
encrypt-then-MAC with the nonce authenticated. It is checked against the
official NIP-44 vectors — all 35 conversation keys, 24 padding cases, the
encrypt/decrypt round trips and every invalid-input case — because a hand-read
of the spec is not evidence.

Verified against a live relay: a buyer sent an address to a maker's pseudonym,
the maker's inbox recovered both the message and the true sender from the inner
seal, and the buyer's own inbox showed nothing, since a wrap is readable only by
its addressee.

## M5 — reputation explorer

```bash
krep serve --rpc grpc://node:16110        # http://127.0.0.1:8080
```

Paste a counterparty's chain; get a verified score breakdown.

It runs on your machine and binds to loopback. A hosted explorer would be a
server of record — you would be trusting its operator's word about whether a
chain is anchored, which is exactly the trust this project exists to remove. So
verification uses the same code path as `krep verify`, against your node, and
the page renders a verdict you reached yourself rather than a claim someone made
to you.

Four verdicts, kept distinct because they mean very different things:

| verdict | meaning |
|---|---|
| **Not a chain** | not a valid attestation chain file |
| **Chain is broken** | signatures or the hash-linked order do not hold |
| **Not proven on-chain** | well-formed, but an entry is not anchored in a settled transaction |
| **Anchored and verified** | every entry committed in a settled Kaspa transaction |

The breakdown surfaces two things a raw score does not. **Concentration** — a
handful of counterparties across many trades is flagged, because a small circle
trading with itself manufactures real cost but not independent endorsement.
And **covenant-witnessed entries** are marked `unsigned`: defaults nobody
signed, which the subject could not refuse or omit.

## M6 — selective disclosure (accumulators built, circuit pending)

SPEC 1.5 wants to prove *"this fresh key controls a chain with ≥N successes and
0 defaults"* without revealing which chain, against "a global Merkle root of all
anchored attestations (maintained by anyone — it's reproducible from chain
data)".

**That root is not reproducible as described.** Kaspa carries the 32-byte
attestation *id*; the body — outcome, role, owner — never goes on chain, which
is the `amount_bucket`-not-amounts privacy decision working as intended. A third
party can rebuild the set of anchored ids and nothing else, so a root over
attestation *contents* cannot be rebuilt by the person checking the proof.

The statement therefore splits across two accumulators, both genuinely
rebuildable from chain data:

| accumulator | leaf | proves |
|---|---|---|
| anchored ids (`merkle`) | `(spent outpoint, 32-byte payload window)` | membership — this success really was anchored |
| defaulted pseudonyms (`smt`) | pseudonym the covenant recorded on a slash | **non**-membership — you are not among them |

### Why the second one is needed

"≥N successes" needs only membership. "0 defaults" needs to prove an *absence*,
and a chain alone cannot: omitting an entry mid-chain breaks the `prev` links
and is caught, but truncating after the last success is invisible. Scanning for
slashes against a pseudonym would settle it — and would reveal the pseudonym,
destroying the unlinkability the proof exists for. A sparse Merkle tree answers
the same question without naming anyone.

M2 is what made this buildable: the covenant records *which pseudonym*
defaulted, on chain, at a known offset, without that pseudonym's cooperation.
The escrow's `kESC` magic bytes are what let a stranger recognise these
transactions at all.

The derivation rules mirror the live verifier — an attestation counts as
anchored when the transaction *spending its anchor outpoint* carries its id —
and are pinned by regression tests against transactions that really settled on
testnet-10 during the M2–M4 runs.

### Poseidon2, matched against the real compiler

The accumulators hash with Poseidon2 over BN254 — arithmetic in the proof
system's own field, so a Merkle path costs tens of constraints per level rather
than the thousands a bit-oriented hash would.

The hard requirement was never cost, it was **agreement**. The verifier rebuilds
the root in Rust; the circuit recomputes paths in Noir. One differing round
constant and every proof fails. Poseidon2 is a family, not a function, so this
uses Noir's own `bn254_blackbox_solver`, pinned to the same version as the
installed nargo — the implementation the circuit will actually run, rather than
a reimplementation whose parameters would have to be guessed. It is checked
against output captured from the real compiler (`krep-zk/tests/`).

Worth recording about this toolchain version: `std::hash` exposes
`poseidon2_permutation` and `pedersen_hash` only. Poseidon v1 and **sha256 are
not in the stdlib** — both moved to external libraries.

**Bytes do not fit in the field.** BN254 scalars are 254 bits; an attestation id
is 256. Reducing modulo the field order is not injective — roughly four fifths
of the id space wraps — so every 32-byte value splits into two 128-bit limbs,
which always fit and always round trip. Leaf and node types are field elements
throughout; only chain values (ids, pubkeys, txids) stay bytes.

Since the stdlib exposes only the permutation, the sponge is defined in
`hash.rs` and **the circuit must mirror it**: capacity holds a domain tag,
inputs are absorbed into the rate three at a time, the first state element is
squeezed. Leaves and nodes carry different tags, so an internal node's preimage
can never be presented as a leaf.

### The circuit

`krep-zk/circuit/` is a Noir program proving, without revealing which chain:
*"the pseudonym I control owns at least N anchored attestations, and is not
among the pseudonyms recorded as having defaulted."*

Both roots are public inputs. Both are rebuildable from chain data by anyone
with a node, so the prover does not choose them.

`krep-zk/examples/prover_input.rs` generates a witness from the *real*
accumulators — including two attestation ids that genuinely settled on
testnet-10 — so the circuit is exercised against the code a verifier runs
rather than hand-written fixtures. Executing it proves the Rust and Noir sponges
agree exactly; if they differed by one round constant the root check would fail.

```
honest prover (clean pseudonym)   -> witness solved
the defaulter attempting the same -> Failed assertion (defaults root)
```

**Known gap, stated plainly.** As written the circuit proves that *some*
attestations are anchored and that *a* pseudonym has not defaulted — but nothing
binds those together. A prover could pair someone else's anchored successes with
their own clean pseudonym.

Closing it means proving `owner == pseudonym` per attestation, which means
recomputing the attestation id from its body in-circuit, since the id is all the
accumulator can hold. That id is `blake3(body ‖ signatures)`, and blake3 is
neither in Noir's stdlib nor cheap in a circuit. Three ways out: bring blake3
into the circuit from an external library (no format change, expensive); give
attestations a second Poseidon2 id anchored alongside (32 more payload bytes and
a domain-tag bump, cheap in-circuit); or re-key ids to Poseidon2 outright
(cheapest, invalidates every chain anchored so far).

That is a decision about kRep's attestation format rather than a circuit
problem, so it is flagged rather than guessed at — the same way SPEC 1.5 flagged
the unilateral-default problem that M2 then solved.

## Next

1. Finish the dogfood run's physical half.
2. The Noir circuit over these accumulators.

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
