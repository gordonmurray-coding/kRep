# Running a job with somebody else

Every trade in this repository so far was made by one person holding both sides.
That is not a small caveat. It is the difference between a system that works and
a system that has only ever been asked questions it already knew the answer to.

Four things cannot be tested any other way, and none of them need a parcel:

- **Counterparty diversity as a signal.** Every chain here scores 1.0 because
  both keys came from the same machine. The wash-trading flag has never seen a
  genuine circle, so it has never been shown to fire on one or to stay quiet on
  an honest trader.
- **Shared conventions.** Anything both parties must compute identically is
  untested while one party computes it twice. The design-file hash was wrong for
  months in exactly this way — see below.
- **The job board against someone who is not expecting you.** Relay propagation,
  an acceptance you did not author, terms you did not write.
- **A dispute where the two sides actually disagree**, rather than one person
  playing both and arriving at the answer they had in mind.

The deliverable does not have to be physical. FabMesh is framed around
fabrication, but the protocol only ever sees a hash — `escrow ship` takes an
already-hashed tracking value, so a real carrier reference and an invented one
are byte-identical to every line of code here. Shipping something tests the
postal service. Use a file.

## What the second party needs

- this repository, built (`cargo build --release`)
- a testnet-10 kaspad they can reach, or the public node network
- a funded testnet wallet — `krep wallet-new`, then `krep wallet-address`
- a reputation seed — `krep keygen --out theirs.seed`

They should generate both themselves. A key you handed them is a key you still
hold, and the run would be self-dealing wearing a second hat.

## The run

Roles below: **B** is the buyer, who wants the thing and pays; **M** is the
maker, who produces it. Pick whichever you like — the interesting side is
whichever one you are *not* used to driving.

**1. B agrees the deliverable and hashes it.** Both parties must get the same
number from the same bytes:

```bash
krep hash --file design.scad      # -> the file hash the escrow commits to
```

M runs the same command on the file they received and compares. If the two
disagree, stop: either the file differs or one of you is not hashing what you
think you are. That check is the entire point of this step.

**2. B opens an escrow naming their own reputation pseudonym.**

```bash
krep escrow new --out job.json --wallet b.wallet \
  --buyer-seed b.seed --buyer-context fabmesh \
  --reward 100000000 --bond 50000000 \
  --deadline <current DAA + slack> --file-hash <from step 1>
krep escrow open --escrow job.json --wallet b.wallet --rpc grpc://node:16110 --submit
```

Set the deadline generously. It gates refund and slash, so it is the buyer's
only exit if nobody delivers — but a deadline that arrives while the maker is
still working turns an honest job into a slashable one. Hours, not minutes.

**3. B posts it, M finds it.**

```bash
krep job post   --escrow job.json --seed b.seed --relay wss://nos.lol
krep job list   --relay wss://nos.lol
krep job verify --escrow-address <from the posting> --relay wss://nos.lol
```

`job verify` is M checking that the advertised reward, bond, deadline and file
hash match the escrow that actually holds the money. The posting is words on a
relay; the address is the only thing that pays.

**4. B scores M before accepting.** This is the step the whole project exists
for, and the first time it will be asked about someone whose history the asker
did not create:

```bash
krep score --chain <M's chain> --rpc grpc://node:16110
```

**5. M claims, binding their pseudonym.**

```bash
krep escrow claim --escrow job.json --wallet m.wallet \
  --rep-seed m.seed --rep-context fabmesh --rpc grpc://node:16110 --submit
```

The covenant requires a signature from the pseudonym being bound, so M cannot
claim under someone else's identity — nor omit one and dodge a future default.

**6. M delivers, then records it.**

```bash
krep hash --text "<tracking number, or any agreed receipt string>"
krep escrow ship --escrow job.json --wallet m.wallet --tracking <that hash> \
  --rpc grpc://node:16110 --submit
```

**7. B settles.** Both reputations are minted by one transaction:

```bash
krep escrow settle --escrow job.json --wallet b.wallet --rpc grpc://node:16110 --submit
krep verify --chain m.chain.json --rpc grpc://node:16110
```

## If it goes wrong on purpose

Worth doing deliberately at least once, with the other party's agreement:

- **M never ships.** B waits for the deadline and runs `krep escrow slash`. M's
  pseudonym enters the defaults tree, and after a rescan M can no longer prove a
  clean record — including if they hand over a chain with the default left off.
- **They disagree.** Open the escrow with `--arbiter` and drive
  `krep escrow dispute` and `krep escrow resolve`. This path has never been run
  by two people who actually disagreed.

## The bug this document exists because of

`Terms::file_hash` was documented as blake3 of the design file. Nothing in this
software computed blake3, and `b3sum` was not installed on the machine doing the
dogfooding, so the escrows here were opened with a blake2b digest instead. The
CLI accepted it, because `--file-hash` takes 32 bytes of hex and cannot tell how
they were derived.

Self-dealt, that is invisible: the same wrong function on both sides agrees with
itself. A second party following the documentation would have computed
`36c50b1b…` where the escrow says `6ba58334…`, and the file commitment — the
thing that lets a maker prove they built the right design — would have referred
to nothing.

`krep hash` exists so both sides get the same number from the same tool, and a
test pins it to blake3's published vector so a counterparty can check the answer
with `b3sum` instead of trusting this binary. Note that `krep hash --text` takes
the bytes of the string exactly as given; `echo foo | b3sum` hashes a trailing
newline and will not match.

One person cannot find a bug of this shape. That is the argument for this
document.
