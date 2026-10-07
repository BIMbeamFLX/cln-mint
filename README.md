# cln-mint

A Core Lightning plugin that runs an [LNURLcash](https://github.com/lnurl/luds/blob/luds/25.md) mint: bearer notes on LNURL-withdraw links ([LUD-25](https://github.com/lnurl/luds/blob/luds/25.md)), deterministic notes and Lightning Address auto-mint ([LUD-26](https://github.com/lnurl/luds/blob/luds/26.md)). It does what [lnurl-mint](https://github.com/dni/lnurl-mint) does, but inside `lightningd`: the node it runs in is its funding source, invoice watcher and certificate signer.

Note handling (decoding, sighashes, `cx1` derivation, `cs1` encoding, the leaf and time rules) comes from [`lnurlcash-core`](https://github.com/lnurlcash/lnurlcash-core). Whether a spend opens its note is decided by Bitcoin Core's own interpreter, through [`lnurlcash-kernel`](https://github.com/lnurlcash/kernel), which compiles `libbitcoinkernel` into the plugin. The plugin layout follows [clnaddress](https://github.com/daywalker90/clnaddress).

* [Installation](#installation)
* [Building](#building)
* [Options](#options)
* [Endpoints](#endpoints)
* [RPC methods](#rpc-methods)
* [How it works](#how-it-works)
* [Differences from lnurl-mint](#differences-from-lnurl-mint)
* [Tests](#tests)

## Installation

With [coffee](https://github.com/coffee-tools/coffee) or reckless, or by hand: build it (below) and add the binary to your CLN config:

```
plugin=/path/to/cln-mint
cln-mint-base-url=https://mint.example
```

`cln-mint-base-url` is required. The plugin serves HTTP on `cln-mint-listen` (default `localhost:8899`); put a TLS reverse proxy for `mint.example` in front of it. The plugin never builds URLs from a request's `Host` header. It only uses that header to pick `cln-mint-onion-url` for Tor visitors.

The mint is then payable at `mint@mint.example` (and at `_@mint.example`), and its notes redeem at `https://mint.example/w`.

## Building

You need Rust 1.85 or newer, a C++20 compiler, CMake ≥ 3.22 and Boost ≥ 1.74 headers (`apt install cmake libboost-dev`, `brew install boost`). `lnurlcash-kernel` compiles Bitcoin Core's kernel from source and links it statically, so the first build takes a few minutes:

`cargo build --release`

The binary is then at `target/release/cln-mint`. It has no runtime dependencies beyond libc and the C++ runtime.

## Options

| Option | Default | |
|---|---|---|
| `cln-mint-base-url` | *required* | Public base URL of the mint. Its host is the domain `ck1` signatures bind to. |
| `cln-mint-onion-url` | | A Tor base URL. Spends bound to its host are accepted too. |
| `cln-mint-listen` | `localhost:8899` | HTTP listen address. |
| `cln-mint-database` | `<lightning-dir>/cln-mint.sqlite3` | Note database. Its schema is lnurl-mint's. |
| `cln-mint-username` | `mint` | The mint's own Lightning Address. |
| `cln-mint-min-sendable-msat` | `10000` | Smallest mint payment accepted. |
| `cln-mint-max-sendable-msat` | `1000000000` | Largest mint payment accepted. |
| `cln-mint-base-fee-msat` | `1000` | Flat mint fee. It is also charged on every split and refunded on merges. |
| `cln-mint-fee-percent-ppm` | `0` | Proportional mint fee, at most 100000. |
| `cln-mint-min-mint-msat` | `10000` | Smallest net value a new note may have. |
| `cln-mint-max-k1s` | `100` | Most notes a single callback may name (`too many k1` beyond that). |
| `cln-mint-sunset-mint` | `false` | Refuse mints and splits. Rotate, merge and melt keep working. |
| `cln-mint-sunset-date` | | A planned shutdown date, advertised at `/.well-known/lnurlw/`. |
| `cln-mint-verify` | `true` | Serve LUD-21 `/verify/<payment_hash>`. |
| `cln-mint-username-registration` | `true` | Let wallets register a Lightning Address against a `cx1` (LUD-26). |
| `cln-mint-nip05` | `true` | Serve `/.well-known/nostr.json` for registered usernames. |
| `cln-mint-title`, `cln-mint-description` | | Text for the front page. |

## Endpoints

| | |
|---|---|
| `GET /.well-known/lnurlp/<username>` | LUD-16 payRequest with `withdrawLink` and `commentAllowed: 64`. For a registered username it also carries `text/cpub`. |
| `GET /p/cb?amount=&comment=` | Mint: `comment` is `cp1<Q>` or a bearer note's hex `h`. The invoice commits to the metadata by hash. |
| `GET /p/<username>?amount=` | Auto-mint onto a registered branch (purpose 2). Any comment is ignored. |
| `POST /p/<username>?cx1=&sig=[&npub=]` | Register a username, or overwrite one (proven by the branch on file). |
| `DELETE /p/<username>?sig=` | Unregister. |
| `GET /w?k1=<spend>` / `GET /w?p=<cp1 or h>` | Informational withdrawRequest: value, `mintPubkey` and a `cs1` certificate `c`. |
| `GET /w/cb` | Melt (`k1`, `pr`), rotate (`k1`, `p1`), split (`k1`…, `amount`, `p1`, `p2`) and merge (`k1`…, `p1`). A rotate also answers with a `cr1` certificate `r`. |
| `GET /verify/<payment_hash>` | LUD-21, for mint invoices and melts. |
| `GET /.well-known/lnurlw/<username>` | Informational: node, bounds, outstanding total. |
| `GET /.well-known/nostr.json?name=` | NIP-05. |
| `GET /` | A page with the Lightning Address and its QR code. |

Every LNURL endpoint answers HTTP 200, with `{"status": "ERROR", "reason": ...}` on failure (LUD-01).

## RPC methods

* `cln-mint-info`: URLs, fees, `mintPubkey` and totals.
* `cln-mint-note <cp1 or h>`: a note's status and value.
* `cln-mint-pending`: notes reserved by in-flight melts, by payment hash.
* `cln-mint-reconcile`: resolve pending melts now, from `listpays`.
* `cln-mint-listusers`: registered usernames, their `cx1` and next index.

## How it works

* **Notes.** A note is a taproot output key `Q`, stored as `hex(Q)` → value. The mint never sees or stores anything that can spend it. Burned notes are kept, so a `Q` is never credited twice.
* **Minting.** The wallet names its note as the LUD-12 comment. The plugin creates the invoice with `invoice` (`deschashonly`). A `waitanyinvoice` loop credits the note once the invoice is paid. It keeps its `pay_index` in the database, so payments that land while the plugin is down are credited on startup. A lookup also settles lazily from `listinvoices`.
* **Spends.** `ck1` key paths, bearer preimages and full `cw1`s are decoded by `lnurlcash-core`. Bitcoin Core then verifies each one as input 0 of LUD-25's canonical spend transaction, with every consensus flag, against every host the mint answers on. So any tapscript leaf consensus accepts opens its note, except the leaf versions and `OP_SUCCESSx` opcodes LUD-25 refuses. Timelocks are checked against the mint's clock. Legacy 65-byte `ck1`s are refused.
* **Certificates.** `cs1` certificates come from the node's `signmessage` over `LNURLcash:<amount_msat>:<hex(Q)>`, so `mintPubkey` is the node id.
* **Rotation certificates.** An extension, not part of LUD-25. A rotate (one `k1`, a `p1`, no `amount`, no `pr`) also answers with `r`, a `cr1` certificate: the same `signmessage`, over `LNURLcash:rotate:<amount_msat>:<hex(Q_spent)>:<hex(Q)>`, encoded like a `cs1` under its own prefix (`cr10n1�` for 1000 msat). It names the note the mint burned, the one note it credited in its place, and that note's value. A note's own `cs1` says the note exists; a `cr1` says where it came from. The mint burns a note once, so it signs at most one such statement for any `Q_spent`. A split or a merge gets none, since neither has one note that became one other, and neither does a melt or the informational request. That is what an asset anchored to a note needs: lnurl-wallet's Seals hand a consignment from owner to owner, and with one `cr1` per transfer its holder can check, against the node's key alone, that every step of the history happened here, in that order.
* **What a rotation certificate rests on.** The statement is the node key's, and no stronger than the mint's own record of what it burned: two databases behind one node key, or a database restored from before a rotation, could each certify a different successor for the same note. There is no new table and no new endpoint. The certificate is computed from the request, and an exact retry of a completed rotate reads the burn already recorded, is signed again and answers with the same certificate, to anyone who can repeat the request, and with the same bytes whenever `signmessage` is deterministic (RFC 6979). `c` and `r` are asked of the node side by side, so a rotate makes two `signmessage` calls and waits for them once. If one of them fails, the rotate still stands and that certificate is left out; a retry is then how it is had at all.
* **Melts.** A melt reserves its note and answers at once (LUD-03), then pays with `xpay`, capping the routing fee at the note's mint fee (at least 0.5% or 5 sat). The note is burned only on a confirmed payment and restored only on a confirmed failure; `listpays` is the arbiter. Anything else stays pending, and a reconciler retries it every minute. An invoice the mint issued, or one already used by a melt, is refused.
* **Retries.** A rotate, split or merge repeated with the same notes, outputs and amount gets its original answer.
* **LUD-26.** Registration proofs are BIP-340 signatures by the branch's purpose-0 index-0 key over `sha256("LNURLcash:<register|unregister>:<domain>:<username>")`. Auto-mint picks the next purpose-2 index whose key is not already in use.

## Differences from lnurl-mint

* One funding source: this node. There are no lnd or spark backends and no REST credentials.
* Settlement is pushed by `waitanyinvoice` instead of polled.
* Mint invoices commit to the payRequest metadata by `description_hash`, as LUD-06 asks.
* The fixed identity always names itself `<cln-mint-username>@host` in `text/identifier`, whichever alias was queried, so the invoice can commit to the same metadata.
* NIP-57 zaps are not implemented. A `nostr` parameter is refused.
* Bitcoin Core is compiled into the plugin rather than loaded from a Python wheel.

## Tests

`cargo test` runs the unit tests, including LUD-25's and LUD-26's own test vectors (`tests/vectors/`), all against Bitcoin Core's interpreter. Rotation certificates are checked against lnurl-mint's `cr1` test vector, and at the callback with a socket that answers `signmessage` in the node's place: a rotate's `r` verifies, for bearer and key-path notes and step by step along a chain; both certificates are asked for at once; a retry answers with `r` again, or with the one whose signing had failed; a split or a merge has none.

The integration tests in `tests/` use `pyln-testing`, as CI does. To run them without installing CLN and bitcoind:

```
docker build -f tests/Dockerfile -t cln-mint-tests .
docker run --rm cln-mint-tests
```
