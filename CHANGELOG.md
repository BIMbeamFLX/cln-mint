# Changelog

## [0.1.0] - unreleased

### Added

- LUD-25 mint: minting from a payRequest (`cp1` or bearer `h` as the LUD-12 comment), the informational withdrawRequest (`?k1=` and `?p=`), melt, rotate, split and merge, retried mutations answered with their original result, `cs1` certificates signed with the node's `signmessage`
- rotation certificates, an extension that is not part of LUD-25: a rotate also answers with `r`, a `cr1` signed with the node's `signmessage` over `LNURLcash:rotate:<amount_msat>:<hex(Q_spent)>:<hex(Q)>`, side by side with `c`; a split, a merge and a melt carry none; an exact retry is signed again from the burn already recorded
- LUD-26: Lightning Address registration against a `cx1` branch with BIP-340 ownership proofs, auto-mint onto purpose 2, `text/cpub` for internal transfers
- LUD-21 `verify` for mint invoices and melts, NIP-05 for registered usernames
- every spend verified by Bitcoin Core's own interpreter, compiled in through `lnurlcash-kernel`
- database compatible with lnurl-mint's
