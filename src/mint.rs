//! LUD-25 and LUD-26, as lnurl-mint implements them: minting from a
//! payRequest, the informational withdrawRequest, melt, rotate, split and
//! merge at its callback, offline-verification certificates, and Lightning
//! Address auto-mint onto a registered `cx1` branch.
//!
//! Every function here answers in LUD-01's shape: success JSON, or a
//! [`MintError`] the HTTP layer turns into `{"status": "ERROR", "reason"}`.

use std::time::Duration;

use lnurlcash_core::{
    recoverable::{
        PURPOSE_LIGHTNING_ADDRESS, PURPOSE_WALLET, decode_cx1, derive_note_pubkey,
        encode_cs1_with_amount, encode_cx1,
    },
    signature::{address_proof_digest, note_signature_message_for_hash},
};
use secp256k1::{XOnlyPublicKey, schnorr};
use serde_json::{Map, Value, json};

use crate::{
    db::{self, StoreError},
    node::{PayError, PayStatus},
    spend,
    structs::PluginState,
};

/// Every invoice this plugin creates is labelled with this prefix.
pub const LABEL_PREFIX: &str = "cln-mint-";

/// Waits between `listpays` checks when a melt's own outcome was unclear.
const CONFIRM_DELAYS_SECS: [u64; 6] = [0, 1, 2, 4, 8, 16];

#[derive(Debug)]
pub enum MintError {
    /// A refusal whose reason is safe to hand back.
    Reject(String),
    /// Something broke. Its detail is logged, never sent.
    Internal(anyhow::Error),
}

pub type MintResult<T> = Result<T, MintError>;

fn reject<T>(reason: impl Into<String>) -> MintResult<T> {
    Err(MintError::Reject(reason.into()))
}

impl From<StoreError> for MintError {
    fn from(err: StoreError) -> Self {
        match err {
            StoreError::Sql(e) => MintError::Internal(e.into()),
            other => MintError::Reject(other.to_string()),
        }
    }
}

impl MintError {
    /// The reason to send. An internal error gets a reference id instead of
    /// its text, which is logged alongside it.
    pub fn reason(self) -> String {
        match self {
            MintError::Reject(reason) => reason,
            MintError::Internal(err) => {
                let reference = hex::encode(rand::random::<[u8; 4]>());
                log::warn!("[{reference}] internal error: {err:#}");
                format!("Internal error (reference: {reference}).")
            }
        }
    }
}

/// Drop `null` fields: LUD responses omit what they do not have.
fn compact(value: Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.into_iter()
                .filter(|(_, v)| !v.is_null())
                .collect::<Map<_, _>>(),
        ),
        other => other,
    }
}

/// A registrable username: short, lowercase, and never shaped like a note.
pub fn valid_username(username: &str) -> bool {
    (1..=32).contains(&username.len())
        && username
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_.-".contains(&b))
}

fn decode_npub(npub: &str) -> Option<[u8; 32]> {
    use bech32::{Bech32, primitives::decode::CheckedHrpstring};
    // NIP-19 is classic bech32, never bech32m
    let checked = CheckedHrpstring::new::<Bech32>(npub).ok()?;
    if checked.hrp().to_lowercase() != "npub" {
        return None;
    }
    checked.byte_iter().collect::<Vec<u8>>().try_into().ok()
}

/// A cx1 as stored: `hex(P || chain_code)`.
fn branch_parts(branch_hex: &str) -> Option<([u8; 32], [u8; 32])> {
    let bytes = hex::decode(branch_hex).ok()?;
    if bytes.len() != 64 {
        return None;
    }
    Some((bytes[..32].try_into().ok()?, bytes[32..].try_into().ok()?))
}

/// Does `sig` prove control of the branch's purpose-0 index-0 key, over
/// `sha256("LNURLcash:<action>:<domain>:<username>")`?
pub(crate) fn owns_branch(
    action: &str,
    domain: &str,
    username: &str,
    branch_hex: &str,
    sig: &str,
) -> bool {
    let Some((point, chain_code)) = branch_parts(branch_hex) else {
        return false;
    };
    let Ok(pk0) = derive_note_pubkey(&point, &chain_code, PURPOSE_WALLET, 0) else {
        return false;
    };
    let Ok(digest) = address_proof_digest(action, domain, username) else {
        return false;
    };
    let Some(sig) = hex::decode(sig.trim())
        .ok()
        .and_then(|b| <[u8; 64]>::try_from(b).ok())
    else {
        return false;
    };
    let Ok(pk) = XOnlyPublicKey::from_byte_array(pk0) else {
        return false;
    };
    schnorr::verify(&schnorr::Signature::from_byte_array(sig), &digest, &pk).is_ok()
}

/// What a rotation certificate signs: the note this mint burned, the one
/// note it credited in its place, and that note's value. Its second field
/// tells it from a note's own certificate, where an amount stands there.
pub(crate) fn rotation_message(spent_id: &str, note_id: &str, amount_msat: u64) -> String {
    format!("LNURLcash:rotate:{amount_msat}:{spent_id}:{note_id}")
}

/// A `cr1`: a `cs1` under its own prefix, so neither is taken for the other.
/// lnurlcash-core 0.2.3 encodes none and keeps its amount suffix to itself,
/// so the human-readable part is taken from the `cs1` of the same amount.
/// This belongs in lnurlcash-core once it exports one.
pub(crate) fn encode_cr1_with_amount(amount_msat: u64, signature: &[u8; 65]) -> String {
    use bech32::{Bech32m, Hrp};
    let cs1 = encode_cs1_with_amount(amount_msat, signature);
    // no data character is a '1': the last one is the separator
    let amount = &cs1[2..cs1.rfind('1').expect("a cs1 has a separator")];
    let hrp = Hrp::parse(&format!("cr{amount}")).expect("a cs1's amount is a valid HRP");
    bech32::encode::<Bech32m>(hrp, signature).expect("a cr1 is well under 1023 characters")
}

impl PluginState {
    fn is_own_username(&self, username: &str) -> bool {
        let username = username.to_ascii_lowercase();
        username == "_" || username == self.settings.username.to_ascii_lowercase()
    }

    /// A registered username's branch, while registration is enabled.
    fn registered_branch(&self, username: &str) -> MintResult<Option<String>> {
        if !self.settings.username_registration_enabled {
            return Ok(None);
        }
        Ok(self.store.username_branch(&username.to_ascii_lowercase())?)
    }

    pub async fn mint_pubkey(&self) -> Option<String> {
        self.node_id
            .get_or_try_init(|| async { self.node.info().await.map(|info| info.id) })
            .await
            .map_err(|e| log::warn!("could not read this node's id: {e:#}"))
            .ok()
            .cloned()
    }

    /// A `cs1` certificate over `(Q, amount)`, signed by this node. `None` if
    /// signing failed: the mutation it belongs to still stands.
    async fn certificate(&self, note_id: &str, amount_msat: u64) -> Option<String> {
        let message = note_signature_message_for_hash(note_id, amount_msat);
        match self.node.sign_message(&message).await {
            Ok(sig) => Some(encode_cs1_with_amount(amount_msat, &sig)),
            Err(e) => {
                log::warn!("could not certify a note: {e:#}");
                None
            }
        }
    }

    /// A `cr1` certificate that the note `spent_id` was burned into the one
    /// note `note_id`, worth `amount_msat`: where a note came from, which its
    /// own `cs1` cannot say. An extension, not part of LUD-25. Only ever for
    /// a rotate: a split has two outputs and a merge several inputs. It is
    /// this key's statement about this mint's own record of what it burned,
    /// and no stronger than that record. `None` if signing failed.
    async fn rotation_certificate(
        &self,
        spent_id: &str,
        note_id: &str,
        amount_msat: u64,
    ) -> Option<String> {
        let message = rotation_message(spent_id, note_id, amount_msat);
        match self.node.sign_message(&message).await {
            Ok(sig) => Some(encode_cr1_with_amount(amount_msat, &sig)),
            Err(e) => {
                log::warn!("could not certify a rotation: {e:#}");
                None
            }
        }
    }

    /// A rotate's two certificates, `c` and `r`: the new note's own and the
    /// rotation's. Asked of the node side by side, so a rotate waits for it
    /// once, as it did before there was an `r`. Either is `None` on its own.
    async fn rotate_certificates(
        &self,
        spent_id: &str,
        note_id: &str,
        amount_msat: u64,
    ) -> (Option<String>, Option<String>) {
        tokio::join!(
            self.certificate(note_id, amount_msat),
            self.rotation_certificate(spent_id, note_id, amount_msat),
        )
    }

    // ---- payRequest (minting) ----

    /// The metadata a username's payRequest advertises, and its invoices commit to.
    fn pay_metadata(&self, username: &str, host: &str) -> MintResult<String> {
        let mut entries = vec![
            json!([
                "text/plain",
                format!("Mint an lnurlcash bearer note on {host}")
            ]),
            json!(["text/identifier", format!("{username}@{host}")]),
        ];
        if !self.is_own_username(username) {
            if let Some(branch_hex) = self.registered_branch(username)? {
                let (point, chain_code) = branch_parts(&branch_hex)
                    .ok_or_else(|| MintError::Internal(anyhow::anyhow!("corrupt cx1 on file")))?;
                let hint = self.store.next_index_hint(username)?.unwrap_or(0);
                entries.push(json!([
                    "text/cpub",
                    format!("{}:{hint}", encode_cx1(&point, &chain_code))
                ]));
            }
        }
        if self.settings.has_fee() {
            entries.push(json!([
                "text/plain",
                format!(
                    "Mint fees: {},{}",
                    self.settings.base_fee_msat, self.settings.fee_percent_ppm
                )
            ]));
        }
        Ok(Value::Array(entries).to_string())
    }

    /// `GET /.well-known/lnurlp/<username>`: LUD-16 payRequest that mints a note.
    pub fn pay_request(&self, username: &str, request_host: Option<&str>) -> MintResult<Value> {
        let username = username.to_ascii_lowercase();
        let own = self.is_own_username(&username);
        if !own && self.registered_branch(&username)?.is_none() {
            return reject("Unknown user.");
        }
        let (base, host) = self.settings.public_base_url_and_host(request_host);
        // the fixed identity always names itself by its canonical username, so
        // its callback can rebuild the same metadata the invoice commits to
        let name = if own {
            self.settings.username.to_ascii_lowercase()
        } else {
            username.clone()
        };
        let callback = if own {
            format!("{base}/p/cb")
        } else {
            format!("{base}/p/{name}")
        };
        Ok(compact(json!({
            "tag": "payRequest",
            "callback": callback,
            "minSendable": self.settings.min_sendable(),
            "maxSendable": self.settings.max_sendable_msat,
            "metadata": self.pay_metadata(&name, &host)?,
            "withdrawLink": format!("{base}/w"),
            // a registered address always mints onto its own branch
            "commentAllowed": if own { Some(64) } else { None },
        })))
    }

    /// `GET /p/cb` and `GET /p/<username>`: an invoice that, once paid, credits
    /// the note named by `comment` (fixed identity) or the next key on the
    /// username's branch (LUD-26 auto-mint).
    pub async fn pay_callback(
        &self,
        username: Option<&str>,
        amount: u64,
        comment: Option<&str>,
        request_host: Option<&str>,
    ) -> MintResult<Value> {
        let s = &self.settings;
        if s.sunset_mint {
            return reject("This mint is sunsetting - minting is disabled.");
        }
        let username = username.map(str::to_ascii_lowercase);
        let branch = match &username {
            Some(name) => match self.registered_branch(name)? {
                Some(branch) => Some(branch),
                None => return reject("Unknown user."),
            },
            None => None,
        };
        if amount < s.min_sendable_msat {
            return reject("Amount too low.");
        }
        if amount > s.max_sendable_msat {
            return reject("Amount too high.");
        }
        let net = amount - s.mint_fee_msat(amount).min(amount);
        if net < s.min_mint_msat {
            return reject(format!(
                "Amount too low to mint a note (min {} msat net of fees).",
                s.min_mint_msat
            ));
        }
        let (base, host) = s.public_base_url_and_host(request_host);
        let name = username
            .clone()
            .unwrap_or_else(|| s.username.to_ascii_lowercase());
        let metadata = self.pay_metadata(&name, &host)?;

        let note_id = match (&branch, &username) {
            (Some(branch_hex), Some(name)) => {
                let (point, chain_code) = branch_parts(branch_hex)
                    .ok_or_else(|| MintError::Internal(anyhow::anyhow!("corrupt cx1 on file")))?;
                self.store
                    .claim_next_index(name, |i| {
                        derive_note_pubkey(&point, &chain_code, PURPOSE_LIGHTNING_ADDRESS, i)
                            .ok()
                            .map(hex::encode)
                    })?
                    .0
            }
            _ => match comment.and_then(spend::note_id_of_ref) {
                Some(id) => id,
                None => {
                    return reject(
                        "Missing or malformed comment: a cp1<Q>, or a bearer note's \
                         hex-encoded 32-byte hash, is required to mint.",
                    );
                }
            },
        };
        // refuse a taken output before an invoice exists for it
        if self.store.note_record(&note_id)?.is_some()
            || self.store.pending_mint_by_note_id(&note_id)?.is_some()
        {
            return reject("already in use");
        }
        let invoice = self
            .node
            .create_invoice(amount, &metadata, LABEL_PREFIX)
            .await
            .map_err(MintError::Internal)?;
        self.store
            .create_mint(&invoice.payment_hash, &invoice.bolt11, net, &note_id)?;
        Ok(compact(json!({
            "pr": invoice.bolt11,
            "routes": [],
            "disposable": false,
            "verify": s.verify_enabled.then(|| format!("{base}/verify/{}", invoice.payment_hash)),
        })))
    }

    /// Credit the note a paid mint invoice names. Idempotent.
    pub fn settle_mint(&self, payment_hash: &str) -> MintResult<()> {
        if let Some((note_id, amount)) = self.store.settle_mint(payment_hash)? {
            log::info!("MINT payment_hash={payment_hash} note={note_id} net_msat={amount}");
        }
        Ok(())
    }

    /// Settle the mint that credits `note_id` if its invoice has been paid
    /// but the invoice watcher has not caught up yet.
    async fn settle_mint_for_note(&self, note_id: &str) -> MintResult<()> {
        if let Some(hash) = self.store.pending_mint_by_note_id(note_id)? {
            if matches!(self.node.invoice_paid(&hash).await, Ok(Some(_))) {
                self.settle_mint(&hash)?;
            }
        }
        Ok(())
    }

    /// `GET /verify/<payment_hash>`: LUD-21, for a mint invoice or a melt.
    pub async fn verify(&self, payment_hash: &str) -> MintResult<Value> {
        if !self.settings.verify_enabled {
            return reject("Not found");
        }
        if let Some(pr) = self.store.mint_pr(payment_hash)? {
            let paid = self.node.invoice_paid(payment_hash).await.ok().flatten();
            if paid.is_some() {
                self.settle_mint(payment_hash)?;
            }
            let settled = paid.is_some() || self.store.mint_settled(payment_hash)?;
            return Ok(compact(json!({
                "status": "OK",
                "settled": settled,
                "preimage": paid.flatten(),
                "pr": pr,
            })));
        }
        if let Some(pr) = self.store.melt_pr(payment_hash)? {
            let (status, preimage) = self
                .node
                .pay_status(payment_hash)
                .await
                .unwrap_or((PayStatus::Pending, None));
            let settled = status == PayStatus::Complete || self.store.melt_settled(payment_hash)?;
            return Ok(compact(json!({
                "status": "OK",
                "settled": settled,
                "preimage": if settled { preimage } else { None },
                "pr": pr,
            })));
        }
        reject("Not found")
    }

    // ---- withdrawRequest (redeeming) ----

    /// The note `k1` spends and its record, once the spend is verified to
    /// open it. Spent notes are returned too, so a retried burn is recognised.
    async fn verified_note(&self, k1: &str) -> MintResult<(String, db::NoteRecord)> {
        let Some(parsed) = spend::parse(k1) else {
            return reject(spend::INVALID_K1);
        };
        self.settle_mint_for_note(&parsed.note_id).await?;
        let Some(record) = self.store.note_record(&parsed.note_id)? else {
            return reject(spend::INVALID_K1);
        };
        if let Some(reason) = spend::verify(
            &parsed,
            record.locked_at,
            &self.settings.spend_domains(),
            db::now(),
        ) {
            return reject(reason);
        }
        Ok((parsed.note_id, record))
    }

    /// `GET /w?k1=<spend>` or `GET /w?p=<cp1>`: read-only; the note's value.
    pub async fn withdraw_request(
        &self,
        k1: Option<&str>,
        p: Option<&str>,
        request_host: Option<&str>,
    ) -> MintResult<Value> {
        let (note_id, record) = match (k1, p) {
            (Some(k1), None) => self.verified_note(k1).await.map_err(|e| match e {
                MintError::Reject(r) if r == spend::INVALID_K1 => {
                    MintError::Reject("Unknown note.".into())
                }
                other => other,
            })?,
            (None, Some(p)) => {
                let Some(note_id) = spend::note_id_of_ref(p) else {
                    return reject("Unknown note.");
                };
                self.settle_mint_for_note(&note_id).await?;
                match self.store.note_record(&note_id)? {
                    Some(record) => (note_id, record),
                    None => return reject("Unknown note."),
                }
            }
            _ => return reject("Specify exactly one of k1 or p."),
        };
        if record.spent {
            return reject("Note already spent.");
        }
        // a note mid-melt must not be advertised as withdrawable
        if record.pending {
            return reject("pending");
        }
        let (base, host) = self.settings.public_base_url_and_host(request_host);
        Ok(compact(json!({
            "tag": "withdrawRequest",
            "callback": format!("{base}/w/cb"),
            "k1": k1,
            "minWithdrawable": record.amount_msat,
            "maxWithdrawable": record.amount_msat,
            "defaultDescription": format!("lnurlcash bearer note on {host}"),
            "mintPubkey": self.mint_pubkey().await,
            "c": self.certificate(&note_id, record.amount_msat).await,
        })))
    }

    /// `GET /w/cb`: melt, rotate, split or merge (LUD-25's callback table).
    pub async fn withdraw_callback(
        &self,
        k1s: &[String],
        pr: Option<&str>,
        amount: Option<u64>,
        p1: Option<&str>,
        p2: Option<&str>,
        request_host: Option<&str>,
    ) -> MintResult<Value> {
        let s = &self.settings;
        if k1s.is_empty() {
            return reject("missing k1");
        }
        if k1s.len() > s.max_k1s {
            return reject("too many k1");
        }
        if pr.is_some() && (k1s.len() > 1 || amount.is_some()) {
            return reject(
                "pr cannot be combined with multiple k1s or amount - merge or split first.",
            );
        }
        if s.sunset_mint && amount.is_some() {
            return reject("This mint is sunsetting - splitting is disabled.");
        }
        // outputs are validated before any note is touched
        let (mut p1_id, mut p2_id) = (None, None);
        if pr.is_none() {
            p1_id = match p1.and_then(spend::note_id_of_ref) {
                Some(id) => Some(id),
                None => return reject("missing p1"),
            };
            if amount.is_some() {
                p2_id = match p2.and_then(spend::note_id_of_ref) {
                    Some(id) => Some(id),
                    None => return reject("missing p2"),
                };
            }
        }

        // every spend must open its note, or nothing happens
        let mut notes = Vec::with_capacity(k1s.len());
        for k1 in k1s {
            notes.push(self.verified_note(k1).await?);
        }
        let note_ids: Vec<String> = notes.iter().map(|(id, _)| id.clone()).collect();

        if pr.is_none() {
            // a retried rotate/split/merge gets its original answer
            if let Some(burn) = self.store.find_burn(&note_ids)? {
                let recorded_amount = burn.id2.as_ref().map(|_| burn.amount1_msat);
                if Some(&burn.id) == p1_id.as_ref()
                    && burn.id2 == p2_id
                    && recorded_amount == amount
                {
                    let c2 = match (&burn.id2, burn.amount2_msat) {
                        (Some(id2), Some(a2)) => self.certificate(id2, a2).await,
                        _ => None,
                    };
                    // only a rotate, one note in and one note out, was a rotation
                    let (c, r) = match (note_ids.as_slice(), &burn.id2) {
                        ([spent], None) => {
                            self.rotate_certificates(spent, &burn.id, burn.amount1_msat)
                                .await
                        }
                        _ => (self.certificate(&burn.id, burn.amount1_msat).await, None),
                    };
                    return Ok(compact(json!({
                        "status": "OK",
                        "c": c,
                        "c2": c2,
                        "r": r,
                    })));
                }
            }
        }
        if notes.iter().any(|(_, r)| r.spent) {
            return reject(spend::INVALID_K1);
        }
        if notes.iter().any(|(_, r)| r.pending) {
            return reject("pending");
        }
        let total: u64 = notes.iter().map(|(_, r)| r.amount_msat).sum();

        if let Some(pr) = pr {
            return self.melt(note_ids, pr, total, request_host).await;
        }
        let p1_id = p1_id.expect("validated above");

        if let Some(amount) = amount {
            if amount == 0 || amount >= total {
                return reject(format!("amount must be between 0 and {total} msat."));
            }
            // the base fee comes out of the change, never the requested amount
            let change = (total - amount)
                .checked_sub(s.base_fee_msat)
                .filter(|c| *c >= 1);
            let Some(change) = change else {
                return reject("insufficient value");
            };
            let p2_id = p2_id.expect("validated above");
            self.store.swap(
                &note_ids,
                &[(p1_id.clone(), amount), (p2_id.clone(), change)],
            )?;
            return Ok(compact(json!({
                "status": "OK",
                "c": self.certificate(&p1_id, amount).await,
                "c2": self.certificate(&p2_id, change).await,
            })));
        }

        // rotate is a merge of one: the refund is 0
        let merged = total + (note_ids.len() as u64 - 1) * s.base_fee_msat;
        self.store.swap(&note_ids, &[(p1_id.clone(), merged)])?;
        // a merge has no one note to name as the one that became p1
        let (c, r) = match note_ids.as_slice() {
            [spent] => self.rotate_certificates(spent, &p1_id, merged).await,
            _ => (self.certificate(&p1_id, merged).await, None),
        };
        Ok(compact(json!({
            "status": "OK",
            "c": c,
            "r": r,
        })))
    }

    /// Reserve the notes and pay `pr` in the background (LUD-03 answers
    /// before paying). The notes burn only once the payment settles.
    async fn melt(
        &self,
        note_ids: Vec<String>,
        pr: &str,
        total: u64,
        request_host: Option<&str>,
    ) -> MintResult<Value> {
        let decoded = match self.node.decode_invoice(pr).await {
            Ok(d) => d,
            Err(e) => return reject(format!("Invalid invoice: {e}")),
        };
        if decoded.amount_msat != Some(total) {
            return reject(format!("Invoice must be for exactly {total} msat."));
        }
        let hash = decoded.payment_hash;
        if self.store.mint_pr(&hash)?.is_some() {
            return reject("Cannot melt into an invoice this mint issued itself.");
        }
        // the node dedupes by payment hash: a second melt into the same
        // invoice would confirm against the first payment and burn for free
        if self.store.melt_pr(&hash)?.is_some() {
            return reject("Invoice already used by an earlier melt - use a fresh one.");
        }
        self.store.mark_pending(&note_ids, &hash)?;
        self.track_melt(&hash, true);
        if let Err(e) = self.store.record_melt(&hash, pr) {
            // nothing was paid: release the reservation
            let _ = self.store.restore(&note_ids);
            self.track_melt(&hash, false);
            return Err(e.into());
        }
        let (base, _) = self.settings.public_base_url_and_host(request_host);
        let response = compact(json!({
            "status": "OK",
            "pr": self.settings.verify_enabled.then_some(pr),
            "verify": self.settings.verify_enabled.then(|| format!("{base}/verify/{hash}")),
        }));
        let state = self.clone();
        let pr = pr.to_string();
        tokio::spawn(async move {
            state.melt_pay(&note_ids, &pr, &hash, total).await;
            state.track_melt(&hash, false);
        });
        Ok(response)
    }

    fn track_melt(&self, payment_hash: &str, start: bool) {
        let mut live = self
            .in_flight_melts
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let count = live.entry(payment_hash.to_string()).or_insert(0);
        if start {
            *count += 1;
        } else {
            *count = count.saturating_sub(1);
            if *count == 0 {
                live.remove(payment_hash);
            }
        }
    }

    fn melt_in_flight(&self, payment_hash: &str) -> bool {
        self.in_flight_melts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains_key(payment_hash)
    }

    /// Pay, then burn on confirmed success, restore on confirmed failure,
    /// and otherwise leave the notes pending for reconciliation. A note is
    /// never burned or restored on a guess: a failed `xpay` can still leave
    /// an HTLC held by the payee.
    async fn melt_pay(&self, note_ids: &[String], pr: &str, hash: &str, amount: u64) {
        let fee_limit = self.settings.melt_fee_limit_msat(amount);
        let failure = match self.node.pay(pr, fee_limit).await {
            Ok(result) => {
                self.finish_melt(note_ids, hash, amount, result.fee_msat);
                return;
            }
            Err(PayError::Failed(reason)) => reason,
            Err(PayError::Unknown(e)) => format!("{e:#}"),
        };
        for delay in CONFIRM_DELAYS_SECS {
            tokio::time::sleep(Duration::from_secs(delay)).await;
            match self.node.pay_status(hash).await {
                Ok((PayStatus::Complete, _)) => {
                    self.finish_melt(note_ids, hash, amount, None);
                    return;
                }
                Ok((PayStatus::Failed, _)) => {
                    log::info!("melt {hash}: not paid ({failure}) - restoring {note_ids:?}");
                    if let Err(e) = self.store.restore(note_ids) {
                        log::warn!("melt {hash}: could not restore notes: {e}");
                    }
                    return;
                }
                Ok((PayStatus::Pending, _)) => {}
                Err(e) => log::warn!("melt {hash}: listpays failed: {e:#}"),
            }
        }
        log::warn!(
            "melt {hash}: outcome unknown ({failure}) - notes left pending for reconciliation"
        );
    }

    fn finish_melt(&self, note_ids: &[String], hash: &str, amount: u64, fee: Option<u64>) {
        match self.store.finalize_melt(note_ids, hash) {
            Ok(()) => log::info!(
                "MELT payment_hash={hash} notes={note_ids:?} amount_msat={amount} routing_fee_msat={fee:?}"
            ),
            // the payment went out: the notes stay pending rather than restored
            Err(e) => log::warn!("melt {hash}: paid, but could not burn {note_ids:?}: {e}"),
        }
    }

    /// Resolve every melt left pending by a crash, a restart or an unknown
    /// outcome. Returns what was done, by payment hash.
    pub async fn reconcile_pending_melts(&self) -> MintResult<Value> {
        let mut report = Map::new();
        for (hash, note_ids) in self.store.pending_melts()? {
            if self.melt_in_flight(&hash) {
                report.insert(hash, json!("in flight"));
                continue;
            }
            let outcome = match self.node.pay_status(&hash).await {
                Ok((PayStatus::Complete, _)) => {
                    let amount = note_ids
                        .iter()
                        .filter_map(|id| self.store.note_record(id).ok().flatten())
                        .map(|r| r.amount_msat)
                        .sum();
                    self.finish_melt(&note_ids, &hash, amount, None);
                    "finalized"
                }
                Ok((PayStatus::Failed, _)) => {
                    self.store.restore(&note_ids)?;
                    log::info!("reconcile: melt {hash} not paid - restored {note_ids:?}");
                    "restored"
                }
                Ok((PayStatus::Pending, _)) => "pending",
                Err(e) => {
                    log::warn!("reconcile: melt {hash}: {e:#}");
                    "unknown"
                }
            };
            report.insert(hash, json!(outcome));
        }
        Ok(Value::Object(report))
    }

    // ---- Lightning Address registration (LUD-26) ----

    /// `POST /p/<username>?cx1=..&sig=..[&npub=..]`: claim or overwrite.
    pub fn register(
        &self,
        username: &str,
        cx1: &str,
        sig: &str,
        npub: Option<&str>,
        request_host: Option<&str>,
    ) -> MintResult<Value> {
        if !self.settings.username_registration_enabled {
            return reject("Not found");
        }
        let username = username.to_ascii_lowercase();
        if !valid_username(&username) || self.is_own_username(&username) {
            return reject("Invalid or reserved username.");
        }
        let Some(branch) = decode_cx1(cx1) else {
            return reject("Invalid cx1.");
        };
        let branch_hex = hex::encode([branch.pubkey_x_only, branch.chain_code].concat());
        let nostr_pubkey = match npub {
            None => None,
            Some(_) if !self.settings.nip05_enabled => {
                return reject("npub registration (NIP-05) is disabled on this mint.");
            }
            Some(npub) => match decode_npub(npub) {
                Some(key) => Some(hex::encode(key)),
                None => return reject("Invalid npub."),
            },
        };
        // a fresh claim proves the new branch; an overwrite proves the one on file
        let proof_branch = self
            .store
            .username_branch(&username)?
            .unwrap_or_else(|| branch_hex.clone());
        let (_, host) = self.settings.public_base_url_and_host(request_host);
        if !owns_branch("register", &host, &username, &proof_branch, sig) {
            return reject("Invalid ownership signature.");
        }
        self.store
            .upsert_username(&username, &branch_hex, nostr_pubkey.as_deref())?;
        Ok(json!({"status": "OK"}))
    }

    /// `DELETE /p/<username>?sig=..`: free a username, proven by the branch on file.
    pub fn unregister(
        &self,
        username: &str,
        sig: &str,
        request_host: Option<&str>,
    ) -> MintResult<Value> {
        if !self.settings.username_registration_enabled {
            return reject("Not found");
        }
        let username = username.to_ascii_lowercase();
        let Some(branch_hex) = self.store.username_branch(&username)? else {
            return reject("Unknown user.");
        };
        let (_, host) = self.settings.public_base_url_and_host(request_host);
        if !owns_branch("unregister", &host, &username, &branch_hex, sig) {
            return reject("Invalid ownership signature.");
        }
        self.store.delete_username(&username)?;
        Ok(json!({"status": "OK"}))
    }

    /// `GET /.well-known/nostr.json?name=..`: NIP-05 for registered usernames.
    pub fn nip05(&self, name: Option<&str>) -> MintResult<Value> {
        if !self.settings.nip05_enabled {
            return reject("Not found");
        }
        let mut names = Map::new();
        if let (Some(name), true) = (name, self.settings.username_registration_enabled) {
            if let Some(pubkey) = self.store.nostr_pubkey(&name.to_ascii_lowercase())? {
                names.insert(name.to_string(), json!(pubkey));
            }
        }
        Ok(json!({"names": names}))
    }

    /// `GET /.well-known/lnurlw/<username>`: informational only. Describes
    /// this mint and points back at its payRequest; there is no balance here.
    pub async fn mint_address(
        &self,
        username: &str,
        request_host: Option<&str>,
    ) -> MintResult<Value> {
        let username = username.to_ascii_lowercase();
        let name = if self.is_own_username(&username) {
            self.settings.username.to_ascii_lowercase()
        } else if self.registered_branch(&username)?.is_some() {
            username
        } else {
            return reject("Unknown user.");
        };
        let (base, host) = self.settings.public_base_url_and_host(request_host);
        let info = self.node.info().await.ok();
        Ok(compact(json!({
            "tag": "withdrawRequest",
            "callback": format!("{base}/w"),
            "minWithdrawable": self.settings.min_mint_msat,
            "maxWithdrawable": self.settings.max_mintable(),
            "defaultDescription": format!("lnurlcash bearer note on {host}"),
            "mintPubkey": info.as_ref().map(|i| i.id.clone()),
            "payLink": format!("{base}/.well-known/lnurlp/{name}"),
            "nodeAlias": info.as_ref().and_then(|i| i.alias.clone()),
            "nodeUri": info.as_ref().and_then(|i| i.uris.first().cloned()),
            "nodeUris": info.as_ref().filter(|i| !i.uris.is_empty()).map(|i| i.uris.clone()),
            "nodeColor": info.as_ref().and_then(|i| i.color.clone()),
            "nodeCapacity": info.as_ref().and_then(|i| i.capacity_msat),
            "nodeNumChannels": info.as_ref().and_then(|i| i.num_channels),
            "nodeNumPeers": info.as_ref().and_then(|i| i.num_peers),
            "sunsetDate": self.settings.sunset_date,
            "outstandingNotesMsat": self.store.stats()?.outstanding_msat,
        })))
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io::{BufRead, BufReader, Write},
        os::unix::net::UnixListener,
        path::PathBuf,
    };

    use super::*;
    use crate::{
        db::NoteStore,
        node::Node,
        structs::test_settings,
        vectors::{certifies_rotation, cr1_signature, lightning_signed_digest},
    };
    use lnurlcash_core::{
        recoverable::{
            derive_note_secret_key, encode_ck1, encode_cp1, encode_cx1, sign_note_ownership,
        },
        signature::{sign_address_proof, verify_note_signature_hash},
    };
    use secp256k1::{Message, SecretKey, ecdsa::RecoverableSignature};
    use sha2::{Digest, Sha256};

    /// The node key the test nodes sign with.
    const NODE_KEY: [u8; 32] = [7; 32];

    /// The node id their certificates verify against.
    fn node_id() -> String {
        let key = SecretKey::from_secret_bytes(NODE_KEY).unwrap();
        hex::encode(key.public_key().serialize())
    }

    /// lightningd's RPC socket, as far as certificates need it. The socket is
    /// removed once its test is over.
    struct Lightningd(PathBuf);

    impl Drop for Lightningd {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    impl Lightningd {
        /// A node that answers `signmessage` as lightningd does, and hangs up
        /// on anything else and on a message starting with `refused`. If
        /// `paired`, it answers no request before a second one is in.
        fn start(refused: Option<&'static str>, paired: bool) -> Self {
            let name = format!("cln-mint-{}.sock", hex::encode(rand::random::<[u8; 8]>()));
            let socket = std::env::temp_dir().join(name);
            let listener = UnixListener::bind(&socket).unwrap();
            std::thread::spawn(move || {
                let mut held = None;
                for stream in listener.incoming() {
                    let stream = stream.unwrap();
                    // one request a connection: a line of JSON, then an empty one
                    let mut request = String::new();
                    BufReader::new(&stream).read_line(&mut request).unwrap();
                    if paired && held.is_none() {
                        held = Some((stream, request));
                        continue;
                    }
                    let both = held.take().into_iter().chain([(stream, request)]);
                    for (mut stream, request) in both {
                        if let Some(answer) = Self::answer(&request, refused) {
                            let answer = format!("{answer}\n\n");
                            stream.write_all(answer.as_bytes()).unwrap();
                        }
                    }
                }
            });
            Lightningd(socket)
        }

        /// What `signmessage` answers: sha256d of the prefixed message, signed
        /// with RFC 6979. `None` is a hang-up.
        fn answer(request: &str, refused: Option<&str>) -> Option<Value> {
            let request: Value = serde_json::from_str(request).ok()?;
            let message = request["params"]["message"].as_str()?;
            let refused = refused.is_some_and(|start| message.starts_with(start));
            if request["method"] != "signmessage" || refused {
                return None;
            }
            let key = SecretKey::from_secret_bytes(NODE_KEY).unwrap();
            let digest = Message::from_digest(lightning_signed_digest(message));
            let (recid, rs) =
                RecoverableSignature::sign_ecdsa_recoverable(digest, &key).serialize_compact();
            Some(json!({"result": {
                "signature": hex::encode(rs),
                "recid": hex::encode([u8::from(recid)]),
            }}))
        }
    }

    /// A mint with an empty store, on the node behind `socket`.
    fn mint_at(socket: impl Into<PathBuf>) -> PluginState {
        PluginState::new(
            test_settings(),
            NoteStore::in_memory().unwrap(),
            Node::new(socket),
            ([127, 0, 0, 1], 0).into(),
        )
    }

    /// A mint whose node signs, with the node id its certificates verify against.
    fn signing_mint() -> (PluginState, String, Lightningd) {
        let node = Lightningd::start(None, false);
        (mint_at(&node.0), node_id(), node)
    }

    /// A bearer note: its spend (the preimage, hex) and its reference (`h`).
    fn bearer(seed: u8) -> (String, String) {
        let preimage = [seed; 32];
        (hex::encode(preimage), hex::encode(Sha256::digest(preimage)))
    }

    /// A key-path note: its spend at this mint (`ck1`), its reference (`cp1`)
    /// and its id, `hex(Q)`.
    fn key_path(seed: u8) -> (String, String, String) {
        let secret = [seed; 32];
        let q = secp256k1::Keypair::from_secret_bytes(secret)
            .unwrap()
            .x_only_public_key()
            .0
            .to_byte_array();
        let ck1 = encode_ck1(&sign_note_ownership(&secret, "mint.example").unwrap());
        (ck1, encode_cp1(&q), hex::encode(q))
    }

    fn note_id(h: &str) -> String {
        spend::note_id_of_ref(h).unwrap()
    }

    /// Credit the note `h` names with `amount_msat`, as a paid mint would.
    fn credit(state: &PluginState, h: &str, amount_msat: u64) {
        let payment_hash = hex::encode(Sha256::digest(h.as_bytes()));
        state
            .store
            .create_mint(&payment_hash, "lnbcrt1", amount_msat, &note_id(h))
            .unwrap();
        state.store.settle_mint(&payment_hash).unwrap();
    }

    /// `GET /w/cb` with outputs: a rotate, a split or a merge.
    async fn swap(
        state: &PluginState,
        k1s: &[&str],
        amount: Option<u64>,
        p1: &str,
        p2: Option<&str>,
    ) -> MintResult<Value> {
        let k1s: Vec<String> = k1s.iter().map(|k1| k1.to_string()).collect();
        state
            .withdraw_callback(&k1s, None, amount, Some(p1), p2, None)
            .await
    }

    #[tokio::test]
    async fn a_rotate_is_certified_from_note_to_note() {
        let (state, mint, _node) = signing_mint();
        let (k1, h) = bearer(1);
        let (_, hb) = bearer(2);
        let (_, hc) = bearer(3);
        credit(&state, &h, 50_000);
        let rotated = swap(&state, &[&k1], None, &hb, None).await.unwrap();
        let r = rotated["r"].as_str().unwrap();
        assert!(r.starts_with("cr500n1"), "{r}");
        let (spent, new) = (note_id(&h), note_id(&hb));
        assert!(certifies_rotation(&mint, &spent, &new, 50_000, r));
        // never another amount, the way back, or a look-alike minted on the side
        assert!(!certifies_rotation(&mint, &spent, &new, 50_001, r));
        assert!(!certifies_rotation(&mint, &new, &spent, 50_000, r));
        assert!(!certifies_rotation(&mint, &spent, &note_id(&hc), 50_000, r));
        // `c` is the new note's own certificate. Either is refused where the
        // other belongs by its prefix alone, before any signature is looked at
        let c = rotated["c"].as_str().unwrap();
        assert!(verify_note_signature_hash(&new, 50_000, c, &mint));
        assert!(!verify_note_signature_hash(&new, 50_000, r, &mint));
        assert!(!certifies_rotation(&mint, &spent, &new, 50_000, c));
        // and `r`'s bare signature certifies neither of the notes it names
        let bare = hex::encode(cr1_signature(r).unwrap());
        assert!(!verify_note_signature_hash(&new, 50_000, &bare, &mint));
        assert!(!verify_note_signature_hash(&spent, 50_000, &bare, &mint));
        // no table of its own: an exact retry reads the burn on record and is
        // signed again, to the same bytes by this deterministic signer
        let retried = swap(&state, &[&k1], None, &hb, None).await.unwrap();
        assert_eq!(retried, rotated);
    }

    #[tokio::test]
    async fn rotation_certificates_chain_step_by_step() {
        let (state, mint, _node) = signing_mint();
        let (k1a, ha) = bearer(1);
        let (k1b, hb) = bearer(2);
        let (_, hc) = bearer(3);
        credit(&state, &ha, 50_000);
        let ab = swap(&state, &[&k1a], None, &hb, None).await.unwrap();
        let bc = swap(&state, &[&k1b], None, &hc, None).await.unwrap();
        let (ab, bc) = (ab["r"].as_str().unwrap(), bc["r"].as_str().unwrap());
        let (a, b, c) = (note_id(&ha), note_id(&hb), note_id(&hc));
        let certifies =
            |r: &str, from: &str, to: &str| certifies_rotation(&mint, from, to, 50_000, r);
        // each certifies its own step
        assert!(certifies(ab, &a, &b) && certifies(bc, &b, &c));
        // and no other: not the step beside it, nor a shortcut past B
        assert!(!certifies(ab, &b, &c) && !certifies(bc, &a, &b));
        assert!(!certifies(ab, &a, &c) && !certifies(bc, &a, &c));
    }

    #[tokio::test]
    async fn a_key_path_note_is_certified_by_its_output_key() {
        // a signature spends these notes, no preimage: Q names them all the same
        let (state, mint, _node) = signing_mint();
        let (ck1, cp1, q) = key_path(3);
        let (ck1b, cp1b, qb) = key_path(4);
        let (_, h) = bearer(5);
        credit(&state, &cp1, 50_000);
        let rotated = swap(&state, &[&ck1], None, &cp1b, None).await.unwrap();
        let r = rotated["r"].as_str().unwrap();
        assert!(certifies_rotation(&mint, &q, &qb, 50_000, r));
        // and on from there, into a bearer note
        let rotated = swap(&state, &[&ck1b], None, &h, None).await.unwrap();
        let r = rotated["r"].as_str().unwrap();
        assert!(certifies_rotation(&mint, &qb, &note_id(&h), 50_000, r));
    }

    #[tokio::test]
    async fn only_a_rotate_gets_a_rotation_certificate() {
        let (state, _, _node) = signing_mint();
        let (k1, h) = bearer(1);
        let (k1a, ha) = bearer(2);
        let (k1b, hb) = bearer(3);
        let (_, hc) = bearer(4);
        credit(&state, &h, 50_000);
        // asking about a note rotates nothing
        let info = state.withdraw_request(Some(&k1), None, None).await.unwrap();
        assert!(info["c"].is_string() && info.get("r").is_none(), "{info}");
        // a split: two notes came out of one, and neither is the note it became
        let split = swap(&state, &[&k1], Some(20_000), &ha, Some(&hb)).await;
        let split = split.unwrap();
        assert!(split["c"].is_string() && split["c2"].is_string(), "{split}");
        assert!(split.get("r").is_none(), "{split}");
        // a merge: no one note became the new one
        let merged = swap(&state, &[&k1a, &k1b], None, &hc, None).await.unwrap();
        assert!(
            merged["c"].is_string() && merged.get("r").is_none(),
            "{merged}"
        );
        // nor does a retry of either
        let again = swap(&state, &[&k1], Some(20_000), &ha, Some(&hb)).await;
        assert_eq!(again.unwrap(), split);
        let again = swap(&state, &[&k1a, &k1b], None, &hc, None).await;
        assert_eq!(again.unwrap(), merged);
        // and neither is replayed as a rotate of one of its notes into one of its outputs
        for (k1, output) in [(&k1, &ha), (&k1a, &hc)] {
            let refused = swap(&state, &[k1], None, output, None).await;
            assert!(matches!(refused, Err(MintError::Reject(r)) if r == spend::INVALID_K1));
        }
    }

    #[tokio::test]
    async fn a_rotation_certificate_lost_to_its_signing_comes_with_a_retry() {
        // a node that signs no rotation, until another answers in its place
        let down = Lightningd::start(Some("LNURLcash:rotate:"), false);
        let (state, mint) = (mint_at(&down.0), node_id());
        let (k1, h) = bearer(1);
        let (_, hb) = bearer(2);
        credit(&state, &h, 50_000);
        // the rotate stands and the new note is certified, without its `r`
        let first = swap(&state, &[&k1], None, &hb, None).await.unwrap();
        assert!(
            first["c"].is_string() && first.get("r").is_none(),
            "{first}"
        );
        // the same request again is how the rest is had
        let up = Lightningd::start(None, false);
        let state = PluginState {
            node: Node::new(&up.0),
            ..state
        };
        let retried = swap(&state, &[&k1], None, &hb, None).await.unwrap();
        assert_eq!(retried["c"], first["c"]);
        let r = retried["r"].as_str().unwrap();
        assert!(certifies_rotation(
            &mint,
            &note_id(&h),
            &note_id(&hb),
            50_000,
            r
        ));
    }

    #[tokio::test]
    async fn a_rotate_waits_for_the_node_once() {
        // this node answers no request before a second one is in: asked for
        // one after the other, a rotate's certificates would never come
        let node = Lightningd::start(None, true);
        let (state, mint) = (mint_at(&node.0), node_id());
        let (k1, h) = bearer(1);
        let (_, hb) = bearer(2);
        credit(&state, &h, 50_000);
        // the rotate, then its retry
        let k1s = [k1.as_str()];
        for _ in 0..2 {
            let rotate = swap(&state, &k1s, None, &hb, None);
            let rotated = tokio::time::timeout(Duration::from_secs(5), rotate).await;
            let rotated = rotated.expect("both are asked for at once").unwrap();
            let c = rotated["c"].as_str().unwrap();
            let r = rotated["r"].as_str().unwrap();
            assert!(verify_note_signature_hash(&note_id(&hb), 50_000, c, &mint));
            assert!(certifies_rotation(
                &mint,
                &note_id(&h),
                &note_id(&hb),
                50_000,
                r
            ));
        }
    }

    #[tokio::test]
    async fn a_rotate_no_one_could_sign_still_stands() {
        // no node behind the socket, no signature: the note moved all the same
        let state = mint_at("/nonexistent/lightning-rpc");
        let (k1, h) = bearer(1);
        let (_, hb) = bearer(2);
        credit(&state, &h, 50_000);
        let rotated = swap(&state, &[&k1], None, &hb, None).await.unwrap();
        assert_eq!(rotated, json!({"status": "OK"}));
        let new = state.store.note_record(&note_id(&hb)).unwrap().unwrap();
        assert_eq!((new.amount_msat, new.spent), (50_000, false));
    }

    #[test]
    fn usernames() {
        assert!(valid_username("alice.b-c_1"));
        assert!(!valid_username("Alice"));
        assert!(!valid_username(""));
        assert!(!valid_username(&"a".repeat(33)));
    }

    #[test]
    fn registration_proofs_bind_action_domain_and_username() {
        let branch_sk = [11u8; 32];
        let chain_code = [2u8; 32];
        let kp = secp256k1::Keypair::from_secret_bytes(branch_sk).unwrap();
        let point = kp.x_only_public_key().0.to_byte_array();
        let branch_hex = hex::encode([point, chain_code].concat());
        let sk0 = derive_note_secret_key(&branch_sk, &chain_code, PURPOSE_WALLET, 0).unwrap();
        let sig =
            hex::encode(sign_address_proof(&sk0, "register", "mint.example", "alice").unwrap());
        assert!(owns_branch(
            "register",
            "mint.example",
            "alice",
            &branch_hex,
            &sig
        ));
        assert!(!owns_branch(
            "unregister",
            "mint.example",
            "alice",
            &branch_hex,
            &sig
        ));
        assert!(!owns_branch(
            "register",
            "other.example",
            "alice",
            &branch_hex,
            &sig
        ));
        assert!(!owns_branch(
            "register",
            "mint.example",
            "bob",
            &branch_hex,
            &sig
        ));
        assert!(decode_cx1(&encode_cx1(&point, &chain_code)).is_some());
    }

    #[test]
    fn npub_decodes() {
        // NIP-19's own example
        let npub = "npub10elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8qzvjptg";
        assert_eq!(
            decode_npub(npub).map(hex::encode).as_deref(),
            Some("7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e")
        );
        assert!(decode_npub("npub1xyz").is_none());
    }
}
