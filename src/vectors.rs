//! LUD-25 and LUD-26's own test vectors, run against this plugin's paths.

use bech32::{Bech32m, primitives::decode::CheckedHrpstring};
use lnurlcash_core::{
    recoverable::{decode_cs1_with_amount, decode_cx1, derive_note_pubkey, encode_cs1_with_amount},
    signature::{note_signature_message_for_hash, verify_note_signature_hash},
};
use secp256k1::{
    Message, SecretKey,
    ecdsa::{RecoverableSignature, RecoveryId},
};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{
    mint::{encode_cr1_with_amount, rotation_message},
    spend,
};

fn vectors(name: &str) -> Value {
    let raw = match name {
        "25" => include_str!("../tests/vectors/25-vectors.json"),
        _ => include_str!("../tests/vectors/26-vectors.json"),
    };
    serde_json::from_str(raw).unwrap()
}

fn s<'a>(v: &'a Value, key: &str) -> &'a str {
    v[key]
        .as_str()
        .unwrap_or_else(|| panic!("vector field {key}"))
}

#[test]
fn key_path_spend_opens_its_note_at_its_domain_only() {
    let v = &vectors("25")["key_path_spend"];
    let parsed = spend::parse(s(v, "ck1")).unwrap();
    assert_eq!(parsed.note_id, s(v, "Q"));
    assert_eq!(
        spend::note_id_of_ref(s(v, "cp1")).as_deref(),
        Some(s(v, "Q"))
    );
    assert_eq!(spend::verify(&parsed, 0, &[s(v, "domain").into()], 1), None);
    assert!(spend::verify(&parsed, 0, &["other.example".into()], 1).is_some());
}

#[test]
fn certificates_encode_as_the_vectors_do() {
    let v = &vectors("25")["certificates"];
    for case in v["cases"].as_array().unwrap() {
        let amount = case["amount_msat"].as_u64().unwrap();
        assert_eq!(
            note_signature_message_for_hash(s(v, "Q"), amount),
            s(case, "message")
        );
        let sig: [u8; 65] = hex::decode(s(case, "signature"))
            .unwrap()
            .try_into()
            .unwrap();
        assert_eq!(encode_cs1_with_amount(amount, &sig), s(case, "cs1"));
    }
}

#[test]
fn bearer_note_every_form_names_one_note() {
    let v = &vectors("25")["bearer_note"];
    let q = s(v, "Q");
    for reference in [s(v, "h"), s(v, "cp1")] {
        assert_eq!(spend::note_id_of_ref(reference).as_deref(), Some(q));
    }
    for k1 in [s(v, "preimage"), s(v, "cw1")] {
        let parsed = spend::parse(k1).unwrap();
        assert_eq!(parsed.note_id, q);
        // a bearer leaf checks no signature: any domain
        assert_eq!(
            spend::verify(&parsed, 0, &["anywhere.example".into()], 1),
            None
        );
    }
    let cert = &v["certificate"];
    let sig: [u8; 65] = hex::decode(s(cert, "signature"))
        .unwrap()
        .try_into()
        .unwrap();
    let amount = cert["amount_msat"].as_u64().unwrap();
    assert_eq!(encode_cs1_with_amount(amount, &sig), s(cert, "cs1"));
}

#[test]
fn cx1_derivation_matches_every_note() {
    for branch in vectors("26")["derivation"].as_array().unwrap() {
        let cx1 = decode_cx1(s(branch, "cx1")).unwrap();
        for note in branch["notes"].as_array().unwrap() {
            let purpose = note["purpose"].as_u64().unwrap() as u32;
            let i = note["i"].as_u64().unwrap() as u32;
            let q = derive_note_pubkey(&cx1.pubkey_x_only, &cx1.chain_code, purpose, i).unwrap();
            // Q is given compressed; its x is the note
            assert_eq!(hex::encode(q), s(note, "Q")[2..]);
            assert_eq!(spend::note_id_of_ref(s(note, "cp1")), Some(hex::encode(q)));
        }
    }
}

#[test]
fn registration_proofs_verify() {
    let v = vectors("26");
    let reg = &v["registration"];
    let cx1 = decode_cx1(s(&v["derivation"][1], "cx1")).unwrap();
    let branch_hex = hex::encode([cx1.pubkey_x_only, cx1.chain_code].concat());
    let (domain, username) = (s(reg, "domain"), s(reg, "username"));
    for action in ["register", "unregister"] {
        let sig = s(&reg[action], "sig");
        assert!(crate::mint::owns_branch(
            action,
            domain,
            username,
            &branch_hex,
            sig
        ));
    }
    let register_sig = s(&reg["register"], "sig");
    assert!(!crate::mint::owns_branch(
        "unregister",
        domain,
        username,
        &branch_hex,
        register_sig
    ));
}

// ---- rotation certificates ----

/// What a Lightning node's signmessage signs.
pub(crate) fn lightning_signed_digest(message: &str) -> [u8; 32] {
    let prefixed = [b"Lightning Signed Message:".as_slice(), message.as_bytes()].concat();
    Sha256::digest(Sha256::digest(prefixed)).into()
}

/// Who signed the rotation of `spent_id` into `note_id`, worth `amount_msat`:
/// the key a holder compares with `mintPubkey`.
fn rotation_signer(
    spent_id: &str,
    note_id: &str,
    amount_msat: u64,
    sig: &[u8; 65],
) -> Option<String> {
    let message = rotation_message(spent_id, note_id, amount_msat);
    let recovery_id = RecoveryId::try_from(i32::from(sig[64])).ok()?;
    let key = RecoverableSignature::from_compact(&sig[..64], recovery_id)
        .ok()?
        .recover_ecdsa(Message::from_digest(lightning_signed_digest(&message)))
        .ok()?;
    Some(hex::encode(key.serialize()))
}

/// The signature a `cr1` carries, whatever amount it states.
pub(crate) fn cr1_signature(cr1: &str) -> Option<[u8; 65]> {
    let checked = CheckedHrpstring::new::<Bech32m>(cr1).ok()?;
    if !checked.hrp().to_lowercase().starts_with("cr") {
        return None;
    }
    checked.byte_iter().collect::<Vec<u8>>().try_into().ok()
}

/// Whether `cr1` is `mint_pubkey`'s certificate that the note `spent_id` was
/// burned into `note_id`, worth `amount_msat`: what a holder checks offline
/// for every step of a note's lineage. The mint itself never does.
pub(crate) fn certifies_rotation(
    mint_pubkey: &str,
    spent_id: &str,
    note_id: &str,
    amount_msat: u64,
    cr1: &str,
) -> bool {
    let Some(sig) = cr1_signature(cr1) else {
        return false;
    };
    // a cr1 states the amount it signs, under its own prefix
    encode_cr1_with_amount(amount_msat, &sig) == cr1
        && rotation_signer(spent_id, note_id, amount_msat, &sig).as_deref() == Some(mint_pubkey)
}

/// lnurl-mint's `cr1` test vector: the mint's key is sha256("LNURLcash
/// rotation certificate test vector"), and one note is burned into another
/// for two amounts.
#[test]
fn rotation_certificates_match_lnurl_mints_vector() {
    let secret: [u8; 32] = Sha256::digest(b"LNURLcash rotation certificate test vector").into();
    assert_eq!(
        hex::encode(secret),
        "e68d48301c476389d71eadbcc6209929339f5326455183f51ee48fb074b2c67b"
    );
    let key = SecretKey::from_secret_bytes(secret).unwrap();
    let mint = "0305299ebc7d5301da5ff64350c558d2daf9933445e611574474024d10d30f826a";
    assert_eq!(hex::encode(key.public_key().serialize()), mint);
    let spent = "aad3a0e36c083eb0d2d92ec0860977dc46d10c952f31830e6443b1faa1997634";
    let note = "01fee34e378bf66de6afa1bfa6e30f5c89551fd92bc1b089dca93c52b7ab61bc";
    assert_eq!(
        rotation_message(spent, note, 1000),
        ["LNURLcash:rotate:1000", spent, note].join(":")
    );
    for (amount, digest, signature, cr1) in [
        (
            1000,
            "0d60b3e73e340395bccbd3b87a2210dc6c949df3cd6f0c74d256349b2b989cc1",
            "3ef03201d14594c51de4d5372f57036b29c0fed94f88c804fc6b69198a40155d\
             4d2969bfef7a9226f1fbcb15246a1be0c2f8c3cc2d0983e0c3e67e422c7c807001",
            "cr10n18mcryqw3gk2v280y65mj74crdv5uplkef7yvsp8udd53nzjqz4w562tfhlhh4y3x78\
             auk9fydgd7pshcc0xz6zvrurp7vljz937gquqp09cjwz",
        ),
        (
            21_000_000,
            "2ee0ec8c1361fd0e1613d62575dd3e790cd4480ac699af7c852eb9819a29db05",
            "6c329cc404f152e5d59d3b737ea9a347e718b676475679d13db0b9112bdfe406\
             4bae7416c87918ad030423c9dcf4913994e83eb278c6ca9e955292220cc109ac01",
            "cr210u1dsefe3qy79fwt4va8deha2drgln33dnkgat8n5fakzu3z27lusryhtn5zmy8jx9dq\
             vzz8jwu7jgnn98g86e833k2n6249y3zpnqsntqpu0dlaz",
        ),
    ] {
        let hash = lightning_signed_digest(&rotation_message(spent, note, amount));
        assert_eq!(hex::encode(hash), digest);
        // signed as a node's signmessage signs: RFC 6979, r || s || recovery id
        let (recovery_id, rs) =
            RecoverableSignature::sign_ecdsa_recoverable(Message::from_digest(hash), &key)
                .serialize_compact();
        let sig: [u8; 65] = [rs.as_slice(), &[u8::from(recovery_id)]]
            .concat()
            .try_into()
            .unwrap();
        assert_eq!(hex::encode(sig), signature);
        assert_eq!(encode_cr1_with_amount(amount, &sig), cr1);
        assert!(certifies_rotation(mint, spent, note, amount, cr1));
        // the amount, the direction and the notes themselves are all signed
        let signed_by_mint = |spent: &str, note: &str, amount: u64| {
            rotation_signer(spent, note, amount, &sig).as_deref() == Some(mint)
        };
        assert!(signed_by_mint(spent, note, amount));
        assert!(!signed_by_mint(spent, note, amount + 1));
        assert!(!signed_by_mint(note, spent, amount));
        assert!(!signed_by_mint(spent, spent, amount));
        // and it is never a note's own certificate, for either note it names
        assert!(!verify_note_signature_hash(note, amount, signature, mint));
        assert!(!verify_note_signature_hash(spent, amount, signature, mint));
    }
}

#[test]
fn a_cr1_is_a_cs1_under_its_own_prefix() {
    let sig = [0x33u8; 65];
    assert!(encode_cr1_with_amount(1000, &sig).starts_with("cr10n1"));
    for amount in [0, 1, 1000, 21_000, 100_000_000, u64::MAX] {
        let cs1 = encode_cs1_with_amount(amount, &sig);
        let cr1 = encode_cr1_with_amount(amount, &sig);
        // the same amount in its human-readable part, the same payload
        let (cs_hrp, _) = cs1.rsplit_once('1').unwrap();
        let (cr_hrp, _) = cr1.rsplit_once('1').unwrap();
        assert_eq!(cr_hrp, cs_hrp.replacen("cs", "cr", 1));
        let checked = CheckedHrpstring::new::<Bech32m>(&cr1).unwrap();
        assert_eq!(checked.byte_iter().collect::<Vec<u8>>(), sig);
        // and a verifier handed the wrong kind sees no certificate at all
        assert!(decode_cs1_with_amount(&cr1).is_none());
    }
}
