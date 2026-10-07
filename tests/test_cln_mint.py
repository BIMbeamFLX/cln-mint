import hashlib
import json
import os
from urllib.parse import urlparse

from pyln.testing.fixtures import *  # noqa: F403
from pyln.testing.utils import only_one, wait_for
from util import error, get, get_plugin, ok, vectors  # noqa: F401

BASE_FEE_MSAT = 1000


def mint_node_opts(get_plugin, port, base_url, **extra):
    opts = {
        "plugin": get_plugin,
        "cln-mint-base-url": base_url,
        "cln-mint-listen": f"127.0.0.1:{port}",
        "cln-mint-base-fee-msat": BASE_FEE_MSAT,
    }
    opts.update(extra)
    return opts


def wallet_and_mint(node_factory, get_plugin, base_url="https://mint.example", **extra):
    """A wallet node with a funded channel to a mint node, and the mint's URL."""
    port = node_factory.get_unused_port()
    wallet, mint = node_factory.line_graph(
        2,
        fundamount=10**7,
        wait_for_announce=True,
        opts=[{}, mint_node_opts(get_plugin, port, base_url, **extra)],
    )
    # past the mint's channel reserve, so it can pay melts back out
    wallet.rpc.xpay(mint.rpc.invoice(300_000_000, "liquidity", "liquidity")["bolt11"])
    url = f"http://127.0.0.1:{port}"
    wait_for(lambda: get_ok(f"{url}/.well-known/lnurlp/mint"))
    return wallet, mint, url


def get_ok(url):
    try:
        return get(url).get("tag") == "payRequest"
    except Exception:
        return False


def local(url, public_url):
    """`public_url` (built from the mint's base URL) on the local listener."""
    parsed = urlparse(public_url)
    return f"{url}{parsed.path}" + (f"?{parsed.query}" if parsed.query else "")


def bearer():
    preimage = os.urandom(32)
    return preimage.hex(), hashlib.sha256(preimage).hexdigest()


def mint_note(wallet, url, comment, amount_msat, username="mint"):
    pay_request = ok(get(f"{url}/.well-known/lnurlp/{username}"))
    invoice = ok(get(local(url, pay_request["callback"]), {"amount": amount_msat, "comment": comment}))
    wallet.rpc.xpay(invoice["pr"])
    return invoice


def value(url, **query):
    return ok(get(f"{url}/w", query))["maxWithdrawable"]


def test_start(node_factory, get_plugin):  # noqa: F811
    port = node_factory.get_unused_port()
    node = node_factory.get_node(options=mint_node_opts(get_plugin, port, "https://mint.example"))
    info = node.rpc.call("cln-mint-info")
    assert info["lightning_address"] == "mint@mint.example"
    assert info["mint_pubkey"] == node.info["id"]
    assert info["stats"]["outstanding_msat"] == 0


def test_missing_base_url_disables_plugin(node_factory, get_plugin):  # noqa: F811
    node = node_factory.get_node(options={"plugin": get_plugin})
    assert node.daemon.is_in_log("Please specify `cln-mint-base-url`")


def test_pay_request(node_factory, get_plugin):  # noqa: F811
    wallet, mint, url = wallet_and_mint(node_factory, get_plugin)
    for username in ["mint", "_", "MINT"]:
        pay_request = ok(get(f"{url}/.well-known/lnurlp/{username}"))
        assert pay_request["tag"] == "payRequest"
        assert pay_request["callback"] == "https://mint.example/p/cb"
        assert pay_request["withdrawLink"] == "https://mint.example/w"
        assert pay_request["commentAllowed"] == 64
        metadata = json.loads(pay_request["metadata"])
        assert ["text/identifier", "mint@mint.example"] in metadata
        assert ["text/plain", f"Mint fees: {BASE_FEE_MSAT},0"] in metadata
    error(get(f"{url}/.well-known/lnurlp/nobody"), "Unknown user.")

    # the invoice commits to the metadata (LUD-06)
    _, h = bearer()
    invoice = ok(get(f"{url}/p/cb", {"amount": 100_000, "comment": h}))
    decoded = mint.rpc.decode(invoice["pr"])
    assert decoded["description_hash"] == hashlib.sha256(pay_request["metadata"].encode()).hexdigest()
    assert invoice["verify"].startswith("https://mint.example/verify/")

    # a comment is required, and names an unused note
    error(get(f"{url}/p/cb", {"amount": 100_000}))
    error(get(f"{url}/p/cb", {"amount": 100_000, "comment": "hello"}))
    error(get(f"{url}/p/cb", {"amount": 100_000, "comment": h}), "already in use")
    error(get(f"{url}/p/cb", {"amount": 1, "comment": bearer()[1]}), "Amount too low.")


def test_bearer_note_lifecycle(node_factory, get_plugin):  # noqa: F811
    wallet, mint, url = wallet_and_mint(node_factory, get_plugin)
    mint_id = mint.info["id"]

    # mint
    k1, h = bearer()
    invoice = mint_note(wallet, url, h, 100_000)
    wait_for(lambda: get(f"{url}/w", {"k1": k1}).get("maxWithdrawable") == 99_000)
    info = ok(get(f"{url}/w", {"k1": k1, "amount": 5}))
    assert info["k1"] == k1
    assert info["minWithdrawable"] == info["maxWithdrawable"] == 99_000
    assert info["callback"] == "https://mint.example/w/cb"
    assert info["mintPubkey"] == mint_id
    assert info["c"].startswith("cs990n1")
    # checking by h exposes no spend
    by_hash = ok(get(f"{url}/w", {"p": h}))
    assert "k1" not in by_hash and by_hash["maxWithdrawable"] == 99_000
    assert ok(get(local(url, invoice["verify"])))["settled"] is True

    # rotate, and a retry of it gets the same answer, rotation certificate included
    k2, h2 = bearer()
    rotated = ok(get(f"{url}/w/cb", {"k1": k1, "p1": h2}))
    assert rotated["c"].startswith("cs990n1") and rotated["r"].startswith("cr990n1")
    assert ok(get(f"{url}/w/cb", {"k1": k1, "p1": h2})) == rotated
    error(get(f"{url}/w", {"k1": k1}), "Note already spent.")
    error(get(f"{url}/w/cb", {"k1": k1, "p1": bearer()[1]}), "Invalid or already spent k1.")
    assert value(url, k1=k2) == 99_000

    # split: the base fee comes out of the change
    (k3, h3), (k4, h4) = bearer(), bearer()
    error(get(f"{url}/w/cb", {"k1": k2, "amount": 40_000, "p1": h3}), "missing p2")
    split = ok(get(f"{url}/w/cb", {"k1": k2, "amount": 40_000, "p1": h3, "p2": h4}))
    assert "c" in split and "c2" in split and "r" not in split
    assert value(url, k1=k3) == 40_000
    assert value(url, k1=k4) == 99_000 - 40_000 - BASE_FEE_MSAT

    # an output already in use is refused and nothing burns
    error(get(f"{url}/w/cb", {"k1": k3, "p1": h4}), "already in use")
    assert value(url, k1=k3) == 40_000

    # merge refunds (n - 1) base fees, and like a split is no rotation
    k5, h5 = bearer()
    assert "r" not in ok(get(f"{url}/w/cb", {"k1": [k3, k4], "p1": h5}))
    assert value(url, k1=k5) == 99_000

    # p is never accepted at the callback
    error(get(f"{url}/w/cb", {"p": h5, "p1": bearer()[1]}))

    # melt: the invoice must match the note exactly
    wrong = wallet.rpc.invoice(1000, "wrong", "melt")["bolt11"]
    error(get(f"{url}/w/cb", {"k1": k5, "pr": wrong}), "Invoice must be for exactly 99000 msat.")
    error(get(f"{url}/w/cb", {"k1": k5, "pr": invoice["pr"]}))
    melt_invoice = wallet.rpc.invoice(99_000, "melt", "melt")
    melted = ok(get(f"{url}/w/cb", {"k1": k5, "pr": melt_invoice["bolt11"]}))
    wait_for(lambda: only_one(wallet.rpc.listinvoices("melt")["invoices"])["status"] == "paid")
    wait_for(lambda: get(f"{url}/w", {"k1": k5}).get("reason") == "Note already spent.")
    verified = ok(get(local(url, melted["verify"])))
    assert verified["settled"] is True
    assert hashlib.sha256(bytes.fromhex(verified["preimage"])).hexdigest() == melt_invoice["payment_hash"]
    error(get(f"{url}/w/cb", {"k1": k5, "pr": melt_invoice["bolt11"]}))

    stats = mint.rpc.call("cln-mint-info")["stats"]
    assert stats["outstanding_msat"] == 0
    assert stats["pending_notes"] == 0


def test_failed_melt_restores_the_note(node_factory, get_plugin):  # noqa: F811
    wallet, mint, url = wallet_and_mint(node_factory, get_plugin)
    k1, h = bearer()
    mint_note(wallet, url, h, 50_000)
    wait_for(lambda: get(f"{url}/w", {"k1": k1}).get("maxWithdrawable") == 49_000)
    # an invoice to a node nobody can route to
    stranger = node_factory.get_node()
    unroutable = stranger.rpc.invoice(49_000, "melt", "melt")["bolt11"]
    ok(get(f"{url}/w/cb", {"k1": k1, "pr": unroutable}))
    wait_for(lambda: get(f"{url}/w", {"k1": k1}).get("maxWithdrawable") == 49_000)
    assert mint.rpc.call("cln-mint-pending")["pending_melts"] == {}


def test_key_path_note(node_factory, get_plugin):  # noqa: F811
    """LUD-25's key_path_spend vector: a ck1 bound to mint.example."""
    v = vectors(25)["key_path_spend"]
    wallet, mint, url = wallet_and_mint(node_factory, get_plugin, base_url=f"https://{v['domain']}")
    mint_note(wallet, url, v["cp1"], 100_000)
    wait_for(lambda: get(f"{url}/w", {"k1": v["ck1"]}).get("maxWithdrawable") == 99_000)
    assert mint.rpc.call("cln-mint-note", [v["cp1"]])["status"] == "outstanding"
    k2, h2 = bearer()
    ok(get(f"{url}/w/cb", {"k1": v["ck1"], "p1": h2}))
    assert mint.rpc.call("cln-mint-note", [v["cp1"]])["status"] == "spent"
    # a burned Q is never credited again
    error(get(f"{url}/p/cb", {"amount": 100_000, "comment": v["cp1"]}), "already in use")


def test_key_path_is_bound_to_the_domain(node_factory, get_plugin):  # noqa: F811
    v = vectors(25)["key_path_spend"]
    wallet, mint, url = wallet_and_mint(node_factory, get_plugin, base_url="https://other.example")
    mint_note(wallet, url, v["cp1"], 100_000)
    wait_for(lambda: get(f"{url}/w", {"p": v["cp1"]}).get("maxWithdrawable") == 99_000)
    error(get(f"{url}/w", {"k1": v["ck1"]}), "Unknown note.")
    error(get(f"{url}/w/cb", {"k1": v["ck1"], "p1": bearer()[1]}), "Invalid or already spent k1.")


def test_lightning_address_registration(node_factory, get_plugin):  # noqa: F811
    """LUD-26's registration vector: alice at cash.example.com."""
    v = vectors(26)
    reg = v["registration"]
    cx1 = v["derivation"][1]["cx1"]
    wallet, mint, url = wallet_and_mint(node_factory, get_plugin, base_url=f"https://{reg['domain']}")
    alice = f"{url}/p/{reg['username']}"

    error(get(alice, {"cx1": cx1, "sig": reg["unregister"]["sig"]}, "POST"), "Invalid ownership signature.")
    error(get(f"{url}/p/mint", {"cx1": cx1, "sig": reg["register"]["sig"]}, "POST"))
    ok(get(alice, {"cx1": cx1, "sig": reg["register"]["sig"]}, "POST"))

    pay_request = ok(get(f"{url}/.well-known/lnurlp/alice"))
    assert pay_request["callback"] == f"https://{reg['domain']}/p/alice"
    assert "commentAllowed" not in pay_request
    metadata = json.loads(pay_request["metadata"])
    assert ["text/cpub", f"{cx1}:0"] in metadata
    assert ["text/identifier", f"alice@{reg['domain']}"] in metadata

    # a payment auto-mints onto purpose 2, index 0
    invoice = ok(get(alice, {"amount": 20_000}))
    assert mint.rpc.decode(invoice["pr"])["description_hash"] == hashlib.sha256(
        pay_request["metadata"].encode()).hexdigest()
    wallet.rpc.xpay(invoice["pr"])
    wait_for(lambda: mint.rpc.call("cln-mint-info")["stats"]["outstanding_msat"] == 19_000)
    assert only_one(mint.rpc.call("cln-mint-listusers")["users"])["next_index"] == 1
    assert ["text/cpub", f"{cx1}:1"] in json.loads(ok(get(f"{url}/.well-known/lnurlp/alice"))["metadata"])

    ok(get(f"{url}/.well-known/lnurlw/alice"))
    error(get(alice, {"sig": reg["register"]["sig"]}, "DELETE"), "Invalid ownership signature.")
    ok(get(alice, {"sig": reg["unregister"]["sig"]}, "DELETE"))
    error(get(f"{url}/.well-known/lnurlp/alice"), "Unknown user.")


def test_sunset(node_factory, get_plugin):  # noqa: F811
    wallet, mint, url = wallet_and_mint(node_factory, get_plugin, **{"cln-mint-sunset-mint": True})
    error(get(f"{url}/p/cb", {"amount": 100_000, "comment": bearer()[1]}),
          "This mint is sunsetting - minting is disabled.")
