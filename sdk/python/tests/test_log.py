"""The log: writing, auditing, tamper detection, bundles and witnesses."""

import json

import pytest

from proof_wire import ProofLog, cosign, generate_identity, verify_bundle


def fill(log, n, start=0):
    for i in range(start, start + n):
        log.append(
            actor={"agent": "claude", "runtime": "test", "session": "s1", "principal": "ops@acme.test"},
            action={"kind": "tool_call", "target": "crm.refund", "params": {"order": f"ord_{i}", "card": "4242 4242 4242 4242"}, "metrics": {"amount_usd": 12.5}},
            decision={"outcome": "allow", "policy": "p1", "rules": []},
        )


@pytest.fixture
def log(tmp_path):
    return ProofLog.create(tmp_path / "log")


def test_a_fresh_log_audits_clean_and_reopens_identically(log):
    fill(log, 5)
    assert log.audit()["ok"]
    again = ProofLog.open(log.dir)
    assert again.root == log.root and again.head == log.head and again.size == 5
    ro = ProofLog.open(log.dir, read_only=True)
    with pytest.raises(PermissionError):
        fill(ro, 1)


def test_files_use_lf_on_every_platform(log):
    fill(log, 2)
    raw = (log.dir / "entries.jsonl").read_bytes()
    assert b"\r" not in raw and raw.count(b"\n") == 2


def test_secrets_never_reach_the_receipt(log):
    fill(log, 1)
    text = (log.dir / "entries.jsonl").read_text("utf-8")
    assert "4242 4242 4242 4242" not in text
    assert json.loads(text)["action"]["params"]["redacted"] == ["credit_card"]
    # ...but the commitment still proves what the value was.
    assert log.reveal(0, "params", {"order": "ord_0", "card": "4242 4242 4242 4242"})
    assert not log.reveal(0, "params", {"order": "ord_0", "card": "4000 0000 0000 0002"})


def test_editing_an_entry_on_disk_is_caught(log):
    fill(log, 3)
    p = log.dir / "entries.jsonl"
    p.write_bytes(p.read_bytes().replace(b"ord_1", b"ord_9"))
    assert not ProofLog.open(log.dir).audit()["ok"]


def test_deleting_an_entry_on_disk_is_caught(log):
    fill(log, 3)
    p = log.dir / "entries.jsonl"
    lines = p.read_bytes().split(b"\n")
    p.write_bytes(b"\n".join([lines[0], lines[2], b""]))
    issues = ProofLog.open(log.dir).audit()["issues"]
    assert any(i["kind"] in ("chain", "sequence") for i in issues)


def test_rewriting_checkpointed_history_with_the_key_is_caught(log, tmp_path):
    fill(log, 4)
    log.checkpoint()
    # The key holder rebuilds a consistent log without entry 2...
    key = (log.dir / "key.pem").read_bytes()
    forged = ProofLog.create(tmp_path / "forged", log_id=log.log_id)
    (forged.dir / "key.pem").write_bytes(key)
    (forged.dir / "keyring.json").write_bytes((log.dir / "keyring.json").read_bytes())
    (forged.dir / "config.json").write_bytes((log.dir / "config.json").read_bytes())
    forged = ProofLog.open(forged.dir)
    fill(forged, 2)
    fill(forged, 2, start=3)
    assert forged.audit()["ok"], "the forgery is internally consistent"
    # ...but the checkpoint signed before says otherwise.
    (forged.dir / "checkpoints.jsonl").write_bytes((log.dir / "checkpoints.jsonl").read_bytes())
    issues = ProofLog.open(forged.dir).audit()["issues"]
    assert any("history was rewritten" in i["message"] for i in issues)


def test_a_bundle_verifies_with_nothing_but_itself_and_catches_a_swap(log):
    fill(log, 6)
    log.checkpoint()
    b = json.loads(json.dumps(log.bundle()))
    assert verify_bundle(b)["ok"], verify_bundle(b)["issues"]
    b["entries"][2]["receipt"]["action"]["target"] = "crm.delete"
    assert not verify_bundle(b)["ok"]


def test_a_filtered_bundle_proves_each_entry_belongs(log):
    fill(log, 8)
    b = json.loads(json.dumps(log.bundle(filter=lambda r: r["seq"] % 2 == 0)))
    assert b["partial"] and len(b["entries"]) == 4
    assert verify_bundle(b)["ok"]


def test_a_checkpoint_of_the_empty_log_is_not_a_rewrite(log):
    log.checkpoint()
    fill(log, 2)
    log.checkpoint()
    assert verify_bundle(json.loads(json.dumps(log.bundle())))["ok"]


def test_witnesses_count_only_when_pinned(log):
    fill(log, 4)
    cp = log.checkpoint()
    witness, _ = generate_identity()
    log.trust_key(witness.kid, witness.public_key)
    sig = next(s for s in cosign(cp, witness)["sigs"] if s["role"] == "witness")
    log.add_signature(cp["body"]["size"], sig)
    b = json.loads(json.dumps(log.bundle()))

    assert not verify_bundle(b, min_witnesses=1)["ok"], "a bundle's own keyring cannot vouch for its witness"
    assert verify_bundle(b, min_witnesses=1, trusted_witnesses={witness.kid: witness.public_key})["ok"]
    impostor, _ = generate_identity()
    assert not verify_bundle(b, min_witnesses=1, trusted_witnesses={impostor.kid: impostor.public_key})["ok"]


def test_shredding_makes_payloads_unprovable_and_the_log_still_verifies(log):
    fill(log, 3)
    assert log.shred(lambda r: r["seq"] == 1) == 1
    assert not log.reveal(1, "params", {"order": "ord_1", "card": "4242 4242 4242 4242"})
    assert log.reveal(0, "params", {"order": "ord_0", "card": "4242 4242 4242 4242"})
    assert ProofLog.open(log.dir).audit()["ok"]


def test_a_receipt_resigned_by_another_key_is_caught_by_its_signature(log):
    # The tip, and no checkpoint: nothing after it to break the chain, no
    # signed root to contradict. Only the signature check can catch this.
    from proof_wire import receipt_digest, sign

    fill(log, 3)
    p = log.dir / "entries.jsonl"
    lines = p.read_bytes().decode().split("\n")
    last = json.loads(lines[2])
    impostor, _ = generate_identity()
    last["attest"]["sig"] = sign(impostor, receipt_digest(last))  # a valid signature, by the wrong key
    lines[2] = json.dumps(last)
    p.write_bytes("\n".join(lines).encode())
    issues = ProofLog.open(log.dir).audit()["issues"]
    assert [i["kind"] for i in issues] == ["signature"], issues


def test_a_validly_signed_receipt_that_was_never_logged_fails_its_inclusion_proof(log):
    # Signed by the log's own key, so the signature passes; slipped into a
    # filtered bundle with a real entry's proof. Only inclusion can catch it.
    from proof_wire import build_receipt, sign_receipt

    fill(log, 4)
    b = json.loads(json.dumps(log.bundle(filter=lambda r: r["seq"] == 1)))
    body, _ = build_receipt(
        log=log.log_id, seq=1, prev=log.entries[1]["prev"],
        actor={"agent": "claude", "runtime": "test", "session": "s1", "principal": "ops@acme.test"},
        action={"kind": "tool_call", "target": "crm.refund", "params": {"order": "never-happened"}},
        decision={"outcome": "allow", "policy": "p1", "rules": []},
    )
    b["entries"][0]["receipt"] = sign_receipt(log.identity, body)
    res = verify_bundle(b)
    assert not res["ok"]
    assert any("not provably part of the logged tree" in i for i in res["issues"]), res["issues"]


def test_a_malformed_bundle_fails_verification_rather_than_crashing():
    for junk in (None, [], {"kind": "proofwire.bundle", "v": 1, "root": "zz"}, {"kind": "proofwire.bundle", "v": 1, "root": "00" * 32, "entries": [{"receipt": 5}], "treeSize": 1}):
        assert verify_bundle(junk)["ok"] is False
