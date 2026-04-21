"""
bank_a/tasks.py
Pure-Python PSI batch runner — no Celery, no Redis required.
Runs inside a threading.Thread; progress is tracked via a shared dict.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import time
import traceback
import requests

import config
from psi_core.ecdh_engine import PSIQuerier
from psi_core.data_normalizer import normalize
from psi_core.crypto_utils import decrypt_label
import bank_a.db_manager as db


# ─── Coordinator helper ───────────────────────────────────────────────────────

def _patch_coordinator(session_id: str, status: str, matches_found: int = None):
    try:
        payload = {"status": status}
        if matches_found is not None:
            payload["matches_found"] = matches_found
        requests.patch(
            f"{config.COORDINATOR_URL}/api/sessions/{session_id}",
            json=payload,
            headers={"x-api-key": config.COORDINATOR_API_KEY},
            timeout=10,
        )
    except Exception as e:
        print(f"[Bank A] Could not update coordinator: {e}")


# ─── Main PSI batch function ──────────────────────────────────────────────────

def run_psi_batch(tracker: dict, run_id: str, session_id: str):
    """
    Full ECDH-PSI batch run executed in a background thread.
    Updates `tracker` dict in-place with progress info.

    tracker keys:  state, progress, message, result
    """

    def progress(pct: int, msg: str):
        tracker["state"]    = "PROGRESS"
        tracker["progress"] = pct
        tracker["message"]  = msg
        print(f"[PSI Run {run_id[:8]}] {pct}% — {msg}")

    start_time = time.time()

    try:
        # ── Stage 1: Fetch accounts ────────────────────────────────────────
        progress(0, "Fetching accounts from database...")
        db.update_psi_run(run_id, "running")
        _patch_coordinator(session_id, "running")

        accounts = db.get_all_accounts()
        if not accounts:
            tracker.update(state="FAILURE", progress=0, message="No accounts in database")
            db.update_psi_run(run_id, "failed")
            _patch_coordinator(session_id, "failed")
            return

        # ── Stage 2: Normalize ─────────────────────────────────────────────
        progress(10, f"Normalizing {len(accounts)} identifiers...")
        normalized_list = []
        account_map = {}          # normalized_value → account row id
        for acc in accounts:
            try:
                norm = normalize(acc["raw_identifier"], acc["identifier_type"])
                normalized_list.append(norm)
                account_map[norm] = acc["id"]
            except Exception:
                pass              # skip malformed entries silently

        db.update_psi_run(run_id, "running", items_checked=len(normalized_list))

        # ── Stage 3: Encrypt Bank A's set with ECDH ────────────────────────
        progress(20, f"Encrypting {len(normalized_list)} items with ECDH (NIST P-256)...")
        querier = PSIQuerier()
        encrypted_a = querier.encrypt_set(normalized_list)
        encrypted_a_str = [
            pt.decode("utf-8") if isinstance(pt, bytes) else pt
            for pt in encrypted_a
        ]

        # ── Stage 4: Exchange with Bank B ──────────────────────────────────
        progress(50, "Exchanging encrypted sets with Bank B...")
        try:
            resp = requests.post(
                f"{config.BANK_B_URL}/api/psi/exchange",
                json={
                    "querier_bank":  "bank_a",
                    "session_id":    session_id,
                    "encrypted_set": encrypted_a_str,
                },
                headers={"X-PSI-API-Key": config.PSI_API_KEY},
                timeout=300,          # P-256 over 10k items can take a minute
            )
            resp.raise_for_status()
        except Exception as e:
            msg = f"Bank B unreachable: {e}"
            print(f"[PSI Run {run_id[:8]}] ERROR — {msg}")
            tracker.update(state="FAILURE", progress=50, message=msg)
            db.update_psi_run(run_id, "failed")
            _patch_coordinator(session_id, "failed")
            return

        b_data              = resp.json()
        double_enc_query    = b_data["double_encrypted_query"]    # list[str]  (P(X)*a)*b
        encrypted_blacklist = b_data["encrypted_blacklist"]        # list[str]  P(Y)*b
        encrypted_labels    = b_data.get("encrypted_labels", {})  # {enc_str: {severity, reason}}

        # ── Stage 5: Double-encrypt Bank B's list and compute intersection ──
        progress(75, "Computing intersection...")
        double_enc_blacklist = querier.double_encrypt_remote(encrypted_blacklist)
        double_enc_bl_str = [
            pt.decode("utf-8") if isinstance(pt, bytes) else pt
            for pt in double_enc_blacklist
        ]

        matched_normalized = querier.find_intersection(
            double_enc_query,
            double_enc_bl_str,
            normalized_list,
        )

        # ── Build label lookup ─────────────────────────────────────────────
        label_lookup = {}
        for enc_pt, label_data in encrypted_labels.items():
            try:
                severity = decrypt_label(label_data["severity"], config.LABEL_ENCRYPTION_KEY)
                reason   = decrypt_label(label_data["reason"],   config.LABEL_ENCRYPTION_KEY)
                label_lookup[enc_pt] = {"severity": severity, "reason": reason}
            except Exception:
                label_lookup[enc_pt] = {"severity": "UNKNOWN", "reason": "Decryption failed"}

        # Build map: double-encrypted blacklist point str → label
        double_to_label = {}
        for enc_pt, dbl_pt in zip(encrypted_blacklist, double_enc_bl_str):
            if enc_pt in label_lookup:
                double_to_label[dbl_pt] = label_lookup[enc_pt]

        # Build the set of double-enc-query strings for O(1) lookup
        double_query_set = set(
            pt.decode("utf-8") if isinstance(pt, bytes) else pt
            for pt in double_enc_query
        )

        # ── Write matches to DB ────────────────────────────────────────────
        progress(90, f"Writing {len(matched_normalized)} matches to database...")
        for norm_val in matched_normalized:
            account_id = account_map.get(norm_val)
            if account_id is None:
                continue
            # Find the label for this matched point (if available)
            sev, rsn = "UNKNOWN", "No reason provided"
            for dbl_str, lbl in double_to_label.items():
                if dbl_str in double_query_set:
                    sev = lbl.get("severity", "UNKNOWN")
                    rsn = lbl.get("reason",   "No reason provided")
                    break
            db.insert_psi_match(run_id, account_id, sev, rsn)

        matches_found = len(matched_normalized)
        elapsed       = round(time.time() - start_time, 2)

        db.update_psi_run(run_id, "completed", matches_found=matches_found)
        _patch_coordinator(session_id, "completed", matches_found=matches_found)

        tracker.update(
            state    = "SUCCESS",
            progress = 100,
            message  = f"Completed in {elapsed}s",
            result   = {
                "status":           "SUCCESS",
                "run_id":           run_id,
                "matches_found":    matches_found,
                "items_checked":    len(normalized_list),
                "duration_seconds": elapsed,
            },
        )
        print(f"[PSI Run {run_id[:8]}] DONE — {matches_found} matches in {elapsed}s")

    except Exception as e:
        traceback.print_exc()
        tracker.update(state="FAILURE", progress=0, message=str(e))
        db.update_psi_run(run_id, "failed")
        _patch_coordinator(session_id, "failed")
