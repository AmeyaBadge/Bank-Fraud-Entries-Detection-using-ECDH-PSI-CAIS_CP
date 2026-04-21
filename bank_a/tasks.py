"""
bank_a/tasks.py
Celery task definitions — async PSI batch run for Bank A.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import uuid
import time
import requests
from celery import Celery
from celery.utils.log import get_task_logger

import config
from psi_core.ecdh_engine import PSIQuerier
from psi_core.data_normalizer import normalize
from psi_core.crypto_utils import decrypt_label
import bank_a.db_manager as db

logger = get_task_logger(__name__)

# ─── Celery App ───────────────────────────────────────────────────────────────

celery_app = Celery(
    "bank_a_tasks",
    broker=config.CELERY_BROKER_URL,
    backend=config.CELERY_RESULT_BACKEND,
)
celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    task_track_started=True,
    worker_prefetch_multiplier=1,
)


# ─── Helper: update coordinator session status ────────────────────────────────

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
        logger.warning(f"Could not update coordinator: {e}")


# ─── Main Batch PSI Task ──────────────────────────────────────────────────────

@celery_app.task(bind=True, name="bank_a.tasks.task_run_psi_batch")
def task_run_psi_batch(self, run_id: str, session_id: str):
    """
    Full ECDH-PSI batch run. Progress stages:
    0%   — Fetching accounts
    20%  — Encrypting with ECDH
    50%  — Exchanging with Bank B
    75%  — Computing intersection
    100% — Done
    """
    start_time = time.time()

    def progress(pct, msg):
        self.update_state(state="PROGRESS", meta={"progress": pct, "message": msg})

    try:
        # ── Stage 1: Fetch accounts ────────────────────────────────────────
        progress(0, "Fetching accounts from database...")
        db.update_psi_run(run_id, "running")
        _patch_coordinator(session_id, "running")

        accounts = db.get_all_accounts()
        if not accounts:
            db.update_psi_run(run_id, "failed")
            _patch_coordinator(session_id, "failed")
            return {"status": "FAILED", "error": "No accounts in database"}

        progress(10, f"Normalizing {len(accounts)} identifiers...")

        # ── Stage 2: Normalize ─────────────────────────────────────────────
        normalized_list = []
        account_map = {}  # normalized_value → account_id
        for acc in accounts:
            try:
                norm = normalize(acc["raw_identifier"], acc["identifier_type"])
                normalized_list.append(norm)
                account_map[norm] = acc["id"]
            except Exception:
                pass  # skip malformed entries silently

        db.update_psi_run(run_id, "running", items_checked=len(normalized_list))

        progress(20, "Encrypting set with ECDH (NIST P-256)...")

        # ── Stage 3: Encrypt Bank A's set ──────────────────────────────────
        querier = PSIQuerier()
        encrypted_a = querier.encrypt_set(normalized_list)
        # Convert bytes to str for JSON serialization
        encrypted_a_str = [
            pt.decode("utf-8") if isinstance(pt, bytes) else pt
            for pt in encrypted_a
        ]

        progress(50, "Exchanging encrypted sets with Bank B...")

        # ── Stage 4: Send to Bank B ─────────────────────────────────────────
        payload = {
            "querier_bank": "bank_a",
            "session_id": session_id,
            "encrypted_set": encrypted_a_str,
        }
        try:
            resp = requests.post(
                f"{config.BANK_B_URL}/api/psi/exchange",
                json=payload,
                headers={"X-PSI-API-Key": config.PSI_API_KEY},
                timeout=120,
            )
            resp.raise_for_status()
        except Exception as e:
            logger.error(f"Bank B exchange failed: {e}")
            db.update_psi_run(run_id, "failed")
            _patch_coordinator(session_id, "failed")
            return {"status": "FAILED", "error": f"Bank B unreachable: {e}"}

        b_data = resp.json()
        double_enc_query    = b_data["double_encrypted_query"]    # (P(X)*a)*b — Bank A's set
        encrypted_blacklist = b_data["encrypted_blacklist"]        # P(Y)*b — Bank B's blacklist
        encrypted_labels    = b_data.get("encrypted_labels", {})  # {encrypted_point_str: {severity, reason}}

        progress(75, "Computing intersection, writing results...")

        # ── Stage 5: Double-encrypt Bank B's blacklist and find intersection ─
        double_enc_blacklist = querier.double_encrypt_remote(encrypted_blacklist)
        double_enc_bl_str = [
            pt.decode("utf-8") if isinstance(pt, bytes) else pt
            for pt in double_enc_blacklist
        ]

        # Also need (P(X)*a)*b — already received from Bank B
        matched_normalized = querier.find_intersection(
            double_enc_query,
            double_enc_bl_str,
            normalized_list,
        )

        # ── Write matches to DB ──────────────────────────────────────────────
        # Build label lookup: encrypted_blacklist_point → {severity, reason}
        label_lookup = {}
        for enc_pt, label_data in encrypted_labels.items():
            try:
                severity = decrypt_label(label_data["severity"], config.LABEL_ENCRYPTION_KEY)
                reason   = decrypt_label(label_data["reason"],   config.LABEL_ENCRYPTION_KEY)
                label_lookup[enc_pt] = {"severity": severity, "reason": reason}
            except Exception:
                label_lookup[enc_pt] = {"severity": "UNKNOWN", "reason": "Decryption failed"}

        # Map double-enc blacklist point → label
        double_to_label = {}
        for enc_pt, double_pt_bytes in zip(encrypted_blacklist, double_enc_blacklist):
            double_key = double_pt_bytes.decode("utf-8") if isinstance(double_pt_bytes, bytes) else double_pt_bytes
            if enc_pt in label_lookup:
                double_to_label[double_key] = label_lookup[enc_pt]

        # Build set of matched double-encrypted points for quick lookup
        matched_double_set = set(
            pt.decode("utf-8") if isinstance(pt, bytes) else pt
            for pt in double_enc_blacklist
            if (pt.decode("utf-8") if isinstance(pt, bytes) else pt) in set(
                pt2.decode("utf-8") if isinstance(pt2, bytes) else pt2
                for pt2 in [x for x in double_enc_query]
            )
        )

        for norm_val in matched_normalized:
            account_id = account_map.get(norm_val)
            if account_id is None:
                continue
            # Find matching label by looking up double-encrypted point
            sev, rsn = "UNKNOWN", "No reason provided"
            for enc_bl, dbl in zip(encrypted_blacklist, double_enc_blacklist):
                dbl_str = dbl.decode("utf-8") if isinstance(dbl, bytes) else dbl
                if dbl_str in (pt.decode("utf-8") if isinstance(pt, bytes) else pt for pt in double_enc_query
                               if (pt.decode("utf-8") if isinstance(pt, bytes) else pt) == dbl_str):
                    if enc_bl in label_lookup:
                        sev = label_lookup[enc_bl]["severity"]
                        rsn = label_lookup[enc_bl]["reason"]
                    break
            db.insert_psi_match(run_id, account_id, sev, rsn)

        matches_found = len(matched_normalized)
        elapsed = round(time.time() - start_time, 2)

        db.update_psi_run(run_id, "completed", matches_found=matches_found)
        _patch_coordinator(session_id, "completed", matches_found=matches_found)

        return {
            "status": "SUCCESS",
            "run_id": run_id,
            "matches_found": matches_found,
            "items_checked": len(normalized_list),
            "duration_seconds": elapsed,
        }

    except Exception as e:
        logger.exception(f"PSI batch task error: {e}")
        db.update_psi_run(run_id, "failed")
        _patch_coordinator(session_id, "failed")
        raise
