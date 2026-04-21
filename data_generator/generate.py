"""
data_generator/generate.py
Faker-based synthetic Indian banking profile generator.
Seeds Bank A (customer accounts) and Bank B (fraud blacklist) databases.

Usage:
    python -m data_generator.generate             # default from seed_config.json
    python -m data_generator.generate --overlap 750
    python -m data_generator.generate --reset
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import json, random, argparse
from faker import Faker

import bank_a.db_manager as db_a
import bank_b.db_manager as db_b
from psi_core.data_normalizer import normalize

# ─── Config ───────────────────────────────────────────────────────────────────

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "seed_config.json")
with open(CONFIG_PATH) as f:
    CONFIG = json.load(f)

FRAUD_REASONS = [
    ("MONEY_LAUNDERING",   "HIGH",     "Suspicious high-value transaction patterns indicative of layering"),
    ("IDENTITY_THEFT",     "HIGH",     "Account opened with stolen credentials from a data breach"),
    ("CHARGEBACK_FRAUD",   "MEDIUM",   "Excessive chargeback-to-transaction ratio over 90 days"),
    ("PHISHING_OPERATOR",  "HIGH",     "Phone number associated with active phishing campaign"),
    ("SYNTHETIC_IDENTITY", "CRITICAL", "Identity created from fabricated PII — no matching KYC"),
    ("ACCOUNT_TAKEOVER",   "HIGH",     "Unauthorized SIM-swap followed by bulk transfer activity"),
    ("LOAN_DEFAULT",       "MEDIUM",   "Defaulted on multiple institutional loans, NPA classification"),
    ("MULE_ACCOUNT",       "HIGH",     "Account used as fund funnel in multi-hop fraud network"),
    ("MONEY_LAUNDERING",   "CRITICAL", "Cross-border structuring to evade reporting thresholds"),
]


# ─── Identity Generators ──────────────────────────────────────────────────────

def make_email(fake: Faker, rng: random.Random) -> tuple:
    """Returns (raw_identifier, normalized_value)"""
    raw = fake.email()
    return raw, normalize(raw, "email")


def make_phone(fake: Faker, rng: random.Random) -> tuple:
    digits = "".join(str(rng.randint(0, 9)) for _ in range(10))
    # Ensure starts with 6-9 (Indian mobile)
    digits = str(rng.randint(6, 9)) + digits[1:]
    raw = f"+91 {digits[:5]} {digits[5:]}"
    return raw, normalize(raw, "phone")


def make_account_number(fake: Faker, rng: random.Random) -> tuple:
    prefix = rng.choice(["BNKA", "BNKB", "HDFC", "ICIC", "AXIS"])
    number = "".join(str(rng.randint(0, 9)) for _ in range(12))
    raw = f"{prefix}{number}"
    return raw, normalize(raw, "account_number")


def make_aadhaar(fake: Faker, rng: random.Random) -> tuple:
    digits = "".join(str(rng.randint(0, 9)) for _ in range(12))
    raw = f"{digits[:4]}-{digits[4:8]}-{digits[8:]}"
    return raw, normalize(raw, "aadhaar")


ID_GENERATORS = {
    "email":          make_email,
    "phone":          make_phone,
    "account_number": make_account_number,
    "aadhaar":        make_aadhaar,
}


def _pick_type(mix: dict, rng: random.Random) -> str:
    r = rng.random()
    cumulative = 0.0
    for typ, prob in mix.items():
        cumulative += prob
        if r < cumulative:
            return typ
    return list(mix.keys())[-1]


def _pick_severity(dist: dict, rng: random.Random) -> str:
    r = rng.random()
    cumulative = 0.0
    for sev, prob in dist.items():
        cumulative += prob
        if r < cumulative:
            return sev
    return "MEDIUM"


# ─── Main Generator ────────────────────────────────────────────────────────────

def generate(overlap_override: int = None, reset: bool = False):
    seed         = CONFIG["seed"]
    total_a      = CONFIG["bank_a_total_accounts"]
    total_b      = CONFIG["bank_b_blacklist_size"]
    overlap      = overlap_override if overlap_override is not None else CONFIG["overlap_count"]
    id_mix       = CONFIG["identifier_mix"]
    sev_dist     = CONFIG["severity_distribution"]

    # Ensure overlap doesn't exceed either set
    overlap = min(overlap, total_a, total_b)

    rng  = random.Random(seed)
    fake = Faker("en_IN")
    Faker.seed(seed)

    print(f"\n{'='*60}")
    print(f"PSI Platform V2 - Synthetic Data Generator")
    print(f"  Seed:          {seed}")
    print(f"  Bank A total:  {total_a}")
    print(f"  Bank B total:  {total_b}")
    print(f"  Overlap:       {overlap}")
    print(f"{'='*60}\n")

    # Init databases
    db_a.init_db()
    db_b.init_db()

    if reset:
        # Wipe and recreate tables
        import sqlite3, config as cfg
        for db_path in [cfg.BANK_A_DB_PATH, cfg.BANK_B_DB_PATH]:
            if os.path.exists(db_path):
                conn = sqlite3.connect(db_path)
                conn.execute("DELETE FROM accounts")
                conn.execute("DELETE FROM psi_runs")
                conn.execute("DELETE FROM psi_matches")
                conn.commit()
                conn.close()
        import sqlite3, config as cfg
        if os.path.exists(cfg.BANK_B_DB_PATH):
            conn = sqlite3.connect(cfg.BANK_B_DB_PATH)
            conn.execute("DELETE FROM blacklist")
            conn.execute("DELETE FROM psi_responses")
            conn.commit()
            conn.close()
        print("[Generator] Databases wiped. Regenerating...")

    # ── Generate overlap entries (appear in BOTH databases) ──────────────────
    print(f"[1/3] Generating {overlap} overlap identifiers...")
    overlap_entries = []  # list of (raw, normalized, identifier_type)
    seen_normalized = set()

    while len(overlap_entries) < overlap:
        typ = _pick_type(id_mix, rng)
        raw, norm = ID_GENERATORS[typ](fake, rng)
        if norm in seen_normalized:
            continue
        seen_normalized.add(norm)
        overlap_entries.append((raw, norm, typ))

    # ── Generate Bank A's remaining unique accounts ──────────────────────────
    print(f"[2/3] Generating {total_a - overlap} unique Bank A accounts...")
    bank_a_only = []
    while len(bank_a_only) < total_a - overlap:
        typ = _pick_type(id_mix, rng)
        raw, norm = ID_GENERATORS[typ](fake, rng)
        if norm in seen_normalized:
            continue
        seen_normalized.add(norm)
        bank_a_only.append((raw, norm, typ))

    # ── Generate Bank B's remaining unique blacklist entries ─────────────────
    print(f"[3/3] Generating {total_b - overlap} unique Bank B blacklist entries...")
    bank_b_only = []
    while len(bank_b_only) < total_b - overlap:
        typ = _pick_type(id_mix, rng)
        raw, norm = ID_GENERATORS[typ](fake, rng)
        if norm in seen_normalized:
            continue
        seen_normalized.add(norm)
        bank_b_only.append((raw, norm, typ))

    # ── Write to Bank A DB ────────────────────────────────────────────────────
    a_total_inserted = 0
    # Shuffle order so overlaps aren't all at the beginning for UI realism
    all_a = overlap_entries + bank_a_only
    rng.shuffle(all_a)
    for raw, norm, typ in all_a:
        db_a.insert_account(raw, typ, norm, label=f"Account {a_total_inserted+1}")
        a_total_inserted += 1

    # ── Write to Bank B DB ────────────────────────────────────────────────────
    b_total_inserted = 0
    all_b = list(overlap_entries) + bank_b_only
    rng.shuffle(all_b)
    for raw, norm, typ in all_b:
        sev = _pick_severity(sev_dist, rng)
        reason_code, _, reason_text = rng.choice(FRAUD_REASONS)
        # Override severity from reason table if CRITICAL
        if reason_code in ("SYNTHETIC_IDENTITY", "MONEY_LAUNDERING") and rng.random() < 0.3:
            sev = "CRITICAL"
        db_b.add_blacklist_entry(
            raw_identifier=raw,
            identifier_type=typ,
            normalized_value=norm,
            reason=f"{reason_code} — {reason_text}",
            severity=sev,
            reported_by=rng.choice(["Compliance", "Risk Team", "External Intelligence", "RegTech API"]),
        )
        b_total_inserted += 1

    print(f"\n{'='*60}")
    print(f"[DONE] Generation Complete!")
    print(f"  Bank A accounts inserted:  {a_total_inserted}")
    print(f"  Bank B blacklist inserted: {b_total_inserted}")
    print(f"  Known overlapping entries: {overlap}")
    print(f"  Expected PSI matches:      {overlap} (after successful batch run)")
    print(f"\n  >> Open http://127.0.0.1:5001 to run a PSI Check")
    print(f"{'='*60}\n")


# ─── CLI ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PSI Platform V2 — Synthetic Data Generator")
    parser.add_argument("--overlap", type=int, default=None, help="Override overlap count")
    parser.add_argument("--reset",   action="store_true",    help="Wipe existing data before generating")
    args = parser.parse_args()
    generate(overlap_override=args.overlap, reset=args.reset)
