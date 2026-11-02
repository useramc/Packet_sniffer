"""
Auth configuration.

PPS-SR-004: no credentials or secrets shall be hardcoded in source code.
JWT_SECRET must come from the environment. We deliberately fail loudly at
startup rather than falling back to a baked-in default, so a missing
secret is caught in dev/CI instead of silently shipping an insecure default.
"""
import os
import sys

JWT_SECRET = os.environ.get("PPS_JWT_SECRET")
JWT_ALGORITHM = "HS256"
JWT_EXPIRY_MINUTES = int(os.environ.get("PPS_JWT_EXPIRY_MINUTES", "60"))
DB_PATH = os.environ.get("PPS_AUTH_DB", "pps_auth.db")

# Only enforce the hard-fail outside of pytest, so `pytest` can inject a
# throwaway secret per-test via monkeypatch/env without needing a real one
# exported in every dev shell.
if not JWT_SECRET and "pytest" not in sys.modules:
    raise RuntimeError(
        "PPS_JWT_SECRET environment variable is not set. "
        "Set it before starting the server, e.g.:\n"
        "  export PPS_JWT_SECRET=$(python -c 'import secrets; print(secrets.token_hex(32))')\n"
        "Never hardcode this value (see PPS-SR-004)."
    )
