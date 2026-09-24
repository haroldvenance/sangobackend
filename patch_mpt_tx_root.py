python3 - <<'PY'
from pathlib import Path
P = Path("crates/sango-wallet/src/main.rs")
src = P.read_text()
old = "use sango_wallet::cli::{parse_args, parse_flags, require_flag, HELP};"
new = "use sango_wallet::cli::{optional_flag, parse_args, parse_flags, require_flag, HELP};"
if old in src:
    src = src.replace(old, new, 1)
    P.write_text(src)
    print("✓ main.rs : optional_flag importé")
elif "optional_flag" in src.split("\n\n")[0]:
    print("· déjà importé")
else:
    print("⚠ motif introuvable")
PY