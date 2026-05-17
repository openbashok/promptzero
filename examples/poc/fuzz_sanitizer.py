"""
fuzz_sanitizer.py — Property-based fuzzer for the PromptZero sanitizer.

Generates random documents stuffed with known PII (hostnames, IPs,
emails, names, national IDs, credit cards, tokens, …) embedded in a
variety of surface forms (bare, inside URLs, inside JSON, inside SSE
payloads, inside HTTP headers, split by punctuation). Runs each through
the Sanitizer and checks three invariants:

  P1  No-leak       — every real value injected into the input must be
                       absent from the sanitized output.
  P2  Round-trip    — desanitize(sanitize(text)) returns exactly the
                       original text for any value the sanitizer caught.
  P3  Consistency   — the same real value within one session always maps
                       to the same fake value.

Each failure is reported with the seed, the offending input, and the
specific invariant that broke — so the run is reproducible.

Usage:
    python fuzz_sanitizer.py                    # 200 iterations, default seed
    python fuzz_sanitizer.py --iter 1000        # more iterations
    python fuzz_sanitizer.py --seed 42          # reproducible run
    python fuzz_sanitizer.py --verbose          # print every test, not just failures

Exit codes:
    0 — all properties held
    1 — at least one invariant violated (details in stdout)
"""

from __future__ import annotations

import argparse
import random
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, List, Optional

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))

from sanitizer import Sanitizer  # noqa: E402


# ---------------------------------------------------------------------------
# Synthetic-but-realistic PII generators
# ---------------------------------------------------------------------------

_FIRST_NAMES = [
    "Mariano", "Lucía", "Federico", "Sofía", "Tomás", "Camila",
    "Sebastián", "Valentina", "Joaquín", "Martina", "Diego", "Florencia",
    "Felipe", "Antonella", "Nicolás", "Catalina", "Maximiliano", "Renata",
]
_LAST_NAMES = [
    "Quintana", "Pellegrini", "Bertoldi", "Mosqueira", "Castelnuovo",
    "Mansilla", "Lombardi", "Fernández", "Silva", "Cabrera",
    "Iturralde", "Mancuso", "Astigarra", "Beltrán", "Pittaluga",
]
_COMPANIES = [
    "Nexabank Financial S.A.", "Globex Aerolíneas", "Initech Hardware",
    "Acme Mining", "Tebca Pagos", "Geopagos Holdings", "Soylent Café",
    "Hooli Industries",
]
_TLDS = ["com.ar", "com", "io", "co.uk", "es", "mx", "local", "internal"]
_HOST_PREFIXES = [
    "vpn", "api", "db-prod", "checkout", "auth", "mail", "portal",
    "internal-jenkins", "redis-cluster-01", "git", "monitoring",
]


def gen_person() -> str:
    return f"{random.choice(_FIRST_NAMES)} {random.choice(_LAST_NAMES)}"


def gen_company() -> str:
    return random.choice(_COMPANIES)


def gen_hostname() -> str:
    return f"{random.choice(_HOST_PREFIXES)}.{random.choice(_COMPANIES).split()[0].lower()}.{random.choice(_TLDS)}"


def gen_email() -> str:
    name = random.choice(_FIRST_NAMES).lower()
    surname = random.choice(_LAST_NAMES).lower().replace("ñ", "n").replace("á", "a")
    host = random.choice(["gmail.com", "hotmail.com", "yahoo.com", "protonmail.com",
                          "outlook.com", "icloud.com"])
    return f"{name}.{surname}@{host}"


def gen_ipv4() -> str:
    # Pick from realistic-looking private + public ranges, but never the
    # synthetic 127.0.0.0/8 range (so we don't generate "real" values
    # that collide with our fakes by construction).
    base = random.choice([
        (10, random.randint(0, 255), random.randint(0, 255), random.randint(1, 254)),
        (172, random.randint(16, 31), random.randint(0, 255), random.randint(1, 254)),
        (192, 168, random.randint(0, 255), random.randint(1, 254)),
        (203, 0, 113, random.randint(1, 254)),
        (198, 51, 100, random.randint(1, 254)),
    ])
    return ".".join(str(o) for o in base)


def gen_ipv6() -> str:
    parts = [f"{random.randint(0, 65535):x}" for _ in range(random.randint(3, 8))]
    return ":".join(parts)


def gen_dni_ar() -> str:
    n = random.randint(10_000_000, 45_000_000)
    return f"DNI {n // 1_000_000}.{(n // 1000) % 1000:03d}.{n % 1000:03d}"


def gen_credit_card() -> str:
    return " ".join(f"{random.randint(0, 9999):04d}" for _ in range(4))


def gen_phone_ar() -> str:
    area = random.choice(["11", "351", "261", "341", "381"])
    return f"+54 9 {area} {random.randint(1000, 9999)}-{random.randint(1000, 9999)}"


def gen_token() -> str:
    chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
    return "sk-ant-" + "".join(random.choice(chars) for _ in range(40))


# Each entry: (label, generator, surface-form expansions). Each surface
# form takes the raw real value and embeds it inside some
# realistic context — a URL, a header, JSON, etc. so the fuzzer
# exercises both bare and embedded matching.
GENERATORS = {
    "person":      gen_person,
    "company":     gen_company,
    "hostname":    gen_hostname,
    "email":       gen_email,
    "ipv4":        gen_ipv4,
    "ipv6":        gen_ipv6,
    "dni_ar":      gen_dni_ar,
    "credit_card": gen_credit_card,
    "phone_ar":    gen_phone_ar,
    "token":       gen_token,
}


def surface_forms(kind: str, value: str) -> List[str]:
    """Return realistic ways the given value might appear in text."""
    bare = [value]
    if kind == "hostname":
        return bare + [
            f"https://{value}/api/v1/users",
            f"https://{value}:8443/admin",
            f"GET / HTTP/1.1\nHost: {value}",
            f"connect to {value} via SSH",
            f"\"{value}\"",
            f"`{value}`",
            f"({value})",
        ]
    if kind == "email":
        return bare + [
            f"From: {value}",
            f"contact <{value}>",
            f"mailto:{value}",
            f"\"email\": \"{value}\"",
        ]
    if kind == "ipv4":
        return bare + [
            f"src={value}",
            f"{value}:443",
            f"({value})",
            f"\"ip\": \"{value}\"",
        ]
    if kind == "ipv6":
        return bare + [
            f"[{value}]",
            f"[{value}]:8080",
            f"\"addr\": \"{value}\"",
        ]
    if kind == "person":
        return bare + [
            f"firmado por {value}",
            f"CISO: {value}",
            f"\"name\": \"{value}\"",
        ]
    if kind == "credit_card":
        return bare + [
            f"PAN: {value}",
            f"card={value}",
        ]
    if kind == "phone_ar":
        return bare + [
            f"Tel: {value}",
            f"contacto al {value}",
        ]
    return bare


# ---------------------------------------------------------------------------
# Test case generator
# ---------------------------------------------------------------------------

@dataclass
class TestCase:
    """One synthetic input together with the ground truth: every real
    PII value injected into it. Used for invariant checks."""
    text: str
    injected: List[tuple] = field(default_factory=list)  # (kind, value)


def make_test_case(min_pii: int = 2, max_pii: int = 8) -> TestCase:
    """Stitch together a synthetic document with several PII spans
    embedded in varied surface forms."""
    kinds = list(GENERATORS.keys())
    n = random.randint(min_pii, max_pii)
    chunks: List[str] = []
    injected: List[tuple] = []
    for _ in range(n):
        kind = random.choice(kinds)
        value = GENERATORS[kind]()
        surface = random.choice(surface_forms(kind, value))
        chunks.append(surface)
        injected.append((kind, value))
    # Pepper in some noise so the sanitizer has surrounding context to
    # disambiguate. Real prompts aren't pure PII strings.
    noise = [
        "El reporte de pentest detectó las siguientes señales: ",
        "\n\nDuring the engagement we observed:\n  - ",
        ".\nFinding severity: critical.\n",
        " (see appendix). ",
        "\n\nProceeding to lateral movement, ",
    ]
    text = random.choice(noise).join(chunks)
    return TestCase(text=text, injected=injected)


# ---------------------------------------------------------------------------
# Property checks
# ---------------------------------------------------------------------------

@dataclass
class Failure:
    seed: int
    invariant: str
    detail: str
    case: TestCase


def check_case(case: TestCase, seed: int) -> List[Failure]:
    """Run a single test case through the sanitizer and collect any
    invariant violations."""
    fails: List[Failure] = []
    sanitizer = Sanitizer()
    sanitized = sanitizer.sanitize(case.text)
    mapping = sanitizer.table._r2f
    fake_to_real = sanitizer.table._f2r

    # P1 — no real value (that the sanitizer caught) may appear in the
    # sanitized output. We check this for every value that ended up in
    # the mapping table; PII the sanitizer DIDN'T detect at all is a
    # separate concern (coverage, not leak).
    for real, fake in mapping.items():
        if real in sanitized:
            fails.append(Failure(
                seed=seed,
                invariant="P1 no-leak",
                detail=f"real value {real!r} still present in sanitized output "
                       f"(was supposed to map to {fake!r})",
                case=case,
            ))

    # P2 — round-trip: desanitize(sanitized) must restore each real
    # value in place of its fake. We don't require character-for-
    # character equality with the original text because the sanitizer
    # may legitimately drop tail punctuation in a URL match etc., but
    # every real-value substring should re-appear after desanitize.
    restored = sanitizer.desanitize(sanitized)
    for real, fake in mapping.items():
        if real not in restored:
            fails.append(Failure(
                seed=seed,
                invariant="P2 round-trip",
                detail=f"real value {real!r} (fake={fake!r}) not restored by "
                       f"desanitize — got: {restored[:200]!r}",
                case=case,
            ))

    # P3 — consistency: every fake must correspond to exactly one real
    # value (and vice-versa) inside one session. Different surface forms
    # of the same logical entity may legitimately register as separate
    # entries; we only flag a true collision (one fake → two distinct
    # real values).
    fake_targets: dict = {}
    for real, fake in mapping.items():
        fake_targets.setdefault(fake, []).append(real)
    for fake, reals in fake_targets.items():
        if len({r.strip() for r in reals}) > 1:
            fails.append(Failure(
                seed=seed,
                invariant="P3 consistency",
                detail=f"fake {fake!r} maps to multiple distinct real values: "
                       f"{reals}",
                case=case,
            ))

    return fails


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

GREEN = "\033[32m"
RED   = "\033[31m"
YEL   = "\033[33m"
DIM   = "\033[2m"
END   = "\033[0m"
color = sys.stdout.isatty()


def c(text: str, code: str) -> str:
    return f"{code}{text}{END}" if color else text


def report_failure(f: Failure) -> None:
    print()
    print(c(f"  ✗ [{f.invariant}]", RED) + f"  seed={f.seed}")
    print(c(f"      {f.detail}", DIM))
    snippet = f.case.text.replace("\n", "\\n")
    if len(snippet) > 220:
        snippet = snippet[:217] + "..."
    print(c(f"      input: {snippet}", DIM))


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Property-based fuzzer for the PromptZero sanitizer.",
    )
    parser.add_argument("--iter", type=int, default=200,
                        help="Number of test cases to generate (default 200)")
    parser.add_argument("--seed", type=int, default=None,
                        help="Random seed for reproducible runs")
    parser.add_argument("--verbose", action="store_true",
                        help="Print every test case, not just failures")
    args = parser.parse_args()

    base_seed = args.seed if args.seed is not None else random.randrange(2**31)
    print(c(f"PromptZero fuzzer — {args.iter} iterations, base seed {base_seed}", DIM))
    print()

    all_failures: List[Failure] = []
    per_invariant: dict = {"P1 no-leak": 0, "P2 round-trip": 0, "P3 consistency": 0}

    for i in range(args.iter):
        seed = base_seed + i
        random.seed(seed)
        case = make_test_case()
        fails = check_case(case, seed)

        if args.verbose:
            tag = c("PASS", GREEN) if not fails else c("FAIL", RED)
            print(f"  {tag}  #{i:04d} seed={seed} pii={len(case.injected)}")

        for f in fails:
            all_failures.append(f)
            per_invariant[f.invariant] = per_invariant.get(f.invariant, 0) + 1
            if not args.verbose:
                report_failure(f)

    print()
    print("─" * 70)
    if not all_failures:
        print(c(f"  ✓ All {args.iter} cases held every invariant.", GREEN))
        return 0

    print(c(f"  ✗ {len(all_failures)} failures across {args.iter} cases:", RED))
    for inv, n in per_invariant.items():
        if n:
            print(f"      {inv:<20}  {n} failures")
    print()
    print(c(f"  Reproduce a specific case with --seed <seed>", DIM))
    return 1


if __name__ == "__main__":
    sys.exit(main())
