#!/usr/bin/env python3
"""
PDF Cracker Tool
================
A multithreaded PDF password cracking tool that supports:
  - Wordlist attack: test passwords from a file
  - Brute-force attack: generate passwords on the fly

Usage:
  # Wordlist attack
  python pdf_cracker.py protected.pdf --wordlist wordlist.txt

  # Brute-force attack
  python pdf_cracker.py protected.pdf --generate --chars abc123 --min-length 1 --max-length 4

  # Brute-force with defaults (lowercase letters, length 1-3)
  python pdf_cracker.py protected.pdf --generate

Dependencies:
  pip install pikepdf tqdm
"""

import argparse
import itertools
import string
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import pikepdf
except ImportError:
    print("[ERROR] pikepdf not installed. Run: pip install pikepdf")
    sys.exit(1)

try:
    from tqdm import tqdm
except ImportError:
    print("[ERROR] tqdm not installed. Run: pip install tqdm")
    sys.exit(1)


# ─────────────────────────────────────────────
# Password Sources
# ─────────────────────────────────────────────

def load_passwords(wordlist_file: str):
    """Yield passwords one-by-one from a wordlist file."""
    try:
        with open(wordlist_file, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                pwd = line.strip()
                if pwd:
                    yield pwd
    except FileNotFoundError:
        print(f"[ERROR] Wordlist file not found: {wordlist_file}")
        sys.exit(1)


def generate_passwords(chars: str, min_length: int, max_length: int):
    """Yield every combination of `chars` from `min_length` to `max_length`."""
    for length in range(min_length, max_length + 1):
        for combo in itertools.product(chars, repeat=length):
            yield "".join(combo)


def count_passwords(chars: str, min_length: int, max_length: int) -> int:
    """Return the total number of brute-force combinations (for tqdm total)."""
    total = 0
    n = len(chars)
    for length in range(min_length, max_length + 1):
        total += n ** length
    return total


# ─────────────────────────────────────────────
# Core Cracking Logic
# ─────────────────────────────────────────────

def try_password(pdf_file: str, password: str) -> str | None:
    """
    Attempt to open the PDF with the given password.
    Returns the password string if successful, otherwise None.
    """
    try:
        with pikepdf.open(pdf_file, password=password):
            return password
    except pikepdf._core.PasswordError:
        return None
    except Exception as e:
        # Unexpected error (e.g., corrupted PDF)
        print(f"\n[WARNING] Unexpected error with password '{password}': {e}")
        return None


def decrypt_pdf(
    pdf_file: str,
    passwords,
    total: int | None = None,
    max_workers: int = 8,
) -> str | None:
    """
    Try passwords in parallel using a ThreadPoolExecutor.

    Args:
        pdf_file:    Path to the encrypted PDF.
        passwords:   An iterable of password strings.
        total:       Total password count (for progress bar accuracy).
        max_workers: Number of concurrent threads.

    Returns:
        The cracked password, or None if not found.
    """
    found_password = None
    stop_event = threading.Event()

    def worker(pwd):
        if stop_event.is_set():
            return None
        return try_password(pdf_file, pwd)

    print(f"\n[*] Target  : {pdf_file}")
    print(f"[*] Threads : {max_workers}")
    if total:
        print(f"[*] Total   : {total:,} passwords to try\n")
    else:
        print()

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        progress = tqdm(
            total=total,
            desc="Cracking",
            unit="pwd",
            dynamic_ncols=True,
        )

        futures = {}
        for pwd in passwords:
            if stop_event.is_set():
                break
            future = executor.submit(worker, pwd)
            futures[future] = pwd

        try:
            for future in as_completed(futures):
                progress.update(1)
                result = future.result()
                if result is not None:
                    found_password = result
                    stop_event.set()
                    # Cancel remaining pending futures (best-effort)
                    for f in futures:
                        f.cancel()
                    break
        except KeyboardInterrupt:
            print("\n[!] Interrupted by user.")
            stop_event.set()
        finally:
            progress.close()

    return found_password


# ─────────────────────────────────────────────
# Argument Parsing
# ─────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pdf_cracker",
        description="Multithreaded PDF password cracker (wordlist or brute-force)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Wordlist attack
  python pdf_cracker.py secret.pdf --wordlist rockyou.txt

  # Brute-force (digits only, up to 4 chars)
  python pdf_cracker.py secret.pdf --generate --chars 0123456789 --max-length 4

  # Brute-force with more threads
  python pdf_cracker.py secret.pdf --generate --max-length 3 --threads 16
        """,
    )

    parser.add_argument("pdf_file", help="Path to the password-protected PDF")

    # Attack mode (mutually exclusive)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--wordlist", "-w",
        metavar="FILE",
        help="Path to a wordlist file (one password per line)",
    )
    mode.add_argument(
        "--generate", "-g",
        action="store_true",
        help="Brute-force: generate passwords on the fly",
    )

    # Brute-force options
    bf = parser.add_argument_group("Brute-force options (used with --generate)")
    bf.add_argument(
        "--chars", "-c",
        default=string.ascii_lowercase + string.digits,
        metavar="CHARSET",
        help=(
            "Characters to use in generated passwords "
            f"(default: lowercase + digits)"
        ),
    )
    bf.add_argument(
        "--min-length",
        type=int,
        default=1,
        metavar="N",
        help="Minimum password length (default: 1)",
    )
    bf.add_argument(
        "--max-length",
        type=int,
        default=4,
        metavar="N",
        help="Maximum password length (default: 4)",
    )

    # General options
    parser.add_argument(
        "--threads", "-t",
        type=int,
        default=8,
        metavar="N",
        help="Number of worker threads (default: 8)",
    )

    return parser


# ─────────────────────────────────────────────
# Entry Point
# ─────────────────────────────────────────────

def main():
    parser = build_parser()
    args = parser.parse_args()

    # Validate brute-force length args
    if args.generate and args.min_length > args.max_length:
        parser.error("--min-length cannot be greater than --max-length")

    # Select password source
    if args.wordlist:
        passwords = load_passwords(args.wordlist)
        total = None  # File length unknown without reading it twice
        print(f"[*] Mode    : Wordlist ({args.wordlist})")
    else:
        chars = args.chars
        min_l, max_l = args.min_length, args.max_length
        passwords = generate_passwords(chars, min_l, max_l)
        total = count_passwords(chars, min_l, max_l)
        print(
            f"[*] Mode    : Brute-force | "
            f"chars='{chars}' | "
            f"length={min_l}-{max_l}"
        )

    # Run cracker
    result = decrypt_pdf(
        pdf_file=args.pdf_file,
        passwords=passwords,
        total=total,
        max_workers=args.threads,
    )

    # Report
    print()
    if result is not None:
        print(f"[✓] SUCCESS! Password found: '{result}'")
    else:
        print("[✗] Password not found. Try a larger wordlist or longer length.")

    sys.exit(0 if result else 1)


if __name__ == "__main__":
    main()
