from __future__ import annotations

import argparse
import sys

from gateway.evidence.verifier import ChainVerifier


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="gateway-verify",
        description="Verify an audit hash.",
    )
    parser.add_argument("database", help="SQLite database path")
    parser.add_argument("chain_id", help="Agent chain identifier")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    result = ChainVerifier(
        db_path=args.database,
        chain_id=args.chain_id,
    ).verify_chain()

    if result.valid:
        print(f"Chain {result.chain_id} is valid. Checked {result.checked_entries} entries.")
        return 0

    print(
        f"INVALID: chain {result.chain_id}"
        f" is broken at sequence {result.broken_seq}. Reason: {result.reason}",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
