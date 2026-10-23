"""Run from the repository root: python -m capture --help."""

import argparse
import json
import sys

from .interfaces import CaptureError, list_interfaces, select_interface
from .smoke import smoke_capture


def main(argv=None):
    parser = argparse.ArgumentParser(description="PPS capture setup diagnostics")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("interfaces", help="List adapters as JSON; use their exact id for selection")
    select = commands.add_parser("select", help="Validate an adapter without starting capture")
    select.add_argument("--interface", required=True)
    smoke = commands.add_parser("smoke", help="Bounded capture of authorized test traffic to a new PCAP")
    smoke.add_argument("--interface", required=True)
    smoke.add_argument("--output", required=True)
    smoke.add_argument("--seconds", type=float, default=5)
    smoke.add_argument("--count", type=int, default=100)
    args = parser.parse_args(argv)
    try:
        if args.command == "interfaces":
            result = [iface.to_dict() for iface in list_interfaces()]
        elif args.command == "select":
            result = select_interface(args.interface).to_dict()
        else:
            count = smoke_capture(args.interface, args.output, args.seconds, args.count)
            result = {"output": args.output, "packets": count}
        print(json.dumps(result, indent=2))
        return 0
    except CaptureError as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
