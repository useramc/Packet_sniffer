"""Run from the repository root: python -m capture --help."""

import argparse
import json
import sys
import math
import threading

from .interfaces import CaptureError, list_interfaces, select_interface
from .smoke import smoke_capture
from .session import CaptureSession
from .settings import save_settings, start_saved


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
    save = commands.add_parser("save-settings", help="Validate and persist interface/filter JSON")
    save.add_argument("--interface", required=True)
    save.add_argument("--filter", default="")
    save.add_argument("--settings", required=True)
    run = commands.add_parser("run", help="Run a saved capture configuration; Ctrl+C stops cleanly")
    run.add_argument("--settings", required=True)
    run.add_argument("--output-dir", required=True)
    run.add_argument("--session-name", default="")
    run.add_argument("--seconds", type=float, default=10)
    args = parser.parse_args(argv)
    try:
        if args.command == "interfaces":
            result = [iface.to_dict() for iface in list_interfaces()]
        elif args.command == "select":
            result = select_interface(args.interface).to_dict()
        elif args.command == "save-settings":
            result = save_settings(args.settings, args.interface, args.filter)
        elif args.command == "run":
            if not math.isfinite(args.seconds) or not 0 < args.seconds <= 14400:
                raise CaptureError("Use a finite duration greater than 0 and at most 14400 seconds.")
            manager = CaptureSession(args.output_dir)
            try:
                start_saved(manager, args.settings, args.session_name)
                threading.Event().wait(args.seconds)
            except KeyboardInterrupt:
                pass
            finally:
                result = manager.terminate()
            if result["error"]:
                raise CaptureError(result["error"])
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
