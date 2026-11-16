import argparse
import contextlib
import io
import json
import sys
from pathlib import Path

import colorama
from colorama import Fore, Style

from scanner import find_log_files
from log_parser import process_logs, DEFAULT_CONFIG_PATH
from grapher import generate_event_graph, visualize_graph
from summary import build_timeline, print_summary
import pacing


def build_arg_parser():
    parser = argparse.ArgumentParser(
        description="L.A.A.S.T: scan a folder for .evtx and text logs, mine event templates, and graph them.")
    parser.add_argument("path", nargs="?", default=".",
                        help="Folder to scan (default: current directory)")
    parser.add_argument("-o", "--output", default="event_graph.html",
                        help="HTML report to write (default: event_graph.html)")
    parser.add_argument("--flagged-report", default="flagged_files.json",
                        help="JSON list of files needing manual review (default: flagged_files.json)")
    parser.add_argument("--no-delay", action="store_true",
                        help="Print everything at once instead of pausing between sections")
    parser.add_argument("--html-only", action="store_true",
                        help="Skip the terminal summary and only write the HTML report")
    parser.add_argument("--config", default=str(DEFAULT_CONFIG_PATH),
                        help="Drain3 config file (default: drain3.ini in the project root)")
    return parser


def write_flagged_report(flagged_files, report_path):
    """Saves the files that couldn't be analyzed so the analyst can review them."""
    report_path = Path(report_path)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(flagged_files, f, indent=2)


def analyze(args):
    found_logs = find_log_files(args.path)
    if not (found_logs["evtx"] or found_logs["text"] or found_logs["unreadable"]):
        print("No logs to process.")
        return 1

    miner, flagged_files, event_sequences, events = process_logs(found_logs, args.config)
    if flagged_files:
        write_flagged_report(flagged_files, args.flagged_report)

    graph = generate_event_graph(miner, event_sequences, events) if events else None
    timeline = build_timeline(events)
    print_summary(events, {c.cluster_id: c.get_template() for c in miner.drain.clusters}, timeline=timeline,
                  flagged=flagged_files, report=args.output,
                  flagged_report=args.flagged_report if flagged_files else None)
    visualize_graph(graph, Path(args.output), timeline, flagged_files)
    return 0


def main(argv=None):
    colorama.init(autoreset=True)
    # Log text can contain characters the Windows console can't show; replace them instead of crashing
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")
    args = build_arg_parser().parse_args(argv)
    pacing.set_enabled(not args.no_delay and not args.html_only)

    if not args.html_only:
        return analyze(args)
    # Run quietly, then say only where the report is
    with contextlib.redirect_stdout(io.StringIO()) as output:
        result = analyze(args)
    if result:
        print(output.getvalue().strip())
    else:
        print(f"Report saved to '{args.output}'.")
    return result


if __name__ == "__main__":
    sys.exit(main())
