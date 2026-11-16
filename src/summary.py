"""Prints a plain-English summary of the analyzed events to the terminal."""
import textwrap
from collections import Counter, defaultdict

from colorama import Fore, Style

from knowledge import SUSPICIOUS, explained, source_key, technique_text
from pacing import pause
from grapher import clean_template

WIDTH = 100
# The terminal shows this many suspicious events; the HTML report lists all of them
MAX_TIMELINE = 10
# This many failed sign-ins for one account from one address looks like password guessing
BRUTE_FORCE_THRESHOLD = 5
FAILED_SIGN_INS = {4625, 4771}


def shorten(text, width):
    """Cuts text to width characters, ending with '...' when it was longer."""
    text = " ".join(str(text).split())
    return text if len(text) <= width else text[:width - 3].rstrip() + "..."


def _source(event):
    """Where an event came from: its provider, or its file name for plain text logs."""
    return source_key(event["provider"]) if event.get("provider") else event.get("file", "Unknown")


def heading(title):
    print(f"\n{Fore.YELLOW}=== {title} ==={Style.RESET_ALL}")
    pause(0.4)


def wrap(text, indent):
    return textwrap.fill(text, WIDTH, initial_indent=indent, subsequent_indent=" " * len(indent))


def _number(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _failed_sign_in(event):
    number = _number(event.get("event_id"))
    if number in FAILED_SIGN_INS:
        return True
    # A Kerberos ticket request (4768) with a non-zero status also failed, e.g. unknown user
    status = str((event.get("fields") or {}).get("Status", "0x0")).lower()
    return number == 4768 and status not in ("0x0", "0")


def find_brute_force(events):
    """Finds password guessing in failed sign-ins: many tries against one account
    (brute force), or tries against many accounts from one address (password spraying)."""
    by_account, by_address = defaultdict(list), defaultdict(list)
    for event in events:
        if _failed_sign_in(event):
            f = event.get("fields") or {}
            by_account[(f.get("TargetUserName", "?"), f.get("IpAddress", "?"))].append(event)
            by_address[f.get("IpAddress", "?")].append(event)

    def burst(group, sentence, reason, technique):
        times = sorted(e.get("time", "") for e in group)
        return {"time": times[0], "file": group[0].get("file", ""), "host": group[0].get("host", ""), "events": group,
                "sentence": f"{sentence} (until {times[-1][11:19]})", "reasons": [reason], "techniques": [technique]}

    bursts = []
    for (user, address), group in by_account.items():
        if len(group) >= BRUTE_FORCE_THRESHOLD:
            bursts.append(burst(group, f"{len(group)} failed sign-ins for {user} from {address}",
                                "Many failed sign-ins in a row usually means someone is guessing the password.",
                                "T1110"))
    for address, group in by_address.items():
        users = {(e.get("fields") or {}).get("TargetUserName", "?") for e in group}
        if len(users) >= BRUTE_FORCE_THRESHOLD:
            bursts.append(burst(group, f"{len(group)} failed sign-ins for {len(users)} different accounts from {address}",
                                "Trying a few passwords against many accounts is password spraying, a way to guess "
                                "passwords without locking any single account out.", "T1110.003"))
    return bursts


def build_timeline(events, explanations=None):
    """Suspicious events in time order, with repeats of the same thing merged into one entry.
    Each entry keeps its events under "events" so the HTML report can point to them."""
    explanations = explanations or [explained(event) for event in events]
    items = []
    for event, info in zip(events, explanations):
        if info["severity"] == SUSPICIOUS:
            items.append({"time": event.get("time", ""), "file": event.get("file", ""), "host": event.get("host", ""),
                          "name": info["name"],
                          "sentence": info["sentence"], "reasons": info["reasons"] or [info["meaning"]],
                          "techniques": info["techniques"], "events": [event]})
    items += find_brute_force(events)
    items.sort(key=lambda item: item["time"])

    # Back-to-back events of the same kind, flagged for the same reasons, become one entry
    merged = []
    for item in items:
        last = merged[-1] if merged else None
        if (last and last["reasons"] == item["reasons"] and last["file"] == item["file"]
                and last.get("name") == item.get("name")):
            last["repeat"] += 1
            last["events"] = last["events"] + item["events"]
            if item["sentence"] != last["sentence"] and item["sentence"] not in last["similar"]:
                last["similar"].append(item["sentence"])
        else:
            merged.append(dict(item, repeat=1, similar=[]))
    return merged


def _activity_table(rows):
    print(f"  {'Count':>7}  {'Event':<8} {'Source':<20} What it is")
    for count, event_id, source, name in rows:
        if len(event_id) > 8:  # long text IDs (from JSON logs) are already the name
            event_id = "-"
        print(f"  {count:>7}  {shorten(event_id, 8):<8} {shorten(source, 20):<20} {shorten(name, 60)}")
        pause(0.05)


def print_manual_review(flagged, flagged_report=None):
    """Lists the files and folders that could not be (fully) analyzed."""
    heading("Needs manual review")
    if not flagged:
        print("Every file was read completely.")
        return
    print(f"{Fore.RED}{len(flagged)} file(s) or folder(s) could not be fully analyzed. "
          f"Check these by hand:{Style.RESET_ALL}")
    for item in flagged:
        print(f"  {item['file']}")
        print(wrap(item["error"], "    "))
        pause(0.2)
    if flagged_report:
        print(f"\nThis list is also saved in {flagged_report}.")
    pause(0.8)


def print_summary(events, templates=None, top_n=5, timeline=None, flagged=None, report=None, flagged_report=None):
    """Prints an overview, files that need manual review, the most common and rarest
    activity, the first few suspicious events, and a short conclusion.

    templates maps Drain3 cluster IDs to their templates; plain text lines are
    grouped by template so lines that differ only in an IP or number count together.
    timeline is build_timeline()'s result (built here if not given). report is the
    HTML file that lists every suspicious event, and flagged_report the saved list
    of flagged files."""
    templates = templates or {}
    flagged = flagged or []
    if not events:
        print_manual_review(flagged, flagged_report)
        return
    explanations = [explained(event) for event in events]

    heading("Overview")
    files = sorted({e.get("file", "") for e in events})
    times = sorted(e["time"] for e in events if e.get("time"))
    print(f"{len(events)} events from {len(files)} file(s)" + (f", {times[0]} to {times[-1]}." if times else "."))
    by_source = Counter(_source(e) for e in events)
    print("\nWhere the events came from:")
    widest = max(by_source.values())
    for source, count in by_source.most_common(8):
        print(f"  {shorten(source, 34):<34} {count:>5}  {'#' * max(1, round(20 * count / widest))}")
        pause(0.05)
    if len(by_source) > 8:
        print(f"  ...and {len(by_source) - 8} more sources")
    pause(0.8)

    print_manual_review(flagged, flagged_report)

    # Count activity by event type
    by_type = defaultdict(lambda: [0, ""])
    for event, info in zip(events, explanations):
        source = _source(event)
        key = (str(event.get("event_id", "-")), source)
        name = info["name"]
        if key[0] == "-":  # plain text lines have no event ID: group them by their pattern
            name = clean_template(templates.get(event.get("cluster_id"), info["sentence"]))
            key = ("-", source, name)
        by_type[key][0] += 1
        by_type[key][1] = by_type[key][1] or name
    rows = sorted(((count, key[0], key[1], name) for key, (count, name) in by_type.items()),
                  key=lambda row: row[0], reverse=True)

    heading("Most common activity")
    if rows[0][0] == rows[-1][0]:
        print(f"Every type of event appears {rows[0][0]} time(s), so nothing stands out by frequency.")
    else:
        _activity_table(rows[:top_n])
        pause(0.8)
        heading("Rarest activity")
        singles = sum(1 for row in rows if row[0] == 1)
        if singles > top_n:
            print(f"{singles} types of event appear only once. The first {top_n}:")
        _activity_table(sorted(rows, key=lambda row: row[0])[:top_n])
    pause(0.8)

    if timeline is None:
        timeline = build_timeline(events, explanations)
    heading("Suspicious activity, in order")
    if not timeline:
        print("Nothing suspicious was found.")
    elif len(timeline) > MAX_TIMELINE:
        print(f"The first {MAX_TIMELINE} of {len(timeline)}"
              + (f". All of them are in {report}, on the Suspicious activity tab." if report else ".") + "\n")
    for item in timeline[:MAX_TIMELINE]:
        repeat = f" (x{item['repeat']})" if item["repeat"] > 1 else ""
        print(f"{Fore.RED}[{item['time'] or 'no time'}]{Style.RESET_ALL} {item['sentence']}{repeat}")
        if item["similar"]:
            more = len(item["similar"]) - 3
            print(wrap("Also: " + "; ".join(item["similar"][:3]) + (f"; and {more} more" if more > 0 else ""), "  "))
        print(f"  Where: {item['file']}" + (f", on {item['host']}" if item.get("host") else ""))
        print("  Why it's suspicious:")
        for reason in item["reasons"]:
            print(wrap(reason, "    - "))
        print()
        pause(0.6)
    if len(timeline) > MAX_TIMELINE:
        rest = len(timeline) - MAX_TIMELINE
        print(f"{rest} more not shown here" + (f". See the Suspicious activity tab in {report}." if report else "."))

    heading("Conclusion")
    techniques = Counter(t for item in timeline for t in item["techniques"])
    suspicious_files = sorted({item["file"] for item in timeline})
    if not timeline:
        print("No signs of an attack were found in these logs.")
    else:
        print(f"Found {sum(i['repeat'] for i in timeline)} suspicious event(s) in {len(suspicious_files)} file(s): "
              + ", ".join(suspicious_files[:5])
              + (f" and {len(suspicious_files) - 5} more." if len(suspicious_files) > 5 else "."))
    if flagged:
        print(f"{Fore.RED}{len(flagged)} file(s) or folder(s) could not be fully analyzed and need manual review "
              f"(listed above).{Style.RESET_ALL}")
    if techniques:
        print("\nAttack techniques seen (MITRE ATT&CK):")
        for technique_id, _ in techniques.most_common():
            print(wrap(technique_text(technique_id), "  - "))
            pause(0.2)
