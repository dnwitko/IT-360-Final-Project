import json
import re
from pathlib import Path

from evtx import PyEvtxParser
from drain3 import TemplateMiner
from drain3.template_miner_config import TemplateMinerConfig
from colorama import Fore, Style

from pacing import pause

# drain3.ini lives in the project root, one level above src/
DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent.parent / "drain3.ini"


def normalize_whitespace(text):
    """Collapses literal and escaped \\r, \\n, \\t and repeated spaces into single spaces."""
    text = text.replace('\\r', ' ').replace('\\n', ' ').replace('\\t', ' ')
    return re.sub(r'\s+', ' ', text).strip()


def provider_token(name):
    """Keeps a provider name as one token (spaces become underscores) so it can be read back."""
    return str(name).strip().replace(" ", "_")


def load_miner(config_path=DEFAULT_CONFIG_PATH):
    """Builds a Drain3 TemplateMiner using an explicit config path.

    Drain3's default only looks for drain3.ini in the current working directory and
    silently falls back to defaults, so we load the file ourselves."""
    config = TemplateMinerConfig()
    config_path = Path(config_path)
    if config_path.is_file():
        config.load(str(config_path))
    else:
        print(f"{Fore.RED}Warning: Drain3 config '{config_path}' not found. Using Drain3 defaults.{Style.RESET_ALL}")
    return TemplateMiner(config=config)


def _flatten(value, prefix=""):
    """Flattens nested EVTX JSON (dicts/lists) into 'key=value' pairs."""
    pairs = []
    if isinstance(value, dict):
        for key, inner in value.items():
            if key in ("#attributes", "#text"):
                pairs.extend(_flatten(inner, prefix))
            else:
                pairs.extend(_flatten(inner, f"{prefix}{key}." if isinstance(inner, (dict, list)) else f"{prefix}{key}"))
    elif isinstance(value, list):
        for inner in value:
            pairs.extend(_flatten(inner, prefix))
    elif value not in (None, ""):
        pairs.append(f"{prefix.rstrip('.')}={value}")
    return pairs


def _leaf_fields(value, fields=None):
    """Collects every named value in nested EVTX JSON into one flat dict (leaf names only)."""
    fields = {} if fields is None else fields
    if isinstance(value, dict):
        for key, inner in value.items():
            if isinstance(inner, (dict, list)):
                _leaf_fields(inner, fields)
            elif not key.startswith("#") and inner not in (None, ""):
                fields.setdefault(key, inner)
    elif isinstance(value, list):
        for inner in value:
            _leaf_fields(inner, fields)
    return fields


def _event_id(value):
    if isinstance(value, dict):  # EventID can carry attributes, e.g. {"#attributes": {...}, "#text": 4624}
        value = value.get("#text")
    return value


def parse_evtx_record(record):
    """Turns one record from PyEvtxParser.records_json() into an event dict plus the line Drain3 mines.

    The event ID is written as one token (EventID_4624) so the NUM mask leaves it alone
    and Drain3 keeps different event IDs in separate templates."""
    event = json.loads(record["data"]).get("Event", {})
    system = event.get("System", {})
    event_id = _event_id(system.get("EventID"))
    provider = system.get("Provider", {}).get("#attributes", {}).get("Name", "")
    channel = system.get("Channel", "")
    data = [event.get("EventData"), event.get("UserData")]
    fields = _leaf_fields(data)

    time = str(record.get("timestamp", "")).replace(" UTC", "")
    if time.startswith("1601"):  # an empty timestamp; fall back to Sysmon's own field
        time = str(fields.get("UtcTime", ""))

    details = _flatten(data[0]) + _flatten(data[1])
    line = normalize_whitespace(f"EventID_{event_id} Provider={provider_token(provider)} Channel={channel} " + " ".join(details))
    return line, {"time": time[:19], "event_id": event_id, "provider": provider,
                  "host": system.get("Computer", ""), "fields": fields, "message": ""}


# Timestamps at the start of a text line, e.g. "2026-04-24T09:15:56+0000 ..." or "Apr 24 09:15:56 ..."
LEADING_ISO_TIME = re.compile(r"^\[?(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})[^\s\]]*\]?\s+")
LEADING_SYSLOG_TIME = re.compile(r"^([A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2})\s+")
TIME_KEYS = ("timestamp", "@timestamp", "time", "EventTime", "date", "datetime")


def _iso(value):
    """'2026-04-24T09:15:56.123Z' -> '2026-04-24 09:15:56'"""
    return str(value)[:19].replace("T", " ")


def _text_event(event_id, provider, fields, message, time="", host=""):
    return {"time": time, "event_id": event_id, "provider": provider, "host": host,
            "fields": fields, "message": message}


def parse_json_record(record, file_name=""):
    """Returns (line Drain3 should mine, event dict) for one JSON log record."""
    if "Message" in record:  # Windows events exported as JSON lines (like Samples/WinEvents.log)
        event_id = record.get("EventID", "")
        source = record.get("SourceName", "")
        message = normalize_whitespace(str(record["Message"]))
        event = _text_event(event_id, source, record, message, _iso(record.get("EventTime", "")),
                            record.get("Hostname", ""))
        return normalize_whitespace(f"EventID_{event_id} Provider={provider_token(source)} {message}"), event
    # Any other JSON: mine its message if it has one, otherwise its keys and values.
    # Large JSON exports can hold hundreds of thousands of records, so keep only short fields.
    time = next((_iso(record[k]) for k in TIME_KEYS if k in record), "")
    event_id = record.get("eventid") or record.get("event_type") or record.get("type") or "-"
    message = record.get("message") or record.get("msg") or " ".join(
        f"{k}={v}" for k, v in record.items() if k not in TIME_KEYS and not isinstance(v, (dict, list)))
    message = normalize_whitespace(str(message))
    line = f"EventID_{event_id} {message}" if event_id != "-" else message
    fields = {k: v for k, v in record.items() if not isinstance(v, (dict, list)) and len(str(v)) < 200}
    return normalize_whitespace(line), _text_event(event_id, "", fields, message, time)


def parse_text_line(line, file_name=""):
    """Returns (line Drain3 should mine, event dict) for one line of a text log.

    JSON lines are parsed so only the meaningful fields are mined, and a leading
    timestamp is pulled out of other lines so every line doesn't look unique to Drain3."""
    if line.startswith("{"):
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            record = None
        if isinstance(record, dict):
            return parse_json_record(record, file_name)

    clean, time = normalize_whitespace(line), ""
    match = LEADING_ISO_TIME.match(clean) or LEADING_SYSLOG_TIME.match(clean)
    if match:
        time = _iso(match.group(1)) if match.re is LEADING_ISO_TIME else match.group(1)
        clean = clean[match.end():]
    return clean, _text_event("-", "", {}, clean, time)


def text_line_to_message(line):
    """The text Drain3 mines for one line of a text log."""
    return parse_text_line(line)[0]


def _mine(miner, line, event, sequence, events, file_name):
    result = miner.add_log_message(line)
    if result:
        sequence.append(result["cluster_id"])
        event["cluster_id"] = result["cluster_id"]
    event["file"] = file_name
    events.append(event)


def parse_evtx_file(file_path, miner, sequence, events):
    """Parses a Windows Event Log file, mining every record with Drain3."""
    records_processed = 0
    try:
        for record in PyEvtxParser(str(file_path)).records_json():
            line, event = parse_evtx_record(record)
            _mine(miner, line, event, sequence, events, Path(file_path).name)
            records_processed += 1
    except Exception as e:
        if records_processed:
            return False, (f"Only the first {records_processed} events could be read before the file stopped "
                           f"making sense, so the rest of it may be damaged or tampered with. ({e})")
        return False, f"This could not be read as a Windows event log. It may be damaged or tampered with. ({e})"
    if not records_processed:
        return False, "No events could be read from this file. It may be empty or damaged."
    return True, records_processed


MAX_JSON_LINES = 1000


def _not_a_text_log(file_path):
    """Why a "text" log can't be analyzed (empty, or really binary data), or None if it looks fine."""
    try:
        with open(file_path, "rb") as f:
            start = f.read(8192)
    except OSError as e:
        return f"The file could not be opened: {e}"
    if not start.strip():
        return "The file is empty. A log that should have entries but doesn't may have been wiped."
    if start.count(b"\x00") > len(start) // 100:
        return ("This doesn't look like a text log: it contains binary data. It may be another kind of "
                "file renamed to look like a log.")
    return None


def parse_text_file(file_path, miner, sequence, events):
    """Parses a text/log file using Drain3 and records the event sequence.

    JSON objects spread over several lines (pretty-printed exports) are joined back
    into one record before parsing."""
    problem = _not_a_text_log(file_path)
    if problem:
        return False, problem
    try:
        lines_processed = 0
        name = Path(file_path).name
        buffer = []
        with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
            for raw in f:
                raw = raw.strip()
                if not raw or raw in ("[", "]"):
                    continue
                lines_processed += 1
                if buffer or (raw.startswith("{") and not raw.endswith("}") and not raw.endswith("},")):
                    buffer.append(raw)
                    try:
                        record = json.loads(" ".join(buffer).rstrip(","))
                    except json.JSONDecodeError:
                        if len(buffer) < MAX_JSON_LINES:
                            continue
                        # Not JSON after all: mine the buffered lines one by one
                        for buffered in buffer:
                            _mine(miner, *parse_text_line(buffered, name), sequence, events, name)
                        buffer = []
                        continue
                    buffer = []
                    if isinstance(record, dict):
                        _mine(miner, *parse_json_record(record, name), sequence, events, name)
                    continue
                _mine(miner, *parse_text_line(raw.rstrip(",") if raw.startswith("{") else raw, name),
                      sequence, events, name)
            for buffered in buffer:  # an unfinished JSON object at the end of the file
                _mine(miner, *parse_text_line(buffered, name), sequence, events, name)
        return True, lines_processed
    except Exception as e:
        return False, f"The file could not be read: {e}"


def process_logs(found_logs, config_path=DEFAULT_CONFIG_PATH):
    """Processes all found logs and flags un-analyzable files.

    Returns (miner, flagged_files, event_sequences, events). event_sequences holds one
    list of cluster IDs per file, so the grapher never links events across files.
    events holds every parsed event (time, event ID, provider, fields) for the summary."""
    flagged_files = [
        {"file": path, "error": f"This folder could not be opened, so the logs in it (if any) were not checked. ({error})"}
        for path, error in found_logs.get("unreadable", [])
    ]
    miner = load_miner(config_path)
    event_sequences, events = [], []

    print(f"{Fore.YELLOW}--- Reading Log Files ---{Style.RESET_ALL}")
    pause(0.5)

    jobs = [("EVTX", path, parse_evtx_file) for path in found_logs["evtx"]]
    jobs += [("TEXT", path, parse_text_file) for path in found_logs["text"]]

    for kind, path, parse in jobs:
        print(f"Reading [{kind}]: {path.name}...", end=" ", flush=True)
        sequence = []
        success, result = parse(path, miner, sequence, events)
        if sequence:
            event_sequences.append(sequence)
        if success:
            unit = "records" if kind == "EVTX" else "lines"
            print(f"{Fore.GREEN}OK ({result} {unit}){Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}Could not be fully read. Flagged for manual review.{Style.RESET_ALL}")
            flagged_files.append({"file": str(path), "error": result})
        pause(0.3)

    print(f"\nGrouped {len(events)} events into {len(miner.drain.clusters)} event patterns.")
    pause(0.8)

    return miner, flagged_files, event_sequences, events
