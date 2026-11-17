# L.A.A.S.T (Log Analysis And Summary Tool)

L.A.A.S.T is a post-intrusion log analysis tool. It scans a folder for Windows Event Logs (`.evtx`) and text logs (`.txt`, `.log`, `.json`), groups their events into templates with [Drain3](https://github.com/logpai/Drain3), maps how events follow one another with [NetworkX](https://networkx.org/), points out activity that looks like an attack, and produces an interactive HTML report. Files or folders that cannot be fully analyzed are always flagged for manual review.

The project plan is in [docs/ProjectProposal.md](docs/ProjectProposal.md).

## Requirements

- Python 3.8 or newer
- The packages listed in `requirements.txt`:
  - [Drain3](https://github.com/logpai/Drain3): groups log lines into event templates
  - [NetworkX](https://networkx.org/): builds the graph of which events follow which
  - [evtx](https://github.com/omerbenamram/pyevtx-rs): reads Windows Event Log (`.evtx`) files
  - [pyvis](https://github.com/WestHealth/pyvis): draws the interactive graph with [vis-network](https://github.com/visjs/vis-network)
  - [colorama](https://github.com/tartley/colorama): colors the terminal output

## Installation

```
python -m venv .venv
.venv\Scripts\activate        # Windows
source .venv/bin/activate     # macOS / Linux
pip install -r requirements.txt
```

## Usage

```
python src/main.py Samples
```

| Option | Default | Description |
| --- | --- | --- |
| `path` | `.` | Folder to scan (searched recursively) |
| `-o`, `--output` | `event_graph.html` | Output path for the HTML report |
| `--flagged-report` | `flagged_files.json` | Output path for the list of files needing manual review (written only when files are flagged) |
| `--no-delay` | off | Print all output at once instead of pausing briefly between sections |
| `--html-only` | off | Skip the terminal summary and only write the HTML report |
| `--config` | `drain3.ini` in the project root | Drain3 configuration file |

The tool can be run from any directory. The HTML report is a single self-contained file that works offline.

### Terminal summary

The terminal output is a short briefing, printed section by section with short pauses (turn them off with `--no-delay`, or skip it entirely with `--html-only`):

- **Overview**: how many events were read, the time span, and which Windows components produced them.
- **Needs manual review**: files and folders that could not be fully analyzed, and why.
- **Most common / rarest activity**: event types by frequency, with plain-English names such as "Failed logon".
- **Suspicious activity, in order**: the first 10 events that look like an attack. Each entry says what happened in plain English (for example, "KeeFarce.exe injected code into KeePass.exe"), where it was found, and why it is suspicious. The full list is in the HTML report.
- **Conclusion**: how many suspicious events were found, how many files need manual review, and which MITRE ATT&CK techniques the events match, each with a short explanation.

### HTML report

The report has three tabs:

1. **Timeline**: a picture of what happened in each log file.
   - Each row is one log file, read left to right, oldest first.
   - Each circle is a step. An event repeated several times in a row becomes one circle with a count, such as "x110". Bigger circles mean more repeats.
   - Colors: red is suspicious, orange is worth noting, blue is routine.
   - Hover over a circle for a one-line description. Click it for full details, including why it was flagged.
   - Long files are shortened to at most 25 steps per row. Stretches of less important events become gray "... N more events ..." circles, while suspicious steps and the steps around them stay visible.
   - Click a gray circle to see what it contains and to show those steps in place (drawn with dashed lines). The "Show hidden steps" button shows or hides all of them at once.
2. **Suspicious activity**: every suspicious event, oldest first.
   - Filter by file or ATT&CK technique, or search the text.
   - "Show on timeline" jumps to the event's circle, and clicking a red circle links back to its entry.
3. **Needs manual review**: the flagged files and folders, with the reason for each.

### Manual review

A file is flagged when it cannot be fully analyzed: an event log that is damaged or only partly readable, a text log that is empty or contains binary data, or a folder that cannot be opened. These are listed in the terminal, in the report and in `flagged_files.json`. A damaged or wiped log can itself be a sign of tampering, so these files should be checked by hand. `Samples/damaged_security_log.evtx` is included to show this.

## How it works

1. **Scanning** (`src/scanner.py`): walks the target folder, collecting `.evtx`, `.txt`, `.log`, and `.json` files and recording any folders that cannot be read.
2. **Parsing** (`src/log_parser.py`): converts each EVTX record, or each line of a text log, into a single message and passes it to Drain3. JSON logs, including pretty-printed objects spread over several lines, are reduced to their event ID, time and message; Windows events exported as JSON (such as `Samples/WinEvents.log`) keep their source too. A timestamp at the start of a text line is pulled out so that lines differing only in time are grouped together. Each event ID becomes a token such as `EventID_4624`, so different events never share a template.
3. **Graphing** (`src/grapher.py`): builds a NetworkX directed graph with one node per template and an edge for each "event A was followed by event B" within the same file, then lays out each file's events as a timeline for the HTML report. Each step is labeled with its event ID and name, or, for event types the tool does not recognize, with the line itself (or its pattern, when repeated lines differ).
4. **Explaining** (`src/knowledge.py`): describes each event in plain English and decides whether it is suspicious. It knows common Security, Sysmon, PowerShell, Defender and BITS event IDs and MITRE ATT&CK technique IDs, and checks for signs such as known attack tools, programs running from folders any user can write to, code injection, access to LSASS (where Windows keeps passwords), cleared logs, and bursts of failed sign-ins.
5. **Summary** (`src/summary.py`): finds suspicious activity (including bursts of failed sign-ins) and prints the overview, manual review list, activity tables, suspicious activity and conclusion. `src/pacing.py` adds the short pauses between sections.
6. **Report** (`src/grapher.py`, `src/report_page.py`): writes the HTML report with its three tabs.

Drain3 masking rules (IP addresses, UUIDs, SIDs, hex values and numbers) are defined in `drain3.ini`.

## TODO

- **LLM summary**: send the findings (the suspicious activity, MITRE ATT&CK techniques and flagged files) to a large language model to write a narrative summary of the intrusion. This would also explain events from log formats the built-in rules do not cover.

## Tests

```
pip install pytest
python -m pytest tests
```

## Sample data

- `Samples/WinEvents.log`: [Windows-Event-Samples](https://github.com/d4rk-d4nph3/Windows-Event-Samples/tree/main) by d4rk-d4nph3
- `Samples/4794_DSRM_password_change_t1098.evtx`, `Samples/CA_keefarce_keepass_credump.evtx`, `Samples/babyshark_mimikatz_powershell.evtx`, `Samples/kerberos_pwd_spray_4771.evtx` and `Samples/DE_1102_security_log_cleared.evtx`: [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) by sbousseaden
- `Samples/damaged_security_log.evtx`: a copy of `4794_DSRM_password_change_t1098.evtx` with part of its internal structure overwritten, to show how damaged logs are flagged for manual review

## License

MIT. See [LICENSE](LICENSE).
