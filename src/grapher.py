import json
import re
import textwrap
from collections import Counter
from pathlib import Path

import networkx as nx
from pyvis.network import Network
from colorama import Fore, Style

import report_page
from knowledge import NOTABLE, ROUTINE, SUSPICIOUS, TECHNIQUES, explained, technique_text
from log_parser import normalize_whitespace
from pacing import pause

SEVERITY_ORDER = {ROUTINE: 0, NOTABLE: 1, SUSPICIOUS: 2}
COLORS = {ROUTINE: "#5b8def", NOTABLE: "#f5a623", SUSPICIOUS: "#e5484d"}

# Big logs can have millions of events; each file's row shows at most this many steps
MAX_STEPS = 25
GAP_COLOR = "#555555"

# vis-network settings: a fixed left-to-right layout (no physics simulation), so
# each log file reads as a chain from its first event to its last
GRAPH_OPTIONS = {
    "layout": {"hierarchical": {"enabled": True, "direction": "LR", "levelSeparation": 200,
                                "nodeSpacing": 100, "treeSpacing": 100, "blockShifting": True,
                                "edgeMinimization": True, "parentCentralization": False}},
    "physics": {"enabled": False},
    "nodes": {"shape": "dot", "font": {"color": "white", "size": 18},
              "scaling": {"min": 10, "max": 32}},
    "edges": {"smooth": False,
              "color": {"color": "#8a8a8a", "highlight": "#ffffff"},
              "font": {"color": "#dddddd", "size": 14, "strokeWidth": 0, "background": "#222222", "align": "top"},
              "arrows": {"to": {"enabled": True, "scaleFactor": 0.5}}},
    "interaction": {"hover": True, "tooltipDelay": 150, "navigationButtons": True},
}

def clean_template(raw_pattern):
    """Makes a Drain3 template readable: single spaces and one <*> per run of wildcards."""
    clean_pattern = normalize_whitespace(raw_pattern)
    return re.sub(r'(<\*>\s*)+', '<*> ', clean_pattern).strip()


def _wrap(text, width=70):
    return textwrap.fill(text, width)


def generate_event_graph(miner, event_sequences=None, events=None):
    """Uses NetworkX to map log templates into a graph of which events follow which.

    event_sequences is a list of per-file cluster ID sequences. Edges are only drawn
    between consecutive events in the same file. events (from process_logs) are used
    to give each node a plain-English name and a severity."""
    print(f"\n{Fore.YELLOW}--- Building Event Graph ---{Style.RESET_ALL}")

    # Events grouped by file, in order, for the timeline drawing
    files = {}
    for event in events or []:
        files.setdefault(event.get("file", ""), []).append(event)
    G = nx.DiGraph(sequences=event_sequences or [], files=files)
    clusters = miner.drain.clusters
    if not clusters:
        print(f"{Fore.RED}No log clusters found to graph.{Style.RESET_ALL}")
        return None

    for cluster in clusters:
        G.add_node(cluster.cluster_id, size=cluster.size, template=cluster.get_template(),
                   name="", meaning="", example="", severity=ROUTINE, reasons=[])

    # Describe each node using the events that belong to it
    for event in events or []:
        node = G.nodes.get(event.get("cluster_id"))
        if node is None:
            continue
        info = explained(event)
        if not node["name"]:
            name = info["name"]
            if not info["meaning"]:
                # Not an event type the tool knows: name it by its pattern instead,
                # without the "EventID_..." token added during parsing
                pattern = re.sub(r"^EventID_\S+\s*(Provider=\S+\s*)?", "", clean_template(node["template"]))
                pattern = re.sub(r"^\[[^\]]*\]\s*", "", pattern)  # a leading "[component]" tag
                name = pattern or name
            node.update(name=name, meaning=info["meaning"], example=info["sentence"],
                        event_id=event.get("event_id", "-"))
        if SEVERITY_ORDER[info["severity"]] > SEVERITY_ORDER[node["severity"]]:
            node.update(severity=info["severity"], example=info["sentence"])
        for reason in info["reasons"]:
            if reason not in node["reasons"]:
                node["reasons"].append(reason)

    for sequence in event_sequences or []:
        for source_node, target_node in zip(sequence, sequence[1:]):
            if source_node == target_node:  # skip self-loops
                continue
            if G.has_edge(source_node, target_node):
                G[source_node][target_node]['weight'] += 1
            else:
                G.add_edge(source_node, target_node, weight=1)

    print(f"{Fore.GREEN}Graph built with {G.number_of_nodes()} event types and {G.number_of_edges()} connections.{Style.RESET_ALL}")
    pause(0.5)
    return G


def _short(text, width):
    text = " ".join(str(text).split())
    return text if len(text) <= width else text[:width - 3] + "..."


def runs(events):
    """Merges back-to-back events of the same type into one step: [(cluster_id, [events])]."""
    steps = []
    for event in events:
        if steps and steps[-1][0] == event.get("cluster_id"):
            steps[-1][1].append(event)
        else:
            steps.append((event.get("cluster_id"), [event]))
    return steps


def _severity(step_events):
    return max((explained(e)["severity"] for e in step_events), key=lambda s: SEVERITY_ORDER[s])


def pick_steps(steps, limit=MAX_STEPS):
    """Chooses which steps of a long file to draw: the first and last two, every
    suspicious or notable step, and the steps right before and after them.
    Returns the kept step indexes in order; the gaps between them become "..." circles."""
    if len(steps) <= limit:
        return list(range(len(steps)))
    important = [i for i, (_, evs) in enumerate(steps) if _severity(evs) != ROUTINE]
    important.sort(key=lambda i: SEVERITY_ORDER[_severity(steps[i][1])], reverse=True)
    keep = {0, 1, len(steps) - 2, len(steps) - 1}
    for i in important:
        if len(keep) >= limit:
            break
        keep.update(j for j in (i - 1, i, i + 1) if 0 <= j < len(steps))
    return sorted(keep)[:limit] if len(keep) > limit else sorted(keep)


def timeline_rows(G):
    """Builds the drawing: one row per log file, in time order.

    Returns a list of rows; each row is (file name, items), where an item is either
    ("step", cluster_id, events, step index) or ("gap", number of hidden events,
    number of hidden steps, [(step index, cluster_id, events) for each hidden step])."""
    rows = []
    for file_name, events in G.graph.get("files", {}).items():
        steps = runs(events)
        kept = pick_steps(steps)
        items, previous = [], -1
        for index in kept + [len(steps)]:
            if index > previous + 1:
                hidden = [(i,) + steps[i] for i in range(previous + 1, index)]
                items.append(("gap", sum(len(evs) for _, _, evs in hidden), len(hidden), hidden))
            if index < len(steps):
                items.append(("step",) + steps[index] + (index,))
            previous = index
        rows.append((file_name, items))
    return rows


def _step_node(attrs, events):
    """vis-network settings for one step: a run of the same event type, back to back."""
    pattern = clean_template(attrs.get("template", ""))
    event_id = attrs.get("event_id", "-")
    name = attrs.get("name") or _short(pattern, 40) or "Log entry"
    count = len(events)
    severity = _severity(events)
    # Describe the step with its most concerning event
    worst = next(e for e in events if explained(e)["severity"] == severity)
    info = explained(worst)
    if not attrs.get("meaning"):
        # An event type the tool doesn't know is named by its Drain3 pattern, where
        # changing values show as <NUM>, <IP> and so on. When every event in this step
        # has the same text, show that real text instead.
        texts = {explained(e)["sentence"] for e in events}
        if len(texts) == 1:
            name = re.sub(r"^\[[^\]]*\]\s*", "", texts.pop()) or name
    times = sorted(e.get("time", "") for e in events if e.get("time"))
    when = (times[0] if times[0] == times[-1] else f"{times[0]} to {times[-1]}") if times else ""

    # vis-network shows a string title as plain text (never as HTML), so log text
    # from an attacker can't inject markup.
    hover = name + (f" x{count:,}" if count > 1 else "")
    same_text = info["sentence"].endswith(name)
    if not same_text:
        hover += "\n" + _short(info["sentence"], 80)
    hover += "\nClick for details"

    details = [name]
    if event_id not in ("-", ""):
        details.append(f"Event ID: {event_id}")
    details.append(("Occurred once" if count == 1 else f"Occurred {count:,} times in a row")
                   + (f", {when}" if when else ""))
    if attrs.get("meaning"):
        details += ["", attrs["meaning"]]
    if not same_text:
        details += ["", "Example:", info["sentence"]]
    if info["reasons"]:
        details += ["", "Why it's suspicious:"] + ["- " + r for r in info["reasons"]]
    details += ["", "Pattern shared by all events of this type (<NUM>, <IP> and similar mark values that change):",
                pattern]

    short_id = event_id not in ("-", "") and len(str(event_id)) <= 8
    label = _short(name, 24) + (f"\nEvent ID: {event_id}" if short_id else "") + (f" | x{count:,}" if count > 1 else "")
    if count > 1 and not short_id:
        label = _short(name, 24) + f"\nx{count:,}"
    return {"label": label, "title": hover, "details": "\n".join(details), "value": count,
            "color": COLORS[severity], "font": {"color": "white", "size": 16}}


# A hidden stretch longer than this many steps is only partly drawn when opened
# (its start and end), so opening it can't freeze the browser
EXPAND_LIMIT = 300


def _gap_node(node_id, hidden, G, expandable=True):
    """A gray "... N more events ..." circle standing for a stretch of hidden steps."""
    events = [e for _, _, evs in hidden for e in evs]
    kinds = Counter()
    for _, cluster_id, evs in hidden:
        kinds[G.nodes[cluster_id].get("name") or "Log entry"] += len(evs)
    suspicious = sum(1 for e in events if explained(e)["severity"] == SUSPICIOUS)
    size = f"{len(events):,} events" + (f" ({len(hidden):,} steps)" if len(hidden) != len(events) else "")
    details = [f"{size} hidden to keep the timeline short."]
    if suspicious:
        details.append(f"{suspicious:,} of them are suspicious and are listed on the Suspicious activity tab.")
    details += ["", "Contains:"]
    details += [f"- {_short(name, 60)} x{count:,}" for name, count in kinds.most_common(8)]
    if len(kinds) > 8:
        details.append(f"- and {len(kinds) - 8:,} other kinds of event")
    if expandable:
        details += ["", "Select Show these steps to display them, or Show hidden steps at the top to "
                        "display every hidden stretch."]
    else:
        details += ["", "This stretch is too long to display, so only the steps around it are shown."]
    return {"id": node_id, "kind": "gap", "expandable": expandable,
            "label": f"... {len(events):,} more events ...", "shape": "dot", "size": 6, "color": GAP_COLOR,
            "font": {"color": "#aaaaaa", "size": 14},
            "title": f"{len(events):,} hidden events\nClick to see what they are",
            "details": "\n".join(details)}


def _technique(technique_id):
    name = TECHNIQUES.get(technique_id, (None,))[0]
    return {"id": technique_id, "label": f"{name} ({technique_id})" if name else technique_id,
            "text": technique_text(technique_id)}


def report_data(G, timeline=None, flagged=None):
    """Everything the report page draws, as plain data for its script."""
    rows, node_of, gap_of, step_nodes = [], {}, {}, {}

    def step(row, index, cluster_id, events, gap=None):
        node = dict(_step_node(G.nodes[cluster_id], events), id=f"s{row}-{index}", kind="step")
        if gap:
            node["gap"] = gap
        for event in events:
            node_of[id(event)] = node["id"]
            if gap:
                gap_of[id(event)] = gap
        step_nodes[node["id"]] = node
        return node

    for row, (file_name, items) in enumerate(timeline_rows(G) if G is not None else []):
        file_node = {"id": f"file-{row}", "kind": "file", "label": _short(file_name, 34), "shape": "box",
                     "title": f"Log file: {file_name}",
                     "details": f"Log file: {file_name}\n\nEvents from this file are shown to the right, oldest first.",
                     "color": {"background": "#333333", "border": "#888888"}, "font": {"color": "white", "size": 16}}
        drawn = []
        for item in items:
            if item[0] == "step":
                _, cluster_id, events, index = item
                drawn.append({"node": step(row, index, cluster_id, events)})
                continue
            hidden = item[3]
            gap_id = f"g{row}-{hidden[0][0]}"
            gap = _gap_node(gap_id, hidden, G)
            if len(hidden) <= EXPAND_LIMIT:
                shown = [step(row, *h, gap=gap_id) for h in hidden]
            else:
                half = EXPAND_LIMIT // 2
                rest = dict(_gap_node(gap_id + "-rest", hidden[half:-half], G, expandable=False), gap=gap_id)
                for _, _, evs in hidden[half:-half]:
                    for event in evs:
                        node_of[id(event)], gap_of[id(event)] = rest["id"], gap_id
                shown = ([step(row, *h, gap=gap_id) for h in hidden[:half]] + [rest]
                         + [step(row, *h, gap=gap_id) for h in hidden[-half:]])
            gap["first"] = shown[0]["id"]
            drawn.append({"node": gap, "hidden": shown})
        rows.append({"file": file_node, "items": drawn})

    entries = []
    for number, item in enumerate(timeline or []):
        events = item.get("events") or []
        first = id(events[0]) if events else None
        for event in events:
            node = step_nodes.get(node_of.get(id(event)))
            if node is not None and number not in node.setdefault("entries", []):
                node["entries"].append(number)
        techniques = [_technique(t) for t in item["techniques"]]
        search = " ".join([item["sentence"], item.get("file", ""), item.get("host", "")] + item.get("similar", [])
                          + item["reasons"] + [t["label"] for t in techniques]).lower()
        entries.append({"time": item.get("time", ""), "sentence": item["sentence"], "repeat": item.get("repeat", 1),
                        "similar": item.get("similar", []), "file": item.get("file", ""),
                        "host": item.get("host", ""), "reasons": item["reasons"], "techniques": techniques,
                        "node": node_of.get(first), "gap": gap_of.get(first), "search": search})
    return {"rows": rows, "entries": entries, "flagged": flagged or [],
            "event_count": sum(item.get("repeat", 1) for item in timeline or []),
            "has_gaps": any("hidden" in item for row in rows for item in row["items"])}


def _script_json(data):
    """JSON that is safe inside a <script> tag: no "<", ">" or "&" that could end the tag."""
    return (json.dumps(data).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026"))


def visualize_graph(G, output_file="event_graph.html", timeline=None, flagged=None):
    """Writes the report: a self-contained HTML page with the timeline graph (each log
    file as a left-to-right row), every suspicious event, and the files that need
    manual review. G can be None when no events could be read."""
    print(f"\n{Fore.YELLOW}--- Saving Report ---{Style.RESET_ALL}")

    # cdn_resources="in_line" embeds the vis.js files in the HTML itself, so pyvis
    # doesn't copy a lib/ folder into the working directory and the page opens
    # offline. The nodes are added by the page's own script (report_page.py), so
    # hidden stretches can be opened and closed.
    net = Network(directed=True, height="75vh", width="100%", bgcolor="#222222",
                  neighborhood_highlight=False, cdn_resources="in_line")
    net.set_options(json.dumps(GRAPH_OPTIONS))

    header = report_page.HEADER % {"suspicious": COLORS[SUSPICIOUS], "notable": COLORS[NOTABLE],
                                   "routine": COLORS[ROUTINE], "gap": GAP_COLOR}
    script = report_page.SCRIPT.replace("__REPORT_DATA__", _script_json(report_data(G, timeline, flagged)))

    output_file = Path(output_file)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    page = net.generate_html(name=str(output_file))
    # pyvis links Bootstrap from a CDN; the page doesn't need it and should work offline
    page = re.sub(r'<link\s+href="https://cdn\.jsdelivr\.net[^>]*>', "", page)
    page = re.sub(r'<script\s+src="https://cdn\.jsdelivr\.net[^>]*>\s*</script>', "", page)
    page = page.replace("<center>\n          <h1></h1>\n        </center>", "")
    page = page.replace("</head>", "<title>L.A.A.S.T Event Graph and Report</title>" + report_page.STYLE + "</head>", 1)
    page = page.replace("<body>", "<body>" + header + report_page.OTHER_VIEWS + script, 1)
    page = page.replace("\n                  return network;", "\n                  setUpReport();\n                  return network;", 1)
    # Write the page ourselves as UTF-8. pyvis's write_html uses the system default
    # encoding (cp1252 on Windows), which can't encode the embedded vis-network script.
    output_file.write_text(page, encoding="utf-8")
    print(f"{Fore.GREEN}Report saved to '{output_file}'. Open it in a web browser.{Style.RESET_ALL}")
    return output_file
