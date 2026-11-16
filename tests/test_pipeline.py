import json
import os
from pathlib import Path

import pytest

from scanner import find_log_files
from log_parser import load_miner, parse_text_line, process_logs, text_line_to_message
from grapher import MAX_STEPS, clean_template, generate_event_graph, timeline_rows, visualize_graph
from knowledge import SUSPICIOUS, explain_event
from summary import MAX_TIMELINE, build_timeline, find_brute_force, print_summary
import main as laast
import pacing

pacing.set_enabled(False)  # no pauses while testing

SAMPLES = Path(__file__).resolve().parent.parent / "Samples"


def test_scanner_finds_samples():
    found = find_log_files(SAMPLES)
    assert len(found["evtx"]) == 6
    assert len(found["text"]) == 1
    assert found["unreadable"] == []


@pytest.mark.skipif(os.name == "nt" or os.geteuid() == 0, reason="needs a non-root POSIX user")
def test_scanner_flags_unreadable_directory(tmp_path):
    locked = tmp_path / "locked"
    locked.mkdir()
    locked.chmod(0)
    try:
        found = find_log_files(tmp_path)
    finally:
        locked.chmod(0o755)
    assert [path for path, _ in found["unreadable"]] == [str(locked)]


def test_config_loads_from_any_directory(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)  # no drain3.ini here
    miner = load_miner()
    mask_names = {m.mask_with for m in miner.config.masking_instructions}
    assert {"IP", "UUID", "SID", "HEX", "NUM"} <= mask_names


def test_json_lines_are_reduced_to_event_and_message():
    line = json.dumps({"EventID": 4624, "SourceName": "Security", "Message": "An account\r\n\twas logged on.", "Hostname": "DC01"})
    assert text_line_to_message(line) == "EventID_4624 Provider=Security An account was logged on."


def test_plain_text_lines_pass_through():
    assert text_line_to_message("  plain   log line ") == "plain log line"


def test_evtx_records_are_mined():
    found = {"evtx": [SAMPLES / "CA_keefarce_keepass_credump.evtx", SAMPLES / "4794_DSRM_password_change_t1098.evtx"],
             "text": []}
    miner, flagged, sequences, events = process_logs(found)
    assert flagged == []
    assert sum(len(s) for s in sequences) == 6  # 5 + 1 records in these two samples
    templates = [c.get_template() for c in miner.drain.clusters]
    assert any("EventID_4794" in t for t in templates)


def test_no_edges_between_files(tmp_path):
    (tmp_path / "a.log").write_text("alpha event one\nalpha event two\n")
    (tmp_path / "b.log").write_text("beta thing happened\n")
    miner, _, sequences, events = process_logs(find_log_files(tmp_path))
    assert len(sequences) == 2
    graph = generate_event_graph(miner, sequences, events)
    alpha, beta = sequences[0][-1], sequences[1][0]
    assert not graph.has_edge(alpha, beta) and not graph.has_edge(beta, alpha)


def test_clean_template_collapses_wildcards():
    assert clean_template("User <*> <*>  logged\\r\\n on") == "User <*> logged on"


def test_html_output_is_plain_text_and_self_contained(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "evil.log").write_text('<img src=x onerror=alert(1)> injected\n')
    miner, _, sequences, events = process_logs(find_log_files(tmp_path))
    graph = generate_event_graph(miner, sequences, events)
    out = visualize_graph(graph, tmp_path / "graph.html")

    # Details are shown with textContent, so log text is never treated as HTML
    page = Path(out).read_text(encoding="utf-8")
    assert "textContent = item.details" in page
    assert "<img src=x" not in page
    assert "cdnjs.cloudflare.com" not in page  # vis.js is embedded, so it opens offline
    assert not (tmp_path / "lib").exists()  # pyvis no longer copies a lib/ folder


def test_html_is_written_as_utf8(tmp_path):
    # The embedded vis-network script contains characters that cp1252 (the Windows
    # default) can't encode, which crashed pyvis's own write_html on Windows.
    (tmp_path / "a.log").write_text("user logged on\n")
    miner, _, sequences, events = process_logs(find_log_files(tmp_path))
    out = visualize_graph(generate_event_graph(miner, sequences, events), tmp_path / "graph.html")
    page = Path(out).read_bytes().decode("utf-8")
    with pytest.raises(UnicodeEncodeError):
        page.encode("cp1252")


def test_events_are_explained_in_plain_english():
    found = {"evtx": sorted(SAMPLES.glob("CA_keefarce*.evtx")), "text": []}
    _, _, _, events = process_logs(found)
    explained = [explain_event(e) for e in events]
    start = next(x for e, x in zip(events, explained) if str(e["event_id"]) == "1")
    assert start["sentence"] == "KeeFarce.exe was started by cmd.exe from C:\\Users\\Public"
    assert start["severity"] == SUSPICIOUS
    assert "T1036" in start["techniques"]
    assert any("Masquerading" in reason for reason in start["reasons"])
    injection = next(x for e, x in zip(events, explained) if str(e["event_id"]) == "8")
    assert "T1055" in injection["techniques"]


def test_routine_events_are_not_flagged():
    event = {"event_id": 4624, "provider": "Microsoft-Windows-Security-Auditing",
             "fields": {"TargetUserName": "alice", "LogonType": 2, "IpAddress": "-"}}
    info = explain_event(event)
    assert info["severity"] != SUSPICIOUS
    assert info["sentence"] == "alice signed in at the keyboard"


def test_failed_sign_in_bursts_count_as_brute_force():
    events = [{"event_id": 4625, "time": f"2024-01-01 10:00:0{i}", "file": "a.evtx",
               "fields": {"TargetUserName": "admin", "IpAddress": "10.0.0.5"}} for i in range(6)]
    bursts = find_brute_force(events)
    assert len(bursts) == 1 and bursts[0]["techniques"] == ["T1110"]
    assert find_brute_force(events[:3]) == []


def test_summary_prints_timeline_and_conclusion(capsys):
    _, flagged, _, events = process_logs(find_log_files(SAMPLES))
    timeline = build_timeline(events)
    assert len(timeline) > MAX_TIMELINE
    assert any("KeeFarce.exe injected code into KeePass.exe" == item["sentence"] for item in timeline)
    capsys.readouterr()
    print_summary(events, timeline=timeline, flagged=flagged, report="event_graph.html")
    out = capsys.readouterr().out
    assert "Suspicious activity, in order" in out
    # The terminal shows the first few and says where the rest are
    assert f"The first {MAX_TIMELINE} of {len(timeline)}" in out
    assert "Suspicious activity tab" in out and "event_graph.html" in out
    assert "Masquerading (T1036)" in out
    assert "Needs manual review" in out and "damaged_security_log.evtx" in out


def test_summary_handles_all_equal_counts(capsys, tmp_path):
    (tmp_path / "a.log").write_text("alpha event\nbeta happened here\n")
    _, _, _, events = process_logs(find_log_files(tmp_path))
    print_summary(events)
    assert "nothing stands out by frequency" in capsys.readouterr().out


def test_leading_timestamps_are_pulled_out_of_text_lines():
    line, event = parse_text_line("2026-04-24T09:15:56+0000 [sshd] Accepted password for bob", "auth.log")
    assert event["time"] == "2026-04-24 09:15:56"
    assert line == "[sshd] Accepted password for bob"
    _, event = parse_text_line("Apr 24 09:15:56 host sshd[42]: Failed password", "auth.log")
    assert event["time"] == "Apr 24 09:15:56"


def test_json_logs_including_multi_line_objects(tmp_path):
    (tmp_path / "app.json").write_text(
        '{"timestamp": "2026-01-02T03:04:05Z", "eventid": "user.login", "message": "login ok"}\n'
        '{\n  "timestamp": "2026-01-02T03:04:06Z",\n  "eventid": "user.logout",\n  "message": "bye"\n}\n')
    _, flagged, _, events = process_logs(find_log_files(tmp_path))
    assert flagged == []
    assert [e["event_id"] for e in events] == ["user.login", "user.logout"]
    assert events[1]["time"] == "2026-01-02 03:04:06"


def test_text_lines_that_differ_only_by_ip_are_grouped(capsys, tmp_path):
    (tmp_path / "ips.txt").write_text("".join(f"10.0.0.{i}\n" for i in range(1, 30)) + "odd line\n")
    miner, _, _, events = process_logs(find_log_files(tmp_path))
    print_summary(events, {c.cluster_id: c.get_template() for c in miner.drain.clusters})
    out = capsys.readouterr().out
    assert "29" in out and "<IP>" in out


def test_graph_rows_merge_repeats_and_shorten_long_files(tmp_path):
    lines = ["service started\n"] * 3 + [f"step{i} happened\n" for i in range(MAX_STEPS + 40)]
    lines.insert(30, "KeeFarce.exe was run\n")  # one suspicious line in the middle
    (tmp_path / "big.log").write_text("".join(lines))
    (tmp_path / "small.log").write_text("a happened\nb happened\n")
    miner, _, sequences, events = process_logs(find_log_files(tmp_path))
    rows = dict(timeline_rows(generate_event_graph(miner, sequences, events)))

    assert [item[0] for item in rows["small.log"]] == ["step", "step"]
    big = rows["big.log"]
    assert big[0][0] == "step" and len(big[0][2]) == 3  # three repeats merged into one step
    assert any(item[0] == "gap" for item in big)  # routine stretches are hidden
    assert any(item[0] == "step" and "KeeFarce" in item[2][0]["message"] for item in big)
    assert sum(1 for item in big if item[0] == "step") <= MAX_STEPS


def test_password_spraying_is_detected():
    found = {"evtx": [SAMPLES / "kerberos_pwd_spray_4771.evtx"], "text": []}
    _, _, _, events = process_logs(found)
    bursts = find_brute_force(events)
    assert any(b["techniques"] == ["T1110.003"] for b in bursts)


def test_damaged_sample_is_flagged_for_manual_review():
    _, flagged, _, _ = process_logs({"evtx": [SAMPLES / "damaged_security_log.evtx"], "text": []})
    assert len(flagged) == 1 and "damaged" in flagged[0]["error"]


def test_empty_and_binary_text_logs_are_flagged(tmp_path):
    (tmp_path / "empty.log").write_text("")
    (tmp_path / "binary.log").write_bytes(b"MZ\x90\x00\x03\x00\x00\x00" * 200)
    (tmp_path / "fine.log").write_text("user logged on\n")
    _, flagged, _, events = process_logs(find_log_files(tmp_path))
    reasons = {Path(item["file"]).name: item["error"] for item in flagged}
    assert set(reasons) == {"empty.log", "binary.log"}
    assert "empty" in reasons["empty.log"] and "binary" in reasons["binary.log"]
    assert len(events) == 1


def _report_data(page):
    start = page.index("var REPORT = ") + len("var REPORT = ")
    return json.loads(page[start:page.index(";\n", start)])


def test_report_lists_every_suspicious_event_and_flagged_file(tmp_path):
    miner, flagged, sequences, events = process_logs(find_log_files(SAMPLES))
    timeline = build_timeline(events)
    graph = generate_event_graph(miner, sequences, events)
    page = Path(visualize_graph(graph, tmp_path / "r.html", timeline, flagged)).read_text(encoding="utf-8")
    data = _report_data(page)
    assert len(data["entries"]) == len(timeline)
    assert [Path(item["file"]).name for item in data["flagged"]] == ["damaged_security_log.evtx"]
    # Every entry that belongs to a drawn file points at a circle on the timeline
    drawn = {item["node"]["id"] for row in data["rows"] for item in row["items"]}
    drawn |= {node["id"] for row in data["rows"] for item in row["items"] for node in item.get("hidden", [])}
    assert all(entry["node"] in drawn for entry in data["entries"])
    assert "cdn.jsdelivr.net" not in page


def test_hidden_stretches_can_be_opened(tmp_path):
    lines = ["service started\n"] * 3 + [["user logged on\n", "cron ran job\n"][i % 2] for i in range(800)]
    (tmp_path / "big.log").write_text("".join(lines))
    miner, _, sequences, events = process_logs(find_log_files(tmp_path))
    page = Path(visualize_graph(generate_event_graph(miner, sequences, events), tmp_path / "r.html")).read_text(
        encoding="utf-8")
    gaps = [item for item in _report_data(page)["rows"][0]["items"] if "hidden" in item]
    assert gaps and all(item["node"]["kind"] == "gap" for item in gaps)
    # A very long stretch only opens its start and end, with the middle still summarized
    biggest = max(gaps, key=lambda item: len(item["hidden"]))
    assert any(node["kind"] == "gap" and not node["expandable"] for node in biggest["hidden"])
    assert "Contains:" in biggest["node"]["details"]


def test_html_only_skips_terminal_output(tmp_path, capsys):
    (tmp_path / "a.log").write_text("user logged on\n")
    out_file = tmp_path / "report.html"
    assert laast.main([str(tmp_path), "--html-only", "-o", str(out_file)]) == 0
    assert capsys.readouterr().out.strip() == f"Report saved to '{out_file}'."
    assert out_file.exists()
