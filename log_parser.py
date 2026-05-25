import json
import csv
import io
import re
from pathlib import Path

try:
    from evtx import PyEvtxParser
    EVTX_AVAILABLE = True
except ImportError:
    EVTX_AVAILABLE = False


def detect_format(filename: str, content: str) -> str:
    """Auto-detect log format from filename and content."""
    filename_lower = filename.lower()

    if filename_lower.endswith(".evtx"):
        return "evtx"
    if filename_lower.endswith(".json"):
        return "json"
    if filename_lower.endswith(".csv"):
        return "csv"

    # Heuristic detection for raw text
    if "<Event" in content or "EventID" in content:
        return "windows_xml"
    if '"host"' in content and '"source"' in content:
        return "splunk"
    if '"rule"' in content and '"agent"' in content:
        return "wazuh"

    return "raw"


def parse_evtx(filepath: str) -> list[dict]:
    """Parse Windows EVTX binary log file."""
    if not EVTX_AVAILABLE:
        return [{"error": "python-evtx not installed. Run: pip install python-evtx"}]

    events = []
    parser = PyEvtxParser(filepath)
    for record in parser.records_json():
        try:
            data = json.loads(record["data"])
            event = data.get("Event", {})
            sys_data = event.get("System", {})
            event_data = event.get("EventData", {})
            events.append({
                "EventID": sys_data.get("EventID", {}).get("#text", ""),
                "TimeCreated": sys_data.get("TimeCreated", {}).get("@SystemTime", ""),
                "Provider": sys_data.get("Provider", {}).get("@Name", ""),
                "Computer": sys_data.get("Computer", ""),
                "EventData": event_data,
                "raw": record["data"][:500]
            })
        except Exception:
            continue
    return events[:200]  # Cap at 200 events


def parse_json_logs(content: str) -> list[dict]:
    """Parse JSON log files — handles array or newline-delimited JSON."""
    events = []
    content = content.strip()

    # Try array first
    if content.startswith("["):
        try:
            data = json.loads(content)
            return data[:200] if isinstance(data, list) else [data]
        except json.JSONDecodeError:
            pass

    # Try newline-delimited JSON (NDJSON)
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            events.append({"raw_line": line})
        if len(events) >= 200:
            break

    return events


def parse_csv_logs(content: str) -> list[dict]:
    """Parse CSV log files."""
    reader = csv.DictReader(io.StringIO(content))
    return [row for i, row in enumerate(reader) if i < 200]


def parse_raw_text(content: str) -> list[dict]:
    """Parse raw text logs — splits by line and wraps each."""
    lines = [l.strip() for l in content.splitlines() if l.strip()]
    return [{"line": i + 1, "content": line} for i, line in enumerate(lines[:200])]


def parse_logs(filepath: str = None, raw_content: str = None, filename: str = "") -> dict:
    """
    Main entry point. Accepts either a file path or raw pasted content.
    Returns: { format, event_count, events, summary }
    """
    content = ""

    if filepath:
        path = Path(filepath)
        if path.suffix.lower() == ".evtx":
            events = parse_evtx(filepath)
            return {
                "format": "Windows EVTX",
                "event_count": len(events),
                "events": events,
                "summary": f"Parsed {len(events)} Windows Event Log records from EVTX binary"
            }
        else:
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
            filename = path.name
    else:
        content = raw_content or ""
        filename = filename or "pasted_content.txt"

    fmt = detect_format(filename, content)

    if fmt == "json" or fmt == "splunk" or fmt == "wazuh":
        events = parse_json_logs(content)
        label = {"json": "JSON", "splunk": "Splunk JSON", "wazuh": "Wazuh JSON"}.get(fmt, "JSON")
    elif fmt == "csv":
        events = parse_csv_logs(content)
        label = "CSV"
    elif fmt == "windows_xml":
        events = parse_raw_text(content)
        label = "Windows XML"
    else:
        events = parse_raw_text(content)
        label = "Raw Text"

    return {
        "format": label,
        "event_count": len(events),
        "events": events,
        "summary": f"Parsed {len(events)} log entries ({label} format)"
    }