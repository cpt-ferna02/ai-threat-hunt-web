import anthropic
import os
import json
from dotenv import load_dotenv

load_dotenv()
client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))


def analyze_logs(parsed_logs: dict) -> dict:
    """
    Send parsed log data to Claude for threat analysis.
    Returns a structured incident report.
    """

    # Serialize events — truncate very large payloads
    events_text = json.dumps(parsed_logs["events"], indent=2)
    if len(events_text) > 30000:
        events_text = events_text[:30000] + "\n... [truncated for context window]"

    prompt = f"""You are a senior SOC analyst and threat hunter. Analyze the following log data for malicious activity, indicators of compromise, and attack patterns.

Log Source Format: {parsed_logs['format']}
Total Events: {parsed_logs['event_count']}
Parse Summary: {parsed_logs['summary']}

LOG DATA:
{events_text}

Perform a thorough threat hunt analysis and return ONLY a valid JSON object with this exact structure (no markdown, no text outside JSON):

{{
  "threat_detected": true or false,
  "overall_severity": "Critical | High | Medium | Low | Informational",
  "executive_summary": "2-3 sentence plain-English summary of what you found",
  "attack_timeline": [
    {{
      "timestamp": "ISO timestamp or best estimate",
      "event": "What happened",
      "mitre_technique": "T1XXX — Name or N/A",
      "significance": "Why this matters"
    }}
  ],
  "mitre_techniques": [
    {{
      "technique_id": "T1XXX.XXX",
      "technique_name": "Name",
      "evidence": "Specific log evidence supporting this",
      "severity": "Critical | High | Medium | Low"
    }}
  ],
  "iocs": [
    {{
      "type": "IP | Domain | Hash | User | Process | File | Command",
      "value": "The actual IOC value",
      "context": "Why this is suspicious"
    }}
  ],
  "kill_chain_stage": "Reconnaissance | Weaponization | Delivery | Exploitation | Installation | C2 | Actions on Objectives | Multiple | Unknown",
  "kill_chain_analysis": "Paragraph describing where in the kill chain the activity sits",
  "recommendations": [
    "Specific actionable remediation step 1",
    "Specific actionable remediation step 2",
    "Specific actionable remediation step 3"
  ],
  "false_positive_assessment": "Assessment of whether any findings could be benign activity",
  "confidence": "High | Medium | Low",
  "analyst_notes": "Any additional technical observations"
}}

Be thorough and technically precise. Reference specific field values from the logs as evidence. If no threats are detected, still provide a complete analysis explaining why the logs appear clean."""

    message = client.messages.create(
        model="claude-opus-4-5",
        max_tokens=4096,
        messages=[{"role": "user", "content": prompt}]
    )

    raw = message.content[0].text.strip()
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]
    raw = raw.strip()

    return json.loads(raw)