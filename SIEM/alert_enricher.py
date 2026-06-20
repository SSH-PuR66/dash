# --- siem/alert_enricher.py ---
import json
import logging
import os
from datetime import datetime, timezone
from typing import Optional                   # was missing — crashed Flask on startup
from flask import Flask, request, jsonify
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from elasticsearch import Elasticsearch

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
log = logging.getLogger("siem.enricher")

app = Flask(__name__)

ES_URL            = os.getenv("ES_URL",    "http://localhost:9200")
ES_USER           = os.getenv("ES_USER",   "elastic")
ES_PASS           = os.getenv("ES_PASS",   "changeme")
SPLUNK_HEC_URL    = os.getenv("SPLUNK_HEC_URL",   "")
SPLUNK_HEC_TOKEN  = os.getenv("SPLUNK_HEC_TOKEN",  "")
PAGERDUTY_KEY     = os.getenv("PAGERDUTY_INTEGRATION_KEY", "")
ENRICH_THRESHOLD  = int(os.getenv("ENRICH_THRESHOLD", "70"))

es = Elasticsearch(ES_URL, basic_auth=(ES_USER, ES_PASS), verify_certs=False)

OBSERVABLE_FIELDS = {
    "ip":     ["srcip", "src_ip", "dstip", "dst_ip"],
    "domain": ["domain", "hostname", "dns_question_name"],
    "hash":   ["md5", "sha1", "sha256", "hash"],
}


def extract_observables(alert: dict) -> list[tuple[str, str]]:
    observables: set[tuple[str, str]] = set()
    data = alert.get("data") or {}

    for itype, fields in OBSERVABLE_FIELDS.items():
        for field in fields:
            val = data.get(field) or alert.get(field)
            if not val:
                # Check syscheck for hash fields
                val = (data.get("syscheck") or {}).get(field)
            if val and isinstance(val, str):
                observables.add((val.strip().lower(), itype))

    return list(observables)


def lookup_indicator(value: str, itype: str) -> Optional[dict]:
    try:
        result = es.search(
            index="threat-indicators",
            body={
                "query": {
                    "bool": {
                        "must": [
                            {"term": {"value.keyword": value}},
                            {"term": {"type.keyword":  itype}},
                        ]
                    }
                },
                "size": 1,
            },
        )
        hits = result["hits"]["hits"]
        if hits:
            return hits[0]["_source"]
    except Exception as exc:
        log.error("ES lookup failed for %s/%s: %s", itype, value, exc)
    return None


def forward_to_splunk(enriched_alert: dict):
    if not SPLUNK_HEC_URL or not SPLUNK_HEC_TOKEN:
        return
    payload = {
        "time":       datetime.now(timezone.utc).timestamp(),
        "sourcetype": "sentinelflow:alert",
        "source":     "wazuh-enricher",
        "index":      "main",
        "event":      enriched_alert,
    }
    try:
        resp = requests.post(
            SPLUNK_HEC_URL,
            headers={"Authorization": f"Splunk {SPLUNK_HEC_TOKEN}"},
            json=payload,
            timeout=5,
            verify=False,
        )
        if resp.status_code != 200:
            log.error("Splunk HEC rejected: %d %s", resp.status_code, resp.text[:200])
    except requests.RequestException as exc:
        log.error("Splunk HEC forward failed: %s", exc)


def page_on_critical(alert: dict, indicator: dict):
    if not PAGERDUTY_KEY:
        return
    payload = {
        "routing_key":  PAGERDUTY_KEY,
        "event_action": "trigger",
        "dedup_key":    f"sentinelflow-{alert.get('id', 'unknown')}",
        "payload": {
            "summary": (
                f"[CRITICAL] Indicator match: {indicator['value']} "
                f"({indicator['type']}) score={indicator['severity_score']}"
            ),
            "severity": "critical",
            "source":   "SentinelFlow",
            "custom_details": {
                "indicator":  indicator,
                "wazuh_rule": alert.get("rule",  {}),
                "agent":      alert.get("agent", {}),
            },
        },
    }
    try:
        resp = requests.post(
            "https://events.pagerduty.com/v2/enqueue",
            json=payload,
            timeout=5,
        )
        if resp.status_code not in (200, 202):
            log.error("PagerDuty enqueue failed: %s", resp.text[:200])
    except requests.RequestException as exc:
        log.error("PagerDuty call failed: %s", exc)


@app.route("/healthz", methods=["GET"])
def healthz():
    return jsonify({"status": "ok"}), 200


@app.route("/alert", methods=["POST"])
def receive_alert():
    try:
        alert = request.get_json(force=True)
        if not alert:
            raise ValueError("empty body")
    except Exception:
        return jsonify({"error": "invalid JSON"}), 400

    observables = extract_observables(alert)
    matches: list[dict] = []

    for value, itype in observables:
        indicator = lookup_indicator(value, itype)
        if indicator and indicator.get("severity_score", 0) >= ENRICH_THRESHOLD:
            matches.append(indicator)

    max_score = max((m["severity_score"] for m in matches), default=0)

    enriched = {
        **alert,
        "sentinelflow": {
            "enriched_at":       datetime.now(timezone.utc).isoformat(),
            "indicator_matches": matches,
            "match_count":       len(matches),
            "max_severity_score":max_score,
        },
    }

    forward_to_splunk(enriched)

    if matches and max_score >= 90:
        top = max(matches, key=lambda m: m["severity_score"])
        page_on_critical(alert, top)

    log.info(
        "Alert processed: %d observables, %d matches, max_score=%d",
        len(observables), len(matches), max_score,
    )
    return jsonify({"status": "ok", "matches": len(matches)}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=False)