# --- ingestion/kafka_producer.py ---
import json
import time
import logging
import os
import hashlib
from datetime import datetime, timezone
from typing import Optional
from kafka import KafkaProducer
from kafka.errors import KafkaError
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
log = logging.getLogger("intel.producer")

KAFKA_BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP", "localhost:9092")
MISP_URL        = os.getenv("MISP_URL", "https://misp.internal")
MISP_KEY        = os.getenv("MISP_API_KEY", "")
OTX_KEY         = os.getenv("OTX_API_KEY", "")
ABUSEIPDB_KEY   = os.getenv("ABUSEIPDB_KEY", "")
GREYNOISE_KEY   = os.getenv("GREYNOISE_KEY", "")
POLL_INTERVAL   = int(os.getenv("POLL_INTERVAL_SECONDS", "300"))

ITYPE_MAP = {
    "ip-dst": "ip", "ip-src": "ip",
    "domain": "domain", "hostname": "domain",
    "url": "url", "md5": "hash",
    "sha1": "hash", "sha256": "hash",
}

OTX_ITYPE_MAP = {
    "IPv4": "ip", "IPv6": "ip",
    "domain": "domain", "hostname": "domain",
    "URL": "url", "FileHash-MD5": "hash",
    "FileHash-SHA1": "hash", "FileHash-SHA256": "hash",
}


def build_producer() -> KafkaProducer:
    return KafkaProducer(
        bootstrap_servers=KAFKA_BOOTSTRAP,
        value_serializer=lambda v: json.dumps(v).encode("utf-8"),
        acks="all",
        retries=5,
        retry_backoff_ms=500,
        compression_type="gzip",
    )


def normalize_indicator(
    value: str,
    itype: str,
    source: str,
    confidence: int,
    tags: list[str],
    tlp: str = "white",
    extra: Optional[dict] = None,
) -> dict:
    return {
        "id": hashlib.sha256(f"{source}:{itype}:{value}".encode()).hexdigest()[:16],
        "value": value,
        "type": itype,
        "source": source,
        "confidence": max(0, min(100, confidence)),
        "tlp": tlp,
        "tags": [t for t in tags if t],
        "first_seen": datetime.now(timezone.utc).isoformat(),
        "extra": extra or {},
    }


def fetch_misp_events(session: requests.Session) -> list[dict]:
    indicators = []
    if not MISP_KEY:
        log.warning("MISP_API_KEY not set — skipping MISP feed")
        return indicators
    try:
        resp = session.get(
            f"{MISP_URL}/events/index",
            headers={"Authorization": MISP_KEY, "Accept": "application/json"},
            timeout=15,
            verify=False,
        )
        resp.raise_for_status()
        for event in resp.json()[:50]:
            eid = event.get("Event", {}).get("id")
            if not eid:
                continue
            detail_resp = session.get(
                f"{MISP_URL}/events/{eid}",
                headers={"Authorization": MISP_KEY, "Accept": "application/json"},
                timeout=15,
                verify=False,
            )
            detail_resp.raise_for_status()
            for attr in detail_resp.json().get("Event", {}).get("Attribute", []):
                atype = attr.get("type", "")
                aval  = attr.get("value", "").strip()
                mapped = ITYPE_MAP.get(atype)
                if not mapped or not aval:
                    continue
                raw_tags = attr.get("Tag", [])
                tag_names = [
                    t.get("name", "") if isinstance(t, dict) else str(t)
                    for t in raw_tags
                ]
                indicators.append(normalize_indicator(
                    value=aval,
                    itype=mapped,
                    source="misp",
                    confidence=int(attr.get("confidence") or 50),
                    tags=tag_names,
                    tlp="amber",
                    extra={"misp_event_id": eid, "misp_type": atype},
                ))
    except requests.RequestException as exc:
        log.error("MISP fetch failed: %s", exc)
    return indicators


def fetch_otx_pulses(session: requests.Session) -> list[dict]:
    indicators = []
    if not OTX_KEY:
        log.warning("OTX_API_KEY not set — skipping OTX feed")
        return indicators
    try:
        resp = session.get(
            "https://otx.alienvault.com/api/v1/pulses/subscribed",
            headers={"X-OTX-API-KEY": OTX_KEY},
            timeout=15,
        )
        resp.raise_for_status()
        for pulse in resp.json().get("results", []):
            tags = pulse.get("tags", [])
            for ind in pulse.get("indicators", []):
                mapped = OTX_ITYPE_MAP.get(ind.get("type"))
                val    = (ind.get("indicator") or "").strip()
                if not mapped or not val:
                    continue
                indicators.append(normalize_indicator(
                    value=val,
                    itype=mapped,
                    source="otx",
                    confidence=70,
                    tags=tags,
                    extra={
                        "pulse_id":   pulse.get("id"),
                        "pulse_name": pulse.get("name"),
                    },
                ))
    except requests.RequestException as exc:
        log.error("OTX fetch failed: %s", exc)
    return indicators


def fetch_abuseipdb(session: requests.Session) -> list[dict]:
    indicators = []
    if not ABUSEIPDB_KEY:
        log.warning("ABUSEIPDB_KEY not set — skipping AbuseIPDB feed")
        return indicators
    try:
        resp = session.get(
            "https://api.abuseipdb.com/api/v2/blacklist",
            headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
            params={"confidenceMinimum": 90, "limit": 500},
            timeout=15,
        )
        resp.raise_for_status()
        for entry in resp.json().get("data", []):
            ip = (entry.get("ipAddress") or "").strip()
            if not ip:
                continue
            indicators.append(normalize_indicator(
                value=ip,
                itype="ip",
                source="abuseipdb",
                confidence=int(entry.get("abuseConfidenceScore") or 90),
                tags=["abuse", "blacklist"],
                extra={
                    "country": entry.get("countryCode"),
                    "reports": entry.get("totalReports"),
                },
            ))
    except requests.RequestException as exc:
        log.error("AbuseIPDB fetch failed: %s", exc)
    return indicators


def fetch_greynoise(session: requests.Session) -> list[dict]:
    indicators = []
    if not GREYNOISE_KEY:
        log.warning("GREYNOISE_KEY not set — skipping GreyNoise feed")
        return indicators
    try:
        resp = session.get(
            "https://api.greynoise.io/v2/experimental/gnql",
            headers={"key": GREYNOISE_KEY},
            params={"query": "last_seen:1d classification:malicious", "size": 200},
            timeout=20,
        )
        if resp.status_code == 200:
            for entry in resp.json().get("data", []):
                ip = (entry.get("ip") or "").strip()
                if not ip:
                    continue
                indicators.append(normalize_indicator(
                    value=ip,
                    itype="ip",
                    source="greynoise",
                    confidence=85,
                    tags=entry.get("tags") or [],
                    extra={
                        "classification": entry.get("classification"),
                        "actor":          entry.get("actor"),
                        "asn":            (entry.get("metadata") or {}).get("asn"),
                    },
                ))
        else:
            log.warning("GreyNoise returned %d", resp.status_code)
    except requests.RequestException as exc:
        log.error("GreyNoise fetch failed: %s", exc)
    return indicators


def run():
    producer = build_producer()
    session  = requests.Session()
    session.headers["User-Agent"] = "SentinelFlow-IntelPipeline/1.0"

    log.info("Intel producer started. Poll interval: %ds", POLL_INTERVAL)

    while True:
        batch: list[dict] = []
        batch.extend(fetch_misp_events(session))
        batch.extend(fetch_otx_pulses(session))
        batch.extend(fetch_abuseipdb(session))
        batch.extend(fetch_greynoise(session))

        seen: set[str] = set()
        deduped: list[dict] = []
        for ind in batch:
            key = ind["id"]
            if key not in seen:
                seen.add(key)
                deduped.append(ind)

        dropped = len(batch) - len(deduped)
        log.info("Publishing %d indicators (%d dupes dropped)", len(deduped), dropped)

        for indicator in deduped:
            future = producer.send("threat.intel.raw", value=indicator)
            try:
                future.get(timeout=10)
            except KafkaError as exc:
                log.error("Kafka publish failed for %s: %s", indicator["value"], exc)

        producer.flush()
        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    run()