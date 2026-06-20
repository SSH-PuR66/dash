# --- ingestion/feed_normalizer.py ---
import json
import logging
import os
from collections import OrderedDict
from datetime import datetime, timezone
from typing import Optional
from kafka import KafkaConsumer, KafkaProducer
from kafka.errors import KafkaError
from elasticsearch import Elasticsearch, helpers
import requests

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
log = logging.getLogger("intel.normalizer")

KAFKA_BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP", "localhost:9092")
ES_URL          = os.getenv("ES_URL", "http://localhost:9200")
ES_USER         = os.getenv("ES_USER", "elastic")
ES_PASS         = os.getenv("ES_PASS", "changeme")
IPINFO_TOKEN    = os.getenv("IPINFO_TOKEN", "")
GEO_CACHE_MAX   = 10_000

es = Elasticsearch(ES_URL, basic_auth=(ES_USER, ES_PASS), verify_certs=False)

# LRU-capped geo cache — prevents unbounded memory growth on long-running instances
_geo_cache: OrderedDict[str, dict] = OrderedDict()

SOURCE_WEIGHTS = {
    "misp":       1.2,
    "otx":        1.0,
    "abuseipdb":  1.1,
    "greynoise":  1.0,
}


def geoip_lookup(ip: str) -> dict:
    if ip in _geo_cache:
        _geo_cache.move_to_end(ip)
        return _geo_cache[ip]
    result: dict = {}
    if IPINFO_TOKEN:
        try:
            resp = requests.get(
                f"https://ipinfo.io/{ip}/json",
                headers={"Authorization": f"Bearer {IPINFO_TOKEN}"},
                timeout=5,
            )
            if resp.status_code == 200:
                data = resp.json()
                result = {
                    "country": data.get("country"),
                    "city":    data.get("city"),
                    "org":     data.get("org"),
                    "asn":     (data.get("org") or "").split()[0] or None,
                    "loc":     data.get("loc"),
                }
        except requests.RequestException as exc:
            log.debug("GeoIP lookup failed for %s: %s", ip, exc)
    _geo_cache[ip] = result
    if len(_geo_cache) > GEO_CACHE_MAX:
        _geo_cache.popitem(last=False)
    return result


def severity_from_score(score: int) -> str:
    if score >= 90:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 50:
        return "medium"
    return "low"


def enrich(indicator: dict) -> dict:
    enriched = dict(indicator)
    enriched["enriched_at"] = datetime.now(timezone.utc).isoformat()

    if indicator.get("type") == "ip":
        enriched["geo"] = geoip_lookup(indicator["value"])

    weight    = SOURCE_WEIGHTS.get(indicator.get("source", ""), 1.0)
    raw_conf  = int(indicator.get("confidence") or 50)
    score     = min(100, int(raw_conf * weight))
    enriched["severity_score"] = score
    enriched["severity"]       = severity_from_score(score)
    return enriched


def index_to_es(docs: list[dict]):
    if not docs:
        return
    actions = [
        {"_index": "threat-indicators", "_id": doc["id"], "_source": doc}
        for doc in docs
    ]
    try:
        success, errors = helpers.bulk(es, actions, raise_on_error=False)
        if errors:
            log.error("ES bulk errors (first 3): %s", errors[:3])
        log.info("Indexed %d documents", success)
    except Exception as exc:
        log.error("Elasticsearch bulk index failed: %s", exc)


def run():
    import signal
    _shutdown = False

    def _handle_signal(signum, frame):
        nonlocal _shutdown
        log.info("Shutdown signal received (sig=%d), flushing buffer...", signum)
        _shutdown = True

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    consumer = KafkaConsumer(
        "threat.intel.raw",
        bootstrap_servers=KAFKA_BOOTSTRAP,
        value_deserializer=lambda b: json.loads(b.decode("utf-8")),
        group_id="intel-normalizer",
        auto_offset_reset="earliest",
        enable_auto_commit=False,
        max_poll_records=100,
    )
    producer = KafkaProducer(
        bootstrap_servers=KAFKA_BOOTSTRAP,
        value_serializer=lambda v: json.dumps(v).encode("utf-8"),
        acks="all",
        retries=3,
    )

    log.info("Normalizer consumer started")
    buffer: list[dict] = []

    try:
        while not _shutdown:
            batch = consumer.poll(timeout_ms=3000)
            if not batch:
                continue
            for topic_partition, messages in batch.items():
                for message in messages:
                    try:
                        enriched = enrich(message.value)
                        buffer.append(enriched)
                        producer.send("threat.intel.enriched", value=enriched)
                    except Exception as exc:
                        log.error("Enrichment failed for %s: %s",
                                  message.value.get("value"), exc)

            if len(buffer) >= 50:
                index_to_es(buffer)
                buffer.clear()
                consumer.commit()
    finally:
        if buffer:
            index_to_es(buffer)
        consumer.commit()
        producer.flush()
        producer.close()
        consumer.close()
        log.info("Normalizer shut down cleanly")


if __name__ == "__main__":
    run()