# --- entity_graph/graph_loader.py ---
import json
import logging
import os
from kafka import KafkaConsumer
from neo4j import GraphDatabase
from neo4j.exceptions import Neo4jError

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
log = logging.getLogger("intel.graphloader")

NEO4J_URI       = os.getenv("NEO4J_URI",   "bolt://localhost:7687")
NEO4J_USER      = os.getenv("NEO4J_USER",  "neo4j")
NEO4J_PASS      = os.getenv("NEO4J_PASS",  "changeme")
KAFKA_BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP", "localhost:9092")

UPSERT_INDICATOR = """
MERGE (i:Indicator {value: $value, type: $itype})
ON CREATE SET
    i.first_seen    = $first_seen,
    i.severity      = $severity,
    i.severity_score= $severity_score,
    i.tlp           = $tlp,
    i.created_at    = timestamp()
ON MATCH SET
    i.last_seen     = $first_seen,
    i.severity_score= CASE WHEN $severity_score > i.severity_score
                          THEN $severity_score ELSE i.severity_score END,
    i.severity      = CASE WHEN $severity_score > i.severity_score
                          THEN $severity ELSE i.severity END,
    i.updated_at    = timestamp()
"""

UPSERT_SOURCE = "MERGE (s:Source {name: $source})"

CREATE_SEEN_BY = """
MATCH (i:Indicator {value: $value, type: $itype})
MATCH (s:Source    {name: $source})
MERGE (i)-[r:SEEN_BY]->(s)
ON CREATE SET r.first_seen = $first_seen, r.confidence = $confidence
ON MATCH  SET r.last_seen  = $first_seen,
              r.confidence = CASE WHEN $confidence > r.confidence
                                  THEN $confidence ELSE r.confidence END
"""

UPSERT_TAG      = "MERGE (t:Tag {name: $tag})"
CREATE_HAS_TAG  = """
MATCH (i:Indicator {value: $value, type: $itype})
MATCH (t:Tag       {name: $tag})
MERGE (i)-[:HAS_TAG]->(t)
"""

UPSERT_GEO = """
MERGE (g:GeoLocation {country: $country})
ON CREATE SET g.asn = $asn
ON MATCH  SET g.asn = COALESCE($asn, g.asn)
"""

CREATE_LOCATED_IN = """
MATCH (i:Indicator   {value: $value, type: $itype})
MATCH (g:GeoLocation {country: $country})
MERGE (i)-[:LOCATED_IN]->(g)
"""


def load_indicator(session, indicator: dict):
    itype  = indicator.get("type",   "unknown")
    value  = indicator.get("value",  "")
    source = indicator.get("source", "unknown")

    session.run(UPSERT_INDICATOR, {
        "value":         value,
        "itype":         itype,
        "first_seen":    indicator.get("first_seen"),
        "severity":      indicator.get("severity",       "low"),
        "severity_score":indicator.get("severity_score", 0),
        "tlp":           indicator.get("tlp",            "white"),
    })
    session.run(UPSERT_SOURCE, {"source": source})
    session.run(CREATE_SEEN_BY, {
        "value":      value,
        "itype":      itype,
        "source":     source,
        "first_seen": indicator.get("first_seen"),
        "confidence": indicator.get("confidence", 50),
    })

    for raw_tag in indicator.get("tags", []):
        tag_name = raw_tag if isinstance(raw_tag, str) else raw_tag.get("name", "")
        tag_name = tag_name.strip()
        if not tag_name:
            continue
        session.run(UPSERT_TAG,     {"tag": tag_name})
        session.run(CREATE_HAS_TAG, {"value": value, "itype": itype, "tag": tag_name})

    geo     = indicator.get("geo") or {}
    country = geo.get("country")
    if country and itype == "ip":
        session.run(UPSERT_GEO,        {"country": country, "asn": geo.get("asn")})
        session.run(CREATE_LOCATED_IN, {"value": value, "itype": itype, "country": country})


def run():
    import signal
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))
    _shutdown = False

    def _handle_signal(signum, frame):
        nonlocal _shutdown
        log.info("Shutdown signal received (sig=%d), finishing current batch...", signum)
        _shutdown = True

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    consumer = KafkaConsumer(
        "threat.intel.enriched",
        bootstrap_servers=KAFKA_BOOTSTRAP,
        value_deserializer=lambda b: json.loads(b.decode("utf-8")),
        group_id="graph-loader",
        auto_offset_reset="earliest",
        enable_auto_commit=False,
        max_poll_records=50,
        consumer_timeout_ms=5000,
    )

    log.info("Graph loader started")
    count = 0

    try:
        while not _shutdown:
            batch = consumer.poll(timeout_ms=3000)
            if not batch:
                continue
            with driver.session() as neo_session:
                for topic_partition, messages in batch.items():
                    for message in messages:
                        try:
                            load_indicator(neo_session, message.value)
                            count += 1
                        except Neo4jError as exc:
                            log.error("Neo4j write failed: %s", exc)
                        except Exception as exc:
                            log.error("Graph load error: %s", exc)
            consumer.commit()
            log.info("Committed batch, total records: %d", count)
    finally:
        consumer.close()
        driver.close()
        log.info("Graph loader shut down cleanly after %d records", count)


if __name__ == "__main__":
    run()