# --- api/query_layer.py ---
import os
import logging
from typing import Optional
from flask import Flask, request, jsonify
from elasticsearch import Elasticsearch
from neo4j import GraphDatabase
from neo4j.exceptions import Neo4jError

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
log = logging.getLogger("intel.api")

app = Flask(__name__)

ES_URL     = os.getenv("ES_URL",    "http://localhost:9200")
ES_USER    = os.getenv("ES_USER",   "elastic")
ES_PASS    = os.getenv("ES_PASS",   "changeme")
NEO4J_URI  = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER","neo4j")
NEO4J_PASS = os.getenv("NEO4J_PASS","changeme")

es           = Elasticsearch(ES_URL, basic_auth=(ES_USER, ES_PASS), verify_certs=False)
neo4j_driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))


@app.route("/healthz", methods=["GET"])
def healthz():
    return jsonify({"status": "ok"}), 200


@app.route("/api/v1/indicator/<itype>/<path:value>", methods=["GET"])
def lookup_indicator(itype: str, value: str):
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
        if not hits:
            return jsonify({"found": False}), 404
        return jsonify({"found": True, "indicator": hits[0]["_source"]}), 200
    except Exception as exc:
        log.error("Indicator lookup failed: %s", exc)
        return jsonify({"error": str(exc)}), 500


@app.route("/api/v1/search", methods=["POST"])
def search_indicators():
    body         = request.get_json(force=True) or {}
    severity_min = int(body.get("severity_min", 0))
    itype        = body.get("type")
    source       = body.get("source")
    tag          = body.get("tag")
    page_size    = min(int(body.get("size", 50)),  500)
    page_from    = max(int(body.get("from", 0)),     0)

    must_clauses = [{"range": {"severity_score": {"gte": severity_min}}}]
    if itype:
        must_clauses.append({"term": {"type.keyword":   itype}})
    if source:
        must_clauses.append({"term": {"source.keyword": source}})
    if tag:
        must_clauses.append({"term": {"tags.keyword":   tag}})

    try:
        result = es.search(
            index="threat-indicators",
            body={
                "query": {"bool": {"must": must_clauses}},
                "sort":  [{"severity_score": {"order": "desc"}}],
                "size":  page_size,
                "from":  page_from,
            },
        )
        hits = result["hits"]["hits"]
        return jsonify({
            "total":   result["hits"]["total"]["value"],
            "results": [h["_source"] for h in hits],
        }), 200
    except Exception as exc:
        log.error("Search failed: %s", exc)
        return jsonify({"error": str(exc)}), 500


@app.route("/api/v1/graph/neighbors/<itype>/<path:value>", methods=["GET"])
def graph_neighbors(itype: str, value: str):
    cypher = """
    MATCH (i:Indicator {value: $value, type: $itype})-[r]-(neighbor)
    RETURN type(r)         AS rel_type,
           labels(neighbor) AS neighbor_labels,
           properties(neighbor) AS neighbor_props
    LIMIT 50
    """
    try:
        with neo4j_driver.session() as session:
            records = session.run(cypher, value=value, itype=itype)
            neighbors = [
                {
                    "relationship":     rec["rel_type"],
                    "neighbor_labels":  rec["neighbor_labels"],
                    "neighbor":         dict(rec["neighbor_props"]),
                }
                for rec in records
            ]
        return jsonify({"value": value, "type": itype, "neighbors": neighbors}), 200
    except Neo4jError as exc:
        log.error("Graph neighbor query failed: %s", exc)
        return jsonify({"error": str(exc)}), 500


@app.route("/api/v1/stats", methods=["GET"])
def stats():
    try:
        aggs = es.search(
            index="threat-indicators",
            body={
                "size": 0,
                "aggs": {
                    "by_type":       {"terms": {"field": "type.keyword",     "size": 10}},
                    "by_source":     {"terms": {"field": "source.keyword",   "size": 10}},
                    "by_severity":   {"terms": {"field": "severity.keyword", "size":  5}},
                    "avg_score":     {"avg":   {"field": "severity_score"}},
                    "total_critical":{"filter": {"range": {"severity_score": {"gte": 90}}}},
                },
            },
        )
        a = aggs["aggregations"]
        return jsonify({
            "total":               aggs["hits"]["total"]["value"],
            "by_type":             {b["key"]: b["doc_count"] for b in a["by_type"]["buckets"]},
            "by_source":           {b["key"]: b["doc_count"] for b in a["by_source"]["buckets"]},
            "by_severity":         {b["key"]: b["doc_count"] for b in a["by_severity"]["buckets"]},
            "avg_severity_score":  round(a["avg_score"]["value"] or 0, 1),
            "critical_count":      a["total_critical"]["doc_count"],
        }), 200
    except Exception as exc:
        log.error("Stats query failed: %s", exc)
        return jsonify({"error": str(exc)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)