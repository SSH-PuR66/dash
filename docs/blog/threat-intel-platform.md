---
title: "Building a Threat Intelligence Platform from Scratch — Kafka, Elasticsearch, Neo4j, and Flask"
published: false
description: "How I designed dash: a modular security intel stack that ingests feeds, enriches indicators, builds relationship graphs, and serves analyst queries."
tags: cybersecurity, python, elasticsearch, docker
cover_image: ""
canonical_url:
---

Most "threat intelligence" projects on GitHub are a single script that calls the VirusTotal API and prints JSON. That's fine for learning HTTP requests, but it doesn't show you understand how intel platforms actually work.

I wanted to build the real thing — or at least something that looks like it. So I built **dash**: a multi-service platform that handles the full intel lifecycle.

---

## Architecture

```
Threat feeds → Kafka → Normalizer → Elasticsearch
                                  → Enriched Kafka topic → Neo4j graph
                                  → SIEM alert enrichment
                                  → Flask API → Analyst dashboard
```

Each box is its own Python module. Each module reads from a queue or database and writes to the next one. If you kill the graph loader, feeds still get normalized and indexed. If Elasticsearch goes down, Kafka buffers the data. That's the point of a pipeline — each stage is independent.

---

## The feed normalizer

This is where raw intel becomes useful. The normalizer:

1. Consumes raw indicators from Kafka
2. Runs geo/IP enrichment via ipinfo.io (with LRU-capped caching to avoid hammering the API)
3. Scores indicators based on source reputation weights
4. Classifies severity (critical/high/medium/low/info)
5. Indexes enriched documents into Elasticsearch
6. Publishes to an enriched Kafka topic for downstream consumers

```python
SOURCE_WEIGHTS = {
    "misp":       1.2,
    "otx":        1.0,
    "abuseipdb":  1.1,
    "greynoise":  1.0,
}
```

The weights are simple but effective — MISP data gets a 20% boost because it's typically higher quality. In a production system you'd tune these based on your own false positive rates.

The geo cache is an `OrderedDict` with a max size. When it fills up, the oldest entry gets evicted. No Redis needed for a simple caching layer.

---

## The graph loader

This is my favorite part. Neo4j turns flat indicator data into a relationship graph:

```cypher
MERGE (i:Indicator {value: $value, type: $itype})
MERGE (s:Source {name: $source})
MERGE (i)-[r:SEEN_BY]->(s)
```

Every indicator connects to its sources, its geo location, and its tags. If two different feeds report the same IP, the graph shows that naturally — one node, two `SEEN_BY` edges.

This is how real analysts think: "This IP was reported by MISP *and* AbuseIPDB, it's geolocated in a high-risk country, and it's tagged as C2." That's a graph query, not a keyword search.

The Cypher uses `MERGE` + `ON CREATE/ON MATCH` to handle upserts cleanly — first sighting creates the node, subsequent sightings update the severity score if the new one is higher.

---

## The API layer

Flask serves analyst queries:

- `/indicators` — search Elasticsearch with filters
- `/graph/neighbors` — get related nodes from Neo4j
- `/stats` — aggregate counts for the dashboard

Nothing fancy here. The API is thin on purpose — it's a translation layer between the analyst's question and the data stores.

---

## Docker Compose

Everything runs as containers:

```yaml
services:
  kafka: ...
  elasticsearch: ...
  neo4j: ...
  normalizer: ...
  graph-loader: ...
  api: ...
  dashboard: ...
```

One `docker-compose up` and the entire stack is running. This is the difference between "I built a script" and "I built a platform" — the infra is part of the project.

---

## What I'd tell someone building their first security project

1. **Think in pipelines, not scripts.** If your whole project is one file, it doesn't demonstrate architecture skills.
2. **Use real data stores.** SQLite is fine for CRUD apps, but if you're building an intel platform, use Elasticsearch for search and Neo4j for graphs. Hiring managers notice.
3. **Make it runnable.** Docker Compose is your friend. If someone can't `docker-compose up` and see your project work, they won't bother reading your code.
4. **Label your findings.** Map to MITRE ATT&CK, NIST, or CVSS. It shows you speak the language.

---

*Source: [github.com/SSH-PuR66/dash](https://github.com/SSH-PuR66/dash)*
