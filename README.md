# dash

> A threat intelligence operations platform that ingests feeds, enriches alerts, correlates indicators, and serves analyst-facing APIs and dashboards.

<table>
  <tr>
    <td align="center">
      <img src="https://media.giphy.com/media/LHZyixOnHwDDy/giphy.gif" width="170" alt="Security shield" />
      <br/><sub>Detection posture</sub>
    </td>
    <td align="center">
      <img src="https://media2.giphy.com/media/v1.Y2lkPTc5MGI3NjExdjI0a2Y1NTN5MmRoeG9tc3V1b203eHdpZ3Jla2xhdGJqNHJmMGtxMyZlcD12MV9naWZzX3NlYXJjaCZjdD1n/1BfRG8cK5SPOer97aK/giphy.gif" width="170" alt="Threat data flow" />
      <br/><sub>Intel pipeline</sub>
    </td>
  </tr>
</table>

## What it is

dash is a modular security intelligence stack built around feed ingestion, normalization, enrichment, graph correlation, and response. The repo is structured like a real operations platform, with independent services for each stage of the pipeline.

## Core modules

| Module | Role |
|---|---|
| `ingestion/` | Pulls intelligence from external feeds and normalizes indicator data |
| `entity_graph/` | Loads enriched indicators into Neo4j for relationship analysis |
| `SIEM/` | Enriches alerts and forwards high-value matches to downstream systems |
| `api/` | Flask query layer for indicators, graph neighbors, and stats |
| `dashboard/` | Analyst-facing frontend entry point |

## Data flow

```mermaid
flowchart LR
    A[Threat feeds] --> B[Ingestion]
    B --> C[Kafka raw topic]
    C --> D[Normalizer]
    D --> E[Elasticsearch]
    D --> F[Enriched Kafka topic]
    F --> G[Graph loader]
    E --> H[API search]
    G --> I[Neo4j relationship graph]
    H --> J[Analyst dashboard]
    E --> K[SIEM alert enrichment]
```

## Stack

| Layer | Stack |
|---|---|
| Messaging | Kafka |
| Search | Elasticsearch |
| Graph | Neo4j |
| API | Flask |
| Containers | Docker Compose |

## Key capabilities

- Indicator normalization and deduplication
- Geo/IP enrichment
- Risk scoring and severity classification
- Graph relationship loading
- Alert enrichment and routing
- Dashboard/API-style analyst access

## Portfolio description

dash is a threat intelligence operations platform that ingests indicators from multiple feeds, enriches and scores them, stores them in Elasticsearch and Neo4j, and exposes the results through a Flask API and analyst dashboard.

## Notes

- The repo is built to look like a real security operations workflow.
- The visual assets above give the README a strong portfolio feel.
- The architecture is modular enough to present cleanly in interviews.
