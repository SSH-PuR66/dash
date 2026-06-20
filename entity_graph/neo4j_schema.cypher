// --- entity_graph/neo4j_schema.cypher ---
CREATE CONSTRAINT indicator_unique IF NOT EXISTS
FOR (i:Indicator) REQUIRE (i.value, i.type) IS UNIQUE;

CREATE CONSTRAINT source_unique IF NOT EXISTS
FOR (s:Source) REQUIRE s.name IS UNIQUE;

CREATE CONSTRAINT tag_unique IF NOT EXISTS
FOR (t:Tag) REQUIRE t.name IS UNIQUE;

CREATE CONSTRAINT geo_unique IF NOT EXISTS
FOR (g:GeoLocation) REQUIRE g.country IS UNIQUE;

CREATE INDEX indicator_severity IF NOT EXISTS
FOR (i:Indicator) ON (i.severity_score);

CREATE INDEX indicator_type IF NOT EXISTS
FOR (i:Indicator) ON (i.type);

CREATE INDEX indicator_first_seen IF NOT EXISTS
FOR (i:Indicator) ON (i.first_seen);