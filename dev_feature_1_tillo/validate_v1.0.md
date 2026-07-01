# Validate v1.0

## Purpose

This file explains how to validate in Neo4j Browser what your current `prueba_grafo_endpoint` execution has created.

The goal is to confirm:

1. the nodes exist
2. the relationships exist
3. the graph paths are connected as intended
4. the current limitations of persisted properties are understood

## 1. Open Neo4j Browser

Open:

```text
http://localhost:7474
```

Login with:

- user: `neo4j`
- password: `password`

## 2. Basic validation

## 2.1 See all nodes

Run:

```cypher
MATCH (n)
RETURN n
```

Expected result:

- one `Project`
- one `Endpoint`
- one `Hardware`
- one `Network`
- two `Software`
- two `SoftwareInstallation`
- three `Finding`
- three `Vulnerability`
- one `Remediation`
- one `Patch`
- optionally one `Exploit` if you kept it in the prototype

## 2.2 See all relationships

Run:

```cypher
MATCH ()-[r]->()
RETURN r
```

Expected relationship types:

- `HAS_ENDPOINT`
- `HAS_HARDWARE`
- `CONNECTED_TO`
- `HAS_INSTALLATION`
- `INSTANCE_OF`
- `HAS_FINDING`
- `OF_VULNERABILITY`
- `HAS_REMEDIATION`
- `USES_PATCH`
- `FIXES`

## 2.3 Count nodes by label

Run:

```cypher
MATCH (n)
RETURN labels(n) AS labels, count(*) AS total
ORDER BY total DESC
```

Expected approximate counts:

- `["Vulnerability"]` -> `3`
- `["Finding"]` -> `3`
- `["Software"]` -> `2`
- `["SoftwareInstallation"]` -> `2`
- `["Project"]` -> `1`
- `["Endpoint"]` -> `1`
- `["Hardware"]` -> `1`
- `["Network"]` -> `1`
- `["Remediation"]` -> `1`
- `["Patch"]` -> `1`
- `["Exploit"]` -> `1` if still present

## 2.4 Count relationships by type

Run:

```cypher
MATCH ()-[r]->()
RETURN type(r) AS relationship, count(*) AS total
ORDER BY relationship
```

Expected approximate counts:

- `CONNECTED_TO` -> `1`
- `FIXES` -> `1`
- `HAS_ENDPOINT` -> `1`
- `HAS_FINDING` -> `3`
- `HAS_HARDWARE` -> `1`
- `HAS_INSTALLATION` -> `2`
- `HAS_REMEDIATION` -> `1`
- `INSTANCE_OF` -> `2`
- `OF_VULNERABILITY` -> `3`
- `USES_PATCH` -> `1`

## 3. Validate each graph segment

## 3.1 Project -> Endpoint

Run:

```cypher
MATCH p=(proj:Project)-[:HAS_ENDPOINT]->(e:Endpoint)
RETURN p
```

Expected result:

- the project node connected to `srv-db`

## 3.2 Endpoint -> Hardware

Run:

```cypher
MATCH p=(e:Endpoint)-[:HAS_HARDWARE]->(h:Hardware)
RETURN p
```

Expected result:

- the endpoint connected to the Dell hardware node

## 3.3 Endpoint -> Network

Run:

```cypher
MATCH p=(e:Endpoint)-[:CONNECTED_TO]->(n:Network)
RETURN p
```

Expected result:

- the endpoint connected to `VLAN-Servers`

## 3.4 Endpoint -> Installation -> Software

Run:

```cypher
MATCH p=(e:Endpoint)-[:HAS_INSTALLATION]->(si:SoftwareInstallation)-[:INSTANCE_OF]->(s:Software)
RETURN p
```

Expected result:

- one chain to `OpenSSL`
- one chain to `PostgreSQL`

## 3.5 Installation -> Finding

Run:

```cypher
MATCH p=(si:SoftwareInstallation)-[:HAS_FINDING]->(f:Finding)
RETURN p
```

Expected result:

- `inst-openssl-srv-prod-01` connected to two findings
- `inst-postgresql-srv-prod-01` connected to one finding

## 3.6 Finding -> Vulnerability

Run:

```cypher
MATCH p=(f:Finding)-[:OF_VULNERABILITY]->(v:Vulnerability)
RETURN p
```

Expected result:

- three finding-to-vulnerability links

## 3.7 Remediation chain

Run:

```cypher
MATCH p=(f:Finding)-[:HAS_REMEDIATION]->(r:Remediation)-[:USES_PATCH]->(pa:Patch)-[:FIXES]->(v:Vulnerability)
RETURN p
```

Expected result:

- one complete remediation path

## 4. Validate the full attack/remediation context

## 4.1 Full project path

Run:

```cypher
MATCH p=
  (proj:Project)-[:HAS_ENDPOINT]->(e:Endpoint)
  -[:HAS_INSTALLATION]->(si:SoftwareInstallation)
  -[:HAS_FINDING]->(f:Finding)
  -[:OF_VULNERABILITY]->(v:Vulnerability)
RETURN p
```

Expected result:

- the full path from project to vulnerabilities

## 4.2 Endpoint neighborhood

Run:

```cypher
MATCH p=(e:Endpoint {hostname: "srv-db"})-[*1..4]-(n)
RETURN p
LIMIT 100
```

Expected result:

- a visual overview of all nearby nodes

## 4.3 Focus only on OpenSSL installation

Run:

```cypher
MATCH p=(si:SoftwareInstallation {id: "inst-openssl-srv-prod-01"})-[*1..4]-(n)
RETURN p
LIMIT 100
```

Expected result:

- OpenSSL installation
- its software node
- its findings
- its vulnerability links
- remediation chain if applicable

## 5. Inspect individual node properties

## 5.1 Endpoint properties

```cypher
MATCH (e:Endpoint {id: 1})
RETURN properties(e)
```

## 5.2 Installation properties

```cypher
MATCH (si:SoftwareInstallation)
RETURN si.id, properties(si)
ORDER BY si.id
```

This is useful to confirm:

- `first_seen`
- `last_seen`
- `status`
- `install_path`
- `detected_by`
- `package_manager`

## 5.3 Vulnerability properties

```cypher
MATCH (v:Vulnerability)
RETURN v.cve_id, properties(v)
ORDER BY v.cve_id
```

## 6. Important interpretation notes

Your runtime output already shows some properties do not come back populated in the Go readback objects. That does not necessarily mean the graph relationships failed.

Current known examples:

- `Finding.FirstSeen`, `LastSeen`, `ResolvedAt` are not being read back by the current repository implementation
- `Patch.ReleaseDate` is not being read back by the current repository implementation
- some other domain structs persist only a subset of fields

So for Phase 1, Neo4j Browser is the source of truth for graph validation.

Use Browser queries to validate:

- graph shape
- relationship existence
- stored properties on nodes

## 7. Quick pass/fail checklist

Phase 1 validation passes if all of these are true:

1. `MATCH (n) RETURN n` shows the expected labels
2. `MATCH ()-[r]->() RETURN r` shows the expected relationship types
3. `Project -> Endpoint` exists
4. `Endpoint -> Hardware` exists
5. `Endpoint -> Network` exists
6. `Endpoint -> SoftwareInstallation` exists for both installations
7. `SoftwareInstallation -> Software` exists for both installations
8. `SoftwareInstallation -> Finding` exists for all expected findings
9. `Finding -> Vulnerability` exists for all three vulnerabilities
10. `Finding -> Remediation -> Patch -> Vulnerability` exists for the remediation path

## 8. Recommended validation order

Use this sequence in Neo4j Browser:

1. `MATCH (n) RETURN n`
2. `MATCH ()-[r]->() RETURN r`
3. `MATCH p=(p:Project)-[:HAS_ENDPOINT]->(e:Endpoint) RETURN p`
4. `MATCH p=(e:Endpoint)-[:HAS_INSTALLATION]->(si:SoftwareInstallation)-[:INSTANCE_OF]->(s:Software) RETURN p`
5. `MATCH p=(si:SoftwareInstallation)-[:HAS_FINDING]->(f:Finding)-[:OF_VULNERABILITY]->(v:Vulnerability) RETURN p`
6. `MATCH p=(f:Finding)-[:HAS_REMEDIATION]->(r:Remediation)-[:USES_PATCH]->(pa:Patch)-[:FIXES]->(v:Vulnerability) RETURN p`
7. `MATCH ()-[r]->() RETURN type(r), count(*)`

If all seven checks look correct, the Phase 1 graph has been applied successfully.
