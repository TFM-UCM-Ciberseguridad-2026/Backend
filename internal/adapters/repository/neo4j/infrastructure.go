package neo4j

import (
	"context"

	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/domain"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/ports"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

type infrastructureRepo struct {
	driver neo4j.DriverWithContext
}

// NewInfrastructureRepository crea un repositorio para operaciones agregadas de infraestructura en Neo4j.
func NewInfrastructureRepository(driver neo4j.DriverWithContext) ports.InfrastructurePort {
	return &infrastructureRepo{driver: driver}
}

// GetGraphData recupera todos los nodos y relaciones de la base de datos Neo4j en un formato estructurado.
func (r *infrastructureRepo) GetGraphData(ctx context.Context) (*domain.GraphData, error) {
	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	// Consulta de lectura optimizada para obtener nodos y relaciones en una sola transacción
	query := `
		MATCH (n)
		WHERE NOT n:ThreatActor AND NOT n:TTP
		WITH collect({id: elementId(n), labels: labels(n), properties: properties(n)}) AS nodes
		OPTIONAL MATCH (s)-[rel]->(t)
		WHERE NOT s:ThreatActor AND NOT s:TTP AND NOT t:ThreatActor AND NOT t:TTP
		WITH nodes, collect(case when rel is null then null else {id: elementId(rel), type: type(rel), source: elementId(s), target: elementId(t), properties: properties(rel)} end) AS relationships
		RETURN nodes, [r in relationships WHERE r IS NOT NULL] AS relationships
	`

	res, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
		result, err := tx.Run(ctx, query, nil)
		if err != nil {
			return nil, err
		}
		if result.Next(ctx) {
			return result.Record().AsMap(), nil
		}
		return nil, nil
	})
	if err != nil {
		return nil, err
	}

	graphData := &domain.GraphData{
		Nodes:         []domain.GraphNode{},
		Relationships: []domain.GraphRelationship{},
	}

	if res == nil {
		return graphData, nil
	}

	recordMap := res.(map[string]interface{})

	// Parsear Nodos
	if nodesRaw, ok := recordMap["nodes"].([]interface{}); ok {
		for _, nodeRaw := range nodesRaw {
			if nodeMap, ok := nodeRaw.(map[string]interface{}); ok {
				id, _ := nodeMap["id"].(string)
				labelsRaw, _ := nodeMap["labels"].([]interface{})
				labels := make([]string, len(labelsRaw))
				for i, l := range labelsRaw {
					labels[i], _ = l.(string)
				}
				props, _ := nodeMap["properties"].(map[string]interface{})

				graphData.Nodes = append(graphData.Nodes, domain.GraphNode{
					ID:         id,
					Labels:     labels,
					Properties: props,
				})
			}
		}
	}

	// Parsear Relaciones
	if relsRaw, ok := recordMap["relationships"].([]interface{}); ok {
		for _, relRaw := range relsRaw {
			if relMap, ok := relRaw.(map[string]interface{}); ok {
				id, _ := relMap["id"].(string)
				relType, _ := relMap["type"].(string)
				source, _ := relMap["source"].(string)
				target, _ := relMap["target"].(string)
				props, _ := relMap["properties"].(map[string]interface{})

				graphData.Relationships = append(graphData.Relationships, domain.GraphRelationship{
					ID:         id,
					Type:       relType,
					Source:     source,
					Target:     target,
					Properties: props,
				})
			}
		}
	}

	return graphData, nil
}


// GetTopAPTsByInfrastructureTTPs recorre el grafo completo desde la infraestructura del usuario
// hasta los actores de amenaza, calculando qué APTs cubren más TTPs vinculadas a las CVEs detectadas.
// Cadena de traversal: Project → Endpoint → SoftwareInstallation → Finding → Vulnerability ← TTP ← ThreatActor
func (r *infrastructureRepo) GetTopAPTsByInfrastructureTTPs(ctx context.Context, limit int) ([]domain.APTThreatResult, error) {
	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	// Consulta Cypher que:
	// 1. Encuentra todas las TTPs únicas vinculadas a las vulnerabilidades de la infraestructura
	// 2. Para cada ThreatActor, cuenta cuántas de esas TTPs utiliza
	// 3. Calcula el porcentaje de cobertura y ordena descendentemente
	query := `
		// Paso 1: Obtener todas las TTPs únicas que apuntan a CVEs de la infraestructura
		MATCH (p:Project)-[:HAS_ENDPOINT]->(e:Endpoint)-[:HAS_INSTALLATION]->(si:SoftwareInstallation)
		      -[:HAS_FINDING]->(f:Finding)-[:OF_VULNERABILITY]->(v:Vulnerability)<-[:TARGETS_VULN]-(ttp:TTP)
		WITH collect(DISTINCT ttp) AS infraTTPs

		// Paso 2: Para cada ThreatActor, calcular solapamiento con las TTPs de la infraestructura
		UNWIND infraTTPs AS infraTTP
		WITH infraTTPs, infraTTP
		MATCH (ta:ThreatActor)-[:USES_TTP]->(infraTTP)
		WITH ta, infraTTPs,
		     collect(DISTINCT infraTTP) AS matchedTTPs

		// Paso 3: Calcular métricas y ordenar
		WITH ta,
		     size(infraTTPs) AS totalInfraTTPs,
		     size(matchedTTPs) AS matchedCount,
		     [t IN matchedTTPs | t.name] AS matchedNames,
		     [t IN matchedTTPs | t.id] AS matchedIDs
		RETURN ta.id AS actor_id,
		       ta.name AS actor_name,
		       ta.origin AS origin,
		       ta.motivation AS motivation,
		       matchedCount AS matched_ttp_count,
		       totalInfraTTPs AS total_infra_ttps,
		       round(toFloat(matchedCount) / totalInfraTTPs * 10000) / 100 AS coverage_percent,
		       matchedNames AS matched_ttp_names,
		       matchedIDs AS matched_ttp_ids
		ORDER BY matchedCount DESC, ta.name ASC
		LIMIT $limit
	`

	res, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
		result, err := tx.Run(ctx, query, map[string]any{"limit": limit})
		if err != nil {
			return nil, err
		}

		var results []domain.APTThreatResult
		for result.Next(ctx) {
			record := result.Record()
			actorID, _ := record.Get("actor_id")
			actorName, _ := record.Get("actor_name")
			origin, _ := record.Get("origin")
			motivation, _ := record.Get("motivation")
			matchedCount, _ := record.Get("matched_ttp_count")
			totalInfra, _ := record.Get("total_infra_ttps")
			coverage, _ := record.Get("coverage_percent")
			namesRaw, _ := record.Get("matched_ttp_names")
			idsRaw, _ := record.Get("matched_ttp_ids")

			// Parsear listas de strings
			var matchedNames []string
			if namesList, ok := namesRaw.([]interface{}); ok {
				for _, n := range namesList {
					if s, ok := n.(string); ok {
						matchedNames = append(matchedNames, s)
					}
				}
			}

			var matchedIDs []string
			if idsList, ok := idsRaw.([]interface{}); ok {
				for _, n := range idsList {
					if s, ok := n.(string); ok {
						matchedIDs = append(matchedIDs, s)
					}
				}
			}

			results = append(results, domain.APTThreatResult{
				ActorID:         actorID.(string),
				ActorName:       actorName.(string),
				Origin:          origin.(string),
				Motivation:      motivation.(string),
				MatchedTTPCount: int(matchedCount.(int64)),
				TotalInfraTTPs:  int(totalInfra.(int64)),
				CoveragePercent: coverage.(float64),
				MatchedTTPNames: matchedNames,
				MatchedTTPIDs:   matchedIDs,
			})
		}

		return results, result.Err()
	})

	if err != nil {
		return nil, err
	}

	if res == nil {
		return []domain.APTThreatResult{}, nil
	}

	return res.([]domain.APTThreatResult), nil
}

// CalculateExploitationPaths busca endpoints expuestos a internet con vulnerabilidades que permiten ejecución de código (RCE).
func (r *infrastructureRepo) CalculateExploitationPaths(ctx context.Context) ([]domain.ExploitationPathResult, error) {
	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	query := `
		MATCH (e:Endpoint {internet_exposed: true})-[:HAS_INSTALLATION]->(si:SoftwareInstallation)-[:HAS_FINDING]->(f:Finding)-[:OF_VULNERABILITY]->(v:Vulnerability)
		WHERE v.base_score >= 9.0 OR v.exploitation_vector = true OR v.description =~ '.*(?i)(code execution|command injection|remote code execution|RCE).*'
		RETURN e.id AS endpoint_id, e.hostname AS hostname, v.cve_id AS cve, v.description AS description, f.risk_score AS risk
		ORDER BY f.risk_score DESC
	`

	res, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
		result, err := tx.Run(ctx, query, nil)
		if err != nil {
			return nil, err
		}

		var paths []domain.ExploitationPathResult
		for result.Next(ctx) {
			record := result.Record()
			epID, _ := record.Get("endpoint_id")
			hostname, _ := record.Get("hostname")
			cve, _ := record.Get("cve")
			desc, _ := record.Get("description")
			risk, _ := record.Get("risk")

			paths = append(paths, domain.ExploitationPathResult{
				EndpointID:  epID.(int64),
				Hostname:    hostname.(string),
				CVE:         cve.(string),
				Description: desc.(string),
				Risk:        risk.(float64),
			})
		}
		return paths, result.Err()
	})

	if err != nil {
		return nil, err
	}
	if res == nil {
		return []domain.ExploitationPathResult{}, nil
	}
	return res.([]domain.ExploitationPathResult), nil
}
