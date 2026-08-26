package neo4j

import (
	"context"
	"fmt"
	"strings"

	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/domain"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

// GetPaginatedInventory consulta Neo4j aplicando filtrado por proyecto, categorías múltiples, búsqueda avanzada,
// ordenación dinámica y paginación acotada (por defecto 50 elementos por página).
func (r *infrastructureRepo) GetPaginatedInventory(ctx context.Context, query domain.InventoryQuery) (*domain.PaginatedInventoryResponse, error) {
	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	if query.Page < 1 {
		query.Page = 1
	}
	if query.Limit <= 0 {
		query.Limit = 50
	}
	offset := (query.Page - 1) * query.Limit

	// Sanitizar dirección de ordenación
	sortDir := "ASC"
	if strings.ToUpper(query.SortDirection) == "DESC" {
		sortDir = "DESC"
	}

	// Determinar expresión Cypher para ordenación
	var orderExpr string
	switch strings.ToLower(query.SortField) {
	case "id":
		orderExpr = "coalesce(toString(n.id), elementId(n))"
	case "name":
		orderExpr = "toLower(coalesce(n.name, n.nombre, n.hostname, n.title, n.cve_id, n.cve, n.ip, elementId(n)))"
	case "category":
		orderExpr = "head(labels(n))"
	case "properties":
		orderExpr = "toLower(toString(properties(n)))"
	default:
		orderExpr = "toLower(coalesce(n.name, n.nombre, n.hostname, n.title, n.cve_id, n.cve, n.ip, elementId(n)))"
	}

	hasCategories := len(query.Categories) > 0

	cypherQuery := fmt.Sprintf(`
		MATCH (n)
		WHERE NOT (n:ThreatActor OR n:TTP OR n:IPAddress OR n:Vulnerability OR n:Finding OR n:CWE OR n:CVE OR n:Exploit OR n:Remediation)
		  AND ($project_id = 0 OR 
		       (n:Project AND (n.id = $project_id OR toString(n.id) = toString($project_id))) OR 
		       EXISTS { MATCH (p:Project)-[*1..6]->(n) WHERE p.id = $project_id OR toString(p.id) = toString($project_id) }
		      )
		  AND ($category = "" OR $category = "ALL" OR $category IN labels(n))
		  AND ($has_categories = false OR head(labels(n)) IN $categories)
		  AND ($search = "" OR 
		       toLower(coalesce(n.name, n.nombre, n.hostname, n.title, n.cve_id, n.cve, n.ip, elementId(n), toString(n.id), "")) CONTAINS toLower($search) OR 
		       any(k IN keys(n) WHERE toLower(toString(n[k])) CONTAINS toLower($search))
		      )
		  AND ($ip_search = "" OR 
		       toLower(coalesce(n.ip, n.cidr, "")) CONTAINS toLower($ip_search) OR 
		       EXISTS { MATCH (n)-[:HAS_IP]->(ip:IPAddress) WHERE toLower(ip.ip) CONTAINS toLower($ip_search) }
		      )
		  AND ($vendor_search = "" OR 
		       toLower(coalesce(n.vendor, n.software_vendor, n.manufacturer, n.fabricante, "")) CONTAINS toLower($vendor_search) OR 
		       EXISTS { MATCH (n)-[:INSTANCE_OF]->(sw:Software) WHERE toLower(sw.vendor) CONTAINS toLower($vendor_search) }
		      )
		  AND ($environment = "" OR $environment = "ALL" OR toLower(coalesce(n.environment, n.entorno, "")) = toLower($environment))
		  AND ($internet_exposed = "" OR $internet_exposed = "ALL" OR 
		       ($internet_exposed = "TRUE" AND (n.internet_exposed = true OR toString(n.internet_exposed) = "true")) OR 
		       ($internet_exposed = "FALSE" AND (n.internet_exposed IS NULL OR n.internet_exposed = false OR toString(n.internet_exposed) = "false"))
		      )
		  AND ($status = "" OR $status = "ALL" OR toLower(coalesce(n.status, n.estado, "")) = toLower($status))
		  AND ($risk_tier = "" OR $risk_tier = "ALL" OR toLower(coalesce(n.risk_tier, n.severity, "")) = toLower($risk_tier))

		WITH collect(n) AS matchedNodes, count(n) AS totalCount

		UNWIND (CASE WHEN size(matchedNodes) > 0 THEN matchedNodes ELSE [null] END) AS n
		WITH matchedNodes, totalCount, n WHERE n IS NOT NULL

		// Recopilar recuentos por categoría primaria para los badges del sidebar
		WITH matchedNodes, totalCount, head(labels(n)) AS catLabel, collect(n) AS catNodes
		WITH matchedNodes, totalCount, collect({category: catLabel, count: size(catNodes)}) AS categoryMetrics

		UNWIND matchedNodes AS n
		WITH totalCount, categoryMetrics, n
		ORDER BY %s %s
		SKIP $offset LIMIT $limit

		OPTIONAL MATCH (n:Endpoint)-[:HAS_IP]->(ipNode:IPAddress)
		WITH totalCount, categoryMetrics, n, collect(ipNode.ip) AS fetchedIPs
		OPTIONAL MATCH (n:SoftwareInstallation)-[:INSTANCE_OF]->(swNode:Software)
		WITH totalCount, categoryMetrics, n, fetchedIPs, swNode

		RETURN totalCount, categoryMetrics, collect({
			id: coalesce(toString(n.id), elementId(n)),
			element_id: elementId(n),
			name: coalesce(n.name, n.nombre, n.hostname, n.title, n.cve_id, n.cve, n.ip, elementId(n)),
			primaryLabel: head(labels(n)),
			labels: labels(n),
			properties: properties(n),
			fetched_ips: fetchedIPs,
			software_name: swNode.name,
			software_vendor: swNode.vendor,
			software_version: swNode.version
		}) AS pagedItems
	`, orderExpr, sortDir)

	params := map[string]any{
		"project_id":       query.ProjectID,
		"category":         query.Category,
		"has_categories":   hasCategories,
		"categories":       query.Categories,
		"search":           strings.TrimSpace(query.Search),
		"ip_search":        strings.TrimSpace(query.IPSearch),
		"vendor_search":    strings.TrimSpace(query.VendorSearch),
		"environment":      strings.TrimSpace(query.Environment),
		"internet_exposed": strings.ToUpper(strings.TrimSpace(query.InternetExposed)),
		"status":           strings.TrimSpace(query.Status),
		"risk_tier":        strings.TrimSpace(query.RiskTier),
		"offset":           offset,
		"limit":            query.Limit,
	}

	res, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
		result, err := tx.Run(ctx, cypherQuery, params)
		if err != nil {
			return nil, err
		}
		if result.Next(ctx) {
			return result.Record().AsMap(), nil
		}
		return nil, nil
	})
	if err != nil {
		return nil, fmt.Errorf("error al consultar inventario en Neo4j: %w", err)
	}

	response := &domain.PaginatedInventoryResponse{
		Items:          []domain.InventoryItem{},
		Page:           query.Page,
		Limit:          query.Limit,
		TotalItems:     0,
		TotalPages:     0,
		CategoryCounts: make(map[string]int64),
	}

	if res == nil {
		return response, nil
	}

	recordMap := res.(map[string]interface{})

	// Total Items & Total Pages
	if tc, ok := recordMap["totalCount"].(int64); ok {
		response.TotalItems = tc
		if tc > 0 && query.Limit > 0 {
			response.TotalPages = int((tc + int64(query.Limit) - 1) / int64(query.Limit))
		}
	}

	// Category Metrics
	if metricsRaw, ok := recordMap["categoryMetrics"].([]interface{}); ok {
		var grandTotal int64 = 0
		for _, item := range metricsRaw {
			if m, ok := item.(map[string]interface{}); ok {
				cat, _ := m["category"].(string)
				cnt, _ := m["count"].(int64)
				if cat != "" {
					response.CategoryCounts[cat] = cnt
					grandTotal += cnt
				}
			}
		}
		response.CategoryCounts["ALL"] = grandTotal
	}

	// Parse Paged Items
	if itemsRaw, ok := recordMap["pagedItems"].([]interface{}); ok {
		for _, raw := range itemsRaw {
			if itemMap, ok := raw.(map[string]interface{}); ok {
				id, _ := itemMap["id"].(string)
				name, _ := itemMap["name"].(string)
				primaryLabel, _ := itemMap["primaryLabel"].(string)

				labelsRaw, _ := itemMap["labels"].([]interface{})
				labels := make([]string, len(labelsRaw))
				for i, l := range labelsRaw {
					labels[i], _ = l.(string)
				}

				props, _ := itemMap["properties"].(map[string]interface{})
				if props == nil {
					props = make(map[string]interface{})
				}

				if fetchedIPs, ok := itemMap["fetched_ips"].([]interface{}); ok && len(fetchedIPs) > 0 {
					ipsList := make([]string, 0, len(fetchedIPs))
					for _, ipVal := range fetchedIPs {
						if s, ok := ipVal.(string); ok && s != "" {
							ipsList = append(ipsList, s)
						}
					}
					if len(ipsList) > 0 {
						props["ips"] = ipsList
					}
				}
				if swName, ok := itemMap["software_name"].(string); ok && swName != "" {
					props["software_name"] = swName
				}
				if swVendor, ok := itemMap["software_vendor"].(string); ok && swVendor != "" {
					props["software_vendor"] = swVendor
				}
				if swVersion, ok := itemMap["software_version"].(string); ok && swVersion != "" {
					props["software_version"] = swVersion
				}

				response.Items = append(response.Items, domain.InventoryItem{
					ID:           id,
					Name:         name,
					PrimaryLabel: primaryLabel,
					Labels:       labels,
					Properties:   props,
				})
			}
		}
	}

	return response, nil
}
