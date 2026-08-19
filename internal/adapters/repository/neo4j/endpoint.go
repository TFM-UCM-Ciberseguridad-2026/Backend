package neo4j

import (
	"context"
	"fmt"
	"strconv"

	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/domain"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

type endpointRepo struct {
	driver neo4j.DriverWithContext
}

// ==========================================
// IMPLEMENTACIÓN DE EndpointPort
// ==========================================

// Save persiste un Endpoint en la base de datos de grafos Neo4j (solo creación).
func (r *endpointRepo) Save(ctx context.Context, endpoint *domain.Endpoint) error {
	query := `
		MERGE (e:Endpoint {id: $id})
		ON CREATE SET e.hostname = $hostname,
		    e.type = $type,
		    e.status = $status,
		    e.environment = $environment,
		    e.internet_exposed = $internet_exposed,
		    e.confidentiality_req = $confidentiality_req,
		    e.integrity_req = $integrity_req,
		    e.availability_req = $availability_req,
		    e.risk_score = $risk_score,
		    e.risk_tier = $risk_tier,
		    e.risk_computed_at = $risk_computed_at,
		    e.updated_at = timestamp(),
			e.priority_score = $priority_score,
			e.priority_tier = $priority_tier,
			e.priority_computed_at = $priority_computed_at,
			e.technical_driver_installation_id = $technical_driver_installation_id,
			e.technical_driver_software_name = $technical_driver_software_name,
			e.technical_driver_risk_score = $technical_driver_risk_score,
			e.technical_driver_cve_id = $technical_driver_cve_id,
			e.priority_driver_installation_id = $priority_driver_installation_id,
			e.priority_driver_software_name = $priority_driver_software_name,
			e.priority_driver_priority_score = $priority_driver_priority_score,
			e.priority_driver_cve_id = $priority_driver_cve_id,
			e.risky_software_count = $risky_software_count
	`

	var riskComputedAt any
	if endpoint.RiskComputedAt != nil {
		riskComputedAt = *endpoint.RiskComputedAt
	}

	var priorityComputedAt any
	if endpoint.PriorityComputedAt != nil {
		priorityComputedAt = *endpoint.PriorityComputedAt
	}

	params := map[string]any{
		"id":                               endpoint.EndpointID,
		"hostname":                         endpoint.Hostname,
		"type":                             endpoint.Type,
		"status":                           endpoint.Status,
		"environment":                      endpoint.Environment,
		"internet_exposed":                 endpoint.InternetExposed,
		"confidentiality_req":              endpoint.ConfidentialityReq,
		"integrity_req":                    endpoint.IntegrityReq,
		"availability_req":                 endpoint.AvailabilityReq,
		"risk_score":                       endpoint.RiskScore,
		"risk_tier":                        endpoint.RiskTier,
		"risk_computed_at":                 riskComputedAt,
		"priority_score":                   endpoint.PriorityScore,
		"priority_tier":                    endpoint.PriorityTier,
		"priority_computed_at":             priorityComputedAt,
		"technical_driver_installation_id": endpoint.TechnicalDriverInstallationID,
		"technical_driver_software_name":   endpoint.TechnicalDriverSoftwareName,
		"technical_driver_risk_score":      endpoint.TechnicalDriverRiskScore,
		"technical_driver_cve_id":          endpoint.TechnicalDriverCVEID,
		"priority_driver_installation_id":  endpoint.PriorityDriverInstallationID,
		"priority_driver_software_name":    endpoint.PriorityDriverSoftwareName,
		"priority_driver_priority_score":   endpoint.PriorityDriverPriorityScore,
		"priority_driver_cve_id":           endpoint.PriorityDriverCVEID,
		"risky_software_count":             endpoint.RiskySoftwareCount,
	}

	return executeWriteSaveHelper(ctx, r.driver, query, params)
}

// Update actualiza un Endpoint existente en la base de datos de grafos Neo4j.
func (r *endpointRepo) Update(ctx context.Context, endpoint *domain.Endpoint) error {
	query := `
		MATCH (e:Endpoint)
		WHERE toString(e.id) = toString($id) OR elementId(e) = toString($id)
		SET e.hostname = $hostname,
		    e.type = $type,
		    e.status = $status,
		    e.environment = $environment,
		    e.internet_exposed = $internet_exposed,
		    e.confidentiality_req = $confidentiality_req,
		    e.integrity_req = $integrity_req,
		    e.availability_req = $availability_req,
		    e.updated_at = timestamp()
	`

	params := map[string]any{
		"id":                  endpoint.EndpointID,
		"hostname":            endpoint.Hostname,
		"type":                endpoint.Type,
		"status":              endpoint.Status,
		"environment":         endpoint.Environment,
		"internet_exposed":    endpoint.InternetExposed,
		"confidentiality_req": endpoint.ConfidentialityReq,
		"integrity_req":       endpoint.IntegrityReq,
		"availability_req":    endpoint.AvailabilityReq,
	}

	return executeWriteUpdateHelper(ctx, r.driver, query, params)
}

// GetByID recupera un Endpoint de Neo4j por su ID.
func (r *endpointRepo) GetByID(ctx context.Context, id int64) (*domain.Endpoint, error) {
	query := `
		MATCH (e:Endpoint {id: $id})
		RETURN properties(e) AS props
	`
	params := map[string]any{"id": id}

	res, err := r.ExecuteRead(ctx, query, params)
	if err != nil {
		return nil, err
	}

	if res == nil {
		return nil, nil // No encontrado
	}

	record := res.(map[string]any)
	props, ok := record["props"].(map[string]any)
	if !ok {
		return nil, nil
	}

	endpoint := &domain.Endpoint{
		EndpointID:                    getInt64(props, "id"),
		Hostname:                      getString(props, "hostname"),
		Type:                          getString(props, "type"),
		Status:                        getString(props, "status"),
		Environment:                   getString(props, "environment"),
		InternetExposed:               getBool(props, "internet_exposed"),
		ConfidentialityReq:            getString(props, "confidentiality_req"),
		IntegrityReq:                  getString(props, "integrity_req"),
		AvailabilityReq:               getString(props, "availability_req"),
		RiskScore:                     getFloat64(props, "risk_score"),
		RiskTier:                      getString(props, "risk_tier"),
		RiskComputedAt:                getTimePtr(props, "risk_computed_at"),
		PriorityScore:                 getFloat64(props, "priority_score"),
		PriorityTier:                  getString(props, "priority_tier"),
		PriorityComputedAt:            getTimePtr(props, "priority_computed_at"),
		TechnicalDriverInstallationID: getString(props, "technical_driver_installation_id"),
		TechnicalDriverSoftwareName:   getString(props, "technical_driver_software_name"),
		TechnicalDriverRiskScore:      getFloat64(props, "technical_driver_risk_score"),
		TechnicalDriverCVEID:          getString(props, "technical_driver_cve_id"),
		PriorityDriverInstallationID:  getString(props, "priority_driver_installation_id"),
		PriorityDriverSoftwareName:    getString(props, "priority_driver_software_name"),
		PriorityDriverPriorityScore:   getFloat64(props, "priority_driver_priority_score"),
		PriorityDriverCVEID:           getString(props, "priority_driver_cve_id"),
		RiskySoftwareCount:            int(getInt64(props, "risky_software_count")),
	}

	return endpoint, nil
}

// DeleteByID elimina un Endpoint y sus nodos dependientes (IPs, Hardware) y limpia huéfanos.
func (r *endpointRepo) DeleteByID(ctx context.Context, id int64) error {
	query := `
		MATCH (e:Endpoint)
		WHERE toString(e.id) = toString($id) OR elementId(e) = toString($id)
		OPTIONAL MATCH (e)-[:CONNECTED_TO]->(n:Network)
		WITH e, n
		OPTIONAL MATCH (p:Project)-[:HAS_ENDPOINT]->(e)
		WITH e, n, p
		FOREACH (proj IN CASE WHEN p IS NOT NULL AND n IS NOT NULL THEN [p] ELSE [] END |
			MERGE (proj)-[:CONTAINS_NETWORK]->(n)
		)
		WITH e
		OPTIONAL MATCH (e)-[:HAS_IP|HAS_HARDWARE|HOSTS]->(sub)
		WITH e, collect(sub) AS subs
		DETACH DELETE e
		WITH subs
		UNWIND subs AS s
		WITH s WHERE s IS NOT NULL
		DETACH DELETE s
	`
	if err := r.ExecuteWrite(ctx, query, map[string]any{"id": id}); err != nil {
		return err
	}

	cleanupQuery := `
		MATCH (n)
		WHERE (n:Software OR n:Hardware OR n:IPAddress OR n:SoftwareInstallation OR n:Finding OR n:Remediation OR n:Container OR n:ContainerImage OR n:Vulnerability OR n:Exploit)
		  AND NOT EXISTS((n)-[*1..5]-(:Endpoint)) AND NOT EXISTS((n)-[*1..5]-(:Project))
		DETACH DELETE n
	`
	return r.ExecuteWrite(ctx, cleanupQuery, nil)
}

// ==========================================
// IMPLEMENTACIÓN DE DatabaseHelper (Genérico)
// ==========================================

// ExecuteWrite ejecuta una consulta Cypher de escritura (CREATE, MERGE, SET, DELETE)
func (r *endpointRepo) ExecuteWrite(ctx context.Context, query string, params map[string]any) error {
	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)

	_, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		_, err := tx.Run(ctx, query, params)
		return nil, err
	})

	return err
}

// ExecuteRead ejecuta una consulta Cypher de lectura (MATCH, RETURN) y devuelve el primer registro como un mapa.
func (r *endpointRepo) ExecuteRead(ctx context.Context, query string, params map[string]any) (any, error) {
	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	result, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		res, err := tx.Run(ctx, query, params)
		if err != nil {
			return nil, err
		}

		if res.Next(ctx) {
			return res.Record().AsMap(), nil
		}
		return nil, nil // No se encontraron registros
	})

	return result, err
}

// GetNodeInfo es un helper dinámico para obtener las propiedades de cualquier nodo dado su Label y un filtro.
func (r *endpointRepo) GetNodeInfo(ctx context.Context, label string, propertyKey string, propertyValue any) (map[string]any, error) {
	query := fmt.Sprintf("MATCH (n:%s { %s: $val }) RETURN properties(n) AS props", label, propertyKey)
	params := map[string]any{"val": propertyValue}

	res, err := r.ExecuteRead(ctx, query, params)
	if err != nil {
		return nil, err
	}

	if res == nil {
		return nil, nil // No encontrado
	}

	record := res.(map[string]any)
	props := record["props"].(map[string]any)

	return props, nil
}

// SaveIPs reemplaza las direcciones IP de un endpoint por las indicadas, modelándolas
// como nodos :IPAddress conectados vía (:Endpoint)-[:HAS_IP]->(:IPAddress).
// Se borran y recrean en bloque porque el formulario del frontend sustituye el
// conjunto completo de IPs en cada guardado, no las edita una a una.
func (r *endpointRepo) SaveIPs(ctx context.Context, endpointID int64, ips []domain.EndpointIP) error {
	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)

	_, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		// 1. Eliminar IPs previas del endpoint
		if _, err := tx.Run(ctx, `
			MATCH (e:Endpoint)-[:HAS_IP]->(ip:IPAddress)
			WHERE toInteger(e.id) = toInteger($endpoint_id) OR toString(e.id) = toString($endpoint_id) OR elementId(e) = toString($endpoint_id)
			DETACH DELETE ip
		`, map[string]any{"endpoint_id": endpointID}); err != nil {
			return nil, err
		}

		// 2. Crear las nuevas
		for _, entry := range ips {
			if _, err := tx.Run(ctx, `
				MATCH (e:Endpoint)
				WHERE toInteger(e.id) = toInteger($endpoint_id) OR toString(e.id) = toString($endpoint_id) OR elementId(e) = toString($endpoint_id)
				CREATE (ip:IPAddress {ip: $ip, vlan_id: $vlan_id})
				MERGE (e)-[:HAS_IP]->(ip)
			`, map[string]any{
				"endpoint_id": endpointID,
				"ip":          entry.IP,
				"vlan_id":     entry.VLANID,
			}); err != nil {
				return nil, err
			}
		}
		return nil, nil
	})

	return err
}

// GetIPs devuelve las direcciones IP asociadas a un endpoint.
func (r *endpointRepo) GetIPs(ctx context.Context, endpointID int64) ([]domain.EndpointIP, error) {
	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	res, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		resultIPs, err := tx.Run(ctx, `
			MATCH (e:Endpoint)-[:HAS_IP]->(ip:IPAddress)
			WHERE toInteger(e.id) = toInteger($endpoint_id) OR toString(e.id) = toString($endpoint_id) OR elementId(e) = toString($endpoint_id)
			RETURN ip.ip AS ip, ip.vlan_id AS vlan_id
		`, map[string]any{"endpoint_id": endpointID})
		if err != nil {
			return nil, err
		}

		ips := make([]domain.EndpointIP, 0)
		vlanMap := make(map[int64]bool)
		for resultIPs.Next(ctx) {
			rec := resultIPs.Record()
			ipVal, _ := rec.Get("ip")
			vlanVal, _ := rec.Get("vlan_id")
			vlanID := getInt64Any(vlanVal)
			vlanMap[vlanID] = true
			ips = append(ips, domain.EndpointIP{
				IP:     getStringAny(ipVal),
				VLANID: vlanID,
			})
		}

		resultNets, err := tx.Run(ctx, `
			MATCH (e:Endpoint)-[:CONNECTED_TO]->(n:Network)
			WHERE toInteger(e.id) = toInteger($endpoint_id) OR toString(e.id) = toString($endpoint_id) OR elementId(e) = toString($endpoint_id)
			RETURN n.vlan_id AS vlan_id
		`, map[string]any{"endpoint_id": endpointID})
		if err != nil {
			return nil, err
		}

		for resultNets.Next(ctx) {
			rec := resultNets.Record()
			vlanVal, _ := rec.Get("vlan_id")
			vlanID := getInt64Any(vlanVal)
			if vlanID > 0 && !vlanMap[vlanID] {
				vlanMap[vlanID] = true
				ips = append(ips, domain.EndpointIP{
					IP:     "",
					VLANID: vlanID,
				})
			}
		}

		return ips, nil
	})

	if err != nil {
		return nil, err
	}
	if res == nil {
		return []domain.EndpointIP{}, nil
	}
	return res.([]domain.EndpointIP), nil
}

// getStringAny/getInt64Any convierten valores any sueltos (no un map[string]any) de
// resultados Neo4j. Los helpers getString/getInt64 ya existentes en db_helpers.go
// operan sobre map[string]any, no sobre un valor individual, de ahí este par extra.
func getStringAny(v any) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprint(v)
}

func getInt64Any(v any) int64 {
	if v == nil {
		return 0
	}
	switch val := v.(type) {
	case int64:
		return val
	case int:
		return int64(val)
	case int32:
		return int64(val)
	case float64:
		return int64(val)
	case float32:
		return int64(val)
	case string:
		i, _ := strconv.ParseInt(val, 10, 64)
		return i
	default:
		valStr := fmt.Sprint(val)
		if i, err := strconv.ParseInt(valStr, 10, 64); err == nil {
			return i
		}
		if f, err := strconv.ParseFloat(valStr, 64); err == nil {
			return int64(f)
		}
		return 0
	}
}
