package neo4j

import (
	"context"
	"fmt"

	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/domain"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

type endpointRepo struct {
	driver neo4j.DriverWithContext
}

// ==========================================
// IMPLEMENTACIÓN DE EndpointPort
// ==========================================

// Save persiste un Endpoint en la base de datos de grafos Neo4j.
func (r *endpointRepo) Save(ctx context.Context, endpoint *domain.Endpoint) error {
	query := `
		MERGE (e:Endpoint {id: $id})
		SET e.hostname = $hostname,
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
		    e.updated_at = timestamp()
	`

	var riskComputedAt any
	if endpoint.RiskComputedAt != nil {
		riskComputedAt = *endpoint.RiskComputedAt
	}

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
		"risk_score":          endpoint.RiskScore,
		"risk_tier":           endpoint.RiskTier,
		"risk_computed_at":    riskComputedAt,
	}

	return r.ExecuteWrite(ctx, query, params)
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
		EndpointID:         getInt64(props, "id"),
		Hostname:           getString(props, "hostname"),
		Type:               getString(props, "type"),
		Status:             getString(props, "status"),
		Environment:        getString(props, "environment"),
		InternetExposed:    getBool(props, "internet_exposed"),
		ConfidentialityReq: getString(props, "confidentiality_req"),
		IntegrityReq:       getString(props, "integrity_req"),
		AvailabilityReq:    getString(props, "availability_req"),
		RiskScore:          getFloat64(props, "risk_score"),
		RiskTier:           getString(props, "risk_tier"),
		RiskComputedAt:     getTimePtr(props, "risk_computed_at"),
	}

	return endpoint, nil
}

// DeleteByID elimina un Endpoint de Neo4j por su ID.
func (r *endpointRepo) DeleteByID(ctx context.Context, id int64) error {
	query := `MATCH (e:Endpoint {id: $id}) DETACH DELETE e`
	return r.ExecuteWrite(ctx, query, map[string]any{"id": id})
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
