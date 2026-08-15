package neo4j

/*
Este archivo implementa el Repositorio de Persistencia en Neo4j para patrones de ataque CAPEC (Common Attack Pattern Enumeration and Classification).

Propósito arquitectónico y teórico:
1. Ubicación en Arquitectura Hexagonal: Se localiza en `internal/adapters/repository/neo4j`, implementando ports.CAPECPort.
2. Persistencia en Grafo: Crea nodos (:CAPEC) y (:CWE), y establece las relaciones dirigidas (:CAPEC)-[:MAPS_TO_CWE]->(:CWE).
*/

import (
	"context"

	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/domain"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

type capecRepo struct {
	driver neo4j.DriverWithContext
}

// NewCAPECRepository crea una instancia del repositorio de CAPEC.
func NewCAPECRepository(driver neo4j.DriverWithContext) *capecRepo {
	return &capecRepo{driver: driver}
}

func (r *capecRepo) Save(ctx context.Context, capec *domain.CAPEC) error {
	cwes := capec.CWEs
	if cwes == nil {
		cwes = []string{}
	}
	ttps := capec.TTPs
	if ttps == nil {
		ttps = []string{}
	}

	queryNode := `
		MERGE (c:CAPEC {capec_id: $capec_id})
		SET c.name = $name,
		    c.description = $description,
		    c.cwes = $cwes,
		    c.ttps = $ttps,
		    c.updated_at = timestamp()
	`
	params := map[string]any{
		"capec_id":    capec.CAPECID,
		"name":        capec.Name,
		"description": capec.Description,
		"cwes":        cwes,
		"ttps":        ttps,
	}

	if err := executeWriteHelper(ctx, r.driver, queryNode, params); err != nil {
		return err
	}

	if len(cwes) > 0 {
		queryCWE := `
			MATCH (c:CAPEC {capec_id: $capec_id})
			UNWIND $cwes AS cwe_id
			MERGE (w:CWE {cwe_id: cwe_id})
			MERGE (c)-[rel:MAPS_TO_CWE]->(w)
			SET rel.updated_at = timestamp()
		`
		if err := executeWriteHelper(ctx, r.driver, queryCWE, params); err != nil {
			return err
		}
	}

	if len(ttps) > 0 {
		queryTTP := `
			MATCH (c:CAPEC {capec_id: $capec_id})
			UNWIND $ttps AS ttp_id
			MATCH (t:TTP {ttp_id: ttp_id})
			MERGE (c)-[rel:MAPS_TO_TTP]->(t)
			SET rel.updated_at = timestamp()
		`
		if err := executeWriteHelper(ctx, r.driver, queryTTP, params); err != nil {
			return err
		}
	}

	return nil
}

func (r *capecRepo) SaveBatch(ctx context.Context, capecs []domain.CAPEC) error {
	if len(capecs) == 0 {
		return nil
	}

	var capecMaps []map[string]any
	for _, c := range capecs {
		cwes := c.CWEs
		if cwes == nil {
			cwes = []string{}
		}
		ttps := c.TTPs
		if ttps == nil {
			ttps = []string{}
		}
		capecMaps = append(capecMaps, map[string]any{
			"capec_id":    c.CAPECID,
			"name":        c.Name,
			"description": c.Description,
			"cwes":        cwes,
			"ttps":        ttps,
		})
	}

	// 1. Guardar o actualizar todos los nodos CAPEC
	queryNodes := `
		UNWIND $capecs AS item
		MERGE (c:CAPEC {capec_id: item.capec_id})
		SET c.name = item.name,
		    c.description = item.description,
		    c.cwes = item.cwes,
		    c.ttps = item.ttps,
		    c.updated_at = timestamp()
	`
	if err := executeWriteHelper(ctx, r.driver, queryNodes, map[string]any{"capecs": capecMaps}); err != nil {
		return err
	}

	// 2. Crear relaciones MAPS_TO_CWE para los que tienen CWEs
	queryCWEs := `
		UNWIND $capecs AS item
		WITH item WHERE size(item.cwes) > 0
		MATCH (c:CAPEC {capec_id: item.capec_id})
		UNWIND item.cwes AS cwe_id
		MERGE (w:CWE {cwe_id: cwe_id})
		MERGE (c)-[rel:MAPS_TO_CWE]->(w)
		SET rel.updated_at = timestamp()
	`
	if err := executeWriteHelper(ctx, r.driver, queryCWEs, map[string]any{"capecs": capecMaps}); err != nil {
		return err
	}

	// 3. Crear relaciones MAPS_TO_TTP para los que tienen TTPs
	queryTTPs := `
		UNWIND $capecs AS item
		WITH item WHERE size(item.ttps) > 0
		MATCH (c:CAPEC {capec_id: item.capec_id})
		UNWIND item.ttps AS ttp_id
		MATCH (t:TTP {ttp_id: ttp_id})
		MERGE (c)-[rel:MAPS_TO_TTP]->(t)
		SET rel.updated_at = timestamp()
	`
	if err := executeWriteHelper(ctx, r.driver, queryTTPs, map[string]any{"capecs": capecMaps}); err != nil {
		return err
	}

	return nil
}

func (r *capecRepo) GetByID(ctx context.Context, id string) (*domain.CAPEC, error) {
	query := `MATCH (c:CAPEC {capec_id: $id}) RETURN properties(c) AS props`
	props, err := executeReadHelper(ctx, r.driver, query, map[string]any{"id": id})
	if err != nil || props == nil {
		return nil, err
	}

	cwes := getStringSlice(props, "cwes")
	ttps := getStringSlice(props, "ttps")

	return &domain.CAPEC{
		CAPECID:     getString(props, "capec_id"),
		Name:        getString(props, "name"),
		Description: getString(props, "description"),
		CWEs:        cwes,
		TTPs:        ttps,
	}, nil
}

func (r *capecRepo) LinkCAPECToCWE(ctx context.Context, capecID string, cweID string) error {
	query := `
		MERGE (c:CAPEC {capec_id: $capec_id})
		MERGE (w:CWE {cwe_id: $cwe_id})
		MERGE (c)-[rel:MAPS_TO_CWE]->(w)
		SET rel.updated_at = timestamp()
	`
	params := map[string]any{
		"capec_id": capecID,
		"cwe_id":   cweID,
	}
	return executeWriteHelper(ctx, r.driver, query, params)
}

func (r *capecRepo) LinkCAPECToTTP(ctx context.Context, capecID string, ttpID string) error {
	query := `
		MERGE (c:CAPEC {capec_id: $capec_id})
		MATCH (t:TTP {ttp_id: $ttp_id})
		MERGE (c)-[rel:MAPS_TO_TTP]->(t)
		SET rel.updated_at = timestamp()
	`
	params := map[string]any{
		"capec_id": capecID,
		"ttp_id":   ttpID,
	}
	return executeWriteHelper(ctx, r.driver, query, params)
}
