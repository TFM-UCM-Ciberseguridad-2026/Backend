package neo4j

import (
	"context"

	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/domain"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

type ttpRepo struct {
	driver neo4j.DriverWithContext
}

// NewTTPRepository crea una instancia del repositorio de TTP.
func NewTTPRepository(driver neo4j.DriverWithContext) *ttpRepo {
	return &ttpRepo{driver: driver}
}

func (r *ttpRepo) Save(ctx context.Context, ttp *domain.TTP) error {
	query := `
		MERGE (t:TTP {ttp_id: $ttp_id})
		SET t.name = $name,
		    t.tactic = $tactic,
		    t.description = $description,
		    t.updated_at = timestamp()
	`
	params := map[string]any{
		"ttp_id":      ttp.TTPID,
		"name":        ttp.Name,
		"tactic":      ttp.Tactic,
		"description": ttp.Description,
	}

	return executeWriteHelper(ctx, r.driver, query, params)
}

func (r *ttpRepo) Update(ctx context.Context, ttp *domain.TTP) error {
	query := `
		MATCH (t:TTP {ttp_id: $ttp_id})
		SET t.name = $name,
		    t.tactic = $tactic,
		    t.description = $description,
		    t.updated_at = timestamp()
	`
	params := map[string]any{
		"ttp_id":      ttp.TTPID,
		"name":        ttp.Name,
		"tactic":      ttp.Tactic,
		"description": ttp.Description,
	}

	return executeWriteUpdateHelper(ctx, r.driver, query, params)
}

func (r *ttpRepo) GetByID(ctx context.Context, id string) (*domain.TTP, error) {
	query := `MATCH (t:TTP {ttp_id: $id}) RETURN properties(t) AS props`
	props, err := executeReadHelper(ctx, r.driver, query, map[string]any{"id": id})
	if err != nil || props == nil {
		return nil, err
	}

	ttp := &domain.TTP{
		TTPID:       getString(props, "ttp_id"),
		Name:        getString(props, "name"),
		Tactic:      getString(props, "tactic"),
		Description: getString(props, "description"),
	}
	return ttp, nil
}

func (r *ttpRepo) DeleteByID(ctx context.Context, id string) error {
	query := `MATCH (t:TTP {ttp_id: $id}) DETACH DELETE t`
	return executeWriteHelper(ctx, r.driver, query, map[string]any{"id": id})
}

func (r *ttpRepo) SaveBatch(ctx context.Context, ttps []domain.TTP) error {
	if len(ttps) == 0 {
		return nil
	}

	var ttpMaps []map[string]any
	for _, t := range ttps {
		ttpMaps = append(ttpMaps, map[string]any{
			"ttp_id":      t.TTPID,
			"name":        t.Name,
			"tactic":      t.Tactic,
			"description": t.Description,
		})
	}

	query := `
		UNWIND $ttps AS item
		MERGE (t:TTP {ttp_id: item.ttp_id})
		SET t.name = item.name,
		    t.tactic = item.tactic,
		    t.description = item.description,
		    t.updated_at = timestamp()
	`

	return executeWriteHelper(ctx, r.driver, query, map[string]any{"ttps": ttpMaps})
}

// GetCatalog devuelve el catálogo vigente ordenado por identificador.
//
// Solo id, nombre y tácticas: es lo que se inyecta en el prompt del mapeador, y
// las descripciones lo harían inmanejable sin aportar nada a la elección.
func (r *ttpRepo) GetCatalog(ctx context.Context) ([]domain.TTP, error) {
	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	query := `
		MATCH (t:TTP)
		RETURN t.ttp_id AS id, coalesce(t.name,'') AS name, coalesce(t.tactic,'') AS tactic
		ORDER BY id
	`

	res, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		resultado, err := tx.Run(ctx, query, nil)
		if err != nil {
			return nil, err
		}
		var catalogo []domain.TTP
		for resultado.Next(ctx) {
			datos := resultado.Record().AsMap()
			id, _ := datos["id"].(string)
			if id == "" {
				continue
			}
			nombre, _ := datos["name"].(string)
			tactica, _ := datos["tactic"].(string)
			catalogo = append(catalogo, domain.TTP{TTPID: id, Name: nombre, Tactic: tactica})
		}
		return catalogo, resultado.Err()
	})
	if err != nil {
		return nil, err
	}

	catalogo, _ := res.([]domain.TTP)
	return catalogo, nil
}

// SaveCatalogInfo guarda la versión de ATT&CK de la que procede el catálogo.
//
// Es un nodo único: no interesa el histórico, sino saber en todo momento con qué
// versión hay que interpretar las técnicas del grafo. Quien exporta una capa para
// el ATT&CK Navigator necesita declararla, y hasta ahora se fijaba a mano en el
// frontend, donde se quedó desfasada sin que nada lo detectara.
func (r *ttpRepo) SaveCatalogInfo(ctx context.Context, info domain.ATTACKCatalogInfo) error {
	query := `
		MERGE (c:ATTACKCatalog {name: 'enterprise-attack'})
		SET c.version = $version,
		    c.spec_version = $spec_version,
		    c.total_ttps = $total_ttps,
		    c.updated_at = timestamp()
	`
	params := map[string]any{
		"version":      info.Version,
		"spec_version": info.SpecVersion,
		"total_ttps":   info.TotalTTPs,
	}
	return executeWriteHelper(ctx, r.driver, query, params)
}
