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
