package neo4j

import (
	"context"
	"fmt"

	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/domain"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

type threatActorRepo struct {
	driver neo4j.DriverWithContext
}

// NewThreatActorRepository crea una instancia del repositorio de ThreatActor.
func NewThreatActorRepository(driver neo4j.DriverWithContext) *threatActorRepo {
	return &threatActorRepo{driver: driver}
}

func (r *threatActorRepo) Save(ctx context.Context, actor *domain.ThreatActor) error {
	query := `
		MERGE (a:ThreatActor {actor_id: $actor_id})
		ON CREATE SET a.name = $name,
		    a.description = $description,
		    a.aliases = $aliases,
		    a.updated_at = timestamp()
	`
	params := map[string]any{
		"actor_id":    actor.ActorID,
		"name":        actor.Name,
		"description": actor.Description,
		"aliases":     actor.Aliases,
	}

	return executeWriteSaveHelper(ctx, r.driver, query, params)
}

func (r *threatActorRepo) Update(ctx context.Context, actor *domain.ThreatActor) error {
	query := `
		MATCH (a:ThreatActor {actor_id: $actor_id})
		SET a.name = $name,
		    a.description = $description,
		    a.aliases = $aliases,
		    a.updated_at = timestamp()
	`
	params := map[string]any{
		"actor_id":    actor.ActorID,
		"name":        actor.Name,
		"description": actor.Description,
		"aliases":     actor.Aliases,
	}

	return executeWriteUpdateHelper(ctx, r.driver, query, params)
}

func (r *threatActorRepo) GetByID(ctx context.Context, id string) (*domain.ThreatActor, error) {
	query := `MATCH (a:ThreatActor {actor_id: $id}) RETURN properties(a) AS props`
	props, err := executeReadHelper(ctx, r.driver, query, map[string]any{"id": id})
	if err != nil || props == nil {
		return nil, err
	}

	actor := &domain.ThreatActor{
		ActorID:     getString(props, "actor_id"),
		Name:        getString(props, "name"),
		Description: getString(props, "description"),
		Aliases:     getString(props, "aliases"),
	}
	return actor, nil
}

func (r *threatActorRepo) DeleteByID(ctx context.Context, id string) error {
	query := `MATCH (a:ThreatActor {actor_id: $id}) DETACH DELETE a`
	return executeWriteHelper(ctx, r.driver, query, map[string]any{"id": id})
}

func (r *threatActorRepo) RelateToTTP(ctx context.Context, actorID string, ttpID string) error {
	query := `
		MATCH (a:ThreatActor {actor_id: $actor_id})
		MATCH (t:TTP {ttp_id: $ttp_id})
		MERGE (a)-[r:USES]->(t)
		SET r.updated_at = timestamp()
	`
	params := map[string]any{
		"actor_id": actorID,
		"ttp_id":   ttpID,
	}
	return executeWriteHelper(ctx, r.driver, query, params)
}

func (r *threatActorRepo) GetTopThreatActors(ctx context.Context, limit int) ([]domain.ThreatActorThreat, error) {
	// Query to find ThreatActors and the count of TTPs they are related to
	query := `
		MATCH (a:ThreatActor)-[:USES]->(t:TTP)
		RETURN properties(a) AS props, count(t) as ttp_count
		ORDER BY ttp_count DESC
		LIMIT $limit
	`
	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	result, err := session.Run(ctx, query, map[string]any{"limit": limit})
	if err != nil {
		return nil, err
	}

	var actors []domain.ThreatActorThreat
	for result.Next(ctx) {
		record := result.Record()
		propsRaw, ok := record.Get("props")
		if !ok {
			continue
		}
		props, ok := propsRaw.(map[string]any)
		if !ok {
			continue
		}
		
		ttpCountRaw, _ := record.Get("ttp_count")
		ttpCount := int(ttpCountRaw.(int64))

		actor := domain.ThreatActor{
			ActorID:     getString(props, "actor_id"),
			Name:        getString(props, "name"),
			Description: getString(props, "description"),
			Aliases:     getString(props, "aliases"),
		}

		actors = append(actors, domain.ThreatActorThreat{
			ThreatActor: actor,
			TTPCount:    ttpCount,
		})
	}

	if err = result.Err(); err != nil {
		return nil, fmt.Errorf("error iterando resultados GetTopThreatActors: %v", err)
	}

	return actors, nil
}
