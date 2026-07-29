package neo4j

import (
	"context"
	"fmt"

	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/domain"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/ports"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

type containerRepo struct {
	driver neo4j.DriverWithContext
}

func NewContainerRepository(driver neo4j.DriverWithContext) ports.ContainerPort {
	return &containerRepo{driver: driver}
}

func (r *containerRepo) SaveContainerImage(ctx context.Context, image *domain.ContainerImage) error {
	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)

	query := `
		MERGE (i:ContainerImage {id: $id})
		SET i.name = $name,
		    i.tag = $tag,
		    i.digest = $digest,
		    i.risk_score = $risk_score
	`
	params := map[string]any{
		"id":         image.ImageID,
		"name":       image.Name,
		"tag":        image.Tag,
		"digest":     image.Digest,
		"risk_score": image.RiskScore,
	}

	_, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		return tx.Run(ctx, query, params)
	})
	return err
}

func (r *containerRepo) GetContainerImage(ctx context.Context, imageID string) (*domain.ContainerImage, error) {
	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	query := `MATCH (i:ContainerImage {id: $id}) RETURN i`
	res, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		result, err := tx.Run(ctx, query, map[string]any{"id": imageID})
		if err != nil {
			return nil, err
		}
		if result.Next(ctx) {
			node := result.Record().Values[0].(neo4j.Node)
			props := node.GetProperties()
			
			getFloat := func(val any) float64 {
				if val == nil { return 0.0 }
				if f, ok := val.(float64); ok { return f }
				if i, ok := val.(int64); ok { return float64(i) }
				return 0.0
			}
			getString := func(val any) string {
				if val == nil { return "" }
				if s, ok := val.(string); ok { return s }
				return ""
			}

			return &domain.ContainerImage{
				ImageID:   getString(props["id"]),
				Name:      getString(props["name"]),
				Tag:       getString(props["tag"]),
				Digest:    getString(props["digest"]),
				RiskScore: getFloat(props["risk_score"]),
			}, nil
		}
		return nil, nil
	})

	if err != nil {
		return nil, err
	}
	if res == nil {
		return nil, fmt.Errorf("container image not found")
	}
	return res.(*domain.ContainerImage), nil
}

// GetAllContainerImages devuelve todas las imágenes registradas
func (r *containerRepo) GetAllContainerImages(ctx context.Context) ([]domain.ContainerImage, error) {
	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	getString := func(props map[string]any, key string) string {
		if val, ok := props[key]; ok {
			if s, ok := val.(string); ok {
				return s
			}
		}
		return ""
	}

	query := `
		MATCH (i:ContainerImage)
		RETURN i
	`
	res, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		result, err := tx.Run(ctx, query, nil)
		if err != nil {
			return nil, err
		}
		
		var images []domain.ContainerImage
		for result.Next(ctx) {
			record := result.Record()
			node, _ := record.Get("i")
			iNode := node.(neo4j.Node)
			props := iNode.GetProperties()

			images = append(images, domain.ContainerImage{
				ImageID: getString(props, "id"),
				Name:    getString(props, "name"),
				Tag:     getString(props, "tag"),
				Digest:  getString(props, "digest"),
			})
		}
		return images, result.Err()
	})

	if err != nil {
		return nil, err
	}
	if res == nil {
		return []domain.ContainerImage{}, nil
	}
	return res.([]domain.ContainerImage), nil
}

func (r *containerRepo) SaveContainer(ctx context.Context, container *domain.Container) error {
	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)

	query := `
		MERGE (c:Container {id: $id})
		SET c.name = $name,
		    c.state = $state,
		    c.risk_score = $risk_score
		
		WITH c
		// Asociar a la imagen si se proporcionó
		MATCH (i:ContainerImage {id: $image_id})
		MERGE (c)-[:USES_IMAGE]->(i)
		
		WITH c
		// Asociar al host
		MATCH (e:Endpoint {id: $host_id})
		MERGE (e)-[:HOSTS]->(c)
	`
	params := map[string]any{
		"id":         container.ContainerID,
		"name":       container.Name,
		"state":      container.State,
		"image_id":   container.ImageID,
		"host_id":    container.HostID,
		"risk_score": container.RiskScore,
	}

	_, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		return tx.Run(ctx, query, params)
	})
	return err
}

func (r *containerRepo) GetContainer(ctx context.Context, containerID string) (*domain.Container, error) {
	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	query := `
		MATCH (c:Container {id: $id})
		OPTIONAL MATCH (c)-[:USES_IMAGE]->(i:ContainerImage)
		OPTIONAL MATCH (e:Endpoint)-[:HOSTS]->(c)
		RETURN c, i.id AS image_id, e.id AS host_id
	`
	res, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		result, err := tx.Run(ctx, query, map[string]any{"id": containerID})
		if err != nil {
			return nil, err
		}
		if result.Next(ctx) {
			record := result.Record()
			cNode := record.Values[0].(neo4j.Node)
			props := cNode.GetProperties()
			
			getFloat := func(val any) float64 {
				if val == nil { return 0.0 }
				if f, ok := val.(float64); ok { return f }
				if i, ok := val.(int64); ok { return float64(i) }
				return 0.0
			}
			getString := func(val any) string {
				if val == nil { return "" }
				if s, ok := val.(string); ok { return s }
				return ""
			}
			getInt := func(val any) int64 {
				if val == nil { return 0 }
				if i, ok := val.(int64); ok { return i }
				return 0
			}

			imgID, _ := record.Get("image_id")
			hostID, _ := record.Get("host_id")

			return &domain.Container{
				ContainerID: getString(props["id"]),
				Name:        getString(props["name"]),
				State:       getString(props["state"]),
				RiskScore:   getFloat(props["risk_score"]),
				ImageID:     getString(imgID),
				HostID:      getInt(hostID),
			}, nil
		}
		return nil, nil
	})

	if err != nil {
		return nil, err
	}
	if res == nil {
		return nil, fmt.Errorf("container not found")
	}
	return res.(*domain.Container), nil
}

// LinkVulnerabilityToImage enlaza una imagen de contenedor con un CVE (descubierto por ejemplo por Docker Scout)
func (r *containerRepo) LinkVulnerabilityToImage(ctx context.Context, imageID string, cveID string) error {
	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)

	query := `
		MATCH (ci:ContainerImage {id: $image_id})
		MATCH (v:Vulnerability {cve_id: $cve_id})
		MERGE (ci)-[:HAS_VULNERABILITY]->(v)
	`
	params := map[string]any{
		"image_id": imageID,
		"cve_id":   cveID,
	}

	_, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		return tx.Run(ctx, query, params)
	})
	return err
}
