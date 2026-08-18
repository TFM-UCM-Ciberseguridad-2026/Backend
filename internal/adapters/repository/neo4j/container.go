package neo4j

import (
	"context"
	"fmt"
	"strings"

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

// normalizeContainerImageID limpia nombres de imagen malformados como "nginx:1.19:latest" → "nginx:1.19".
func normalizeContainerImageID(name string) string {
	parts := strings.Split(name, ":")
	if len(parts) <= 2 {
		return name
	}
	// Más de un ':', ej: "httpd:2.4.49:latest" → quitar ":latest" del final
	if parts[len(parts)-1] == "latest" {
		return strings.Join(parts[:len(parts)-1], ":")
	}
	// Otro formato: quedarse con los dos primeros segmentos
	return parts[0] + ":" + parts[1]
}

func (r *containerRepo) SaveContainer(ctx context.Context, container *domain.Container) error {
	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)

	query := `
		MERGE (c:Container {id: $id})
		SET c.name = $name,
		    c.state = $state,
		    c.image_id = $image_id,
		    c.internet_exposed = $internet_exposed,
		    c.privileged = $privileged,
		    c.risk_score = $risk_score
		
		WITH c
		// Asociar al host (obligatorio)
		MATCH (e:Endpoint)
		WHERE e.id = $host_id OR toInteger(e.id) = toInteger($host_id) OR toString(e.id) = toString($host_id)
		MERGE (e)-[:HOSTS]->(c)
	`
	// Normalizar el image_id para evitar nombres como "httpd:2.4.49:latest"
	imageID := normalizeContainerImageID(container.ImageID)

	params := map[string]any{
		"id":               container.ContainerID,
		"name":             container.Name,
		"state":            container.State,
		"image_id":         imageID,
		"internet_exposed": container.InternetExposed,
		"privileged":       container.Privileged,
		"host_id":          container.HostID,
		"risk_score":       container.RiskScore,
	}

	_, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		return tx.Run(ctx, query, params)
	})
	if err != nil {
		return err
	}

	// Desenlazar imagen anterior si ha cambiado o se ha vaciado
	cleanQuery := `
		MATCH (c:Container {id: $id})-[r:USES_IMAGE]->(old_i:ContainerImage)
		WHERE old_i.id <> $image_id OR $image_id = ''
		DELETE r
		WITH old_i
		WHERE NOT ()-[:USES_IMAGE]->(old_i)
		DETACH DELETE old_i
	`
	_, _ = session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		return tx.Run(ctx, cleanQuery, params)
	})

	if container.ImageID != "" {
		imgQuery := `
			MATCH (c:Container {id: $id})
			MERGE (i:ContainerImage {id: $image_id})
			ON CREATE SET i.name = $image_id
			MERGE (c)-[:USES_IMAGE]->(i)
		`
		_, _ = session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
			return tx.Run(ctx, imgQuery, params)
		})
	}
	return nil
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

			getBool := func(val any) bool {
				if val == nil { return false }
				if b, ok := val.(bool); ok { return b }
				return false
			}

			return &domain.Container{
				ContainerID: getString(props["id"]),
				Name:        getString(props["name"]),
				State:       getString(props["state"]),
				RiskScore:   getFloat(props["risk_score"]),
				InternetExposed: getBool(props["internet_exposed"]),
				Privileged:  getBool(props["privileged"]),
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
		MERGE (f:Finding {unique_ref: 'finding-' + $image_id + '-' + $cve_id})
		ON CREATE SET f.id = id(f),
		              f.status = 'OPEN',
		              f.severity = coalesce(v.severity, 'CRITICAL'),
		              f.risk_score = coalesce(v.base_score / 10.0, 0.98),
		              f.impact_score = coalesce(v.base_score / 10.0, 0.98),
		              f.likelihood = 1.0,
		              f.exposure_factor = 1.0,
		              f.remediation_factor = 1.0
		MERGE (ci)-[:HAS_FINDING]->(f)
		MERGE (f)-[:OF_VULNERABILITY]->(v)
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

func (r *containerRepo) SaveIPs(ctx context.Context, containerID string, ips []domain.EndpointIP) error {
	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)

	// Primero eliminar relaciones existentes
	delQuery := `
		MATCH (c:Container {id: $container_id})-[:HAS_IP]->(ip:IPAddress)
		DETACH DELETE ip
	`
	_, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		return tx.Run(ctx, delQuery, map[string]any{"container_id": containerID})
	})
	if err != nil {
		return err
	}

	if len(ips) == 0 {
		return nil
	}

	// Luego enlazar las nuevas
	for _, ipData := range ips {
		query := `
			MATCH (c:Container {id: $container_id})
			CREATE (ip:IPAddress {ip: $ip, vlan_id: $vlan_id})
			MERGE (c)-[:HAS_IP]->(ip)
		`
		params := map[string]any{
			"container_id": containerID,
			"ip":           ipData.IP,
			"vlan_id":      ipData.VLANID,
		}
		_, err = session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
			return tx.Run(ctx, query, params)
		})
		if err != nil {
			return err
		}
	}
	return nil
}
