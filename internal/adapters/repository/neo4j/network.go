package neo4j

import (
	"context"

	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/domain"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

type networkRepo struct {
	driver neo4j.DriverWithContext
}

func (r *networkRepo) Save(ctx context.Context, nw *domain.Network) error {
	query := `
		MERGE (n:Network {id: $id})
		ON CREATE SET n.nombre = $name,
		    n.cidr = $cidr,
		    n.gateway = $gw,
		    n.vlan_id = $vlan,
		    n.descripcion = $desc
	`
	params := map[string]any{
		"id":   nw.NetworkID,
		"name": nw.Nombre,
		"cidr": nw.CIDR,
		"gw":   nw.Gateway,
		"vlan": nw.VLANID,
		"desc": nw.Descripcion,
	}
	return executeWriteHelper(ctx, r.driver, query, params)
}

func (r *networkRepo) Update(ctx context.Context, nw *domain.Network) error {
	query := `
		MATCH (n:Network {id: $id})
		SET n.nombre = $name,
		    n.cidr = $cidr,
		    n.gateway = $gw,
		    n.vlan_id = $vlan,
		    n.descripcion = $desc
	`
	params := map[string]any{
		"id":   nw.NetworkID,
		"name": nw.Nombre,
		"cidr": nw.CIDR,
		"gw":   nw.Gateway,
		"vlan": nw.VLANID,
		"desc": nw.Descripcion,
	}
	return executeWriteHelper(ctx, r.driver, query, params)
}

func (r *networkRepo) GetByID(ctx context.Context, id int64) (*domain.Network, error) {
	query := `MATCH (n:Network {id: $id}) RETURN properties(n) AS props`
	props, err := executeReadHelper(ctx, r.driver, query, map[string]any{"id": id})
	if err != nil || props == nil {
		return nil, err
	}
	return &domain.Network{
		NetworkID:   getInt64(props, "id"),
		Nombre:      getString(props, "nombre"),
		CIDR:        getString(props, "cidr"),
		Gateway:     getString(props, "gateway"),
		VLANID:      getInt64(props, "vlan_id"),
		Descripcion: getString(props, "descripcion"),
	}, nil
}

func (r *networkRepo) DeleteByID(ctx context.Context, id int64) error {
	query := `MATCH (n:Network {id: $id}) DETACH DELETE n`
	return executeWriteHelper(ctx, r.driver, query, map[string]any{"id": id})
}