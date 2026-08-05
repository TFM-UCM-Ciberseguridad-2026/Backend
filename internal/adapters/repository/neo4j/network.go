package neo4j

import (
	"context"
	"fmt"
	"net"

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
	return executeWriteSaveHelper(ctx, r.driver, query, params)
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
	return executeWriteUpdateHelper(ctx, r.driver, query, params)
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

// LinkMatchingEndpoints recorre todos los endpoints con IPs registradas y conecta
// los que caen dentro del CIDR de la red y, si la red define VLAN,
// comparten esa misma VLAN. Devuelve cuántos endpoints se enlazaron.
func (r *networkRepo) LinkMatchingEndpoints(ctx context.Context, networkID int64, cidr string, vlanID int64) (int, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return 0, fmt.Errorf("CIDR inválido: %w", err)
	}

	readSession := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer readSession.Close(ctx)

	type candidate struct {
		endpointID int64
	}

	res, err := readSession.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		result, err := tx.Run(ctx, `
			MATCH (e:Endpoint)-[:HAS_IP]->(ip:IPAddress)
			RETURN e.id AS endpoint_id, ip.ip AS ip, ip.vlan_id AS vlan_id
		`, nil)
		if err != nil {
			return nil, err
		}

		var matches []candidate
		for result.Next(ctx) {
			rec := result.Record()
			endpointIDVal, _ := rec.Get("endpoint_id")
			ipVal, _ := rec.Get("ip")
			vlanVal, _ := rec.Get("vlan_id")

			parsedIP := net.ParseIP(getStringAny(ipVal))
			if parsedIP == nil || !ipNet.Contains(parsedIP) {
				continue
			}
			if vlanID > 0 && getInt64Any(vlanVal) != vlanID {
				continue
			}
			matches = append(matches, candidate{endpointID: getInt64Any(endpointIDVal)})
		}
		return matches, result.Err()
	})
	if err != nil {
		return 0, err
	}

	matches, _ := res.([]candidate)
	if len(matches) == 0 {
		return 0, nil
	}

	writeSession := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer writeSession.Close(ctx)

	_, err = writeSession.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		for _, m := range matches {
			if _, err := tx.Run(ctx, `
				MATCH (e:Endpoint {id: $endpoint_id})
				MATCH (n:Network {id: $network_id})
				MERGE (e)-[:CONNECTED_TO]->(n)
			`, map[string]any{
				"endpoint_id": m.endpointID,
				"network_id":  networkID,
			}); err != nil {
				return nil, err
			}
		}
		return nil, nil
	})
	if err != nil {
		return 0, err
	}

	return len(matches), nil
}