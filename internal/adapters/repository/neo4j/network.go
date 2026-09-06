package neo4j

import (
	"context"
	"net"
	"fmt"

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
	query := `
		MATCH (n:Network)
		WHERE toString(n.id) = toString($id) OR elementId(n) = toString($id)
		DETACH DELETE n
	`
	_ = executeWriteHelper(ctx, r.driver, query, map[string]any{"id": id})

	cleanupQuery := `
		MATCH (n)
		WHERE (n:Software OR n:Network OR n:Hardware OR n:IPAddress OR n:SoftwareInstallation OR n:Finding OR n:Remediation OR n:Exploit OR n:Patch OR n:Container OR n:ContainerImage OR n:Vulnerability)
		  AND NOT EXISTS((n)-[*1..5]-(:Endpoint)) AND NOT EXISTS((n)-[*1..5]-(:Project))
		DETACH DELETE n
	`
	return executeWriteHelper(ctx, r.driver, cleanupQuery, nil)
}

// LinkMatchingEndpoints recorre todos los Endpoints y Contenedores con IPs registradas y conecta
// los que caen dentro del CIDR y coinciden en VLAN con la red. Devuelve cuántos activos se enlazaron.
func (r *networkRepo) LinkMatchingEndpoints(ctx context.Context, networkID int64, cidr string, vlanID int64) (int, error) {
	var ipNet *net.IPNet
	if cidr != "" {
		_, ipNet, _ = net.ParseCIDR(cidr)
	}
	if ipNet == nil && vlanID <= 0 {
		return 0, nil
	}

	readSession := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer readSession.Close(ctx)

	type candidate struct {
		nodeID  any
		isCont  bool
	}

	res, err := readSession.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		result, err := tx.Run(ctx, `
			MATCH (e)-[:HAS_IP]->(ip:IPAddress)
			WHERE e:Endpoint OR e:Container
			RETURN e.id AS node_id, labels(e) AS labels, ip.ip AS ip, ip.vlan_id AS vlan_id
		`, nil)
		if err != nil {
			return nil, err
		}

		var matches []candidate
		seen := make(map[string]bool)

		for result.Next(ctx) {
			rec := result.Record()
			nodeIDVal, _ := rec.Get("node_id")
			labelsVal, _ := rec.Get("labels")
			ipVal, _ := rec.Get("ip")
			vlanVal, _ := rec.Get("vlan_id")
			epVlan := getInt64Any(vlanVal)

			isContainer := false
			if lList, ok := labelsVal.([]any); ok {
				for _, l := range lList {
					if lStr, ok := l.(string); ok && lStr == "Container" {
						isContainer = true
						break
					}
				}
			}

			matched := true
			if vlanID > 0 && epVlan != vlanID {
				matched = false
			}

			if ipNet != nil {
				parsedIP := net.ParseIP(getStringAny(ipVal))
				if parsedIP == nil || !ipNet.Contains(parsedIP) {
					matched = false
				}
			}

			key := fmt.Sprintf("%v", nodeIDVal)
			if matched && !seen[key] {
				seen[key] = true
				matches = append(matches, candidate{nodeID: nodeIDVal, isCont: isContainer})
			}
		}
		return matches, result.Err()
	})
	if err != nil {
		return 0, err
	}

	matches, _ := res.([]candidate)
	writeSession := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer writeSession.Close(ctx)

	_, err = writeSession.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		// 1. Desconectar los activos antiguos manteniendo relaciones de proyecto
		_, err := tx.Run(ctx, `
			MATCH (e)-[r:CONNECTED_TO]->(n:Network)
			WHERE (e:Endpoint OR e:Container)
			  AND (toInteger(n.id) = toInteger($network_id) OR toString(n.id) = toString($network_id) OR elementId(n) = toString($network_id))
			WITH e, r, n
			OPTIONAL MATCH (p:Project)-[:HAS_ENDPOINT]->(e)
			WITH e, r, n, p
			FOREACH (proj IN CASE WHEN p IS NOT NULL THEN [p] ELSE [] END |
				MERGE (proj)-[:CONTAINS_NETWORK]->(n)
			)
			WITH e, r
			DELETE r
		`, map[string]any{"network_id": networkID})
		if err != nil {
			return nil, err
		}

		if len(matches) == 0 {
			return nil, nil
		}

		// 2. Conectar los matches (Endpoints y Contenedores)
		for _, m := range matches {
			if _, err := tx.Run(ctx, `
				MATCH (e), (n:Network)
				WHERE (e:Endpoint OR e:Container)
				  AND (toInteger(e.id) = toInteger($node_id) OR toString(e.id) = toString($node_id) OR e.id = $node_id)
				  AND (toInteger(n.id) = toInteger($network_id) OR toString(n.id) = toString($network_id) OR elementId(n) = toString($network_id))
				MERGE (e)-[:CONNECTED_TO]->(n)
				WITH e, n
				OPTIONAL MATCH (p:Project)-[:HAS_ENDPOINT]->(e)
				WITH n, p
				FOREACH (proj IN CASE WHEN p IS NOT NULL THEN [p] ELSE [] END |
					MERGE (proj)-[:CONTAINS_NETWORK]->(n)
				)
			`, map[string]any{
				"node_id":    m.nodeID,
				"network_id": networkID,
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

func (r *networkRepo) LinkEndpointToMatchingNetworks(ctx context.Context, endpointID int64, ips []domain.EndpointIP) (int, error) {
	writeSession := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer writeSession.Close(ctx)

	_, _ = writeSession.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		_, err := tx.Run(ctx, `
			MATCH (e:Endpoint)-[r:CONNECTED_TO]->(n:Network)
			WHERE toInteger(e.id) = toInteger($endpoint_id) OR toString(e.id) = toString($endpoint_id) OR elementId(e) = toString($endpoint_id)
			WITH e, r, n
			OPTIONAL MATCH (p:Project)-[:HAS_ENDPOINT]->(e)
			WITH e, r, n, p
			FOREACH (proj IN CASE WHEN p IS NOT NULL THEN [p] ELSE [] END |
				MERGE (proj)-[:CONTAINS_NETWORK]->(n)
			)
			WITH e, r
			DELETE r
		`, map[string]any{"endpoint_id": endpointID})
		return nil, err
	})

	if len(ips) == 0 {
		return 0, nil
	}

	readSession := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer readSession.Close(ctx)

	type networkCandidate struct {
		networkID int64
		cidr      string
		vlanID    int64
	}

	res, err := readSession.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		result, err := tx.Run(ctx, `
			MATCH (n:Network)
			RETURN n.id AS network_id, n.cidr AS cidr, n.vlan_id AS vlan_id
		`, nil)
		if err != nil {
			return nil, err
		}

		var candidates []networkCandidate
		for result.Next(ctx) {
			rec := result.Record()
			netIDVal, _ := rec.Get("network_id")
			cidrVal, _ := rec.Get("cidr")
			vlanVal, _ := rec.Get("vlan_id")

			candidates = append(candidates, networkCandidate{
				networkID: getInt64Any(netIDVal),
				cidr:      getStringAny(cidrVal),
				vlanID:    getInt64Any(vlanVal),
			})
		}
		return candidates, result.Err()
	})
	if err != nil {
		return 0, err
	}

	candidates, _ := res.([]networkCandidate)
	if len(candidates) == 0 {
		return 0, nil
	}

	var matchingNetworkIDs []int64
	for _, cand := range candidates {
		matched := false
		for _, ipEntry := range ips {
			ipMatch := true

			if cand.vlanID > 0 && ipEntry.VLANID != cand.vlanID {
				ipMatch = false
			}

			if cand.cidr != "" {
				_, ipNet, err := net.ParseCIDR(cand.cidr)
				parsedIP := net.ParseIP(ipEntry.IP)
				if err != nil || parsedIP == nil || !ipNet.Contains(parsedIP) {
					ipMatch = false
				}
			}

			if ipMatch {
				matched = true
				break
			}
		}
		if matched {
			matchingNetworkIDs = append(matchingNetworkIDs, cand.networkID)
		}
	}

	if len(matchingNetworkIDs) == 0 {
		return 0, nil
	}

	writeSession2 := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer writeSession2.Close(ctx)

	_, err = writeSession2.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		for _, netID := range matchingNetworkIDs {
			if _, err := tx.Run(ctx, `
				MATCH (e:Endpoint), (n:Network)
				WHERE (toInteger(e.id) = toInteger($endpoint_id) OR toString(e.id) = toString($endpoint_id))
				  AND (toInteger(n.id) = toInteger($network_id) OR toString(n.id) = toString($network_id))
				MERGE (e)-[:CONNECTED_TO]->(n)
				WITH e, n
				OPTIONAL MATCH (p:Project)-[:HAS_ENDPOINT]->(e)
				WITH n, p
				FOREACH (proj IN CASE WHEN p IS NOT NULL THEN [p] ELSE [] END |
					MERGE (proj)-[:CONTAINS_NETWORK]->(n)
				)
			`, map[string]any{
				"endpoint_id": endpointID,
				"network_id":  netID,
			}); err != nil {
				return nil, err
			}
		}
		return nil, nil
	})
	if err != nil {
		return 0, err
	}

	return len(matchingNetworkIDs), nil
}

func (r *networkRepo) LinkNetworkToProjectIfOrphan(ctx context.Context, networkID int64, projectID int64) error {
	query := `
		MATCH (n:Network)
		WHERE (toInteger(n.id) = toInteger($network_id) OR toString(n.id) = toString($network_id) OR elementId(n) = toString($network_id))
		  AND NOT EXISTS((:Project)-[:CONTAINS_NETWORK]->(n))
		  AND NOT EXISTS((:Endpoint)-[:CONNECTED_TO]->(n))
		  AND NOT EXISTS((:Container)-[:CONNECTED_TO]->(n))
		WITH n
		MATCH (p:Project)
		WHERE toInteger(p.id) = toInteger($project_id) OR toString(p.id) = toString($project_id) OR elementId(p) = toString($project_id)
		MERGE (p)-[:CONTAINS_NETWORK]->(n)
	`
	return executeWriteHelper(ctx, r.driver, query, map[string]any{
		"network_id": networkID,
		"project_id": projectID,
	})
}

func (r *networkRepo) LinkContainerToMatchingNetworks(ctx context.Context, containerID string, ips []domain.EndpointIP) (int, error) {
	writeSession := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer writeSession.Close(ctx)

	_, _ = writeSession.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		_, err := tx.Run(ctx, `
			MATCH (c:Container)-[r:CONNECTED_TO]->(n:Network)
			WHERE c.id = $container_id OR toString(c.id) = toString($container_id)
			WITH c, r, n
			OPTIONAL MATCH (p:Project)-[:HAS_ENDPOINT]->(:Endpoint)-[:HOSTS]->(c)
			WITH c, r, n, p
			FOREACH (proj IN CASE WHEN p IS NOT NULL THEN [p] ELSE [] END |
				MERGE (proj)-[:CONTAINS_NETWORK]->(n)
			)
			WITH c, r
			DELETE r
		`, map[string]any{"container_id": containerID})
		return nil, err
	})

	if len(ips) == 0 {
		return 0, nil
	}

	readSession := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer readSession.Close(ctx)

	type networkCandidate struct {
		networkID int64
		cidr      string
		vlanID    int64
	}

	res, err := readSession.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		result, err := tx.Run(ctx, "MATCH (n:Network) RETURN n.id AS network_id, n.cidr AS cidr, n.vlan_id AS vlan_id", nil)
		if err != nil {
			return nil, err
		}

		var candidates []networkCandidate
		for result.Next(ctx) {
			rec := result.Record()
			netIDVal, _ := rec.Get("network_id")
			cidrVal, _ := rec.Get("cidr")
			vlanVal, _ := rec.Get("vlan_id")

			candidates = append(candidates, networkCandidate{
				networkID: getInt64Any(netIDVal),
				cidr:      getStringAny(cidrVal),
				vlanID:    getInt64Any(vlanVal),
			})
		}
		return candidates, result.Err()
	})
	if err != nil {
		return 0, err
	}

	candidates, _ := res.([]networkCandidate)
	if len(candidates) == 0 {
		return 0, nil
	}

	var matchingNetworkIDs []int64
	for _, cand := range candidates {
		matched := false
		for _, ipEntry := range ips {
			if cand.vlanID > 0 && ipEntry.VLANID != cand.vlanID {
				continue
			}
			if cand.cidr != "" {
				if _, ipNet, err := net.ParseCIDR(cand.cidr); err == nil {
					if parsedIP := net.ParseIP(ipEntry.IP); parsedIP != nil && ipNet.Contains(parsedIP) {
						if cand.vlanID == 0 || ipEntry.VLANID == cand.vlanID {
							matched = true
							break
						}
					}
				}
			}
		}
		if matched {
			matchingNetworkIDs = append(matchingNetworkIDs, cand.networkID)
		}
	}

	if len(matchingNetworkIDs) == 0 {
		return 0, nil
	}

	writeSession2 := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer writeSession2.Close(ctx)

	_, err = writeSession2.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		for _, netID := range matchingNetworkIDs {
			if _, err := tx.Run(ctx, `
				MATCH (c:Container), (n:Network)
				WHERE (c.id = $container_id OR toString(c.id) = toString($container_id))
				  AND (toInteger(n.id) = toInteger($network_id) OR toString(n.id) = toString($network_id))
				MERGE (c)-[:CONNECTED_TO]->(n)
				WITH c, n
				OPTIONAL MATCH (p:Project)-[:HAS_ENDPOINT]->(e:Endpoint)-[:HOSTS]->(c)
				WITH n, p
				FOREACH (proj IN CASE WHEN p IS NOT NULL THEN [p] ELSE [] END |
					MERGE (proj)-[:CONTAINS_NETWORK]->(n)
				)
			`, map[string]any{
				"container_id": containerID,
				"network_id":   netID,
			}); err != nil {
				return nil, err
			}
		}
		return nil, nil
	})
	if err != nil {
		return 0, err
	}

	return len(matchingNetworkIDs), nil
}