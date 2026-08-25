package neo4j

import (
	"context"
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

// LinkMatchingEndpoints recorre todos los endpoints con IPs registradas y conecta
// los que caen dentro del CIDR de la red y, si la red define VLAN,
// comparten esa misma VLAN. Devuelve cuántos endpoints se enlazaron.
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
			epVlan := getInt64Any(vlanVal)

			// Evaluamos con condición AND estricta:
			matched := true

			// Condición 1: Si se especificó VLAN (> 0), DEBE coincidir
			if vlanID > 0 && epVlan != vlanID {
				matched = false
			}

			// Condición 2: Si se especificó CIDR, la IP DEBE estar dentro del rango
			if ipNet != nil {
				parsedIP := net.ParseIP(getStringAny(ipVal))
				if parsedIP == nil || !ipNet.Contains(parsedIP) {
					matched = false
				}
			}

			if matched {
				matches = append(matches, candidate{endpointID: getInt64Any(endpointIDVal)})
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
		// 1. Desconectar a los endpoints antiguos, reteniendo la red en el proyecto
		_, err := tx.Run(ctx, `
			MATCH (e:Endpoint)-[r:CONNECTED_TO]->(n:Network)
			WHERE toInteger(n.id) = toInteger($network_id) OR toString(n.id) = toString($network_id) OR elementId(n) = toString($network_id)
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

		// 2. Conectar los matches (si los hay)
		for _, m := range matches {
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
				RETURN n
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

// LinkEndpointToMatchingNetworks recorre las redes existentes en la base de datos y, si alguna
// IP del endpoint cae dentro de su CIDR (y coincide en VLAN si la red lo especifica), conecta
// automáticamente el endpoint a la red via (:Endpoint)-[:CONNECTED_TO]->(:Network).
func (r *networkRepo) LinkEndpointToMatchingNetworks(ctx context.Context, endpointID int64, ips []domain.EndpointIP) (int, error) {
	writeSession := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer writeSession.Close(ctx)

	// 1. Desconectar de redes previas por si se alteró o borró la VLAN / IP
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

			// 1. Si la red exige VLAN, la IP debe coincidir en VLAN
			if cand.vlanID > 0 && ipEntry.VLANID != cand.vlanID {
				ipMatch = false
			}

			// 2. Si la red exige CIDR, la IP debe estar en el rango CIDR
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

// LinkNetworkToProjectIfOrphan ver comentario en ports.NetworkPort.
func (r *networkRepo) LinkNetworkToProjectIfOrphan(ctx context.Context, networkID int64, projectID int64) error {
	query := `
		MATCH (n:Network)
		WHERE (toInteger(n.id) = toInteger($network_id) OR toString(n.id) = toString($network_id) OR elementId(n) = toString($network_id))
		  AND NOT EXISTS((:Project)-[:CONTAINS_NETWORK]->(n))
		  AND NOT EXISTS((:Endpoint)-[:CONNECTED_TO]->(n))
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

// LinkContainerToMatchingNetworks vincula un contenedor a las redes compatibles con sus IPs.
func (r *networkRepo) LinkContainerToMatchingNetworks(ctx context.Context, containerID string, ips []domain.EndpointIP) (int, error) {
	writeSession := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer writeSession.Close(ctx)

	// 1. Desconectar de redes previas por si se alteró o borró la VLAN / IP
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
			// Coincidencia estricta por VLAN
			if cand.vlanID > 0 && ipEntry.VLANID == cand.vlanID {
				matched = true
				break
			}
			// Coincidencia por CIDR
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
