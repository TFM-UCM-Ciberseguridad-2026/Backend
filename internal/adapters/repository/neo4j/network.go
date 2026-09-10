package neo4j

import (
	"context"
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
	// Los vecinos se anotan antes del borrado: después ya no hay forma de saber qué colgaba
	// de esta red y qué estaba aislado por su cuenta desde el principio.
	neighbours, err := r.neighbourIDs(ctx, id)
	if err != nil {
		return fmt.Errorf("error localizando los nodos vecinos de la red %d: %w", id, err)
	}

	query := `
		MATCH (n:Network)
		WHERE toString(n.id) = toString($id) OR elementId(n) = toString($id)
		DETACH DELETE n
	`
	_ = executeWriteHelper(ctx, r.driver, query, map[string]any{"id": id})

	// Limpieza de lo que colgaba SOLO de la red borrada.
	//
	// Antes esta consulta barría toda la base sin filtro de ámbito: cualquier nodo aislado,
	// tuviera o no que ver con la red que se estaba borrando, se eliminaba de propina. En
	// una base con redes huérfanas legítimas —creadas sin proyecto y todavía sin activos—
	// eso significaba perderlas al borrar cualquier otra red. Ahora solo se consideran los
	// nodos que eran vecinos de la red eliminada.
	//
	// La lista de etiquetas y la condición de "no alcanza ni Endpoint ni Project" se
	// conservan tal cual: lo que cambia es únicamente el conjunto de candidatos.
	cleanupQuery := `
		UNWIND $neighbour_ids AS nid
		MATCH (n) WHERE elementId(n) = nid
		  AND (n:Software OR n:Network OR n:Hardware OR n:IPAddress OR n:SoftwareInstallation OR n:Finding OR n:Remediation OR n:Exploit OR n:Patch OR n:Container OR n:ContainerImage OR n:Vulnerability)
		  AND NOT EXISTS((n)-[*1..5]-(:Endpoint)) AND NOT EXISTS((n)-[*1..5]-(:Project))
		DETACH DELETE n
	`
	if len(neighbours) == 0 {
		return nil
	}
	return executeWriteHelper(ctx, r.driver, cleanupQuery, map[string]any{"neighbour_ids": neighbours})
}

// neighbourIDs devuelve los elementId de los nodos directamente conectados a una red. Es la
// lista de candidatos a limpieza tras borrarla: solo puede quedar huérfano por culpa del
// borrado algo que estuviera colgando de ella.
func (r *networkRepo) neighbourIDs(ctx context.Context, networkID int64) ([]string, error) {
	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	res, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		result, err := tx.Run(ctx, `
			MATCH (n:Network)-[]-(vecino)
			WHERE toString(n.id) = toString($id) OR elementId(n) = toString($id)
			RETURN collect(DISTINCT elementId(vecino)) AS ids
		`, map[string]any{"id": networkID})
		if err != nil {
			return nil, err
		}
		var ids []string
		if result.Next(ctx) {
			val, _ := result.Record().Get("ids")
			ids = decodeStringList(val)
		}
		return ids, result.Err()
	})
	if err != nil {
		return nil, err
	}
	ids, _ := res.([]string)
	return ids, nil
}

/*
=== Emparejamiento activo↔red ===

Toda la decisión de "qué activo va en qué red" la toma domain.MatchAssetToNetworks. Aquí
solo se carga el ámbito desde el grafo, se le pregunta al dominio y se aplica el resultado.

Hay dos caminos, y la diferencia entre ellos es qué puede haber cambiado:

  - Cambia UN activo (alta o edición de endpoint/contenedor): solo hay que recolocar ese
    activo. Lo hacen LinkEndpointToMatchingNetworks y LinkContainerToMatchingNetworks.
  - Cambia UNA RED (alta, edición o borrado): puede cambiar la asignación de cualquier
    activo del proyecto, porque declarar una subred más específica dentro de un rango que
    ya tenía activos se los lleva. Lo hace ReconcileProjectNetworkLinks, que recalcula el
    ámbito entero y además rehace la jerarquía CONTAINS_SUBNET.

En los dos casos, antes de soltar una arista CONNECTED_TO se ancla la red a su proyecto con
CONTAINS_NETWORK: si no, una red que se queda sin activos directos —justo lo que le pasa a
un supernet cuando se le declaran subredes dentro— desaparecería del grafo del proyecto.
*/

// networksInScopeQuery devuelve las redes visibles desde una lista de proyectos. Acotar por
// proyecto es imprescindible: con la unicidad de CIDR por proyecto, dos proyectos pueden
// declarar el mismo rango, y sin este filtro los activos se cruzarían entre proyectos y la
// jerarquía de subredes se calcularía mezclando redes de proyectos distintos.
const networksInScopeQuery = `
	UNWIND $project_ids AS pid
	MATCH (p:Project)
	WHERE toInteger(p.id) = toInteger(pid) OR toString(p.id) = toString(pid)
	CALL {
		WITH p
		MATCH (p)-[:CONTAINS_NETWORK]->(n:Network) RETURN n
		UNION
		WITH p
		MATCH (p)-[:HAS_ENDPOINT]->(:Endpoint)-[:CONNECTED_TO]->(n:Network) RETURN n
		UNION
		WITH p
		MATCH (p)-[:HAS_ENDPOINT]->(:Endpoint)-[:HOSTS]->(:Container)-[:CONNECTED_TO]->(n:Network) RETURN n
	}
	RETURN DISTINCT n.id AS network_id, n.cidr AS cidr, n.vlan_id AS vlan_id, n.nombre AS nombre
`

// orphanNetworksQuery es el ámbito cuando no se puede resolver el proyecto del activo o de
// la red: las redes que no cuelgan de ningún proyecto.
//
// Antes este caso barría toda la base (MATCH (n:Network)), lo que enganchaba activos a
// redes de otros proyectos que usaran el mismo direccionamiento privado. "Sin proyecto" es
// un ámbito más, no un comodín, y usa el mismo criterio que GetNetworksInProjectScope.
const orphanNetworksQuery = `
	MATCH (n:Network)
	WHERE NOT EXISTS { MATCH (:Project)-[:CONTAINS_NETWORK]->(n) }
	  AND NOT EXISTS { MATCH (:Project)-[:HAS_ENDPOINT]->(:Endpoint)-[:CONNECTED_TO]->(n) }
	  AND NOT EXISTS { MATCH (:Project)-[:HAS_ENDPOINT]->(:Endpoint)-[:HOSTS]->(:Container)-[:CONNECTED_TO]->(n) }
	RETURN n.id AS network_id, n.cidr AS cidr, n.vlan_id AS vlan_id, n.nombre AS nombre
`

// loadNetworksInScope carga las redes candidatas del ámbito. Una lista de proyectos vacía
// significa "redes sin proyecto", no "todas las redes".
func (r *networkRepo) loadNetworksInScope(ctx context.Context, projectIDs []int64) ([]domain.Network, error) {
	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	query := orphanNetworksQuery
	if len(projectIDs) > 0 {
		query = networksInScopeQuery
	}

	res, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		result, err := tx.Run(ctx, query, map[string]any{"project_ids": projectIDs})
		if err != nil {
			return nil, err
		}

		var networks []domain.Network
		for result.Next(ctx) {
			rec := result.Record()
			idVal, _ := rec.Get("network_id")
			cidrVal, _ := rec.Get("cidr")
			vlanVal, _ := rec.Get("vlan_id")
			nameVal, _ := rec.Get("nombre")

			networks = append(networks, domain.Network{
				NetworkID: getInt64Any(idVal),
				CIDR:      getStringAny(cidrVal),
				VLANID:    getInt64Any(vlanVal),
				Nombre:    getStringAny(nameVal),
			})
		}
		return networks, result.Err()
	})
	if err != nil {
		return nil, err
	}

	networks, _ := res.([]domain.Network)
	return networks, nil
}

// scopedAsset es un activo del ámbito con sus IPs y las redes a las que está conectado
// ahora mismo. Los ids se manejan como string porque un Endpoint los tiene numéricos y un
// Container los tiene en texto (UUID).
type scopedAsset struct {
	id       string
	name     string
	ips      []domain.EndpointIP
	current  []string
	isConter bool
}

const assetsInScopeQuery = `
	UNWIND $project_ids AS pid
	MATCH (p:Project)
	WHERE toInteger(p.id) = toInteger(pid) OR toString(p.id) = toString(pid)
	CALL {
		WITH p
		MATCH (p)-[:HAS_ENDPOINT]->(e:Endpoint) RETURN e
		UNION
		WITH p
		MATCH (p)-[:HAS_ENDPOINT]->(:Endpoint)-[:HOSTS]->(e:Container) RETURN e
	}
	WITH DISTINCT e
	OPTIONAL MATCH (e)-[:HAS_IP]->(ip:IPAddress)
	WITH e, [x IN collect(CASE WHEN ip IS NULL THEN null ELSE {ip: ip.ip, vlan_id: ip.vlan_id} END) WHERE x IS NOT NULL] AS ips
	OPTIONAL MATCH (e)-[:CONNECTED_TO]->(n:Network)
	RETURN toString(e.id) AS asset_id,
	       coalesce(e.hostname, e.name, toString(e.id)) AS asset_name,
	       labels(e) AS labels,
	       ips,
	       [x IN collect(n.id) WHERE x IS NOT NULL | toString(x)] AS current_networks
`

const orphanAssetsInScopeQuery = `
	MATCH (e)
	WHERE (e:Endpoint OR e:Container)
	  AND NOT EXISTS { MATCH (:Project)-[:HAS_ENDPOINT]->(e) }
	  AND NOT EXISTS { MATCH (:Project)-[:HAS_ENDPOINT]->(:Endpoint)-[:HOSTS]->(e) }
	OPTIONAL MATCH (e)-[:HAS_IP]->(ip:IPAddress)
	WITH e, [x IN collect(CASE WHEN ip IS NULL THEN null ELSE {ip: ip.ip, vlan_id: ip.vlan_id} END) WHERE x IS NOT NULL] AS ips
	OPTIONAL MATCH (e)-[:CONNECTED_TO]->(n:Network)
	RETURN toString(e.id) AS asset_id,
	       coalesce(e.hostname, e.name, toString(e.id)) AS asset_name,
	       labels(e) AS labels,
	       ips,
	       [x IN collect(n.id) WHERE x IS NOT NULL | toString(x)] AS current_networks
`

// loadAssetsInScope carga TODOS los activos del ámbito, tengan IPs o no.
//
// Los que no tienen ninguna IP importan precisamente porque no pueden emparejar con nada:
// si se quedan fuera del cálculo, el reconciliador no genera un plan para ellos y sus
// CONNECTED_TO viejos no se borran nunca, porque el borrado solo actúa sobre los activos
// que sí tienen plan. Así es como en la base quedaron activos sin una sola IP colgando de
// dos redes de VLANs distintas, haciendo de puente entre ellas en el grafo. Ahora entran
// con la lista de IPs vacía, el emparejamiento les asigna cero redes y sus aristas caen.
func (r *networkRepo) loadAssetsInScope(ctx context.Context, projectIDs []int64) ([]scopedAsset, error) {
	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	query := orphanAssetsInScopeQuery
	if len(projectIDs) > 0 {
		query = assetsInScopeQuery
	}

	res, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		result, err := tx.Run(ctx, query, map[string]any{"project_ids": projectIDs})
		if err != nil {
			return nil, err
		}

		var assets []scopedAsset
		for result.Next(ctx) {
			rec := result.Record()
			idVal, _ := rec.Get("asset_id")
			nameVal, _ := rec.Get("asset_name")
			labelsVal, _ := rec.Get("labels")
			ipsVal, _ := rec.Get("ips")
			currentVal, _ := rec.Get("current_networks")

			asset := scopedAsset{
				id:       getStringAny(idVal),
				name:     getStringAny(nameVal),
				ips:      decodeIPList(ipsVal),
				current:  decodeStringList(currentVal),
				isConter: hasLabel(labelsVal, "Container"),
			}
			assets = append(assets, asset)
		}
		return assets, result.Err()
	})
	if err != nil {
		return nil, err
	}

	assets, _ := res.([]scopedAsset)
	return assets, nil
}

// decodeIPList convierte la lista de mapas {ip, vlan_id} que devuelve Neo4j en EndpointIP.
func decodeIPList(v any) []domain.EndpointIP {
	raw, ok := v.([]any)
	if !ok {
		return nil
	}
	ips := make([]domain.EndpointIP, 0, len(raw))
	for _, item := range raw {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		ips = append(ips, domain.EndpointIP{
			IP:     getStringAny(m["ip"]),
			VLANID: getInt64Any(m["vlan_id"]),
		})
	}
	return ips
}

func decodeStringList(v any) []string {
	raw, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		if s := getStringAny(item); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func hasLabel(v any, label string) bool {
	raw, ok := v.([]any)
	if !ok {
		return false
	}
	for _, item := range raw {
		if s, ok := item.(string); ok && s == label {
			return true
		}
	}
	return false
}

// ReconcileProjectNetworkLinks recalcula, para el ámbito de proyecto indicado, a qué red va
// cada activo y qué red es subred de cuál. Es la operación que se dispara al crear, editar
// o borrar una red.
//
// Se recalcula el ámbito completo y no solo la red tocada porque declarar una subred más
// específica reasigna activos que estaban colgando del rango padre: si solo se recalculara
// la red nueva, esos activos se quedarían enganchados también al padre y el resultado
// dependería del orden en que se hubieran creado las redes.
func (r *networkRepo) ReconcileProjectNetworkLinks(ctx context.Context, projectIDs []int64) (domain.NetworkReconciliation, error) {
	summary := domain.NetworkReconciliation{}

	networks, err := r.loadNetworksInScope(ctx, projectIDs)
	if err != nil {
		return summary, fmt.Errorf("error cargando las redes del ámbito: %w", err)
	}
	assets, err := r.loadAssetsInScope(ctx, projectIDs)
	if err != nil {
		return summary, fmt.Errorf("error cargando los activos del ámbito: %w", err)
	}
	summary.Networks = len(networks)
	summary.Assets = len(assets)

	cidrByID := make(map[string]string, len(networks))
	networkIDs := make([]string, 0, len(networks))
	for _, nw := range networks {
		key := fmt.Sprintf("%d", nw.NetworkID)
		label := nw.CIDR
		if nw.Nombre != "" {
			label = fmt.Sprintf("%s (%s)", nw.Nombre, nw.CIDR)
		}
		cidrByID[key] = label
		networkIDs = append(networkIDs, key)
	}

	// Delta por activo: lo que debería estar conectado frente a lo que lo está ahora.
	type assetPlan struct {
		id      string
		desired []string
	}
	plans := make([]assetPlan, 0, len(assets))
	var links []map[string]any

	for _, asset := range assets {
		desiredIDs := domain.MatchAssetToNetworks(asset.ips, networks)
		desired := make([]string, 0, len(desiredIDs))
		desiredSet := make(map[string]bool, len(desiredIDs))
		for _, id := range desiredIDs {
			key := fmt.Sprintf("%d", id)
			desired = append(desired, key)
			desiredSet[key] = true
			links = append(links, map[string]any{"asset_id": asset.id, "network_id": key})
		}

		currentSet := make(map[string]bool, len(asset.current))
		for _, key := range asset.current {
			currentSet[key] = true
		}

		var from, to []string
		for _, key := range asset.current {
			if !desiredSet[key] {
				summary.LinksRemoved++
				from = append(from, describeNetwork(cidrByID, key))
			}
		}
		for _, key := range desired {
			if !currentSet[key] {
				summary.LinksAdded++
				to = append(to, describeNetwork(cidrByID, key))
			}
		}
		if len(from) > 0 || len(to) > 0 {
			summary.Moves = append(summary.Moves, domain.NetworkMove{
				AssetID:   asset.id,
				AssetName: asset.name,
				From:      from,
				To:        to,
			})
		}

		plans = append(plans, assetPlan{id: asset.id, desired: desired})
	}

	// Jerarquía derivada: qué red es subred inmediata de cuál dentro de este mismo ámbito.
	parents := domain.SubnetParents(networks)
	var subnetEdges []map[string]any
	for child, parent := range parents {
		subnetEdges = append(subnetEdges, map[string]any{
			"parent": fmt.Sprintf("%d", parent),
			"child":  fmt.Sprintf("%d", child),
		})
	}
	summary.SubnetEdges = len(subnetEdges)

	assetPlanParams := make([]map[string]any, 0, len(plans))
	for _, p := range plans {
		assetPlanParams = append(assetPlanParams, map[string]any{
			"asset_id": p.id,
			"desired":  p.desired,
		})
	}

	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)

	_, err = session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		// 1. Anclar cada red del ámbito a su proyecto ANTES de soltar aristas: un supernet
		//    al que se le declaran subredes se queda sin activos directos, y sin este ancla
		//    dejaría de aparecer en el grafo del proyecto.
		if len(projectIDs) > 0 && len(networkIDs) > 0 {
			if _, err := tx.Run(ctx, `
				UNWIND $project_ids AS pid
				MATCH (p:Project)
				WHERE toInteger(p.id) = toInteger(pid) OR toString(p.id) = toString(pid)
				UNWIND $network_ids AS nid
				MATCH (n:Network)
				WHERE toString(n.id) = nid
				  AND (
				    EXISTS { MATCH (p)-[:CONTAINS_NETWORK]->(n) }
				    OR EXISTS { MATCH (p)-[:HAS_ENDPOINT]->(:Endpoint)-[:CONNECTED_TO]->(n) }
				    OR EXISTS { MATCH (p)-[:HAS_ENDPOINT]->(:Endpoint)-[:HOSTS]->(:Container)-[:CONNECTED_TO]->(n) }
				  )
				MERGE (p)-[:CONTAINS_NETWORK]->(n)
			`, map[string]any{"project_ids": projectIDs, "network_ids": networkIDs}); err != nil {
				return nil, err
			}
		}

		// 2. Soltar las aristas que ya no corresponden, acotando a las redes del ámbito
		//    para no tocar nunca relaciones de otros proyectos.
		if len(assetPlanParams) > 0 && len(networkIDs) > 0 {
			if _, err := tx.Run(ctx, `
				UNWIND $plans AS plan
				MATCH (e)-[rel:CONNECTED_TO]->(n:Network)
				WHERE (e:Endpoint OR e:Container)
				  AND toString(e.id) = plan.asset_id
				  AND toString(n.id) IN $network_ids
				  AND NOT toString(n.id) IN plan.desired
				DELETE rel
			`, map[string]any{"plans": assetPlanParams, "network_ids": networkIDs}); err != nil {
				return nil, err
			}
		}

		// 3. Crear las aristas que faltan.
		if len(links) > 0 {
			if _, err := tx.Run(ctx, `
				UNWIND $links AS link
				MATCH (e)
				WHERE (e:Endpoint OR e:Container) AND toString(e.id) = link.asset_id
				MATCH (n:Network) WHERE toString(n.id) = link.network_id
				MERGE (e)-[:CONNECTED_TO]->(n)
			`, map[string]any{"links": links}); err != nil {
				return nil, err
			}
		}

		// 4. Rehacer la jerarquía CONTAINS_SUBNET del ámbito. Es una arista DERIVADA de los
		//    CIDR, nunca editada a mano: se borra entera y se vuelve a calcular, que es lo
		//    único que garantiza que no sobreviva un padre obsoleto tras cambiar un CIDR.
		if len(networkIDs) > 0 {
			if _, err := tx.Run(ctx, `
				MATCH (n:Network)-[rel:CONTAINS_SUBNET]->(:Network)
				WHERE toString(n.id) IN $network_ids
				DELETE rel
			`, map[string]any{"network_ids": networkIDs}); err != nil {
				return nil, err
			}
		}
		if len(subnetEdges) > 0 {
			if _, err := tx.Run(ctx, `
				UNWIND $edges AS edge
				MATCH (parent:Network) WHERE toString(parent.id) = edge.parent
				MATCH (child:Network) WHERE toString(child.id) = edge.child
				MERGE (parent)-[:CONTAINS_SUBNET]->(child)
			`, map[string]any{"edges": subnetEdges}); err != nil {
				return nil, err
			}
		}

		return nil, nil
	})
	if err != nil {
		return summary, err
	}

	return summary, nil
}

// describeNetwork da un nombre legible a una red para los informes de reconciliación.
func describeNetwork(labels map[string]string, id string) string {
	if label, ok := labels[id]; ok && label != "" {
		return label
	}
	return "red " + id
}

// CountAssetsInNetwork cuenta los activos conectados a una red concreta. Es lo que la API
// devuelve como `linked_endpoints` tras crear o editar una red.
func (r *networkRepo) CountAssetsInNetwork(ctx context.Context, networkID int64) (int, error) {
	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	res, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		result, err := tx.Run(ctx, `
			MATCH (e)-[:CONNECTED_TO]->(n:Network)
			WHERE (e:Endpoint OR e:Container)
			  AND (toInteger(n.id) = toInteger($network_id) OR toString(n.id) = toString($network_id))
			RETURN count(DISTINCT e) AS total
		`, map[string]any{"network_id": networkID})
		if err != nil {
			return nil, err
		}
		if result.Next(ctx) {
			total, _ := result.Record().Get("total")
			return int(getInt64Any(total)), nil
		}
		return 0, result.Err()
	})
	if err != nil {
		return 0, err
	}

	count, _ := res.(int)
	return count, nil
}

// linkAssetToMatchingNetworks es el camino de un solo activo: recoloca ese activo y nada
// más. No toca CONTAINS_SUBNET porque las redes no han cambiado, solo el activo.
func (r *networkRepo) linkAssetToMatchingNetworks(ctx context.Context, assetID string, ips []domain.EndpointIP, projectID int64) (int, error) {
	var scope []int64
	if projectID > 0 {
		scope = []int64{projectID}
	}

	networks, err := r.loadNetworksInScope(ctx, scope)
	if err != nil {
		return 0, fmt.Errorf("error cargando las redes del ámbito: %w", err)
	}

	matched := domain.MatchAssetToNetworks(ips, networks)
	desired := make([]string, 0, len(matched))
	for _, id := range matched {
		desired = append(desired, fmt.Sprintf("%d", id))
	}

	// El borrado se acota a las redes del ámbito. Sin esta acotación, un activo cuyo
	// proyecto no se haya podido resolver (ámbito vacío -> casi ningún candidato) perdería
	// de golpe todas sus aristas de red en vez de quedarse como estaba.
	scopeIDs := make([]string, 0, len(networks))
	for _, nw := range networks {
		scopeIDs = append(scopeIDs, fmt.Sprintf("%d", nw.NetworkID))
	}
	if len(scopeIDs) == 0 {
		return 0, nil
	}

	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)

	_, err = session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		// Anclar al proyecto las redes de las que el activo va a salir, para que no se
		// queden descolgadas del grafo si era el último activo que las sostenía.
		if _, err := tx.Run(ctx, `
			MATCH (e)-[rel:CONNECTED_TO]->(n:Network)
			WHERE (e:Endpoint OR e:Container) AND toString(e.id) = $asset_id
			  AND toString(n.id) IN $scope_ids
			  AND NOT toString(n.id) IN $desired
			WITH e, rel, n
			OPTIONAL MATCH (p:Project)-[:HAS_ENDPOINT]->(e)
			OPTIONAL MATCH (p2:Project)-[:HAS_ENDPOINT]->(:Endpoint)-[:HOSTS]->(e)
			WITH rel, n, coalesce(p, p2) AS proj
			FOREACH (x IN CASE WHEN proj IS NOT NULL THEN [proj] ELSE [] END |
				MERGE (x)-[:CONTAINS_NETWORK]->(n)
			)
			DELETE rel
		`, map[string]any{"asset_id": assetID, "desired": desired, "scope_ids": scopeIDs}); err != nil {
			return nil, err
		}

		if len(desired) == 0 {
			return nil, nil
		}

		if _, err := tx.Run(ctx, `
			UNWIND $desired AS nid
			MATCH (e) WHERE (e:Endpoint OR e:Container) AND toString(e.id) = $asset_id
			MATCH (n:Network) WHERE toString(n.id) = nid
			MERGE (e)-[:CONNECTED_TO]->(n)
			WITH e, n
			OPTIONAL MATCH (p:Project)-[:HAS_ENDPOINT]->(e)
			OPTIONAL MATCH (p2:Project)-[:HAS_ENDPOINT]->(:Endpoint)-[:HOSTS]->(e)
			WITH n, coalesce(p, p2) AS proj
			FOREACH (x IN CASE WHEN proj IS NOT NULL THEN [proj] ELSE [] END |
				MERGE (x)-[:CONTAINS_NETWORK]->(n)
			)
		`, map[string]any{"asset_id": assetID, "desired": desired}); err != nil {
			return nil, err
		}

		return nil, nil
	})
	if err != nil {
		return 0, err
	}

	return len(desired), nil
}

func (r *networkRepo) LinkEndpointToMatchingNetworks(ctx context.Context, endpointID int64, ips []domain.EndpointIP, projectID int64) (int, error) {
	return r.linkAssetToMatchingNetworks(ctx, fmt.Sprintf("%d", endpointID), ips, projectID)
}

func (r *networkRepo) LinkContainerToMatchingNetworks(ctx context.Context, containerID string, ips []domain.EndpointIP, projectID int64) (int, error) {
	return r.linkAssetToMatchingNetworks(ctx, containerID, ips, projectID)
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
