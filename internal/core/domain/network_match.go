package domain

/*
Regla única de emparejamiento entre los activos (Endpoints y Contenedores) y las redes.

Antes existían tres variantes de esta lógica repartidas por el repositorio —una por cada
sentido en que se puede disparar el emparejamiento (al guardar la red, al guardar un
endpoint, al guardar un contenedor)— y no coincidían entre sí: diferían en el valor por
defecto del match y en qué hacían cuando a la red le faltaba el CIDR o lo tenía mal
formado. El resultado era que el grafo dependía de por qué lado se hubiera tocado último.
Este archivo es ahora la única definición de la regla; los tres caminos la invocan.

La regla, en orden:

 1. Una red sin CIDR válido no empareja con nada. Antes, guardar la red enganchaba por VLAN
    ignorando el rango, lo que dejó en la base activos colgando de redes con CIDR inválido.
 2. La VLAN tiene que coincidir exactamente, y el 0 no es un comodín: es la VLAN nativa,
    la de las IPs sin etiquetar. Una red en la VLAN 102 solo empareja con IPs de la 102, y
    una red con vlan_id = 0 solo con IPs que tampoco traigan VLAN.
    Antes el 0 no filtraba, y eso juntaba en una misma red activos de VLANs distintas: un
    /16 declarado con vlan_id = 0 recogía por igual IPs de la VLAN 2 y de la 3, que
    acababan colgando del mismo nodo Network y por tanto adyacentes en el grafo y en las
    rutas de ataque, cuando en la realidad están en dominios de broadcast separados y no se
    alcanzan sin pasar por un router.
 3. Entre las redes supervivientes que contienen la IP gana la más específica (el rango más
    pequeño). Empate exacto -> el id menor, para que el resultado sea estable.
 4. Se resuelve IP por IP y se unen los ganadores: un activo multi-homed sigue conectado a
    tantas redes como IPs tenga en rangos distintos.
*/

import "sort"

// NetworkMatch es la red ganadora para una IP concreta de un activo.
type NetworkMatch struct {
	IP        string
	NetworkID int64
	CIDR      string
	// Discarded son las redes que también contenían la IP pero perdieron el desempate por
	// ser menos específicas. Se conserva para poder explicar la decisión en los informes de
	// reconciliación, no influye en el resultado.
	Discarded []int64
}

// MatchIPToNetwork resuelve la red más específica que contiene una IP, aplicando el filtro
// de VLAN. Devuelve false si ninguna red candidata la contiene.
func MatchIPToNetwork(ip EndpointIP, candidates []Network) (NetworkMatch, bool) {
	type scored struct {
		nw       Network
		hostBits int
	}

	var winners []scored
	for _, nw := range candidates {
		// Regla 2: la VLAN de la red y la de la IP tienen que ser la misma, sin excepción
		// para el 0. Que la IP caiga dentro del rango no basta: si no comparten dominio de
		// broadcast, el activo no pertenece a esa red.
		if ip.VLANID != nw.VLANID {
			continue
		}
		// Regla 1 + contención. CIDRSpecificity y CIDRContainsIP rechazan por su cuenta
		// cualquier CIDR que no se pueda interpretar.
		if !CIDRContainsIP(nw.CIDR, ip.IP) {
			continue
		}
		hostBits, err := CIDRSpecificity(nw.CIDR)
		if err != nil {
			continue
		}
		winners = append(winners, scored{nw: nw, hostBits: hostBits})
	}

	if len(winners) == 0 {
		return NetworkMatch{}, false
	}

	// Regla 3: menos bits de host = rango más pequeño = más específica. A igualdad de
	// tamaño, el id menor; sin este segundo criterio dos redes con el mismo CIDR harían
	// que el ganador dependiera del orden en que los devuelva la consulta.
	sort.Slice(winners, func(i, j int) bool {
		if winners[i].hostBits != winners[j].hostBits {
			return winners[i].hostBits < winners[j].hostBits
		}
		return winners[i].nw.NetworkID < winners[j].nw.NetworkID
	})

	match := NetworkMatch{
		IP:        ip.IP,
		NetworkID: winners[0].nw.NetworkID,
		CIDR:      winners[0].nw.CIDR,
	}
	for _, loser := range winners[1:] {
		match.Discarded = append(match.Discarded, loser.nw.NetworkID)
	}
	return match, true
}

// MatchAssetToNetworks devuelve las redes a las que debe conectarse un activo: la más
// específica por cada una de sus IPs, sin repetir. Las IPs que no caen en ninguna red
// simplemente no aportan nada, que es el tratamiento de siempre para una IP sin red.
//
// El orden de salida es ascendente por id para que dos ejecuciones sobre los mismos datos
// produzcan exactamente el mismo resultado.
func MatchAssetToNetworks(ips []EndpointIP, candidates []Network) []int64 {
	seen := make(map[int64]bool, len(ips))
	var ids []int64

	for _, ip := range ips {
		match, ok := MatchIPToNetwork(ip, candidates)
		if !ok || seen[match.NetworkID] {
			continue
		}
		seen[match.NetworkID] = true
		ids = append(ids, match.NetworkID)
	}

	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids
}

// SubnetParents relaciona cada red con su red padre inmediata dentro del mismo ámbito: la
// red más pequeña de entre las que contienen estrictamente su rango. Es lo que materializa
// la arista derivada CONTAINS_SUBNET, y se recalcula entera en cada reconciliación.
//
// "Contiene estrictamente" significa que el padre abarca todo el rango de la hija y es más
// grande que ella: dos redes con el mismo CIDR no son padre e hija, son un duplicado.
// La cadena es de un solo salto: con 10.0.0.0/8, 10.0.0.0/16 y 10.0.1.0/24, la /24 cuelga
// de la /16 y la /16 de la /8, no las dos de la /8.
func SubnetParents(networks []Network) map[int64]int64 {
	type entry struct {
		nw       Network
		hostBits int
	}

	valid := make([]entry, 0, len(networks))
	for _, nw := range networks {
		hostBits, err := CIDRSpecificity(nw.CIDR)
		if err != nil {
			continue
		}
		valid = append(valid, entry{nw: nw, hostBits: hostBits})
	}

	parents := make(map[int64]int64)
	for _, child := range valid {
		var best *entry
		for i := range valid {
			cand := &valid[i]
			if cand.nw.NetworkID == child.nw.NetworkID {
				continue
			}
			// El padre tiene que ser estrictamente mayor y abarcar el rango de la hija.
			// Basta comprobar la dirección base: si la contiene y su máscara es más corta,
			// contiene el rango entero.
			if cand.hostBits <= child.hostBits || !cidrContainsCIDR(cand.nw.CIDR, child.nw.CIDR) {
				continue
			}
			if best == nil || cand.hostBits < best.hostBits ||
				(cand.hostBits == best.hostBits && cand.nw.NetworkID < best.nw.NetworkID) {
				best = cand
			}
		}
		if best != nil {
			parents[child.nw.NetworkID] = best.nw.NetworkID
		}
	}
	return parents
}

// cidrContainsCIDR indica si el rango outer abarca por completo al rango inner. Se apoya en
// que inner ya está validado: comprobar su dirección base basta cuando outer es más grande.
func cidrContainsCIDR(outer, inner string) bool {
	normalizedInner, err := NormalizeCIDR(inner)
	if err != nil {
		return false
	}
	base := normalizedInner
	for i := 0; i < len(base); i++ {
		if base[i] == '/' {
			base = base[:i]
			break
		}
	}
	return CIDRContainsIP(outer, base)
}

// NetworkReconciliation resume el resultado de recalcular las relaciones activo↔red de un
// ámbito. Se devuelve a la capa de servicio para poder registrar qué se movió: al declarar
// una subred más específica dentro de una red que ya tenía activos, esos activos se
// reasignan, y conviene que eso quede explicado y no aparezca como un cambio espontáneo.
type NetworkReconciliation struct {
	Networks     int           `json:"networks"`
	Assets       int           `json:"assets"`
	LinksAdded   int           `json:"links_added"`
	LinksRemoved int           `json:"links_removed"`
	SubnetEdges  int           `json:"subnet_edges"`
	Moves        []NetworkMove `json:"moves,omitempty"`
}

// NetworkMove describe el cambio de redes de un activo concreto durante una reconciliación.
type NetworkMove struct {
	AssetID   string   `json:"asset_id"`
	AssetName string   `json:"asset_name"`
	From      []string `json:"from"`
	To        []string `json:"to"`
}
