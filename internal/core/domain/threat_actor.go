package domain

/*
Este archivo define las entidades de dominio asociadas a los Threat Actors (Grupos de Amenazas).

Propósito arquitectónico y teórico:
1. Ubicación en Arquitectura Hexagonal: Se localiza en `internal/core/domain` en el núcleo de lógica pura.
2. Mapeo de Actores de Amenaza: Permite categorizar y cuantificar los grupos cibercriminales o estatales que usan las TTPs detectadas.
*/

type ThreatActor struct {
	ActorID     string `json:"actor_id"`    // e.g. "G0007"
	Name        string `json:"name"`        // e.g. "APT28"
	Description string `json:"description"` // e.g. "APT28 is a threat group..."
	Aliases     string `json:"aliases"`     // e.g. "Fancy Bear, Pawn Storm"
}

// ThreatActorThreat representa un actor de amenaza y el número de TTPs coincidentes con la infraestructura.
type ThreatActorThreat struct {
	ThreatActor ThreatActor `json:"threat_actor"`
	TTPCount    int         `json:"ttp_count"`
}

// ThreatActorTTPRelation representa la relación de uso de una TTP por parte de un Threat Actor.
type ThreatActorTTPRelation struct {
	ActorID string
	TTPID   string
}
