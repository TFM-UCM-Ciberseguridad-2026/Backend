package domain

// GraphNode representa un nodo genérico en el grafo de Neo4j.
type GraphNode struct {
	ID         string                 `json:"id"`
	Labels     []string               `json:"labels"`
	Properties map[string]interface{} `json:"properties"`
}

// GraphRelationship representa una relación (arista) entre dos nodos en el grafo de Neo4j.
type GraphRelationship struct {
	ID         string                 `json:"id"`
	Type       string                 `json:"type"`
	Source     string                 `json:"source"`
	Target     string                 `json:"target"`
	Properties map[string]interface{} `json:"properties"`
}

// GraphData contiene el conjunto de nodos y relaciones que componen el grafo.
type GraphData struct {
	Nodes         []GraphNode         `json:"nodes"`
	Relationships []GraphRelationship `json:"relationships"`
}

// APTThreatResult representa un Actor de Amenaza (APT) correlacionado con las TTPs
// encontradas en la infraestructura del usuario, ordenado por relevancia.
type APTThreatResult struct {
	ActorID         string   `json:"actor_id"`
	ActorName       string   `json:"actor_name"`
	Origin          string   `json:"origin"`
	Motivation      string   `json:"motivation"`
	MatchedTTPCount int      `json:"matched_ttp_count"`
	TotalInfraTTPs  int      `json:"total_infra_ttps"`
	CoveragePercent float64  `json:"coverage_percent"`
	MatchedTTPNames []string `json:"matched_ttp_names"`
	MatchedTTPIDs   []string `json:"matched_ttp_ids"`
}
