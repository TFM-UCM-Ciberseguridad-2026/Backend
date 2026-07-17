package domain

// FindingRiskContext agrupa todo lo necesario para calcular el riesgo de un finding:
// datos del finding, de la vulnerabilidad asociada y los requisitos CIA del endpoint.
// Es el resultado del traversal Endpoint→Installation→Finding→Vulnerability en Neo4j.
type FindingRiskContext struct {
	FindingID         int64
	FindingStatus     string
	RemediationFactor float64
	PatchAvailable    bool // true si existe un nodo Patch vinculado a la remediación

	CVEID          string
	CVSSVector     string
	CachedBaseScore float64 // fallback si el vector es inválido o está vacío
	CachedEPSS     float64 // valor almacenado en Neo4j; se sobreescribe con datos frescos
	CachedKEV      bool
	HasExploit     bool

	// Requisitos CIA del endpoint (Low/Medium/High)
	ConfidentialityReq string
	IntegrityReq       string
	AvailabilityReq    string
}
