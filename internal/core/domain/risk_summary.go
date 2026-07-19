package domain

// FindingRiskSummary representa el resumen mínimo necesario para agregar riesgo
// de findings en una instalación de software.
type FindingRiskSummary struct {
	FindingID int64
	CVEID     string
	RiskScore float64
	Status    string
}
