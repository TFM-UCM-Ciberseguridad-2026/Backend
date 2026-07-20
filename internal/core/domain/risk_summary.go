package domain

// FindingRiskSummary representa el resumen mínimo necesario para agregar riesgo
// de findings en una instalación de software.
type FindingRiskSummary struct {
	FindingID     int64
	CVEID         string
	RiskScore     float64
	PriorityScore float64
	Status        string
}

// SoftwareRiskSummary representa el resumen mínimo necesario para agregar riesgo
// de software en un endpoint.
type SoftwareRiskSummary struct {
	InstallationID        string
	SoftwareID            int64
	SoftwareName          string
	RiskScore             float64
	RiskTier              string
	CriticalityLevel      string
	CriticalityMultiplier float64
	PriorityScore         float64
	PriorityTier          string
	DriverCVEID           string
	Status                string
}
