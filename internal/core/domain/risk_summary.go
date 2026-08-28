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
// de software en un endpoint o contenedor.
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
	DriverFindingID       int64
	DriverCVEID           string
	DriverRiskScore       float64
	Status                string
}

// ContainerRiskSummary representa el resumen operativo de riesgo y prioridad de un contenedor.
type ContainerRiskSummary struct {
	ContainerID   string
	ContainerName string
	State         string

	RiskScore     float64
	RiskTier      string
	PriorityScore float64
	PriorityTier  string

	TechnicalDriverType      string
	TechnicalDriverAssetID   string
	TechnicalDriverAssetName string
	TechnicalDriverFindingID int64
	TechnicalDriverCVEID     string
	TechnicalDriverRiskScore float64

	PriorityDriverType          string
	PriorityDriverAssetID       string
	PriorityDriverAssetName     string
	PriorityDriverFindingID     int64
	PriorityDriverCVEID         string
	PriorityDriverPriorityScore float64

	RiskyAssetCount        int
	DirectFindingCount     int
	RiskyInstallationCount int
}

// EndpointRiskSummary representa el resumen mínimo necesario para agregar riesgo
// de un endpoint en un proyecto.
type EndpointRiskSummary struct {
	EndpointID int64
	Hostname   string
	Status     string

	RiskScore float64
	RiskTier  string

	PriorityScore float64
	PriorityTier  string

	TechnicalDriverInstallationID string
	TechnicalDriverSoftwareName   string
	TechnicalDriverRiskScore      float64
	TechnicalDriverCVEID          string

	PriorityDriverInstallationID string
	PriorityDriverSoftwareName   string
	PriorityDriverPriorityScore  float64
	PriorityDriverCVEID          string

	RiskySoftwareCount int

	TechnicalDriverType      string
	TechnicalDriverAssetID   string
	TechnicalDriverAssetName string
	PriorityDriverType       string
	PriorityDriverAssetID    string
	PriorityDriverAssetName  string
}

// AssetRiskSummary representa una fuente homogénea de riesgo de un endpoint.
// Puede ser una instalación nativa o un contenedor ya agregado.
type AssetRiskSummary struct {
	AssetType           string
	AssetID             string
	AssetName           string
	RiskScore           float64
	PriorityScore       float64
	DriverFindingID     int64
	DriverCVEID         string
	DriverRiskScore     float64
	DriverPriorityScore float64
}
