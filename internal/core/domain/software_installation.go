package domain

import "time"

// Representa una instalacion de un software en un endpoint de la red. (nodo SoftwareInstallation en Neo4j).

type SoftwareInstallation struct {
	InstallationID string     `json:"installation_id"`
	FirstSeen      time.Time  `json:"first_seen"`
	LastSeen       *time.Time `json:"last_seen"`
	Status         string     `json:"status"`
	InstallPath    string     `json:"install_path"`
	DetectedBy     string     `json:"detected_by"`
	PackageManager string     `json:"package_manager"`

	RiskScore       float64    `json:"risk_score"`
	RiskTier        string     `json:"risk_tier"`
	RiskComputedAt  *time.Time `json:"risk_computed_at"`
	DriverFindingID int64      `json:"driver_finding_id"`
	DriverCVEID     string     `json:"driver_cve_id"`
}
