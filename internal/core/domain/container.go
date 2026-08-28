package domain

import "time"

// ContainerImage representa una imagen de contenedor.
type ContainerImage struct {
	ImageID                string     `json:"image_id"`
	Name                   string     `json:"name"`
	Tag                    string     `json:"tag"`
	Digest                 string     `json:"digest"`
	RiskScore              float64    `json:"risk_score"`
	VulnScanStartedAt      *time.Time `json:"vuln_scan_started_at,omitempty"`
	VulnScanCompletedAt    *time.Time `json:"vuln_scan_completed_at,omitempty"`
	VulnScanCacheHit       bool       `json:"vuln_scan_cache_hit"`
	VulnScanTotalAvailable int        `json:"vuln_scan_total_available"`
	VulnScanProcessed      int        `json:"vuln_scan_processed"`
	VulnScanPagesFetched   int        `json:"vuln_scan_pages_fetched"`
}

// Container representa una instancia de un contenedor en ejecución.
type Container struct {
	ContainerID     string       `json:"container_id"`
	Name            string       `json:"name"`
	State           string       `json:"state"`
	ImageID         string       `json:"image_id"`
	HostID          int64        `json:"host_id"` // ID del Endpoint donde corre
	Privileged      bool         `json:"privileged"`
	InternetExposed bool         `json:"internet_exposed"`
	IPs             []EndpointIP `json:"ips,omitempty"` // IPs asociadas al contenedor (opcional)

	RiskScore float64 `json:"risk_score"`
	RiskTier  string  `json:"risk_tier"`

	PriorityScore float64 `json:"priority_score"`
	PriorityTier  string  `json:"priority_tier"`

	TechnicalDriverType      string  `json:"technical_driver_type"`
	TechnicalDriverAssetID   string  `json:"technical_driver_asset_id"`
	TechnicalDriverAssetName string  `json:"technical_driver_asset_name"`
	TechnicalDriverFindingID int64   `json:"technical_driver_finding_id"`
	TechnicalDriverCVEID     string  `json:"technical_driver_cve_id"`
	TechnicalDriverRiskScore float64 `json:"technical_driver_risk_score"`

	PriorityDriverType          string  `json:"priority_driver_type"`
	PriorityDriverAssetID       string  `json:"priority_driver_asset_id"`
	PriorityDriverAssetName     string  `json:"priority_driver_asset_name"`
	PriorityDriverFindingID     int64   `json:"priority_driver_finding_id"`
	PriorityDriverCVEID         string  `json:"priority_driver_cve_id"`
	PriorityDriverPriorityScore float64 `json:"priority_driver_priority_score"`

	RiskyAssetCount    int        `json:"risky_asset_count"`
	RiskComputedAt     *time.Time `json:"risk_computed_at,omitempty"`
	PriorityComputedAt *time.Time `json:"priority_computed_at,omitempty"`
}
