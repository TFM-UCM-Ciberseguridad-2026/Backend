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
	RiskScore       float64      `json:"risk_score"`
	Privileged      bool         `json:"privileged"`
	InternetExposed bool         `json:"internet_exposed"`
	IPs             []EndpointIP `json:"ips,omitempty"` // IPs asociadas al contenedor (opcional)
}
