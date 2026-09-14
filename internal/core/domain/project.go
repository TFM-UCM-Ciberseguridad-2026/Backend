package domain

import "time"

/*
Este archivo define la entidad de dominio para los Proyectos (Projects).

Propósito arquitectónico y teórico:
1. Ubicación en Arquitectura Hexagonal: Se sitúa en `internal/core/domain`.
2. Definición de Proyecto: Modela un proyecto organizativo o alcance de auditoría bajo el cual se agrupan los activos.
*/

// Project representa la entidad de dominio de un proyecto (nodo Project en Neo4j).
type Project struct {
	ProjectID int64  `json:"project_id"`
	Name      string `json:"name"`

	RiskScore      float64    `json:"risk_score"`
	RiskTier       string     `json:"risk_tier"`
	RiskComputedAt *time.Time `json:"risk_computed_at"`

	PriorityScore      float64    `json:"priority_score"`
	PriorityTier       string     `json:"priority_tier"`
	PriorityComputedAt *time.Time `json:"priority_computed_at"`

	TechnicalDriverEndpointID       int64   `json:"technical_driver_endpoint_id"`
	TechnicalDriverEndpointHostname string  `json:"technical_driver_endpoint_hostname"`
	TechnicalDriverRiskScore        float64 `json:"technical_driver_risk_score"`
	TechnicalDriverSoftwareName     string  `json:"technical_driver_software_name"`
	TechnicalDriverCVEID            string  `json:"technical_driver_cve_id"`

	PriorityDriverEndpointID       int64   `json:"priority_driver_endpoint_id"`
	PriorityDriverEndpointHostname string  `json:"priority_driver_endpoint_hostname"`
	PriorityDriverPriorityScore    float64 `json:"priority_driver_priority_score"`
	PriorityDriverSoftwareName     string  `json:"priority_driver_software_name"`
	PriorityDriverCVEID            string  `json:"priority_driver_cve_id"`

	RiskyEndpointCount int `json:"risky_endpoint_count"`
}
