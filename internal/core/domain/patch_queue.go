package domain

// Cola de parcheo: los findings pendientes ordenados por prioridad, que pondera el
// riesgo con la criticidad del activo y la urgencia del CVE.

// PatchQueueItem es una entrada de la cola. Lleva el activo y el software además del
// finding para que la respuesta se pueda leer sin consultar el grafo por cada línea.
type PatchQueueItem struct {
	Position int `json:"position"`

	FindingID int64  `json:"finding_id"`
	CVEID     string `json:"cve_id"`
	Status    string `json:"status"`

	InstallationID  string `json:"installation_id"`
	SoftwareName    string `json:"software_name"`
	SoftwareVersion string `json:"software_version"`
	FixedVersion    string `json:"fixed_version,omitempty"`

	EndpointID  int64  `json:"endpoint_id"`
	Hostname    string `json:"hostname"`
	Environment string `json:"environment"`
	// InContainer distingue el software del host del que corre en un contenedor: el
	// procedimiento de parcheo no es el mismo (actualizar el paquete o reconstruir la imagen).
	InContainer   bool   `json:"in_container"`
	ContainerName string `json:"container_name,omitempty"`

	RiskScore        float64 `json:"risk_score"`
	AssetCriticality float64 `json:"asset_criticality"`
	UrgencyBoost     float64 `json:"urgency_boost"`
	PriorityScore    float64 `json:"priority_score"`
	PriorityTier     string  `json:"priority_tier"`

	// PatchAvailable indica si hay un parche registrado para el CVE. Un finding muy
	// prioritario sin parche disponible no es accionable todavía.
	PatchAvailable bool `json:"patch_available"`
}

type ProjectPatchRefreshItem struct {
	CVEID         string `json:"cve_id"`
	Found         bool   `json:"found"`
	PatchCount    int    `json:"patches"`
	FixedVersions int    `json:"fixed_versions"`
	Error         string `json:"error,omitempty"`
}

type ProjectPatchRefreshResult struct {
	ProjectID  int64                     `json:"project_id"`
	TotalCVEs  int                       `json:"total_cves"`
	Offset     int                       `json:"offset"`
	Limit      int                       `json:"limit"`
	Processed  int                       `json:"processed"`
	HasMore    bool                      `json:"has_more"`
	NextOffset int                       `json:"next_offset"`
	Refreshed  int                       `json:"refreshed"`
	NotFound   int                       `json:"not_found"`
	Failed     int                       `json:"failed"`
	Results    []ProjectPatchRefreshItem `json:"results"`
}
