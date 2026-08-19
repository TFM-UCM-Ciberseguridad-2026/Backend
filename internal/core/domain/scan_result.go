package domain

type VulnerabilityScanResult struct {
	InstallationID       string `json:"installation_id"`
	SoftwareID           int64  `json:"software_id"`
	CPE                  string `json:"cpe"`
	VulnerabilitiesFound int    `json:"vulnerabilities_found"`
	FindingsCreated      int    `json:"findings_created"`
	FindingsExisting     int    `json:"findings_existing"`
	LimitApplied         int    `json:"limit_applied"`
}
