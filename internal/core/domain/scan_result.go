package domain

import "time"

type VulnerabilityScanOptions struct {
	Limit        int
	ForceRefresh bool
}

type VulnerabilityFetchOptions struct {
	ForceRefresh bool
	PageSize     int
}

type VulnerabilityFetchResult struct {
	Vulnerabilities []Vulnerability
	CacheHit        bool
	CachedAt        *time.Time
	CacheExpiresAt  *time.Time
	TotalAvailable  int
	PagesFetched    int
}

type VulnerabilityScanResult struct {
	InstallationID       string     `json:"installation_id"`
	SoftwareID           int64      `json:"software_id"`
	CPE                  string     `json:"cpe"`
	VulnerabilitiesFound int        `json:"vulnerabilities_found"`
	FindingsCreated      int        `json:"findings_created"`
	FindingsExisting     int        `json:"findings_existing"`
	LimitApplied         int        `json:"limit_applied"`
	TotalAvailable       int        `json:"total_available"`
	Processed            int        `json:"processed"`
	Truncated            bool       `json:"truncated"`
	CacheHit             bool       `json:"cache_hit"`
	CacheExpiresAt       *time.Time `json:"cache_expires_at,omitempty"`
	ProviderPagesFetched int        `json:"provider_pages_fetched"`
	ScanStartedAt        *time.Time `json:"scan_started_at,omitempty"`
	ScanCompletedAt      *time.Time `json:"scan_completed_at,omitempty"`
}
