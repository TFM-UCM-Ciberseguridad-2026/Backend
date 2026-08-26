package domain

// InventoryQuery representa los parámetros de búsqueda, filtrado avanzado, ordenación y paginación para el inventario.
type InventoryQuery struct {
	ProjectID       int64    `json:"project_id"`
	Page            int      `json:"page"`
	Limit           int      `json:"limit"`
	Category        string   `json:"category"`
	Categories      []string `json:"categories"`
	Search          string   `json:"search"`
	IPSearch        string   `json:"ip_search"`
	VendorSearch    string   `json:"vendor_search"`
	Environment     string   `json:"environment"`
	InternetExposed string   `json:"internet_exposed"`
	Status          string   `json:"status"`
	RiskTier        string   `json:"risk_tier"`
	SortField       string   `json:"sort_field"`
	SortDirection   string   `json:"sort_direction"`
}

// InventoryItem representa un activo genérico formateado para la tabla de inventario.
type InventoryItem struct {
	ID           string                 `json:"id"`
	Name         string                 `json:"name"`
	PrimaryLabel string                 `json:"primaryLabel"`
	Labels       []string               `json:"labels"`
	Properties   map[string]interface{} `json:"properties"`
}

// PaginatedInventoryResponse engloba la lista de ítems de la página actual y las métricas de paginación.
type PaginatedInventoryResponse struct {
	Items          []InventoryItem  `json:"items"`
	Page           int              `json:"page"`
	Limit          int              `json:"limit"`
	TotalItems     int64            `json:"total_items"`
	TotalPages     int              `json:"total_pages"`
	CategoryCounts map[string]int64 `json:"category_counts"`
}
