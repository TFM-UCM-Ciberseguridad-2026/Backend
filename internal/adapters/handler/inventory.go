package handler

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/domain"
)

// GET /api/inventory
// Devuelve la lista paginada de activos de inventario según filtros avanzados y ordenación.
func (h *OrchestratorHandler) GetInventory(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	var projectID int64 = 0
	if raw := q.Get("project_id"); raw != "" {
		if parsed, err := strconv.ParseInt(raw, 10, 64); err == nil {
			projectID = parsed
		}
	}

	page := 1
	if raw := q.Get("page"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
			page = parsed
		}
	}

	limit := 50
	if raw := q.Get("limit"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
			limit = parsed
		}
	}

	category := strings.TrimSpace(q.Get("category"))
	if category == "" {
		category = "ALL"
	}

	var categories []string
	if rawCats := q.Get("categories"); rawCats != "" {
		parts := strings.Split(rawCats, ",")
		for _, p := range parts {
			trimmed := strings.TrimSpace(p)
			if trimmed != "" && trimmed != "ALL" {
				categories = append(categories, trimmed)
			}
		}
	}

	search := strings.TrimSpace(q.Get("search"))
	ipSearch := strings.TrimSpace(q.Get("ip_search"))
	vendorSearch := strings.TrimSpace(q.Get("vendor_search"))
	environment := strings.TrimSpace(q.Get("environment"))
	internetExposed := strings.TrimSpace(q.Get("internet_exposed"))
	status := strings.TrimSpace(q.Get("status"))
	riskTier := strings.TrimSpace(q.Get("risk_tier"))

	sortBy := strings.TrimSpace(q.Get("sort_by"))
	if sortBy == "" {
		sortBy = "name"
	}

	order := strings.TrimSpace(q.Get("order"))
	if order == "" {
		order = "asc"
	}

	query := domain.InventoryQuery{
		ProjectID:       projectID,
		Page:            page,
		Limit:           limit,
		Category:        category,
		Categories:      categories,
		Search:          search,
		IPSearch:        ipSearch,
		VendorSearch:    vendorSearch,
		Environment:     environment,
		InternetExposed: internetExposed,
		Status:          status,
		RiskTier:        riskTier,
		SortField:       sortBy,
		SortDirection:   order,
	}

	resp, err := h.orchestrator.GetPaginatedInventory(r.Context(), query)
	if err != nil {
		sendError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	sendJSON(w, resp, http.StatusOK)
}
