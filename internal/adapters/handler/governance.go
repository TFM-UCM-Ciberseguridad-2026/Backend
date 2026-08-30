package handler

import (
	"encoding/json"
	"net/http"

	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/domain"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/ports"
)

type GovernanceHandler struct {
	service ports.GovernanceService
}

func NewGovernanceHandler(service ports.GovernanceService) *GovernanceHandler {
	return &GovernanceHandler{service: service}
}

func (h *GovernanceHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/governance/policies", h.GetPolicies)
	mux.HandleFunc("POST /api/governance/policies", h.SavePolicy)
	mux.HandleFunc("DELETE /api/governance/policies/{id}", h.DeletePolicy)

	mux.HandleFunc("GET /api/governance/procedures", h.GetProcedures)
	mux.HandleFunc("POST /api/governance/procedures", h.SaveProcedure)
	mux.HandleFunc("DELETE /api/governance/procedures/{id}", h.DeleteProcedure)

	mux.HandleFunc("GET /api/governance/roles", h.GetRoles)
	mux.HandleFunc("POST /api/governance/roles", h.SaveRole)
	mux.HandleFunc("DELETE /api/governance/roles/{id}", h.DeleteRole)

	mux.HandleFunc("GET /api/governance/raci", h.GetRACIActivities)
	mux.HandleFunc("POST /api/governance/raci", h.SaveRACIActivity)
	mux.HandleFunc("DELETE /api/governance/raci/{id}", h.DeleteRACIActivity)

	mux.HandleFunc("GET /api/governance/sla", h.GetSLAConfigs)
	mux.HandleFunc("PUT /api/governance/sla", h.SaveSLAConfigs)
	mux.HandleFunc("GET /api/governance/sla/breaches", h.GetSLABreaches)
}

// -- Policies --
func (h *GovernanceHandler) GetPolicies(w http.ResponseWriter, r *http.Request) {
	policies, err := h.service.GetPolicies(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(policies)
}

func (h *GovernanceHandler) SavePolicy(w http.ResponseWriter, r *http.Request) {
	var policy domain.PolicyDocument
	if err := json.NewDecoder(r.Body).Decode(&policy); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := h.service.SavePolicy(r.Context(), &policy); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (h *GovernanceHandler) DeletePolicy(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := h.service.DeletePolicy(r.Context(), id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// -- Procedures --
func (h *GovernanceHandler) GetProcedures(w http.ResponseWriter, r *http.Request) {
	procedures, err := h.service.GetProcedures(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(procedures)
}

func (h *GovernanceHandler) SaveProcedure(w http.ResponseWriter, r *http.Request) {
	var procedure domain.Procedure
	if err := json.NewDecoder(r.Body).Decode(&procedure); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := h.service.SaveProcedure(r.Context(), &procedure); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (h *GovernanceHandler) DeleteProcedure(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := h.service.DeleteProcedure(r.Context(), id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// -- Roles --
func (h *GovernanceHandler) GetRoles(w http.ResponseWriter, r *http.Request) {
	roles, err := h.service.GetRoles(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(roles)
}

func (h *GovernanceHandler) SaveRole(w http.ResponseWriter, r *http.Request) {
	var role domain.Role
	if err := json.NewDecoder(r.Body).Decode(&role); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := h.service.SaveRole(r.Context(), &role); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (h *GovernanceHandler) DeleteRole(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := h.service.DeleteRole(r.Context(), id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// -- RACI Activities --
func (h *GovernanceHandler) GetRACIActivities(w http.ResponseWriter, r *http.Request) {
	activities, err := h.service.GetRACIActivities(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(activities)
}

func (h *GovernanceHandler) SaveRACIActivity(w http.ResponseWriter, r *http.Request) {
	var activity domain.RACIActivity
	if err := json.NewDecoder(r.Body).Decode(&activity); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := h.service.SaveRACIActivity(r.Context(), &activity); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (h *GovernanceHandler) DeleteRACIActivity(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := h.service.DeleteRACIActivity(r.Context(), id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (h *GovernanceHandler) GetSLAConfigs(w http.ResponseWriter, r *http.Request) {
	configs, err := h.service.GetSLAConfigs(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(configs)
}

func (h *GovernanceHandler) SaveSLAConfigs(w http.ResponseWriter, r *http.Request) {
	var configs []domain.SLAConfig
	if err := json.NewDecoder(r.Body).Decode(&configs); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	for _, conf := range configs {
		if conf.Days <= 0 {
			http.Error(w, "SLA days must be greater than 0", http.StatusBadRequest)
			return
		}
	}

	if err := h.service.SaveSLAConfigs(r.Context(), configs); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (h *GovernanceHandler) GetSLABreaches(w http.ResponseWriter, r *http.Request) {
	breaches, err := h.service.GetSLABreaches(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(breaches)
}
