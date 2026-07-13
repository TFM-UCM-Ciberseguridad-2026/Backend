package http_handler

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/domain"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/service"
)

type OrchestratorHandler struct {
	orchestrator *service.Orchestrator
}

func NewOrchestratorHandler(o *service.Orchestrator) *OrchestratorHandler {
	return &OrchestratorHandler{orchestrator: o}
}

func sendError(w http.ResponseWriter, msg string, code int) {
	http.Error(w, msg, code)
}

func sendJSON(w http.ResponseWriter, data any, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(data)
}

// POST /api/projects
func (h *OrchestratorHandler) CreateProject(w http.ResponseWriter, r *http.Request) {
	var project domain.Project
	if err := json.NewDecoder(r.Body).Decode(&project); err != nil {
		sendError(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if err := h.orchestrator.CreateProject(r.Context(), &project); err != nil {
		sendError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	sendJSON(w, map[string]string{"status": "success"}, http.StatusCreated)
}

// POST /api/projects/{id}/endpoints
func (h *OrchestratorHandler) AddEndpointToProject(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	projectID, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		sendError(w, "Invalid project ID", http.StatusBadRequest)
		return
	}

	var endpoint domain.Endpoint
	if err := json.NewDecoder(r.Body).Decode(&endpoint); err != nil {
		sendError(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if err := h.orchestrator.AddEndpointToProject(r.Context(), projectID, &endpoint); err != nil {
		sendError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	sendJSON(w, map[string]string{"status": "success"}, http.StatusCreated)
}

// POST /api/endpoints/{id}/hardware
func (h *OrchestratorHandler) AssociateHardwareToEndpoint(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	endpointID, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		sendError(w, "Invalid endpoint ID", http.StatusBadRequest)
		return
	}

	var hw domain.Hardware
	if err := json.NewDecoder(r.Body).Decode(&hw); err != nil {
		sendError(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if err := h.orchestrator.AssociateHardwareToEndpoint(r.Context(), endpointID, &hw); err != nil {
		sendError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	sendJSON(w, map[string]string{"status": "success"}, http.StatusCreated)
}

// POST /api/endpoints/{id}/networks
func (h *OrchestratorHandler) AssociateNetworkToEndpoint(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	endpointID, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		sendError(w, "Invalid endpoint ID", http.StatusBadRequest)
		return
	}

	var net domain.Network
	if err := json.NewDecoder(r.Body).Decode(&net); err != nil {
		sendError(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if err := h.orchestrator.AssociateNetworkToEndpoint(r.Context(), endpointID, &net); err != nil {
		sendError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	sendJSON(w, map[string]string{"status": "success"}, http.StatusCreated)
}

// POST /api/endpoints/{id}/installations
func (h *OrchestratorHandler) RegisterSoftwareInstallation(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	endpointID, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		sendError(w, "Invalid endpoint ID", http.StatusBadRequest)
		return
	}

	var req struct {
		Software     domain.Software             `json:"software"`
		Installation domain.SoftwareInstallation `json:"installation"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if err := h.orchestrator.RegisterSoftwareInstallation(r.Context(), endpointID, &req.Software, &req.Installation); err != nil {
		sendError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	sendJSON(w, map[string]string{"status": "success"}, http.StatusCreated)
}

// POST /api/installations/{id}/findings
func (h *OrchestratorHandler) GenerateFinding(w http.ResponseWriter, r *http.Request) {
	instID := r.PathValue("id")

	var finding domain.Finding
	if err := json.NewDecoder(r.Body).Decode(&finding); err != nil {
		sendError(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if err := h.orchestrator.GenerateFinding(r.Context(), instID, &finding); err != nil {
		sendError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	sendJSON(w, map[string]string{"status": "success"}, http.StatusCreated)
}

// POST /api/findings/{id}/vuln-remediations
func (h *OrchestratorHandler) AssociateVulnerabilitiesAndRemediations(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	findingID, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		sendError(w, "Invalid finding ID", http.StatusBadRequest)
		return
	}

	var req struct {
		Vulnerability domain.Vulnerability `json:"vulnerability"`
		Remediation   domain.Remediation   `json:"remediation"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if err := h.orchestrator.AssociateVulnerabilitiesAndRemediations(r.Context(), findingID, &req.Vulnerability, &req.Remediation); err != nil {
		sendError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	sendJSON(w, map[string]string{"status": "success"}, http.StatusCreated)
}

// GET /api/infrastructure
func (h *OrchestratorHandler) GetInfrastructure(w http.ResponseWriter, r *http.Request) {
	graph, err := h.orchestrator.GetInfrastructure(r.Context())
	if err != nil {
		sendError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	sendJSON(w, graph, http.StatusOK)
}



// GET /api/infrastructure/top-apts
func (h *OrchestratorHandler) GetTopAPTs(w http.ResponseWriter, r *http.Request) {
	results, err := h.orchestrator.GetTopAPTs(r.Context())
	if err != nil {
		sendError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	sendJSON(w, results, http.StatusOK)
}
