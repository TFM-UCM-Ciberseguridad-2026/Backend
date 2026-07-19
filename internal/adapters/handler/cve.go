package handler

/*
Este archivo contiene los Controladores / Manejadores (HTTP Handlers) de la API REST.

Propósito arquitectónico y teórico:
1. Ubicación en Arquitectura Hexagonal: Se localiza en `internal/adapters/handler`, actuando como un Adaptador de Entrada (Driving Adapter) que traduce las peticiones HTTP entrantes en llamadas comprensibles por los puertos del Core.
2. Adaptador de Entrada (Driving Adapter): Sirve como la interfaz de entrada HTTP para interactuar con el sistema de vulnerabilidades.
3. Serialización y Deserialización: Traduce payloads de formato JSON a tipos estructurados del dominio (Deserialización) y codifica las estructuras de negocio de vuelta a formato JSON (Serialización).
4. Gestión del Protocolo HTTP: Configura cabeceras específicas (Content-Type: application/json), valida el método HTTP y asigna el código de estado adecuado (200 OK, 400 Bad Request, 500 Internal Server Error) basándose en las respuestas devueltas por los servicios del dominio.
*/

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

/*
ScanSoftwareVulnerabilities maneja la solicitud HTTP POST para ejecutar el escaneo y registro automático de vulnerabilidades.
Ruta: POST /api/installations/{id}/scan-vulns?software_id={software_id}
- 'id': Corresponde al ID de la instalación del software.
- 'software_id': ID numérico (Query Parameter) que apunta al software instalado.
Llama directamente al servicio Orchestrator y devuelve un JSON indicando estado exitoso o el respectivo código de error HTTP.
*/
func (h *OrchestratorHandler) ScanSoftwareVulnerabilities(w http.ResponseWriter, r *http.Request) {
	instID := r.PathValue("id")
	swIDStr := r.URL.Query().Get("software_id")
	if swIDStr == "" {
		sendError(w, "Missing software_id query parameter", http.StatusBadRequest)
		return
	}
	swID, err := strconv.ParseInt(swIDStr, 10, 64)
	if err != nil {
		sendError(w, "Invalid software_id", http.StatusBadRequest)
		return
	}

	if err := h.orchestrator.AutoScanAndRegisterVulnerabilities(r.Context(), instID, swID); err != nil {
		sendError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	sendJSON(w, map[string]string{"status": "success"}, http.StatusOK)
}

// POST /api/endpoints/{id}/compute-risk
// Calcula y persiste el riesgo de todos los findings abiertos del endpoint indicado.
// Llama a las APIs EPSS y KEV para obtener datos frescos antes de calcular.
func (h *OrchestratorHandler) ComputeEndpointRisk(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	endpointID, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		sendError(w, "Invalid endpoint ID", http.StatusBadRequest)
		return
	}

	if err := h.orchestrator.ComputeEndpointRisk(r.Context(), endpointID); err != nil {
		sendError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	sendJSON(w, map[string]string{"status": "risk computed"}, http.StatusOK)
}

// POST /api/risk/recalculate-all
// Recalcula el riesgo de todos los endpoints. Pensado para el cron diario o trigger manual.
func (h *OrchestratorHandler) ComputeAllRisks(w http.ResponseWriter, r *http.Request) {
	if err := h.orchestrator.ComputeAllEndpointsRisk(r.Context()); err != nil {
		sendError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	sendJSON(w, map[string]string{"status": "all risks recomputed"}, http.StatusOK)
}

// POST /api/installations/{id}/compute-risk
// Calcula y persiste el riesgo de todos los findings abiertos de la instalación de software indicada.
func (h *OrchestratorHandler) ComputeSoftwareInstallationRisk(w http.ResponseWriter, r *http.Request) {
	installationID := r.PathValue("id")
	if installationID == "" {
		sendError(w, "Invalid installation ID", http.StatusBadRequest)
		return
	}

	riskScore, err := h.orchestrator.ComputeSoftwareInstallationRisk(r.Context(), installationID)
	if err != nil {
		sendError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	sendJSON(w, map[string]any{
		"status":     "software installation risk computed",
		"risk_score": riskScore,
	}, http.StatusOK)
}
