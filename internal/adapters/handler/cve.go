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
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"

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
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
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

// DELETE /api/projects/{id}
func (h *OrchestratorHandler) DeleteProject(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	projectID, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		sendError(w, "ID de proyecto inválido: "+err.Error(), http.StatusBadRequest)
		return
	}

	if err := h.orchestrator.DeleteProject(r.Context(), projectID); err != nil {
		sendError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	sendJSON(w, map[string]string{"status": "success", "message": "Proyecto eliminado con éxito"}, http.StatusOK)
}

// PUT /api/projects/{id}
func (h *OrchestratorHandler) RenameProject(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	projectID, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		sendError(w, "ID de proyecto inválido: "+err.Error(), http.StatusBadRequest)
		return
	}

	var payload struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		sendError(w, "Error decodificando payload: "+err.Error(), http.StatusBadRequest)
		return
	}

	if err := h.orchestrator.RenameProject(r.Context(), projectID, payload.Name); err != nil {
		sendError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	sendJSON(w, map[string]string{"status": "success", "message": "Proyecto renombrado con éxito"}, http.StatusOK)
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

// POST /api/containers/images/{id}/scan-vulns
func (h *OrchestratorHandler) ScanContainerImageVulnerabilities(w http.ResponseWriter, r *http.Request) {
	imageID, err := url.PathUnescape(r.PathValue("id"))
	if err != nil || imageID == "" {
		imageID = r.PathValue("id")
	}

	if imageID == "" {
		sendError(w, "Invalid Image ID", http.StatusBadRequest)
		return
	}

	var req struct {
		ImageName string `json:"image_name"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	imageName := req.ImageName
	if imageName == "" {
		imageName = imageID
	}

	// Ejecutar el escaneo de forma síncrona (bloqueante)
	// Gracias al timeout de 5 minutos en Vite, no debería dar 502 con imágenes grandes.
	if err := h.orchestrator.ScanAndSaveContainerImage(r.Context(), imageName, imageID); err != nil {
		fmt.Printf("[ScanContainerImage] Error escaneando %s: %v\n", imageName, err)
		sendError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	fmt.Printf("[ScanContainerImage] Escaneo completado para %s\n", imageName)

	// Responder con éxito una vez terminado
	sendJSON(w, map[string]string{
		"status":  "success",
		"message": fmt.Sprintf("Escaneo de '%s' completado.", imageName),
	}, http.StatusOK)
}

// POST /api/containers/{id}/installations
func (h *OrchestratorHandler) RegisterContainerSoftwareInstallation(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")

	var req struct {
		Software     domain.Software             `json:"software"`
		Installation domain.SoftwareInstallation `json:"installation"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if err := h.orchestrator.RegisterContainerSoftwareInstallation(r.Context(), idStr, &req.Software, &req.Installation); err != nil {
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

// GET /api/findings/{id}/vulnerabilities
func (h *OrchestratorHandler) GetFindingVulnerabilities(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")

	var findingID any
	if idInt, err := strconv.ParseInt(idStr, 10, 64); err == nil {
		findingID = idInt
	} else {
		findingID = idStr
	}

	vulns, err := h.orchestrator.GetVulnerabilitiesForFinding(r.Context(), findingID)
	if err != nil {
		sendError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	sendJSON(w, map[string]any{
		"finding_id":      findingID,
		"count":           len(vulns),
		"vulnerabilities": vulns,
	}, http.StatusOK)
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

// POST /api/infrastructure/import
func (h *OrchestratorHandler) ImportInfrastructure(w http.ResponseWriter, r *http.Request) {
	var payload domain.GraphData
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		sendError(w, "JSON inválido: "+err.Error(), http.StatusBadRequest)
		return
	}

	if err := h.orchestrator.ImportInfrastructure(r.Context(), &payload); err != nil {
		sendError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	sendJSON(w, map[string]string{"status": "success", "message": "Infraestructura importada con éxito"}, http.StatusCreated)
}

// GET /api/infrastructure/top-apts
func (h *OrchestratorHandler) GetTopAPTs(w http.ResponseWriter, r *http.Request) {
	projectIDStr := r.URL.Query().Get("project_id")
	var projectID int64 = 0
	if projectIDStr != "" {
		if id, err := strconv.ParseInt(projectIDStr, 10, 64); err == nil {
			projectID = id
		}
	}

	results, err := h.orchestrator.GetTopAPTs(r.Context(), projectID)
	if err != nil {
		sendError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	sendJSON(w, results, http.StatusOK)
}

// GET /api/infrastructure/mitre-ttp-count
func (h *OrchestratorHandler) GetMitreTTPCount(w http.ResponseWriter, r *http.Request) {
	count, err := h.orchestrator.GetTotalMitreTTPs(r.Context())
	if err != nil {
		sendError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	sendJSON(w, map[string]int{"count": count}, http.StatusOK)
}

// GET /api/infrastructure/exploitation-paths?project_id={id}
func (h *OrchestratorHandler) GetExploitationPaths(w http.ResponseWriter, r *http.Request) {
	projectIDStr := r.URL.Query().Get("project_id")
	var projectID int64
	if projectIDStr != "" {
		var err error
		projectID, err = strconv.ParseInt(projectIDStr, 10, 64)
		if err != nil {
			sendError(w, "Invalid project_id", http.StatusBadRequest)
			return
		}
	}
	paths, err := h.orchestrator.GenerateExploitationPaths(r.Context(), projectID)
	if err != nil {
		sendError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Comprobar si hay análisis en background
	isPending, err := h.orchestrator.IsAnalysisPending(r.Context(), projectID)
	if err == nil && isPending {
		w.Header().Set("X-Analysis-Pending", "true")
		w.Header().Set("X-Analysis-Warning", url.PathEscape("Se ha detectado una imagen y se está analizando en segundo plano. Podrían surgir más rutas de ataque en el futuro."))
	}

	sendJSON(w, paths, http.StatusOK)
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

	limit := 100
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		parsedLimit, err := strconv.Atoi(limitStr)
		if err != nil || parsedLimit <= 0 {
			sendError(w, "Invalid limit", http.StatusBadRequest)
			return
		}
		if parsedLimit < limit {
			limit = parsedLimit
		}
	}

	result, err := h.orchestrator.AutoScanAndRegisterVulnerabilities(r.Context(), instID, swID, limit)
	if err != nil {
		sendError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	sendJSON(w, result, http.StatusOK)
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
	sendJSON(w, map[string]any{
		"status":      "risk computed",
		"endpoint_id": endpointID,
	}, http.StatusOK)
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

// POST /api/projects/{id}/compute-risk
// Recalcula el riesgo agregado de un proyecto completo, basado en todos sus endpoints y findings asociados.
func (h *OrchestratorHandler) ComputeProjectRisk(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	projectID, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		sendError(w, "Invalid project ID", http.StatusBadRequest)
		return
	}

	if err := h.orchestrator.ComputeProjectRisk(r.Context(), projectID); err != nil {
		sendError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	sendJSON(w, map[string]any{
		"status":     "project risk computed",
		"project_id": projectID,
	}, http.StatusOK)
}

// POST /api/risk/recalculate-all-projects
// Recalcula el riesgo de todos los proyectos. Pensado para el cron diario o trigger manual.
func (h *OrchestratorHandler) ComputeAllProjectsRisk(w http.ResponseWriter, r *http.Request) {
	if err := h.orchestrator.ComputeAllProjectsRisk(r.Context()); err != nil {
		sendError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	sendJSON(w, map[string]string{"status": "all project risks recomputed"}, http.StatusOK)
}

// GET /api/vulnerabilities/{cve}/patches
// Devuelve los parches oficiales disponibles para un CVE concreto.
func (h *OrchestratorHandler) GetPatchesForVulnerability(w http.ResponseWriter, r *http.Request) {
	cveID := r.PathValue("cve")
	if cveID == "" {
		sendError(w, "Invalid CVE ID", http.StatusBadRequest)
		return
	}

	patches, err := h.orchestrator.GetPatchesForVulnerability(r.Context(), cveID)
	if err != nil {
		sendError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	sendJSON(w, map[string]any{
		"cve_id":  cveID,
		"count":   len(patches),
		"patches": patches,
	}, http.StatusOK)
}

// POST /api/vulnerabilities/{cve}/patches/refresh
// Consulta la fuente externa de parches (OSV), registra los que encuentre y propaga la
// versión corregida a las remediaciones del CVE.
func (h *OrchestratorHandler) RefreshPatchesForVulnerability(w http.ResponseWriter, r *http.Request) {
	cveID := r.PathValue("cve")
	if cveID == "" {
		sendError(w, "Invalid CVE ID", http.StatusBadRequest)
		return
	}

	info, err := h.orchestrator.EnrichPatchesFromProvider(r.Context(), cveID)
	if err != nil {
		sendError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// La fuente no cubre este CVE: no es un error, simplemente no aporta datos.
	if info == nil {
		sendJSON(w, map[string]any{
			"cve_id": cveID,
			"status": "sin datos en la fuente externa",
			"found":  false,
		}, http.StatusOK)
		return
	}

	sendJSON(w, map[string]any{
		"cve_id":         cveID,
		"status":         "parches actualizados",
		"found":          true,
		"source":         info.Source,
		"patches":        info.Patches,
		"fixed_versions": info.FixedVersions,
	}, http.StatusOK)
}

// POST /api/installations/{id}/applied-patches
// Declara que un parche se ha aplicado sobre la instalación indicada.
//
// Cuerpo esperado:
//
//	{
//	  "cve_id": "CVE-2021-44228",
//	  "patch_id": 8,                       // opcional si el CVE solo tiene un parche
//	  "remediation_level": "OFFICIAL_FIX",  // OFFICIAL_FIX | TEMPORARY_FIX | WORKAROUND | UNAVAILABLE
//	  "applied_at": "2026-07-29T10:00:00Z", // opcional, por defecto ahora
//	  "applied_by": "diego",
//	  "notes": "..."
//	}
func (h *OrchestratorHandler) DeclarePatchApplied(w http.ResponseWriter, r *http.Request) {
	installationID := r.PathValue("id")
	if installationID == "" {
		sendError(w, "Invalid installation ID", http.StatusBadRequest)
		return
	}

	var req struct {
		CVEID            string     `json:"cve_id"`
		PatchID          int64      `json:"patch_id"`
		RemediationLevel string     `json:"remediation_level"`
		AppliedAt        *time.Time `json:"applied_at"`
		AppliedBy        string     `json:"applied_by"`
		Notes            string     `json:"notes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	appliedAt := time.Time{}
	if req.AppliedAt != nil {
		appliedAt = *req.AppliedAt
	}

	application, affected, err := h.orchestrator.DeclarePatchApplied(
		r.Context(), installationID, req.CVEID, req.PatchID,
		domain.RemediationLevel(req.RemediationLevel),
		appliedAt, req.AppliedBy, req.Notes,
	)
	if err != nil {
		// Datos mal informados por el cliente, no fallo del servidor.
		sendError(w, err.Error(), http.StatusBadRequest)
		return
	}

	sendJSON(w, map[string]any{
		"status":            "parche declarado como aplicado",
		"application":       application,
		"affected_findings": affected,
	}, http.StatusCreated)
}

// GET /api/patch-queue?project_id={id}&limit={n}
// Cola de parcheo: findings pendientes ordenados por prioridad. Sin project_id recorre
// toda la infraestructura.
func (h *OrchestratorHandler) GetPatchQueue(w http.ResponseWriter, r *http.Request) {
	var projectID *int64
	if raw := r.URL.Query().Get("project_id"); raw != "" {
		parsed, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			sendError(w, "Invalid project_id", http.StatusBadRequest)
			return
		}
		projectID = &parsed
	}

	limit := 0
	if raw := r.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed <= 0 {
			sendError(w, "Invalid limit", http.StatusBadRequest)
			return
		}
		limit = parsed
	}

	queue, err := h.orchestrator.GetPatchQueue(r.Context(), projectID, limit)
	if err != nil {
		sendError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	sendJSON(w, map[string]any{
		"count": len(queue),
		"queue": queue,
	}, http.StatusOK)
}

// GET /api/installations/{id}/applied-patches
// Devuelve el histórico de parches aplicados sobre una instalación.
func (h *OrchestratorHandler) GetAppliedPatchHistory(w http.ResponseWriter, r *http.Request) {
	installationID := r.PathValue("id")
	if installationID == "" {
		sendError(w, "Invalid installation ID", http.StatusBadRequest)
		return
	}

	history, err := h.orchestrator.GetAppliedPatchHistory(r.Context(), installationID)
	if err != nil {
		sendError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	sendJSON(w, map[string]any{
		"installation_id": installationID,
		"count":           len(history),
		"applied_patches": history,
	}, http.StatusOK)
}

// createNetworkRequest es el DTO de entrada para POST /api/networks y PUT /api/networks/{id}.
// ProjectID identifica el proyecto activo en el frontend en el momento de crear/editar la
// red: si la red no coincide con ningún endpoint, se usa para anclarla como huérfana de
// ese proyecto únicamente (ver Orchestrator.CreateNetwork/UpdateNetwork).
type createNetworkRequest struct {
	Nombre      string `json:"nombre"`
	CIDR        string `json:"cidr"`
	Gateway     string `json:"gateway"`
	VLANID      int64  `json:"vlan_id"`
	Descripcion string `json:"descripcion"`
	ProjectID   int64  `json:"project_id"`
}

// POST /api/networks
// Crea una red de forma independiente (sin endpoint asociado) y enlaza automáticamente
// los endpoints cuya IP caiga dentro del CIDR y, si se indica VLAN, la compartan.
func (h *OrchestratorHandler) CreateNetwork(w http.ResponseWriter, r *http.Request) {
	var req createNetworkRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if req.Nombre == "" || req.CIDR == "" || req.Gateway == "" {
		sendError(w, "nombre, cidr y gateway son obligatorios", http.StatusBadRequest)
		return
	}

	network := domain.Network{
		Nombre:      req.Nombre,
		CIDR:        req.CIDR,
		Gateway:     req.Gateway,
		VLANID:      req.VLANID,
		Descripcion: req.Descripcion,
	}

	networkID, linked, err := h.orchestrator.CreateNetwork(r.Context(), &network, req.ProjectID)
	if err != nil {
		sendError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	sendJSON(w, map[string]any{
		"status":           "success",
		"network_id":       networkID,
		"nombre":           req.Nombre,
		"cidr":             req.CIDR,
		"gateway":          req.Gateway,
		"vlan_id":          req.VLANID,
		"descripcion":      req.Descripcion,
		"linked_endpoints": linked,
	}, http.StatusCreated)
}

// === HANDLERS DE EDICIÓN Y BORRADO (CRUD COMPLETO) ===

// PUT /api/endpoints/{id}
func (h *OrchestratorHandler) UpdateEndpoint(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	endpointID, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		sendError(w, "ID de endpoint inválido", http.StatusBadRequest)
		return
	}
	var endpoint domain.Endpoint
	if err := json.NewDecoder(r.Body).Decode(&endpoint); err != nil {
		sendError(w, "JSON inválido: "+err.Error(), http.StatusBadRequest)
		return
	}
	endpoint.EndpointID = endpointID

	if err := h.orchestrator.UpdateEndpoint(r.Context(), &endpoint); err != nil {
		sendError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	sendJSON(w, map[string]any{"status": "success", "message": "Endpoint actualizado con éxito"}, http.StatusOK)
}

// GET /api/endpoints/{id}/ips
func (h *OrchestratorHandler) GetEndpointIPs(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	endpointID, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		sendError(w, "ID de endpoint inválido", http.StatusBadRequest)
		return
	}
	ips, err := h.orchestrator.GetEndpointIPs(r.Context(), endpointID)
	if err != nil {
		sendError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	sendJSON(w, map[string]any{"ips": ips}, http.StatusOK)
}

// DELETE /api/endpoints/{id}
func (h *OrchestratorHandler) DeleteEndpoint(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	if endpointID, err := strconv.ParseInt(idStr, 10, 64); err == nil {
		if err := h.orchestrator.DeleteEndpoint(r.Context(), endpointID); err == nil {
			sendJSON(w, map[string]any{"status": "success", "message": "Endpoint eliminado con éxito"}, http.StatusOK)
			return
		}
	}
	if err := h.orchestrator.DeleteNodeByID(r.Context(), idStr); err != nil {
		sendError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	sendJSON(w, map[string]any{"status": "success", "message": "Endpoint eliminado con éxito"}, http.StatusOK)
}

// PUT /api/networks/{id}
func (h *OrchestratorHandler) UpdateNetwork(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	networkID, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		sendError(w, "ID de red inválido", http.StatusBadRequest)
		return
	}
	var req createNetworkRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(w, "JSON inválido: "+err.Error(), http.StatusBadRequest)
		return
	}
	network := domain.Network{
		NetworkID:   networkID,
		Nombre:      req.Nombre,
		CIDR:        req.CIDR,
		Gateway:     req.Gateway,
		VLANID:      req.VLANID,
		Descripcion: req.Descripcion,
	}
	linked, err := h.orchestrator.UpdateNetwork(r.Context(), &network, req.ProjectID)
	if err != nil {
		sendError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	sendJSON(w, map[string]any{"status": "success", "linked_endpoints": linked, "message": "Red actualizada con éxito"}, http.StatusOK)
}

// DELETE /api/networks/{id}
func (h *OrchestratorHandler) DeleteNetwork(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	if networkID, err := strconv.ParseInt(idStr, 10, 64); err == nil {
		if err := h.orchestrator.DeleteNetwork(r.Context(), networkID); err == nil {
			sendJSON(w, map[string]any{"status": "success", "message": "Red eliminada con éxito"}, http.StatusOK)
			return
		}
	}
	if err := h.orchestrator.DeleteNodeByID(r.Context(), idStr); err != nil {
		sendError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	sendJSON(w, map[string]any{"status": "success", "message": "Red eliminada con éxito"}, http.StatusOK)
}

// PUT /api/hardware/{id}
func (h *OrchestratorHandler) UpdateHardware(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	hwID, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		sendError(w, "ID de hardware inválido", http.StatusBadRequest)
		return
	}
	var hw domain.Hardware
	if err := json.NewDecoder(r.Body).Decode(&hw); err != nil {
		sendError(w, "JSON inválido: "+err.Error(), http.StatusBadRequest)
		return
	}
	hw.HardwareID = hwID
	if err := h.orchestrator.UpdateHardware(r.Context(), &hw); err != nil {
		sendError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	sendJSON(w, map[string]any{"status": "success", "message": "Hardware actualizado con éxito"}, http.StatusOK)
}

// DELETE /api/hardware/{id}
func (h *OrchestratorHandler) DeleteHardware(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	if hwID, err := strconv.ParseInt(idStr, 10, 64); err == nil {
		if err := h.orchestrator.DeleteHardware(r.Context(), hwID); err == nil {
			sendJSON(w, map[string]any{"status": "success", "message": "Hardware eliminado con éxito"}, http.StatusOK)
			return
		}
	}
	if err := h.orchestrator.DeleteNodeByID(r.Context(), idStr); err != nil {
		sendError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	sendJSON(w, map[string]any{"status": "success", "message": "Hardware eliminado con éxito"}, http.StatusOK)
}

// PUT /api/software/{id}
func (h *OrchestratorHandler) UpdateSoftware(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	swID, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		sendError(w, "ID de software inválido", http.StatusBadRequest)
		return
	}
	var sw domain.Software
	if err := json.NewDecoder(r.Body).Decode(&sw); err != nil {
		sendError(w, "JSON inválido: "+err.Error(), http.StatusBadRequest)
		return
	}
	sw.SoftwareID = swID
	if err := h.orchestrator.UpdateSoftware(r.Context(), &sw); err != nil {
		sendError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	sendJSON(w, map[string]any{"status": "success", "message": "Software actualizado con éxito"}, http.StatusOK)
}

// DELETE /api/software/{id}
func (h *OrchestratorHandler) DeleteSoftware(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	if swID, err := strconv.ParseInt(idStr, 10, 64); err == nil {
		if err := h.orchestrator.DeleteSoftware(r.Context(), swID); err == nil {
			sendJSON(w, map[string]any{"status": "success", "message": "Software eliminado con éxito"}, http.StatusOK)
			return
		}
	}
	if err := h.orchestrator.DeleteNodeByID(r.Context(), idStr); err != nil {
		sendError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	sendJSON(w, map[string]any{"status": "success", "message": "Software eliminado con éxito"}, http.StatusOK)
}

// PUT /api/installations/{id}
func (h *OrchestratorHandler) UpdateSoftwareInstallation(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	if idStr == "" {
		sendError(w, "ID de instalación obligatorio", http.StatusBadRequest)
		return
	}
	var inst domain.SoftwareInstallation
	if err := json.NewDecoder(r.Body).Decode(&inst); err != nil {
		sendError(w, "JSON inválido: "+err.Error(), http.StatusBadRequest)
		return
	}
	inst.InstallationID = idStr
	if err := h.orchestrator.UpdateSoftwareInstallation(r.Context(), &inst); err != nil {
		sendError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	sendJSON(w, map[string]any{"status": "success", "message": "Instalación actualizada con éxito"}, http.StatusOK)
}

// DELETE /api/installations/{id}
func (h *OrchestratorHandler) DeleteSoftwareInstallation(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	if idStr == "" {
		sendError(w, "ID de instalación obligatorio", http.StatusBadRequest)
		return
	}
	if err := h.orchestrator.DeleteSoftwareInstallation(r.Context(), idStr); err != nil {
		// Si falló el borrado de instalación específico, intentar borrado genérico
		if err2 := h.orchestrator.DeleteNodeByID(r.Context(), idStr); err2 == nil {
			sendJSON(w, map[string]any{"status": "success", "message": "Instalación eliminada con éxito"}, http.StatusOK)
			return
		}
		sendError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	sendJSON(w, map[string]any{"status": "success", "message": "Instalación eliminada con éxito"}, http.StatusOK)
}

// DELETE /api/nodes/{id} (Borrado genérico de cualquier nodo del grafo)
func (h *OrchestratorHandler) DeleteNode(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	if idStr == "" {
		sendError(w, "ID de nodo obligatorio", http.StatusBadRequest)
		return
	}
	if err := h.orchestrator.DeleteNodeByID(r.Context(), idStr); err != nil {
		sendError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	sendJSON(w, map[string]any{"status": "success", "message": "Nodo eliminado con éxito"}, http.StatusOK)
}

func (h *OrchestratorHandler) GetTTPSyncStatus(w http.ResponseWriter, r *http.Request) {
	status := h.orchestrator.GetTTPSyncStatus()
	sendJSON(w, status, http.StatusOK)
}

// POST /api/infrastructure/map-ttps
func (h *OrchestratorHandler) MapTTPsManually(w http.ResponseWriter, r *http.Request) {
	go h.orchestrator.StartBackgroundTTPMapping()
	sendJSON(w, map[string]any{"status": "success", "message": "Mapeo de TTPs iniciado en segundo plano"}, http.StatusOK)
}

// POST /api/endpoints/{id}/containers
func (h *OrchestratorHandler) AddContainerToEndpoint(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	endpointID, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		sendError(w, "Invalid endpoint ID", http.StatusBadRequest)
		return
	}

	var container domain.Container
	if err := json.NewDecoder(r.Body).Decode(&container); err != nil {
		sendError(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if err := h.orchestrator.AddContainerToEndpoint(r.Context(), endpointID, &container); err != nil {
		sendError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	sendJSON(w, map[string]string{"status": "success"}, http.StatusCreated)
}

// PUT /api/containers/{id}
func (h *OrchestratorHandler) UpdateContainer(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")

	var container domain.Container
	if err := json.NewDecoder(r.Body).Decode(&container); err != nil {
		sendError(w, "JSON inválido: "+err.Error(), http.StatusBadRequest)
		return
	}
	container.ContainerID = idStr

	if err := h.orchestrator.UpdateContainer(r.Context(), &container); err != nil {
		sendError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	sendJSON(w, map[string]any{"status": "success", "message": "Contenedor actualizado con éxito"}, http.StatusOK)
}

// DELETE /api/containers/{id}
func (h *OrchestratorHandler) DeleteContainer(w http.ResponseWriter, r *http.Request) {
	// Se puede delegar en el borrado genérico o tener lógica específica si hace falta
	h.DeleteNode(w, r)
}

func (h *OrchestratorHandler) GetTTPMatrix(w http.ResponseWriter, r *http.Request) {
	var projectID *int64
	projectIDStr := r.URL.Query().Get("project_id")
	if projectIDStr != "" {
		parsedID, err := strconv.ParseInt(projectIDStr, 10, 64)
		if err == nil {
			projectID = &parsedID
		}
	}

	matrix, err := h.orchestrator.GetTTPMatrix(r.Context(), projectID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	json.NewEncoder(w).Encode(matrix)
}
