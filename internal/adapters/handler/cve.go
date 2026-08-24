package handler

/*
Este archivo contiene los Controladores / Manejadores (HTTP Handlers) de la API REST.
Emite logs estructurados en JSON (sin campo operador) con diffs exactos y justificación.
*/

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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


// ESTRUCTURAS Y EMISOR DE AUDITORÍA (STDOUT + FICHERO PERSISTENTE)

var auditWriter io.Writer = os.Stdout

func init() {
	logPath := os.Getenv("AUDIT_LOG_PATH")
	if logPath == "" {
		logPath = "logs/audit.log"
	}
	dir := filepath.Dir(logPath)
	if dir != "" && dir != "." {
		_ = os.MkdirAll(dir, 0755)
	}
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err == nil {
		auditWriter = io.MultiWriter(os.Stdout, f)
	} else {
		auditWriter = os.Stdout
	}
}

type auditChange struct {
	Antes   any `json:"antes,omitempty"`
	Despues any `json:"despues,omitempty"`
}

type auditAction struct {
	Tipo         string `json:"tipo"`          // CREACION, MODIFICACION, ELIMINACION
	TipoActivo   string `json:"tipo_activo"`   // Endpoint, Network, Container, etc.
	IDActivo     string `json:"id_activo"`
	NombreActivo string `json:"nombre_activo,omitempty"`
	ProyectoID   string `json:"proyecto_id,omitempty"`
}

type auditLogEntry struct {
	FechaHora         string                 `json:"fecha_hora"`
	Nivel             string                 `json:"nivel"` // "AUDIT"
	Accion            auditAction            `json:"accion"`
	Justificacion     string                 `json:"justificacion,omitempty"`
	CambiosRealizados map[string]auditChange `json:"cambios_realizados,omitempty"`
	Estado            string                 `json:"estado"` // SUCCESS / ERROR
	DetallesError     string                 `json:"detalles_error,omitempty"`
}

func emitAuditLog(tipoAccion, tipoActivo, idActivo, nombreActivo, proyectoID, justificacion string, cambios map[string]auditChange, estado, errStr string) {
	entry := auditLogEntry{
		FechaHora: time.Now().UTC().Format(time.RFC3339Nano),
		Nivel:     "AUDIT",
		Accion: auditAction{
			Tipo:         tipoAccion,
			TipoActivo:   tipoActivo,
			IDActivo:     idActivo,
			NombreActivo: nombreActivo,
			ProyectoID:   proyectoID,
		},
		Justificacion:     justificacion,
		CambiosRealizados: cambios,
		Estado:            estado,
		DetallesError:     errStr,
	}

	if b, err := json.Marshal(entry); err == nil {
		fmt.Fprintln(auditWriter, string(b)) // Escribe simultáneamente en consola y fichero
	}
}

func extractJustification(r *http.Request) string {
	if q := r.URL.Query().Get("justification"); strings.TrimSpace(q) != "" {
		return strings.TrimSpace(q)
	}
	return ""
}

func sendError(w http.ResponseWriter, msg string, code int) {
	http.Error(w, msg, code)
}

func sendJSON(w http.ResponseWriter, data any, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(data)
}

// POST /api/projects
func (h *OrchestratorHandler) CreateProject(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		domain.Project
		Justification string `json:"justification"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		sendError(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	project := payload.Project
	if err := h.orchestrator.CreateProject(r.Context(), &project); err != nil {
		emitAuditLog("CREACION", "Project", fmt.Sprint(project.ProjectID), project.Nombre, fmt.Sprint(project.ProjectID), payload.Justification, nil, "ERROR", err.Error())
		sendError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	cambios := map[string]auditChange{
		"nombre":     {Despues: project.Nombre},
		"project_id": {Despues: project.ProjectID},
	}
	emitAuditLog("CREACION", "Project", fmt.Sprint(project.ProjectID), project.Nombre, fmt.Sprint(project.ProjectID), payload.Justification, cambios, "SUCCESS", "")
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

	oldProj, _ := h.orchestrator.GetProjectByID(r.Context(), projectID)
	nombre := ""
	if oldProj != nil {
		nombre = oldProj.Nombre
	}

	if err := h.orchestrator.DeleteProject(r.Context(), projectID); err != nil {
		emitAuditLog("ELIMINACION", "Project", idStr, nombre, idStr, "", nil, "ERROR", err.Error())
		sendError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	emitAuditLog("ELIMINACION", "Project", idStr, nombre, idStr, "", nil, "SUCCESS", "")
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
		Name          string `json:"name"`
		Justification string `json:"justification"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		sendError(w, "Error decodificando payload: "+err.Error(), http.StatusBadRequest)
		return
	}

	oldProj, _ := h.orchestrator.GetProjectByID(r.Context(), projectID)

	if err := h.orchestrator.RenameProject(r.Context(), projectID, payload.Name); err != nil {
		emitAuditLog("MODIFICACION", "Project", idStr, payload.Name, idStr, payload.Justification, nil, "ERROR", err.Error())
		sendError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	cambios := make(map[string]auditChange)
	if oldProj != nil && oldProj.Nombre != payload.Name {
		cambios["nombre"] = auditChange{Antes: oldProj.Nombre, Despues: payload.Name}
	}

	emitAuditLog("MODIFICACION", "Project", idStr, payload.Name, idStr, payload.Justification, cambios, "SUCCESS", "")
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

	var payload struct {
		domain.Endpoint
		Justification string `json:"justification"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		sendError(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	endpoint := payload.Endpoint
	if err := h.orchestrator.AddEndpointToProject(r.Context(), projectID, &endpoint); err != nil {
		emitAuditLog("CREACION", "Endpoint", fmt.Sprint(endpoint.EndpointID), endpoint.Hostname, idStr, payload.Justification, nil, "ERROR", err.Error())
		sendError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	cambios := map[string]auditChange{
		"endpoint_id":         {Despues: endpoint.EndpointID},
		"hostname":            {Despues: endpoint.Hostname},
		"tipo":                {Despues: endpoint.Type},
		"status":              {Despues: endpoint.Status},
		"environment":         {Despues: endpoint.Environment},
		"internet_exposed":    {Despues: endpoint.InternetExposed},
		"confidentiality_req": {Despues: endpoint.ConfidentialityReq},
		"integrity_req":       {Despues: endpoint.IntegrityReq},
		"availability_req":    {Despues: endpoint.AvailabilityReq},
		"project_id":          {Despues: projectID},
	}
	if len(endpoint.IPs) > 0 {
		cambios["ips"] = auditChange{Despues: endpoint.IPs}
	}

	emitAuditLog("CREACION", "Endpoint", fmt.Sprint(endpoint.EndpointID), endpoint.Hostname, idStr, payload.Justification, cambios, "SUCCESS", "")
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

	var payload struct {
		domain.Hardware
		Justification string `json:"justification"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		sendError(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	hw := payload.Hardware
	if err := h.orchestrator.AssociateHardwareToEndpoint(r.Context(), endpointID, &hw); err != nil {
		emitAuditLog("CREACION", "Hardware", fmt.Sprint(hw.HardwareID), hw.Model, "", payload.Justification, nil, "ERROR", err.Error())
		sendError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	cambios := map[string]auditChange{
		"hardware_id":   {Despues: hw.HardwareID},
		"modelo":        {Despues: hw.Model},
		"tipo":          {Despues: hw.Type},
		"manufacturer":  {Despues: hw.Manufacturer},
		"serial_number": {Despues: hw.SerialNumber},
		"cpu":           {Despues: hw.CPU},
		"ram_gb":        {Despues: hw.RAMGB},
		"storage_gb":    {Despues: hw.StorageGB},
		"endpoint_id":   {Despues: endpointID},
	}

	emitAuditLog("CREACION", "Hardware", fmt.Sprint(hw.HardwareID), hw.Model, "", payload.Justification, cambios, "SUCCESS", "")
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
		Software      domain.Software             `json:"software"`
		Installation  domain.SoftwareInstallation `json:"installation"`
		Justification string                      `json:"justification"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if err := h.orchestrator.RegisterSoftwareInstallation(r.Context(), endpointID, &req.Software, &req.Installation); err != nil {
		emitAuditLog("CREACION", "SoftwareInstallation", req.Installation.InstallationID, req.Software.Name, "", req.Justification, nil, "ERROR", err.Error())
		sendError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	cambios := map[string]auditChange{
		"software_id":       {Despues: req.Software.SoftwareID},
		"name":              {Despues: req.Software.Name},
		"version":           {Despues: req.Software.Version},
		"vendor":            {Despues: req.Software.Vendor},
		"type":              {Despues: req.Software.Type},
		"cpe":               {Despues: req.Software.CPE},
		"installation_id":   {Despues: req.Installation.InstallationID},
		"install_path":      {Despues: req.Installation.InstallPath},
		"status":            {Despues: req.Installation.Status},
		"criticality_level": {Despues: req.Installation.CriticalityLevel},
		"endpoint_id":       {Despues: endpointID},
	}

	emitAuditLog("CREACION", "SoftwareInstallation", req.Installation.InstallationID, req.Software.Name, "", req.Justification, cambios, "SUCCESS", "")
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

	if err := h.orchestrator.ScanAndSaveContainerImage(r.Context(), imageName, imageID); err != nil {
		fmt.Printf("[ScanContainerImage] Error escaneando %s: %v\n", imageName, err)
		sendError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	sendJSON(w, map[string]string{
		"status":  "success",
		"message": fmt.Sprintf("Escaneo de '%s' completado.", imageName),
	}, http.StatusOK)
}

// POST /api/containers/{id}/installations
func (h *OrchestratorHandler) RegisterContainerSoftwareInstallation(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")

	var req struct {
		Software      domain.Software             `json:"software"`
		Installation  domain.SoftwareInstallation `json:"installation"`
		Justification string                      `json:"justification"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if err := h.orchestrator.RegisterContainerSoftwareInstallation(r.Context(), idStr, &req.Software, &req.Installation); err != nil {
		emitAuditLog("CREACION", "ContainerSoftwareInstallation", req.Installation.InstallationID, req.Software.Name, "", req.Justification, nil, "ERROR", err.Error())
		sendError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	cambios := map[string]auditChange{
		"software_id":       {Despues: req.Software.SoftwareID},
		"name":              {Despues: req.Software.Name},
		"version":           {Despues: req.Software.Version},
		"vendor":            {Despues: req.Software.Vendor},
		"type":              {Despues: req.Software.Type},
		"cpe":               {Despues: req.Software.CPE},
		"installation_id":   {Despues: req.Installation.InstallationID},
		"install_path":      {Despues: req.Installation.InstallPath},
		"status":            {Despues: req.Installation.Status},
		"criticality_level": {Despues: req.Installation.CriticalityLevel},
		"container_id":      {Despues: idStr},
	}

	emitAuditLog("CREACION", "ContainerSoftwareInstallation", req.Installation.InstallationID, req.Software.Name, "", req.Justification, cambios, "SUCCESS", "")
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

	emitAuditLog("CREACION", "InfrastructureImport", "batch", "GraphImport", "", "Importación masiva de infraestructura JSON", nil, "SUCCESS", "")
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

// GET /api/infrastructure/analysis-pending?project_id={id}
// Endpoint ligero para que el frontend haga polling y detecte cuando el enriquecimiento NVD en background termina.
func (h *OrchestratorHandler) GetAnalysisPending(w http.ResponseWriter, r *http.Request) {
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

	isPending, err := h.orchestrator.IsAnalysisPending(r.Context(), projectID)
	if err != nil {
		sendError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	sendJSON(w, map[string]bool{"pending": isPending}, http.StatusOK)
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
func (h *OrchestratorHandler) ComputeAllRisks(w http.ResponseWriter, r *http.Request) {
	if err := h.orchestrator.ComputeAllEndpointsRisk(r.Context()); err != nil {
		sendError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	sendJSON(w, map[string]string{"status": "all risks recomputed"}, http.StatusOK)
}

// POST /api/installations/{id}/compute-risk
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
func (h *OrchestratorHandler) ComputeAllProjectsRisk(w http.ResponseWriter, r *http.Request) {
	if err := h.orchestrator.ComputeAllProjectsRisk(r.Context()); err != nil {
		sendError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	sendJSON(w, map[string]string{"status": "all project risks recomputed"}, http.StatusOK)
}

// GET /api/vulnerabilities/{cve}/patches
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
		sendError(w, err.Error(), http.StatusBadRequest)
		return
	}

	emitAuditLog("CREACION", "AppliedPatch", fmt.Sprint(req.PatchID), req.CVEID, "", req.Notes, nil, "SUCCESS", "")
	sendJSON(w, map[string]any{
		"status":            "parche declarado como aplicado",
		"application":       application,
		"affected_findings": affected,
	}, http.StatusCreated)
}

// GET /api/patch-queue
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

type createNetworkRequest struct {
	Nombre        string `json:"nombre"`
	CIDR          string `json:"cidr"`
	Gateway       string `json:"gateway"`
	VLANID        int64  `json:"vlan_id"`
	Descripcion   string `json:"descripcion"`
	ProjectID     int64  `json:"project_id"`
	Justification string `json:"justification"`
}

// POST /api/networks
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
		emitAuditLog("CREACION", "Network", fmt.Sprint(networkID), req.Nombre, fmt.Sprint(req.ProjectID), req.Justification, nil, "ERROR", err.Error())
		sendError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	cambios := map[string]auditChange{
		"network_id":  {Despues: networkID},
		"nombre":      {Despues: req.Nombre},
		"cidr":        {Despues: req.CIDR},
		"gateway":     {Despues: req.Gateway},
		"vlan_id":     {Despues: req.VLANID},
		"descripcion": {Despues: req.Descripcion},
		"project_id":  {Despues: req.ProjectID},
	}

	emitAuditLog("CREACION", "Network", fmt.Sprint(networkID), req.Nombre, fmt.Sprint(req.ProjectID), req.Justification, cambios, "SUCCESS", "")
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

// === HANDLERS DE EDICIÓN Y BORRADO ===

// PUT /api/endpoints/{id}
func (h *OrchestratorHandler) UpdateEndpoint(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	endpointID, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		sendError(w, "ID de endpoint inválido", http.StatusBadRequest)
		return
	}

	var req struct {
		domain.Endpoint
		Justification string `json:"justification"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(w, "JSON inválido: "+err.Error(), http.StatusBadRequest)
		return
	}

	justification := strings.TrimSpace(req.Justification)
	if justification == "" {
		sendError(w, "El campo 'justificación' es obligatorio para modificar el endpoint", http.StatusBadRequest)
		return
	}

	oldEndpoint, _ := h.orchestrator.GetEndpointByID(r.Context(), endpointID)

	endpoint := req.Endpoint
	endpoint.EndpointID = endpointID

	if err := h.orchestrator.UpdateEndpoint(r.Context(), &endpoint); err != nil {
		emitAuditLog("MODIFICACION", "Endpoint", idStr, endpoint.Hostname, "", justification, nil, "ERROR", err.Error())
		sendError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	cambios := make(map[string]auditChange)
	if oldEndpoint != nil {
		if oldEndpoint.Hostname != endpoint.Hostname && endpoint.Hostname != "" {
			cambios["hostname"] = auditChange{Antes: oldEndpoint.Hostname, Despues: endpoint.Hostname}
		}
		if oldEndpoint.Type != endpoint.Type && endpoint.Type != "" {
			cambios["tipo"] = auditChange{Antes: oldEndpoint.Type, Despues: endpoint.Type}
		}
		if oldEndpoint.Status != endpoint.Status && endpoint.Status != "" {
			cambios["status"] = auditChange{Antes: oldEndpoint.Status, Despues: endpoint.Status}
		}
		if oldEndpoint.Environment != endpoint.Environment {
			cambios["environment"] = auditChange{Antes: oldEndpoint.Environment, Despues: endpoint.Environment}
		}
		if oldEndpoint.InternetExposed != endpoint.InternetExposed {
			cambios["internet_exposed"] = auditChange{Antes: oldEndpoint.InternetExposed, Despues: endpoint.InternetExposed}
		}
		if oldEndpoint.ConfidentialityReq != endpoint.ConfidentialityReq && endpoint.ConfidentialityReq != "" {
			cambios["confidentiality_req"] = auditChange{Antes: oldEndpoint.ConfidentialityReq, Despues: endpoint.ConfidentialityReq}
		}
		if oldEndpoint.IntegrityReq != endpoint.IntegrityReq && endpoint.IntegrityReq != "" {
			cambios["integrity_req"] = auditChange{Antes: oldEndpoint.IntegrityReq, Despues: endpoint.IntegrityReq}
		}
		if oldEndpoint.AvailabilityReq != endpoint.AvailabilityReq && endpoint.AvailabilityReq != "" {
			cambios["availability_req"] = auditChange{Antes: oldEndpoint.AvailabilityReq, Despues: endpoint.AvailabilityReq}
		}
	}

	emitAuditLog("MODIFICACION", "Endpoint", idStr, endpoint.Hostname, "", justification, cambios, "SUCCESS", "")
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
	justification := extractJustification(r)
	if justification == "" {
		var req struct {
			Justification string `json:"justification"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		justification = strings.TrimSpace(req.Justification)
	}

	if justification == "" {
		sendError(w, "El campo 'justificación' es obligatorio para eliminar el endpoint", http.StatusBadRequest)
		return
	}

	endpointID, parseErr := strconv.ParseInt(idStr, 10, 64)
	nombre := ""
	if parseErr == nil {
		if oldEp, _ := h.orchestrator.GetEndpointByID(r.Context(), endpointID); oldEp != nil {
			nombre = oldEp.Hostname
		}
	}

	var err error
	if parseErr == nil {
		err = h.orchestrator.DeleteEndpoint(r.Context(), endpointID)
	} else {
		err = h.orchestrator.DeleteNodeByID(r.Context(), idStr)
	}

	if err != nil {
		emitAuditLog("ELIMINACION", "Endpoint", idStr, nombre, "", justification, nil, "ERROR", err.Error())
		sendError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	emitAuditLog("ELIMINACION", "Endpoint", idStr, nombre, "", justification, nil, "SUCCESS", "")
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

	justification := strings.TrimSpace(req.Justification)
	if justification == "" {
		sendError(w, "El campo 'justificación' es obligatorio para modificar la red", http.StatusBadRequest)
		return
	}

	oldNet, _ := h.orchestrator.GetNetworkByID(r.Context(), networkID)

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
		emitAuditLog("MODIFICACION", "Network", idStr, req.Nombre, fmt.Sprint(req.ProjectID), justification, nil, "ERROR", err.Error())
		sendError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	cambios := make(map[string]auditChange)
	if oldNet != nil {
		if oldNet.Nombre != network.Nombre {
			cambios["nombre"] = auditChange{Antes: oldNet.Nombre, Despues: network.Nombre}
		}
		if oldNet.CIDR != network.CIDR {
			cambios["cidr"] = auditChange{Antes: oldNet.CIDR, Despues: network.CIDR}
		}
		if oldNet.Gateway != network.Gateway {
			cambios["gateway"] = auditChange{Antes: oldNet.Gateway, Despues: network.Gateway}
		}
		if oldNet.VLANID != network.VLANID {
			cambios["vlan_id"] = auditChange{Antes: oldNet.VLANID, Despues: network.VLANID}
		}
		if oldNet.Descripcion != network.Descripcion {
			cambios["descripcion"] = auditChange{Antes: oldNet.Descripcion, Despues: network.Descripcion}
		}
	}

	emitAuditLog("MODIFICACION", "Network", idStr, req.Nombre, fmt.Sprint(req.ProjectID), justification, cambios, "SUCCESS", "")
	sendJSON(w, map[string]any{"status": "success", "linked_endpoints": linked, "message": "Red actualizada con éxito"}, http.StatusOK)
}

// DELETE /api/networks/{id}
func (h *OrchestratorHandler) DeleteNetwork(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	justification := extractJustification(r)
	if justification == "" {
		var req struct {
			Justification string `json:"justification"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		justification = strings.TrimSpace(req.Justification)
	}

	if justification == "" {
		sendError(w, "El campo 'justificación' es obligatorio para eliminar la red", http.StatusBadRequest)
		return
	}

	nombre := ""
	if networkID, parseErr := strconv.ParseInt(idStr, 10, 64); parseErr == nil {
		if oldNet, _ := h.orchestrator.GetNetworkByID(r.Context(), networkID); oldNet != nil {
			nombre = oldNet.Nombre
		}
	}

	var err error
	if networkID, parseErr := strconv.ParseInt(idStr, 10, 64); parseErr == nil {
		err = h.orchestrator.DeleteNetwork(r.Context(), networkID)
	} else {
		err = h.orchestrator.DeleteNodeByID(r.Context(), idStr)
	}

	if err != nil {
		emitAuditLog("ELIMINACION", "Network", idStr, nombre, "", justification, nil, "ERROR", err.Error())
		sendError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	emitAuditLog("ELIMINACION", "Network", idStr, nombre, "", justification, nil, "SUCCESS", "")
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

	var req struct {
		domain.Hardware
		Justification string `json:"justification"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(w, "JSON inválido: "+err.Error(), http.StatusBadRequest)
		return
	}

	justification := strings.TrimSpace(req.Justification)
	if justification == "" {
		sendError(w, "El campo 'justificación' es obligatorio para modificar el hardware", http.StatusBadRequest)
		return
	}

	oldHW, _ := h.orchestrator.GetHardwareByID(r.Context(), hwID)

	hw := req.Hardware
	hw.HardwareID = hwID
	if err := h.orchestrator.UpdateHardware(r.Context(), &hw); err != nil {
		emitAuditLog("MODIFICACION", "Hardware", idStr, hw.Model, "", justification, nil, "ERROR", err.Error())
		sendError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	cambios := make(map[string]auditChange)
	if oldHW != nil {
		if oldHW.Model != hw.Model && hw.Model != "" {
			cambios["modelo"] = auditChange{Antes: oldHW.Model, Despues: hw.Model}
		}
		if oldHW.Type != hw.Type && hw.Type != "" {
			cambios["tipo"] = auditChange{Antes: oldHW.Type, Despues: hw.Type}
		}
		if oldHW.Manufacturer != hw.Manufacturer && hw.Manufacturer != "" {
			cambios["manufacturer"] = auditChange{Antes: oldHW.Manufacturer, Despues: hw.Manufacturer}
		}
		if oldHW.SerialNumber != hw.SerialNumber && hw.SerialNumber != "" {
			cambios["serial_number"] = auditChange{Antes: oldHW.SerialNumber, Despues: hw.SerialNumber}
		}
		if oldHW.CPU != hw.CPU && hw.CPU != "" {
			cambios["cpu"] = auditChange{Antes: oldHW.CPU, Despues: hw.CPU}
		}
		if oldHW.RAMGB != hw.RAMGB && hw.RAMGB > 0 {
			cambios["ram_gb"] = auditChange{Antes: oldHW.RAMGB, Despues: hw.RAMGB}
		}
		if oldHW.StorageGB != hw.StorageGB && hw.StorageGB > 0 {
			cambios["storage_gb"] = auditChange{Antes: oldHW.StorageGB, Despues: hw.StorageGB}
		}
	}

	emitAuditLog("MODIFICACION", "Hardware", idStr, hw.Model, "", justification, cambios, "SUCCESS", "")
	sendJSON(w, map[string]any{"status": "success", "message": "Hardware actualizado con éxito"}, http.StatusOK)
}

// DELETE /api/hardware/{id}
func (h *OrchestratorHandler) DeleteHardware(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	justification := extractJustification(r)
	if justification == "" {
		var req struct {
			Justification string `json:"justification"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		justification = strings.TrimSpace(req.Justification)
	}

	if justification == "" {
		sendError(w, "El campo 'justificación' es obligatorio para eliminar el hardware", http.StatusBadRequest)
		return
	}

	nombre := ""
	if hwID, parseErr := strconv.ParseInt(idStr, 10, 64); parseErr == nil {
		if oldHW, _ := h.orchestrator.GetHardwareByID(r.Context(), hwID); oldHW != nil {
			nombre = oldHW.Model
		}
	}

	var err error
	if hwID, parseErr := strconv.ParseInt(idStr, 10, 64); parseErr == nil {
		err = h.orchestrator.DeleteHardware(r.Context(), hwID)
	} else {
		err = h.orchestrator.DeleteNodeByID(r.Context(), idStr)
	}

	if err != nil {
		emitAuditLog("ELIMINACION", "Hardware", idStr, nombre, "", justification, nil, "ERROR", err.Error())
		sendError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	emitAuditLog("ELIMINACION", "Hardware", idStr, nombre, "", justification, nil, "SUCCESS", "")
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

	var req struct {
		domain.Software
		Justification string `json:"justification"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(w, "JSON inválido: "+err.Error(), http.StatusBadRequest)
		return
	}

	justification := strings.TrimSpace(req.Justification)
	if justification == "" {
		sendError(w, "El campo 'justificación' es obligatorio para modificar el software", http.StatusBadRequest)
		return
	}

	oldSW, _ := h.orchestrator.GetSoftwareByID(r.Context(), swID)

	sw := req.Software
	sw.SoftwareID = swID
	if err := h.orchestrator.UpdateSoftware(r.Context(), &sw); err != nil {
		emitAuditLog("MODIFICACION", "Software", idStr, sw.Name, "", justification, nil, "ERROR", err.Error())
		sendError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	cambios := make(map[string]auditChange)
	if oldSW != nil {
		if oldSW.Name != sw.Name && sw.Name != "" {
			cambios["name"] = auditChange{Antes: oldSW.Name, Despues: sw.Name}
		}
		if oldSW.Version != sw.Version {
			cambios["version"] = auditChange{Antes: oldSW.Version, Despues: sw.Version}
		}
		if oldSW.Vendor != sw.Vendor && sw.Vendor != "" {
			cambios["vendor"] = auditChange{Antes: oldSW.Vendor, Despues: sw.Vendor}
		}
		if oldSW.Type != sw.Type && sw.Type != "" {
			cambios["type"] = auditChange{Antes: oldSW.Type, Despues: sw.Type}
		}
		if oldSW.CPE != sw.CPE {
			cambios["cpe"] = auditChange{Antes: oldSW.CPE, Despues: sw.CPE}
		}
	}

	emitAuditLog("MODIFICACION", "Software", idStr, sw.Name, "", justification, cambios, "SUCCESS", "")
	sendJSON(w, map[string]any{"status": "success", "message": "Software actualizado con éxito"}, http.StatusOK)
}

// DELETE /api/software/{id}
func (h *OrchestratorHandler) DeleteSoftware(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	justification := extractJustification(r)
	if justification == "" {
		var req struct {
			Justification string `json:"justification"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		justification = strings.TrimSpace(req.Justification)
	}

	if justification == "" {
		sendError(w, "El campo 'justificación' es obligatorio para eliminar el software", http.StatusBadRequest)
		return
	}

	nombre := ""
	if swID, parseErr := strconv.ParseInt(idStr, 10, 64); parseErr == nil {
		if oldSW, _ := h.orchestrator.GetSoftwareByID(r.Context(), swID); oldSW != nil {
			nombre = oldSW.Name
		}
	}

	var err error
	if swID, parseErr := strconv.ParseInt(idStr, 10, 64); parseErr == nil {
		err = h.orchestrator.DeleteSoftware(r.Context(), swID)
	} else {
		err = h.orchestrator.DeleteNodeByID(r.Context(), idStr)
	}

	if err != nil {
		emitAuditLog("ELIMINACION", "Software", idStr, nombre, "", justification, nil, "ERROR", err.Error())
		sendError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	emitAuditLog("ELIMINACION", "Software", idStr, nombre, "", justification, nil, "SUCCESS", "")
	sendJSON(w, map[string]any{"status": "success", "message": "Software eliminado con éxito"}, http.StatusOK)
}

// PUT /api/installations/{id}
func (h *OrchestratorHandler) UpdateSoftwareInstallation(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	if idStr == "" {
		sendError(w, "ID de instalación obligatorio", http.StatusBadRequest)
		return
	}

	var req struct {
		domain.SoftwareInstallation
		Justification string `json:"justification"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(w, "JSON inválido: "+err.Error(), http.StatusBadRequest)
		return
	}

	justification := strings.TrimSpace(req.Justification)
	if justification == "" {
		sendError(w, "El campo 'justificación' es obligatorio para modificar la instalación", http.StatusBadRequest)
		return
	}

	oldInst, _ := h.orchestrator.GetSoftwareInstallationByID(r.Context(), idStr)

	inst := req.SoftwareInstallation
	inst.InstallationID = idStr
	if err := h.orchestrator.UpdateSoftwareInstallation(r.Context(), &inst); err != nil {
		emitAuditLog("MODIFICACION", "SoftwareInstallation", idStr, inst.InstallPath, "", justification, nil, "ERROR", err.Error())
		sendError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	cambios := make(map[string]auditChange)
	if oldInst != nil {
		if oldInst.InstallPath != inst.InstallPath && inst.InstallPath != "" {
			cambios["install_path"] = auditChange{Antes: oldInst.InstallPath, Despues: inst.InstallPath}
		}
		if oldInst.Status != inst.Status && inst.Status != "" {
			cambios["status"] = auditChange{Antes: oldInst.Status, Despues: inst.Status}
		}
		if oldInst.DetectedBy != inst.DetectedBy && inst.DetectedBy != "" {
			cambios["detected_by"] = auditChange{Antes: oldInst.DetectedBy, Despues: inst.DetectedBy}
		}
		if oldInst.PackageManager != inst.PackageManager && inst.PackageManager != "" {
			cambios["package_manager"] = auditChange{Antes: oldInst.PackageManager, Despues: inst.PackageManager}
		}
		if oldInst.CriticalityLevel != inst.CriticalityLevel && inst.CriticalityLevel != "" {
			cambios["criticality_level"] = auditChange{Antes: oldInst.CriticalityLevel, Despues: inst.CriticalityLevel}
		}
	}

	emitAuditLog("MODIFICACION", "SoftwareInstallation", idStr, inst.InstallPath, "", justification, cambios, "SUCCESS", "")
	sendJSON(w, map[string]any{"status": "success", "message": "Instalación actualizada con éxito"}, http.StatusOK)
}

// DELETE /api/installations/{id}
func (h *OrchestratorHandler) DeleteSoftwareInstallation(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	if idStr == "" {
		sendError(w, "ID de instalación obligatorio", http.StatusBadRequest)
		return
	}

	justification := extractJustification(r)
	if justification == "" {
		var req struct {
			Justification string `json:"justification"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		justification = strings.TrimSpace(req.Justification)
	}

	if justification == "" {
		sendError(w, "El campo 'justificación' es obligatorio para eliminar la instalación", http.StatusBadRequest)
		return
	}

	oldInst, _ := h.orchestrator.GetSoftwareInstallationByID(r.Context(), idStr)
	nombre := ""
	if oldInst != nil {
		nombre = oldInst.InstallPath
	}

	if err := h.orchestrator.DeleteSoftwareInstallation(r.Context(), idStr); err != nil {
		if err2 := h.orchestrator.DeleteNodeByID(r.Context(), idStr); err2 == nil {
			emitAuditLog("ELIMINACION", "SoftwareInstallation", idStr, nombre, "", justification, nil, "SUCCESS", "")
			sendJSON(w, map[string]any{"status": "success", "message": "Instalación eliminada con éxito"}, http.StatusOK)
			return
		}
		emitAuditLog("ELIMINACION", "SoftwareInstallation", idStr, nombre, "", justification, nil, "ERROR", err.Error())
		sendError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	emitAuditLog("ELIMINACION", "SoftwareInstallation", idStr, nombre, "", justification, nil, "SUCCESS", "")
	sendJSON(w, map[string]any{"status": "success", "message": "Instalación eliminada con éxito"}, http.StatusOK)
}

// DELETE /api/nodes/{id}
func (h *OrchestratorHandler) DeleteNode(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	if idStr == "" {
		sendError(w, "ID de nodo obligatorio", http.StatusBadRequest)
		return
	}

	justification := extractJustification(r)
	if justification == "" {
		var req struct {
			Justification string `json:"justification"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		justification = strings.TrimSpace(req.Justification)
	}

	if justification == "" {
		sendError(w, "El campo 'justificación' es obligatorio para eliminar el nodo", http.StatusBadRequest)
		return
	}

	if err := h.orchestrator.DeleteNodeByID(r.Context(), idStr); err != nil {
		emitAuditLog("ELIMINACION", "GenericNode", idStr, "", "", justification, nil, "ERROR", err.Error())
		sendError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	emitAuditLog("ELIMINACION", "GenericNode", idStr, "", "", justification, nil, "SUCCESS", "")
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

	var payload struct {
		domain.Container
		Justification string `json:"justification"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		sendError(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	container := payload.Container
	if err := h.orchestrator.AddContainerToEndpoint(r.Context(), endpointID, &container); err != nil {
		emitAuditLog("CREACION", "Container", container.ContainerID, container.Name, "", payload.Justification, nil, "ERROR", err.Error())
		sendError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	cambios := map[string]auditChange{
		"container_id":     {Despues: container.ContainerID},
		"name":             {Despues: container.Name},
		"state":            {Despues: container.State},
		"image_id":         {Despues: container.ImageID},
		"host_id":          {Despues: endpointID},
		"privileged":       {Despues: container.Privileged},
		"internet_exposed": {Despues: container.InternetExposed},
	}
	if len(container.IPs) > 0 {
		cambios["ips"] = auditChange{Despues: container.IPs}
	}

	emitAuditLog("CREACION", "Container", container.ContainerID, container.Name, "", payload.Justification, cambios, "SUCCESS", "")
	sendJSON(w, map[string]string{"status": "success"}, http.StatusCreated)
}

// PUT /api/containers/{id}
func (h *OrchestratorHandler) UpdateContainer(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")

	var req struct {
		domain.Container
		Justification string `json:"justification"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(w, "JSON inválido: "+err.Error(), http.StatusBadRequest)
		return
	}

	justification := strings.TrimSpace(req.Justification)
	if justification == "" {
		sendError(w, "El campo 'justificación' es obligatorio para modificar el contenedor", http.StatusBadRequest)
		return
	}

	oldCont, _ := h.orchestrator.GetContainerByID(r.Context(), idStr)

	container := req.Container
	container.ContainerID = idStr

	if err := h.orchestrator.UpdateContainer(r.Context(), &container); err != nil {
		emitAuditLog("MODIFICACION", "Container", idStr, container.Name, "", justification, nil, "ERROR", err.Error())
		sendError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	cambios := make(map[string]auditChange)
	if oldCont != nil {
		if oldCont.Name != container.Name && container.Name != "" {
			cambios["name"] = auditChange{Antes: oldCont.Name, Despues: container.Name}
		}
		if oldCont.State != container.State && container.State != "" {
			cambios["state"] = auditChange{Antes: oldCont.State, Despues: container.State}
		}
		if oldCont.ImageID != container.ImageID && container.ImageID != "" {
			cambios["image_id"] = auditChange{Antes: oldCont.ImageID, Despues: container.ImageID}
		}
		if oldCont.InternetExposed != container.InternetExposed {
			cambios["internet_exposed"] = auditChange{Antes: oldCont.InternetExposed, Despues: container.InternetExposed}
		}
		if oldCont.Privileged != container.Privileged {
			cambios["privileged"] = auditChange{Antes: oldCont.Privileged, Despues: container.Privileged}
		}
	}

	emitAuditLog("MODIFICACION", "Container", idStr, container.Name, "", justification, cambios, "SUCCESS", "")
	sendJSON(w, map[string]any{"status": "success", "message": "Contenedor actualizado con éxito"}, http.StatusOK)
}

// DELETE /api/containers/{id}
func (h *OrchestratorHandler) DeleteContainer(w http.ResponseWriter, r *http.Request) {
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
	_ = json.NewEncoder(w).Encode(matrix)
}

// GET /api/cpe/search?query=... o ?q=... o ?vendor=...&product=...&version=...
func (h *OrchestratorHandler) SearchCPE(w http.ResponseWriter, r *http.Request) {
	rawInput := r.URL.Query().Get("query")
	if rawInput == "" {
		rawInput = r.URL.Query().Get("q")
	}

	if rawInput == "" {
		vendor := r.URL.Query().Get("vendor")
		product := r.URL.Query().Get("product")
		version := r.URL.Query().Get("version")
		rawInput = strings.TrimSpace(fmt.Sprintf("%s %s %s", vendor, product, version))
	}

	if rawInput == "" {
		sendJSON(w, []domain.CPEFinalItem{}, http.StatusOK)
		return
	}

	items, err := h.orchestrator.ExecuteCPEPipeline(r.Context(), rawInput)
	if err != nil {
		sendError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	sendJSON(w, items, http.StatusOK)
}


