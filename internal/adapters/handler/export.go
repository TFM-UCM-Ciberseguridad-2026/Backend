package handler

import (
	"encoding/json"
	"net/http"
	"strconv"
)

// ExportProject exporta todos los nodos y relaciones de un proyecto en formato JSON nativo.
func (h *OrchestratorHandler) ExportProject(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	projectID, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		sendError(w, "ID de proyecto inválido", http.StatusBadRequest)
		return
	}

	exportData, err := h.orchestrator.ExportProjectGraph(r.Context(), projectID)
	if err != nil {
		sendError(w, "Error exportando proyecto: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(exportData); err != nil {
		sendError(w, "Error codificando respuesta JSON: "+err.Error(), http.StatusInternalServerError)
	}
}
