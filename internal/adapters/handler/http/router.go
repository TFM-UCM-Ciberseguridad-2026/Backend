package http_handler

import (
	"net/http"
)

// NewRouter crea y configura el multiplexor HTTP con las rutas de la aplicación.
func NewRouter(h *OrchestratorHandler) *http.ServeMux {
	mux := http.NewServeMux()

	// Definición de las rutas RESTful.
	// Aprovecha el nuevo patrón de enrutamiento introducido en Go 1.22+
	mux.HandleFunc("POST /api/projects", h.CreateProject)
	mux.HandleFunc("POST /api/projects/{id}/endpoints", h.AddEndpointToProject)

	mux.HandleFunc("POST /api/endpoints/{id}/hardware", h.AssociateHardwareToEndpoint)
	mux.HandleFunc("POST /api/endpoints/{id}/networks", h.AssociateNetworkToEndpoint)
	mux.HandleFunc("POST /api/endpoints/{id}/installations", h.RegisterSoftwareInstallation)

	mux.HandleFunc("POST /api/installations/{id}/findings", h.GenerateFinding)
	mux.HandleFunc("POST /api/findings/{id}/vuln-remediations", h.AssociateVulnerabilitiesAndRemediations)

	mux.HandleFunc("GET /api/infrastructure", h.GetInfrastructure)
	mux.HandleFunc("POST /api/infrastructure/populate", h.PopulateInfrastructure)
	mux.HandleFunc("GET /api/infrastructure/top-apts", h.GetTopAPTs)

	return mux
}
