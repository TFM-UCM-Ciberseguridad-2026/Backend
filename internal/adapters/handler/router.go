package handler

import (
	"net/http"
)

/*
Este archivo configura el Enrutador HTTP (ServeMux).

Propósito arquitectónico y teórico:
1. Ubicación en Arquitectura Hexagonal: Se localiza en `internal/adapters/handler`, actuando como el configurador y distribuidor de peticiones HTTP hacia los handlers correspondientes.
2. Multiplexación de Peticiones: Mapea los patrones de rutas y verbos HTTP (sintaxis nativa de Go 1.22+: "METHOD /path/{param}") con sus respectivos controladores de la capa de handlers.
3. Cadena de Filtros (Middleware Chain): Envuelve el enrutador en las funciones decoradoras (CORS, Logger) para aplicarles reglas de seguridad y auditoría global de forma centralizada.
*/
//va a haber una api que se sea /fetch/vuln/endpoint?endpoint=nombreendpoint

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

	return mux
}
