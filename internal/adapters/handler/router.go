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
	
	/* POST /api/projects: Crea y registra un nuevo proyecto de auditoría. */
	mux.HandleFunc("POST /api/projects", h.CreateProject)
	
	/* POST /api/projects/{id}/endpoints: Asocia un endpoint (host) a un proyecto por su ID. */
	mux.HandleFunc("POST /api/projects/{id}/endpoints", h.AddEndpointToProject)
	
	/* POST /api/endpoints/{id}/hardware: Asocia las especificaciones de hardware a un endpoint. */
	mux.HandleFunc("POST /api/endpoints/{id}/hardware", h.AssociateHardwareToEndpoint)
	
	/* POST /api/endpoints/{id}/networks: Asocia direccionamiento y red a un endpoint. */
	mux.HandleFunc("POST /api/endpoints/{id}/networks", h.AssociateNetworkToEndpoint)
	
	/* POST /api/endpoints/{id}/installations: Registra la instalación de un software en un endpoint. */
	mux.HandleFunc("POST /api/endpoints/{id}/installations", h.RegisterSoftwareInstallation)
	
	/* POST /api/installations/{id}/findings: Genera un hallazgo de seguridad asociado a una instalación de software. */
	mux.HandleFunc("POST /api/installations/{id}/findings", h.GenerateFinding)
	
	/* POST /api/findings/{id}/vuln-remediations: Asocia vulnerabilidades y planes de remediación a un hallazgo. */
	mux.HandleFunc("POST /api/findings/{id}/vuln-remediations", h.AssociateVulnerabilitiesAndRemediations)
	
	/* POST /api/installations/{id}/scan-vulns: Automatiza el escaneo y registro de vulnerabilidades por CPE/versión contra la API del NIST. */
	mux.HandleFunc("POST /api/installations/{id}/scan-vulns", h.ScanSoftwareVulnerabilities)

	/* GET /api/infrastructure: Obtiene el grafo de infraestructura y relaciones. */
	mux.HandleFunc("GET /api/infrastructure", h.GetInfrastructure)
	
	/* GET /api/infrastructure/top-apts: Obtiene los actores de amenazas (APTs) que afectan la infraestructura auditada. */
	mux.HandleFunc("GET /api/infrastructure/top-apts", h.GetTopAPTs)

	return mux
}
