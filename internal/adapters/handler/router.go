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
func NewRouter(h *OrchestratorHandler, hub *WSHub) *http.ServeMux {
	mux := http.NewServeMux()

	// Definición de las rutas RESTful.
	// Aprovecha el nuevo patrón de enrutamiento introducido en Go 1.22+

	/* POST /api/projects: Crea y registra un nuevo proyecto de auditoría. */
	mux.HandleFunc("POST /api/projects", h.CreateProject)

	/* DELETE /api/projects/{id}: Elimina un proyecto y su infraestructura en cascada. */
	mux.HandleFunc("DELETE /api/projects/{id}", h.DeleteProject)

	/* PUT /api/projects/{id}: Renombra un proyecto existente. */
	mux.HandleFunc("PUT /api/projects/{id}", h.RenameProject)

	/* POST /api/projects/{id}/endpoints: Asocia un endpoint (host) a un proyecto por su ID. */
	mux.HandleFunc("POST /api/projects/{id}/endpoints", h.AddEndpointToProject)

	/* POST /api/endpoints/{id}/hardware: Asocia las especificaciones de hardware a un endpoint. */
	mux.HandleFunc("POST /api/endpoints/{id}/hardware", h.AssociateHardwareToEndpoint)

	/* POST /api/networks: Crea una red de forma independiente; el orchestrator enlaza automáticamente los endpoints cuya IP caiga en el CIDR y compartan VLAN. */
	mux.HandleFunc("POST /api/networks", h.CreateNetwork)

	/* POST /api/endpoints/{id}/installations: Registra la instalación de un software en un endpoint. */
	mux.HandleFunc("POST /api/endpoints/{id}/installations", h.RegisterSoftwareInstallation)

	/* POST /api/installations/{id}/findings: Genera un hallazgo de seguridad asociado a una instalación de software. */
	mux.HandleFunc("POST /api/installations/{id}/findings", h.GenerateFinding)

	/* POST /api/findings/{id}/vuln-remediations: Asocia vulnerabilidades y planes de remediación a un hallazgo. */
	mux.HandleFunc("POST /api/findings/{id}/vuln-remediations", h.AssociateVulnerabilitiesAndRemediations)

	/* GET /api/findings/{id}/vulnerabilities: Devuelve los CVEs asociados a un finding, usado por el modal "Ver CVEs" del inspector de nodos. */
	mux.HandleFunc("GET /api/findings/{id}/vulnerabilities", h.GetFindingVulnerabilities)

	/* GET /api/infrastructure: Obtiene el grafo de infraestructura y relaciones. */
	mux.HandleFunc("GET /api/infrastructure", h.GetInfrastructure)

	/* POST /api/infrastructure/import: Importa la declaración de infraestructura desde un JSON. */
	mux.HandleFunc("POST /api/infrastructure/import", h.ImportInfrastructure)

	/* GET /api/projects/{id}/export: Exporta el grafo de infraestructura de un proyecto. */
	mux.HandleFunc("GET /api/projects/{id}/export", h.ExportProject)

	/* GET /api/infrastructure/top-apts: Obtiene los actores de amenazas (APTs) que afectan la infraestructura auditada. */
	mux.HandleFunc("GET /api/infrastructure/top-apts", h.GetTopAPTs)

	/* GET /api/infrastructure/mitre-ttp-count: Obtiene el numero total de TTPs en el catalogo MITRE. */
	mux.HandleFunc("GET /api/infrastructure/mitre-ttp-count", h.GetMitreTTPCount)

	/* GET /api/infrastructure/ttps: Obtiene la matriz de TTPs procesada, opcionalmente filtrada por project_id */
	mux.HandleFunc("GET /api/infrastructure/ttps", h.GetTTPMatrix)

	/* GET /api/infrastructure/ttp-sync-status: Obtiene el estado actual del mapeo de TTPs en segundo plano. */
	mux.HandleFunc("GET /api/infrastructure/ttp-sync-status", h.GetTTPSyncStatus)

	/* GET /api/infrastructure/exploitation-paths: Obtiene las rutas de explotación calculadas en la infraestructura. */
	mux.HandleFunc("GET /api/infrastructure/exploitation-paths", h.GetExploitationPaths)

	/* GET /api/infrastructure/analysis-pending: Polling endpoint para detectar si el enriquecimiento NVD de background ha finalizado. */
	mux.HandleFunc("GET /api/infrastructure/analysis-pending", h.GetAnalysisPending)

	/* POST /api/infrastructure/map-ttps: Inicia manualmente el mapeo (directo e indirecto) de TTPs en background. */
	mux.HandleFunc("POST /api/infrastructure/map-ttps", h.MapTTPsManually)

	/* GET /api/ws/ttps: WebSocket de notificaciones en tiempo real del worker de TTPs.
	   Query param opcional: ?project_id=N para suscripción acotada al proyecto N.
	   Sin query param (o project_id=0): suscripción global (recibe todos los eventos). */
	mux.HandleFunc("GET /api/ws/ttps", hub.ServeWS)

	/* POST /api/installations/{id}/scan-vulns: Automatiza el escaneo y registro de vulnerabilidades por CPE/versión contra la API del NIST. */
	mux.HandleFunc("POST /api/installations/{id}/scan-vulns", h.ScanSoftwareVulnerabilities)

	/* POST /api/installations/{id}/compute-risk: Calcula el riesgo de una instalación de software con datos frescos de EPSS y KEV. */
	mux.HandleFunc("POST /api/installations/{id}/compute-risk", h.ComputeSoftwareInstallationRisk)

	/* POST /api/endpoints/{id}/compute-risk: Calcula el riesgo del endpoint con datos frescos de EPSS y KEV. */
	mux.HandleFunc("POST /api/endpoints/{id}/compute-risk", h.ComputeEndpointRisk)

	/* POST /api/risk/recalculate-all: Recalcula el riesgo de todos los endpoints (trigger manual o cron). */
	mux.HandleFunc("POST /api/risk/recalculate-all", h.ComputeAllRisks)

	// POST /api/projects/{id}/compute-risk: Recalcula el riesgo agregado de un proyecto completo, basado en todos sus endpoints y findings asociados.
	mux.HandleFunc("POST /api/projects/{id}/compute-risk", h.ComputeProjectRisk)

	// POST /api/risk/recalculate-all-projects: Recalcula el riesgo de todos los proyectos (trigger manual o cron).
	mux.HandleFunc("POST /api/risk/recalculate-all-projects", h.ComputeAllProjectsRisk)

	/* GET /api/vulnerabilities/{cve}/patches: Recupera los parches oficiales disponibles para un CVE. */
	mux.HandleFunc("GET /api/vulnerabilities/{cve}/patches", h.GetPatchesForVulnerability)

	/* POST /api/vulnerabilities/{cve}/patches/refresh: Consulta la fuente externa (OSV) y actualiza parches y versión corregida. */
	mux.HandleFunc("POST /api/vulnerabilities/{cve}/patches/refresh", h.RefreshPatchesForVulnerability)

	/* POST /api/installations/{id}/applied-patches: Declara un parche como aplicado sobre la instalación y propaga el efecto al riesgo. */
	mux.HandleFunc("POST /api/installations/{id}/applied-patches", h.DeclarePatchApplied)

	/* GET /api/installations/{id}/applied-patches: Histórico de parches aplicados sobre la instalación. */
	mux.HandleFunc("GET /api/installations/{id}/applied-patches", h.GetAppliedPatchHistory)
	mux.HandleFunc("POST /api/containers/{id}/applied-patches", h.DeclareContainerPatchApplied)
	mux.HandleFunc("GET /api/containers/{id}/applied-patches", h.GetContainerAppliedPatchHistory)

	/* GET /api/patch-queue: Cola de parcheo ordenada por prioridad, opcionalmente filtrada por proyecto. */
	mux.HandleFunc("GET /api/patch-queue", h.GetPatchQueue)

	// Rutas CRUD para Edición y Borrado de Activos
	mux.HandleFunc("GET /api/endpoints/{id}/ips", h.GetEndpointIPs)
	mux.HandleFunc("PUT /api/endpoints/{id}", h.UpdateEndpoint)

	mux.HandleFunc("DELETE /api/endpoints/{id}", h.DeleteEndpoint)
	mux.HandleFunc("PUT /api/networks/{id}", h.UpdateNetwork)
	mux.HandleFunc("DELETE /api/networks/{id}", h.DeleteNetwork)
	mux.HandleFunc("PUT /api/hardware/{id}", h.UpdateHardware)
	mux.HandleFunc("DELETE /api/hardware/{id}", h.DeleteHardware)
	mux.HandleFunc("PUT /api/software/{id}", h.UpdateSoftware)
	mux.HandleFunc("DELETE /api/software/{id}", h.DeleteSoftware)
	mux.HandleFunc("PUT /api/installations/{id}", h.UpdateSoftwareInstallation)
	mux.HandleFunc("DELETE /api/installations/{id}", h.DeleteSoftwareInstallation)

	// Contenedores CRUD
	mux.HandleFunc("POST /api/endpoints/{id}/containers", h.AddContainerToEndpoint)
	mux.HandleFunc("PUT /api/containers/{id}", h.UpdateContainer)
	mux.HandleFunc("DELETE /api/containers/{id}", h.DeleteContainer)
	mux.HandleFunc("POST /api/containers/{id}/installations", h.RegisterContainerSoftwareInstallation)
	mux.HandleFunc("POST /api/containers/images/{id}/scan-vulns", h.ScanContainerImageVulnerabilities)

	mux.HandleFunc("DELETE /api/nodes/{id}", h.DeleteNode)

	/* POST /api/projects/{id}/patches/refresh: Refresca patches y fixed_versions para todos los CVEs abiertos del proyecto. */
	mux.HandleFunc("POST /api/projects/{id}/patches/refresh", h.RefreshProjectPatches)

	// Búsqueda y Autocompletado de CPEs para la UI
	mux.HandleFunc("GET /api/cpe/search", h.SearchCPE)

	/* GET /api/inventory: Devuelve la lista paginada de activos de inventario según filtros y ordenación. */
	mux.HandleFunc("GET /api/inventory", h.GetInventory)

	return mux
}
