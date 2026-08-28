package ports

import (
	"context"
	"time"

	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/domain"
)

/*
Este archivo define los Puertos (Ports) de entrada y salida para los servicios de la aplicación (vulnerabilidades, exploits y persistencia).

Propósito arquitectónico y teórico:
1. Puertos en Arquitectura Hexagonal: Define las interfaces formales (contratos lógicos) Inbound (de entrada, como handlers o casos de uso) y Outbound (de salida, como repositorios o clientes de APIs externas) que describen qué operaciones ofrece o requiere el núcleo de la aplicación, sin implementar cómo se realizan.
2. Principio de Inversión de Dependencias (DIP): Asegura que el núcleo del negocio (service y domain) dependa de abstracciones de esta capa (ports) y no de detalles concretos de infraestructura de red, HTTP o bases de datos (adapters).
3. Testabilidad mediante Mocks: Permite sustituir en tiempo de pruebas unitarias los componentes de persistencia o APIs externas por implementaciones simuladas que cumplan las firmas de las interfaces.
*/

type EndpointPort interface {
	Save(ctx context.Context, endpoint *domain.Endpoint) error                    // Guarda en la DB
	Update(ctx context.Context, endpoint *domain.Endpoint) error                  // Actualiza en la DB
	GetByID(ctx context.Context, id int64) (*domain.Endpoint, error)              // Te da con el id el objeto recuperado de la bd
	DeleteByID(ctx context.Context, id int64) error                               // Borra un nodo de la BD
	SaveIPs(ctx context.Context, endpointID int64, ips []domain.EndpointIP) error // Reemplaza el conjunto de direcciones IP de un endpoint por las indicadas.
	GetIPs(ctx context.Context, endpointID int64) ([]domain.EndpointIP, error)    // Devuelve las direcciones IP asociadas a un endpoint.
}

type VulnerabilityPort interface {
	Save(ctx context.Context, vuln *domain.Vulnerability) error
	Update(ctx context.Context, vuln *domain.Vulnerability) error
	GetByID(ctx context.Context, cveID string) (*domain.Vulnerability, error)
	DeleteByID(ctx context.Context, cveID string) error
	LinkVulnerabilityToCWEs(ctx context.Context, cveID string, cwes []string) error
	LinkTTPsToVulnerability(ctx context.Context, cveID, cweID string, ttps []string, confidence, source string) error
	GetUnmappedVulnerabilities(ctx context.Context, projectID int64) ([]domain.Vulnerability, error) // projectID=0 → sin filtro (sweep global)
}

type SoftwarePort interface {
	Save(ctx context.Context, software *domain.Software) error
	Update(ctx context.Context, software *domain.Software) error
	GetByID(ctx context.Context, id int64) (*domain.Software, error)
	DeleteByID(ctx context.Context, id int64) error
}

// CPEResolverPort define las operaciones de consulta y validación externa contra la API CPE de NIST NVD.
type CPEResolverPort interface {
	SearchCPECandidates(ctx context.Context, vendor, product, version string) ([]domain.CPESuggestion, error)
	ValidateExactCPE(ctx context.Context, cpeString string) (bool, error)
	FetchNVDProductsByCPEMatch(ctx context.Context, cpeBase string, limit int) ([]domain.NVDProductItem, error)
}

// CPEGuesserPort define la interfaz para realizar búsquedas difusas de prefijos base en CIRCL CPE Guesser.
type CPEGuesserPort interface {
	SearchBaseCPEs(ctx context.Context, tokens []string, topK int) ([]string, error)
}

type FindingPort interface {
	Save(ctx context.Context, finding *domain.Finding) error
	Update(ctx context.Context, finding *domain.Finding) error
	GetByID(ctx context.Context, id int64) (*domain.Finding, error)
	DeleteByID(ctx context.Context, id int64) error

	EnsureForInstallationAndCVE(ctx context.Context, installationID string, cveID string, finding *domain.Finding) (*domain.Finding, bool, error)
	EnsureForContainerImageContextAndCVE(ctx context.Context, containerID string, imageID string, cveID string, finding *domain.Finding) (*domain.Finding, bool, error)
	SupersedeContainerImageFindings(ctx context.Context, containerID string, oldImageID string, changedAt time.Time) (int, error)

	// ApplyRemediationByInstallationAndCVE fija factor y estado en los findings del CVE
	// en esa instalación, y devuelve sus IDs. Con factor 0 pone también risk_score y
	// priority_score a cero: el finding sale de las agregaciones y conservaría si no la
	// última puntuación calculada.
	ApplyRemediationByInstallationAndCVE(ctx context.Context, installationID, cveID string, remediationFactor float64, status string) ([]int64, error)
	GetVulnerabilitiesByFinding(ctx context.Context, findingID any) ([]domain.Vulnerability, error)
}

type RemediationPort interface {
	UpdateFixedVersionByCVE(ctx context.Context, cveID string, fixedVersion string) (int, error)

	// ApplyByInstallationAndCVE sincroniza estado y fecha en las remediaciones del CVE en
	// esa instalación, y devuelve cuántas cambió. appliedAt nulo limpia la fecha.
	ApplyByInstallationAndCVE(ctx context.Context, installationID, cveID, status string, appliedAt *time.Time) (int, error)

	// GetFixedVersionByInstallationAndCVE devuelve la versión corregida que dejó el
	// enriquecimiento desde OSV, o cadena vacía si no consta.
	GetFixedVersionByInstallationAndCVE(ctx context.Context, installationID, cveID string) (string, error)

	Save(ctx context.Context, remediation *domain.Remediation) error
	Update(ctx context.Context, remediation *domain.Remediation) error
	GetByID(ctx context.Context, id int64) (*domain.Remediation, error)
	DeleteByID(ctx context.Context, id int64) error
}

type ExploitPort interface {
	Save(ctx context.Context, exploit *domain.Exploit) error
	Update(ctx context.Context, exploit *domain.Exploit) error
	GetByID(ctx context.Context, id int64) (*domain.Exploit, error)
	DeleteByID(ctx context.Context, id int64) error
}

type HardwarePort interface {
	Save(ctx context.Context, hardware *domain.Hardware) error
	Update(ctx context.Context, hardware *domain.Hardware) error
	GetByID(ctx context.Context, id int64) (*domain.Hardware, error)
	DeleteByID(ctx context.Context, id int64) error
}

type NetworkPort interface {
	Save(ctx context.Context, network *domain.Network) error
	Update(ctx context.Context, network *domain.Network) error
	GetByID(ctx context.Context, id int64) (*domain.Network, error)
	DeleteByID(ctx context.Context, id int64) error
	LinkMatchingEndpoints(ctx context.Context, networkID int64, cidr string, vlanID int64) (int, error)
	LinkEndpointToMatchingNetworks(ctx context.Context, endpointID int64, ips []domain.EndpointIP) (int, error)
	LinkContainerToMatchingNetworks(ctx context.Context, containerID string, ips []domain.EndpointIP) (int, error)
	LinkNetworkToProjectIfOrphan(ctx context.Context, networkID int64, projectID int64) error
}

type PatchPort interface {
	Save(ctx context.Context, patch *domain.Patch) error
	Update(ctx context.Context, patch *domain.Patch) error
	GetByID(ctx context.Context, id int64) (*domain.Patch, error)
	DeleteByID(ctx context.Context, id int64) error

	// GetByURL recupera un parche por su URL, que es su identificador natural y permite
	// deduplicar entre escaneos. Devuelve (nil, nil) si no existe.
	GetByURL(ctx context.Context, url string) (*domain.Patch, error)

	// GetByVulnerability devuelve los parches que corrigen un CVE.
	GetByVulnerability(ctx context.Context, cveID string) ([]domain.Patch, error)

	// SaveApplication crea (Patch)-[:APPLIED_TO]->(SoftwareInstallation). Redeclarar
	// actualiza la arista existente.
	SaveApplication(ctx context.Context, application *domain.AppliedPatch) error

	// GetApplicationsByInstallation devuelve el histórico, del más reciente al más antiguo.
	GetApplicationsByInstallation(ctx context.Context, installationID string) ([]domain.AppliedPatch, error)
}

type ProjectPort interface {
	Save(ctx context.Context, project *domain.Project) error
	Update(ctx context.Context, project *domain.Project) error
	RenameProject(ctx context.Context, id int64, newName string) error
	GetByID(ctx context.Context, id int64) (*domain.Project, error)
	DeleteByID(ctx context.Context, id int64) error
	ExportGraph(ctx context.Context, id int64) (*domain.GraphData, error)
}

type SoftwareInstallationPort interface {
	Save(ctx context.Context, installation *domain.SoftwareInstallation) error
	Update(ctx context.Context, installation *domain.SoftwareInstallation) error
	GetByID(ctx context.Context, id string) (*domain.SoftwareInstallation, error)
	DeleteByID(ctx context.Context, id string) error

	// GetInstalledSoftware recorre (SoftwareInstallation)-[:INSTANCE_OF]->(Software).
	// Devuelve (nil, nil) si la instalación no tiene software asociado.
	GetInstalledSoftware(ctx context.Context, installationID string) (*domain.Software, error)
}

// RelationshipPort abstrae la creación de relaciones entre entidades del dominio
type RelationshipPort interface {
	LinkProjectToEndpoint(ctx context.Context, projectID int64, endpointID int64) error
	LinkEndpointToHardware(ctx context.Context, endpointID int64, hardwareID int64) error
	LinkEndpointToNetwork(ctx context.Context, endpointID int64, networkID int64) error
	LinkEndpointToInstallation(ctx context.Context, endpointID int64, installationID string) error
	LinkContainerToInstallation(ctx context.Context, containerID string, installationID string) error
	LinkInstallationToSoftware(ctx context.Context, installationID string, softwareID int64) error
	LinkInstallationToFinding(ctx context.Context, installationID string, findingID int64) error
	LinkFindingToVulnerability(ctx context.Context, findingID int64, cveID string) error
	LinkFindingToExploit(ctx context.Context, findingID int64, exploitID int64) error
	LinkFindingToRemediation(ctx context.Context, findingID int64, remediationID int64) error
	LinkRemediationToPatch(ctx context.Context, remediationID int64, patchID int64) error
	LinkPatchToVulnerability(ctx context.Context, patchID int64, cveID string) error
}

// DatabaseHelper es un puerto genérico para ejecutar consultas Cypher (Neo4j) que no están
// estrictamente ligadas a un único dominio, permitiendo ingestas dinámicas o consultas puras.
type DatabaseHelper interface {
	ExecuteWrite(ctx context.Context, query string, params map[string]any) error
	ExecuteRead(ctx context.Context, query string, params map[string]any) (any, error)
	GetNodeInfo(ctx context.Context, label string, propertyKey string, propertyValue any) (map[string]any, error)
}

// VulnerabilityAPIscanner escanea vuln de la api del nist (puerto de salida)
type VulnerabilityAPIscanner interface {
	// FetchVulnerabilities obtiene una lista de vulnerabilidades desde el API externa.
	FetchVulnerabilities(ctx context.Context, limit int, offset int) ([]domain.Vulnerability, error)
	// FetchByCPE obtiene las vulnerabilidades asociadas a un CPE específico.
	FetchByCPE(ctx context.Context, cpe string, opts ...domain.VulnerabilityFetchOptions) (*domain.VulnerabilityFetchResult, error)
	// FetchByDate obtiene las vulnerabilidades modificadas en un rango de fechas.
	FetchByDate(ctx context.Context, startDate, endDate time.Time) ([]domain.Vulnerability, error)
	// FetchByCVE obtiene el detalle completo de una vulnerabilidad específica.
	FetchByCVE(ctx context.Context, cve string) (*domain.Vulnerability, error)
}

//Los CRUDS para el mitre... consutarlo con Julve

type TTPPort interface {
	Save(ctx context.Context, ttp *domain.TTP) error
	Update(ctx context.Context, ttp *domain.TTP) error
	GetByID(ctx context.Context, id string) (*domain.TTP, error)
	DeleteByID(ctx context.Context, id string) error
	RelateToVulnerability(ctx context.Context, cveID string, ttpID string) error
	SaveBatch(ctx context.Context, ttps []domain.TTP) error
}

// MitreATTACKProvider obtiene el catálogo MITRE ATT&CK Enterprise desde el feed STIX 2.1.
type MitreATTACKProvider interface {
	FetchATTACKBundle(ctx context.Context) ([]domain.TTP, []domain.ThreatActor, []domain.ThreatActorTTPRelation, error)
}

type TTPMapper interface {
	MapCWEToTTP(ctx context.Context, cwe string) ([]string, error)
	MapEnrichedToTTPRaw(ctx context.Context, cwe, description, cvssVector string) ([]string, string, error)
}

type ThreatActorPort interface {
	Save(ctx context.Context, actor *domain.ThreatActor) error
	Update(ctx context.Context, actor *domain.ThreatActor) error
	GetByID(ctx context.Context, id string) (*domain.ThreatActor, error)
	DeleteByID(ctx context.Context, id string) error
	RelateToTTP(ctx context.Context, actorID string, ttpID string) error
	GetTopThreatActors(ctx context.Context, limit int) ([]domain.ThreatActorThreat, error)
	SaveBatch(ctx context.Context, actors []domain.ThreatActor) error
	SaveRelationshipsBatch(ctx context.Context, relations []domain.ThreatActorTTPRelation) error
}

type InfrastructurePort interface {
	GetGraphData(ctx context.Context) (*domain.GraphData, error)
	GetTopAPTsByInfrastructureTTPs(ctx context.Context, limit int, projectID int64) ([]domain.APTThreatResult, error)
	GetTTPMatrix(ctx context.Context, projectID *int64) ([]domain.TTPMatrixItem, error)
	GetTotalMitreTTPs(ctx context.Context) (int, error)
	GetExploitationPaths(ctx context.Context, projectID int64) ([]domain.ExploitationPath, error)
	// IsAnalysisPending comprueba si hay vulnerabilidades de red pendientes de enriquecimiento en background.
	IsAnalysisPending(ctx context.Context, projectID int64) (bool, error)
	ImportGraphData(ctx context.Context, data *domain.GraphData) error
	GetPaginatedInventory(ctx context.Context, query domain.InventoryQuery) (*domain.PaginatedInventoryResponse, error)
}

// ContainerPort define las operaciones para gestionar imágenes y contenedores.
type ContainerPort interface {
	SaveContainerImage(ctx context.Context, image *domain.ContainerImage) error
	GetContainerImage(ctx context.Context, imageID string) (*domain.ContainerImage, error)
	GetAllContainerImages(ctx context.Context) ([]domain.ContainerImage, error)
	SaveContainer(ctx context.Context, container *domain.Container) error
	GetContainer(ctx context.Context, containerID string) (*domain.Container, error)
	GetContainerIDsByImage(ctx context.Context, imageID string) ([]string, error)
	GetVulnerabilitiesByContainerImage(ctx context.Context, imageID string) ([]domain.Vulnerability, error)
	LinkVulnerabilityToImage(ctx context.Context, imageID string, cveID string) error
	SaveIPs(ctx context.Context, containerID string, ips []domain.EndpointIP) error
}

// ContainerScannerPort define las operaciones para escanear imágenes de contenedores en busca de vulnerabilidades (ej. Docker Scout).
type ContainerScannerPort interface {
	ScanImage(ctx context.Context, imageName string) ([]domain.Vulnerability, error)
}

// EPSSProvider obtiene scores de probabilidad de explotación desde la API FIRST/EPSS.
type EPSSProvider interface {
	FetchEPSS(ctx context.Context, cveIDs []string) (map[string]float64, error)
}

// KEVProvider obtiene el catálogo CISA Known Exploited Vulnerabilities.
type KEVProvider interface {
	FetchKEV(ctx context.Context) (map[string]bool, error)
}

// CAPECProvider obtiene el catálogo MITRE CAPEC desde el feed STIX 2.1.
type CAPECProvider interface {
	FetchCAPECBundle(ctx context.Context) ([]domain.CAPEC, error)
}

// CAPECPort define las operaciones de persistencia para patrones de ataque CAPEC.
type CAPECPort interface {
	Save(ctx context.Context, capec *domain.CAPEC) error
	GetByID(ctx context.Context, id string) (*domain.CAPEC, error)
	LinkCAPECToCWE(ctx context.Context, capecID string, cweID string) error
	LinkCAPECToTTP(ctx context.Context, capecID string, ttpID string) error
	SaveBatch(ctx context.Context, capecs []domain.CAPEC) error
	GetTTPsByCWE(ctx context.Context, cweID string) ([]string, error)
}

// PatchProvider obtiene información de remediación (parches publicados y versiones
// corregidas) de un CVE desde una fuente externa.
//
// Las fuentes no son universales: OSV cubre ecosistemas open source y MSRC cubre
// Microsoft. Cuando la fuente no conoce el CVE, la implementación devuelve (nil, nil)
// en lugar de un error: no encontrarlo es un resultado válido, no un fallo.
type PatchProvider interface {
	FetchPatchInfo(ctx context.Context, cveID string) (*domain.PatchIntelligence, error)
}

// RiskPort agrupa las queries Neo4j específicas del motor de riesgo.
// Se separa de los puertos CRUD para no contaminar el contrato base de cada entidad.
type RiskPort interface {
	// GetFindingContextsByEndpoint recorre Endpoint→Installation→Finding→Vulnerability
	// y devuelve todo lo necesario para calcular el riesgo de cada finding.
	GetFindingContextsByEndpoint(ctx context.Context, endpointID int64) ([]domain.FindingRiskContext, error)

	// GetPatchQueue devuelve los findings pendientes ordenados por prioridad y paginados.
	GetPatchQueue(ctx context.Context, query domain.PatchQueueQuery) (*domain.PatchQueueResponse, error)

	// GetOpenFindingCVEsByProject devuelve los CVEs de findings abiertos de un proyecto.
	GetOpenFindingCVEsByProject(ctx context.Context, projectID int64) ([]string, error)

	// GetEndpointIDsByInstallation devuelve los endpoints que alojan una instalación,
	// directamente o vía contenedor. Inverso de GetInstallationIDsByEndpoint.
	GetEndpointIDsByInstallation(ctx context.Context, installationID string) ([]int64, error)

	// UpdateFindingScores persiste los scores calculados en el nodo Finding.
	UpdateFindingScores(ctx context.Context, findingID int64, impactScore, likelihood, exposureFactor, remediationFactor, riskScore, assetCriticality, urgencyBoost, priorityScore float64) error
	// UpdateEndpointRisk persiste el riesgo agregado en el nodo Endpoint.
	UpdateEndpointRisk(ctx context.Context, endpointID int64, riskScore float64, riskTier string) error

	// GetAllEndpointIDs devuelve los IDs de todos los endpoints para el recálculo diario.
	GetAllEndpointIDs(ctx context.Context) ([]int64, error)

	// GetFindingScoresByInstallation devuelve los scores de riesgo de todos los findings asociados a una instalación de software.
	GetFindingScoresByInstallation(ctx context.Context, installationID string) ([]domain.FindingRiskSummary, error)

	// UpdateSoftwareInstallationRisk actualiza el riesgo agregado de una instalación de software.
	UpdateSoftwareInstallationRisk(ctx context.Context, installationID string, riskScore float64, riskTier string, driverFindingID int64, driverCVEID string) error

	// GetInstallationIDsByEndpoint devuelve los IDs de todas las instalaciones de software asociadas a un endpoint.
	GetInstallationIDsByEndpoint(ctx context.Context, endpointID int64) ([]string, error)

	// UpdateSoftwareInstallationPriority actualiza el score de prioridad de una instalación de software.
	UpdateSoftwareInstallationPriority(ctx context.Context, installationID string, criticalityLevel string, criticalityMultiplier float64, priorityScore float64, priorityTier string) error

	// GetSoftwareCriticalityLevel obtiene el nivel de criticidad de una instalación de software.
	GetSoftwareCriticalityLevel(ctx context.Context, installationID string) (string, error)

	// GetSoftwareRiskSummariesByEndpoint devuelve un resumen de riesgo de software para todas las instalaciones asociadas a un endpoint.
	GetSoftwareRiskSummariesByEndpoint(ctx context.Context, endpointID int64) ([]domain.SoftwareRiskSummary, error)
	GetNativeInstallationIDsByEndpoint(ctx context.Context, endpointID string) ([]string, error)
	GetNativeSoftwareRiskSummariesByEndpoint(ctx context.Context, endpointID string) ([]domain.SoftwareRiskSummary, error)
	GetContainerRiskSummariesByEndpoint(ctx context.Context, endpointID string) ([]domain.ContainerRiskSummary, error)
	UpdateEndpointRiskAndPrioritySummary(ctx context.Context, summary domain.EndpointRiskSummary) error

	// UpdateEndpointRiskAndPriority actualiza el riesgo y la prioridad de un endpoint, incluyendo los drivers técnicos y de prioridad.
	UpdateEndpointRiskAndPriority(ctx context.Context, endpointID int64, riskScore float64, riskTier string, priorityScore float64, priorityTier string, technicalDriverInstallationID string, technicalDriverSoftwareName string, technicalDriverRiskScore float64, technicalDriverCVEID string, priorityDriverInstallationID string, priorityDriverSoftwareName string, priorityDriverPriorityScore float64, priorityDriverCVEID string, riskySoftwareCount int) error

	// GetEndpointIDsByProject devuelve los IDs de todos los endpoints asociados a un proyecto.
	GetEndpointIDsByProject(ctx context.Context, projectID int64) ([]int64, error)

	// GetProjectIDByEndpoint devuelve el ID del proyecto al que pertenece un endpoint.
	GetProjectIDByEndpoint(ctx context.Context, endpointID int64) (int64, error)

	// GetEndpointRiskSummariesByProject devuelve un resumen de riesgo de todos los endpoints asociados a un proyecto.
	GetEndpointRiskSummariesByProject(ctx context.Context, projectID int64) ([]domain.EndpointRiskSummary, error)

	// UpdateProjectRiskAndPriority actualiza el riesgo y la prioridad de un proyecto, incluyendo los drivers técnicos y de prioridad.
	UpdateProjectRiskAndPriority(ctx context.Context, projectID int64, riskScore float64, riskTier string, priorityScore float64, priorityTier string, technicalDriverEndpointID int64, technicalDriverEndpointHostname string, technicalDriverRiskScore float64, technicalDriverSoftwareName string, technicalDriverCVEID string, priorityDriverEndpointID int64, priorityDriverEndpointHostname string, priorityDriverPriorityScore float64, priorityDriverSoftwareName string, priorityDriverCVEID string, riskyEndpointCount int) error

	// GetAllProjectIDs devuelve los IDs de todos los proyectos para el recálculo diario.
	GetAllProjectIDs(ctx context.Context) ([]int64, error)

	// Métodos para agregación de riesgo y hallazgos en contenedores
	GetContainerIDsByEndpoint(ctx context.Context, endpointID int64) ([]string, error)
	GetInstallationIDsByContainer(ctx context.Context, containerID string) ([]string, error)
	GetDirectFindingScoresByContainer(ctx context.Context, containerID string) ([]domain.FindingRiskSummary, error)
	GetSoftwareRiskSummariesByContainer(ctx context.Context, containerID string) ([]domain.SoftwareRiskSummary, error)
	UpdateContainerRiskAndPriority(ctx context.Context, summary domain.ContainerRiskSummary) error
}

// TTPMappedEvent se emite por el worker de TTPs cada vez que una CVE queda mapeada.
// ProjectID = 0 indica origen global (sweep automático, cron, o escaneo sin contexto de proyecto).
type TTPMappedEvent struct {
	CVEID      string   `json:"cve_id"`
	TTPs       []string `json:"ttps"`
	Confidence string   `json:"confidence"`
	Source     string   `json:"source"`
	ProjectID  int64    `json:"project_id"` // 0 = global
	Log        string   `json:"log"`
}

// NotificationPort desacopla el worker de TTPs de cualquier detalle de transporte (WebSocket, SSE, etc.).
// La implementación concreta (WSHub) vive en la capa de adapters/handler.
type NotificationPort interface {
	NotifyTTPMapped(ctx context.Context, event TTPMappedEvent) error
}
