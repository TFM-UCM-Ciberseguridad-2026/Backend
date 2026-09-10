package service

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/domain"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/ports"
)

const autoScanVulnerabilityLimit = 0
const nvdEnrichmentTTL = 6 * time.Hour

/*
Este archivo contiene el Servicio de Aplicación (Application Service) u Orquestador de Casos de Uso.

Propósito arquitectónico y teórico:
1. Ubicación en Arquitectura Hexagonal: Se localiza en `internal/core/service`, actuando como el implementador de los puertos de entrada (inbound ports) y consumidor de los puertos de salida (outbound ports).
2. Núcleo Lógico de la Aplicación: Implementa los casos de uso principales de la lógica de negocio (como el análisis y correlación de vulnerabilidades de equipos mediante CPEs).
3. Coordinación de Dependencias: Recibe los puertos (CVEProvider, ExploitProvider, Database) a través del constructor (Inyección de Dependencias) y orquesta las llamadas necesarias en orden lógico para cumplir con el proceso de negocio.
4. Neutralidad Tecnológica: No expone tipos HTTP ni dependencias de frameworks web, garantizando que las reglas de negocio puedan ser llamadas por un servidor HTTP, un CLI de consola o un proceso de ejecución programada (cron).
*/

type ProjectTTPSyncState struct {
	Processing bool
	CurrentCVE string
	Logs       []string
	QueuedCVEs map[string]bool
}

type TTPBackgroundSyncManager struct {
	mu            sync.RWMutex
	projectStates map[int64]*ProjectTTPSyncState
}

type TTPBackgroundSyncResponse struct {
	Processing  bool     `json:"processing"`
	CurrentCVE  string   `json:"current_cve"`
	QueueLength int      `json:"queue_length"`
	Logs        []string `json:"logs"`
}

// ttpTask agrupa el CVE ID y el project_id del contexto que originó el encolado.
// ProjectID = 0 significa origen global (sweep automático, cron, escaneo sin contexto de proyecto).
type ttpTask struct {
	cveID     string
	projectID int64
}

type Orchestrator struct {
	projectPort         ports.ProjectPort
	endpointPort        ports.EndpointPort
	hardwarePort        ports.HardwarePort
	networkPort         ports.NetworkPort
	softwareInstPort    ports.SoftwareInstallationPort
	softwarePort        ports.SoftwarePort
	findingPort         ports.FindingPort
	vulnPort            ports.VulnerabilityPort
	remediationPort     ports.RemediationPort
	relationshipPort    ports.RelationshipPort
	infraPort           ports.InfrastructurePort
	containerPort       ports.ContainerPort
	patchPort           ports.PatchPort
	dbHelper            ports.DatabaseHelper
	vulnScannerPort     ports.VulnerabilityAPIscanner
	riskPort            ports.RiskPort
	epssProvider        ports.EPSSProvider
	kevProvider         ports.KEVProvider
	scoutPort           ports.ContainerScannerPort
	patchProvider       ports.PatchProvider
	capecPort           ports.CAPECPort
	capecProvider       ports.CAPECProvider
	ttpPort             ports.TTPPort
	mitreAttackProvider ports.MitreATTACKProvider
	activeBgEnrichments int64         // contador atómico de goroutines de enriquecimiento activas
	nvdSyncSem          chan struct{} // semáforo global: limita a 2 llamadas NVD síncronas simultáneas en total
	ttpMapper           ports.TTPMapper
	threatActorPort     ports.ThreatActorPort
	notifier            ports.NotificationPort // nil si no se inyecta
	cpeService          *CPEService
	ttpSync             TTPBackgroundSyncManager
	ttpQueueHigh        chan ttpTask
	ttpQueueLow         chan ttpTask
	CapecReady          chan struct{}
	nodeIDMutex         sync.Mutex
}

func NewOrchestrator(
	projectPort ports.ProjectPort,
	endpointPort ports.EndpointPort,
	hardwarePort ports.HardwarePort,
	networkPort ports.NetworkPort,
	softwareInstPort ports.SoftwareInstallationPort,
	softwarePort ports.SoftwarePort,
	findingPort ports.FindingPort,
	vulnPort ports.VulnerabilityPort,
	remediationPort ports.RemediationPort,
	relationshipPort ports.RelationshipPort,
	infraPort ports.InfrastructurePort,
	containerPort ports.ContainerPort,
	patchPort ports.PatchPort,
	dbHelper ports.DatabaseHelper,
	vulnScannerPort ports.VulnerabilityAPIscanner,
) *Orchestrator {
	return &Orchestrator{
		projectPort:      projectPort,
		endpointPort:     endpointPort,
		hardwarePort:     hardwarePort,
		networkPort:      networkPort,
		softwareInstPort: softwareInstPort,
		softwarePort:     softwarePort,
		findingPort:      findingPort,
		vulnPort:         vulnPort,
		remediationPort:  remediationPort,
		relationshipPort: relationshipPort,
		infraPort:        infraPort,
		containerPort:    containerPort,
		patchPort:        patchPort,
		dbHelper:         dbHelper,
		vulnScannerPort:  vulnScannerPort,
		nvdSyncSem:       make(chan struct{}, 2), // máximo 2 llamadas NVD síncronas en total a la vez
		ttpQueueHigh:     make(chan ttpTask, 1000),
		ttpQueueLow:      make(chan ttpTask, 10000),
		CapecReady:       make(chan struct{}),
		ttpSync: TTPBackgroundSyncManager{
			projectStates: make(map[int64]*ProjectTTPSyncState),
		},
	}
}

// WithCPEResolution inyecta los componentes de resolución CPE e inicializa el CPEService
func (o *Orchestrator) WithCPEResolution(resolver ports.CPEResolverPort) *Orchestrator {
	o.cpeService = NewCPEService(resolver)
	return o
}

// WithCPEService inyecta directamente un CPEService previamente instanciado
func (o *Orchestrator) WithCPEService(cpeService *CPEService) *Orchestrator {
	o.cpeService = cpeService
	return o
}

// WithCPEGuesser inyecta el proveedor de búsqueda difusa cpe-guesser en el CPEService
func (o *Orchestrator) WithCPEGuesser(guesser ports.CPEGuesserPort) *Orchestrator {
	if o.cpeService != nil {
		o.cpeService.WithCPEGuesser(guesser)
	}
	return o
}

// WithRisk inyecta los componentes del motor de riesgo y devuelve el mismo orquestador.
// Permite que el código existente siga usando NewOrchestrator sin cambios.
func (o *Orchestrator) WithRisk(riskPort ports.RiskPort, epss ports.EPSSProvider, kev ports.KEVProvider) *Orchestrator {
	o.riskPort = riskPort
	o.epssProvider = epss
	o.kevProvider = kev
	return o
}

// WithScout inyecta el escáner de contenedores.
func (o *Orchestrator) WithScout(scoutPort ports.ContainerScannerPort) *Orchestrator {
	o.scoutPort = scoutPort
	return o
}

// WithPatchProvider inyecta la fuente externa de información de parches y devuelve el
// mismo orquestador. Igual que WithRisk, se añade como decorador para no alterar la firma
// de NewOrchestrator y no romper el código que ya la usa.
func (o *Orchestrator) WithPatchProvider(patchProvider ports.PatchProvider) *Orchestrator {
	o.patchProvider = patchProvider
	return o
}

// WithCAPEC inyecta el repositorio y proveedor STIX del catálogo CAPEC.
func (o *Orchestrator) WithCAPEC(capecPort ports.CAPECPort, capecProvider ports.CAPECProvider) *Orchestrator {
	o.capecPort = capecPort
	o.capecProvider = capecProvider
	return o
}

// WithTTPMapper inyecta el proveedor de mapeo de TTPs vía LLM.
func (o *Orchestrator) WithTTPMapper(ttpMapper ports.TTPMapper) *Orchestrator {
	o.ttpMapper = ttpMapper
	return o
}

// WithNotifier inyecta el puerto de notificación en tiempo real (ej. WSHub).
// Si no se inyecta, el worker funciona igual pero sin emitir eventos WebSocket.
func (o *Orchestrator) WithNotifier(n ports.NotificationPort) *Orchestrator {
	o.notifier = n
	return o
}

// nextNodeID genera un ID numérico auto-incremental simple para un label dado.
// Reutiliza el mismo patrón que ya usaba el código para Patch en
// AutoScanAndRegisterVulnerabilities, generalizado a cualquier label.
//
// NOTA de concurrencia: no es atómico. Si dos altas del mismo tipo llegan
// exactamente a la vez, ambas podrían leer el mismo max(id) antes de que la
// primera confirme su escritura, resultando en un ID duplicado. Para el
// volumen de esta aplicación es aceptable; si en el futuro hay altas
// concurrentes reales, esto debería migrarse a una secuencia dedicada de
// Neo4j o a UUIDs.
func (o *Orchestrator) nextNodeID(ctx context.Context, label string) (int64, error) {
	o.nodeIDMutex.Lock()
	defer o.nodeIDMutex.Unlock()

	query := fmt.Sprintf("MATCH (n:%s) RETURN coalesce(max(n.id), 0) AS maxId", label)
	res, err := o.dbHelper.ExecuteRead(ctx, query, nil)
	if err != nil {
		return 0, err
	}
	if res == nil {
		return 1, nil
	}
	m, ok := res.(map[string]any)
	if !ok {
		return 1, nil
	}
	if maxID, ok := m["maxId"].(int64); ok {
		return maxID + 1, nil
	}
	if maxIDFloat, ok := m["maxId"].(float64); ok {
		return int64(maxIDFloat) + 1, nil
	}
	return 1, nil
}

// nextInstallationID genera un identificador string único para SoftwareInstallation,
// cuyo ID es de tipo string (no numérico) en el dominio.
func (o *Orchestrator) nextInstallationID() string {
	return fmt.Sprintf("inst-%d-%d", time.Now().UnixNano(), rand.Int31n(10000))
}

// CreateProject guarda el proyecto principal.
func (o *Orchestrator) CreateProject(ctx context.Context, project *domain.Project) error {
	if project.Nombre != "" && o.infraPort != nil {
		if exists, err := o.infraPort.IsProjectNameDuplicate(ctx, project.Nombre, 0); err == nil && exists {
			return fmt.Errorf("Ya existe un proyecto con este nombre. Por favor, elige un nombre único.")
		}
	}

	if project.ProjectID == 0 {
		id, err := o.nextNodeID(ctx, "Project")
		if err != nil {
			return fmt.Errorf("error generando ID de proyecto: %w", err)
		}
		project.ProjectID = id
	}

	return o.projectPort.Save(ctx, project)
}

// DeleteProject elimina un proyecto y su infraestructura asociada en cascada.
func (o *Orchestrator) DeleteProject(ctx context.Context, projectID int64) error {
	return o.projectPort.DeleteByID(ctx, projectID)
}

// RenameProject actualiza el nombre de un proyecto.
func (o *Orchestrator) RenameProject(ctx context.Context, projectID int64, newName string) error {
	newNameTrimmed := strings.TrimSpace(newName)
	if newNameTrimmed == "" {
		return fmt.Errorf("el nombre del proyecto no puede estar vacío")
	}

	if o.infraPort != nil {
		if exists, err := o.infraPort.IsProjectNameDuplicate(ctx, newNameTrimmed, projectID); err == nil && exists {
			return fmt.Errorf("Ya existe un proyecto con este nombre. Por favor, elige un nombre único.")
		}
	}

	return o.projectPort.RenameProject(ctx, projectID, newNameTrimmed)
}

// AddEndpointToProject guarda un nuevo endpoint y lo vincula a un proyecto.
func (o *Orchestrator) AddEndpointToProject(ctx context.Context, projectID int64, endpoint *domain.Endpoint) error {
	if err := o.validateAssetNameUnique(ctx, endpoint.Hostname, endpoint.EndpointID, projectID); err != nil {
		return err
	}

	validIPs, err := o.validateAssetIPs(ctx, projectID, endpoint.IPs, endpoint.EndpointID, "")
	if err != nil {
		return err
	}
	endpoint.IPs = validIPs
	if endpoint.EndpointID == 0 {
		id, err := o.nextNodeID(ctx, "Endpoint")
		if err != nil {
			return fmt.Errorf("error generando ID de endpoint: %w", err)
		}
		endpoint.EndpointID = id
	}

	// La categoría de negocio (puesto o servidor) se congela en el activo al darlo de alta:
	// es la que gobierna el SLA de parcheo y debe quedar fija aunque el mapeo cambie después.
	endpoint.ApplyCategory()

	if err := o.endpointPort.Save(ctx, endpoint); err != nil && !errors.Is(err, domain.ErrNodeAlreadyExists) {
		return err
	}
	if err := o.relationshipPort.LinkProjectToEndpoint(ctx, projectID, endpoint.EndpointID); err != nil {
		return err
	}

	// Persistir las IPs del endpoint (si el formulario envió alguna). Se hace tras
	// tener el EndpointID definitivo, ya que SaveIPs cuelga los nodos :IPAddress de él.
	if len(endpoint.IPs) > 0 {
		if err := o.endpointPort.SaveIPs(ctx, endpoint.EndpointID, endpoint.IPs); err != nil {
			return fmt.Errorf("error guardando IPs del endpoint: %w", err)
		}
	}

	// El emparejamiento se recalcula aunque el endpoint venga sin IPs: si el alta reutiliza
	// un ID que ya existía, quedarse dentro del if dejaría vivas las aristas de las IPs
	// anteriores. Es la misma llamada incondicional que hace UpdateEndpoint.
	if o.networkPort != nil {
		if _, err := o.networkPort.LinkEndpointToMatchingNetworks(ctx, endpoint.EndpointID, endpoint.IPs, projectID); err != nil {
			return fmt.Errorf("error enlazando endpoint a las redes coincidentes: %w", err)
		}
	}

	return nil
}

// AssociateHardwareToEndpoint guarda componentes de hardware y los enlaza a un endpoint.
func (o *Orchestrator) AssociateHardwareToEndpoint(ctx context.Context, endpointID int64, hardware *domain.Hardware) error {
	if err := domain.ValidateAndNormalizeHardware(hardware); err != nil {
		return err
	}

	if hardware.HardwareID == 0 {
		id, err := o.nextNodeID(ctx, "Hardware")
		if err != nil {
			return fmt.Errorf("error generando ID de hardware: %w", err)
		}
		hardware.HardwareID = id
	}

	if err := o.hardwarePort.Save(ctx, hardware); err != nil && !errors.Is(err, domain.ErrNodeAlreadyExists) {
		return err
	}
	return o.relationshipPort.LinkEndpointToHardware(ctx, endpointID, hardware.HardwareID)
}

// CreateNetwork crea una red de forma independiente (sin endpoint asociado explícito) y
// enlaza automáticamente los endpoints cuya IP caiga dentro del CIDR y, si la red define
// VLAN, compartan esa misma VLAN. Si ningún endpoint coincide, ancla la red al proyecto
// indicado como nodo huérfano de ese proyecto en concreto (no aparece en el resto).
// Devuelve el ID de la red creada y cuántos endpoints se enlazaron.
func (o *Orchestrator) CreateNetwork(ctx context.Context, network *domain.Network, projectID int64) (int64, int, error) {
	scope, err := o.validateNetworkUniqueness(ctx, network, projectID, 0)
	if err != nil {
		return 0, 0, err
	}
	if network.NetworkID == 0 {
		id, err := o.nextNodeID(ctx, "Network")
		if err != nil {
			return 0, 0, fmt.Errorf("error generando ID de red: %w", err)
		}
		network.NetworkID = id
	}

	if err := o.networkPort.Save(ctx, network); err != nil && !errors.Is(err, domain.ErrNodeAlreadyExists) {
		return 0, 0, err
	}

	// El ancla al proyecto va ANTES de reconciliar. El ámbito se descubre recorriendo el
	// grafo desde el proyecto, y una red recién guardada todavía no cuelga de él por ningún
	// lado: si se reconciliara primero, la red nueva no entraría en su propio cálculo y no
	// emparejaría con nada.
	if projectID > 0 {
		if err := o.networkPort.LinkNetworkToProjectIfOrphan(ctx, network.NetworkID, projectID); err != nil {
			return network.NetworkID, 0, fmt.Errorf("error anclando la red huérfana al proyecto: %w", err)
		}
	}

	linked, err := o.reconcileNetworkScope(ctx, scope, network.NetworkID)
	if err != nil {
		return network.NetworkID, 0, fmt.Errorf("error enlazando endpoints a la red: %w", err)
	}

	return network.NetworkID, linked, nil
}

// reconcileNetworkScope recalcula el emparejamiento activo↔red y la jerarquía de subredes
// de un ámbito de proyecto, y devuelve cuántos activos quedan colgando de la red indicada.
//
// El recálculo es del ámbito completo, no solo de la red tocada: al declarar una subred más
// específica dentro de un rango que ya tenía activos, esos activos se reasignan a la subred.
// Si solo se recalculara la red nueva se quedarían enganchados también al padre.
func (o *Orchestrator) reconcileNetworkScope(ctx context.Context, scope []int64, networkID int64) (int, error) {
	summary, err := o.networkPort.ReconcileProjectNetworkLinks(ctx, scope)
	if err != nil {
		return 0, err
	}

	// Las reasignaciones se registran porque desde fuera parecen un cambio espontáneo: el
	// usuario crea una /24 y ve moverse activos que él no ha tocado.
	for _, move := range summary.Moves {
		log.Printf("[redes] '%s' reasignado: %v -> %v", move.AssetName, move.From, move.To)
	}

	if networkID <= 0 {
		return 0, nil
	}
	return o.networkPort.CountAssetsInNetwork(ctx, networkID)
}

// ExecuteCPEPipeline ejecuta el pipeline completo de 5 fases para la sugerencia de CPEs
func (o *Orchestrator) ExecuteCPEPipeline(ctx context.Context, rawInput string) ([]domain.CPEFinalItem, error) {
	if o.cpeService != nil {
		return o.cpeService.ExecuteCPEPipeline(ctx, rawInput)
	}
	return []domain.CPEFinalItem{}, nil
}

// SearchCPE busca candidatos a CPE combinando el diccionario de alias en Neo4j y la API NVD
func (o *Orchestrator) SearchCPE(ctx context.Context, vendor, product, version string) ([]domain.CPESuggestion, error) {

	if o.cpeService != nil {
		return o.cpeService.SearchCPE(ctx, vendor, product, version)
	}
	return []domain.CPESuggestion{}, nil
}

// ResolveSoftwareCPE resuelve el CPE adecuado para un software siguiendo la estrategia multinivel
func (o *Orchestrator) ResolveSoftwareCPE(ctx context.Context, software *domain.Software, saveAlias bool) (*domain.CPEMatchResult, error) {
	if o.cpeService != nil {
		return o.cpeService.ResolveSoftwareCPE(ctx, software, saveAlias)
	}
	return &domain.CPEMatchResult{
		CPE:       software.CPE,
		CPEStatus: software.CPEStatus,
	}, nil
}

// RegisterSoftwareInstallation guarda la definición del software, la instancia instalada,
// asocia la instancia al endpoint y el software genérico a la instancia instalada.
func (o *Orchestrator) RegisterSoftwareInstallation(ctx context.Context, endpointID int64, software *domain.Software, installation *domain.SoftwareInstallation) error {
	if strings.TrimSpace(software.Vendor) == "" && strings.TrimSpace(software.CPE) != "" {
		parts := strings.Split(software.CPE, ":")
		if len(parts) >= 4 && parts[3] != "" && parts[3] != "*" {
			software.Vendor = parts[3]
		}
	}
	if strings.TrimSpace(software.Vendor) == "" {
		software.Vendor = "custom"
	}

	// 1. Resolver CPE multinivel y aplicar alias guardados
	_, _ = o.ResolveSoftwareCPE(ctx, software, true)

	if software.SoftwareID == 0 {
		swID, err := o.nextNodeID(ctx, "Software")
		if err != nil {
			return fmt.Errorf("error generando ID de software: %w", err)
		}
		software.SoftwareID = swID
	}

	// 2. Guardar nodo :Software genérico en Neo4j
	if err := o.softwarePort.Save(ctx, software); err != nil && !errors.Is(err, domain.ErrNodeAlreadyExists) {
		return err
	}

	if installation.InstallationID == "" {
		installation.InstallationID = o.nextInstallationID()
	}

	installation.CriticalityLevel = NormalizeSoftwareCriticalityLevel(installation.CriticalityLevel)
	installation.CriticalityMultiplier = CalculateSoftwareCriticalityMultiplier(installation.CriticalityLevel)

	if err := o.softwareInstPort.Save(ctx, installation); err != nil && !errors.Is(err, domain.ErrNodeAlreadyExists) {
		return err
	}
	if err := o.relationshipPort.LinkEndpointToInstallation(ctx, endpointID, installation.InstallationID); err != nil {
		return err
	}
	return o.relationshipPort.LinkInstallationToSoftware(ctx, installation.InstallationID, software.SoftwareID)
}

// RegisterContainerSoftwareInstallation guarda la definición del software, la instancia instalada,
// asocia la instancia al contenedor y el software genérico a la instancia instalada.
func (o *Orchestrator) RegisterContainerSoftwareInstallation(ctx context.Context, containerID string, software *domain.Software, installation *domain.SoftwareInstallation) error {
	if strings.TrimSpace(software.Vendor) == "" && strings.TrimSpace(software.CPE) != "" {
		parts := strings.Split(software.CPE, ":")
		if len(parts) >= 4 && parts[3] != "" && parts[3] != "*" {
			software.Vendor = parts[3]
		}
	}
	if strings.TrimSpace(software.Vendor) == "" {
		software.Vendor = "custom"
	}

	// 1. Resolver CPE multinivel y aplicar alias guardados
	_, _ = o.ResolveSoftwareCPE(ctx, software, true)

	if software.SoftwareID == 0 {
		swID, err := o.nextNodeID(ctx, "Software")
		if err != nil {
			return fmt.Errorf("error generando ID de software: %w", err)
		}
		software.SoftwareID = swID
	}

	// 2. Guardar nodo :Software genérico en Neo4j
	if err := o.softwarePort.Save(ctx, software); err != nil && !errors.Is(err, domain.ErrNodeAlreadyExists) {
		return err
	}

	if installation.InstallationID == "" {

		installation.InstallationID = o.nextInstallationID()
	}

	installation.CriticalityLevel = NormalizeSoftwareCriticalityLevel(installation.CriticalityLevel)
	installation.CriticalityMultiplier = CalculateSoftwareCriticalityMultiplier(installation.CriticalityLevel)

	if err := o.softwareInstPort.Save(ctx, installation); err != nil && !errors.Is(err, domain.ErrNodeAlreadyExists) {
		return err
	}
	if err := o.relationshipPort.LinkContainerToInstallation(ctx, containerID, installation.InstallationID); err != nil {
		return err
	}
	return o.relationshipPort.LinkInstallationToSoftware(ctx, installation.InstallationID, software.SoftwareID)
}

// GenerateFinding registra un hallazgo de vulnerabilidad (Finding) a una instalación específica.
func (o *Orchestrator) GenerateFinding(ctx context.Context, installationID string, finding *domain.Finding) error {
	if strings.TrimSpace(installationID) == "" {
		return fmt.Errorf("installation_id vacío")
	}
	if finding == nil {
		return fmt.Errorf("finding vacío")
	}
	if err := o.findingPort.Save(ctx, finding); err != nil && !errors.Is(err, domain.ErrNodeAlreadyExists) {
		return err
	}
	if finding.FindingID <= 0 {
		return fmt.Errorf("el repositorio no asignó un finding_id válido")
	}
	return o.relationshipPort.LinkInstallationToFinding(ctx, installationID, finding.FindingID)
}

// AssociateVulnerabilitiesAndRemediations guarda la vulnerabilidad (CVE), el parche o mitigación,
// y relaciona ambas partes al finding detectado.
func (o *Orchestrator) AssociateVulnerabilitiesAndRemediations(ctx context.Context, findingID int64, vuln *domain.Vulnerability, rem *domain.Remediation) error {
	if rem.RemediationID == 0 {
		id, err := o.nextNodeID(ctx, "Remediation")
		if err == nil {
			rem.RemediationID = id
		}
	}
	if err := o.saveVulnerabilityWithTTPs(ctx, vuln); err != nil && !errors.Is(err, domain.ErrNodeAlreadyExists) {
		return err
	}
	if err := o.remediationPort.Save(ctx, rem); err != nil && !errors.Is(err, domain.ErrNodeAlreadyExists) {
		return err
	}
	if err := o.relationshipPort.LinkFindingToVulnerability(ctx, findingID, vuln.CVEID); err != nil {
		return err
	}
	go o.StartBackgroundTTPMapping(0) // 0 = sin contexto de proyecto (barrido de novedades tras alta manual)
	return o.relationshipPort.LinkFindingToRemediation(ctx, findingID, rem.RemediationID)
}

// GetInfrastructure recupera el grafo actual de infraestructura del usuario.
// Si la base de datos está vacía (0 nodos), automáticamente la inicializa con el escenario de prueba.
func (o *Orchestrator) GetInfrastructure(ctx context.Context, projectID int64) (*domain.GraphData, error) {
	graph, err := o.infraPort.GetGraphData(ctx, projectID)
	if err != nil {
		return nil, err
	}

	return graph, nil
}

// ImportInfrastructure importa dinámicamente un conjunto de nodos y relaciones al grafo.
func (o *Orchestrator) ImportInfrastructure(ctx context.Context, data *domain.GraphData) error {
	if data == nil {
		return fmt.Errorf("los datos de infraestructura a importar son nulos")
	}
	return o.infraPort.ImportGraphData(ctx, data)
}

// GetTopAPTs obtiene la lista rankeada de Actores de Amenaza (APT) que más TTPs comparten
// con las vulnerabilidades detectadas en la infraestructura del usuario.
func (o *Orchestrator) GetTopAPTs(ctx context.Context, projectID int64) ([]domain.APTThreatResult, error) {
	return o.infraPort.GetTopAPTsByInfrastructureTTPs(ctx, 10, projectID)
}

// GetTotalMitreTTPs obtiene el numero total de TTPs en el catalogo de MITRE.
func (o *Orchestrator) GetTotalMitreTTPs(ctx context.Context) (int, error) {
	return o.infraPort.GetTotalMitreTTPs(ctx)
}

// GetVulnerabilitiesForFinding devuelve los CVEs asociados a un finding concreto. Se usa
// desde el botón "Ver CVEs" del inspector de nodos, ya que los nodos Vulnerability no
// viajan en el grafo general.
func (o *Orchestrator) GetVulnerabilitiesForFinding(ctx context.Context, findingID any) ([]domain.Vulnerability, error) {
	return o.findingPort.GetVulnerabilitiesByFinding(ctx, findingID)
}

func (o *Orchestrator) saveVulnerabilityWithTTPs(ctx context.Context, vuln *domain.Vulnerability) error {
	if err := o.vulnPort.Save(ctx, vuln); err != nil && !errors.Is(err, domain.ErrNodeAlreadyExists) {
		return err
	}
	return nil
}

func isNVDEnrichmentFresh(v domain.Vulnerability) bool {
	if !v.NVDEnriched || v.NVDEnrichedAt == nil {
		return false
	}
	return time.Since(*v.NVDEnrichedAt) <= nvdEnrichmentTTL
}

/*
AutoScanAndRegisterVulnerabilities implementa el caso de uso central para automatizar la detección y registro de
fallos:
1. Recupera la entidad del software a partir de su ID.
2. Si no tiene una cadena CPE válida (o está vacía o es "N/A"), la genera dinámicamente usando el tipo de
software (aplicación, sistema operativo, etc.) y la guarda en la base de datos para futuras referencias.
 3. Invoca el puerto externo VulnerabilityAPIscanner para buscar vulnerabilidades usando el CPE generado.
 4. Para cada vulnerabilidad encontrada, la guarda/actualiza en la base de datos de grafos Neo4j.
 5. Crea o reutiliza un Hallazgo (Finding) para conectar la instalación del software con el CVE detectado:
    SoftwareInstallation -> [:HAS_FINDING] -> Finding -> [:OF_VULNERABILITY] -> Vulnerability.
 6. Devuelve un resumen del escaneo para que el frontend pueda mostrar cuántas vulnerabilidades se encontraron,
    cuántos findings se crearon y cuántos ya existían.
*/
func (o *Orchestrator) AutoScanAndRegisterVulnerabilities(ctx context.Context, installationID string, softwareID int64, opts ...domain.VulnerabilityScanOptions) (*domain.VulnerabilityScanResult, error) {
	// Desacoplar el contexto de la desconexión HTTP del cliente con un timeout amplio de 15 minutos
	scanCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Minute)
	defer cancel()

	scanStartedAt := time.Now().UTC()
	scanOpts := domain.VulnerabilityScanOptions{}
	if len(opts) > 0 {
		scanOpts = opts[0]
	}

	// 1. Obtener la entidad de software
	sw, err := o.softwarePort.GetByID(scanCtx, softwareID)
	if err != nil {
		return nil, fmt.Errorf("no se pudo recuperar el software: %w", err)
	}

	// 2. Si es software interno o no verificado en NVD, omitir consulta a la API de vulnerabilidades
	if sw.CPEStatus == domain.CPEStatusNotInNVD || sw.CPEStatus == domain.CPEStatusPendingConfirmation {

		return &domain.VulnerabilityScanResult{
			InstallationID:       installationID,
			SoftwareID:           softwareID,
			CPE:                  sw.CPE,
			LimitApplied:         0,
			VulnerabilitiesFound: 0,
		}, nil
	}

	// 3. Resolver o generar CPE
	cpe := sw.CPE
	if cpe == "" || cpe == "N/A" {
		cpe = domain.GenerateCPE23(sw.Type, sw.Vendor, sw.Name, sw.Version)
		sw.CPE = cpe

		if err := o.softwarePort.Save(scanCtx, sw); err != nil && !errors.Is(err, domain.ErrNodeAlreadyExists) {
			return nil, fmt.Errorf("error guardando software con CPE generado: %w", err)
		}
	}

	// 3. Determinar el límite de vulnerabilidades a procesar
	limit := autoScanVulnerabilityLimit
	if scanOpts.Limit >= 0 {
		limit = scanOpts.Limit
	}

	// Preparar el resultado detallado del escaneo para API/frontend
	result := &domain.VulnerabilityScanResult{
		InstallationID: installationID,
		SoftwareID:     softwareID,
		CPE:            cpe,
		LimitApplied:   limit,
		ScanStartedAt:  &scanStartedAt,
	}

	// 4. Buscar vulnerabilidades a través del puerto de escaneo
	fetchResult, err := o.vulnScannerPort.FetchByCPE(scanCtx, cpe, domain.VulnerabilityFetchOptions{
		ForceRefresh: scanOpts.ForceRefresh,
	})
	if err != nil {
		return nil, fmt.Errorf("error consultando la API de vulnerabilidades para el CPE %s: %w", cpe, err)
	}
	vulns := fetchResult.Vulnerabilities

	// VulnerabilitiesFound refleja lo devuelto por NVD antes de aplicar el límite local
	result.VulnerabilitiesFound = len(vulns)
	result.TotalAvailable = fetchResult.TotalAvailable
	result.CacheHit = fetchResult.CacheHit
	result.CacheExpiresAt = fetchResult.CacheExpiresAt
	result.ProviderPagesFetched = fetchResult.PagesFetched

	if limit > 0 && len(vulns) > limit {
		vulns = vulns[:limit]
	}
	result.Processed = len(vulns)
	result.Truncated = limit > 0 && result.VulnerabilitiesFound > limit

	// 5. Registrar vulnerabilidades y enlazarlas como hallazgos (Findings)
	for _, v := range vulns {
		vCopy := v
		// Guardar o reutilizar la vulnerabilidad global
		if err := o.vulnPort.Save(ctx, &vCopy); err != nil && !errors.Is(err, domain.ErrNodeAlreadyExists) {
			return nil, fmt.Errorf("error al guardar la vulnerabilidad %s: %w", vCopy.CVEID, err)
		}

		// Guardar los parches si los hay y vincularlos a la vulnerabilidad
		_ = o.RegisterPatchesForVulnerability(ctx, vCopy.CVEID, vCopy.Patches)

		// Crear un Finding inicial solo si no existe ya para installation_id + cve_id
		now := time.Now().UTC()

		finding := &domain.Finding{
			FindingID:         0,
			Status:            "OPEN",
			FirstSeen:         now,
			LastSeen:          &now,
			ImpactScore:       vCopy.BaseScore,
			Likelihood:        0.5,
			RemediationFactor: 1.0,
			RiskScore:         vCopy.BaseScore * 0.5,
		}

		_, created, err := o.findingPort.EnsureForInstallationAndCVE(ctx, installationID, vCopy.CVEID, finding)
		if err != nil {
			return nil, fmt.Errorf("error asegurando finding para instalación %s y CVE %s: %w", installationID, vCopy.CVEID,
				err)
		}

		if created {
			result.FindingsCreated++
		} else {
			result.FindingsExisting++
		}
	}

	// Lanzar barrido inteligente para mapear solo las vulnerabilidades nuevas de este escaneo
	go o.StartBackgroundTTPMapping(0)

	scanCompletedAt := time.Now().UTC()
	result.ScanCompletedAt = &scanCompletedAt
	if err := o.updateSoftwareInstallationScanMetadata(ctx, result, scanStartedAt); err != nil {
		return nil, err
	}

	return result, nil
}

func (o *Orchestrator) updateSoftwareInstallationScanMetadata(ctx context.Context, result *domain.VulnerabilityScanResult, startedAt time.Time) error {
	if o.dbHelper == nil || result == nil {
		return nil
	}

	completedAt := time.Now().UTC()
	if result.ScanCompletedAt != nil {
		completedAt = *result.ScanCompletedAt
	}

	query := `
		MATCH (si:SoftwareInstallation {id: $installation_id})
		SET si.vuln_scan_started_at = $started_at,
		    si.vuln_scan_completed_at = $completed_at,
		    si.vuln_scan_cache_hit = $cache_hit,
		    si.vuln_scan_cpe = $cpe,
		    si.vuln_scan_total_available = $total_available,
		    si.vuln_scan_processed = $processed,
		    si.vuln_scan_pages_fetched = $pages_fetched
	`

	return o.dbHelper.ExecuteWrite(ctx, query, map[string]any{
		"installation_id": result.InstallationID,
		"started_at":      startedAt,
		"completed_at":    completedAt,
		"cache_hit":       result.CacheHit,
		"cpe":             result.CPE,
		"total_available": result.TotalAvailable,
		"processed":       result.Processed,
		"pages_fetched":   result.ProviderPagesFetched,
	})
}

// ComputeEndpointRisk calcula y persiste el riesgo de todos los findings abiertos de un endpoint.
// Flujo:
//  1. Recupera el contexto completo de cada finding (CVSSVector, CIA del endpoint, flags de vuln).
//  2. Obtiene scores EPSS frescos y el catálogo KEV actual de las APIs externas.
//  3. Para cada finding: calcula environmental score, likelihood y risk_score.
//  4. Agrega el riesgo a nivel de endpoint y clasifica el tier.
//  5. Persiste todos los scores en Neo4j.
func (o *Orchestrator) ComputeEndpointRisk(ctx context.Context, endpointID int64) error {
	// 1. Obtener y puntuar los findings activos del endpoint.
	contexts, err := o.riskPort.GetFindingContextsByEndpoint(ctx, endpointID)
	if err != nil {
		return fmt.Errorf("error obteniendo contexto de findings: %w", err)
	}

	cveIDs := make([]string, 0, len(contexts))
	for _, fc := range contexts {
		if fc.CVEID != "" {
			cveIDs = append(cveIDs, fc.CVEID)
		}
	}

	epssScores := map[string]float64{}
	kevCatalog := map[string]bool{}
	if len(cveIDs) > 0 {
		epssScores, err = o.epssProvider.FetchEPSS(ctx, cveIDs)
		if err != nil {
			return fmt.Errorf("error obteniendo scores EPSS: %w", err)
		}
		kevCatalog, err = o.kevProvider.FetchKEV(ctx)
		if err != nil {
			return fmt.Errorf("error obteniendo catálogo KEV: %w", err)
		}
	}

	for _, fc := range contexts {
		// EPSS fresco o default conservador si el CVE aún no tiene score
		epss, found := epssScores[fc.CVEID]
		if !found {
			epss = 0.1
		}

		isKEV := kevCatalog[fc.CVEID] || fc.CachedKEV

		// Impact score: CVSS Environmental (contextualizado con CIA del endpoint)
		impactScore, envErr := domain.CalculateCVSS31EnvironmentalScore(
			fc.CVSSVector, fc.ConfidentialityReq, fc.IntegrityReq, fc.AvailabilityReq,
		)
		if envErr != nil {
			// Vector inválido o vacío: fallback al base score normalizado
			impactScore = fc.CachedBaseScore / 10.0
		}

		likelihood := CalculateLikelihood(isKEV, fc.HasExploit, epss)

		exposureFactor := CalculateExposureFactor(fc.InternetExposed, fc.Environment, fc.CVSSVector)
		riskScore := CalculateFindingRisk(likelihood, exposureFactor, fc.RemediationFactor, impactScore)

		// Para la prioridad de parcheo, necesitamos la criticidad del activo y el boost de urgencia
		assetCriticality := CalculateAssetCriticality(
			fc.InternetExposed,
			fc.Environment,
			fc.ConfidentialityReq,
			fc.IntegrityReq,
			fc.AvailabilityReq,
		)

		urgencyBoost := CalculateUrgencyBoost(
			impactScore,
			isKEV,
			fc.HasExploit,
			fc.PatchAvailable,
		)

		priorityScore := CalculatePriorityScore(riskScore, assetCriticality, urgencyBoost)

		if err := o.riskPort.UpdateFindingScores(
			ctx, fc.FindingID, impactScore, likelihood, exposureFactor, fc.RemediationFactor, riskScore, assetCriticality, urgencyBoost, priorityScore,
			ClassifyRiskTier(riskScore), ClassifyRiskTier(priorityScore),
		); err != nil {
			return fmt.Errorf("error actualizando scores del finding %d: %w", fc.FindingID, err)
		}
	}

	// 2. Recalcular únicamente las instalaciones nativas del endpoint.
	nativeInstallationIDs, err := o.riskPort.GetNativeInstallationIDsByEndpoint(ctx, fmt.Sprint(endpointID))
	if err != nil {
		return fmt.Errorf("error obteniendo instalaciones nativas del endpoint %d: %w", endpointID, err)
	}
	for _, installationID := range nativeInstallationIDs {
		if _, err := o.ComputeSoftwareInstallationRisk(ctx, installationID); err != nil {
			return fmt.Errorf("error recalculando instalación nativa %s del endpoint %d: %w", installationID, endpointID, err)
		}
	}

	// 3. Recalcular todos los contenedores antes de construir el endpoint.
	containerIDs, err := o.riskPort.GetContainerIDsByEndpoint(ctx, endpointID)
	if err != nil {
		return fmt.Errorf("error obteniendo contenedores del endpoint %d: %w", endpointID, err)
	}
	for _, containerID := range containerIDs {
		if _, err := o.ComputeContainerRisk(ctx, containerID); err != nil {
			return fmt.Errorf("error recalculando contenedor %s del endpoint %d: %w", containerID, endpointID, err)
		}
	}

	nativeSummaries, err := o.riskPort.GetNativeSoftwareRiskSummariesByEndpoint(ctx, fmt.Sprint(endpointID))
	if err != nil {
		return fmt.Errorf("error obteniendo resumen de instalaciones nativas del endpoint %d: %w", endpointID, err)
	}
	containerSummaries, err := o.riskPort.GetContainerRiskSummariesByEndpoint(ctx, fmt.Sprint(endpointID))
	if err != nil {
		return fmt.Errorf("error obteniendo resumen de contenedores del endpoint %d: %w", endpointID, err)
	}

	components := make([]domain.AssetRiskSummary, 0, len(nativeSummaries)+len(containerSummaries))
	for _, summary := range nativeSummaries {
		if summary.RiskScore <= 0 && summary.PriorityScore <= 0 {
			continue
		}
		components = append(components, domain.AssetRiskSummary{
			AssetType: "SOFTWARE_INSTALLATION", AssetID: summary.InstallationID, AssetName: summary.SoftwareName,
			RiskScore: clamp(summary.RiskScore, 0, 1), PriorityScore: clamp(summary.PriorityScore, 0, 1),
			DriverFindingID: summary.DriverFindingID, DriverCVEID: summary.DriverCVEID,
			DriverRiskScore: summary.DriverRiskScore, DriverPriorityScore: summary.PriorityScore,
		})
	}
	for _, summary := range containerSummaries {
		if summary.RiskScore <= 0 && summary.PriorityScore <= 0 {
			continue
		}
		components = append(components, domain.AssetRiskSummary{
			AssetType: "CONTAINER", AssetID: summary.ContainerID, AssetName: summary.ContainerName,
			RiskScore: clamp(summary.RiskScore, 0, 1), PriorityScore: clamp(summary.PriorityScore, 0, 1),
			DriverFindingID: summary.TechnicalDriverFindingID, DriverCVEID: summary.TechnicalDriverCVEID,
			DriverRiskScore: summary.TechnicalDriverRiskScore, DriverPriorityScore: summary.PriorityDriverPriorityScore,
		})
	}

	riskScores := make([]float64, 0, len(components))
	priorityScores := make([]float64, 0, len(components))
	for _, component := range components {
		riskScores = append(riskScores, component.RiskScore)
		priorityScores = append(priorityScores, component.PriorityScore)
	}

	endpointRisk := AggregateEndpointRisk(riskScores)
	endpointRiskTier := ClassifyRiskTier(endpointRisk)

	endpointPriority := AggregateEndpointPriority(priorityScores)
	endpointPriorityTier := ClassifyRiskTier(endpointPriority)

	var technicalDriver, priorityDriver domain.AssetRiskSummary
	for _, component := range components {
		if component.RiskScore > technicalDriver.RiskScore {
			technicalDriver = component
		}
		if component.PriorityScore > priorityDriver.PriorityScore {
			priorityDriver = component
		}
	}

	endpointSummary := domain.EndpointRiskSummary{
		EndpointID: endpointID, RiskScore: endpointRisk, RiskTier: endpointRiskTier,
		PriorityScore: endpointPriority, PriorityTier: endpointPriorityTier,
		TechnicalDriverType: technicalDriver.AssetType, TechnicalDriverAssetID: technicalDriver.AssetID,
		TechnicalDriverAssetName: technicalDriver.AssetName, TechnicalDriverRiskScore: technicalDriver.RiskScore,
		PriorityDriverType: priorityDriver.AssetType, PriorityDriverAssetID: priorityDriver.AssetID,
		PriorityDriverAssetName: priorityDriver.AssetName, PriorityDriverPriorityScore: priorityDriver.PriorityScore,
		TechnicalDriverInstallationID: technicalDriver.AssetID,
		TechnicalDriverSoftwareName:   technicalDriver.AssetName,
		PriorityDriverInstallationID:  priorityDriver.AssetID,
		PriorityDriverSoftwareName:    priorityDriver.AssetName,
		RiskySoftwareCount:            len(components),
	}
	if err := o.riskPort.UpdateEndpointRiskAndPrioritySummary(ctx, endpointSummary); err != nil {
		return fmt.Errorf("error persistiendo riesgo del endpoint %d: %w", endpointID, err)
	}

	return nil
}

// ComputeAllEndpointsRisk recalcula el riesgo de todos los endpoints (para el cron diario).
func (o *Orchestrator) ComputeAllEndpointsRisk(ctx context.Context) error {
	ids, err := o.riskPort.GetAllEndpointIDs(ctx)
	if err != nil {
		return fmt.Errorf("error obteniendo IDs de endpoints: %w", err)
	}
	for _, id := range ids {
		if err := o.ComputeEndpointRisk(ctx, id); err != nil {
			return fmt.Errorf("error calculando riesgo del endpoint %d: %w", id, err)
		}
	}
	return nil
}

// Helper para ComputeSoftwareInstallationRisk: encuentra el finding "driver" con mayor riesgo y devuelve su ID y CVE.
func findDriverFinding(summaries []domain.FindingRiskSummary) (int64, string, float64) {
	var driverID int64
	var driverCVE string
	driverScore := 0.0

	for _, summary := range summaries {
		if summary.RiskScore > driverScore {
			driverID = summary.FindingID
			driverCVE = summary.CVEID
			driverScore = summary.RiskScore
		}
	}

	return driverID, driverCVE, driverScore
}

// ComputeSoftwareInstallationRisk recalcula el riesgo agregado de una instalación de software
func (o *Orchestrator) ComputeSoftwareInstallationRisk(ctx context.Context, installationID string) (float64, error) {
	summaries, err := o.riskPort.GetFindingScoresByInstallation(ctx, installationID)
	if err != nil {
		return 0, fmt.Errorf("error obteniendo findings de instalación %s: %w", installationID, err)
	}

	criticalityLevel, err := o.riskPort.GetSoftwareCriticalityLevel(ctx, installationID)
	if err != nil {
		return 0, fmt.Errorf("error obteniendo criticality_level de instalación %s: %w", installationID, err)
	}
	criticalityMultiplier := CalculateSoftwareCriticalityMultiplier(criticalityLevel)

	if len(summaries) == 0 {
		if err := o.riskPort.UpdateSoftwareInstallationRisk(ctx, installationID, 0.0, "LOW", 0, ""); err != nil {
			return 0, err
		}
		if err := o.riskPort.UpdateSoftwareInstallationPriority(ctx, installationID, criticalityLevel, criticalityMultiplier, 0.0, "LOW"); err != nil {
			return 0, err
		}
		return 0.0, nil
	}

	riskScores := make([]float64, 0, len(summaries))
	priorityScores := make([]float64, 0, len(summaries))
	for _, summary := range summaries {
		riskScores = append(riskScores, summary.RiskScore)
		priorityScores = append(priorityScores, summary.PriorityScore)
	}

	softwareRisk := AggregateSoftwareInstallationRisk(riskScores)
	riskTier := ClassifyRiskTier(softwareRisk)
	driverFindingID, driverCVEID, _ := findDriverFinding(summaries)

	priorityBase := AggregateRiskScores(priorityScores)
	softwarePriority := CalculateSoftwarePriorityScore(priorityBase, criticalityMultiplier)
	priorityTier := ClassifyRiskTier(softwarePriority)

	if err := o.riskPort.UpdateSoftwareInstallationRisk(ctx, installationID, softwareRisk, riskTier, driverFindingID, driverCVEID); err != nil {
		return 0, fmt.Errorf("error persistiendo riesgo de instalación %s: %w", installationID, err)
	}

	if err := o.riskPort.UpdateSoftwareInstallationPriority(ctx, installationID, criticalityLevel, criticalityMultiplier, softwarePriority, priorityTier); err != nil {
		return 0, fmt.Errorf("error persistiendo prioridad de instalación %s: %w", installationID, err)
	}

	return softwareRisk, nil
}

// ComputeContainerRisk recalcula y persiste el riesgo y la prioridad agregados de un contenedor.
func (o *Orchestrator) ComputeContainerRisk(ctx context.Context, containerID string) (domain.ContainerRiskSummary, error) {
	container, err := o.containerPort.GetContainer(ctx, containerID)
	if err != nil || container == nil {
		return domain.ContainerRiskSummary{}, fmt.Errorf("contenedor %s no encontrado: %w", containerID, err)
	}

	state := strings.ToLower(container.State)
	// Si el contenedor está detenido/exited, conserva sus findings pero su riesgo operativo es 0.0
	if state != "running" {
		summary := domain.ContainerRiskSummary{
			ContainerID:   container.ContainerID,
			ContainerName: container.Name,
			State:         container.State,
			RiskScore:     0.0,
			RiskTier:      "LOW",
			PriorityScore: 0.0,
			PriorityTier:  "LOW",
		}
		if err := o.riskPort.UpdateContainerRiskAndPriority(ctx, summary); err != nil {
			return domain.ContainerRiskSummary{}, fmt.Errorf("error limpiando riesgo del contenedor %s: %w", containerID, err)
		}
		return summary, nil
	}

	directFindings, err := o.riskPort.GetDirectFindingScoresByContainer(ctx, containerID)
	if err != nil {
		return domain.ContainerRiskSummary{}, fmt.Errorf("error obteniendo findings directos de contenedor %s: %w", containerID, err)
	}

	installationIDs, err := o.riskPort.GetInstallationIDsByContainer(ctx, containerID)
	if err != nil {
		return domain.ContainerRiskSummary{}, fmt.Errorf("error obteniendo instalaciones del contenedor %s: %w", containerID, err)
	}

	for _, installationID := range installationIDs {
		if _, err := o.ComputeSoftwareInstallationRisk(ctx, installationID); err != nil {
			return domain.ContainerRiskSummary{}, fmt.Errorf(
				"error recalculando instalación %s del contenedor %s: %w",
				installationID,
				containerID,
				err,
			)
		}
	}

	swSummaries, err := o.riskPort.GetSoftwareRiskSummariesByContainer(ctx, containerID)
	if err != nil {
		return domain.ContainerRiskSummary{}, fmt.Errorf("error obteniendo software summaries de contenedor %s: %w", containerID, err)
	}

	imageRiskScores := make([]float64, 0, len(directFindings))
	imagePriorityScores := make([]float64, 0, len(directFindings))
	imageID := strings.TrimSpace(container.ImageID)

	for _, df := range directFindings {
		imageRiskScores = append(imageRiskScores, clamp(df.RiskScore, 0.0, 1.0))
		imagePriorityScores = append(imagePriorityScores, clamp(df.PriorityScore, 0.0, 1.0))
	}

	imageRisk := AggregateRiskScores(imageRiskScores)
	imagePriority := AggregateRiskScores(imagePriorityScores)

	type riskComponent struct {
		assetType string
		assetID   string
		assetName string
		riskScore float64
		priority  float64
		findingID int64
		cveID     string
	}
	components := make([]riskComponent, 0, len(swSummaries)+1)
	if imageRisk > 0 {
		components = append(components, riskComponent{
			assetType: "CONTAINER_IMAGE_FINDING",
			assetID:   imageID,
			assetName: container.Name,
			riskScore: imageRisk,
			priority:  imagePriority,
			findingID: directFindings[0].FindingID,
			cveID:     directFindings[0].CVEID,
		})
	}

	riskyInstallationCount := 0
	for _, sw := range swSummaries {
		riskScore := clamp(sw.RiskScore, 0.0, 1.0)
		priorityScore := clamp(sw.PriorityScore, 0.0, 1.0)
		if riskScore <= 0 && priorityScore <= 0 {
			continue
		}
		riskyInstallationCount++
		components = append(components, riskComponent{
			assetType: "SOFTWARE_INSTALLATION",
			assetID:   sw.InstallationID,
			assetName: sw.SoftwareName,
			riskScore: riskScore,
			priority:  priorityScore,
			findingID: sw.DriverFindingID,
			cveID:     sw.DriverCVEID,
		})
	}

	componentRisks := make([]float64, 0, len(components))
	componentPriorities := make([]float64, 0, len(components))
	for _, component := range components {
		componentRisks = append(componentRisks, component.riskScore)
		componentPriorities = append(componentPriorities, component.priority)
	}

	var bestTechType, bestTechAssetID, bestTechAssetName, bestTechCVE string
	var bestTechFindingID int64
	var maxTechRisk float64 = -1

	var bestPrioType, bestPrioAssetID, bestPrioAssetName, bestPrioCVE string
	var bestPrioFindingID int64
	var maxPrioScore float64 = -1

	for _, component := range components {
		if component.riskScore > maxTechRisk {
			maxTechRisk = component.riskScore
			bestTechType = component.assetType
			bestTechAssetID = component.assetID
			bestTechAssetName = component.assetName
			bestTechFindingID = component.findingID
			bestTechCVE = component.cveID
		}
		if component.priority > maxPrioScore {
			maxPrioScore = component.priority
			bestPrioType = component.assetType
			bestPrioAssetID = component.assetID
			bestPrioAssetName = component.assetName
			bestPrioFindingID = component.findingID
			bestPrioCVE = component.cveID
		}
	}

	totalRisk := AggregateRiskScores(componentRisks)
	totalPriority := AggregateRiskScores(componentPriorities)

	summary := domain.ContainerRiskSummary{
		ContainerID:                 container.ContainerID,
		ContainerName:               container.Name,
		State:                       container.State,
		RiskScore:                   totalRisk,
		RiskTier:                    ClassifyRiskTier(totalRisk),
		PriorityScore:               totalPriority,
		PriorityTier:                ClassifyRiskTier(totalPriority),
		TechnicalDriverType:         bestTechType,
		TechnicalDriverAssetID:      bestTechAssetID,
		TechnicalDriverAssetName:    bestTechAssetName,
		TechnicalDriverFindingID:    bestTechFindingID,
		TechnicalDriverCVEID:        bestTechCVE,
		TechnicalDriverRiskScore:    maxTechRisk,
		PriorityDriverType:          bestPrioType,
		PriorityDriverAssetID:       bestPrioAssetID,
		PriorityDriverAssetName:     bestPrioAssetName,
		PriorityDriverFindingID:     bestPrioFindingID,
		PriorityDriverCVEID:         bestPrioCVE,
		PriorityDriverPriorityScore: maxPrioScore,
		RiskyAssetCount:             len(components),
		DirectFindingCount:          len(directFindings),
		RiskyInstallationCount:      riskyInstallationCount,
	}

	if summary.TechnicalDriverRiskScore < 0 {
		summary.TechnicalDriverRiskScore = 0
	}
	if summary.PriorityDriverPriorityScore < 0 {
		summary.PriorityDriverPriorityScore = 0
	}

	if err := o.riskPort.UpdateContainerRiskAndPriority(ctx, summary); err != nil {
		return domain.ContainerRiskSummary{}, fmt.Errorf("error persistiendo riesgo del contenedor %s: %w", containerID, err)
	}

	return summary, nil
}

// SyncNistDaily obtiene las vulnerabilidades modificadas en las últimas 24 horas y actualiza la BBDD.
func (o *Orchestrator) SyncNistDaily(ctx context.Context) error {
	endDate := time.Now().UTC()
	startDate := endDate.Add(-24 * time.Hour)

	vulns, err := o.vulnScannerPort.FetchByDate(ctx, startDate, endDate)
	if err != nil {
		return fmt.Errorf("error sincronizando con NIST: %w", err)
	}

	for _, v := range vulns {
		vCopy := v
		if err := o.saveVulnerabilityWithTTPs(ctx, &vCopy); err != nil && !errors.Is(err, domain.ErrNodeAlreadyExists) {
			continue // Loguear o continuar si una falla
		}

		_ = o.RegisterPatchesForVulnerability(ctx, vCopy.CVEID, vCopy.Patches)
		o.EnqueueCVE(vCopy.CVEID, 0) // 0 = sin contexto de proyecto (cron diario NIST)
	}

	return nil
}

// RegisterPatchesForVulnerability guarda los parches de un CVE y los vincula mediante
// (Patch)-[:FIXES]->(Vulnerability).
//
// Deduplica por URL: la URL publicada por el fabricante es el identificador natural del
// parche, mientras que el PatchID es un secuencial interno. Sin esta comprobación cada
// escaneo crearía un nodo Patch nuevo para el mismo parche, ya que nextNodeID devuelve
// siempre un ID distinto y el MERGE del repositorio va contra el id.
//
// Los errores individuales no abortan el proceso: un parche que falle no debe impedir el
// registro del resto ni el del propio finding.
func (o *Orchestrator) RegisterPatchesForVulnerability(ctx context.Context, cveID string, patches []domain.Patch) error {
	if cveID == "" {
		return fmt.Errorf("cve_id vacío")
	}

	for _, p := range patches {
		pCopy := p

		if pCopy.URL != "" {
			existing, err := o.patchPort.GetByURL(ctx, pCopy.URL)
			if err == nil && existing != nil {
				// El parche ya está en el grafo: reutilizamos su nodo y actualizamos
				// la clasificación para corregir registros creados antes de estos campos.
				pCopy.PatchID = existing.PatchID
				if err := o.patchPort.Update(ctx, &pCopy); err != nil {
					continue
				}
				_ = o.relationshipPort.LinkPatchToVulnerability(ctx, existing.PatchID, cveID)
				continue
			}
		}

		id, err := o.nextNodeID(ctx, "Patch")
		if err != nil {
			continue
		}
		pCopy.PatchID = id

		if err := o.patchPort.Save(ctx, &pCopy); err != nil && !errors.Is(err, domain.ErrNodeAlreadyExists) {
			continue
		}
		_ = o.relationshipPort.LinkPatchToVulnerability(ctx, pCopy.PatchID, cveID)
	}

	return nil
}

// GetPatchesForVulnerability recupera los parches disponibles para un CVE concreto.
func (o *Orchestrator) GetPatchesForVulnerability(ctx context.Context, cveID string) ([]domain.Patch, error) {
	if cveID == "" {
		return nil, fmt.Errorf("cve_id vacío")
	}
	return o.patchPort.GetByVulnerability(ctx, cveID)
}

// resolvePatchLevel deriva el nivel de la evidencia del patch. Manda que haya versión
// corregida, no que el aviso sea del fabricante. Es un techo: el cliente puede declarar
// menos, nunca más.
func (o *Orchestrator) resolvePatchLevel(ctx context.Context, installationID, cveID string, patchID int64, targetVersion string, requested domain.RemediationLevel) (domain.RemediationLevel, error) {
	patch, err := o.patchPort.GetByID(ctx, patchID)
	if err != nil {
		return "", fmt.Errorf("error recuperando el patch %d: %w", patchID, err)
	}
	if patch == nil {
		return "", fmt.Errorf("no existe el patch %d", patchID)
	}

	patches, err := o.patchPort.GetByVulnerability(ctx, cveID)
	if err != nil {
		return "", fmt.Errorf("error comprobando el patch %d para la CVE %s: %w", patchID, cveID, err)
	}

	belongsToCVE := false
	for _, candidate := range patches {
		if candidate.PatchID == patchID {
			belongsToCVE = true
			break
		}
	}
	if !belongsToCVE {
		return "", fmt.Errorf("el patch %d no está asociado a la CVE %s", patchID, cveID)
	}

	ceiling := domain.RemediationLevelUnavailable
	referenceType := strings.ToUpper(strings.TrimSpace(patch.ReferenceType))
	switch {
	case referenceType == "MITIGATION":
		ceiling = domain.RemediationLevelWorkaround
	case patch.Official && fixedVersionIsValid(patch.FixedVersion):
		ceiling = domain.RemediationLevelOfficialFix
	// Sin aval del fabricante hay que comprobar que la instalación sube a la versión.
	case fixedVersionIsValid(patch.FixedVersion):
		if o.versionSatisfiesFix(ctx, installationID, targetVersion, patch.FixedVersion) {
			ceiling = domain.RemediationLevelOfficialFix
		} else {
			ceiling = domain.RemediationLevelWorkaround
		}
	case patch.Official:
		ceiling = domain.RemediationLevelOfficialFix
	}

	return weakerRemediationLevel(requested, ceiling), nil
}

// versionSatisfiesFix comprueba si la versión destino, o la instalada si no se declara,
// alcanza alguna de las corregidas.
func (o *Orchestrator) versionSatisfiesFix(ctx context.Context, installationID, targetVersion, rawFixedVersion string) bool {
	candidate := strings.TrimSpace(targetVersion)
	if idx := strings.LastIndex(candidate, "@"); idx >= 0 {
		candidate = candidate[idx+1:]
	}

	if candidate == "" {
		if strings.TrimSpace(installationID) == "" || o.softwareInstPort == nil {
			return false
		}
		software, err := o.softwareInstPort.GetInstalledSoftware(ctx, installationID)
		if err != nil || software == nil {
			return false
		}
		candidate = strings.TrimSpace(software.Version)
	}
	if candidate == "" {
		return false
	}

	for _, fv := range domain.ParseFixedVersions(rawFixedVersion) {
		if strings.TrimSpace(fv.Version) == "" {
			continue
		}
		if cmp, comparable := domain.CompareVersions(candidate, fv.Version); comparable && cmp >= 0 {
			return true
		}
	}
	return false
}

// weakerRemediationLevel devuelve el de mayor factor, es decir el que menos riesgo retira.
func weakerRemediationLevel(a, b domain.RemediationLevel) domain.RemediationLevel {
	if !a.IsValid() {
		return b
	}
	if RemediationFactorForLevel(a) >= RemediationFactorForLevel(b) {
		return a
	}
	return b
}

func fixedVersionIsValid(raw string) bool {
	for _, fixedVersion := range domain.ParseFixedVersions(raw) {
		version := strings.TrimSpace(fixedVersion.Version)
		if version != "" {
			if _, comparable := domain.CompareVersions(version, version); comparable {
				return true
			}
		}
	}
	return false
}

// DeclarePatchApplied registra un parche aplicado, cierra en cascada todos los findings
// afectados, actualiza la versión del software si procede, reescanea vulnerabilidades
// y recalcula el riesgo de la infraestructura completa.
//
// El nivel determina el factor que multiplica el riesgo: OFFICIAL_FIX 0.00 (el finding
// pasa a PATCHED), TEMPORARY_FIX 0.30, WORKAROUND 0.50 y UNAVAILABLE 1.00, que revierte
// una declaración previa. Solo el parche oficial cierra el finding; una mitigación deja
// el software vulnerable instalado.
//
// La declaración se contrasta con la versión instalada, pero eso nunca la bloquea: hay
// parcheos legítimos que no cambian el número de versión.
//
// Devuelve la declaración persistida y los findings afectados.

func (o *Orchestrator) DeclarePatchApplied(
	ctx context.Context,
	installationID string,
	cveID string,
	patchID int64,
	level domain.RemediationLevel,
	appliedAt time.Time,
	appliedBy string,
	notes string,
	targetVersion string,
) (*domain.AppliedPatch, []int64, error) {
	if installationID == "" {
		return nil, nil, fmt.Errorf("installation_id vacío")
	}
	if cveID == "" {
		return nil, nil, fmt.Errorf("cve_id vacío")
	}
	if appliedAt.IsZero() {
		appliedAt = time.Now().UTC()
	}

	// 1. Obtener TODOS los findings actualmente ABIERTOS en esta instalación
	initialOpenFindings, _ := o.findingPort.GetOpenFindingsByInstallation(ctx, installationID)

	// 2. Resolver o generar patchID si no viene dado
	if patchID == 0 {
		patches, err := o.patchPort.GetByVulnerability(ctx, cveID)
		if err == nil && len(patches) > 0 {
			patchID = patches[0].PatchID
		} else {
			patchID, _ = o.nextNodeID(ctx, "Patch")
		}
	}

	level, err := o.resolvePatchLevel(ctx, installationID, cveID, patchID, targetVersion, level)
	if err != nil {
		return nil, nil, err
	}

	cleanTargetVer := strings.TrimSpace(targetVersion)
	if idx := strings.LastIndex(cleanTargetVer, "@"); idx >= 0 {
		cleanTargetVer = cleanTargetVer[idx+1:]
	}

	if cleanTargetVer == "" && patchID > 0 {
		if patch, patchErr := o.patchPort.GetByID(ctx, patchID); patchErr == nil &&
			patch != nil && patch.FixedVersion != "" {
			fixedVersions := domain.ParseFixedVersions(patch.FixedVersion)
			if len(fixedVersions) > 0 && fixedVersions[0].Version != "" {
				cleanTargetVer = fixedVersions[0].Version
			}
		}
	}

	remediationFactor := RemediationFactorForLevel(level)

	// Mapa acumulativo de CVEs resueltas por esta operación
	resolvedCVEsMap := make(map[string]bool)
	resolvedCVEsMap[cveID] = true

	// 3. Regla A: Comparación de versión semántica (cleanTargetVer >= fixed_version)
	// Se ejecuta siempre que haya una nueva versión, sea oficial o workaround
	if cleanTargetVer != "" {
		for _, oldF := range initialOpenFindings {
			if oldF.FixedVersion != "" {
				fvs := domain.ParseFixedVersions(oldF.FixedVersion)
				for _, fv := range fvs {
					if fv.Version != "" {
						cmp, ok := domain.CompareVersions(cleanTargetVer, fv.Version)
						if ok && cmp > 0 {
							resolvedCVEsMap[oldF.CVEID] = true
							break
						}
					}
				}
			}
		}
	}

	// 4. Actualizar versión en el nodo Software y consultar nuevo CPE en NVD
	// Se ejecuta siempre que haya cleanTargetVer (eliminada la condición que exigía OfficialFix)
	if cleanTargetVer != "" {
		software, err := o.softwareInstPort.GetInstalledSoftware(ctx, installationID)
		if err == nil && software != nil {
			software.Version = cleanTargetVer
			software.CPE = domain.GenerateCPE23(software.Type, software.Vendor, software.Name, cleanTargetVer)

			if updateErr := o.softwarePort.Update(ctx, software); updateErr == nil {
				// Regla B: Comparación diferencial contra el nuevo escaneo de NVD
				fetchResult, fetchErr := o.vulnScannerPort.FetchByCPE(ctx, software.CPE, domain.VulnerabilityFetchOptions{
					ForceRefresh: true,
				})

				if fetchErr == nil && fetchResult != nil {
					newScanCVEs := make(map[string]bool)
					for _, v := range fetchResult.Vulnerabilities {
						newScanCVEs[v.CVEID] = true
					}

					// Cualquier CVE anterior que ya NO esté en el nuevo escaneo se considera resuelto
					for _, oldF := range initialOpenFindings {
						if !newScanCVEs[oldF.CVEID] {
							resolvedCVEsMap[oldF.CVEID] = true
						}
					}
				}
			}
		}
	}

	// 5. Lista consolidada de CVEs resueltas
	resolvedCVEs := make([]string, 0, len(resolvedCVEsMap))
	for cve := range resolvedCVEsMap {
		resolvedCVEs = append(resolvedCVEs, cve)
	}

	status := "OPEN"
	switch level {
	case domain.RemediationLevelOfficialFix:
		status = "PATCHED"
	case domain.RemediationLevelTemporaryFix, domain.RemediationLevelWorkaround:
		status = "MITIGATED"
	case domain.RemediationLevelUnavailable:
		status = "OPEN"
	}

	// 6. Cerrar en bloque todos los findings resueltos en Neo4j
	affectedFindingIDs, err := o.findingPort.CloseResolvedFindingsBatch(
		ctx, installationID, resolvedCVEs, remediationFactor, status,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("error cerrando findings resueltos: %w", err)
	}

	// 7. Persistir en el histórico la relación APPLIED_TO controlando duplicados y convivencia
	existingApps, _ := o.patchPort.GetApplicationsByInstallation(ctx, installationID)
	existingLevelsByCVE := make(map[string][]domain.RemediationLevel)
	for _, a := range existingApps {
		existingLevelsByCVE[a.CVEID] = append(existingLevelsByCVE[a.CVEID], a.RemediationLevel)
	}

	var primaryApplication *domain.AppliedPatch
	for _, resCVE := range resolvedCVEs {
		verification := o.verifyPatchApplication(ctx, installationID, resCVE, level)

		// Si el usuario aplicó una versión destino específica, esa es la versión objetivo real
		if cleanTargetVer != "" {
			verification.ExpectedVersion = cleanTargetVer
		}

		app := &domain.AppliedPatch{
			PatchID:           patchID,
			InstallationID:    installationID,
			CVEID:             resCVE,
			AppliedAt:         appliedAt.UTC(),
			AppliedBy:         appliedBy,
			RemediationLevel:  level,
			RemediationFactor: remediationFactor,
			Notes:             notes,
			Verification:      verification,
		}

		shouldAddToHistory := true
		if levels, exists := existingLevelsByCVE[resCVE]; exists && len(levels) > 0 {
			hasOfficial := false
			hasTemporary := false
			for _, l := range levels {
				if l == domain.RemediationLevelOfficialFix {
					hasOfficial = true
				}
				if l == domain.RemediationLevelTemporaryFix || l == domain.RemediationLevelWorkaround {
					hasTemporary = true
				}
			}

			if hasOfficial {
				// Si la existente es OFFICIAL_FIX, no se añade la nueva
				shouldAddToHistory = false
			} else if hasTemporary && level == domain.RemediationLevelOfficialFix {
				// Si la existente es TEMPORARY_FIX y la nueva es OFFICIAL_FIX, sí se añade (conviven ambas)
				shouldAddToHistory = true
			} else {
				// Si la existente es TEMPORARY_FIX y la nueva es TEMPORARY_FIX (o ya existe), no se añade
				shouldAddToHistory = false
			}
		}

		if shouldAddToHistory {
			_ = o.patchPort.SaveApplication(ctx, app)
			existingLevelsByCVE[resCVE] = append(existingLevelsByCVE[resCVE], level)
		}

		var remAppliedAt *time.Time
		if level != domain.RemediationLevelUnavailable {
			remAppliedAt = &appliedAt
		}
		_, _ = o.remediationPort.ApplyByInstallationAndCVE(
			ctx, installationID, resCVE, level.RemediationStatus(), remAppliedAt,
		)

		if resCVE == cveID {
			primaryApplication = app
		}
	}

	if primaryApplication == nil && len(resolvedCVEs) > 0 {
		primaryApplication = &domain.AppliedPatch{
			PatchID:        patchID,
			InstallationID: installationID,
			CVEID:          cveID,
			AppliedAt:      appliedAt.UTC(),
		}
	}

	// 8. Re-escanear para asegurar que las nuevas vulnerabilidades de la nueva versión queden registradas
	if cleanTargetVer != "" {
		if sw, err := o.softwareInstPort.GetInstalledSoftware(ctx, installationID); err == nil && sw != nil {
			_, _ = o.AutoScanAndRegisterVulnerabilities(ctx, installationID, sw.SoftwareID, domain.VulnerabilityScanOptions{
				ForceRefresh: true,
			})
		}
	}

	// 9. Recalcular riesgo completo para los endpoints afectados y el proyecto
	_ = o.recomputeRiskForInstallation(ctx, installationID)

	return primaryApplication, affectedFindingIDs, nil
}

// GetAppliedPatchHistoryByEndpoint obtiene el histórico de parches de un endpoint estructurado por software.
func (o *Orchestrator) GetAppliedPatchHistoryByEndpoint(ctx context.Context, endpointID int64) (*domain.EndpointPatchHistory, error) {
	if endpointID <= 0 {
		return nil, fmt.Errorf("endpointID inválido")
	}
	return o.patchPort.GetAppliedPatchHistoryByEndpoint(ctx, endpointID)
}

// DeclarePatchAppliedToContainer declara la remediación únicamente sobre el finding
// contextual seleccionado del contenedor. La imagen compartida no se modifica.
func (o *Orchestrator) DeclarePatchAppliedToContainer(
	ctx context.Context, containerID, cveID string, findingID, patchID int64,
	level domain.RemediationLevel, appliedAt time.Time, appliedBy, notes string,
) (*domain.AppliedPatch, []int64, error) {
	if strings.TrimSpace(containerID) == "" {
		return nil, nil, fmt.Errorf("container_id vacío")
	}
	if strings.TrimSpace(cveID) == "" {
		return nil, nil, fmt.Errorf("cve_id vacío")
	}
	if findingID <= 0 {
		return nil, nil, fmt.Errorf("finding_id debe ser positivo")
	}
	if !level.IsValid() {
		return nil, nil, fmt.Errorf("nivel de remediación no reconocido: %q", level)
	}
	if appliedAt.IsZero() {
		appliedAt = time.Now().UTC()
	}
	if patchID == 0 {
		patches, err := o.patchPort.GetByVulnerability(ctx, cveID)
		if err != nil {
			return nil, nil, fmt.Errorf("error recuperando parches de %s: %w", cveID, err)
		}
		if len(patches) == 0 {
			return nil, nil, fmt.Errorf("no hay ningún parche registrado para %s", cveID)
		}
		if len(patches) > 1 {
			return nil, nil, fmt.Errorf("hay %d parches registrados para %s: indica patch_id", len(patches), cveID)
		}
		patchID = patches[0].PatchID
	}

	// El contenedor no expone instalación ni versión destino: sin comprobación de versión.
	level, err := o.resolvePatchLevel(ctx, "", cveID, patchID, "", level)
	if err != nil {
		return nil, nil, err
	}

	factor := RemediationFactorForLevel(level)
	status := "OPEN"
	if level == domain.RemediationLevelOfficialFix {
		status = "PATCHED"
	}
	if level == domain.RemediationLevelTemporaryFix || level == domain.RemediationLevelWorkaround {
		status = "MITIGATED"
	}
	application := &domain.AppliedPatch{
		PatchID: patchID, AssetType: "CONTAINER", AssetID: containerID, ContainerID: containerID,
		FindingID: findingID, CVEID: cveID, AppliedAt: appliedAt.UTC(), AppliedBy: appliedBy,
		RemediationLevel: level, RemediationFactor: factor, Notes: notes,
		Verification: domain.PatchVerification{Reason: domain.VerificationNotApplicable},
	}

	// Comprobar histórico del contenedor para evitar duplicados
	existingApps, _ := o.patchPort.GetApplicationsByContainer(ctx, containerID)
	shouldAddToHistory := true
	if len(existingApps) > 0 {
		hasOfficial := false
		hasTemporary := false
		for _, prevApp := range existingApps {
			if prevApp.CVEID == cveID {
				if prevApp.RemediationLevel == domain.RemediationLevelOfficialFix {
					hasOfficial = true
				}
				if prevApp.RemediationLevel == domain.RemediationLevelTemporaryFix || prevApp.RemediationLevel == domain.RemediationLevelWorkaround {
					hasTemporary = true
				}
			}
		}

		if hasOfficial {
			shouldAddToHistory = false
		} else if hasTemporary && level == domain.RemediationLevelOfficialFix {
			shouldAddToHistory = true
		} else if hasTemporary {
			shouldAddToHistory = false
		}
	}

	if shouldAddToHistory {
		if err := o.patchPort.SaveApplication(ctx, application); err != nil {
			return nil, nil, fmt.Errorf("error declarando remediación del contenedor %s: %w", containerID, err)
		}
	}

	affected, err := o.findingPort.ApplyRemediationByContainerAndCVE(ctx, containerID, cveID, findingID, factor, status)
	if err != nil {
		return nil, nil, fmt.Errorf("error actualizando finding %d del contenedor %s: %w", findingID, containerID, err)
	}
	if len(affected) != 1 || affected[0] != findingID {
		return nil, affected, fmt.Errorf("el finding %d no pertenece al contenedor %s y al CVE %s", findingID, containerID, cveID)
	}
	var remediationAt *time.Time
	if level != domain.RemediationLevelUnavailable {
		value := application.AppliedAt
		remediationAt = &value
	}
	if _, err := o.remediationPort.ApplyByContainerAndCVE(ctx, containerID, cveID, findingID, level.RemediationStatus(), remediationAt); err != nil {
		return nil, affected, fmt.Errorf("error sincronizando remediación contextual del finding %d: %w", findingID, err)
	}
	if o.riskPort == nil {
		return application, affected, nil
	}
	if _, err := o.ComputeContainerRisk(ctx, containerID); err != nil {
		return application, affected, fmt.Errorf("remediación guardada, pero falló el riesgo del contenedor %s: %w", containerID, err)
	}
	endpointID, err := o.riskPort.GetEndpointIDByContainer(ctx, containerID)
	if err != nil {
		return application, affected, fmt.Errorf("falló localización del endpoint del contenedor %s: %w", containerID, err)
	}
	if endpointID == 0 {
		return application, affected, nil
	}
	if err := o.ComputeEndpointRisk(ctx, endpointID); err != nil {
		return application, affected, fmt.Errorf("falló recálculo del endpoint %d: %w", endpointID, err)
	}
	projectID, err := o.riskPort.GetProjectIDByEndpoint(ctx, endpointID)
	if err != nil {
		return application, affected, fmt.Errorf("falló localización del proyecto del endpoint %d: %w", endpointID, err)
	}
	if projectID != 0 {
		if err := o.AggregateProjectRiskFromCurrentEndpointScores(ctx, projectID); err != nil {
			return application, affected, fmt.Errorf("falló recálculo del proyecto %d: %w", projectID, err)
		}
	}
	return application, affected, nil
}

// verifyPatchApplication contrasta la declaración con la versión instalada. No devuelve
// error: es informativa, así que los fallos se traducen a un motivo.
func (o *Orchestrator) verifyPatchApplication(
	ctx context.Context,
	installationID, cveID string,
	level domain.RemediationLevel,
) domain.PatchVerification {
	// Una mitigación no cambia la versión instalada, así que compararla sería ruido.
	if !level.FullyRemediates() {
		return domain.PatchVerification{Reason: domain.VerificationNotApplicable}
	}

	software, err := o.softwareInstPort.GetInstalledSoftware(ctx, installationID)
	if err != nil || software == nil {
		return domain.PatchVerification{Reason: domain.VerificationNoInstalledVersion}
	}

	rawFixedVersion, err := o.remediationPort.GetFixedVersionByInstallationAndCVE(ctx, installationID, cveID)
	if err != nil {
		return domain.PatchVerification{
			Reason:           domain.VerificationNoFixedVersion,
			InstalledVersion: software.Version,
		}
	}

	return domain.VerifyInstalledVersion(
		software.Name,
		software.Version,
		domain.ParseFixedVersions(rawFixedVersion),
	)
}

// recomputeRiskForInstallation recalcula el riesgo de los endpoints que alojan una
// instalación, directamente o vía contenedor.
func (o *Orchestrator) recomputeRiskForInstallation(ctx context.Context, installationID string) error {
	if o.riskPort == nil {
		return fmt.Errorf("el motor de riesgo no está configurado")
	}

	endpointIDs, err := o.riskPort.GetEndpointIDsByInstallation(ctx, installationID)
	if err != nil {
		return fmt.Errorf("error localizando los endpoints de la instalación %s: %w", installationID, err)
	}

	for _, endpointID := range endpointIDs {
		if err := o.ComputeEndpointRisk(ctx, endpointID); err != nil {
			return fmt.Errorf("error recalculando el riesgo del endpoint %d: %w", endpointID, err)
		}
		// Recalcular también el riesgo agregado del proyecto
		projectID, pErr := o.riskPort.GetProjectIDByEndpoint(ctx, endpointID)
		if pErr == nil && projectID != 0 {
			_ = o.AggregateProjectRiskFromCurrentEndpointScores(ctx, projectID)
		}
	}

	return nil
}

// defaultPatchQueueLimit acota la cola cuando el cliente no pide un tamaño.
const defaultPatchQueueLimit = 50

// matchesTokenOrSubstr verifica coincidencia entre target (ej: name/cpeProduct) y pkg/artifact.
// Evita falsos positivos con palabras cortas (ej. "go" en "django" o "cat" en "concat").
func matchesTokenOrSubstr(target, str string) bool {
	if target == "" || str == "" {
		return false
	}
	if target == str || strings.Contains(str, target) {
		// Para cadenas cortas (<= 3 caracteres), exigimos coincidencia por token delimitado (-, _, ., :, /, @)
		if len(target) <= 3 {
			for _, part := range strings.FieldsFunc(str, func(r rune) bool {
				return r == '-' || r == '_' || r == '.' || r == ':' || r == '/' || r == '@'
			}) {
				if part == target {
					return true
				}
			}
			return false
		}
		return true
	}
	return false
}

// matchesSoftwarePackage evalúa si un nombre de paquete coincide con el software, vendor o CPE indicados.
func matchesSoftwarePackage(packageName, swName, swVendor, swCPE string) bool {
	if packageName == "" {
		return true
	}
	pkg := strings.ToLower(strings.TrimSpace(packageName))
	name := strings.ToLower(strings.TrimSpace(swName))
	vendor := strings.ToLower(strings.TrimSpace(swVendor))
	cpe := strings.ToLower(strings.TrimSpace(swCPE))

	// Si el paquete tiene formato Maven/Java (group:artifact) o NPM (@scope/pkg), extraemos el artefacto
	artifact := pkg
	if idx := strings.Index(pkg, ":"); idx >= 0 {
		artifact = pkg[idx+1:]
	} else if idx := strings.Index(pkg, "/"); idx >= 0 && strings.HasPrefix(pkg, "@") {
		artifact = pkg[idx+1:]
	}

	// 1. Coincidencia directa por artefacto / nombre de producto
	if name != "" {
		if matchesTokenOrSubstr(name, artifact) || matchesTokenOrSubstr(artifact, name) ||
			matchesTokenOrSubstr(name, pkg) || matchesTokenOrSubstr(pkg, name) {
			return true
		}
		// Manejo especial de demonio HTTP (httpd vs http_server vs apache2)
		if (name == "http_server" || name == "apache" || name == "httpd") &&
			(artifact == "httpd" || strings.HasPrefix(artifact, "httpd") || artifact == "apache2") {
			return true
		}
	}

	// 2. Coincidencia por CPE (extrae proveedor y producto del CPE cpe:2.3:part:vendor:product:...)
	if strings.HasPrefix(cpe, "cpe:2.3:") {
		parts := strings.Split(cpe, ":")
		if len(parts) >= 5 {
			cpeProduct := parts[4]
			if cpeProduct != "" && cpeProduct != "*" {
				if matchesTokenOrSubstr(cpeProduct, artifact) || matchesTokenOrSubstr(artifact, cpeProduct) ||
					matchesTokenOrSubstr(cpeProduct, pkg) || matchesTokenOrSubstr(pkg, cpeProduct) {
					return true
				}
				if (cpeProduct == "http_server") && (artifact == "httpd" || strings.HasPrefix(artifact, "httpd") || artifact == "apache2") {
					return true
				}
			}
		}
	}

	// 3. Coincidencia por Vendor solo si no es un umbrella vendor genérico (como "apache", "oracle", "microsoft", "google", "redhat", "debian", "canonical")
	// o si el vendor coincide en paquetes del SO simples (como "apache2" para vendor "apache")
	isGenericUmbrella := vendor == "apache" || vendor == "oracle" || vendor == "microsoft" ||
		vendor == "google" || vendor == "redhat" || vendor == "debian" || vendor == "canonical"
	if len(vendor) > 2 && matchesTokenOrSubstr(vendor, pkg) {
		if !isGenericUmbrella {
			return true
		}
		// Para umbrella vendors como "apache", sólo aceptar paquetes simples de SO sin ":" o "/" (ej: apache2, apache-httpd)
		if !strings.Contains(pkg, ":") && !strings.Contains(pkg, "/") {
			return true
		}
	}

	return false
}

// FilterFixedVersionForSoftware filtra una cadena de fixed_versions separadas por coma,
// reteniendo únicamente aquellas que corresponden al software, vendor o CPE del ítem.
func FilterFixedVersionForSoftware(rawFixedVersion, currentVersion, swName, swVendor, swCPE string) string {
	if strings.TrimSpace(rawFixedVersion) == "" {
		return ""
	}

	entries := strings.Split(rawFixedVersion, ",")
	validEntries := make([]string, 0, len(entries))

	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		packageName := ""
		if idx := strings.LastIndex(entry, "@"); idx >= 0 {
			packageName = strings.TrimSpace(entry[:idx])
		}

		if matchesSoftwarePackage(packageName, swName, swVendor, swCPE) {
			validEntries = append(validEntries, entry)
		}
	}

	return strings.Join(validEntries, ", ")
}

// GetPatchQueue devuelve los findings pendientes ordenados por prioridad de parcheo con soporte para filtrado avanzado, ordenación y paginación.
func (o *Orchestrator) GetPatchQueue(ctx context.Context, query domain.PatchQueueQuery) (*domain.PatchQueueResponse, error) {
	if o.riskPort == nil {
		return nil, fmt.Errorf("el motor de riesgo no está configurado")
	}
	if query.Page <= 0 {
		query.Page = 1
	}
	if query.Limit <= 0 {
		query.Limit = 20
	}

	resp, err := o.riskPort.GetPatchQueue(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("error obteniendo la cola de parcheo: %w", err)
	}

	for i := range resp.Queue {
		resp.Queue[i].PriorityTier = ClassifyRiskTier(resp.Queue[i].PriorityScore)
		resp.Queue[i].FixedVersion = FilterFixedVersionForSoftware(
			resp.Queue[i].FixedVersion,
			resp.Queue[i].SoftwareVersion,
			resp.Queue[i].SoftwareName,
			resp.Queue[i].SoftwareVendor,
			resp.Queue[i].SoftwareCPE,
		)
	}
	return resp, nil
}

// GetAppliedPatchHistory devuelve el histórico de parches aplicados sobre una instalación,
// del más reciente al más antiguo.
func (o *Orchestrator) GetAppliedPatchHistory(ctx context.Context, installationID string) ([]domain.AppliedPatch, error) {
	if installationID == "" {
		return nil, fmt.Errorf("installation_id vacío")
	}
	return o.patchPort.GetApplicationsByInstallation(ctx, installationID)
}

func (o *Orchestrator) GetAppliedPatchHistoryByContainer(ctx context.Context, containerID string) ([]domain.AppliedPatch, error) {
	if strings.TrimSpace(containerID) == "" {
		return nil, fmt.Errorf("container_id vacío")
	}
	return o.patchPort.GetApplicationsByContainer(ctx, containerID)
}

// EnrichPatchesFromProvider consulta la fuente externa de parches para un CVE, registra
// los parches encontrados y propaga la versión corregida a sus remediaciones.
//
// Devuelve (nil, nil) cuando la fuente no cubre el CVE: OSV solo agrega ecosistemas open
// source, así que un CVE de software propietario no tiene por qué estar. No es un error.
//
// Cuando el CVE se corrige en varias versiones (ramas mantenidas en paralelo, como
// Log4Shell en 2.3.1 / 2.12.2 / 2.15.0) se persisten todas separadas por coma: sin conocer
// la rama del software instalado no podemos elegir una, y descartar el resto perdería
// información necesaria para calcular el salto de versión.
func (o *Orchestrator) EnrichPatchesFromProvider(ctx context.Context, cveID string) (*domain.PatchIntelligence,
	error) {
	if cveID == "" {
		return nil, fmt.Errorf("cve_id vacío")
	}
	if o.patchProvider == nil {
		return nil, fmt.Errorf("no hay ningún PatchProvider configurado")
	}

	info, err := o.patchProvider.FetchPatchInfo(ctx, cveID)
	if err != nil {
		return nil, fmt.Errorf("error consultando la fuente de parches para %s: %w", cveID, err)
	}
	if info == nil {
		return nil, nil
	}

	if len(info.Patches) == 0 && len(info.FixedVersions) > 0 {
		if synthetic := syntheticPatchFromFixedVersions(cveID, info.FixedVersions); synthetic != nil {
			info.Patches = append(info.Patches, *synthetic)
		}
	}

	if len(info.Patches) > 0 {
		if err := o.RegisterPatchesForVulnerability(ctx, cveID, info.Patches); err != nil {
			return nil, fmt.Errorf("error registrando los parches de %s: %w", cveID, err)
		}

		// Releemos del grafo para devolver los parches tal y como han quedado
		// persistidos, con su PatchID asignado. Los que vienen del provider lo tienen
		// a 0 y devolverlos así daría una respuesta engañosa.
		persisted, err := o.patchPort.GetByVulnerability(ctx, cveID)
		if err != nil {
			return nil, fmt.Errorf("error releyendo los parches de %s: %w", cveID, err)
		}
		info.Patches = persisted
	}

	if len(info.FixedVersions) > 0 {
		formatted := make([]string, 0, len(info.FixedVersions))
		for _, fv := range info.FixedVersions {
			formatted = append(formatted, fv.String())
		}
		fixedVersion := strings.Join(formatted, ", ")
		if _, err := o.remediationPort.UpdateFixedVersionByCVE(ctx, cveID, fixedVersion); err != nil {
			return nil, fmt.Errorf("error propagando la versión corregida de %s: %w", cveID, err)
		}
	}

	return info, nil
}

// findDriverSoftwareByRisk encuentra la instalación de software con mayor riesgo agregado
func findDriverSoftwareByRisk(summaries []domain.SoftwareRiskSummary) (domain.SoftwareRiskSummary, bool) {
	var driver domain.SoftwareRiskSummary
	found := false
	for _, summary := range summaries {
		if !found || summary.RiskScore > driver.RiskScore {
			driver = summary
			found = true
		}
	}
	return driver, found
}

// findDriverFindingByRisk encuentra el finding con mayor riesgo agregado
func findDriverSoftwareByPriority(summaries []domain.SoftwareRiskSummary) (domain.SoftwareRiskSummary, bool) {
	var driver domain.SoftwareRiskSummary
	found := false
	for _, summary := range summaries {
		if !found || summary.PriorityScore > driver.PriorityScore {
			driver = summary
			found = true
		}
	}
	return driver, found
}

// countRiskySoftware cuenta cuántas instalaciones de software tienen un riesgo mayor a cero
func countRiskySoftware(summaries []domain.SoftwareRiskSummary) int {
	count := 0
	for _, summary := range summaries {
		if summary.RiskScore > 0 {
			count++
		}
	}
	return count
}

// findDriverEndpointByRisk encuentra el endpoint con mayor riesgo agregado
func findDriverEndpointByRisk(summaries []domain.EndpointRiskSummary) (domain.EndpointRiskSummary, bool) {
	var driver domain.EndpointRiskSummary
	found := false
	for _, summary := range summaries {
		if !found || summary.RiskScore > driver.RiskScore {
			driver = summary
			found = true
		}
	}
	return driver, found
}

// findDriverEndpointByPriority encuentra el endpoint con mayor prioridad de parcheo
func findDriverEndpointByPriority(summaries []domain.EndpointRiskSummary) (domain.EndpointRiskSummary, bool) {
	var driver domain.EndpointRiskSummary
	found := false
	for _, summary := range summaries {
		if !found || summary.PriorityScore > driver.PriorityScore {
			driver = summary
			found = true
		}
	}
	return driver, found
}

// countRiskyEndpoints cuenta cuántos endpoints tienen un riesgo mayor a cero
func countRiskyEndpoints(summaries []domain.EndpointRiskSummary) int {
	count := 0
	for _, summary := range summaries {
		if summary.RiskScore > 0 {
			count++
		}
	}
	return count
}

// ComputeProjectRisk recalcula el riesgo agregado de un proyecto completo, basado en todos sus endpoints y findings asociados.
func (o *Orchestrator) ComputeProjectRisk(ctx context.Context, projectID int64) error {
	endpointIDs, err := o.riskPort.GetEndpointIDsByProject(ctx, projectID)
	if err != nil {
		return fmt.Errorf("error obteniendo endpoints del proyecto %d: %w", projectID, err)
	}

	for _, endpointID := range endpointIDs {
		if err := o.ComputeEndpointRisk(ctx, endpointID); err != nil {
			return fmt.Errorf("error recalculando endpoint %d del proyecto %d: %w", endpointID, projectID, err)
		}
	}

	return o.AggregateProjectRiskFromCurrentEndpointScores(ctx, projectID)
}

// ComputeAllProjectsRisk recorre todos los proyectos y recalcula su riesgo agregado.
func (o *Orchestrator) ComputeAllProjectsRisk(ctx context.Context) error {
	projectIDs, err := o.riskPort.GetAllProjectIDs(ctx)
	if err != nil {
		return fmt.Errorf("error obteniendo proyectos: %w", err)
	}

	for _, projectID := range projectIDs {
		if err := o.ComputeProjectRisk(ctx, projectID); err != nil {
			return fmt.Errorf("error recalculando riesgo del proyecto %d: %w", projectID, err)
		}
	}

	return nil
}

// GenerateExploitationPaths devuelve las rutas de explotación calculadas desde el motor de grafos,
// filtradas por proyecto si se indica un projectID > 0.
func (o *Orchestrator) GenerateExploitationPaths(ctx context.Context, projectID int64) ([]domain.ExploitationPath, error) {
	paths, err := o.infraPort.GetExploitationPaths(ctx, projectID)
	if err != nil {
		return nil, err
	}

	o.scorePathPriorities(ctx, paths)
	return paths, nil
}

// scorePathPriorities pondera cada ruta por la criticidad de su activo final.
// El repositorio ya deja PathRiskScore; aquí se añade el peso de negocio, que
// necesita leer el endpoint. Si no se puede leer, queda criticidad neutra en vez
// de descartar la ruta.
func (o *Orchestrator) scorePathPriorities(ctx context.Context, paths []domain.ExploitationPath) {
	criticalityCache := make(map[int64]float64)

	for i := range paths {
		path := &paths[i]
		if len(path.Steps) == 0 {
			continue
		}

		// El impacto lo marca el activo más valioso que toca la cadena, no el
		// último: una ruta que atraviesa la BBDD de producción para acabar en un
		// puesto ya ha hecho el daño al pasar por la BBDD.
		peak := 0.0
		var peakID int64
		for _, step := range path.Steps {
			criticality, cached := criticalityCache[step.TargetEndpointID]
			if !cached {
				criticality = minAssetCriticality
				if endpoint, err := o.endpointPort.GetByID(ctx, step.TargetEndpointID); err == nil && endpoint != nil {
					criticality = CalculateAssetCriticality(
						endpoint.InternetExposed,
						endpoint.Environment,
						endpoint.ConfidentialityReq,
						endpoint.IntegrityReq,
						endpoint.AvailabilityReq,
					)
				}
				criticalityCache[step.TargetEndpointID] = criticality
			}

			if criticality > peak {
				peak, peakID = criticality, step.TargetEndpointID
			}
		}

		path.TargetCriticality = peak
		path.CriticalAssetID = peakID
		path.PathPriorityScore = CalculatePathPriority(path.PathRiskScore, peak)
	}
}

// IsAnalysisPending comprueba si hay enriquecimiento NVD activo en background.
func (o *Orchestrator) IsAnalysisPending(ctx context.Context, projectID int64) (bool, error) {
	return atomic.LoadInt64(&o.activeBgEnrichments) > 0, nil
}

// SaveContainerImage registra una imagen de contenedor en Neo4j.
func (o *Orchestrator) SaveContainerImage(ctx context.Context, image *domain.ContainerImage) error {
	return o.containerPort.SaveContainerImage(ctx, image)
}

// SaveContainer registra una instancia de contenedor en ejecución en Neo4j,
// asociándolo al Endpoint host y a la imagen base si existe.
func (o *Orchestrator) SaveContainer(ctx context.Context, container *domain.Container) error {
	if container == nil {
		return fmt.Errorf("contenedor vacío")
	}

	containerID := strings.TrimSpace(container.ContainerID)
	imageID := strings.TrimSpace(container.ImageID)

	if containerID == "" {
		return fmt.Errorf("container_id vacío")
	}

	existingContainer, err := o.containerPort.GetContainer(ctx, containerID)
	if err != nil && !errors.Is(err, domain.ErrNodeNotFound) {
		return fmt.Errorf(
			"error recuperando container_id=%s antes de actualizar image_id: %w",
			containerID,
			err,
		)
	}

	if existingContainer != nil {
		oldImageID := strings.TrimSpace(existingContainer.ImageID)
		oldImageRef := strings.TrimPrefix(oldImageID, containerID+"_")

		if oldImageID != "" && oldImageRef != imageID {
			changedAt := time.Now().UTC()

			if _, err := o.findingPort.SupersedeContainerImageFindings(
				ctx,
				containerID,
				oldImageID,
				changedAt,
			); err != nil {
				return fmt.Errorf(
					"error invalidando findings de container_id=%s e image_id=%s: %w",
					containerID,
					oldImageID,
					err,
				)
			}
		}
	}

	if err := o.containerPort.SaveContainer(ctx, container); err != nil {
		return fmt.Errorf(
			"error guardando container_id=%s, image_id=%s: %w",
			containerID,
			imageID,
			err,
		)
	}

	savedContainer, err := o.containerPort.GetContainer(ctx, containerID)
	if err != nil {
		return fmt.Errorf(
			"error recuperando imagen persistida para container_id=%s: %w",
			containerID,
			err,
		)
	}

	imageNodeID := strings.TrimSpace(savedContainer.ImageID)

	if imageNodeID != "" {
		vulns, err := o.containerPort.GetVulnerabilitiesByContainerImage(
			ctx,
			imageNodeID,
		)
		if err != nil {
			return fmt.Errorf(
				"contenedor guardado parcialmente: container_id=%s, image_id=%s: %w",
				containerID,
				imageNodeID,
				err,
			)
		}

		if _, err := o.syncContainerFindingsForImage(
			ctx,
			imageNodeID,
			vulns,
		); err != nil {
			return fmt.Errorf(
				"contenedor guardado parcialmente: container_id=%s, image_id=%s: %w",
				containerID,
				imageNodeID,
				err,
			)
		}
	}

	return nil
}

// syncContainerFindingsForImage sincroniza/materializa los findings contextuales para todos los contenedores que usan la imagen.
func (o *Orchestrator) syncContainerFindingsForImage(
	ctx context.Context,
	imageID string,
	vulns []domain.Vulnerability,
) (domain.ContainerFindingSyncResult, error) {
	syncResult := domain.ContainerFindingSyncResult{}

	imageID = strings.TrimSpace(imageID)
	if imageID == "" {
		return syncResult, fmt.Errorf("image_id vacío")
	}

	if len(vulns) == 0 {
		return syncResult, nil
	}

	containerIDs, err := o.containerPort.GetContainerIDsByImage(ctx, imageID)
	if err != nil {
		return syncResult, fmt.Errorf(
			"error obteniendo contenedores de la imagen %s: %w",
			imageID,
			err,
		)
	}

	if len(containerIDs) == 0 {
		return syncResult, nil
	}

	now := time.Now().UTC()
	seenCVEs := make(map[string]struct{}, len(vulns))

	for _, vulnerability := range vulns {
		cveID := strings.ToUpper(strings.TrimSpace(vulnerability.CVEID))
		if cveID == "" {
			return syncResult, fmt.Errorf(
				"la imagen %s contiene una vulnerabilidad sin cve_id",
				imageID,
			)
		}

		if _, alreadyProcessed := seenCVEs[cveID]; alreadyProcessed {
			continue
		}
		seenCVEs[cveID] = struct{}{}

		for _, containerID := range containerIDs {
			finding := &domain.Finding{
				FindingID:         0,
				Status:            "OPEN",
				FirstSeen:         now,
				LastSeen:          &now,
				ImpactScore:       vulnerability.BaseScore,
				Likelihood:        0.5,
				RemediationFactor: 1.0,
				RiskScore:         vulnerability.BaseScore * 0.5,
			}

			_, created, err := o.findingPort.EnsureForContainerImageContextAndCVE(
				ctx,
				containerID,
				imageID,
				cveID,
				finding,
			)
			if err != nil {
				return syncResult, fmt.Errorf(
					"error sincronizando finding para container_id=%s, image_id=%s y cve_id=%s: %w",
					containerID,
					imageID,
					cveID,
					err,
				)
			}

			syncResult.Processed++

			if created {
				syncResult.Created++
			} else {
				syncResult.Existing++
			}
		}
	}

	return syncResult, nil
}

func partialContainerScanResult(
	result *domain.VulnerabilityScanResult,
	err error,
) (*domain.VulnerabilityScanResult, error) {
	if result != nil {
		result.Partial = true
		result.Error = err.Error()
	}

	return result, err
}

// ScanAndSaveContainerImage escanea una imagen de contenedor usando el ScoutAdapter
// y guarda los resultados (Vulnerabilidades) en la BD, enlazándolos a la imagen.
func (o *Orchestrator) ScanAndSaveContainerImage(ctx context.Context, imageName string, imageID string, opts ...domain.VulnerabilityScanOptions) (*domain.VulnerabilityScanResult, error) {
	if o.scoutPort == nil {
		return nil, errors.New("scoutPort is not initialized")
	}

	// if idx := strings.Index(imageID, "_"); idx != -1 && strings.HasPrefix(imageID, "container") {
	// 	imageID = imageID[idx+1:]
	// }
	if idx := strings.Index(imageName, "_"); idx != -1 && strings.HasPrefix(imageName, "container") {
		imageName = imageName[idx+1:]
	}

	imageID = strings.TrimSpace(imageID)
	scoutImageName := strings.TrimSpace(imageName)

	if idx := strings.Index(scoutImageName, "_"); idx != -1 &&
		strings.HasPrefix(scoutImageName, "container") {
		scoutImageName = scoutImageName[idx+1:]
	}

	// Desacoplar el contexto de la desconexión HTTP del cliente, manteniendo un timeout de seguridad amplio (15 min)
	// para garantizar que la ingesta de vulnerabilidades y findings en Neo4j se complete de forma atómica.
	scanCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Minute)
	defer cancel()

	scanStartedAt := time.Now().UTC()
	scanOpts := domain.VulnerabilityScanOptions{}
	if len(opts) > 0 {
		scanOpts = opts[0]
	}

	result := &domain.VulnerabilityScanResult{
		InstallationID: imageID,
		CPE:            imageName,
		ScanStartedAt:  &scanStartedAt,
	}

	if !scanOpts.ForceRefresh {
		image, err := o.containerPort.GetContainerImage(scanCtx, scoutImageName)
		if err == nil && image != nil && image.VulnScanCompletedAt != nil && time.Since(*image.VulnScanCompletedAt) <= nvdEnrichmentTTL {
			result.VulnerabilitiesFound = image.VulnScanProcessed
			result.TotalAvailable = image.VulnScanTotalAvailable
			result.Processed = image.VulnScanProcessed
			result.CacheHit = true
			result.ProviderPagesFetched = image.VulnScanPagesFetched
			scanCompletedAt := time.Now().UTC()
			result.ScanCompletedAt = &scanCompletedAt
			// Sincronizar findings contextuales para contenedores existentes en caso de cache hit
			vulns, err := o.containerPort.GetVulnerabilitiesByContainerImage(
				scanCtx,
				imageID,
			)
			if err != nil {
				scanErr := fmt.Errorf(
					"error recuperando vulnerabilidades cacheadas de la imagen %s: %w",
					imageID,
					err,
				)
				return partialContainerScanResult(result, scanErr)
			}

			syncResult, err := o.syncContainerFindingsForImage(
				scanCtx,
				imageID,
				vulns,
			)
			result.FindingsCreated += syncResult.Created
			result.FindingsExisting += syncResult.Existing
			if err != nil {
				scanErr := fmt.Errorf(
					"scan parcial para image_id=%s usando caché: %w",
					imageID,
					err,
				)
				return partialContainerScanResult(result, scanErr)
			}

			if err := o.markContainerImageCacheHit(scanCtx, imageID); err != nil {
				scanErr := fmt.Errorf(
					"scan parcial para image_id=%s: error actualizando metadata de caché: %w",
					imageID,
					err,
				)
				return partialContainerScanResult(result, scanErr)
			}

			return result, nil
		}
	}

	// 1. Llamar a Docker Scout
	vulns, err := o.scoutPort.ScanImage(scanCtx, imageName)
	if err != nil {
		return nil, fmt.Errorf("error escaneando imagen %s: %w", imageName, err)
	}
	result.VulnerabilitiesFound = len(vulns)
	result.TotalAvailable = len(vulns)

	// 2. Validar y enriquecer vulnerabilidades con NVD (Gatekeeper), guardando solo las válidas
	var validVulns []domain.Vulnerability
	for _, v := range vulns {
		cveID := strings.ToUpper(strings.TrimSpace(v.CVEID))
		if cveID == "" || strings.EqualFold(cveID, "UNSPECIFIED") || strings.EqualFold(cveID, "UNKNOWN") {
			fmt.Printf("[Scout Gatekeeper] Omitiendo vulnerabilidad sin cve_id válido para image_id=%s\n", imageID)
			continue
		}
		v.CVEID = cveID

		existingVuln, err := o.vulnPort.GetByID(scanCtx, v.CVEID)
		if err != nil {
			scanErr := fmt.Errorf(
				"scan parcial para image_id=%s, cve_id=%s: error recuperando vulnerabilidad existente: %w",
				imageID,
				cveID,
				err,
			)
			return partialContainerScanResult(result, scanErr)
		}

		isValid := false

		if v.IsRejected() {
			fmt.Printf("[Scout Gatekeeper] CVE %s descartado por estar marcado como REJECTED\n", cveID)
			isValid = false
		} else if existingVuln != nil && existingVuln.NVDEnriched {
			if existingVuln.IsRejected() {
				fmt.Printf("[Scout Gatekeeper] CVE %s descartado por estar marcado como REJECTED en BD\n", cveID)
				isValid = false
			} else {
				v.NVDEnriched = existingVuln.NVDEnriched
				v.NVDEnrichedAt = existingVuln.NVDEnrichedAt
				if len(v.CWE) == 0 {
					v.CWE = existingVuln.CWE
				}
				if !v.Exploit {
					v.Exploit = existingVuln.Exploit
				}
				if !v.KEV {
					v.KEV = existingVuln.KEV
				}
				if v.CVSSVector == "" {
					v.CVSSVector = existingVuln.CVSSVector
				}
				if v.NVDVector == "" {
					v.NVDVector = existingVuln.NVDVector
				}
				if existingVuln.BaseScore > 0 {
					v.BaseScore = existingVuln.BaseScore
				}
				if existingVuln.Description != "" {
					v.Description = existingVuln.Description
				}
				isValid = true
			}
		} else if o.vulnScannerPort != nil {
			enrichedData, err := o.vulnScannerPort.FetchByCVE(scanCtx, v.CVEID)
			if err == nil && enrichedData != nil {
				if enrichedData.IsRejected() {
					fmt.Printf("[Scout Gatekeeper] CVE %s descartado por NVD (vulnerabilidad REJECTED/retirada por la autoridad)\n", cveID)
					isValid = false
				} else {
					v.CWE = enrichedData.CWE
					v.Exploit = enrichedData.Exploit
					v.KEV = enrichedData.KEV
					if enrichedData.CVSSVector != "" {
						v.CVSSVector = enrichedData.CVSSVector
					}
					if enrichedData.NVDVector != "" {
						v.NVDVector = enrichedData.NVDVector
					}
					if enrichedData.BaseScore > 0 {
						v.BaseScore = enrichedData.BaseScore
					}
					if enrichedData.Description != "" {
						v.Description = enrichedData.Description
					}
					enrichedAt := time.Now().UTC()
					v.NVDEnriched = true
					v.NVDEnrichedAt = &enrichedAt
					isValid = true
				}
			} else if err == nil && enrichedData == nil {
				// NVD retornó 404 (La vulnerabilidad no existe en la base de datos oficial)
				fmt.Printf("[Scout Gatekeeper] CVE %s descartado por NVD (no existe registro oficial en NVD)\n", cveID)
				isValid = false
			} else {
				// Error de comunicación con NVD: fallback si el ID tiene formato CVE/GHSA y BaseScore > 0 y no rechazada
				isValid = !v.IsRejected() && v.BaseScore > 0 && (strings.HasPrefix(cveID, "CVE-") || strings.HasPrefix(cveID, "GHSA-"))
			}
		} else {
			// Entornos de prueba sin proveedor NVD: validar formato y BaseScore > 0 y no rechazada
			isValid = !v.IsRejected() && v.BaseScore > 0 && (strings.HasPrefix(cveID, "CVE-") || strings.HasPrefix(cveID, "GHSA-"))
		}

		if !isValid {
			fmt.Printf("[Scout Gatekeeper] Vulnerabilidad %s descartada por no ser válida\n", cveID)
			continue
		}

		if err := o.saveVulnerabilityWithTTPs(scanCtx, &v); err != nil {
			scanErr := fmt.Errorf(
				"scan parcial para image_id=%s, cve_id=%s: error persistiendo vulnerabilidad: %w",
				imageID,
				cveID,
				err,
			)
			return partialContainerScanResult(result, scanErr)
		}

		if err := o.containerPort.LinkVulnerabilityToImage(scanCtx, imageID, cveID); err != nil {
			scanErr := fmt.Errorf(
				"scan parcial para image_id=%s, cve_id=%s: error enlazando vulnerabilidad con imagen: %w",
				imageID,
				cveID,
				err,
			)
			return partialContainerScanResult(result, scanErr)
		}

		result.Processed++
		validVulns = append(validVulns, v)
		o.EnqueueCVE(v.CVEID, 0)
	}

	// Purgar cualquier vulnerabilidad o finding rechazado previamente en Neo4j
	_ = o.PurgeRejectedVulnerabilities(scanCtx)

	// Materializar/Sincronizar los findings contextuales únicamente para las vulnerabilidades validadas
	syncResult, err := o.syncContainerFindingsForImage(
		scanCtx,
		imageID,
		validVulns,
	)
	result.FindingsCreated += syncResult.Created
	result.FindingsExisting += syncResult.Existing
	if err != nil {
		scanErr := fmt.Errorf(
			"scan parcial para image_id=%s: la inteligencia compartida fue guardada, pero falló la materialización contextual: %w",
			imageID,
			err,
		)
		return partialContainerScanResult(result, scanErr)
	}

	scanCompletedAt := time.Now().UTC()
	result.ScanCompletedAt = &scanCompletedAt
	result.ProviderPagesFetched = 1

	if err := o.updateContainerImageScanMetadata(scanCtx, imageID, result, scanStartedAt); err != nil {
		scanErr := fmt.Errorf(
			"scan parcial para image_id=%s: vulnerabilidades y findings persistidos, pero falló la metadata final: %w",
			imageID,
			err,
		)
		return partialContainerScanResult(result, scanErr)
	}

	// Recálculo síncrono de riesgo tras el escaneo y enriquecimiento NVD de la imagen de contenedor
	if o.riskPort != nil {
		if err := o.ComputeAllProjectsRisk(scanCtx); err != nil {
			fmt.Printf("[ScanAndSaveContainerImage] Advertencia en recálculo síncrono de riesgo de proyectos: %v\n", err)
		}
	}

	return result, nil
}

func (o *Orchestrator) markContainerImageCacheHit(ctx context.Context, imageID string) error {
	if o.dbHelper == nil {
		return nil
	}

	query := `
		MATCH (ci:ContainerImage {id: $image_id})
		SET ci.vuln_scan_cache_hit = true
	`

	return o.dbHelper.ExecuteWrite(ctx, query, map[string]any{
		"image_id": imageID,
	})
}

func (o *Orchestrator) updateContainerImageScanMetadata(ctx context.Context, imageID string, result *domain.VulnerabilityScanResult, startedAt time.Time) error {
	if o.dbHelper == nil || result == nil {
		return nil
	}

	completedAt := time.Now().UTC()
	if result.ScanCompletedAt != nil {
		completedAt = *result.ScanCompletedAt
	}

	query := `
		MATCH (ci:ContainerImage) WHERE ci.id = $image_id OR ci.image_id = $image_id OR ci.name = $image_id
		SET ci.vuln_scan_started_at = $started_at,
		    ci.vuln_scan_completed_at = $completed_at,
		    ci.vuln_scan_cache_hit = $cache_hit,
		    ci.vuln_scan_total_available = $total_available,
		    ci.vuln_scan_processed = $processed,
		    ci.vuln_scan_pages_fetched = $pages_fetched
	`

	return o.dbHelper.ExecuteWrite(ctx, query, map[string]any{
		"image_id":        imageID,
		"started_at":      startedAt,
		"completed_at":    completedAt,
		"cache_hit":       result.CacheHit,
		"total_available": result.TotalAvailable,
		"processed":       result.Processed,
		"pages_fetched":   result.ProviderPagesFetched,
	})
}

// SyncScoutDaily obtiene todas las imágenes de contenedores registradas
// y ejecuta un escaneo automatizado contra Docker Scout.
func (o *Orchestrator) SyncScoutDaily(ctx context.Context) error {
	if o.scoutPort == nil {
		return errors.New("scoutPort is not initialized, cannot run SyncScoutDaily")
	}

	images, err := o.containerPort.GetAllContainerImages(ctx)
	if err != nil {
		return fmt.Errorf("error obteniendo imagenes de contenedor: %w", err)
	}

	var errs []error
	for _, img := range images {
		// Usar el ImageID directamente como nombre canónico de la imagen.
		// El ImageID ya contiene el nombre completo (ej: "nginx:1.19", "httpd:2.4.49").
		// No recomponemos Name+Tag para evitar duplicados como "httpd:2.4.49:latest".
		imageName := img.ImageID
		if imageName == "" {
			imageName = img.Name
		}

		fmt.Printf("[Scout Sync] Escaneando imagen: %s\n", imageName)
		_, err := o.ScanAndSaveContainerImage(ctx, imageName, img.ImageID, domain.VulnerabilityScanOptions{ForceRefresh: true})
		if err != nil {
			errs = append(errs, fmt.Errorf("fallo al escanear %s: %v", imageName, err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("SyncScoutDaily completado con %d errores: %v", len(errs), errs)
	}

	return nil
}

// RunDailyPipeline ejecuta la canalización nocturna completa a las 03:00 AM (o bajo demanda):
// 1. Obtiene los identificadores de todos los proyectos registrados en el sistema.
// 2. Ejecuta el análisis automático de vulnerabilidades para TODAS las instalaciones de software en todos los proyectos (equivalente al botón del frontend).
// 3. Escanea TODAS las imágenes de contenedores mediante Docker Scout (SyncScoutDaily), registrando hallazgos e imágenes.
// 4. Sincroniza las vulnerabilidades NVD/NIST globales recientes (SyncNistDaily).
// 5. Recalcula el riesgo global y niveles de prioridad para todos los proyectos y sus activos (ComputeAllProjectsRisk).
func (o *Orchestrator) RunDailyPipeline(ctx context.Context) error {
	log.Println("[CRON 03:00 AM] Iniciando canalización diaria unificada de análisis de vulnerabilidades y recálculo de riesgo...")

	// 1. Obtener todos los IDs de proyectos
	var projectIDs []int64
	if o.riskPort != nil {
		pIDs, err := o.riskPort.GetAllProjectIDs(ctx)
		if err == nil {
			projectIDs = pIDs
		}
	}

	log.Printf("[CRON 03:00 AM] Proyectos a analizar: %d %v", len(projectIDs), projectIDs)

	// 2. Fase 1/4: Análisis de vulnerabilidades de Software (cruce CPE -> NVD)
	log.Println("[CRON 03:00 AM] Fase 1/4: Escaneando vulnerabilidades de instalaciones de software...")
	if o.softwareInstPort != nil {
		var installations []domain.SoftwareInstallationItem
		if len(projectIDs) > 0 {
			for _, pid := range projectIDs {
				items, pErr := o.softwareInstPort.GetSoftwareInstallationsByProject(ctx, pid)
				if pErr == nil && len(items) > 0 {
					installations = append(installations, items...)
				}
			}
		}
		// Fallback o complemento: si la búsqueda por proyecto devuelve 0 o para asegurar cobertura completa
		if len(installations) == 0 {
			items, allErr := o.softwareInstPort.GetAllSoftwareInstallations(ctx)
			if allErr == nil {
				installations = items
			}
		}

		log.Printf("[CRON 03:00 AM] Iniciando análisis automático de %d instalaciones de software...", len(installations))
		var scanErrs []error
		for _, inst := range installations {
			log.Printf("[CRON 03:00 AM] Analizando vulnerabilidades de instalación: %s (Software ID: %d)", inst.InstallationID, inst.SoftwareID)
			_, scanErr := o.AutoScanAndRegisterVulnerabilities(ctx, inst.InstallationID, inst.SoftwareID, domain.VulnerabilityScanOptions{ForceRefresh: true})
			if scanErr != nil {
				scanErrs = append(scanErrs, scanErr)
			}
		}
		if len(scanErrs) > 0 {
			log.Printf("[CRON 03:00 AM] Análisis de software completado con %d advertencias/errores.", len(scanErrs))
		} else {
			log.Println("[CRON 03:00 AM] Análisis de vulnerabilidades de instalaciones de software completado con éxito.")
		}
	}

	// 3. Fase 2/4: Escaneo de imágenes Docker con Scout
	if o.scoutPort != nil {
		log.Println("[CRON 03:00 AM] Fase 2/4: Escaneando imágenes de contenedores con Docker Scout...")
		var containerImages []domain.ContainerImage
		if len(projectIDs) > 0 && o.containerPort != nil {
			for _, pid := range projectIDs {
				imgs, pErr := o.containerPort.GetContainerImagesByProject(ctx, pid)
				if pErr == nil && len(imgs) > 0 {
					containerImages = append(containerImages, imgs...)
				}
			}
		}
		if len(containerImages) == 0 && o.containerPort != nil {
			imgs, allErr := o.containerPort.GetAllContainerImages(ctx)
			if allErr == nil {
				containerImages = imgs
			}
		}

		log.Printf("[CRON 03:00 AM] Escaneando %d imágenes de contenedores...", len(containerImages))
		var scoutErrs []error
		for _, img := range containerImages {
			imageName := img.ImageID
			if imageName == "" {
				imageName = img.Name
			}
			log.Printf("[CRON 03:00 AM] Escaneando imagen Docker Scout: %s", imageName)
			_, err := o.ScanAndSaveContainerImage(ctx, imageName, img.ImageID, domain.VulnerabilityScanOptions{ForceRefresh: true})
			if err != nil {
				scoutErrs = append(scoutErrs, err)
			}
		}
		if len(scoutErrs) > 0 {
			log.Printf("[CRON 03:00 AM] Escaneo Docker Scout completado con %d errores.", len(scoutErrs))
		} else {
			log.Println("[CRON 03:00 AM] Escaneo de imágenes Docker Scout completado con éxito.")
		}
	} else {
		log.Println("[CRON 03:00 AM] Fase 2/4: Docker Scout no está configurado, omitiendo escaneo de imágenes.")
	}

	// 4. Fase 3/4: Sincronización diaria con NIST/NVD para vulnerabilidades globales
	log.Println("[CRON 03:00 AM] Fase 3/4: Sincronizando vulnerabilidades globales con NIST/NVD...")
	if err := o.SyncNistDaily(ctx); err != nil {
		log.Printf("[CRON 03:00 AM] Advertencia en sincronización NIST: %v", err)
	} else {
		log.Println("[CRON 03:00 AM] Sincronización de vulnerabilidades NIST/NVD completada.")
	}

	// 5. Fase 4/4: Recálculo global del riesgo de todos los proyectos
	if o.riskPort != nil {
		log.Println("[CRON 03:00 AM] Fase 4/4: Recalculando riesgo global de todos los proyectos...")
		if err := o.ComputeAllProjectsRisk(ctx); err != nil {
			log.Printf("[CRON 03:00 AM] Error recalculando riesgo global de proyectos: %v", err)
			return err
		}
		log.Println("[CRON 03:00 AM] Recálculo global de riesgo completado con éxito.")
	}

	log.Println("[CRON 03:00 AM] Canalización diaria de las 03:00 AM finalizada correctamente.")
	return nil
}

// AddContainerToEndpoint guarda un contenedor y lo vincula a un host (endpoint)
func (o *Orchestrator) AddContainerToEndpoint(ctx context.Context, hostID int64, container *domain.Container) error {
	if err := o.validateAssetNameUnique(ctx, container.Name, container.ContainerID, o.projectIDOfEndpoint(ctx, hostID)); err != nil {
		return err
	}

	validIPs, err := o.validateAssetIPs(ctx, o.projectIDOfEndpoint(ctx, hostID), container.IPs, 0, container.ContainerID)
	if err != nil {
		return err
	}
	container.IPs = validIPs

	if container.ContainerID == "" {
		// En principio el frontend genera UUID, pero si no...
		container.ContainerID = fmt.Sprintf("container-%d", time.Now().UnixNano())
	}
	container.HostID = hostID

	if err := o.SaveContainer(ctx, container); err != nil && !errors.Is(err, domain.ErrNodeAlreadyExists) {
		return err
	}

	if len(container.IPs) > 0 {
		if err := o.containerPort.SaveIPs(ctx, container.ContainerID, container.IPs); err != nil {
			return fmt.Errorf("error guardando IPs del contenedor: %w", err)
		}
	}

	// Incondicional por el mismo motivo que en el alta de endpoint: un alta que reutiliza
	// un ID existente tiene que limpiar las aristas de las IPs anteriores.
	if o.networkPort != nil {
		if _, err := o.networkPort.LinkContainerToMatchingNetworks(ctx, container.ContainerID, container.IPs, o.projectIDOfEndpoint(ctx, hostID)); err != nil {
			return fmt.Errorf("error enlazando contenedor a las redes coincidentes: %w", err)
		}
	}
	return nil
}

// UpdateContainer actualiza los datos de un contenedor y sus IPs.
func (o *Orchestrator) UpdateContainer(ctx context.Context, container *domain.Container) error {
	projectID := int64(0)
	if o.infraPort != nil {
		projectID, _ = o.infraPort.GetProjectIDByContainer(ctx, container.ContainerID)
	}

	if err := o.validateAssetNameUnique(ctx, container.Name, container.ContainerID, projectID); err != nil {
		return err
	}

	validIPs, err := o.validateAssetIPs(ctx, projectID, container.IPs, 0, container.ContainerID)
	if err != nil {
		return err
	}
	container.IPs = validIPs

	if err := o.SaveContainer(ctx, container); err != nil {
		return err
	}

	if err := o.containerPort.SaveIPs(ctx, container.ContainerID, container.IPs); err != nil {
		return fmt.Errorf("error actualizando IPs del contenedor: %w", err)
	}
	if o.networkPort != nil {
		if _, err := o.networkPort.LinkContainerToMatchingNetworks(ctx, container.ContainerID, container.IPs, projectID); err != nil {
			return fmt.Errorf("error re-enlazando contenedor a redes coincidentes: %w", err)
		}
	}
	return nil
}

// === EDICIÓN Y BORRADO DE ACTIVOS (CRUD COMPLETO) ===

// UpdateEndpoint actualiza los datos y re-enlaza las IPs de un Endpoint en Neo4j.
func (o *Orchestrator) UpdateEndpoint(ctx context.Context, endpoint *domain.Endpoint) error {
	endpointProjectID := o.projectIDOfEndpoint(ctx, endpoint.EndpointID)

	if err := o.validateAssetNameUnique(ctx, endpoint.Hostname, endpoint.EndpointID, endpointProjectID); err != nil {
		return err
	}

	// Las IPs se validan antes de tocar nada: SaveIPs borra y recrea los nodos :IPAddress,
	// así que comprobar después dejaría el duplicado ya escrito.
	validIPs, err := o.validateAssetIPs(ctx, endpointProjectID, endpoint.IPs, endpoint.EndpointID, "")
	if err != nil {
		return err
	}
	endpoint.IPs = validIPs

	// Recalcular la categoría aquí es lo que permite reclasificar un activo mal dado de alta:
	// al corregir su tipo, el bucket de SLA se recoloca en la misma operación.
	endpoint.ApplyCategory()

	if err := o.endpointPort.Update(ctx, endpoint); err != nil {
		return fmt.Errorf("error actualizando endpoint: %w", err)
	}

	if err := o.endpointPort.SaveIPs(ctx, endpoint.EndpointID, endpoint.IPs); err != nil {
		return fmt.Errorf("error actualizando IPs del endpoint %d: %w", endpoint.EndpointID, err)
	}

	if o.networkPort != nil {
		if _, err := o.networkPort.LinkEndpointToMatchingNetworks(ctx, endpoint.EndpointID, endpoint.IPs, endpointProjectID); err != nil {
			return fmt.Errorf("error actualizando relaciones endpoint-red para endpoint %d: %w", endpoint.EndpointID, err)
		}
	}

	if o.riskPort != nil {
		if err := o.ComputeEndpointRisk(ctx, endpoint.EndpointID); err != nil {
			return fmt.Errorf("endpoint actualizado, pero falló el recálculo de riesgo del endpoint %d: %w",
				endpoint.EndpointID, err)
		}

		projectID, err := o.riskPort.GetProjectIDByEndpoint(ctx, endpoint.EndpointID)
		if err != nil {
			return fmt.Errorf("endpoint actualizado, pero falló la búsqueda del proyecto para recalcular riesgo: %w", err)
		}

		if projectID != 0 {
			if err := o.AggregateProjectRiskFromCurrentEndpointScores(ctx, projectID); err != nil {
				return fmt.Errorf("endpoint actualizado, pero falló la agregación de riesgo del proyecto %d: %w", projectID, err)
			}
		}
	}

	return nil
}

// DeleteEndpoint elimina un Endpoint por su ID.
func (o *Orchestrator) DeleteEndpoint(ctx context.Context, endpointID int64) error {
	return o.endpointPort.DeleteByID(ctx, endpointID)
}

// GetEndpointIPs devuelve las IPs asociadas a un endpoint.
func (o *Orchestrator) GetEndpointIPs(ctx context.Context, endpointID int64) ([]domain.EndpointIP, error) {
	return o.endpointPort.GetIPs(ctx, endpointID)
}

// UpdateNetwork actualiza los datos y re-enlaza automáticamente los Endpoints compatibles a la red.
// Si tras la actualización ningún endpoint coincide, ancla la red al proyecto indicado
// como huérfana de ese proyecto (ver LinkNetworkToProjectIfOrphan).
func (o *Orchestrator) UpdateNetwork(ctx context.Context, network *domain.Network, projectID int64) (int, error) {
	scope, err := o.validateNetworkUniqueness(ctx, network, projectID, network.NetworkID)
	if err != nil {
		return 0, err
	}
	if err := o.networkPort.Update(ctx, network); err != nil {
		return 0, err
	}
	// Igual que en CreateNetwork: primero el ancla, luego la reconciliación. Al editar el
	// CIDR de una red hasta dejarla sin activos, el ancla es lo único que la mantiene
	// visible en el grafo del proyecto para poder volver a corregirla.
	if projectID > 0 {
		if err := o.networkPort.LinkNetworkToProjectIfOrphan(ctx, network.NetworkID, projectID); err != nil {
			return 0, fmt.Errorf("error anclando la red huérfana al proyecto: %w", err)
		}
	}
	linked, err := o.reconcileNetworkScope(ctx, scope, network.NetworkID)
	if err != nil {
		return 0, fmt.Errorf("error enlazando endpoints a la red actualizada: %w", err)
	}
	return linked, nil
}

// DeleteNetwork elimina una Red por su ID y recalcula el ámbito que la contenía.
//
// El recálculo es imprescindible: al borrar una subred específica, los activos que colgaban
// de ella tienen que volver al rango padre que los sigue conteniendo. El ámbito se resuelve
// ANTES del borrado, porque después la red ya no tiene proyecto del que colgar.
func (o *Orchestrator) DeleteNetwork(ctx context.Context, networkID int64) error {
	var scope []int64
	if o.infraPort != nil {
		owners, err := o.infraPort.GetProjectIDsByNetwork(ctx, networkID)
		if err != nil {
			return fmt.Errorf("error resolviendo el proyecto de la red antes de borrarla: %w", err)
		}
		scope = owners
	}

	if err := o.networkPort.DeleteByID(ctx, networkID); err != nil {
		return err
	}

	if _, err := o.reconcileNetworkScope(ctx, scope, 0); err != nil {
		return fmt.Errorf("red borrada, pero falló el recálculo de las relaciones activo-red: %w", err)
	}
	return nil
}

// UpdateHardware actualiza las especificaciones de Hardware.
func (o *Orchestrator) UpdateHardware(ctx context.Context, hardware *domain.Hardware) error {
	if err := domain.ValidateAndNormalizeHardware(hardware); err != nil {
		return err
	}
	return o.hardwarePort.Update(ctx, hardware)
}

// DeleteHardware elimina un componente Hardware por su ID.
func (o *Orchestrator) DeleteHardware(ctx context.Context, hardwareID int64) error {
	return o.hardwarePort.DeleteByID(ctx, hardwareID)
}

// UpdateSoftware actualiza los datos del Software en el catálogo.
func (o *Orchestrator) UpdateSoftware(ctx context.Context, software *domain.Software) error {
	return o.softwarePort.Update(ctx, software)
}

// DeleteSoftware elimina un nodo Software por su ID numérico.
func (o *Orchestrator) DeleteSoftware(ctx context.Context, softwareID int64) error {
	return o.softwarePort.DeleteByID(ctx, softwareID)
}

// UpdateSoftwareInstallation actualiza los datos de una instalación de software.
func (o *Orchestrator) UpdateSoftwareInstallation(ctx context.Context, installation *domain.SoftwareInstallation) error {
	installation.CriticalityLevel = NormalizeSoftwareCriticalityLevel(installation.CriticalityLevel)

	if err := o.softwareInstPort.Update(ctx, installation); err != nil {
		return fmt.Errorf("error actualizando instalación de software %s: %w", installation.InstallationID, err)
	}

	if o.riskPort == nil {
		return nil
	}

	endpointIDs, err := o.riskPort.GetEndpointIDsByInstallation(ctx, installation.InstallationID)
	if err != nil {
		return fmt.Errorf("instalación actualizada, pero falló la búsqueda de endpoints afectados: %w", err)
	}

	if len(endpointIDs) == 0 {
		if _, err := o.ComputeSoftwareInstallationRisk(ctx, installation.InstallationID); err != nil {
			return fmt.Errorf("instalación actualizada, pero falló el recálculo de riesgo de la instalación %s: %w", installation.InstallationID, err)
		}
		return nil
	}

	for _, endpointID := range endpointIDs {
		if err := o.ComputeEndpointRisk(ctx, endpointID); err != nil {
			return fmt.Errorf("instalación actualizada, pero falló el recálculo de riesgo del endpoint %d: %w", endpointID, err)
		}

		projectID, err := o.riskPort.GetProjectIDByEndpoint(ctx, endpointID)
		if err != nil {
			return fmt.Errorf("instalación actualizada, pero falló la búsqueda del proyecto del endpoint %d: %w", endpointID, err)
		}

		if projectID != 0 {
			if err := o.AggregateProjectRiskFromCurrentEndpointScores(ctx, projectID); err != nil {
				return fmt.Errorf("instalación actualizada, pero falló la agregación de riesgo del proyecto %d: %w", projectID, err)
			}
		}
	}

	return nil
}

// DeleteSoftwareInstallation elimina una instalación por su ID.
func (o *Orchestrator) DeleteSoftwareInstallation(ctx context.Context, installationID string) error {
	return o.softwareInstPort.DeleteByID(ctx, installationID)
}

// DeleteNodeByID elimina genéricamente cualquier nodo del grafo de Neo4j (sea entero o string su ID/CVE/TTP o elementId).
func (o *Orchestrator) DeleteNodeByID(ctx context.Context, id string) error {
	if o.dbHelper == nil {
		return fmt.Errorf("dbHelper no disponible para borrado genérico")
	}
	query := `
		MATCH (n)
		WHERE toString(n.id) = toString($id) OR toString(n.cve_id) = toString($id) OR toString(n.ttp_id) = toString($id) OR toString(n.installation_id) = toString($id) OR elementId(n) = $id
		OPTIONAL MATCH (n)-[:USES_IMAGE]->(old_i:ContainerImage)
		DETACH DELETE n
		WITH old_i
		WHERE old_i IS NOT NULL AND NOT ()-[:USES_IMAGE]->(old_i)
		DETACH DELETE old_i
	`
	return o.dbHelper.ExecuteWrite(ctx, query, map[string]any{"id": id})
}

// ExportProjectGraph orquesta la exportación nativa de un proyecto desde Neo4j.
func (o *Orchestrator) ExportProjectGraph(ctx context.Context, projectID int64) (*domain.GraphData, error) {
	if o.projectPort == nil {
		return nil, fmt.Errorf("puerto de proyectos no inicializado")
	}
	return o.projectPort.ExportGraph(ctx, projectID)
}

// SyncCAPECCatalog descarga el catálogo STIX 2.1 de MITRE CAPEC e ingiere los patrones de ataque y sus relaciones con CWE en Neo4j.
func (o *Orchestrator) SyncCAPECCatalog(ctx context.Context) (int, error) {
	if o.capecProvider == nil || o.capecPort == nil {
		return 0, fmt.Errorf("los componentes de CAPEC (capecPort y capecProvider) no han sido inyectados en el orquestador")
	}

	capecs, err := o.capecProvider.FetchCAPECBundle(ctx)
	if err != nil {
		return 0, fmt.Errorf("error obteniendo el catálogo STIX CAPEC: %w", err)
	}

	if err := o.capecPort.SaveBatch(ctx, capecs); err != nil {
		return 0, fmt.Errorf("error guardando el catálogo CAPEC en Neo4j: %w", err)
	}

	return len(capecs), nil
}

func (o *Orchestrator) WithMitreATTACK(ttpPort ports.TTPPort, provider ports.MitreATTACKProvider, actorPort ports.ThreatActorPort) *Orchestrator {
	o.ttpPort = ttpPort
	o.mitreAttackProvider = provider
	o.threatActorPort = actorPort
	return o
}

// SyncATTACKCatalog descarga el catálogo STIX 2.1 de MITRE ATT&CK Enterprise e ingiere la metadata de TTPs, Threat Actors y relaciones en Neo4j.
func (o *Orchestrator) SyncATTACKCatalog(ctx context.Context) (int, error) {
	if o.mitreAttackProvider == nil || o.ttpPort == nil || o.threatActorPort == nil {
		return 0, fmt.Errorf("los componentes de MITRE ATT&CK (ttpPort, threatActorPort y mitreAttackProvider) no han sido inyectados en el orquestador")
	}

	ttps, actors, relations, err := o.mitreAttackProvider.FetchATTACKBundle(ctx)
	if err != nil {
		return 0, fmt.Errorf("error obteniendo el catálogo STIX MITRE ATT&CK: %w", err)
	}

	if err := o.ttpPort.SaveBatch(ctx, ttps); err != nil {
		return 0, fmt.Errorf("error guardando el catálogo MITRE ATT&CK TTPs en Neo4j: %w", err)
	}

	if err := o.threatActorPort.SaveBatch(ctx, actors); err != nil {
		return 0, fmt.Errorf("error guardando el catálogo MITRE ATT&CK Threat Actors en Neo4j: %w", err)
	}

	if err := o.threatActorPort.SaveRelationshipsBatch(ctx, relations); err != nil {
		return 0, fmt.Errorf("error guardando las relaciones MITRE ATT&CK USES en Neo4j: %w", err)
	}

	return len(ttps), nil
}

func (o *Orchestrator) StartBackgroundTTPMapping(projectID int64) int {
	// Disparo manual: ejecuta un barrido acotado al proyecto indicado y devuelve cuántos CVEs encoló
	return o.runSweep(context.Background(), projectID)
}

func (o *Orchestrator) StartTTPWorker(ctx context.Context) {
	// 1. Worker Consumidor Principal
	go func() {
		var highCount int
		for {
			var task ttpTask
			var ok bool

			// Prevención de Inanición (Starvation):
			// Si hemos procesado 10 tareas de alta prioridad seguidas, intentamos
			// forzar el consumo de 1 tarea de baja prioridad si está disponible.
			if highCount >= 10 {
				select {
				case task, ok = <-o.ttpQueueLow:
					if !ok {
						return
					}
					highCount = 0
					goto process
				default:
					highCount = 0
				}
			}

			// Prioridad: Intentar leer primero de High
			select {
			case <-ctx.Done():
				return
			case task, ok = <-o.ttpQueueHigh:
				if !ok {
					return
				}
				highCount++
			default:
				// Si High está vacía, bloquear esperando en cualquiera de las dos
				select {
				case <-ctx.Done():
					return
				case task, ok = <-o.ttpQueueHigh:
					if !ok {
						return
					}
					highCount++
				case task, ok = <-o.ttpQueueLow:
					if !ok {
						return
					}
					highCount = 0
				}
			}

		process:
			o.startProcessingCVE(task.cveID, task.projectID)
			if err := o.processSingleCVE(ctx, task); err != nil {
				o.addTTPLog(fmt.Sprintf("Error procesando %s: %v", task.cveID, err), task.projectID)
			}
			o.endProcessingCVE(task.cveID, task.projectID)
		}
	}()

	// 2. Barrido Periódico de Seguridad (cada 10 minutos) — global, sin filtro de proyecto
	go func() {
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()

		// Barrido inicial al arrancar
		o.runSweep(ctx, 0)

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_ = o.runSweep(ctx, 0)
			}
		}
	}()
}

func (o *Orchestrator) runSweep(ctx context.Context, projectID int64) int {
	vulns, err := o.vulnPort.GetUnmappedVulnerabilities(ctx, projectID)
	if err != nil {
		log.Printf("[TTP-BG-SWEEP] Error obteniendo vulnerabilidades no mapeadas: %v", err)
		return 0
	}
	if len(vulns) > 0 {
		log.Printf("[TTP-BG-SWEEP] Encolando %d vulnerabilidades sin TTP (projectID=%d)...", len(vulns), projectID)
		for _, v := range vulns {
			o.EnqueueCVE(v.CVEID, projectID)
		}
	}
	return len(vulns)
}

func (o *Orchestrator) getProjectState(projectID int64) *ProjectTTPSyncState {
	o.ttpSync.mu.Lock()
	defer o.ttpSync.mu.Unlock()
	state, exists := o.ttpSync.projectStates[projectID]
	if !exists {
		state = &ProjectTTPSyncState{
			Logs:       []string{},
			QueuedCVEs: make(map[string]bool),
		}
		o.ttpSync.projectStates[projectID] = state
	}
	return state
}

func (o *Orchestrator) EnqueueCVE(cveID string, projectID int64) {
	state := o.getProjectState(projectID)

	o.ttpSync.mu.Lock()
	if state.QueuedCVEs[cveID] {
		o.ttpSync.mu.Unlock()
		return // Ya está encolado o procesándose
	}
	state.QueuedCVEs[cveID] = true
	state.Processing = true
	o.ttpSync.mu.Unlock()

	queue := o.ttpQueueHigh
	if projectID == 0 {
		queue = o.ttpQueueLow
	}

	select {
	case queue <- ttpTask{cveID: cveID, projectID: projectID}:
		// Encolado con éxito
	default:
		// Sacar del mapa si se descarta de la cola (para que pueda volver a re-encolarse en el barrido)
		o.ttpSync.mu.Lock()
		delete(state.QueuedCVEs, cveID)
		o.ttpSync.mu.Unlock()
		o.addTTPLog(fmt.Sprintf("Advertencia: Cola de mapeo TTP llena, descartado temporalmente: %s", cveID), projectID)
	}
}

func (o *Orchestrator) startProcessingCVE(cveID string, projectID int64) {
	state := o.getProjectState(projectID)
	o.ttpSync.mu.Lock()
	defer o.ttpSync.mu.Unlock()
	state.CurrentCVE = cveID
	state.Processing = true
}

func (o *Orchestrator) endProcessingCVE(cveID string, projectID int64) {
	state := o.getProjectState(projectID)
	o.ttpSync.mu.Lock()
	defer o.ttpSync.mu.Unlock()
	state.CurrentCVE = ""
	delete(state.QueuedCVEs, cveID)

	if len(state.QueuedCVEs) == 0 {
		state.Processing = false
	}
}

func (o *Orchestrator) processSingleCVE(ctx context.Context, task ttpTask) error {
	v, err := o.vulnPort.GetByID(ctx, task.cveID)
	if err != nil {
		return fmt.Errorf("error obteniendo vuln: %w", err)
	}
	if v == nil {
		return fmt.Errorf("vulnerabilidad %s no encontrada", task.cveID)
	}

	var ttps []string
	var confidence, source string
	var mappedCWE string

	validCWEs := []string{}
	for _, cwe := range v.CWE {
		cleaned := strings.TrimSpace(cwe)
		if cleaned != "" && cleaned != "[]" && cleaned != "NVD-CWE-Other" && cleaned != "NVD-CWE-noinfo" {
			validCWEs = append(validCWEs, cleaned)
		}
	}

	start := time.Now()
	if len(validCWEs) > 0 {
		mappedCWE = validCWEs[0]
		var capecErr error
		log.Printf("DEBUG HEX: mappedCWE=%q | len=%d | hex=%x", mappedCWE, len(mappedCWE), mappedCWE)
		if o.capecPort != nil {
			ttps, capecErr = o.capecPort.GetTTPsByCWE(ctx, mappedCWE)
		} else {
			capecErr = fmt.Errorf("capecPort no inicializado")
		}
		if capecErr == nil && len(ttps) > 0 {
			confidence = "high"
			source = "capec_static"
		} else {
			if capecErr != nil {
				log.Printf("[CAPEC] Error consultando CAPEC para %s: %v — usando fallback LLM", mappedCWE, capecErr)
			} else {
				log.Printf("[CAPEC] Sin cobertura para %s, usando fallback LLM", mappedCWE)
			}
			ttps, _, err = o.ttpMapper.MapEnrichedToTTPRaw(ctx, mappedCWE, v.Description, v.CVSSVector)
			confidence = "medium"
			source = "llm_enriched"
		}
	} else {
		ttps, _, err = o.ttpMapper.MapEnrichedToTTPRaw(ctx, "", v.Description, v.CVSSVector)
		confidence = "medium"
		source = "llm_enriched"
	}
	duration := time.Since(start)

	if err != nil {
		return err
	}

	o.addTTPLog(fmt.Sprintf("CVE %s mapeado a TTPs %v en %v (Confianza: %s)", v.CVEID, ttps, duration.Round(time.Millisecond), confidence), task.projectID)
	if len(ttps) > 0 {
		err = o.vulnPort.LinkTTPsToVulnerability(ctx, v.CVEID, mappedCWE, ttps, confidence, source)
		if err != nil {
			return err
		}
		// Emitir evento WebSocket si el notificador está inyectado
		if o.notifier != nil {
			_ = o.notifier.NotifyTTPMapped(ctx, ports.TTPMappedEvent{
				CVEID:      v.CVEID,
				TTPs:       ttps,
				Confidence: confidence,
				Source:     source,
				ProjectID:  task.projectID,
				Log:        fmt.Sprintf("CVE %s → TTPs %v (Confianza: %s)", v.CVEID, ttps, confidence),
			})
		}
	}
	return nil
}

func (o *Orchestrator) addTTPLog(msg string, projectID int64) {
	state := o.getProjectState(projectID)
	o.ttpSync.mu.Lock()
	defer o.ttpSync.mu.Unlock()
	logLine := fmt.Sprintf("[%s] %s", time.Now().Format("15:04:05"), msg)
	state.Logs = append(state.Logs, logLine)

	prefix := "[TTP-BG-GLOBAL]"
	if projectID > 0 {
		prefix = fmt.Sprintf("[TTP-PROJ-%d]", projectID)
	}
	fmt.Printf("%s %s\n", prefix, msg)
}

func (o *Orchestrator) GetTTPSyncStatus(projectID int64) TTPBackgroundSyncResponse {
	o.ttpSync.mu.RLock()
	defer o.ttpSync.mu.RUnlock()

	state, exists := o.ttpSync.projectStates[projectID]
	if !exists {
		return TTPBackgroundSyncResponse{
			Processing:  false,
			CurrentCVE:  "",
			QueueLength: 0,
			Logs:        []string{},
		}
	}

	logsCopy := make([]string, len(state.Logs))
	copy(logsCopy, state.Logs)

	queueLen := len(o.ttpQueueHigh)
	if projectID == 0 {
		queueLen = len(o.ttpQueueLow)
	}

	return TTPBackgroundSyncResponse{
		Processing:  state.Processing,
		CurrentCVE:  state.CurrentCVE,
		QueueLength: queueLen,
		Logs:        logsCopy,
	}
}

// AggregateProjectRiskFromCurrentEndpointScores recalcula el riesgo agregado de un proyecto completo, basado en los scores actuales de sus endpoints asociados.
func (o *Orchestrator) AggregateProjectRiskFromCurrentEndpointScores(ctx context.Context, projectID int64) error {
	summaries, err := o.riskPort.GetEndpointRiskSummariesByProject(ctx, projectID)
	if err != nil {
		return fmt.Errorf("error obteniendo resumen de endpoints del proyecto %d: %w", projectID, err)
	}

	if len(summaries) == 0 {
		return o.riskPort.UpdateProjectRiskAndPriority(
			ctx,
			projectID,
			0.0,
			"LOW",
			0.0,
			"LOW",
			0,
			"",
			0.0,
			"",
			"",
			0,
			"",
			0.0,
			"",
			"",
			0,
		)
	}

	riskScores := make([]float64, 0, len(summaries))
	priorityScores := make([]float64, 0, len(summaries))

	for _, summary := range summaries {
		riskScores = append(riskScores, summary.RiskScore)
		priorityScores = append(priorityScores, summary.PriorityScore)
	}

	projectRisk := AggregateInfrastructureRisk(riskScores)
	projectRiskTier := ClassifyRiskTier(projectRisk)

	projectPriority := AggregateInfrastructurePriority(priorityScores)
	projectPriorityTier := ClassifyRiskTier(projectPriority)

	technicalDriver, hasTechnicalDriver := findDriverEndpointByRisk(summaries)
	priorityDriver, hasPriorityDriver := findDriverEndpointByPriority(summaries)

	if !hasTechnicalDriver {
		technicalDriver = domain.EndpointRiskSummary{}
	}
	if !hasPriorityDriver {
		priorityDriver = domain.EndpointRiskSummary{}
	}

	return o.riskPort.UpdateProjectRiskAndPriority(
		ctx,
		projectID,
		projectRisk,
		projectRiskTier,
		projectPriority,
		projectPriorityTier,
		technicalDriver.EndpointID,
		technicalDriver.Hostname,
		technicalDriver.RiskScore,
		technicalDriver.TechnicalDriverSoftwareName,
		technicalDriver.TechnicalDriverCVEID,
		priorityDriver.EndpointID,
		priorityDriver.Hostname,
		priorityDriver.PriorityScore,
		priorityDriver.PriorityDriverSoftwareName,
		priorityDriver.PriorityDriverCVEID,
		countRiskyEndpoints(summaries),
	)
}

func (o *Orchestrator) RefreshProjectPatches(ctx context.Context, projectID int64, limit int, offset int) (*domain.ProjectPatchRefreshResult, error) {
	if projectID == 0 {
		return nil, fmt.Errorf("projectID es obligatorio")
	}
	if o.riskPort == nil {
		return nil, fmt.Errorf("el motor de riesgo no está configurado")
	}
	if limit <= 0 {
		limit = 20
	}
	if limit > 50 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}

	cves, err := o.riskPort.GetOpenFindingCVEsByProject(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("error obteniendo CVEs del proyecto: %w", err)
	}

	totalCVEs := len(cves)
	end := offset + limit
	if end > totalCVEs {
		end = totalCVEs
	}

	batch := []string{}
	if offset < totalCVEs {
		batch = cves[offset:end]
	}

	result := &domain.ProjectPatchRefreshResult{
		ProjectID:  projectID,
		TotalCVEs:  totalCVEs,
		Offset:     offset,
		Limit:      limit,
		Processed:  len(batch),
		HasMore:    end < totalCVEs,
		NextOffset: end,
		Results:    make([]domain.ProjectPatchRefreshItem, 0, len(batch)),
	}

	for _, cveID := range batch {
		item := domain.ProjectPatchRefreshItem{CVEID: cveID}

		info, err := o.EnrichPatchesFromProvider(ctx, cveID)
		if err != nil {
			item.Error = err.Error()
			result.Failed++
			result.Results = append(result.Results, item)
			continue
		}

		if info == nil {
			result.NotFound++
			result.Results = append(result.Results, item)
			continue
		}

		item.Found = true
		item.PatchCount = len(info.Patches)
		item.FixedVersions = len(info.FixedVersions)
		result.Refreshed++
		result.Results = append(result.Results, item)
	}

	return result, nil
}

// fixedVersionText genera un texto con las versiones fijas separadas por comas.
func fixedVersionText(fixedVersions []domain.FixedVersion) string {
	values := make([]string, 0, len(fixedVersions))
	for _, fixedVersion := range fixedVersions {
		values = append(values, fixedVersion.String())
	}
	return strings.Join(values, ", ")
}

// SyntheticPatchFromFixedVersions genera un objeto Patch sintético basado en la existencia de versiones fijas para un CVE dado.
func syntheticPatchFromFixedVersions(cveID string, fixedVersions []domain.FixedVersion) *domain.Patch {
	if strings.TrimSpace(cveID) == "" || len(fixedVersions) == 0 {
		return nil
	}

	return &domain.Patch{
		Description:   fmt.Sprintf("Actualización recomendada según OSV (%s)", cveID),
		URL:           fmt.Sprintf("https://osv.dev/vulnerability/%s", cveID),
		Source:        "OSV",
		ReferenceType: "FIXED_VERSION",
		Official:      true,
		FixedVersion:  fixedVersionText(fixedVersions),
	}
}

func (o *Orchestrator) GetTTPMatrix(ctx context.Context, projectID *int64) ([]domain.TTPMatrixItem, error) {
	return o.infraPort.GetTTPMatrix(ctx, projectID)
}

// Métodos auxiliares de consulta de estado previo para auditoría
func (o *Orchestrator) GetEndpointByID(ctx context.Context, id int64) (*domain.Endpoint, error) {
	return o.endpointPort.GetByID(ctx, id)
}

func (o *Orchestrator) GetNetworkByID(ctx context.Context, id int64) (*domain.Network, error) {
	return o.networkPort.GetByID(ctx, id)
}

func (o *Orchestrator) GetHardwareByID(ctx context.Context, id int64) (*domain.Hardware, error) {
	return o.hardwarePort.GetByID(ctx, id)
}

func (o *Orchestrator) GetSoftwareByID(ctx context.Context, id int64) (*domain.Software, error) {
	return o.softwarePort.GetByID(ctx, id)
}

func (o *Orchestrator) GetSoftwareInstallationByID(ctx context.Context, id string) (*domain.SoftwareInstallation, error) {
	return o.softwareInstPort.GetByID(ctx, id)
}

func (o *Orchestrator) GetContainerByID(ctx context.Context, id string) (*domain.Container, error) {
	return o.containerPort.GetContainer(ctx, id)
}

func (o *Orchestrator) GetProjectByID(ctx context.Context, id int64) (*domain.Project, error) {
	return o.projectPort.GetByID(ctx, id)
}

// GetTTPStats devuelve las métricas agregadas para el dashboard de inteligencia de amenazas.
func (o *Orchestrator) GetTTPStats(ctx context.Context, projectID int64) (*domain.TTPStats, error) {
	return o.infraPort.GetTTPStats(ctx, projectID)

}

// PurgeRejectedVulnerabilities elimina de Neo4j todas las vulnerabilidades marcadas como REJECTED por NVD/MITRE,
// así como sus findings contextuales y relaciones asociadas.
func (o *Orchestrator) PurgeRejectedVulnerabilities(ctx context.Context) error {
	if o.dbHelper == nil {
		return nil
	}
	query := `
		MATCH (v:Vulnerability)
		WHERE toLower(v.description) STARTS WITH 'rejected reason:'
		   OR toLower(v.description) CONTAINS 'rejected reason:'
		   OR v.description CONTAINS '** REJECTED **'
		   OR toLower(v.description) STARTS WITH 'rejected:'
		   OR toLower(v.description) CONTAINS 'this cve id has been rejected'
		OPTIONAL MATCH (f:Finding)-[:OF_VULNERABILITY]->(v)
		DETACH DELETE f, v
	`
	err := o.dbHelper.ExecuteWrite(ctx, query, nil)
	if err != nil {
		fmt.Printf("[Purge] Error eliminando vulnerabilidades rechazadas: %v\n", err)
		return err
	}
	fmt.Println("[Purge] Vulnerabilidades rechazadas y sus findings fueron purgados exitosamente de Neo4j.")
	return nil
}

// GetPaginatedInventory consulta el inventario paginado (50 elementos por página por defecto).
func (o *Orchestrator) GetPaginatedInventory(ctx context.Context, query domain.InventoryQuery) (*domain.PaginatedInventoryResponse, error) {
	if query.Page < 1 {
		query.Page = 1
	}
	if query.Limit <= 0 {
		query.Limit = 50
	}
	return o.infraPort.GetPaginatedInventory(ctx, query)
}

// validateNetworkUniqueness valida y normaliza los datos de una red y comprueba que no
// colisione con otra red del mismo proyecto por nombre, rango CIDR o VLAN ID.
//
// El ámbito es el proyecto, no la base de datos entera: dos auditorías distintas pueden
// tener cada una su "DMZ" en 10.0.1.0/24. El ámbito se calcula uniendo el proyecto que
// llega en la petición con los que ya tenga la red en el grafo, porque el cliente no
// siempre manda project_id al editar y una red puede colgar de varios proyectos.
//
// Los errores del repositorio se propagan en lugar de ignorarse: si la base de datos no
// puede responder, no damos por hecho que no hay duplicados.
func (o *Orchestrator) validateNetworkUniqueness(ctx context.Context, network *domain.Network, projectID int64, excludeID int64) ([]int64, error) {
	if err := domain.ValidateAndNormalizeNetwork(network); err != nil {
		return nil, err
	}
	if o.infraPort == nil {
		// Sin repositorio no hay comprobación posible; devolvemos al menos el proyecto pedido
		// para que el emparejamiento posterior siga acotado.
		if projectID > 0 {
			return []int64{projectID}, nil
		}
		return nil, nil
	}

	scope, err := o.networkProjectScope(ctx, projectID, excludeID)
	if err != nil {
		return nil, err
	}

	candidates, err := o.infraPort.GetNetworksInProjectScope(ctx, scope, excludeID)
	if err != nil {
		return nil, fmt.Errorf("error comprobando las redes del proyecto: %w", err)
	}

	nameKey := strings.ToLower(network.Nombre)
	for _, other := range candidates {
		if strings.ToLower(strings.TrimSpace(other.Nombre)) == nameKey {
			return nil, fmt.Errorf("%w: ya existe una red con este nombre en el proyecto. Por favor, elige un nombre único", domain.ErrDuplicateNetwork)
		}

		// Comparamos por la forma canónica: 10.0.1.37/24 y 10.0.1.0/24 son la misma subred.
		if otherCIDR, err := domain.NormalizeCIDR(other.CIDR); err == nil && otherCIDR == network.CIDR {
			return nil, fmt.Errorf("%w: el rango %s ya está asignado a la red '%s' de este proyecto. Por favor, elige un CIDR único", domain.ErrDuplicateNetwork, network.CIDR, other.Nombre)
		}

		if network.VLANID > 0 && other.VLANID == network.VLANID {
			return nil, fmt.Errorf("%w: el VLAN ID %d ya está asignado a la red '%s' de este proyecto. Por favor, elige un VLAN ID único", domain.ErrDuplicateNetwork, network.VLANID, other.Nombre)
		}
	}

	return scope, nil
}

// networkProjectScope devuelve los proyectos contra los que comprobar duplicados: el que
// llega en la petición más los que la red ya tenga asignados en el grafo. Una lista vacía
// significa "redes sin proyecto", que es el ámbito de una red creada sin proyecto.
func (o *Orchestrator) networkProjectScope(ctx context.Context, projectID int64, networkID int64) ([]int64, error) {
	seen := make(map[int64]bool)
	var scope []int64

	if projectID > 0 {
		seen[projectID] = true
		scope = append(scope, projectID)
	}

	if networkID > 0 {
		owners, err := o.infraPort.GetProjectIDsByNetwork(ctx, networkID)
		if err != nil {
			return nil, fmt.Errorf("error resolviendo el proyecto de la red: %w", err)
		}
		for _, id := range owners {
			if id > 0 && !seen[id] {
				seen[id] = true
				scope = append(scope, id)
			}
		}
	}

	return scope, nil
}

// validateAssetIPs normaliza las IPs de un endpoint o contenedor y comprueba que ninguna
// esté ya ocupada por otro activo del mismo proyecto. Devuelve las IPs ya normalizadas
// para que el llamante persista esas y no las del formulario.
//
// Se llama SIEMPRE antes de escribir: SaveIPs borra y recrea los nodos :IPAddress, así que
// validar después dejaría el duplicado ya guardado.
func (o *Orchestrator) validateAssetIPs(ctx context.Context, projectID int64, ips []domain.EndpointIP, excludeEndpointID int64, excludeContainerID string) ([]domain.EndpointIP, error) {
	normalized, err := domain.NormalizeAssetIPs(ips)
	if err != nil {
		return nil, err
	}

	if len(normalized) == 0 || o.infraPort == nil || projectID <= 0 {
		return normalized, nil
	}

	values := make([]string, 0, len(normalized))
	for _, entry := range normalized {
		values = append(values, entry.IP)
	}

	conflicts, err := o.infraPort.FindIPConflicts(ctx, projectID, values, excludeEndpointID, excludeContainerID)
	if err != nil {
		return nil, err
	}
	if len(conflicts) > 0 {
		return nil, domain.FormatIPConflicts(conflicts)
	}

	return normalized, nil
}

// projectIDOfEndpoint resuelve el proyecto de un endpoint, o 0 si no se puede determinar.
// Se usa para acotar la comprobación de IPs duplicadas; si falla, la comprobación cruzada
// se omite y solo queda la validación de formato, que no depende de la base de datos.
func (o *Orchestrator) projectIDOfEndpoint(ctx context.Context, endpointID int64) int64 {
	if o.riskPort == nil || endpointID <= 0 {
		return 0
	}
	projectID, err := o.riskPort.GetProjectIDByEndpoint(ctx, endpointID)
	if err != nil {
		return 0
	}
	return projectID
}

// validateAssetNameUnique comprueba que no exista ya un endpoint o un contenedor con ese
// nombre en el proyecto. Los dos tipos comparten espacio de nombres, pero el ámbito es el
// proyecto: dos auditorías distintas pueden tener cada una su "validation-dmz-web".
//
// excludeID es el identificador del propio activo al editarlo (int64 para endpoints,
// string para contenedores), para que no choque consigo mismo.
//
// El error del repositorio se propaga en lugar de ignorarse: si la base de datos no puede
// responder, no damos por hecho que el nombre está libre.
func (o *Orchestrator) validateAssetNameUnique(ctx context.Context, name string, excludeID any, projectID int64) error {
	if strings.TrimSpace(name) == "" || o.infraPort == nil {
		return nil
	}

	exists, err := o.infraPort.IsAssetNodeNameDuplicate(ctx, name, excludeID, projectID)
	if err != nil {
		return fmt.Errorf("error comprobando el nombre del activo: %w", err)
	}
	if exists {
		return fmt.Errorf("%w: ya existe un activo con este nombre en el proyecto. Por favor, elige un nombre único", domain.ErrDuplicateAsset)
	}

	return nil
}
