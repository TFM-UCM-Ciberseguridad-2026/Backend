package service

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"strings"
	"time"

	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/domain"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/ports"
)

const autoScanVulnerabilityLimit = 100

/*
Este archivo contiene el Servicio de Aplicación (Application Service) u Orquestador de Casos de Uso.

Propósito arquitectónico y teórico:
1. Ubicación en Arquitectura Hexagonal: Se localiza en `internal/core/service`, actuando como el implementador de los puertos de entrada (inbound ports) y consumidor de los puertos de salida (outbound ports).
2. Núcleo Lógico de la Aplicación: Implementa los casos de uso principales de la lógica de negocio (como el análisis y correlación de vulnerabilidades de equipos mediante CPEs).
3. Coordinación de Dependencias: Recibe los puertos (CVEProvider, ExploitProvider, Database) a través del constructor (Inyección de Dependencias) y orquesta las llamadas necesarias en orden lógico para cumplir con el proceso de negocio.
4. Neutralidad Tecnológica: No expone tipos HTTP ni dependencias de frameworks web, garantizando que las reglas de negocio puedan ser llamadas por un servidor HTTP, un CLI de consola o un proceso de ejecución programada (cron).
*/

type Orchestrator struct {
	projectPort      ports.ProjectPort
	endpointPort     ports.EndpointPort
	hardwarePort     ports.HardwarePort
	networkPort      ports.NetworkPort
	softwareInstPort ports.SoftwareInstallationPort
	softwarePort     ports.SoftwarePort
	findingPort      ports.FindingPort
	vulnPort         ports.VulnerabilityPort
	remediationPort  ports.RemediationPort
	relationshipPort ports.RelationshipPort
	infraPort        ports.InfrastructurePort
	containerPort    ports.ContainerPort
	patchPort        ports.PatchPort
	dbHelper         ports.DatabaseHelper
	vulnScannerPort  ports.VulnerabilityAPIscanner
	riskPort         ports.RiskPort
	epssProvider     ports.EPSSProvider
	kevProvider      ports.KEVProvider
	scoutPort        ports.ContainerScannerPort
	patchProvider    ports.PatchProvider
	capecPort        ports.CAPECPort
	capecProvider    ports.CAPECProvider
	ttpPort          ports.TTPPort
	mitreAttackProvider ports.MitreATTACKProvider
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
	}
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

// AddEndpointToProject guarda un nuevo endpoint y lo vincula a un proyecto.
func (o *Orchestrator) AddEndpointToProject(ctx context.Context, projectID int64, endpoint *domain.Endpoint) error {
	if endpoint.EndpointID == 0 {
		id, err := o.nextNodeID(ctx, "Endpoint")
		if err != nil {
			return fmt.Errorf("error generando ID de endpoint: %w", err)
		}
		endpoint.EndpointID = id
	}

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
		if o.networkPort != nil {
			if _, err := o.networkPort.LinkEndpointToMatchingNetworks(ctx, endpoint.EndpointID, endpoint.IPs); err != nil {
				return fmt.Errorf("error enlazando endpoint a las redes coincidentes: %w", err)
			}
		}
	}

	return nil
}

// AssociateHardwareToEndpoint guarda componentes de hardware y los enlaza a un endpoint.
func (o *Orchestrator) AssociateHardwareToEndpoint(ctx context.Context, endpointID int64, hardware *domain.Hardware) error {
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
// VLAN, compartan esa misma VLAN. Devuelve el ID de la red creada y cuántos endpoints se
// enlazaron.
func (o *Orchestrator) CreateNetwork(ctx context.Context, network *domain.Network) (int64, int, error) {
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

	linked, err := o.networkPort.LinkMatchingEndpoints(ctx, network.NetworkID, network.CIDR, network.VLANID)
	if err != nil {
		return network.NetworkID, 0, fmt.Errorf("error enlazando endpoints a la red: %w", err)
	}

	return network.NetworkID, linked, nil
}

// RegisterSoftwareInstallation guarda la definición del software, la instancia instalada,
// asocia la instancia al endpoint y el software genérico a la instancia instalada.
func (o *Orchestrator) RegisterSoftwareInstallation(ctx context.Context, endpointID int64, software *domain.Software, installation *domain.SoftwareInstallation) error {
	if strings.TrimSpace(software.Vendor) == "" {
		return fmt.Errorf("el fabricante (vendor) es obligatorio para registrar el software y consultar vulnerabilidades en NIST")
	}

	if software.SoftwareID == 0 {
		swID, err := o.nextNodeID(ctx, "Software")
		if err != nil {
			return fmt.Errorf("error generando ID de software: %w", err)
		}
		software.SoftwareID = swID
	}

	if installation.InstallationID == "" {
		installation.InstallationID = o.nextInstallationID()
	}

	if strings.TrimSpace(software.CPE) == "" || software.CPE == "N/A" {
		software.CPE = domain.GenerateCPE23(software.Type, software.Vendor, software.Name, software.Version)
	}

	if err := o.softwarePort.Save(ctx, software); err != nil && !errors.Is(err, domain.ErrNodeAlreadyExists) {
		return err
	}
	if err := o.softwareInstPort.Save(ctx, installation); err != nil && !errors.Is(err, domain.ErrNodeAlreadyExists) {
		return err
	}
	if err := o.relationshipPort.LinkEndpointToInstallation(ctx, endpointID, installation.InstallationID); err != nil {
		return err
	}
	return o.relationshipPort.LinkInstallationToSoftware(ctx, installation.InstallationID, software.SoftwareID)
}

// GenerateFinding registra un hallazgo de vulnerabilidad (Finding) a una instalación específica.
func (o *Orchestrator) GenerateFinding(ctx context.Context, installationID string, finding *domain.Finding) error {
	if finding.FindingID == 0 {
		id, err := o.nextNodeID(ctx, "Finding")
		if err == nil {
			finding.FindingID = id
		}
	}
	if err := o.findingPort.Save(ctx, finding); err != nil && !errors.Is(err, domain.ErrNodeAlreadyExists) {
		return err
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
	if err := o.vulnPort.Save(ctx, vuln); err != nil && !errors.Is(err, domain.ErrNodeAlreadyExists) {
		return err
	}
	if err := o.remediationPort.Save(ctx, rem); err != nil && !errors.Is(err, domain.ErrNodeAlreadyExists) {
		return err
	}
	if err := o.relationshipPort.LinkFindingToVulnerability(ctx, findingID, vuln.CVEID); err != nil {
		return err
	}
	return o.relationshipPort.LinkFindingToRemediation(ctx, findingID, rem.RemediationID)
}

// GetInfrastructure recupera el grafo actual de infraestructura del usuario.
// Si la base de datos está vacía (0 nodos), automáticamente la inicializa con el escenario de prueba.
func (o *Orchestrator) GetInfrastructure(ctx context.Context) (*domain.GraphData, error) {
	graph, err := o.infraPort.GetGraphData(ctx)
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


// GetVulnerabilitiesForFinding devuelve los CVEs asociados a un finding concreto. Se usa
// desde el botón "Ver CVEs" del inspector de nodos, ya que los nodos Vulnerability no
// viajan en el grafo general.
func (o *Orchestrator) GetVulnerabilitiesForFinding(ctx context.Context, findingID int64) ([]domain.Vulnerability, error) {
	return o.findingPort.GetVulnerabilitiesByFinding(ctx, findingID)
}


/*
AutoScanAndRegisterVulnerabilities implementa el caso de uso central para automatizar la detección y registro de fallos:
 1. Recupera la entidad del software a partir de su ID.
 2. Si no tiene una cadena CPE válida (o está vacía o es "N/A"), la genera dinámicamente usando el tipo de software (aplicación, sistema operativo, etc.) y la guarda en la base de datos para futuras referencias.
 3. Invoca el puerto externo VulnerabilityAPIscanner para buscar vulnerabilidades usando el CPE generado.
 4. Para cada vulnerabilidad encontrada, la guarda/actualiza en la base de datos de grafos Neo4j.
 5. Crea un Hallazgo (Finding) con puntaje de riesgo inicializado y genera los enlaces relacionales de infraestructura:
    SoftwareInstallation -> [:HAS_FINDING] -> Finding -> [:OF_VULNERABILITY] -> Vulnerability.
*/
func (o *Orchestrator) AutoScanAndRegisterVulnerabilities(ctx context.Context, installationID string, softwareID int64, limits ...int) error {
	// 1. Obtener la entidad de software
	sw, err := o.softwarePort.GetByID(ctx, softwareID)
	if err != nil {
		return fmt.Errorf("no se pudo recuperar el software: %w", err)
	}

	// 2. Resolver o generar CPE
	cpe := sw.CPE
	if cpe == "" || cpe == "N/A" {
		// Generar automáticamente el CPE a partir del tipo (part), vendor, nombre del software y su versión
		cpe = domain.GenerateCPE23(sw.Type, sw.Vendor, sw.Name, sw.Version)
		sw.CPE = cpe
		// Actualizar el software con el nuevo CPE generado
		if err := o.softwarePort.Save(ctx, sw); err != nil && !errors.Is(err, domain.ErrNodeAlreadyExists) {
			return fmt.Errorf("error guardando software con CPE generado: %w", err)
		}
	}

	// 3. Buscar vulnerabilidades a través del puerto de escaneo
	vulns, err := o.vulnScannerPort.FetchByCPE(ctx, cpe)
	if err != nil {
		return fmt.Errorf("error consultando la API de vulnerabilidades para el CPE %s: %w", cpe, err)
	}
	limit := autoScanVulnerabilityLimit
	if len(limits) > 0 && limits[0] > 0 && limits[0] < limit {
		limit = limits[0]
	}
	if len(vulns) > limit {
		vulns = vulns[:limit]
	}

	// 4. Registrar vulnerabilidades y enlazarlas como hallazgos (Findings)
	for _, v := range vulns {
		vCopy := v
		if err := o.vulnPort.Save(ctx, &vCopy); err != nil && !errors.Is(err, domain.ErrNodeAlreadyExists) {
			return fmt.Errorf("error al guardar la vulnerabilidad %s: %w", vCopy.CVEID, err)
		}

		// Guardar los parches si los hay y vincularlos a la vulnerabilidad
		_ = o.RegisterPatchesForVulnerability(ctx, vCopy.CVEID, vCopy.Patches)

		// Crear un Hallazgo (Finding) para conectar la instalación del software con el CVE detectado
		now := time.Now().UTC()
		findingID, err := o.nextNodeID(ctx, "Finding")
		if err != nil {
			findingID = int64(rand.Int31n(1000000) + 1)
		}
		finding := &domain.Finding{ //TODO: retocar los valores por defectoooo TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO
			FindingID:         findingID,
			Status:            "OPEN",
			FirstSeen:         now,
			ImpactScore:       vCopy.BaseScore,
			Likelihood:        0.5,
			RemediationFactor: 1.0,
			RiskScore:         vCopy.BaseScore * 0.5,
		}

		if err := o.findingPort.Save(ctx, finding); err != nil && !errors.Is(err, domain.ErrNodeAlreadyExists) {
			return fmt.Errorf("error al guardar el hallazgo para la vulnerabilidad %s: %w", vCopy.CVEID, err)
		}

		// Establecer las relaciones en Neo4j
		if err := o.relationshipPort.LinkInstallationToFinding(ctx, installationID, finding.FindingID); err != nil {
			return fmt.Errorf("error al enlazar la instalación al finding: %w", err)
		}
		if err := o.relationshipPort.LinkFindingToVulnerability(ctx, finding.FindingID, vCopy.CVEID); err != nil {
			return fmt.Errorf("error al enlazar el finding a la vulnerabilidad: %w", err)
		}
	}

	return nil
}

// ComputeEndpointRisk calcula y persiste el riesgo de todos los findings abiertos de un endpoint.
// Flujo:
//  1. Recupera el contexto completo de cada finding (CVSSVector, CIA del endpoint, flags de vuln).
//  2. Obtiene scores EPSS frescos y el catálogo KEV actual de las APIs externas.
//  3. Para cada finding: calcula environmental score, likelihood y risk_score.
//  4. Agrega el riesgo a nivel de endpoint y clasifica el tier.
//  5. Persiste todos los scores en Neo4j.
func (o *Orchestrator) ComputeEndpointRisk(ctx context.Context, endpointID int64) error {
	// 1. Obtener contexto de findings activos del endpoint.
	contexts, err := o.riskPort.GetFindingContextsByEndpoint(ctx, endpointID)
	if err != nil {
		return fmt.Errorf("error obteniendo contexto de findings: %w", err)
	}
	if len(contexts) == 0 {
		installationIDs, err := o.riskPort.GetInstallationIDsByEndpoint(ctx, endpointID)
		if err != nil {
			return fmt.Errorf("error obteniendo instalaciones del endpoint %d: %w", endpointID, err)
		}
		for _, installationID := range installationIDs {
			if _, err := o.ComputeSoftwareInstallationRisk(ctx, installationID); err != nil {
				return err
			}
		}
		return o.riskPort.UpdateEndpointRiskAndPriority(ctx, endpointID, 0.0, "LOW", 0.0, "LOW", "", "", 0.0, "", "", "", 0.0, "", 0)
	}

	// 2. Recopilar CVE IDs y obtener datos frescos de EPSS y KEV.
	cveIDs := make([]string, 0, len(contexts))
	for _, fc := range contexts {
		if fc.CVEID != "" {
			cveIDs = append(cveIDs, fc.CVEID)
		}
	}

	epssScores, err := o.epssProvider.FetchEPSS(ctx, cveIDs)
	if err != nil {
		return fmt.Errorf("error obteniendo scores EPSS: %w", err)
	}

	kevCatalog, err := o.kevProvider.FetchKEV(ctx)
	if err != nil {
		return fmt.Errorf("error obteniendo catálogo KEV: %w", err)
	}

	// 3. Recalcular riesgo contextual por finding.
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
		); err != nil {
			return fmt.Errorf("error actualizando scores del finding %d: %w", fc.FindingID, err)
		}
	}

	// 4. Recalcular riesgo por instalación con findings ya actualizados.
	installationIDs, err := o.riskPort.GetInstallationIDsByEndpoint(ctx, endpointID)
	if err != nil {
		return fmt.Errorf("error obteniendo instalaciones del endpoint %d: %w", endpointID, err)
	}

	for _, installationID := range installationIDs {
		if _, err := o.ComputeSoftwareInstallationRisk(ctx, installationID); err != nil {
			return err
		}
	}

	summaries, err := o.riskPort.GetSoftwareRiskSummariesByEndpoint(ctx, endpointID)
	if err != nil {
		return fmt.Errorf("error obteniendo resumen de software del endpoint %d: %w", endpointID, err)
	}

	riskScores := make([]float64, 0, len(summaries))
	priorityScores := make([]float64, 0, len(summaries))
	for _, summary := range summaries {
		riskScores = append(riskScores, summary.RiskScore)
		priorityScores = append(priorityScores, summary.PriorityScore)
	}

	endpointRisk := AggregateEndpointRisk(riskScores)
	endpointRiskTier := ClassifyRiskTier(endpointRisk)

	endpointPriority := AggregateEndpointPriority(priorityScores)
	endpointPriorityTier := ClassifyRiskTier(endpointPriority)

	technicalDriver, hasTechnicalDriver := findDriverSoftwareByRisk(summaries)
	priorityDriver, hasPriorityDriver := findDriverSoftwareByPriority(summaries)
	riskySoftwareCount := countRiskySoftware(summaries)

	if !hasTechnicalDriver {
		technicalDriver = domain.SoftwareRiskSummary{}
	}
	if !hasPriorityDriver {
		priorityDriver = domain.SoftwareRiskSummary{}
	}

	return o.riskPort.UpdateEndpointRiskAndPriority(
		ctx,
		endpointID,
		endpointRisk,
		endpointRiskTier,
		endpointPriority,
		endpointPriorityTier,
		technicalDriver.InstallationID,
		technicalDriver.SoftwareName,
		technicalDriver.RiskScore,
		technicalDriver.DriverCVEID,
		priorityDriver.InstallationID,
		priorityDriver.SoftwareName,
		priorityDriver.PriorityScore,
		priorityDriver.DriverCVEID,
		riskySoftwareCount,
	)
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
		if err := o.vulnPort.Save(ctx, &vCopy); err != nil && !errors.Is(err, domain.ErrNodeAlreadyExists) {
			continue // Loguear o continuar si una falla
		}

		_ = o.RegisterPatchesForVulnerability(ctx, vCopy.CVEID, vCopy.Patches)
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
				// El parche ya está en el grafo: reutilizamos su nodo y solo garantizamos el enlace.
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

// DeclarePatchApplied registra que un parche se ha aplicado sobre una instalación y
// propaga el efecto a los findings de esa instalación afectados por el CVE.
//
// El nivel de remediación determina el factor que multiplica el riesgo:
//   - OFFICIAL_FIX   → factor 0.00, los findings pasan a PATCHED y salen de la agregación
//   - TEMPORARY_FIX  → factor 0.30, los findings siguen abiertos con riesgo reducido
//   - WORKAROUND     → factor 0.50, idem
//   - UNAVAILABLE    → factor 1.00, revierte una declaración previa
//
// Solo el parche oficial cierra el finding: una mitigación reduce el riesgo pero el
// software vulnerable sigue instalado y la mitigación puede revertirse o no cubrir todos
// los vectores.
//
// No recalcula el riesgo del endpoint: esta operación fija las entradas del cálculo
// (factor y estado) y el recálculo se dispara con ComputeEndpointRisk, que es lo que ya
// hace el cron. Devuelve la declaración persistida y los findings afectados.
func (o *Orchestrator) DeclarePatchApplied(
	ctx context.Context,
	installationID string,
	cveID string,
	patchID int64,
	level domain.RemediationLevel,
	appliedAt time.Time,
	appliedBy string,
	notes string,
) (*domain.AppliedPatch, []int64, error) {
	if installationID == "" {
		return nil, nil, fmt.Errorf("installation_id vacío")
	}
	if cveID == "" {
		return nil, nil, fmt.Errorf("cve_id vacío")
	}
	if !level.IsValid() {
		return nil, nil, fmt.Errorf("nivel de remediación no reconocido: %q", level)
	}
	if appliedAt.IsZero() {
		appliedAt = time.Now().UTC()
	}

	// Si no se indica el parche, se resuelve a partir del CVE. Cuando hay varios
	// registrados no podemos elegir por el usuario: pedimos que lo concrete.
	if patchID == 0 {
		patches, err := o.patchPort.GetByVulnerability(ctx, cveID)
		if err != nil {
			return nil, nil, fmt.Errorf("error recuperando los parches de %s: %w", cveID, err)
		}
		switch len(patches) {
		case 0:
			return nil, nil, fmt.Errorf("no hay ningún parche registrado para %s: regístralo primero", cveID)
		case 1:
			patchID = patches[0].PatchID
		default:
			return nil, nil, fmt.Errorf("hay %d parches registrados para %s: indica patch_id", len(patches), cveID)
		}
	}

	remediationFactor := RemediationFactorForLevel(level)

	application := &domain.AppliedPatch{
		PatchID:           patchID,
		InstallationID:    installationID,
		CVEID:             cveID,
		AppliedAt:         appliedAt.UTC(),
		AppliedBy:         appliedBy,
		RemediationLevel:  level,
		RemediationFactor: remediationFactor,
		Notes:             notes,
	}

	if err := o.patchPort.SaveApplication(ctx, application); err != nil {
		if errors.Is(err, domain.ErrNodeNotFound) {
			return nil, nil, fmt.Errorf("no existe el parche %d o la instalación %q", patchID, installationID)
		}
		return nil, nil, fmt.Errorf("error declarando el parche aplicado: %w", err)
	}

	// Un parche oficial cierra el finding; una mitigación lo deja abierto con menos riesgo.
	status := "OPEN"
	if level.FullyRemediates() {
		status = "PATCHED"
	}

	affected, err := o.findingPort.ApplyRemediationByInstallationAndCVE(
		ctx, installationID, cveID, remediationFactor, status,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("error propagando la remediación a los findings: %w", err)
	}

	// Sincronizar el nodo Remediation con la declaración. La arista APPLIED_TO es la
	// fuente de verdad del histórico, pero Remediation.status/applied_at es lo que
	// consulta quien mira la remediación de un finding, así que deben coincidir.
	//
	// Al revertir (UNAVAILABLE) se limpia la fecha: la remediación vuelve a estar
	// pendiente y conservar un applied_at antiguo daría a entender lo contrario.
	var remediationAppliedAt *time.Time
	if level != domain.RemediationLevelUnavailable {
		applied := application.AppliedAt
		remediationAppliedAt = &applied
	}

	if _, err := o.remediationPort.ApplyByInstallationAndCVE(
		ctx, installationID, cveID, level.RemediationStatus(), remediationAppliedAt,
	); err != nil {
		return nil, nil, fmt.Errorf("error sincronizando las remediaciones: %w", err)
	}

	return application, affected, nil
}

// GetAppliedPatchHistory devuelve el histórico de parches aplicados sobre una instalación,
// del más reciente al más antiguo.
func (o *Orchestrator) GetAppliedPatchHistory(ctx context.Context, installationID string) ([]domain.AppliedPatch, error) {
	if installationID == "" {
		return nil, fmt.Errorf("installation_id vacío")
	}
	return o.patchPort.GetApplicationsByInstallation(ctx, installationID)
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
func (o *Orchestrator) EnrichPatchesFromProvider(ctx context.Context, cveID string) (*domain.PatchIntelligence, error) {
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

// GenerateExploitationPaths devuelve las rutas de explotación calculadas desde el motor de grafos.
func (o *Orchestrator) GenerateExploitationPaths(ctx context.Context) ([]domain.ExploitationPath, error) {
	return o.infraPort.GetExploitationPaths(ctx)
}

// SaveContainerImage registra una imagen de contenedor en Neo4j.
func (o *Orchestrator) SaveContainerImage(ctx context.Context, image *domain.ContainerImage) error {
	return o.containerPort.SaveContainerImage(ctx, image)
}

// SaveContainer registra una instancia de contenedor en ejecución en Neo4j,
// asociándolo al Endpoint host y a la imagen base si existe.
func (o *Orchestrator) SaveContainer(ctx context.Context, container *domain.Container) error {
	return o.containerPort.SaveContainer(ctx, container)
}

// ScanAndSaveContainerImage escanea una imagen de contenedor usando el ScoutAdapter
// y guarda los resultados (Vulnerabilidades) en la BD, enlazándolos a la imagen.
func (o *Orchestrator) ScanAndSaveContainerImage(ctx context.Context, imageName string, imageID string) error {
	if o.scoutPort == nil {
		return errors.New("scoutPort is not initialized")
	}
	
	// 1. Llamar a Docker Scout
	vulns, err := o.scoutPort.ScanImage(ctx, imageName)
	if err != nil {
		return fmt.Errorf("error escaneando imagen %s: %w", imageName, err)
	}

	// 2. Guardar las vulnerabilidades y enlazarlas a la imagen
	for _, v := range vulns {
		// Guardar Vulnerabilidad
		err = o.vulnPort.Save(ctx, &v)
		if err != nil {
			// Podría fallar si ya existe, idealmente debería haber un Update o ignorar error de duplicado.
			// Para esta PoC ignoramos si ya existe.
		}

		// Enlazar a la imagen
		err = o.containerPort.LinkVulnerabilityToImage(ctx, imageID, v.CVEID)
		if err != nil {
			return fmt.Errorf("error enlazando CVE %s a imagen %s: %w", v.CVEID, imageID, err)
		}
	}

	return nil
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
		// Para Scout el nombre es el Tag si es que está disponible, o simplemente name
		// Por ejemplo: nginx:latest
		imageName := img.Name
		if img.Tag != "" && img.Tag != "latest" {
			imageName = fmt.Sprintf("%s:%s", img.Name, img.Tag)
		}
		
		fmt.Printf("[Scout Sync] Escaneando imagen: %s (ID: %s)\n", imageName, img.ImageID)
		err := o.ScanAndSaveContainerImage(ctx, imageName, img.ImageID)
		if err != nil {
			errs = append(errs, fmt.Errorf("fallo al escanear %s: %v", imageName, err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("SyncScoutDaily completado con %d errores: %v", len(errs), errs)
	}

	return nil
}

// === EDICIÓN Y BORRADO DE ACTIVOS (CRUD COMPLETO) ===

// UpdateEndpoint actualiza los datos y re-enlaza las IPs de un Endpoint en Neo4j.
func (o *Orchestrator) UpdateEndpoint(ctx context.Context, endpoint *domain.Endpoint) error {
	if err := o.endpointPort.Update(ctx, endpoint); err != nil {
		return err
	}
	// Siempre sincronizamos IPs (para poder borrar VLANs o quitar todas las IPs de un endpoint)
	if err := o.endpointPort.SaveIPs(ctx, endpoint.EndpointID, endpoint.IPs); err != nil {
		return fmt.Errorf("error actualizando IPs del endpoint: %w", err)
	}
	if o.networkPort != nil {
		if _, err := o.networkPort.LinkEndpointToMatchingNetworks(ctx, endpoint.EndpointID, endpoint.IPs); err != nil {
			return fmt.Errorf("error re-enlazando endpoint a las redes coincidentes: %w", err)
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
func (o *Orchestrator) UpdateNetwork(ctx context.Context, network *domain.Network) (int, error) {
	if err := o.networkPort.Update(ctx, network); err != nil {
		return 0, err
	}
	linked, err := o.networkPort.LinkMatchingEndpoints(ctx, network.NetworkID, network.CIDR, network.VLANID)
	if err != nil {
		return 0, fmt.Errorf("error enlazando endpoints a la red actualizada: %w", err)
	}
	return linked, nil
}

// DeleteNetwork elimina una Red por su ID.
func (o *Orchestrator) DeleteNetwork(ctx context.Context, networkID int64) error {
	return o.networkPort.DeleteByID(ctx, networkID)
}

// UpdateHardware actualiza las especificaciones de Hardware.
func (o *Orchestrator) UpdateHardware(ctx context.Context, hardware *domain.Hardware) error {
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
	return o.softwareInstPort.Update(ctx, installation)
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
		DETACH DELETE n
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

func (o *Orchestrator) WithMitreATTACK(ttpPort ports.TTPPort, provider ports.MitreATTACKProvider) *Orchestrator {
	o.ttpPort = ttpPort
	o.mitreAttackProvider = provider
	return o
}

// SyncATTACKCatalog descarga el catálogo STIX 2.1 de MITRE ATT&CK Enterprise e ingiere la metadata de TTPs (nombre, tácticas, descripción) en Neo4j.
func (o *Orchestrator) SyncATTACKCatalog(ctx context.Context) (int, error) {
	if o.mitreAttackProvider == nil || o.ttpPort == nil {
		return 0, fmt.Errorf("los componentes de MITRE ATT&CK (ttpPort y mitreAttackProvider) no han sido inyectados en el orquestador")
	}

	ttps, err := o.mitreAttackProvider.FetchATTACKBundle(ctx)
	if err != nil {
		return 0, fmt.Errorf("error obteniendo el catálogo STIX MITRE ATT&CK: %w", err)
	}

	if err := o.ttpPort.SaveBatch(ctx, ttps); err != nil {
		return 0, fmt.Errorf("error guardando el catálogo MITRE ATT&CK TTPs en Neo4j: %w", err)
	}

	return len(ttps), nil
}

