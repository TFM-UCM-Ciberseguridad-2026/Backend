package service

import (
	"context"
	"fmt"
	"math/rand"
	"time"

	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/domain"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/ports"
)

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
	patchPort        ports.PatchPort
	dbHelper         ports.DatabaseHelper
	vulnScannerPort  ports.VulnerabilityAPIscanner
	riskPort         ports.RiskPort
	epssProvider     ports.EPSSProvider
	kevProvider      ports.KEVProvider
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

// CreateProject guarda el proyecto principal.
func (o *Orchestrator) CreateProject(ctx context.Context, project *domain.Project) error {
	return o.projectPort.Save(ctx, project)
}

// AddEndpointToProject guarda un nuevo endpoint y lo vincula a un proyecto.
func (o *Orchestrator) AddEndpointToProject(ctx context.Context, projectID int64, endpoint *domain.Endpoint) error {
	if err := o.endpointPort.Save(ctx, endpoint); err != nil {
		return err
	}
	return o.relationshipPort.LinkProjectToEndpoint(ctx, projectID, endpoint.EndpointID)
}

// AssociateHardwareToEndpoint guarda componentes de hardware y los enlaza a un endpoint.
func (o *Orchestrator) AssociateHardwareToEndpoint(ctx context.Context, endpointID int64, hardware *domain.Hardware) error {
	if err := o.hardwarePort.Save(ctx, hardware); err != nil {
		return err
	}
	return o.relationshipPort.LinkEndpointToHardware(ctx, endpointID, hardware.HardwareID)
}

// AssociateNetworkToEndpoint guarda un segmento de red y lo asocia a un endpoint.
func (o *Orchestrator) AssociateNetworkToEndpoint(ctx context.Context, endpointID int64, network *domain.Network) error {
	if err := o.networkPort.Save(ctx, network); err != nil {
		return err
	}
	return o.relationshipPort.LinkEndpointToNetwork(ctx, endpointID, network.NetworkID)
}

// RegisterSoftwareInstallation guarda la definición del software, la instancia instalada,
// asocia la instancia al endpoint y el software genérico a la instancia instalada.
func (o *Orchestrator) RegisterSoftwareInstallation(ctx context.Context, endpointID int64, software *domain.Software, installation *domain.SoftwareInstallation) error {
	if err := o.softwarePort.Save(ctx, software); err != nil {
		return err
	}
	if err := o.softwareInstPort.Save(ctx, installation); err != nil {
		return err
	}
	if err := o.relationshipPort.LinkEndpointToInstallation(ctx, endpointID, installation.InstallationID); err != nil {
		return err
	}
	return o.relationshipPort.LinkInstallationToSoftware(ctx, installation.InstallationID, software.SoftwareID)
}

// GenerateFinding registra un hallazgo de vulnerabilidad (Finding) a una instalación específica.
func (o *Orchestrator) GenerateFinding(ctx context.Context, installationID string, finding *domain.Finding) error {
	if err := o.findingPort.Save(ctx, finding); err != nil {
		return err
	}
	return o.relationshipPort.LinkInstallationToFinding(ctx, installationID, finding.FindingID)
}

// AssociateVulnerabilitiesAndRemediations guarda la vulnerabilidad (CVE), el parche o mitigación,
// y relaciona ambas partes al finding detectado.
func (o *Orchestrator) AssociateVulnerabilitiesAndRemediations(ctx context.Context, findingID int64, vuln *domain.Vulnerability, rem *domain.Remediation) error {
	if err := o.vulnPort.Save(ctx, vuln); err != nil {
		return err
	}
	if err := o.remediationPort.Save(ctx, rem); err != nil {
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

// GetTopAPTs obtiene la lista rankeada de Actores de Amenaza (APT) que más TTPs comparten
// con las vulnerabilidades detectadas en la infraestructura del usuario.
func (o *Orchestrator) GetTopAPTs(ctx context.Context) ([]domain.APTThreatResult, error) {
	return o.infraPort.GetTopAPTsByInfrastructureTTPs(ctx, 10)
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
func (o *Orchestrator) AutoScanAndRegisterVulnerabilities(ctx context.Context, installationID string, softwareID int64) error {
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
		if err := o.softwarePort.Save(ctx, sw); err != nil {
			return fmt.Errorf("error guardando software con CPE generado: %w", err)
		}
	}

	// 3. Buscar vulnerabilidades a través del puerto de escaneo
	vulns, err := o.vulnScannerPort.FetchByCPE(ctx, cpe)
	if err != nil {
		return fmt.Errorf("error consultando la API de vulnerabilidades para el CPE %s: %w", cpe, err)
	}

	// 4. Registrar vulnerabilidades y enlazarlas como hallazgos (Findings)
	for _, v := range vulns {
		vCopy := v
		if err := o.vulnPort.Save(ctx, &vCopy); err != nil {
			return fmt.Errorf("error al guardar la vulnerabilidad %s: %w", vCopy.CVEID, err)
		}

		// Guardar los parches si los hay y vincularlos a la vulnerabilidad
		for _, p := range vCopy.Patches {
			pCopy := p
			// Auto-increment simple id for patch
			idRes, err := o.dbHelper.ExecuteRead(ctx, "MATCH (p:Patch) RETURN coalesce(max(p.id), 0) AS maxId", nil)
			if err == nil && idRes != nil {
				if maxIdMap, ok := idRes.(map[string]any); ok {
					if maxId, ok := maxIdMap["maxId"].(int64); ok {
						pCopy.PatchID = maxId + 1
					} else if maxIdFloat, ok := maxIdMap["maxId"].(float64); ok {
						pCopy.PatchID = int64(maxIdFloat) + 1
					}
				}
			}
			if pCopy.PatchID == 0 {
				pCopy.PatchID = int64(rand.Int31n(1000000) + 1)
			}

			if err := o.patchPort.Save(ctx, &pCopy); err != nil {
				continue
			}
			// Vincular parche a la vulnerabilidad
			_ = o.relationshipPort.LinkPatchToVulnerability(ctx, pCopy.PatchID, vCopy.CVEID)
		}

		// Crear un Hallazgo (Finding) para conectar la instalación del software con el CVE detectado
		now := time.Now().UTC()
		findingID := int64(rand.Int31n(1000000) + 1)
		finding := &domain.Finding{ //TODO: retocar los valores por defectoooo TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO
			FindingID:         findingID,
			Status:            "OPEN",
			FirstSeen:         now,
			ImpactScore:       vCopy.BaseScore,
			Likelihood:        0.5,
			RemediationFactor: 1.0,
			RiskScore:         vCopy.BaseScore * 0.5,
		}

		if err := o.findingPort.Save(ctx, finding); err != nil {
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
		if err := o.vulnPort.Save(ctx, &vCopy); err != nil {
			continue // Loguear o continuar si una falla
		}

		for _, p := range vCopy.Patches {
			pCopy := p
			idRes, err := o.dbHelper.ExecuteRead(ctx, "MATCH (p:Patch) RETURN coalesce(max(p.id), 0) AS maxId", nil)
			if err == nil && idRes != nil {
				if maxIdMap, ok := idRes.(map[string]any); ok {
					if maxId, ok := maxIdMap["maxId"].(int64); ok {
						pCopy.PatchID = maxId + 1
					} else if maxIdFloat, ok := maxIdMap["maxId"].(float64); ok {
						pCopy.PatchID = int64(maxIdFloat) + 1
					}
				}
			}
			if pCopy.PatchID == 0 {
				pCopy.PatchID = int64(rand.Int31n(1000000) + 1)
			}
			if err := o.patchPort.Save(ctx, &pCopy); err == nil {
				_ = o.relationshipPort.LinkPatchToVulnerability(ctx, pCopy.PatchID, vCopy.CVEID)
			}
		}
	}
	return nil
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
