package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/adapters/provider"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/adapters/repository/neo4j"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/config"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/domain"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/service"
	neo4jdriver "github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

const (
	projectID      int64  = 9701
	endpointID     int64  = 9702
	hardwareID     int64  = 9703
	networkID      int64  = 9704
	softwareID     int64  = 9705
	installationID string = "inst-front-validation-tomcat"
)

func main() {
	fmt.Println("=== PRUEBA GENERATE PROJECT FRONT VALIDATION ===")

	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Error cargando config: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	driver, err := neo4j.NewDriver(ctx, cfg)
	if err != nil {
		log.Fatalf("Error conectando a Neo4j: %v", err)
	}
	defer driver.Close(ctx)

	endpointRepo, vulnRepo, softwareRepo, softwareInstRepo, findingRepo, remediationRepo, _, hardwareRepo, networkRepo, patchRepo, projectRepo, dbHelper, relRepo, containerRepo := neo4j.NewRepository(driver)
	infraRepo := neo4j.NewInfrastructureRepository(driver)
	riskRepo := neo4j.NewRiskRepository(driver)

	orchestrator := service.NewOrchestrator(
		projectRepo,
		endpointRepo,
		hardwareRepo,
		networkRepo,
		softwareInstRepo,
		softwareRepo,
		findingRepo,
		vulnRepo,
		remediationRepo,
		relRepo,
		infraRepo,
		containerRepo,
		patchRepo,
		dbHelper,
		provider.NewNistAPIAdapter(cfg.NVD.BaseURL, cfg.NVD.APIKey, cfg.NVD.TimeoutSeconds),
	).WithRisk(riskRepo, provider.NewEPSSAdapter(), provider.NewKEVAdapter())

	fmt.Println("[1/4] Cleaning previous mock data...")
	if err := cleanMockData(ctx, driver); err != nil {
		log.Fatalf("Error limpiando mock data: %v", err)
	}

	fmt.Println("[2/4] Creating project...")
	project := &domain.Project{
		ProjectID: projectID,
		Nombre:    "Frontend Validation Project",
	}
	if err := orchestrator.CreateProject(ctx, project); err != nil {
		log.Fatalf("Error creando proyecto: %v", err)
	}

	fmt.Println("[3/4] Creating endpoint, hardware, network and software installation...")
	endpoint := &domain.Endpoint{
		EndpointID:         endpointID,
		Hostname:           "front-validation-tomcat",
		Type:               "Linux",
		Status:             "ACTIVE",
		InternetExposed:    true,
		Environment:        "production",
		ConfidentialityReq: "High",
		IntegrityReq:       "High",
		AvailabilityReq:    "Medium",
	}
	if err := orchestrator.AddEndpointToProject(ctx, projectID, endpoint); err != nil {
		log.Fatalf("Error creando endpoint: %v", err)
	}

	hardware := &domain.Hardware{
		HardwareID:   hardwareID,
		Model:        "Front Validation VM",
		Type:         "server",
		Manufacturer: "local",
		CPU:          "2 vCPU",
		RAMGB:        4,
		StorageGB:    40,
	}
	if err := orchestrator.AssociateHardwareToEndpoint(ctx, endpointID, hardware); err != nil {
		log.Fatalf("Error creando hardware: %v", err)
	}

	network := &domain.Network{
		NetworkID:   networkID,
		Nombre:      "front-validation-net",
		CIDR:        "10.97.0.0/24",
		Gateway:     "10.97.0.1",
		VLANID:      970,
		Descripcion: "Network for frontend validation",
	}
	if _, _, err := orchestrator.CreateNetwork(ctx, network); err != nil {
		log.Fatalf("Error creando network: %v", err)
	}

	software := &domain.Software{
		SoftwareID: softwareID,
		Name:       "tomcat",
		Version:    "9.0.37",
		Type:       "application",
		Vendor:     "apache",
		CPE:        "cpe:2.3:a:apache:tomcat:9.0.37:*:*:*:*:*:*:*",
	}
	installation := &domain.SoftwareInstallation{
		InstallationID:   installationID,
		FirstSeen:        time.Now().UTC(),
		Status:           "INSTALLED",
		InstallPath:      "/opt/tomcat",
		DetectedBy:       "mock",
		PackageManager:   "manual",
		CriticalityLevel: "HIGH",
	}
	if err := orchestrator.RegisterSoftwareInstallation(ctx, endpointID, software, installation); err != nil {
		log.Fatalf("Error registrando software installation: %v", err)
	}

	fmt.Println("[4/4] Mock project ready.")
	fmt.Println("Project ID:", projectID)
	fmt.Println("Endpoint ID:", endpointID)
	fmt.Println("Software ID:", softwareID)
	fmt.Println("Installation ID:", installationID)
	fmt.Println("Next frontend steps:")
	fmt.Println("  1. Open dashboard")
	fmt.Println("  2. Select 'Frontend Validation Project'")
	fmt.Println("  3. Click 'Analizar vulnerabilidades'")
	fmt.Println("  4. Click 'Calcular riesgo'")
}

func cleanMockData(ctx context.Context, driver neo4jdriver.DriverWithContext) error {
	session := driver.NewSession(ctx, neo4jdriver.SessionConfig{AccessMode: neo4jdriver.AccessModeWrite})
	defer session.Close(ctx)

	_, err := session.ExecuteWrite(ctx, func(tx neo4jdriver.ManagedTransaction) (any, error) {
		projectCleanup := `
			MATCH (p:Project {id: $project_id})
			OPTIONAL MATCH (p)-[:HAS_ENDPOINT]->(e)
			OPTIONAL MATCH (e)-[:HAS_HARDWARE]->(h)
			OPTIONAL MATCH (e)-[:CONNECTED_TO]->(net)
			OPTIONAL MATCH (e)-[:HAS_INSTALLATION]->(si)
			OPTIONAL MATCH (si)-[:INSTANCE_OF]->(s)
			OPTIONAL MATCH (si)-[:HAS_FINDING]->(f)
			OPTIONAL MATCH (f)-[:HAS_REMEDIATION]->(r)
			WITH collect(p) + collect(e) + collect(h) + collect(net) + collect(si) + collect(s) + collect(f) + collect(r) AS nodes
			UNWIND nodes AS n
			WITH DISTINCT n
			WHERE n IS NOT NULL
			DETACH DELETE n
		`
		if _, err := tx.Run(ctx, projectCleanup, map[string]any{"project_id": projectID}); err != nil {
			return nil, err
		}

		orphanCleanup := `
			MATCH (n)
			WHERE n.id IN [$endpoint_id, $hardware_id, $network_id, $software_id]
			   OR n.id = $installation_id
			   OR n.hostname = 'front-validation-tomcat'
			   OR n.nombre = 'Frontend Validation Project'
			   OR n.nombre = 'front-validation-net'
			DETACH DELETE n
		`
		_, err := tx.Run(ctx, orphanCleanup, map[string]any{
			"endpoint_id":     endpointID,
			"hardware_id":     hardwareID,
			"network_id":      networkID,
			"software_id":     softwareID,
			"installation_id": installationID,
		})
		return nil, err
	})

	return err
}
