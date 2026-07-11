package neo4j

import (
	"context"

	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/domain"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/ports"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

type infrastructureRepo struct {
	driver neo4j.DriverWithContext
}

// NewInfrastructureRepository crea un repositorio para operaciones agregadas de infraestructura en Neo4j.
func NewInfrastructureRepository(driver neo4j.DriverWithContext) ports.InfrastructurePort {
	return &infrastructureRepo{driver: driver}
}

// GetGraphData recupera todos los nodos y relaciones de la base de datos Neo4j en un formato estructurado.
func (r *infrastructureRepo) GetGraphData(ctx context.Context) (*domain.GraphData, error) {
	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	// Consulta de lectura optimizada para obtener nodos y relaciones en una sola transacción
	query := `
		MATCH (n)
		WITH collect({id: elementId(n), labels: labels(n), properties: properties(n)}) AS nodes
		OPTIONAL MATCH (s)-[rel]->(t)
		WITH nodes, collect(case when rel is null then null else {id: elementId(rel), type: type(rel), source: elementId(s), target: elementId(t), properties: properties(rel)} end) AS relationships
		RETURN nodes, [r in relationships WHERE r IS NOT NULL] AS relationships
	`

	res, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
		result, err := tx.Run(ctx, query, nil)
		if err != nil {
			return nil, err
		}
		if result.Next(ctx) {
			return result.Record().AsMap(), nil
		}
		return nil, nil
	})
	if err != nil {
		return nil, err
	}

	graphData := &domain.GraphData{
		Nodes:         []domain.GraphNode{},
		Relationships: []domain.GraphRelationship{},
	}

	if res == nil {
		return graphData, nil
	}

	recordMap := res.(map[string]interface{})

	// Parsear Nodos
	if nodesRaw, ok := recordMap["nodes"].([]interface{}); ok {
		for _, nodeRaw := range nodesRaw {
			if nodeMap, ok := nodeRaw.(map[string]interface{}); ok {
				id, _ := nodeMap["id"].(string)
				labelsRaw, _ := nodeMap["labels"].([]interface{})
				labels := make([]string, len(labelsRaw))
				for i, l := range labelsRaw {
					labels[i], _ = l.(string)
				}
				props, _ := nodeMap["properties"].(map[string]interface{})

				graphData.Nodes = append(graphData.Nodes, domain.GraphNode{
					ID:         id,
					Labels:     labels,
					Properties: props,
				})
			}
		}
	}

	// Parsear Relaciones
	if relsRaw, ok := recordMap["relationships"].([]interface{}); ok {
		for _, relRaw := range relsRaw {
			if relMap, ok := relRaw.(map[string]interface{}); ok {
				id, _ := relMap["id"].(string)
				relType, _ := relMap["type"].(string)
				source, _ := relMap["source"].(string)
				target, _ := relMap["target"].(string)
				props, _ := relMap["properties"].(map[string]interface{})

				graphData.Relationships = append(graphData.Relationships, domain.GraphRelationship{
					ID:         id,
					Type:       relType,
					Source:     source,
					Target:     target,
					Properties: props,
				})
			}
		}
	}

	return graphData, nil
}

// CleanAndSeedInfrastructure limpia la base de datos Neo4j y carga un escenario completo de infraestructura de prueba.
func (r *infrastructureRepo) CleanAndSeedInfrastructure(ctx context.Context) error {
	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)

	_, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
		// 1. Limpieza de base de datos
		_, err := tx.Run(ctx, "MATCH (n) DETACH DELETE n", nil)
		if err != nil {
			return nil, err
		}

		// 2. Ingesta del escenario completo de infraestructura y vectores de ataque
		seedQuery := `
			// 1. Crear Proyecto Principal
			CREATE (p:Project {id: 1, name: "Proyecto Auditoría Interna 2026", description: "Evaluación de seguridad de la infraestructura corporativa principal y simulador de rutas de ataque"})

			// 2. Redes / Subredes
			CREATE (n_dmz:Network {id: 10, name: "DMZ", cidr: "192.168.10.0/24", description: "Zona desmilitarizada expuesta a Internet"})
			CREATE (n_lan:Network {id: 20, name: "LAN Interna", cidr: "10.0.1.0/24", description: "Red interna corporativa para empleados y lógica de negocio"})
			CREATE (n_db:Network {id: 30, name: "Subred Datos", cidr: "10.0.2.0/24", description: "Segmento aislado críticamente para servidores de almacenamiento de datos"})

			// 3. Equipos (Endpoints)
			CREATE (e_gateway:Endpoint {id: 100, hostname: "web-gateway-01", type: "Linux Server", status: "Active", environment: "Production", internet_exposed: true, risk_score: 8.5, risk_tier: "CRITICAL"})
			CREATE (e_app:Endpoint {id: 101, hostname: "app-server-01", type: "Linux Server", status: "Active", environment: "Production", internet_exposed: false, risk_score: 6.8, risk_tier: "HIGH"})
			CREATE (e_db:Endpoint {id: 102, hostname: "db-prod-01", type: "Windows Server", status: "Active", environment: "Production", internet_exposed: false, risk_score: 9.2, risk_tier: "CRITICAL"})
			CREATE (e_workstation:Endpoint {id: 103, hostname: "pc-admin-99", type: "Windows Client", status: "Active", environment: "Development", internet_exposed: false, risk_score: 4.5, risk_tier: "MEDIUM"})

			// 4. Componentes de Hardware
			CREATE (h1:Hardware {id: 200, name: "Intel Xeon Platinum", brand: "Intel", model: "vCPU 8-Core", serial_number: "VCPU-INTEL-001"})
			CREATE (h2:Hardware {id: 201, name: "AMD EPYC Epyc", brand: "AMD", model: "vCPU 16-Core", serial_number: "VCPU-AMD-002"})

			// 5. Definiciones de Software
			CREATE (s_nginx:Software {id: 300, name: "Nginx HTTP Server", version: "1.18.0", vendor: "Nginx"})
			CREATE (s_java:Software {id: 301, name: "Oracle Java JRE", version: "1.8.0_121", vendor: "Oracle"})
			CREATE (s_mssql:Software {id: 302, name: "Microsoft SQL Server", version: "2019", vendor: "Microsoft"})
			CREATE (s_smb:Software {id: 303, name: "Windows SMB v1", version: "1.0", vendor: "Microsoft"})

			// 6. Instancias Instaladas de Software
			CREATE (si_nginx:SoftwareInstallation {id: "si-001", status: "Running", path: "/etc/nginx"})
			CREATE (si_java:SoftwareInstallation {id: "si-002", status: "Running", path: "/usr/lib/jvm/java-8"})
			CREATE (si_mssql:SoftwareInstallation {id: "si-003", status: "Running", path: "C:\\Program Files\\Microsoft SQL Server"})
			CREATE (si_smb:SoftwareInstallation {id: "si-004", status: "Running", path: "System32\\drivers\\srv.sys"})

			// 7. Hallazgos de Seguridad (Findings)
			CREATE (f_nginx:Finding {id: 400, title: "Versión de Nginx obsoleta", severity: "MEDIUM", description: "Servidor nginx desactualizado con fuga potencial de versión en cabeceras HTTP"})
			CREATE (f_java:Finding {id: 401, title: "Log4Shell RCE Crítico", severity: "CRITICAL", description: "Biblioteca interna Log4j expuesta a inyección JNDI maliciosa"})
			CREATE (f_mssql:Finding {id: 402, title: "Credenciales SA por defecto", severity: "HIGH", description: "Configuración inicial sin rotación del administrador de la base de datos"})
			CREATE (f_smb:Finding {id: 403, title: "SMBv1 Habilitado y Vulnerable", severity: "CRITICAL", description: "El protocolo SMB versión 1 está activo, exponiendo la máquina a EternalBlue"})

			// 8. Vulnerabilidades (CVEs)
			CREATE (v_log4shell:Vulnerability {cve_id: "CVE-2021-44228", description: "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP endpoints, causing Remote Code Execution (RCE).", severity: "CRITICAL"})
			CREATE (v_eternalblue:Vulnerability {cve_id: "CVE-2017-0144", description: "Remote code execution vulnerability in Microsoft Server Message Block 1.0 (SMBv1) protocol (MS17-010).", severity: "CRITICAL"})
			CREATE (v_curve3d:Vulnerability {cve_id: "CVE-2020-0601", description: "Windows CryptoAPI spoofing vulnerability that bypasses Authenticode signature verification.", severity: "HIGH"})

			// 9. Mitigaciones y Parches
			CREATE (rem_log4shell:Remediation {id: 500, description: "Deshabilitar lookup JNDI mediante variables de entorno o actualizar log4j2 a la versión 2.17.1.", status: "Open"})
			CREATE (rem_eternalblue:Remediation {id: 501, description: "Deshabilitar el protocolo SMBv1 en el registro del sistema y aplicar parche acumulativo de seguridad.", status: "Open"})
			CREATE (p_ms17010:Patch {id: 600, name: "MS17-010 Security Update", description: "Parche oficial de seguridad de Microsoft para mitigar la explotación remota de SMBv1."})

			// 10. Tácticas, Técnicas y Procedimientos (TTP - MITRE ATT&CK)
			CREATE (ttp_rce:TTP {id: "T1190", name: "Exploit Public-Facing Application", description: "Uso de vulnerabilidades de software para obtener acceso inicial a la infraestructura corporativa"})
			CREATE (ttp_lateral:TTP {id: "T1210", name: "Exploitation of Remote Services", description: "Explotación de servicios expuestos internamente por red para movimiento lateral"})

			// 11. Actores de Amenaza (Threat Actors)
			CREATE (ta_cozy:ThreatActor {id: "TA-APT29", name: "Cozy Bear (APT29)", motivation: "Espionage", origin: "Russia"})
			CREATE (ta_lazarus:ThreatActor {id: "TA-APT38", name: "Lazarus Group (APT38)", motivation: "Financial / Cyber-warfare", origin: "North Korea"})

			// ==========================================
			// RELACIONES DEL GRAFO DE INFRAESTRUCTURA
			// ==========================================
			// Enlazar Proyecto a Endpoints
			CREATE (p)-[:HAS_ENDPOINT]->(e_gateway)
			CREATE (p)-[:HAS_ENDPOINT]->(e_app)
			CREATE (p)-[:HAS_ENDPOINT]->(e_db)
			CREATE (p)-[:HAS_ENDPOINT]->(e_workstation)

			// Conectividad de Redes
			CREATE (e_gateway)-[:CONNECTED_TO]->(n_dmz)
			CREATE (e_app)-[:CONNECTED_TO]->(n_lan)
			CREATE (e_db)-[:CONNECTED_TO]->(n_db)
			CREATE (e_workstation)-[:CONNECTED_TO]->(n_lan)

			// Asignación de Hardware
			CREATE (e_gateway)-[:HAS_HARDWARE]->(h1)
			CREATE (e_app)-[:HAS_HARDWARE]->(h1)
			CREATE (e_db)-[:HAS_HARDWARE]->(h2)

			// Asignación de Instalaciones de Software
			CREATE (e_gateway)-[:HAS_INSTALLATION]->(si_nginx)
			CREATE (e_app)-[:HAS_INSTALLATION]->(si_java)
			CREATE (e_db)-[:HAS_INSTALLATION]->(si_mssql)
			CREATE (e_db)-[:HAS_INSTALLATION]->(si_smb)

			// Instalación -> Definición General
			CREATE (si_nginx)-[:INSTANCE_OF]->(s_nginx)
			CREATE (si_java)-[:INSTANCE_OF]->(s_java)
			CREATE (si_mssql)-[:INSTANCE_OF]->(s_mssql)
			CREATE (si_smb)-[:INSTANCE_OF]->(s_smb)

			// Relación de Vulnerabilidades encontradas en Instalaciones
			CREATE (si_nginx)-[:HAS_FINDING]->(f_nginx)
			CREATE (si_java)-[:HAS_FINDING]->(f_java)
			CREATE (si_mssql)-[:HAS_FINDING]->(f_mssql)
			CREATE (si_smb)-[:HAS_FINDING]->(f_smb)

			// Hallazgo -> CVEs
			CREATE (f_java)-[:OF_VULNERABILITY]->(v_log4shell)
			CREATE (f_smb)-[:OF_VULNERABILITY]->(v_eternalblue)

			// Hallazgo -> Mitigaciones
			CREATE (f_java)-[:HAS_REMEDIATION]->(rem_log4shell)
			CREATE (f_smb)-[:HAS_REMEDIATION]->(rem_eternalblue)

			// Remediation -> Parche
			CREATE (rem_eternalblue)-[:USES_PATCH]->(p_ms17010)

			// Parche -> CVE que arregla
			CREATE (p_ms17010)-[:FIXES]->(v_eternalblue)

			// Actor de Amenaza -> TTP que suele usar
			CREATE (ta_cozy)-[:USES_TTP]->(ttp_rce)
			CREATE (ta_lazarus)-[:USES_TTP]->(ttp_lateral)

			// TTP -> CVE que ataca
			CREATE (ttp_rce)-[:TARGETS_VULN]->(v_log4shell)
			CREATE (ttp_lateral)-[:TARGETS_VULN]->(v_eternalblue)
		`
		_, err = tx.Run(ctx, seedQuery, nil)
		return nil, err
	})

	return err
}
