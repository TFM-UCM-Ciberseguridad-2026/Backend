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
		WHERE NOT n:ThreatActor AND NOT n:TTP
		WITH collect({id: elementId(n), labels: labels(n), properties: properties(n)}) AS nodes
		OPTIONAL MATCH (s)-[rel]->(t)
		WHERE NOT s:ThreatActor AND NOT s:TTP AND NOT t:ThreatActor AND NOT t:TTP
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
			CREATE (s_crypto:Software {id: 304, name: "Windows CryptoAPI", version: "10.0", vendor: "Microsoft"})

			// 6. Instancias Instaladas de Software
			CREATE (si_nginx:SoftwareInstallation {id: "si-001", status: "Running", path: "/etc/nginx"})
			CREATE (si_java:SoftwareInstallation {id: "si-002", status: "Running", path: "/usr/lib/jvm/java-8"})
			CREATE (si_mssql:SoftwareInstallation {id: "si-003", status: "Running", path: "C:\\Program Files\\Microsoft SQL Server"})
			CREATE (si_smb:SoftwareInstallation {id: "si-004", status: "Running", path: "System32\\drivers\\srv.sys"})
			CREATE (si_crypto:SoftwareInstallation {id: "si-005", status: "Running", path: "System32\\crypt32.dll"})

			// 7. Hallazgos de Seguridad (Findings)
			CREATE (f_nginx:Finding {id: 400, title: "Versión de Nginx obsoleta", severity: "MEDIUM", description: "Servidor nginx desactualizado con fuga potencial de versión en cabeceras HTTP"})
			CREATE (f_java:Finding {id: 401, title: "Log4Shell RCE Crítico", severity: "CRITICAL", description: "Biblioteca interna Log4j expuesta a inyección JNDI maliciosa"})
			CREATE (f_mssql:Finding {id: 402, title: "Credenciales SA por defecto", severity: "HIGH", description: "Configuración inicial sin rotación del administrador de la base de datos"})
			CREATE (f_smb:Finding {id: 403, title: "SMBv1 Habilitado y Vulnerable", severity: "CRITICAL", description: "El protocolo SMB versión 1 está activo, exponiendo la máquina a EternalBlue"})
			CREATE (f_crypto:Finding {id: 404, title: "CryptoAPI Signature Spoofing", severity: "HIGH", description: "La API criptográfica de Windows permite suplantación de firmas Authenticode y certificados ECC"})

			// 8. Vulnerabilidades (CVEs)
			CREATE (v_log4shell:Vulnerability {cve_id: "CVE-2021-44228", description: "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP endpoints, causing Remote Code Execution (RCE).", severity: "CRITICAL"})
			CREATE (v_eternalblue:Vulnerability {cve_id: "CVE-2017-0144", description: "Remote code execution vulnerability in Microsoft Server Message Block 1.0 (SMBv1) protocol (MS17-010).", severity: "CRITICAL"})
			CREATE (v_cryptoapi:Vulnerability {cve_id: "CVE-2020-0601", description: "Windows CryptoAPI spoofing vulnerability that bypasses Authenticode signature verification.", severity: "HIGH"})

			// 9. Mitigaciones y Parches
			CREATE (rem_log4shell:Remediation {id: 500, description: "Deshabilitar lookup JNDI mediante variables de entorno o actualizar log4j2 a la versión 2.17.1.", status: "Open"})
			CREATE (rem_eternalblue:Remediation {id: 501, description: "Deshabilitar el protocolo SMBv1 en el registro del sistema y aplicar parche acumulativo de seguridad.", status: "Open"})
			CREATE (rem_cryptoapi:Remediation {id: 502, description: "Aplicar la actualización de seguridad KB4528760 para Windows 10 y Server 2016/2019.", status: "Open"})
			CREATE (p_ms17010:Patch {id: 600, name: "MS17-010 Security Update", description: "Parche oficial de seguridad de Microsoft para mitigar la explotación remota de SMBv1."})
			CREATE (p_kb4528760:Patch {id: 601, name: "KB4528760 Security Update", description: "Actualización de seguridad para la vulnerabilidad de suplantación de CryptoAPI."})

			// 10. Tácticas, Técnicas y Procedimientos (TTP - MITRE ATT&CK) - 8 TTPs
			CREATE (ttp_t1190:TTP {id: "T1190", name: "Exploit Public-Facing Application", description: "Uso de vulnerabilidades de software en aplicaciones expuestas a Internet para obtener acceso inicial"})
			CREATE (ttp_t1210:TTP {id: "T1210", name: "Exploitation of Remote Services", description: "Explotación de servicios expuestos internamente por red para movimiento lateral"})
			CREATE (ttp_t1059:TTP {id: "T1059", name: "Command and Scripting Interpreter", description: "Uso de intérpretes de comandos y scripts para ejecutar código arbitrario en el sistema comprometido"})
			CREATE (ttp_t1078:TTP {id: "T1078", name: "Valid Accounts", description: "Uso de credenciales legítimas robadas o predeterminadas para obtener acceso y persistencia"})
			CREATE (ttp_t1021:TTP {id: "T1021", name: "Remote Services", description: "Uso de servicios remotos legítimos (RDP, SSH, SMB) para acceder a sistemas internos"})
			CREATE (ttp_t1071:TTP {id: "T1071", name: "Application Layer Protocol", description: "Uso de protocolos de capa de aplicación (HTTP, DNS) para establecer canales de C2"})
			CREATE (ttp_t1105:TTP {id: "T1105", name: "Ingress Tool Transfer", description: "Transferencia de herramientas y payloads desde un sistema externo al entorno comprometido"})
			CREATE (ttp_t1053:TTP {id: "T1053", name: "Scheduled Task/Job", description: "Uso de tareas programadas del sistema para ejecutar código malicioso de forma persistente"})

			// 11. Actores de Amenaza (Threat Actors) - 5 APT Groups
			CREATE (ta_apt29:ThreatActor {id: "TA-APT29", name: "Cozy Bear (APT29)", motivation: "Espionage", origin: "Russia"})
			CREATE (ta_apt38:ThreatActor {id: "TA-APT38", name: "Lazarus Group (APT38)", motivation: "Financial / Cyber-warfare", origin: "North Korea"})
			CREATE (ta_apt41:ThreatActor {id: "TA-APT41", name: "Winnti Group (APT41)", motivation: "Espionage / Financial", origin: "China"})
			CREATE (ta_apt28:ThreatActor {id: "TA-APT28", name: "Fancy Bear (APT28)", motivation: "Espionage / Disruption", origin: "Russia"})
			CREATE (ta_fin7:ThreatActor {id: "TA-FIN7", name: "FIN7 (Carbanak)", motivation: "Financial", origin: "Eastern Europe"})

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
			CREATE (e_workstation)-[:HAS_INSTALLATION]->(si_crypto)

			// Instalación -> Definición General
			CREATE (si_nginx)-[:INSTANCE_OF]->(s_nginx)
			CREATE (si_java)-[:INSTANCE_OF]->(s_java)
			CREATE (si_mssql)-[:INSTANCE_OF]->(s_mssql)
			CREATE (si_smb)-[:INSTANCE_OF]->(s_smb)
			CREATE (si_crypto)-[:INSTANCE_OF]->(s_crypto)

			// Relación de Vulnerabilidades encontradas en Instalaciones
			CREATE (si_nginx)-[:HAS_FINDING]->(f_nginx)
			CREATE (si_java)-[:HAS_FINDING]->(f_java)
			CREATE (si_mssql)-[:HAS_FINDING]->(f_mssql)
			CREATE (si_smb)-[:HAS_FINDING]->(f_smb)
			CREATE (si_crypto)-[:HAS_FINDING]->(f_crypto)

			// Hallazgo -> CVEs
			CREATE (f_java)-[:OF_VULNERABILITY]->(v_log4shell)
			CREATE (f_smb)-[:OF_VULNERABILITY]->(v_eternalblue)
			CREATE (f_crypto)-[:OF_VULNERABILITY]->(v_cryptoapi)

			// Hallazgo -> Mitigaciones
			CREATE (f_java)-[:HAS_REMEDIATION]->(rem_log4shell)
			CREATE (f_smb)-[:HAS_REMEDIATION]->(rem_eternalblue)
			CREATE (f_crypto)-[:HAS_REMEDIATION]->(rem_cryptoapi)

			// Remediation -> Parche
			CREATE (rem_eternalblue)-[:USES_PATCH]->(p_ms17010)
			CREATE (rem_cryptoapi)-[:USES_PATCH]->(p_kb4528760)

			// Parche -> CVE que arregla
			CREATE (p_ms17010)-[:FIXES]->(v_eternalblue)
			CREATE (p_kb4528760)-[:FIXES]->(v_cryptoapi)

			// ==========================================
			// RELACIONES TTP -> CVE (TARGETS_VULN)
			// ==========================================
			CREATE (ttp_t1190)-[:TARGETS_VULN]->(v_log4shell)
			CREATE (ttp_t1210)-[:TARGETS_VULN]->(v_eternalblue)
			CREATE (ttp_t1059)-[:TARGETS_VULN]->(v_log4shell)
			CREATE (ttp_t1078)-[:TARGETS_VULN]->(v_cryptoapi)
			CREATE (ttp_t1021)-[:TARGETS_VULN]->(v_eternalblue)
			CREATE (ttp_t1071)-[:TARGETS_VULN]->(v_log4shell)
			CREATE (ttp_t1105)-[:TARGETS_VULN]->(v_eternalblue)
			CREATE (ttp_t1053)-[:TARGETS_VULN]->(v_cryptoapi)

			// ==========================================
			// RELACIONES THREAT ACTOR -> TTP (USES_TTP)
			// ==========================================
			// APT29 (Cozy Bear): T1190, T1059, T1078, T1071, T1053, T1105 → 6 TTPs
			CREATE (ta_apt29)-[:USES_TTP]->(ttp_t1190)
			CREATE (ta_apt29)-[:USES_TTP]->(ttp_t1059)
			CREATE (ta_apt29)-[:USES_TTP]->(ttp_t1078)
			CREATE (ta_apt29)-[:USES_TTP]->(ttp_t1071)
			CREATE (ta_apt29)-[:USES_TTP]->(ttp_t1053)
			CREATE (ta_apt29)-[:USES_TTP]->(ttp_t1105)

			// APT41 (Winnti): T1190, T1059, T1071, T1105, T1210, T1053 → 6 TTPs
			CREATE (ta_apt41)-[:USES_TTP]->(ttp_t1190)
			CREATE (ta_apt41)-[:USES_TTP]->(ttp_t1059)
			CREATE (ta_apt41)-[:USES_TTP]->(ttp_t1071)
			CREATE (ta_apt41)-[:USES_TTP]->(ttp_t1105)
			CREATE (ta_apt41)-[:USES_TTP]->(ttp_t1210)
			CREATE (ta_apt41)-[:USES_TTP]->(ttp_t1053)

			// APT28 (Fancy Bear): T1210, T1078, T1021, T1053 → 4 TTPs
			CREATE (ta_apt28)-[:USES_TTP]->(ttp_t1210)
			CREATE (ta_apt28)-[:USES_TTP]->(ttp_t1078)
			CREATE (ta_apt28)-[:USES_TTP]->(ttp_t1021)
			CREATE (ta_apt28)-[:USES_TTP]->(ttp_t1053)

			// APT38 (Lazarus): T1210, T1021, T1105 → 3 TTPs
			CREATE (ta_apt38)-[:USES_TTP]->(ttp_t1210)
			CREATE (ta_apt38)-[:USES_TTP]->(ttp_t1021)
			CREATE (ta_apt38)-[:USES_TTP]->(ttp_t1105)

			// FIN7 (Carbanak): T1059, T1078, T1053 → 3 TTPs
			CREATE (ta_fin7)-[:USES_TTP]->(ttp_t1059)
			CREATE (ta_fin7)-[:USES_TTP]->(ttp_t1078)
			CREATE (ta_fin7)-[:USES_TTP]->(ttp_t1053)
		`
		_, err = tx.Run(ctx, seedQuery, nil)
		return nil, err
	})

	return err
}

// GetTopAPTsByInfrastructureTTPs recorre el grafo completo desde la infraestructura del usuario
// hasta los actores de amenaza, calculando qué APTs cubren más TTPs vinculadas a las CVEs detectadas.
// Cadena de traversal: Project → Endpoint → SoftwareInstallation → Finding → Vulnerability ← TTP ← ThreatActor
func (r *infrastructureRepo) GetTopAPTsByInfrastructureTTPs(ctx context.Context, limit int) ([]domain.APTThreatResult, error) {
	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	// Consulta Cypher que:
	// 1. Encuentra todas las TTPs únicas vinculadas a las vulnerabilidades de la infraestructura
	// 2. Para cada ThreatActor, cuenta cuántas de esas TTPs utiliza
	// 3. Calcula el porcentaje de cobertura y ordena descendentemente
	query := `
		// Paso 1: Obtener todas las TTPs únicas que apuntan a CVEs de la infraestructura
		MATCH (p:Project)-[:HAS_ENDPOINT]->(e:Endpoint)-[:HAS_INSTALLATION]->(si:SoftwareInstallation)
		      -[:HAS_FINDING]->(f:Finding)-[:OF_VULNERABILITY]->(v:Vulnerability)<-[:TARGETS_VULN]-(ttp:TTP)
		WITH collect(DISTINCT ttp) AS infraTTPs

		// Paso 2: Para cada ThreatActor, calcular solapamiento con las TTPs de la infraestructura
		UNWIND infraTTPs AS infraTTP
		WITH infraTTPs, infraTTP
		MATCH (ta:ThreatActor)-[:USES_TTP]->(infraTTP)
		WITH ta, infraTTPs,
		     collect(DISTINCT infraTTP) AS matchedTTPs

		// Paso 3: Calcular métricas y ordenar
		WITH ta,
		     size(infraTTPs) AS totalInfraTTPs,
		     size(matchedTTPs) AS matchedCount,
		     [t IN matchedTTPs | t.name] AS matchedNames,
		     [t IN matchedTTPs | t.id] AS matchedIDs
		RETURN ta.id AS actor_id,
		       ta.name AS actor_name,
		       ta.origin AS origin,
		       ta.motivation AS motivation,
		       matchedCount AS matched_ttp_count,
		       totalInfraTTPs AS total_infra_ttps,
		       round(toFloat(matchedCount) / totalInfraTTPs * 10000) / 100 AS coverage_percent,
		       matchedNames AS matched_ttp_names,
		       matchedIDs AS matched_ttp_ids
		ORDER BY matchedCount DESC, ta.name ASC
		LIMIT $limit
	`

	res, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
		result, err := tx.Run(ctx, query, map[string]any{"limit": limit})
		if err != nil {
			return nil, err
		}

		var results []domain.APTThreatResult
		for result.Next(ctx) {
			record := result.Record()
			actorID, _ := record.Get("actor_id")
			actorName, _ := record.Get("actor_name")
			origin, _ := record.Get("origin")
			motivation, _ := record.Get("motivation")
			matchedCount, _ := record.Get("matched_ttp_count")
			totalInfra, _ := record.Get("total_infra_ttps")
			coverage, _ := record.Get("coverage_percent")
			namesRaw, _ := record.Get("matched_ttp_names")
			idsRaw, _ := record.Get("matched_ttp_ids")

			// Parsear listas de strings
			var matchedNames []string
			if namesList, ok := namesRaw.([]interface{}); ok {
				for _, n := range namesList {
					if s, ok := n.(string); ok {
						matchedNames = append(matchedNames, s)
					}
				}
			}

			var matchedIDs []string
			if idsList, ok := idsRaw.([]interface{}); ok {
				for _, n := range idsList {
					if s, ok := n.(string); ok {
						matchedIDs = append(matchedIDs, s)
					}
				}
			}

			results = append(results, domain.APTThreatResult{
				ActorID:         actorID.(string),
				ActorName:       actorName.(string),
				Origin:          origin.(string),
				Motivation:      motivation.(string),
				MatchedTTPCount: int(matchedCount.(int64)),
				TotalInfraTTPs:  int(totalInfra.(int64)),
				CoveragePercent: coverage.(float64),
				MatchedTTPNames: matchedNames,
				MatchedTTPIDs:   matchedIDs,
			})
		}

		return results, result.Err()
	})

	if err != nil {
		return nil, err
	}

	if res == nil {
		return []domain.APTThreatResult{}, nil
	}

	return res.([]domain.APTThreatResult), nil
}
