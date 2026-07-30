package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/adapters/repository/neo4j"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/config"
)

func main() {
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Error cargando configuración: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	driver, err := neo4j.NewDriver(ctx, cfg)
	if err != nil {
		log.Fatalf("Error conectando a Neo4j: %v", err)
	}
	defer driver.Close(ctx)

	// Instanciamos sólo para obtener el DatabaseHelper
	_, _, _, _, _, _, _, _, _, _, _, dbHelper, _ , _ := neo4j.NewRepository(driver)

	// 1. Limpieza de base de datos
	err = dbHelper.ExecuteWrite(ctx, "MATCH (n) DETACH DELETE n", nil)
	if err != nil {
		log.Fatalf("Error limpiando base de datos: %v", err)
	}

	// 2. Ingesta del escenario completo de infraestructura y vectores de ataque
	seedQuery := `
		// 1. Crear Proyecto Principal
		CREATE (p:Project {id: 1, name: "Proyecto Auditoría Interna 2026", description: "Evaluación de seguridad de la infraestructura corporativa principal y simulador de rutas de ataque"})

		// 2. Redes / Subredes
		CREATE (n_dmz:Network {id: 10, name: "DMZ Perimetral", cidr: "192.168.10.0/24", description: "Zona desmilitarizada expuesta a Internet"})
		CREATE (n_lan:Network {id: 20, name: "LAN Interna", cidr: "10.0.1.0/24", description: "Red interna corporativa para empleados y lógica de negocio"})
		CREATE (n_db:Network {id: 30, name: "Subred Datos", cidr: "10.0.2.0/24", description: "Segmento aislado críticamente para servidores de almacenamiento de datos"})
		CREATE (n_mgmt:Network {id: 40, name: "Red Gestión & AD", cidr: "10.0.99.0/24", description: "Segmento de administración y servicios de directorio Active Directory"})

		// 3. Equipos (Endpoints) - Representando los roles funcionalmente
		CREATE (e_gateway:Endpoint {id: 100, hostname: "web-gateway-01", type: "Server", status: "Active", environment: "Production", internet_exposed: true, risk_score: 8.5, risk_tier: "CRITICAL"})
		CREATE (e_app:Endpoint {id: 101, hostname: "app-server-01", type: "Server", status: "Active", environment: "Production", internet_exposed: false, risk_score: 6.8, risk_tier: "HIGH"})
		CREATE (e_db:Endpoint {id: 102, hostname: "db-prod-01", type: "Server", status: "Active", environment: "Production", internet_exposed: false, risk_score: 9.2, risk_tier: "CRITICAL"})
		CREATE (e_workstation:Endpoint {id: 103, hostname: "pc-admin-99", type: "Workstation", status: "Active", environment: "Development", internet_exposed: false, risk_score: 4.5, risk_tier: "MEDIUM"})
		CREATE (e_dc:Endpoint {id: 104, hostname: "dc-corp-01", type: "Domain Controller", status: "Active", environment: "Production", internet_exposed: false, risk_score: 9.5, risk_tier: "CRITICAL"})
		CREATE (e_fw:Endpoint {id: 105, hostname: "fw-edge-perimeter", type: "Firewall", status: "Active", environment: "Production", internet_exposed: true, risk_score: 8.8, risk_tier: "CRITICAL"})
		CREATE (e_router:Endpoint {id: 106, hostname: "rtr-core-01", type: "Router", status: "Active", environment: "Production", internet_exposed: false, risk_score: 5.2, risk_tier: "MEDIUM"})
		CREATE (e_workstation2:Endpoint {id: 107, hostname: "pc-user-42", type: "Workstation", status: "Active", environment: "Production", internet_exposed: false, risk_score: 3.2, risk_tier: "LOW"})

		// 4. Componentes de Hardware
		CREATE (h1:Hardware {id: 200, name: "Intel Xeon Platinum", brand: "Intel", model: "vCPU 8-Core", serial_number: "VCPU-INTEL-001"})
		CREATE (h2:Hardware {id: 201, name: "AMD EPYC Epyc", brand: "AMD", model: "vCPU 16-Core", serial_number: "VCPU-AMD-002"})
		CREATE (h3:Hardware {id: 202, name: "Fortinet FortiGate 100F", brand: "Fortinet", model: "FG-100F", serial_number: "FG100F-SN-987"})
		CREATE (h4:Hardware {id: 203, name: "Cisco Catalyst 9300", brand: "Cisco", model: "C9300-24T", serial_number: "CISCO-CAT93-004"})

		// 5. Definiciones de Software (clasificación CPE: 'a' app, 'o' sistema operativo, 'h' hardware)
		CREATE (s_nginx:Software {id: 300, name: "Nginx HTTP Server", version: "1.18.0", vendor: "Nginx", type: "a"})
		CREATE (s_java:Software {id: 301, name: "Oracle Java JRE", version: "1.8.0_121", vendor: "Oracle", type: "a"})
		CREATE (s_mssql:Software {id: 302, name: "Microsoft SQL Server", version: "2019", vendor: "Microsoft", type: "a"})
		CREATE (s_smb:Software {id: 303, name: "Windows SMB v1", version: "1.0", vendor: "Microsoft", type: "o"})
		CREATE (s_crypto:Software {id: 304, name: "Windows CryptoAPI", version: "10.0", vendor: "Microsoft", type: "o"})
		CREATE (s_ad:Software {id: 305, name: "Active Directory Domain Services", version: "2022", vendor: "Microsoft", type: "o"})
		CREATE (s_fortios:Software {id: 306, name: "FortiOS", version: "7.2.4", vendor: "Fortinet", type: "h"})
		CREATE (s_iosxe:Software {id: 307, name: "Cisco IOS XE", version: "17.6.1", vendor: "Cisco", type: "h"})

		// 6. Instancias Instaladas de Software
		CREATE (si_nginx:SoftwareInstallation {id: "si-001", status: "Running", path: "/etc/nginx"})
		CREATE (si_java:SoftwareInstallation {id: "si-002", status: "Running", path: "/usr/lib/jvm/java-8"})
		CREATE (si_mssql:SoftwareInstallation {id: "si-003", status: "Running", path: "C:\\Program Files\\Microsoft SQL Server"})
		CREATE (si_smb:SoftwareInstallation {id: "si-004", status: "Running", path: "System32\\drivers\\srv.sys"})
		CREATE (si_crypto:SoftwareInstallation {id: "si-005", status: "Running", path: "System32\\crypt32.dll"})
		CREATE (si_ad:SoftwareInstallation {id: "si-006", status: "Running", path: "C:\\Windows\\NTDS"})
		CREATE (si_fortios:SoftwareInstallation {id: "si-007", status: "Running", path: "/flash/fortios.bin"})
		CREATE (si_iosxe:SoftwareInstallation {id: "si-008", status: "Running", path: "/bootflash/iosxe.bin"})

		// 7. Hallazgos de Seguridad (Findings)
		CREATE (f_nginx:Finding {id: 400, title: "Versión de Nginx obsoleta", severity: "MEDIUM", description: "Servidor nginx desactualizado con fuga potencial de versión en cabeceras HTTP"})
		CREATE (f_java:Finding {id: 401, title: "Log4Shell RCE Crítico", severity: "CRITICAL", description: "Biblioteca interna Log4j expuesta a inyección JNDI maliciosa"})
		CREATE (f_mssql:Finding {id: 402, title: "Credenciales SA por defecto", severity: "HIGH", description: "Configuración inicial sin rotación del administrador de la base de datos"})
		CREATE (f_smb:Finding {id: 403, title: "SMBv1 Habilitado y Vulnerable", severity: "CRITICAL", description: "El protocolo SMB versión 1 está activo, exponiendo la máquina a EternalBlue"})
		CREATE (f_crypto:Finding {id: 404, title: "CryptoAPI Signature Spoofing", severity: "HIGH", description: "La API criptográfica de Windows permite suplantación de firmas Authenticode y certificados ECC"})
		CREATE (f_ad:Finding {id: 405, title: "Zerologon Privilege Escalation", severity: "CRITICAL", description: "Elevación de privilegios no autenticada a Domain Admin mediante Netlogon (Zerologon)"})
		CREATE (f_fortios:Finding {id: 406, title: "FortiOS SSL-VPN RCE", severity: "CRITICAL", description: "Desbordamiento de búfer en SSL-VPN permitiendo ejecución remota de código sin autenticar"})
		CREATE (f_iosxe:Finding {id: 407, title: "Cisco IOS XE Web UI Privilege Escalation", severity: "CRITICAL", description: "Creación de usuario privilegiado sin autenticación a través de la interfaz web de gestión"})

		// 8. Vulnerabilidades (CVEs)
		CREATE (v_log4shell:Vulnerability {cve_id: "CVE-2021-44228", description: "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP endpoints, causing Remote Code Execution (RCE).", severity: "CRITICAL", base_score: 10.0})
		CREATE (v_eternalblue:Vulnerability {cve_id: "CVE-2017-0144", description: "Remote code execution vulnerability in Microsoft Server Message Block 1.0 (SMBv1) protocol (MS17-010).", severity: "CRITICAL", base_score: 9.8})
		CREATE (v_cryptoapi:Vulnerability {cve_id: "CVE-2020-0601", description: "Windows CryptoAPI spoofing vulnerability that bypasses Authenticode signature verification.", severity: "HIGH", base_score: 8.1})
		CREATE (v_zerologon:Vulnerability {cve_id: "CVE-2020-1472", description: "Unauthenticated RCE and privilege escalation vulnerability in Netlogon Remote Protocol.", severity: "CRITICAL", base_score: 10.0})
		CREATE (v_fortios_rce:Vulnerability {cve_id: "CVE-2023-27997", description: "Heap-based buffer overflow in FortiOS SSL-VPN enables remote code execution via tailored requests.", severity: "CRITICAL", base_score: 9.8})
		CREATE (v_cisco_priv:Vulnerability {cve_id: "CVE-2023-20198", description: "Cisco IOS XE Web UI vulnerability allowing an unauthenticated remote attacker to create an account with privilege level 15.", severity: "CRITICAL", base_score: 10.0})

		// 9. Mitigaciones y Parches
		CREATE (rem_log4shell:Remediation {id: 500, description: "Deshabilitar lookup JNDI mediante variables de entorno o actualizar log4j2 a la versión 2.17.1.", status: "Open"})
		CREATE (rem_eternalblue:Remediation {id: 501, description: "Deshabilitar el protocolo SMBv1 en el registro del sistema y aplicar parche acumulativo de seguridad.", status: "Open"})
		CREATE (rem_cryptoapi:Remediation {id: 502, description: "Aplicar la actualización de seguridad KB4528760 para Windows 10 y Server 2016/2019.", status: "Open"})
		CREATE (rem_zerologon:Remediation {id: 503, description: "Aplicar la actualización de seguridad KB4565349 en controladores de dominio.", status: "Open"})
		CREATE (rem_fortios:Remediation {id: 504, description: "Actualizar firmware FortiOS a versión 7.2.5 o superior.", status: "Open"})
		CREATE (rem_cisco:Remediation {id: 505, description: "Deshabilitar el servidor web de gestión o aplicar parche de Cisco.", status: "Open"})

		CREATE (p_ms17010:Patch {id: 600, name: "MS17-010 Security Update", description: "Parche oficial de seguridad de Microsoft para mitigar la explotación remota de SMBv1."})
		CREATE (p_kb4528760:Patch {id: 601, name: "KB4528760 Security Update", description: "Actualización de seguridad para la vulnerabilidad de suplantación de CryptoAPI."})
		CREATE (p_kb4565349:Patch {id: 602, name: "KB4565349 Security Update", description: "Parche oficial de Microsoft para vulnerabilidad Zerologon en Active Directory."})
		CREATE (p_fortios_patch:Patch {id: 603, name: "FortiOS 7.2.5 Update", description: "Parche de firmware Fortinet que corrige desbordamiento de búfer en SSL-VPN."})

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
		CREATE (p)-[:HAS_ENDPOINT]->(e_dc)
		CREATE (p)-[:HAS_ENDPOINT]->(e_fw)
		CREATE (p)-[:HAS_ENDPOINT]->(e_router)
		CREATE (p)-[:HAS_ENDPOINT]->(e_workstation2)

		// Conectividad de Redes
		CREATE (e_fw)-[:CONNECTED_TO]->(n_dmz)
		CREATE (e_gateway)-[:CONNECTED_TO]->(n_dmz)
		CREATE (e_app)-[:CONNECTED_TO]->(n_lan)
		CREATE (e_db)-[:CONNECTED_TO]->(n_db)
		CREATE (e_workstation)-[:CONNECTED_TO]->(n_lan)
		CREATE (e_dc)-[:CONNECTED_TO]->(n_mgmt)
		CREATE (e_router)-[:CONNECTED_TO]->(n_lan)
		CREATE (e_router)-[:CONNECTED_TO]->(n_db)
		CREATE (e_workstation2)-[:CONNECTED_TO]->(n_lan)

		// Asignación de Hardware
		CREATE (e_gateway)-[:HAS_HARDWARE]->(h1)
		CREATE (e_app)-[:HAS_HARDWARE]->(h1)
		CREATE (e_db)-[:HAS_HARDWARE]->(h2)
		CREATE (e_dc)-[:HAS_HARDWARE]->(h2)
		CREATE (e_fw)-[:HAS_HARDWARE]->(h3)
		CREATE (e_router)-[:HAS_HARDWARE]->(h4)

		// Asignación de Instalaciones de Software
		CREATE (e_gateway)-[:HAS_INSTALLATION]->(si_nginx)
		CREATE (e_app)-[:HAS_INSTALLATION]->(si_java)
		CREATE (e_db)-[:HAS_INSTALLATION]->(si_mssql)
		CREATE (e_db)-[:HAS_INSTALLATION]->(si_smb)
		CREATE (e_workstation)-[:HAS_INSTALLATION]->(si_crypto)
		CREATE (e_dc)-[:HAS_INSTALLATION]->(si_ad)
		CREATE (e_fw)-[:HAS_INSTALLATION]->(si_fortios)
		CREATE (e_router)-[:HAS_INSTALLATION]->(si_iosxe)

		// Instalación -> Definición General
		CREATE (si_nginx)-[:INSTANCE_OF]->(s_nginx)
		CREATE (si_java)-[:INSTANCE_OF]->(s_java)
		CREATE (si_mssql)-[:INSTANCE_OF]->(s_mssql)
		CREATE (si_smb)-[:INSTANCE_OF]->(s_smb)
		CREATE (si_crypto)-[:INSTANCE_OF]->(s_crypto)
		CREATE (si_ad)-[:INSTANCE_OF]->(s_ad)
		CREATE (si_fortios)-[:INSTANCE_OF]->(s_fortios)
		CREATE (si_iosxe)-[:INSTANCE_OF]->(s_iosxe)

		// Relación de Vulnerabilidades encontradas en Instalaciones
		CREATE (si_nginx)-[:HAS_FINDING]->(f_nginx)
		CREATE (si_java)-[:HAS_FINDING]->(f_java)
		CREATE (si_mssql)-[:HAS_FINDING]->(f_mssql)
		CREATE (si_smb)-[:HAS_FINDING]->(f_smb)
		CREATE (si_crypto)-[:HAS_FINDING]->(f_crypto)
		CREATE (si_ad)-[:HAS_FINDING]->(f_ad)
		CREATE (si_fortios)-[:HAS_FINDING]->(f_fortios)
		CREATE (si_iosxe)-[:HAS_FINDING]->(f_iosxe)

		// Hallazgo -> CVEs
		CREATE (f_java)-[:OF_VULNERABILITY]->(v_log4shell)
		CREATE (f_smb)-[:OF_VULNERABILITY]->(v_eternalblue)
		CREATE (f_crypto)-[:OF_VULNERABILITY]->(v_cryptoapi)
		CREATE (f_ad)-[:OF_VULNERABILITY]->(v_zerologon)
		CREATE (f_fortios)-[:OF_VULNERABILITY]->(v_fortios_rce)
		CREATE (f_iosxe)-[:OF_VULNERABILITY]->(v_cisco_priv)

		// Hallazgo -> Mitigaciones
		CREATE (f_java)-[:HAS_REMEDIATION]->(rem_log4shell)
		CREATE (f_smb)-[:HAS_REMEDIATION]->(rem_eternalblue)
		CREATE (f_crypto)-[:HAS_REMEDIATION]->(rem_cryptoapi)
		CREATE (f_ad)-[:HAS_REMEDIATION]->(rem_zerologon)
		CREATE (f_fortios)-[:HAS_REMEDIATION]->(rem_fortios)
		CREATE (f_iosxe)-[:HAS_REMEDIATION]->(rem_cisco)

		// Remediation -> Parche
		CREATE (rem_eternalblue)-[:USES_PATCH]->(p_ms17010)
		CREATE (rem_cryptoapi)-[:USES_PATCH]->(p_kb4528760)
		CREATE (rem_zerologon)-[:USES_PATCH]->(p_kb4565349)
		CREATE (rem_fortios)-[:USES_PATCH]->(p_fortios_patch)

		// Parche -> CVE que arregla
		CREATE (p_ms17010)-[:FIXES]->(v_eternalblue)
		CREATE (p_kb4528760)-[:FIXES]->(v_cryptoapi)
		CREATE (p_kb4565349)-[:FIXES]->(v_zerologon)
		CREATE (p_fortios_patch)-[:FIXES]->(v_fortios_rce)

		// ==========================================
		// RELACIONES TTP -> CVE (TARGETS_VULN)
		// ==========================================
		CREATE (ttp_t1190)-[:TARGETS_VULN]->(v_log4shell)
		CREATE (ttp_t1190)-[:TARGETS_VULN]->(v_fortios_rce)
		CREATE (ttp_t1210)-[:TARGETS_VULN]->(v_eternalblue)
		CREATE (ttp_t1210)-[:TARGETS_VULN]->(v_zerologon)
		CREATE (ttp_t1059)-[:TARGETS_VULN]->(v_log4shell)
		CREATE (ttp_t1078)-[:TARGETS_VULN]->(v_cryptoapi)
		CREATE (ttp_t1078)-[:TARGETS_VULN]->(v_cisco_priv)
		CREATE (ttp_t1021)-[:TARGETS_VULN]->(v_eternalblue)
		CREATE (ttp_t1071)-[:TARGETS_VULN]->(v_log4shell)
		CREATE (ttp_t1105)-[:TARGETS_VULN]->(v_eternalblue)
		CREATE (ttp_t1053)-[:TARGETS_VULN]->(v_cryptoapi)

		// ==========================================
		// RELACIONES THREAT ACTOR -> TTP (USES_TTP)
		// ==========================================
		// APT29 (Cozy Bear)
		CREATE (ta_apt29)-[:USES_TTP]->(ttp_t1190)
		CREATE (ta_apt29)-[:USES_TTP]->(ttp_t1059)
		CREATE (ta_apt29)-[:USES_TTP]->(ttp_t1078)
		CREATE (ta_apt29)-[:USES_TTP]->(ttp_t1071)
		CREATE (ta_apt29)-[:USES_TTP]->(ttp_t1053)
		CREATE (ta_apt29)-[:USES_TTP]->(ttp_t1105)

		// APT41 (Winnti)
		CREATE (ta_apt41)-[:USES_TTP]->(ttp_t1190)
		CREATE (ta_apt41)-[:USES_TTP]->(ttp_t1059)
		CREATE (ta_apt41)-[:USES_TTP]->(ttp_t1071)
		CREATE (ta_apt41)-[:USES_TTP]->(ttp_t1105)
		CREATE (ta_apt41)-[:USES_TTP]->(ttp_t1210)
		CREATE (ta_apt41)-[:USES_TTP]->(ttp_t1053)

		// APT28 (Fancy Bear)
		CREATE (ta_apt28)-[:USES_TTP]->(ttp_t1210)
		CREATE (ta_apt28)-[:USES_TTP]->(ttp_t1078)
		CREATE (ta_apt28)-[:USES_TTP]->(ttp_t1021)
		CREATE (ta_apt28)-[:USES_TTP]->(ttp_t1053)

		// APT38 (Lazarus)
		CREATE (ta_apt38)-[:USES_TTP]->(ttp_t1210)
		CREATE (ta_apt38)-[:USES_TTP]->(ttp_t1021)
		CREATE (ta_apt38)-[:USES_TTP]->(ttp_t1105)

		// FIN7 (Carbanak)
		CREATE (ta_fin7)-[:USES_TTP]->(ttp_t1059)
		CREATE (ta_fin7)-[:USES_TTP]->(ttp_t1078)
		CREATE (ta_fin7)-[:USES_TTP]->(ttp_t1053)
	`
	err = dbHelper.ExecuteWrite(ctx, seedQuery, nil)
	if err != nil {
		log.Fatalf("Error poblando base de datos: %v", err)
	}

	fmt.Println("[OK] Base de datos Neo4j poblada correctamente con datos de prueba.")
}
