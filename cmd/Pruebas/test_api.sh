#!/bin/bash

# Este script prueba la API HTTP del orquestador.
# Asegúrate de tener el servidor levantado ejecutando primero:
# go run cmd/main.go

BASE_URL="http://localhost:8080/api"

echo "=== LIMPIANDO NEO4J ==="
go run clean_db/main.go

echo -e "\n1. Creando Proyecto..."
curl -s -X POST $BASE_URL/projects \
  -H "Content-Type: application/json" \
  -d '{
        "project_id": 100, 
        "nombre": "Proyecto Orquestador"
      }' | jq || echo "OK (sin jq)"

echo -e "\n\n2. Añadiendo Endpoint al Proyecto..."
curl -s -X POST $BASE_URL/projects/100/endpoints \
  -H "Content-Type: application/json" \
  -d '{
        "endpoint_id": 555, 
        "hostname": "srv-orchestrator", 
        "tipo": "Windows", 
        "internet_exposed": true,
        "confidentiality_req": "High",
        "integrity_req": "High",
        "availability_req": "High"
      }' | jq || echo "OK (sin jq)"

echo -e "\n\n3. Asociando Hardware al Endpoint..."
curl -s -X POST $BASE_URL/endpoints/555/hardware \
  -H "Content-Type: application/json" \
  -d '{
        "hardware_id": 777, 
        "modelo": "ThinkServer", 
        "fabricante": "Lenovo", 
        "ram_gb": 64
      }' | jq || echo "OK (sin jq)"

echo -e "\n\n4. Asociando Red al Endpoint..."
curl -s -X POST $BASE_URL/endpoints/555/networks \
  -H "Content-Type: application/json" \
  -d '{
        "network_id": 999, 
        "nombre": "DMZ", 
        "cidr": "192.168.1.0/24", 
        "gateway": "192.168.1.1"
      }' | jq || echo "OK (sin jq)"

echo -e "\n\n5. Registrando Instalación de Software..."
curl -s -X POST $BASE_URL/endpoints/555/installations \
  -H "Content-Type: application/json" \
  -d '{
        "software": {
          "software_id": 404,
          "name": "Apache Tomcat",
          "version": "9.0.41",
          "vendor": "Apache Software Foundation"
        },
        "installation": {
          "installation_id": "inst-tomcat-555",
          "status": "INSTALLED",
          "install_path": "/opt/tomcat"
        }
      }' | jq || echo "OK (sin jq)"

echo -e "\n\n6. Generando Finding para la Instalación..."
curl -s -X POST $BASE_URL/installations/inst-tomcat-555/findings \
  -H "Content-Type: application/json" \
  -d '{
        "finding_id": 808,
        "status": "OPEN",
        "impact_score": 6.5,
        "likelihood": 0.8,
        "remediation_factor": 1.0,
        "priority_score": 7.2,
        "risk_score": 9.8
      }' | jq || echo "OK (sin jq)"

echo -e "\n\n7. Asociando CVE y Remediación al Finding..."
curl -s -X POST $BASE_URL/findings/808/vuln-remediations \
  -H "Content-Type: application/json" \
  -d '{
        "vulnerability": {
          "cve_id": "CVE-2026-TEST",
          "description": "Vulnerabilidad inventada de prueba",
          "base_score": 9.8,
          "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
          "kev": true,
          "epss_score": 0.95
        },
        "remediation": {
          "remediation_id": 303,
          "fixed_version": "9.0.43",
          "status": "PENDING"
        }
      }' | jq || echo "OK (sin jq)"

echo -e "\n\n=== PRUEBA DE API FINALIZADA ==="
