# Este script prueba la API HTTP del orquestador desde PowerShell.
# Asegúrate de tener el servidor levantado ejecutando primero:
# go run cmd/main.go

$BaseUrl = "http://localhost:8080/api"
$Headers = @{ "Content-Type" = "application/json" }

Write-Host "=== LIMPIANDO NEO4J ===" -ForegroundColor Yellow
go run cmd\Pruebas\clean_db\main.go

Write-Host "`n1. Creando Proyecto..." -ForegroundColor Cyan
$bodyProj = @{
    project_id = 100
    nombre = "Proyecto Orquestador"
} | ConvertTo-Json
Invoke-RestMethod -Uri "$BaseUrl/projects" -Method Post -Headers $Headers -Body $bodyProj

Write-Host "`n2. Añadiendo Endpoint al Proyecto..." -ForegroundColor Cyan
$bodyEp = @{
    endpoint_id = 555
    hostname = "srv-orchestrator"
    tipo = "Windows"
    internet_exposed = $true
} | ConvertTo-Json
Invoke-RestMethod -Uri "$BaseUrl/projects/100/endpoints" -Method Post -Headers $Headers -Body $bodyEp

Write-Host "`n3. Asociando Hardware al Endpoint..." -ForegroundColor Cyan
$bodyHw = @{
    hardware_id = 777
    modelo = "ThinkServer"
    fabricante = "Lenovo"
    ram_gb = 64
} | ConvertTo-Json
Invoke-RestMethod -Uri "$BaseUrl/endpoints/555/hardware" -Method Post -Headers $Headers -Body $bodyHw

Write-Host "`n4. Asociando Red al Endpoint..." -ForegroundColor Cyan
$bodyNet = @{
    network_id = 999
    nombre = "DMZ"
    cidr = "192.168.1.0/24"
    gateway = "192.168.1.1"
} | ConvertTo-Json
Invoke-RestMethod -Uri "$BaseUrl/endpoints/555/networks" -Method Post -Headers $Headers -Body $bodyNet

Write-Host "`n5. Registrando Instalación de Software..." -ForegroundColor Cyan
$bodyInst = @{
    software = @{
        software_id = 404
        name = "Apache Tomcat"
        version = "9.0.41"
        vendor = "Apache Software Foundation"
    }
    installation = @{
        installation_id = "inst-tomcat-555"
        status = "INSTALLED"
        install_path = "/opt/tomcat"
    }
} | ConvertTo-Json -Depth 5
Invoke-RestMethod -Uri "$BaseUrl/endpoints/555/installations" -Method Post -Headers $Headers -Body $bodyInst

Write-Host "`n6. Generando Finding para la Instalación..." -ForegroundColor Cyan
$bodyFind = @{
    finding_id = 808
    risk_score = 9.8
    status = "OPEN"
} | ConvertTo-Json
Invoke-RestMethod -Uri "$BaseUrl/installations/inst-tomcat-555/findings" -Method Post -Headers $Headers -Body $bodyFind

Write-Host "`n7. Asociando CVE y Remediación al Finding..." -ForegroundColor Cyan
$bodyVulnRem = @{
    vulnerability = @{
        cve_id = "CVE-2026-TEST"
        description = "Vulnerabilidad inventada de prueba"
        base_score = 9.8
    }
    remediation = @{
        remediation_id = 303
        fixed_version = "9.0.43"
        status = "PENDING"
    }
} | ConvertTo-Json -Depth 5
Invoke-RestMethod -Uri "$BaseUrl/findings/808/vuln-remediations" -Method Post -Headers $Headers -Body $bodyVulnRem

Write-Host "`n=== PRUEBA DE API FINALIZADA ===" -ForegroundColor Green
