package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/config"

	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/adapters/provider"
)

/*
Este archivo implementa el Compositor Principal (Composition Root) del sistema.

Propósito arquitectónico y teórico:
1. Ubicación en Arquitectura Hexagonal: Se localiza en la raíz de comandos (`cmd/main.go`), sirviendo como el punto de inicio donde se configuran y cablean todos los adaptadores y puertos (Inyección de Dependencias).
2. Punto de Entrada Único (main): Actúa como el punto de inicio del hilo ejecutable principal del sistema operativo.
3. Inyección de Dependencias Manual: Instancia de manera secuencial los componentes de configuración, bases de datos (adaptadores de persistencia), proveedores de API externa (adaptadores de salida), servicios lógicos (núcleo/casos de uso) y controladores HTTP (adaptadores de entrada).
4. Orquestador de Bootstrap: Asocia los adaptadores específicos a sus correspondientes puertos (interfaces) y los inyecta en el constructor de los servicios de aplicación, iniciando posteriormente el servidor web.
*/


func main() {
	// Carga de configuración
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Error inicializando la configuración: %v", err)
	}

	log.Printf("Configuración cargada correctamente.")

	// Inicializamos el adaptador inyectando la BaseURL y la APIKey desde la config
	nistScanner := provider.NewNistAPIAdapter(cfg.NVD.BaseURL, cfg.NVD.APIKey, cfg.NVD.TimeoutSeconds)

	// --------- PRUEBA API DEL NIST (ELIMINAR DEL MAIN SIN PROBLEMAS, SOLO ES UNA PRUEBA) -----------------------
	// ejecutar con go run cmd/main.go (estando dentro del dir backend)

	// Definimos un contexto, eso sirve para enviar señales de cancelacion de forma limpia (caracteristica interna de go) en este caso son 20 segundos
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel() // el comando defer hace que lo que tenga a su derecha (en este caso cancel()) se ejecute justo antes de salir de la funcion (en este caso main)

	log.Printf("Conectando a la API de NIST en: %s", cfg.NVD.BaseURL)

	// Ejecutamos el parseo (Pedimos 5 vulnerabilidades como prueba) (TODO: idseñar algoritmo para comparar lo que hay en la bd respecto a lo que hemos pedido para ver nuevas vuln y no duplicarlas)
	limit := 5
	offset := 100000
	vulnerabilities, err := nistScanner.FetchVulnerabilities(ctx, limit, offset) // el adapter te devuelve un objeto tipo vulnerability del domain!! adapter (parseamos api nist) -> port (adapter impl interfaz) -> domain (te devuelve un objeto estandar del domain, en este caso uno tipo vulnerability)
	if err != nil {
		log.Fatalf("Error ejecutando el scanner de NIST: %v", err)
	}

	fmt.Printf("\nmostrando %d vulnerabilidades de la respuesta de NIST:\n", len(vulnerabilities))
	fmt.Println("================================================================================")

	for _, vuln := range vulnerabilities {
		fmt.Printf("[ID CVE]:      %s\n", vuln.CVEID)
		fmt.Printf("    Score CVSS:  %.1f\n", vuln.BaseScore)
		fmt.Printf("    CWE:         %s\n", vuln.CWE)
		fmt.Printf("    Primer CPE:  %s\n", vuln.CPE)
		fmt.Printf("    Descripción (%s): %s\n", vuln.Description, vuln.Description)
		fmt.Println("--------------------------------------------------------------------------------")
	}

	fmt.Println("================================================================================")

	// --------- FIN PRUEBA API DEL NIST (ELIMINAR DEL MAIN SIN PROBLEMAS, SOLO ES UNA PRUEBA) -----------------------
}
