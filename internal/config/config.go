package config

import (
	"log"
	"os"

	"github.com/joho/godotenv"
)

/*
Este archivo gestiona el subsistema de configuración estática y dinámica de la aplicación.

Propósito arquitectónico y teórico:
1. Carga de Variables de Entorno: Lee los parámetros del runtime del sistema operativo (u opcionalmente de un archivo .env en desarrollo).
2. Estructura de Configuración Tipada (Config): Define los tipos de datos requeridos por la aplicación (puertos, credenciales, URLs de APIs externas) para evitar dependencias directas de llamadas al sistema operativo (os.Getenv) a lo largo del código.
3. Desacoplamiento de Variables: Centraliza las constantes y configuraciones iniciales para que el resto de los componentes operen de manera agnóstica al entorno de despliegue (desarrollo, preproducción, producción).
*/

type Config struct {
	Port          string
	Env           string
	Neo4jURI      string
	Neo4jUser     string
	Neo4jPassword string
	NVDApiKey     string
	NVDBaseURL    string
}

// LoadConfig lee las variables de entorno, opcionalmente desde un archivo .env,
// y retorna una estructura Config fuertemente tipada.
func LoadConfig() *Config {
	// Intentamos cargar el archivo .env, si no existe no pasa nada (asumimos que las vars están en el OS)
	err := godotenv.Load()
	if err != nil {
		log.Println("Aviso: No se encontró archivo .env, leyendo variables del sistema...")
	}

	return &Config{
		Port:          getEnv("PORT", "8080"),
		Env:           getEnv("ENV", "development"),
		Neo4jURI:      getEnv("NEO4J_URI", "bolt://localhost:7687"),
		Neo4jUser:     getEnv("NEO4J_USER", "neo4j"),
		Neo4jPassword: getEnv("NEO4J_PASSWORD", "password"),
		NVDApiKey:     getEnv("NVD_API_KEY", ""),
		NVDBaseURL:    getEnv("NVD_BASE_URL", "https://services.nvd.nist.gov/rest/json/cves/2.0"),
	}
}

// getEnv es un helper para leer variables de entorno con un valor por defecto
func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}
