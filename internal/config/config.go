package config

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

/*
Este archivo gestiona el subsistema de configuración estática y dinámica de la aplicación.

Propósito arquitectónico y teórico:
1. Carga de Variables de Entorno: Lee los parámetros del runtime del sistema operativo (u opcionalmente de un archivo .env en desarrollo).
2. Estructura de Configuración Tipada (Config): Define los tipos de datos requeridos por la aplicación (puertos, credenciales, URLs de APIs externas) para evitar dependencias directas de llamadas al sistema operativo (os.Getenv) a lo largo del código.
3. Desacoplamiento de Variables: Centraliza las constantes y configuraciones iniciales para que el resto de los componentes operen de manera agnóstica al entorno de despliegue (desarrollo, preproducción, producción).
*/

// DatabaseConfig contiene las credenciales y parámetros de conexión para la base de datos (Postgres/MySQL - Legacy o futuro).
type DatabaseConfig struct {
	Host     string
	Port     string
	User     string
	Password string
	Name     string
	SSLMode  string
}

// NVDConfig contiene las credenciales y URLs para interactuar con la API NIST NVD.
type NVDConfig struct {
	APIKey         string
	BaseURL        string
	TimeoutSeconds int
	CacheTTLHours  int
}

// OllamaConfig contiene los ajustes para conectarse al LLM local.
type OllamaConfig struct {
	Host  string
	Model string
}

// Config centraliza todas las variables de configuración cargadas del entorno.
type Config struct {
	Port          string
	Env           string
	Neo4jURI      string
	Neo4jUser     string
	Neo4jPassword string
	Database      DatabaseConfig
	NVD           NVDConfig
	Ollama        OllamaConfig
}

// ParseEnvFile lee un archivo .env y extrae sus pares clave-valor a un mapa.
// Soporta líneas vacías, comentarios con '#' y remueve comillas simples o dobles en los valores.
func ParseEnvFile(path string) (map[string]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	envMap := make(map[string]string)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimSpace(line)

		// Ignorar líneas vacías y comentarios
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Encontrar el delimitador '='
		idx := strings.Index(line, "=")
		if idx == -1 {
			continue // Omitir líneas malformadas
		}

		key := strings.TrimSpace(line[:idx])
		value := strings.TrimSpace(line[idx+1:])

		// Remover comillas envolventes del valor si existen
		if len(value) >= 2 {
			if (strings.HasPrefix(value, "\"") && strings.HasSuffix(value, "\"")) ||
				(strings.HasPrefix(value, "'") && strings.HasSuffix(value, "'")) {
				value = value[1 : len(value)-1]
			}
		}

		envMap[key] = value
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error escaneando el archivo .env: %w", err)
	}

	return envMap, nil
}

// LoadEnv carga las variables de un archivo .env en el entorno del sistema operativo (os.Setenv).
// Respeta las variables de entorno ya existentes para permitir la configuración externa en contenedores.
func LoadEnv(path string) error {
	envMap, err := ParseEnvFile(path)
	if err != nil {
		return err
	}

	for key, value := range envMap {
		// Solo establece la variable si no existe previamente en el entorno del sistema
		if os.Getenv(key) == "" {
			if err := os.Setenv(key, value); err != nil {
				return fmt.Errorf("error estableciendo la variable de entorno %s: %w", key, err)
			}
		}
	}

	return nil
}

// LoadConfig inicializa y carga la configuración de la aplicación.
// Primero intenta cargar el archivo .env local si existe, y luego recupera las variables del entorno.
// NOTA: Se modificó la firma original en Backend para devolver (*Config, error) compatible con Lucas.
func LoadConfig() (*Config, error) {
	// Intentamos cargar el archivo .env desde la raíz del proyecto (../.env) o el directorio actual (.env).
	envPaths := []string{"../.env", ".env"}
	for _, envPath := range envPaths {
		if err := LoadEnv(envPath); err == nil {
			break
		}
	}

	cfg := &Config{
		Port:          getEnv("PORT", "8080"),
		Env:           getEnv("ENV", "development"),
		Neo4jURI:      getEnv("NEO4J_URI", "bolt://localhost:7687"),
		Neo4jUser:     getEnv("NEO4J_USER", "neo4j"),
		Neo4jPassword: getEnv("NEO4J_PASSWORD", "password"),
		Database: DatabaseConfig{
			Host:     getEnv("DB_HOST", "localhost"),
			Port:     getEnv("DB_PORT", "5432"),
			User:     getEnv("DB_USER", ""),
			Password: getEnv("DB_PASSWORD", ""),
			Name:     getEnv("DB_NAME", ""),
			SSLMode:  getEnv("DB_SSLMODE", ""),
		},
		NVD: NVDConfig{
			APIKey:         getEnv("NVD_API_KEY", ""),
			BaseURL:        getEnv("NVD_BASE_URL", "https://services.nvd.nist.gov/rest/json/cves/2.0"),
			TimeoutSeconds: getEnvAsInt("NVD_API_TIMEOUT", 90),
			CacheTTLHours:  getEnvAsInt("NVD_CACHE_TTL_HOURS", 6),
		},
		Ollama: OllamaConfig{
			Host:  getEnv("OLLAMA_HOST", "http://localhost:11434"),
			Model: getEnv("OLLAMA_MODEL", "gemma3:4b"),
		},
	}

	return cfg, nil
}

// getEnv es una función auxiliar que obtiene una variable de entorno o devuelve un valor por defecto.
func getEnv(key, defaultValue string) string {
	if val, exists := os.LookupEnv(key); exists {
		return val
	}
	return defaultValue
}

// getEnvAsInt es una función auxiliar para obtener un entero del entorno.
func getEnvAsInt(key string, defaultValue int) int {
	if val, exists := os.LookupEnv(key); exists {
		if i, err := strconv.Atoi(val); err == nil {
			return i
		}
	}
	return defaultValue
}
