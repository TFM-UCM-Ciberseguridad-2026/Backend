# Orquestador - Backend en Go

Este es el backend del Orquestador de Ciberseguridad, diseñado en Go siguiendo las mejores prácticas del lenguaje, modularidad y los principios de la **Arquitectura Hexagonal Pura**.

Este README está diseñado para explicar detalladamente la estructura del proyecto y los conceptos de diseño de software utilizados, explicados desde cero.

---

## 🧩 Glosario de Conceptos Difíciles (Desde Cero)

### 1. ¿Qué es la Arquitectura Hexagonal (Puertos y Adaptadores)?
Imagina que tienes un teléfono móvil. El teléfono tiene un puerto de carga **USB-C**. Al teléfono no le importa si lo enchufas a una toma de corriente de pared, al encendedor de un coche o a una batería portátil, siempre que el cable termine en un conector USB-C.
* **El Puerto (Interface):** Es el conector USB-C (la regla/contrato que define cómo comunicarse).
* **El Adaptador (Adapter):** Es el cargador físico específico (el enchufe europeo, el cargador de coche, etc.) que se adapta al puerto.

En nuestro software:
* El **Núcleo (Core)** es la lógica de negocio pura y sus modelos (en `internal/core/domain` y `internal/core/service`).
* Los **Puertos (Ports)** son interfaces de Go (en `internal/core/ports/ports.go`) que dicen: *"Necesito un proveedor que me dé CVEs"*.
* Los **Adaptadores (Adapters)** son los archivos concretos (bajo `internal/adapters/`) que conectan con APIs externas, bases de datos o exponen endpoints HTTP. Si mañana decidimos cambiar PostgreSQL por MongoDB, solo cambiamos el *Adaptador* de base de datos (`adapters/repository/postgres.go`); la lógica de negocio ni se entera.

### 2. Inversión e Inyección de Dependencias
* **Inversión de Dependencias:** En lugar de que la lógica de negocio llame directamente al cliente de la API del NIST (lo que nos acoplaría fuertemente a esa API externa), la lógica de negocio define una interfaz abstracta (un contrato/puerto) de lo que necesita. El cliente externo se ajusta a esa interfaz.
* **Inyección de Dependencias:** Consiste en pasarle ("inyectarle") a una estructura los componentes externos que necesita para funcionar desde fuera, en lugar de que ella misma los cree internamente. Esto hace que el código sea testeable, ya que en las pruebas de software podemos "inyectar" un proveedor simulado (mock) en lugar de hacer peticiones reales a internet.

### 3. CVE (Common Vulnerabilities and Exposures)
Es el "identificador único de identidad" de una vulnerabilidad de seguridad conocida. Tiene un formato como `CVE-2023-38606`. Permite que cualquier herramienta en el mundo sepa exactamente de qué fallo de seguridad se está hablando.

### 4. CPE (Common Platform Enumeration)
Es un formato estandarizado que sirve como el "código de barras" para identificar sistemas operativos, aplicaciones y hardware.
* Ejemplo: `cpe:2.3:a:apache:http_server:2.4.41`
* Significa: Tipo Aplicación (`a`), Fabricante `apache`, Producto `http_server`, Versión `2.4.41`. Con este código, consultamos al NIST si existen CVEs activos para esa versión de Apache.

### 5. Middleware
Imagina que eres el dueño de una discoteca. En la puerta pones a un portero que:
1. Comprueba si los clientes son mayores de edad (Autenticación).
2. Anota cuánta gente entra (Logger).
3. Asegura que nadie pase con botellas de fuera (CORS / Filtros).

En desarrollo web, un **Middleware** es una capa intermedia de software que intercepta y procesa una petición HTTP antes de que llegue a su controlador final (Handler).

### 6. Graceful Shutdown (Apagado Ordenado)
Si estás escribiendo un documento y de repente desenchufas el ordenador de la corriente, es probable que pierdas información o corrompas el archivo. Lo correcto es cerrar el programa, guardar cambios y apagar.
Un apagado ordenado en el backend intercepta señales de parada del sistema (`Ctrl+C` o señales del servidor) y le da tiempo al servidor HTTP para que termine de procesar las peticiones de los usuarios conectados actualmente antes de cerrar la base de datos y apagar el programa por completo.

### 7. Handlers (adapters de entrada)
Son componentes de la capa de infraestructura (adaptadores de entrada o *driving adapters*) que comunican el protocolo de red HTTP con el núcleo (*Core*) de la aplicación:
* **Entrada de datos:** Reciben las peticiones HTTP entrantes (del front) y extraen la información (JSON, parámetros de consulta o variables de ruta).
* **Traducción:** Convierten los datos recibidos (formato de red) en estructuras del dominio comprensibles para la lógica del negocio.
* **Llamada al núcleo:** Invocan los casos de uso llamando a los servicios del Core a través de las interfaces de los puertos.
* **Salida de datos:** Reciben las respuestas o errores de la lógica de negocio, configuran las cabeceras HTTP, codifican el resultado a formato JSON y establecen el código de estado HTTP adecuado antes de enviarlo de vuelta al cliente (front).

---

## 📁 Estructura de Directorios del Proyecto

El backend está organizado siguiendo una **Arquitectura Hexagonal Pura**:

```
backend/
├── cmd/
│   └── main.go                         # Punto de entrada de la aplicación. Inicializa todo.
├── internal/                           # Código privado de la aplicación (no importable por terceros)
│   ├── config/                         # Carga la configuración (puertos, claves de API, base de datos)
│   ├── core/                           # Núcleo de la Aplicación (Dominio y Lógica de Negocio)
│   │   ├── domain/                     # Entidades lógicas puras (CVE, Exploit, Software, Endpoint)
│   │   ├── ports/                      # Puertos (Interfaces de Go - Contratos lógicos - para comunicacion con adapters)
│   │   └── service/                    # Casos de uso / Lógica de negocio (Orquestador)
│   └── adapters/                       # Infraestructura y Tecnología (Adaptadores)
│       ├── handler/                    # Adaptadores de Entrada (HTTP Server, Router, Handlers y Middlewares)
│       ├── repository/                 # Adaptador de Persistencia (PostgreSQL)
│       └── provider/                   # Adaptadores de APIs Externas (Clientes de NIST NVD, Exploit-DB)
├── .env.example                        # Archivo de ejemplo para configurar credenciales locales
├── go.mod                              # Administrador de módulos y dependencias de Go
└── changelog.md                        # Registro de cambios cronológico del desarrollo
```

---

## 🔄 Flujo de Datos en el Sistema (Ejemplo)

1. El **Frontend** solicita buscar las vulnerabilidades de un equipo haciendo un `POST /api/v1/scan`.
2. El adaptador de entrada **HTTP (handler)** recibe la petición, lee el JSON que contiene el software del equipo y llama al **Servicio (service)** del Core a través de su puerto.
3. El **Servicio** de vulnerabilidades toma el identificador **CPE** del software y le pide al **Provider del NIST (adapters/provider/nvd)** (que implementa el puerto `CVEProvider`) que busque vulnerabilidades relacionadas a través de internet.
4. El **Servicio** también le pide al **Provider de Exploit-DB (adapters/provider/exploitdb)** (que implementa el puerto `ExploitProvider`) que busque si hay código de explotación pública asociado.
5. El **Servicio** procesa esta información, la guarda en la **Base de datos (adapters/repository/postgres)** (que implementa el puerto de persistencia) y devuelve el informe consolidado a los **handlers**.
6. Los **handlers** formatean la información en un JSON limpio y se la devuelven al **Frontend** para que la renderice de forma visual e intuitiva para el usuario.

---

## 🤖 Mapeo de TTPs usando Ollama (LLM Local)

El sistema integra un modelo de lenguaje local (LLM) a través de **Ollama** para inferir Técnicas, Tácticas y Procedimientos (TTPs) de MITRE ATT&CK a partir de vulnerabilidades ingeridas.

### Cómo levantar Ollama

Ollama está configurado como un servicio dentro de `docker-compose.yml` con descarga automática del modelo. Al ejecutar `docker compose up -d`, el sistema:

1. Levanta el contenedor de Ollama en el puerto `11434`.
2. Un servicio auxiliar (`ollama-init`) descarga automáticamente el modelo `gemma4:e4b`.
3. El backend espera a que ambos estén listos antes de arrancar.

**No es necesario ejecutar ningún comando manual.** Un solo `docker compose up -d` lo hace todo.

### Variables de entorno

El backend necesita saber dónde se encuentra Ollama y qué modelo utilizar. Estas son las variables que se pueden configurar en `.env`:
* `OLLAMA_HOST`: URL del servicio Ollama (por defecto `http://localhost:11434` o `http://ollama:11434` dentro de Docker).
* `OLLAMA_MODEL`: Modelo a utilizar (por defecto `gemma4:e4b`).

### Pipeline con dos niveles de confianza

El proceso de inferencia de TTPs cuenta con dos rutas dependiendo de la calidad de la información obtenida desde la vulnerabilidad (CVE):

1. **Ruta 1 (Alta Confianza - `cwe_mapping`)**: Si el CVE tiene un CWE válido (se descartan `"NVD-CWE-Other"` y `"NVD-CWE-noinfo"`), se realiza una consulta al LLM pidiéndole que asocie el CWE en cuestión a un conjunto de TTPs. En Neo4j, esto persiste como:
   `(CVE)-[:HAS_WEAKNESS]->(CWE)-[:MAPS_TO {confidence: "high", source: "cwe_mapping"}]->(TTP)`
   *(Nota: Se emplea una caché en memoria para no re-evaluar CWEs idénticos)*

2. **Ruta 2 (Baja Confianza - `cve_description_fallback`)**: Si el CVE carece de CWE útil, el sistema recurre como *fallback* a enviar la descripción del CVE al LLM para que infiera directamente el TTP. Esto se persiste como:
   `(CVE)-[:MAPS_TO {confidence: "low", source: "cve_description_fallback"}]->(TTP)`

> **Nota Técnica:** Se ha **eliminado por completo** el mecanismo antiguo de mapeo que empleaba una inferencia transversal de base de datos a través del catálogo MITRE CAPEC (`(CVE)-[:HAS_CWE]->(CWE)<-[:MAPS_TO_CWE]-(CAPEC)-[:MAPS_TO_TTP]->(TTP)`). El uso del LLM local consolida un único pipeline dinámico y más preciso, evitando mantener caminos duplicados o grafos pesados obsoletos para este propósito.
