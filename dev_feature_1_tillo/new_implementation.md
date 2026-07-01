# Nueva Implementación

## 1. Contexto

El backend ya tenía una base sólida para trabajar con Neo4j:

- modelos de dominio para nodos como `Project`, `Endpoint`, `Hardware`, `Network`, `Software`, `Finding`, `Vulnerability`, `Remediation` y `Patch`
- repositorios tipados para persistir esos nodos
- un helper genérico para ejecutar Cypher: `DatabaseHelper`

Sin embargo, el estado inicial tenía una limitación importante:

- solo se estaban creando nodos aislados
- no se estaban creando relaciones entre ellos
- no existía el concepto de instalación concreta de software sobre un endpoint

Eso impedía modelar correctamente un grafo como el que necesitábamos:

- un proyecto con endpoints
- un endpoint con hardware y red
- instalaciones de software específicas en ese endpoint
- findings asociados a esas instalaciones
- vulnerabilidades asociadas a los findings
- remediaciones y parches conectados a esas vulnerabilidades

En otras palabras, faltaba pasar de un inventario de nodos sueltos a un grafo navegable y con contexto operativo.

## 2. Objetivo de esta implementación

El objetivo fue construir una **Phase 1** funcional que permitiera:

1. crear todos los nodos relevantes en Neo4j
2. crear las relaciones entre esos nodos
3. validar visualmente el resultado en Neo4j Browser
4. dejar una base clara para evolucionar después hacia:
   - puertos tipados de relaciones
   - servicios de aplicación
   - API HTTP

Esta fase no buscaba cerrar toda la arquitectura final, sino demostrar que el modelo de grafo propuesto funciona de verdad en el repositorio actual.

## 3. Por qué se hizo así

Se siguió este enfoque por motivos prácticos y arquitectónicos:

### 3.1 Mantener la arquitectura hexagonal existente

Ya existían repositorios tipados para la persistencia de nodos. Lo correcto era reutilizarlos, no saltárselos.

### 3.2 Añadir solo lo mínimo imprescindible

Antes faltaba un tipo clave:

- `SoftwareInstallation`

Sin ese nodo, no se podía distinguir entre:

- el software como producto o catálogo
- la instalación concreta de ese software en un equipo

Esa distinción era fundamental para poder colgar findings del contexto real del endpoint.

### 3.3 Evitar rediseñar todo demasiado pronto

Para esta fase, las relaciones se implementaron usando:

- `dbHelper.ExecuteWrite(...)`

Esto permitió validar el grafo rápidamente sin tener que diseñar todavía un `RelationshipPort` o `TopologyPort` completo.

## 4. Qué se ha implementado

## 4.1 Nuevo nodo de dominio: `SoftwareInstallation`

Se añadió un nuevo modelo de dominio para representar una instalación concreta de software en la red.

Archivo:

- internal/core/domain/software_installation.go

Campos definidos:

- `InstallationID`
- `FirstSeen`
- `LastSeen`
- `Status`
- `InstallPath`
- `DetectedBy`
- `PackageManager`

### Por qué era necesario

Porque `Software` por sí solo no representa una instancia instalada en un host concreto.

Ejemplo:

- `Software`: OpenSSL 1.1.1
- `SoftwareInstallation`: OpenSSL 1.1.1 instalado en `srv-db`

Ese segundo nivel es el que permite relacionar findings y vulnerabilidades con el endpoint real.

## 4.2 Nuevo puerto: `SoftwareInstallationPort`

Se añadió el contrato correspondiente en:

- internal/core/ports/ports.go

Con las operaciones:

- `Save`
- `GetByID`
- `DeleteByID`

### Por qué era necesario

Para mantener el patrón ya existente en el proyecto:

- cada entidad principal tiene su propio puerto
- el core depende de interfaces, no de Neo4j directamente

## 4.3 Extensión del repositorio Neo4j para `SoftwareInstallation`

Se modificó:

- internal/adapters/repository/neo4j_repo.go

Se hicieron varios cambios:

### a. Se actualizó `NewNeo4jRepository(...)`

Ahora devuelve también:

- `ports.SoftwareInstallationPort`

### b. Se añadió `neo4jSoftwareInstallationRepo`

Con implementación de:

- `Save`
- `GetByID`
- `DeleteByID`

### c. Se añadieron helpers temporales para tiempos

- `getTime(...)`
- `getTimePtr(...)`

Esto permitió mapear:

- `time.Time`
- `*time.Time`

desde Neo4j hacia el dominio Go.

### d. Se corrigió el problema con `*time.Time`

Se detectó un error real en runtime:

```text
Usage of type '*time.Time' is not supported
```

La causa estaba en el `Save` de `SoftwareInstallation`, donde se estaba pasando directamente `si.LastSeen` como `*time.Time` al mapa de parámetros del driver de Neo4j.

Se solucionó convirtiendo:

- `*time.Time` a `time.Time` cuando no es nil
- `*time.Time` a `nil` cuando no existe

### Por qué era necesario

Porque el driver de Neo4j no acepta ese tipo puntero como parámetro de Cypher.

## 4.4 Nuevo ejecutable de prueba del grafo conectado

Se creó:

- cmd/Pruebas/prueba_grafo_endpoint/main.go

Este fichero es el centro de la Phase 1.

### Qué hace

1. carga configuración
2. conecta con Neo4j
3. limpia la base de datos
4. crea todos los nodos necesarios
5. crea todas las relaciones necesarias
6. recupera algunos nodos para una validación rápida en consola

### Nodos creados

- `Project`
- `Endpoint`
- `Hardware`
- `Network`
- `Software` x2
- `SoftwareInstallation` x2
- `Finding` x3
- `Vulnerability` x3
- `Remediation` x1
- `Patch` x1
- `Exploit` x1

### Relaciones creadas

- `HAS_ENDPOINT`
- `HAS_HARDWARE`
- `CONNECTED_TO`
- `HAS_INSTALLATION`
- `INSTANCE_OF`
- `HAS_FINDING`
- `OF_VULNERABILITY`
- `HAS_REMEDIATION`
- `USES_PATCH`
- `FIXES`

### Por qué era necesario

Porque era la forma más directa de demostrar que el modelo de grafo realmente funciona de extremo a extremo dentro del backend actual.

## 5. Cómo se implementaron las relaciones

Las relaciones no se añadieron todavía como métodos tipados del repositorio.

En su lugar se usó:

- `dbHelper.ExecuteWrite(ctx, query, params)`

Esta función ya existía en:

- internal/adapters/repository/neo4j_repo.go

### Qué hace `ExecuteWrite`

1. abre una sesión de escritura en Neo4j
2. ejecuta una query Cypher con parámetros
3. devuelve error si algo falla

### Por qué se eligió este enfoque

Porque en esta fase era más importante validar el modelo del grafo que diseñar aún toda una capa de puertos de relaciones.

Esto permitió:

- avanzar rápido
- no bloquear la implementación
- confirmar visualmente que la estructura funciona

## 6. Problemas encontrados y cómo se resolvieron

Durante la implementación aparecieron varios problemas importantes.

## 6.1 Mismatch entre constructor y call sites

Al añadir `SoftwareInstallationPort` en `NewNeo4jRepository(...)`, cambió el número de valores devueltos.

Eso obligaba a actualizar los puntos donde se desempaquetaba el constructor.

### Problema

Los tests antiguos seguían esperando 11 valores cuando el constructor ya devolvía 12.

### Estado

Esto se detectó, se documentó, y se decidió no tocar todavía los otros tests porque el foco de esta fase era exclusivamente `prueba_grafo_endpoint`.

## 6.2 Campos erróneos en `SoftwareInstallation`

En una versión intermedia se intentó usar:

- `SoftwareID`
- `EndpointID`

dentro de `SoftwareInstallation`.

### Problema

Esos campos no existían en el dominio actual.

### Resolución

Se eliminó esa idea y se dejó claro que:

- la relación con `Endpoint` se representa mediante aristas
- la relación con `Software` también se representa mediante aristas

Esto es más correcto desde el punto de vista del grafo.

## 6.3 Error de validación Cypher en Neo4j Browser

Se detectó una query incorrecta:

```cypher
MATCH p=(p:Project)-[:HAS_ENDPOINT]->(e:Endpoint)
RETURN p
```

### Problema

La variable `p` se usaba dos veces:

- como path
- como nodo `Project`

### Resolución

Se corrigió a algo como:

```cypher
MATCH path=(proj:Project)-[:HAS_ENDPOINT]->(e:Endpoint)
RETURN path
```

## 6.4 Persistencia parcial de algunos campos

La salida por consola mostró que algunos campos seguían volviendo vacíos o en cero:

- fechas de `Finding`
- `ReleaseDate` de `Patch`
- otros atributos parciales en diferentes nodos

### Por qué pasa

Porque algunos repositorios actuales solo persisten un subconjunto del struct de dominio.

### Importancia

Esto no rompe la validación del grafo.

En esta fase, la prioridad era validar:

- existencia de nodos
- existencia de relaciones
- navegabilidad del grafo

no todavía la persistencia completa de todas las propiedades.

## 7. Archivos creados y modificados

## 7.1 Archivos funcionales principales

- internal/core/domain/software_installation.go
- internal/core/ports/ports.go
- internal/adapters/repository/neo4j_repo.go
- cmd/Pruebas/prueba_grafo_endpoint/main.go

## 7.2 Archivos de documentación generados durante el proceso

- validate_v1.0.md

## 8. Resultado conseguido

El resultado de esta fase es que ahora existe una prueba funcional capaz de generar un grafo conectado en Neo4j con este flujo conceptual:

- `Project`
- `Endpoint`
- `Hardware`
- `Network`
- `SoftwareInstallation`
- `Software`
- `Finding`
- `Vulnerability`
- `Remediation`
- `Patch`

Y con relaciones navegables entre ellos.

Eso ya permite:

- inspección visual en Neo4j Browser
- validación de paths
- validación del modelo de datos
- preparar la siguiente fase de formalización arquitectónica

## 9. Pasos de validación realizados

Estas son las validaciones que se hicieron y que cualquier persona puede repetir.

## 9.1 Compilación del ejecutable

Se validó la compilación con:

```bash
env GOCACHE=/tmp/gocache go build ./cmd/Pruebas/prueba_grafo_endpoint
```

### Objetivo

Confirmar que:

- el código compila
- el binario de prueba está listo para ejecutarse

## 9.2 Ejecución de la prueba

Se ejecutó:

```bash
go run ./cmd/Pruebas/prueba_grafo_endpoint
```

### Resultado esperado

- conexión exitosa a Neo4j
- limpieza de la BD
- creación de nodos
- creación de relaciones
- salida final de éxito

## 9.3 Validación en Neo4j Browser

Se abrió:

```text
http://localhost:7474
```

Con:

- usuario: `neo4j`
- contraseña: `password`

Y se validó con las siguientes queries.

### a. Ver todos los nodos

```cypher
MATCH (n)
RETURN n
```

### b. Ver todas las relaciones

```cypher
MATCH ()-[r]->()
RETURN r
```

### c. Ver la relación proyecto -> endpoint

```cypher
MATCH path=(proj:Project)-[:HAS_ENDPOINT]->(e:Endpoint)
RETURN path
```

### d. Ver endpoint -> instalación -> software

```cypher
MATCH path=(e:Endpoint)-[:HAS_INSTALLATION]->(si:SoftwareInstallation)-[:INSTANCE_OF]->(s:Software)
RETURN path
```

### e. Ver instalación -> finding -> vulnerability

```cypher
MATCH path=(si:SoftwareInstallation)-[:HAS_FINDING]->(f:Finding)-[:OF_VULNERABILITY]->(v:Vulnerability)
RETURN path
```

### f. Ver cadena de remediación

```cypher
MATCH path=(f:Finding)-[:HAS_REMEDIATION]->(r:Remediation)-[:USES_PATCH]->(pa:Patch)-[:FIXES]->(v:Vulnerability)
RETURN path
```

### g. Contar relaciones por tipo

```cypher
MATCH ()-[r]->()
RETURN type(r) AS relationship, count(*) AS total
ORDER BY relationship
```

## 10. Cómo replicar exactamente lo que hicimos

Para reproducir esta implementación en otro entorno:

## Paso 1

Asegurarse de tener Neo4j levantado, por ejemplo con Docker Compose, y exponer:

- `7474`
- `7687`

## Paso 2

Configurar `.env` con al menos:

```env
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=password
```

## Paso 3

Compilar el ejecutable:

```bash
env GOCACHE=/tmp/gocache go build ./cmd/Pruebas/prueba_grafo_endpoint
```

## Paso 4

Ejecutarlo:

```bash
go run ./cmd/Pruebas/prueba_grafo_endpoint
```

## Paso 5

Abrir Neo4j Browser:

```text
http://localhost:7474
```

## Paso 6

Ejecutar las queries de validación descritas en:

- validate_v1.0.md

## 11. Siguientes pasos por fases

Ahora que la Phase 1 ya demuestra que el grafo funciona, el siguiente trabajo se puede organizar así.

## Phase 2: Formalizar relaciones en la capa de puertos

### Objetivo

Dejar de escribir relaciones con Cypher “a mano” desde `main.go`.

### Qué hacer

- crear un puerto de relaciones, por ejemplo:
  - `RelationshipPort`
  - o `TopologyPort`
- mover las queries Cypher de relaciones al adaptador Neo4j

### Beneficio

- menos lógica Cypher en ejecutables
- más claridad semántica
- mejor mantenibilidad

## Phase 3: Servicios de aplicación

### Objetivo

Pasar de scripts de prueba a casos de uso reales.

### Qué hacer

- implementar `internal/core/service/orchestrator.go`
- definir casos como:
  - crear proyecto
  - añadir endpoint al proyecto
  - asociar hardware
  - asociar red
  - registrar instalación
  - generar findings
  - asociar vulnerabilidades y remediaciones

### Beneficio

- lógica de negocio centralizada
- menos código procedural en `cmd/Pruebas`

## Phase 4: Consultas de lectura útiles

### Objetivo

No solo escribir el grafo, sino poder consumirlo bien.

### Qué hacer

- queries para:
  - obtener el contexto completo de un endpoint
  - obtener todos los endpoints de un proyecto
  - obtener findings por instalación
  - obtener vulnerabilidades por proyecto
  - obtener la cadena de remediación de un finding

### Beneficio

- el grafo pasa a ser realmente útil para la aplicación

## Phase 5: API HTTP

### Objetivo

Exponer esta lógica a frontend u otros consumidores.

### Qué hacer

- implementar handlers reales
- implementar router real
- cablear `cmd/main.go`

### Beneficio

- el backend deja de ser solo una prueba o prototipo
- pasa a ser una API funcional

## 12. Conclusión

Esta implementación ha servido para cerrar con éxito la primera validación seria del modelo de grafo sobre Neo4j.

Lo más importante que se consiguió fue:

- añadir el concepto correcto de `SoftwareInstallation`
- persistirlo en Neo4j
- conectar nodos mediante relaciones reales
- validar el resultado visualmente en Neo4j Browser

Eso convierte el proyecto en algo mucho más cercano a un backend de grafo real, y deja bien preparada la evolución hacia fases más limpias y más completas a nivel arquitectónico.
