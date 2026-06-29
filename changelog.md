# Changelog - Backend

Todos los cambios notables realizados en el backend del Orquestador serán documentados en este archivo. El formato está basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/).

## [0.1.0] - 2026-06-22

### Añadido
- **Estructura de Directorios:** Seguimos patron de arquitectura hexagonal pura, la estructura de carpetas esta siguiendo las practicas de esta arquitectura y se ha creado un poco la base de los archivos necesarios, en ellos hay comentarios de su funcionalidad con la aplicacion.


## [0.1.1] - 2026-06-27 - Tillo

### Modificacion
- **Dominios en Core:** Ampliacion de los dominios en core para acercarlo al modelo de BBDD propuesto. Se han añadido ademas los dominios Remediation y Finding para gestionar la asociacion de vulnerabilidades con un Endpoint y las remediaciones de dichas vulnerabilidades

## [0.1.2] - 2026-06-27 - Lucas

### Modificacion
- Parse .envs en internal/config/config.go y parseo de api del nist en internal/adapters/privider/nvd.go