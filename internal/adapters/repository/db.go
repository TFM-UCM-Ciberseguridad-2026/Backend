package repository

/*
Este archivo gestiona el Adaptador de Salida (Outbound/Driven Adapter) para la persistencia de datos en Mariadb.

Propósito arquitectónico y teórico:
1. Ubicación en Arquitectura Hexagonal: Se localiza en `internal/adapters/repository`, actuando como el adaptador técnico concreto que implementa las interfaces de persistencia (puertos) del dominio.
2. Conexión e Infraestructura de Persistencia: Modela la conexión física con el motor de base de datos relacional (mariadb) usando la configuración de entorno cargada.
4. Aislamiento de Persistencia: Actúa como el puente que las implementaciones de los repositorios usarán para ejecutar sentencias de base de datos relacionales sin contaminar el dominio.
*/
