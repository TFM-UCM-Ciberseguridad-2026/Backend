package provider

/*
Este archivo implementa el Adaptador de Salida (Outbound/Driven Adapter) para la API v2.0 del NIST NVD (National Vulnerability Database).

Propósito arquitectónico y teórico:
1. Ubicación en Arquitectura Hexagonal: Se localiza en `internal/adapters/provider`, actuando como el adaptador técnico externo que interactúa con la API del NIST NVD e implementa el puerto correspondiente.
2. Adaptador en Arquitectura Hexagonal: Concreta la interfaz CVEProvider (Puerto) mediante una implementación técnica real conectada a un servicio web de terceros.
3. Encapsulación de Infraestructura HTTP: Centraliza la lógica de peticiones REST, control de cabeceras de autorización (apiKey), timeouts de red, manejo de códigos de estado HTTP y procesamiento de límites de peticiones (rate limiting).
4. Mapeo y Normalización de Datos: Traduce la respuesta estructurada de la API del NIST al modelo limpio del dominio (domain.CVE), abstrayendo al resto de la aplicación del formato externo.
*/
