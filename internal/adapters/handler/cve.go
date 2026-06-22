package handler

/*
Este archivo contiene los Controladores / Manejadores (HTTP Handlers) de la API REST.

Propósito arquitectónico y teórico:
1. Ubicación en Arquitectura Hexagonal: Se localiza en `internal/adapters/handler`, actuando como un Adaptador de Entrada (Driving Adapter) que traduce las peticiones HTTP entrantes en llamadas comprensibles por los puertos del Core.
2. Adaptador de Entrada (Driving Adapter): Sirve como la interfaz de entrada HTTP para interactuar con el sistema de vulnerabilidades.
3. Serialización y Deserialización: Traduce payloads de formato JSON a tipos estructurados del dominio (Deserialización) y codifica las estructuras de negocio de vuelta a formato JSON (Serialización).
4. Gestión del Protocolo HTTP: Configura cabeceras específicas (Content-Type: application/json), valida el método HTTP y asigna el código de estado adecuado (200 OK, 400 Bad Request, 500 Internal Server Error) basándose en las respuestas devueltas por los servicios del dominio.
*/
