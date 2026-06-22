package handler

/*
Este archivo configura el Enrutador HTTP (ServeMux).

Propósito arquitectónico y teórico:
1. Ubicación en Arquitectura Hexagonal: Se localiza en `internal/adapters/handler`, actuando como el configurador y distribuidor de peticiones HTTP hacia los handlers correspondientes.
2. Multiplexación de Peticiones: Mapea los patrones de rutas y verbos HTTP (sintaxis nativa de Go 1.22+: "METHOD /path/{param}") con sus respectivos controladores de la capa de handlers.
3. Cadena de Filtros (Middleware Chain): Envuelve el enrutador en las funciones decoradoras (CORS, Logger) para aplicarles reglas de seguridad y auditoría global de forma centralizada.
*/
