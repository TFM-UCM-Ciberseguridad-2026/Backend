package middleware

/*
Este archivo define la capa de Middleware (Interceptores HTTP).

Propósito arquitectónico y teórico:
1. Ubicación en Arquitectura Hexagonal: Pertenece a la infraestructura de entrada (`internal/adapters/handler/middleware`), filtrando y preprocesando peticiones antes de que lleguen a los controladores de negocio.
2. Patrón Decorador / Cadena de Responsabilidad: Intercepta y procesa las peticiones HTTP entrantes y salientes antes y después de que lleguen a los manejadores de endpoints de la API (handlers).
3. Control de CORS (Cross-Origin Resource Sharing): Inyecta cabeceras HTTP que declaran orígenes permitidos, métodos y cabeceras admitidas por el servidor para autorizar llamadas cross-origin del navegador.
4. Observabilidad e Instrumentación: Loguea el tráfico HTTP de entrada (IP, método, ruta) y evalúa el tiempo de respuesta en milisegundos para monitorear el rendimiento de la API.
*/
