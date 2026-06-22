package handler

/*
Este archivo encapsula el Ciclo de Vida del Servidor HTTP y el proceso de Graceful Shutdown (Apagado Seguro).

Propósito arquitectónico y teórico:
1. Ubicación en Arquitectura Hexagonal: Se localiza en `internal/adapters/handler`, como el cargador y gestor de ciclo de vida del servidor web de entrada.
2. Inicialización de Servidor Seguro: Configura los timeouts del puerto y sockets TCP (ReadTimeout, WriteTimeout, IdleTimeout) para mitigar vulnerabilidades de denegación de servicio por conexiones lentas (ej: Slowloris).
3. Apagado Seguro (Graceful Shutdown): Utiliza canales de comunicación del sistema operativo para escuchar señales de interrupción (SIGINT, SIGTERM). Al detectarse, bloquea la aceptación de nuevas conexiones y permite un margen de tiempo para que las peticiones activas completen sus respuestas antes de finalizar el proceso principal del backend.
*/
