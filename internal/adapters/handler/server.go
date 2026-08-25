package handler

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

/*
Este archivo encapsula el Ciclo de Vida del Servidor HTTP y el proceso de Graceful Shutdown (Apagado Seguro).

Propósito arquitectónico y teórico:
1. Ubicación en Arquitectura Hexagonal: Se localiza en `internal/adapters/handler`, como el cargador y gestor de ciclo de vida del servidor web de entrada.
2. Inicialización de Servidor Seguro: Configura los timeouts del puerto y sockets TCP (ReadTimeout, WriteTimeout, IdleTimeout) para mitigar vulnerabilidades de denegación de servicio por conexiones lentas (ej: Slowloris).
3. Apagado Seguro (Graceful Shutdown): Utiliza canales de comunicación del sistema operativo para escuchar señales de interrupción (SIGINT, SIGTERM). Al detectarse, bloquea la aceptación de nuevas conexiones y permite un margen de tiempo para que las peticiones activas completen sus respuestas antes de finalizar el proceso principal del backend.
*/

// Server encapsula la lógica del servidor HTTP.
type Server struct {
	httpServer *http.Server
}

// NewServer crea un nuevo servidor HTTP preconfigurado con timeouts seguros.
func NewServer(port string, handler http.Handler) *Server {
	return &Server{
		httpServer: &http.Server{
			Addr:         port,
			Handler:      handler,
			ReadTimeout:  300 * time.Second,
			WriteTimeout: 300 * time.Second,
			IdleTimeout:  120 * time.Second,
		},
	}
}

// Start inicia el servidor y maneja el graceful shutdown.
func (s *Server) Start() {
	// Canal para escuchar señales del SO.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	// Goroutine para ejecutar el servidor.
	go func() {
		fmt.Printf("Servidor HTTP levantado en el puerto %s\n", s.httpServer.Addr)
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Error crítico en el servidor HTTP: %v", err)
		}
	}()

	// Bloquear hasta recibir señal.
	<-stop
	fmt.Println("\nRecibida señal de interrupción. Iniciando apagado seguro (Graceful Shutdown)...")

	// Contexto con timeout de 5 segundos para cerrar conexiones activas.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := s.httpServer.Shutdown(ctx); err != nil {
		log.Fatalf("Error durante el apagado del servidor: %v", err)
	}

	fmt.Println("Servidor HTTP apagado correctamente.")
}
