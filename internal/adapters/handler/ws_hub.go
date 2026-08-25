package handler

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"sync"

	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/ports"
	"github.com/gorilla/websocket"
)

var wsUpgrader = websocket.Upgrader{
	// En producción, validar el Origin contra una lista blanca.
	CheckOrigin: func(r *http.Request) bool { return true },
}

// wsClient representa una conexión WebSocket activa con su suscripción de proyecto.
type wsClient struct {
	conn      *websocket.Conn
	projectID int64     // 0 = suscripción global (recibe todos los eventos)
	send      chan []byte
}

// WSHub gestiona todas las conexiones WebSocket activas e implementa ports.NotificationPort.
// Las conexiones se agrupan por projectID para garantizar aislamiento real de eventos entre proyectos.
type WSHub struct {
	mu      sync.RWMutex
	clients map[*wsClient]struct{}
}

// NewWSHub crea un hub vacío listo para aceptar conexiones.
func NewWSHub() *WSHub {
	return &WSHub{clients: make(map[*wsClient]struct{})}
}

// NotifyTTPMapped implementa ports.NotificationPort.
//
// Regla de entrega:
//   - c.projectID == 0  → cliente global, recibe TODOS los eventos (sweep automático + manuales)
//   - c.projectID == N  → cliente de proyecto N, recibe SOLO eventos donde event.ProjectID == N
//
// Demostración de aislamiento:
//   Cliente A: projectID=2, Cliente B: projectID=1
//   Evento: ProjectID=1 → solo llega a Cliente B (y a cualquier suscriptor global).
//   Cliente A: c.projectID(2) == 0? NO → c.projectID(2) == event.ProjectID(1)? NO → descartado.
func (h *WSHub) NotifyTTPMapped(_ context.Context, event ports.TTPMappedEvent) error {
	data, err := json.Marshal(map[string]any{
		"type":  "CVE_MAPPED",
		"event": event,
	})
	if err != nil {
		return err
	}

	h.mu.RLock()
	defer h.mu.RUnlock()

	for c := range h.clients {
		// FILTRO REAL: entregar solo si el cliente es global o coincide el proyecto
		if c.projectID == 0 || c.projectID == event.ProjectID {
			select {
			case c.send <- data:
			default:
				log.Printf("[WSHub] Canal lleno para cliente projectID=%d, evento descartado", c.projectID)
			}
		}
	}
	return nil
}

// ServeWS realiza el upgrade HTTP→WebSocket y registra el cliente en el hub.
// El cliente indica su suscripción mediante el query param ?project_id=N.
// Si omite el parámetro (o envía 0), queda suscrito a "global".
func (h *WSHub) ServeWS(w http.ResponseWriter, r *http.Request) {
	conn, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[WSHub] Error en upgrade WebSocket: %v", err)
		return
	}

	var projectID int64
	if pidStr := r.URL.Query().Get("project_id"); pidStr != "" {
		if pid, err := strconv.ParseInt(pidStr, 10, 64); err == nil {
			projectID = pid
		}
	}

	client := &wsClient{
		conn:      conn,
		projectID: projectID,
		send:      make(chan []byte, 512),
	}

	h.mu.Lock()
	h.clients[client] = struct{}{}
	h.mu.Unlock()

	log.Printf("[WSHub] Cliente conectado (projectID=%d). Total activos: %d", projectID, len(h.clients))

	// Writer goroutine: consume el canal send y escribe al WebSocket.
	go func() {
		defer func() {
			h.mu.Lock()
			delete(h.clients, client)
			h.mu.Unlock()
			conn.Close()
			log.Printf("[WSHub] Cliente desconectado (projectID=%d). Total activos: %d", projectID, len(h.clients))
		}()
		for msg := range client.send {
			if err := conn.WriteMessage(websocket.TextMessage, msg); err != nil {
				return
			}
		}
	}()

	// Reader goroutine: necesaria para detectar el cierre del cliente (ping/pong o EOF).
	// Los mensajes entrantes del cliente se descartan; el canal es unidireccional servidor→cliente.
	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			close(client.send)
			break
		}
	}
}
