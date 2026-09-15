package handler

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/ports"
)

func clienteDePrueba(h *WSHub, projectID int64) *wsClient {
	c := &wsClient{projectID: projectID, send: make(chan []byte, 4)}
	h.clients[c] = struct{}{}
	return c
}

func mensajeRecibido(c *wsClient) []byte {
	select {
	case m := <-c.send:
		return m
	default:
		return nil
	}
}

func TestNotifyTTPMappedEntregaATodosLosProyectosDelEvento(t *testing.T) {
	h := NewWSHub()
	global := clienteDePrueba(h, 0)
	a := clienteDePrueba(h, 1)
	b := clienteDePrueba(h, 2)
	ajeno := clienteDePrueba(h, 3)

	err := h.NotifyTTPMapped(context.Background(), ports.TTPMappedEvent{
		CVEID:      "CVE-2099-0001",
		ProjectIDs: []int64{1, 2},
		Result:     ports.ResultadoTTPMapeada,
		Remaining:  map[int64]int{1: 0, 2: 3},
	})
	if err != nil {
		t.Fatal(err)
	}

	for nombre, c := range map[string]*wsClient{"global": global, "proyecto 1": a, "proyecto 2": b} {
		if mensajeRecibido(c) == nil {
			t.Errorf("%s no recibió el evento", nombre)
		}
	}
	if mensajeRecibido(ajeno) != nil {
		t.Errorf("un proyecto que no está en el evento lo recibió")
	}
}

func TestNotifyTTPMappedSoloGlobalNoLlegaAProyectos(t *testing.T) {
	h := NewWSHub()
	global := clienteDePrueba(h, 0)
	proyecto := clienteDePrueba(h, 1)

	_ = h.NotifyTTPMapped(context.Background(), ports.TTPMappedEvent{CVEID: "CVE-2099-0002", ProjectIDs: []int64{0}})

	if mensajeRecibido(global) == nil {
		t.Errorf("el cliente global no recibió el evento")
	}
	if mensajeRecibido(proyecto) != nil {
		t.Errorf("un evento solo global llegó a un proyecto")
	}
}

// El frontend lee project_ids, result y remaining (con claves de texto).
func TestNotifyTTPMappedFormatoDelMensaje(t *testing.T) {
	h := NewWSHub()
	c := clienteDePrueba(h, 7)
	_ = h.NotifyTTPMapped(context.Background(), ports.TTPMappedEvent{
		CVEID:      "CVE-2099-0003",
		ProjectIDs: []int64{7},
		Result:     ports.ResultadoTTPSinTecnicas,
		Remaining:  map[int64]int{7: 2},
	})

	var msg struct {
		Type  string `json:"type"`
		Event struct {
			ProjectIDs []int64        `json:"project_ids"`
			Result     string         `json:"result"`
			Remaining  map[string]int `json:"remaining"`
		} `json:"event"`
	}
	if err := json.Unmarshal(mensajeRecibido(c), &msg); err != nil {
		t.Fatal(err)
	}
	if msg.Type != "CVE_MAPPED" || msg.Event.Result != "no_ttps" || msg.Event.Remaining["7"] != 2 || len(msg.Event.ProjectIDs) != 1 {
		t.Errorf("mensaje inesperado: %+v", msg)
	}
}
