package domain

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestNormalizeCIDR(t *testing.T) {
	cases := []struct{ in, want string; wantErr bool }{
		{"10.0.1.0/24", "10.0.1.0/24", false},
		{"10.0.1.37/24", "10.0.1.0/24", false},
		{" 10.0.1.0/24 ", "10.0.1.0/24", false},
		{"192.168.0.0/16", "192.168.0.0/16", false},
		{"10.0.1.0", "", true},
		{"", "", true},
		{"no-es-un-cidr", "", true},
		{"10.0.1.0/33", "", true},
	}
	for _, c := range cases {
		got, err := NormalizeCIDR(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("NormalizeCIDR(%q) esperaba error, devolvió %q", c.in, got)
			} else if !errors.Is(err, ErrInvalidNetwork) {
				t.Errorf("NormalizeCIDR(%q) error no envuelve ErrInvalidNetwork: %v", c.in, err)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Errorf("NormalizeCIDR(%q) = %q, %v; quería %q", c.in, got, err, c.want)
		}
	}
}

func TestValidateAndNormalizeNetwork(t *testing.T) {
	ok := &Network{Nombre: " DMZ ", CIDR: "10.0.1.37/24", Gateway: " 10.0.1.1 ", VLANID: 100}
	if err := ValidateAndNormalizeNetwork(ok); err != nil {
		t.Fatalf("red válida rechazada: %v", err)
	}
	if ok.Nombre != "DMZ" || ok.CIDR != "10.0.1.0/24" || ok.Gateway != "10.0.1.1" {
		t.Fatalf("normalización incorrecta: %+v", ok)
	}

	bad := []*Network{
		{Nombre: "", CIDR: "10.0.1.0/24", Gateway: "10.0.1.1"},
		{Nombre: "A", CIDR: "chorizo", Gateway: "10.0.1.1"},
		{Nombre: "A", CIDR: "10.0.1.0/24", Gateway: ""},
		{Nombre: "A", CIDR: "10.0.1.0/24", Gateway: "no-ip"},
		{Nombre: "A", CIDR: "10.0.1.0/24", Gateway: "192.168.5.1"}, // fuera de rango
		{Nombre: "A", CIDR: "10.0.1.0/24", Gateway: "10.0.1.1", VLANID: 5000},
		{Nombre: "A", CIDR: "10.0.1.0/24", Gateway: "10.0.1.1", VLANID: -1},
	}
	for i, nw := range bad {
		if err := ValidateAndNormalizeNetwork(nw); err == nil {
			t.Errorf("caso %d: red inválida aceptada: %+v", i, nw)
		} else if !errors.Is(err, ErrInvalidNetwork) {
			t.Errorf("caso %d: error no envuelve ErrInvalidNetwork: %v", i, err)
		}
	}
}

func TestGatewayMustBeUsableHost(t *testing.T) {
	rechazados := []struct {
		nombre  string
		cidr    string
		gateway string
	}{
		{"dirección de red /24", "10.0.1.0/24", "10.0.1.0"},
		{"broadcast /24", "10.0.1.0/24", "10.0.1.255"},
		{"dirección de red /16", "192.168.0.0/16", "192.168.0.0"},
		{"broadcast /16", "192.168.0.0/16", "192.168.255.255"},
		{"dirección de red /30", "10.0.1.0/30", "10.0.1.0"},
		{"broadcast /30", "10.0.1.0/30", "10.0.1.3"},
	}
	for _, c := range rechazados {
		nw := &Network{Nombre: "X", CIDR: c.cidr, Gateway: c.gateway}
		err := ValidateAndNormalizeNetwork(nw)
		if err == nil {
			t.Errorf("%s: se aceptó gateway %s en %s", c.nombre, c.gateway, c.cidr)
		} else if !errors.Is(err, ErrInvalidNetwork) {
			t.Errorf("%s: error no envuelve ErrInvalidNetwork: %v", c.nombre, err)
		}
	}

	aceptados := []struct {
		nombre  string
		cidr    string
		gateway string
	}{
		{"host normal", "10.0.1.0/24", "10.0.1.1"},
		{"último host usable", "10.0.1.0/24", "10.0.1.254"},
		{"/31 primera (RFC 3021)", "10.0.1.0/31", "10.0.1.0"},
		{"/31 segunda (RFC 3021)", "10.0.1.0/31", "10.0.1.1"},
		{"/32 host único", "10.0.1.5/32", "10.0.1.5"},
		{"IPv6 sin broadcast", "2001:db8::/32", "2001:db8::"},
	}
	for _, c := range aceptados {
		nw := &Network{Nombre: "X", CIDR: c.cidr, Gateway: c.gateway}
		if err := ValidateAndNormalizeNetwork(nw); err != nil {
			t.Errorf("%s: se rechazó gateway %s en %s: %v", c.nombre, c.gateway, c.cidr, err)
		}
	}
}

func TestNormalizeAssetIPs(t *testing.T) {
	// Las filas vacías del formulario se descartan; el resto se normaliza.
	got, err := NormalizeAssetIPs([]EndpointIP{
		{IP: " 10.0.1.5 ", VLANID: 100},
		{IP: "", VLANID: 0},
		{IP: "10.0.1.6", VLANID: 0},
	})
	if err != nil {
		t.Fatalf("lista válida rechazada: %v", err)
	}
	if len(got) != 2 || got[0].IP != "10.0.1.5" || got[1].IP != "10.0.1.6" {
		t.Fatalf("normalización incorrecta: %+v", got)
	}

	casos := []struct {
		nombre string
		ips    []EndpointIP
	}{
		{"IP repetida", []EndpointIP{{IP: "10.0.1.5"}, {IP: "10.0.1.5"}}},
		{"IP repetida con espacios", []EndpointIP{{IP: "10.0.1.5"}, {IP: " 10.0.1.5 "}}},
		{"IP no válida", []EndpointIP{{IP: "no-soy-una-ip"}}},
		{"IP incompleta", []EndpointIP{{IP: "10.0.1"}}},
		{"VLAN fuera de rango", []EndpointIP{{IP: "10.0.1.5", VLANID: 9999}}},
		{"VLAN negativa", []EndpointIP{{IP: "10.0.1.5", VLANID: -1}}},
	}
	for _, c := range casos {
		if _, err := NormalizeAssetIPs(c.ips); err == nil {
			t.Errorf("%s: se aceptó %+v", c.nombre, c.ips)
		} else if !errors.Is(err, ErrInvalidIP) {
			t.Errorf("%s: error no envuelve ErrInvalidIP: %v", c.nombre, err)
		}
	}
}

func TestFormatIPConflicts(t *testing.T) {
	if err := FormatIPConflicts(nil); err != nil {
		t.Errorf("sin conflictos debería devolver nil, devolvió %v", err)
	}

	err := FormatIPConflicts([]IPConflict{
		{IP: "10.0.1.5", AssetID: "3", AssetName: "web-01", AssetKind: "Endpoint"},
	})
	if !errors.Is(err, ErrDuplicateIP) {
		t.Fatalf("error no envuelve ErrDuplicateIP: %v", err)
	}
	if !strings.Contains(err.Error(), "10.0.1.5") || !strings.Contains(err.Error(), "web-01") {
		t.Errorf("el mensaje no identifica el conflicto: %v", err)
	}
}

func TestSentinelsDeDuplicado(t *testing.T) {
	// Cada tipo de colisión debe envolver su propio centinela: de ahí sale el código HTTP
	// que devuelve assetErrorStatus (409 para duplicados, 400 para datos inválidos).
	casos := []struct {
		nombre    string
		err       error
		centinela error
	}{
		{"activo duplicado", fmt.Errorf("%w: ya existe un activo", ErrDuplicateAsset), ErrDuplicateAsset},
		{"red duplicada", fmt.Errorf("%w: ya existe una red", ErrDuplicateNetwork), ErrDuplicateNetwork},
		{"IP duplicada", fmt.Errorf("%w: IP ocupada", ErrDuplicateIP), ErrDuplicateIP},
	}
	for _, c := range casos {
		if !errors.Is(c.err, c.centinela) {
			t.Errorf("%s: el error no envuelve su centinela", c.nombre)
		}
	}

	// Los centinelas no deben confundirse entre sí.
	if errors.Is(fmt.Errorf("%w: x", ErrDuplicateAsset), ErrDuplicateNetwork) {
		t.Error("ErrDuplicateAsset no debería coincidir con ErrDuplicateNetwork")
	}
	if errors.Is(fmt.Errorf("%w: x", ErrDuplicateAsset), ErrInvalidIP) {
		t.Error("ErrDuplicateAsset no debería coincidir con ErrInvalidIP")
	}
}
