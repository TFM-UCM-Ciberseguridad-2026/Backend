package domain

import (
	"reflect"
	"testing"
)

func TestSanitizeAndTokenizeInput(t *testing.T) {
	tests := []struct {
		name             string
		input            string
		expectedTokens   []string
		expectedVersion  string
	}{
		{
			name:            "Ejemplo Contec SolarView",
			input:           "Contec  SolarView  v6.0",
			expectedTokens:  []string{"contec", "solarview"},
			expectedVersion: "6.0",
		},
		{
			name:            "Software con guiones y slash",
			input:           "F5/NGINX-Server v1.24.0",
			expectedTokens:  []string{"f5", "nginx"},
			expectedVersion: "1.24.0",
		},
		{
			name:            "Sin versión explicita",
			input:           "PostgreSQL Database",
			expectedTokens:  []string{"postgresql", "database"},
			expectedVersion: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokens, version := SanitizeAndTokenizeInput(tt.input)
			if !reflect.DeepEqual(tokens, tt.expectedTokens) {
				t.Errorf("SanitizeAndTokenizeInput(%q) tokens = %v, expected %v", tt.input, tokens, tt.expectedTokens)
			}
			if version != tt.expectedVersion {
				t.Errorf("SanitizeAndTokenizeInput(%q) version = %q, expected %q", tt.input, version, tt.expectedVersion)
			}
		})
	}
}
