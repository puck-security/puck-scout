package config

import (
	"testing"
)

func TestTransportAuth_DefaultsApplied(t *testing.T) {
	c := Config{MCPToken: "some-token"}
	if err := c.ValidateTransportAuth(); err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if c.CACertPath != "/etc/puck-mcp/ca.pem" {
		t.Fatalf("ca_cert_path: %q", c.CACertPath)
	}
	if len(c.ServerCertSans) != 3 {
		t.Fatalf("default SANs: %v", c.ServerCertSans)
	}
}

func TestTransportAuth_RejectsEmptyMCPToken(t *testing.T) {
	c := Config{}
	if err := c.ValidateTransportAuth(); err == nil {
		t.Fatal("expected error for empty mcp_token")
	}
}
