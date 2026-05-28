package server

import (
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"time"

	"github.com/puck-security/puck-scout/mcp/internal/audit"
	"github.com/puck-security/puck-scout/mcp/internal/pki"
)

type renewRequest struct {
	CSRPem string `json:"csr_pem"`
}

// RenewCertHandler signs a new agent cert authenticated by the agent's
// current cert (already verified by the requireMTLSIdentity middleware).
type RenewCertHandler struct {
	CA      *pki.CA
	CertTTL time.Duration
	Audit   *audit.Logger
}

func (h *RenewCertHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Cap body size: a CSR is under 1 KiB; 64 KiB is generous while still
	// preventing unbounded reads from misbehaving or malicious agents.
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)

	hostname := HostnameFromContext(r.Context())
	var req renewRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "malformed json body", http.StatusBadRequest)
		return
	}
	csr, err := pki.ParseCSR([]byte(req.CSRPem))
	if err != nil {
		http.Error(w, "csr invalid: "+err.Error(), http.StatusBadRequest)
		return
	}
	if csr.Subject != hostname {
		http.Error(w, "csr subject does not match presented cert hostname", http.StatusForbidden)
		return
	}
	certPEM, notAfter, serial, err := pki.SignAgentCert(h.CA, csr, h.CertTTL)
	if err != nil {
		http.Error(w, "sign failure", http.StatusInternalServerError)
		return
	}

	if h.Audit != nil {
		_ = h.Audit.Log(audit.Entry{
			EventType: audit.EventCertIssued,
			Hostname:  hostname,
			Reason:    fmt.Sprintf("serial=%s lifetime_days=%d renew=true not_after=%s", serial.String(), int(h.CertTTL.Hours()/24), notAfter.UTC().Format(time.RFC3339)),
		})
	}

	caCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: h.CA.CertDER})
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(enrollResponse{
		CertPEM:   string(certPEM),
		CACertPEM: string(caCertPEM),
		NotAfter:  notAfter,
	})
}
