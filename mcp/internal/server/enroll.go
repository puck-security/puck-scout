package server

import (
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/puck-security/puck-scout/mcp/internal/audit"
	"github.com/puck-security/puck-scout/mcp/internal/pki"
)

type enrollRequest struct {
	Hostname string `json:"hostname"`
	CSRPem   string `json:"csr_pem"`
}

type enrollResponse struct {
	CertPEM   string    `json:"cert_pem"`
	CACertPEM string    `json:"ca_cert_pem"`
	NotAfter  time.Time `json:"not_after"`
}

// EnrollHandler signs an agent cert in exchange for a valid bootstrap token.
// Authentication is via `Authorization: Bearer puck-bt-…`.
type EnrollHandler struct {
	CA      *pki.CA
	Ledger  *pki.TokenLedger
	CertTTL time.Duration
	Audit   *audit.Logger
}

func (h *EnrollHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Cap body size: a CSR is under 1 KiB; 64 KiB is generous while still
	// preventing unbounded reads from misbehaving or malicious agents.
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)

	token, ok := extractBootstrapToken(r)
	if !ok {
		http.Error(w, "bootstrap token required in Authorization: Bearer header", http.StatusUnauthorized)
		return
	}

	var req enrollRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "malformed json body", http.StatusBadRequest)
		return
	}
	if req.Hostname == "" || req.CSRPem == "" {
		http.Error(w, "hostname and csr_pem required", http.StatusBadRequest)
		return
	}
	// Canonicalise the hostname to lowercase so token binding, the issued
	// cert's identity, and later fleet-query routing all agree regardless of
	// the case the operator typed.  See server/identity.go for the rationale.
	req.Hostname = strings.ToLower(req.Hostname)

	// Parse + validate the CSR shape before consuming the token.  Garbage
	// CSRs shouldn't waste single-use tokens.
	csr, err := pki.ParseCSR([]byte(req.CSRPem))
	if err != nil {
		http.Error(w, "csr invalid: "+err.Error(), http.StatusBadRequest)
		return
	}
	// Case-insensitive CN match: the agent may present a mixed-case CSR CN
	// (e.g. an older agent that did not lowercase its hostname) while we
	// canonicalised req.Hostname above.  Identity is derived case-folded at
	// every comparison point, so EqualFold is the correct equality here.
	if !strings.EqualFold(csr.Subject, req.Hostname) {
		http.Error(w, "csr subject CN does not match hostname", http.StatusBadRequest)
		return
	}

	// Atomic validate+spend: closes the race where two concurrent enrollments
	// could each pass Validate and both get certs signed for the same hostname.
	// After this returns nil, the token is spent on disk; cert issuance below
	// is allowed to fail (operator just issues a new token).
	if err := h.Ledger.ValidateAndSpend(token, req.Hostname); err != nil {
		switch {
		case errors.Is(err, pki.ErrTokenHostMismatch):
			http.Error(w, "token hostname mismatch", http.StatusForbidden)
		case errors.Is(err, pki.ErrTokenSpent):
			http.Error(w, "bootstrap token already spent (issue a new one with `puck-mcp generate-bootstrap-token`)", http.StatusUnauthorized)
		case errors.Is(err, pki.ErrTokenExpired):
			http.Error(w, "bootstrap token expired (issue a new one with `puck-mcp generate-bootstrap-token`)", http.StatusUnauthorized)
		case errors.Is(err, pki.ErrTokenUnknown):
			http.Error(w, "bootstrap token unknown", http.StatusUnauthorized)
		default:
			http.Error(w, "bootstrap token invalid", http.StatusUnauthorized)
		}
		return
	}

	certPEM, notAfter, serial, err := pki.SignAgentCert(h.CA, csr, h.CertTTL)
	if err != nil {
		// Token already spent.  Audit so operators can correlate "issued a
		// token that the agent never cleanly enrolled with" — they'll need
		// to issue a fresh token.
		if h.Audit != nil {
			_ = h.Audit.Log(audit.Entry{
				EventType: audit.EventCertIssuanceFailed,
				Hostname:  req.Hostname,
				Reason:    "sign failed after token consumed: " + err.Error(),
			})
		}
		http.Error(w, "sign failure", http.StatusInternalServerError)
		return
	}

	if h.Audit != nil {
		_ = h.Audit.Log(audit.Entry{
			EventType: audit.EventCertIssued,
			Hostname:  req.Hostname,
			Reason: fmt.Sprintf("serial=%s lifetime_days=%d not_after=%s",
				serial.String(), int(h.CertTTL.Hours()/24), notAfter.UTC().Format(time.RFC3339)),
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

func extractBootstrapToken(r *http.Request) (string, bool) {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return "", false
	}
	tok := strings.TrimPrefix(auth, "Bearer ")
	if !strings.HasPrefix(tok, "puck-bt-") {
		return "", false
	}
	return tok, true
}
