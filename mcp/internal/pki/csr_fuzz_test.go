package pki

import "testing"

func FuzzParseCSR(f *testing.F) {
	f.Add([]byte("-----BEGIN CERTIFICATE REQUEST-----\nbm90IGEgY3Ny\n-----END CERTIFICATE REQUEST-----\n"))
	f.Add([]byte(""))
	f.Add([]byte("\x00\x00\x00"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseCSR(data)
	})
}
