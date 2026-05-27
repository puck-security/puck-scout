package server

import "testing"

func TestBindOrAdvise_SuccessOnFreePort(t *testing.T) {
	lst, err := BindOrAdvise(":0", "test_listener")
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	defer lst.Close()
	if lst.Addr().Network() != "tcp" {
		t.Fatalf("network: %s", lst.Addr().Network())
	}
}
