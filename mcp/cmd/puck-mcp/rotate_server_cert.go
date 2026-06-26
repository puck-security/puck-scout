package main

import (
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/puck-security/puck-scout/mcp/internal/config"
	"github.com/puck-security/puck-scout/mcp/internal/pki"
	"gopkg.in/yaml.v3"
)

// stringSliceFlag accumulates repeated --add-san / --remove-san values.
type stringSliceFlag []string

func (s *stringSliceFlag) String() string { return strings.Join(*s, ",") }
func (s *stringSliceFlag) Set(v string) error {
	v = strings.TrimSpace(v)
	if v == "" {
		return fmt.Errorf("empty value")
	}
	*s = append(*s, v)
	return nil
}

func runRotateServerCert(args []string) error {
	fs := flag.NewFlagSet("rotate-server-cert", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConfigPath(), "path to puck-mcp.yaml")
	var addSan stringSliceFlag
	var removeSan stringSliceFlag
	replaceSans := fs.String("replace-sans", "", "comma-separated SAN list; replaces the entire list (mutually exclusive with --add-san/--remove-san)")
	list := fs.Bool("list", false, "print current SANs and exit without regenerating")
	fs.Var(&addSan, "add-san", "DNS name or IP to add to the server cert (repeatable)")
	fs.Var(&removeSan, "remove-san", "DNS name or IP to remove from the server cert (repeatable)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: puck-mcp rotate-server-cert [flags]")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Regenerate the MCP-server TLS cert with an updated SAN list. The CA is")
		fmt.Fprintln(os.Stderr, "preserved, so already-enrolled agents continue to trust the new cert")
		fmt.Fprintln(os.Stderr, "without re-enrolling — they pin the CA, not the leaf.")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Flags:")
		fmt.Fprintf(os.Stderr, "  --config string        path to puck-mcp.yaml (default %q)\n", defaultConfigPath())
		fmt.Fprintln(os.Stderr, "  --add-san value        DNS name or IP to add (repeatable)")
		fmt.Fprintln(os.Stderr, "  --remove-san value     DNS name or IP to remove (repeatable)")
		fmt.Fprintln(os.Stderr, "  --replace-sans csv     comma-separated list that replaces the current SANs")
		fmt.Fprintln(os.Stderr, "                         (mutually exclusive with --add-san/--remove-san)")
		fmt.Fprintln(os.Stderr, "  --list                 print current SANs and exit")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Examples:")
		fmt.Fprintln(os.Stderr, "  puck-mcp rotate-server-cert --list")
		fmt.Fprintln(os.Stderr, "  puck-mcp rotate-server-cert --add-san mybox.tail-abc.ts.net")
		fmt.Fprintln(os.Stderr, "  puck-mcp rotate-server-cert --add-san 100.64.0.5 --add-san mybox.local")
		fmt.Fprintln(os.Stderr, "  puck-mcp rotate-server-cert --replace-sans \"mybox.example.com,127.0.0.1\"")
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *replaceSans != "" && (len(addSan) > 0 || len(removeSan) > 0) {
		return fmt.Errorf("--replace-sans is mutually exclusive with --add-san and --remove-san")
	}

	if err := requireConfigFound(fs, *cfgPath); err != nil {
		return err
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	// --list: print and exit.
	if *list {
		printSANs(os.Stdout, "configured (from puck-mcp.yaml)", cfg.ServerCertSans)
		// Also print what the cert on disk actually has, so the operator can
		// spot the case where the cert was regenerated outside this command.
		if certSANs, err := readServerCertSANs(cfg.ServerCertPath); err == nil {
			printSANs(os.Stdout, "on disk ("+cfg.ServerCertPath+")", certSANs)
		}
		return nil
	}

	// Compute the new SAN list.
	var newSans []string
	switch {
	case *replaceSans != "":
		for _, s := range strings.Split(*replaceSans, ",") {
			if s = strings.TrimSpace(s); s != "" {
				newSans = append(newSans, s)
			}
		}
	default:
		newSans = append(newSans, cfg.ServerCertSans...)
		removeSet := map[string]struct{}{}
		for _, s := range removeSan {
			removeSet[s] = struct{}{}
		}
		filtered := newSans[:0]
		for _, s := range newSans {
			if _, drop := removeSet[s]; !drop {
				filtered = append(filtered, s)
			}
		}
		newSans = filtered
		for _, s := range addSan {
			newSans = append(newSans, s)
		}
	}

	newSans = dedupeSANs(newSans)
	if len(newSans) == 0 {
		return fmt.Errorf("refusing to write an empty SAN list — pass at least one --add-san or --replace-sans value")
	}
	if equalStringSlices(newSans, cfg.ServerCertSans) {
		fmt.Println("No changes — SAN list is already:")
		printSANs(os.Stdout, "current", cfg.ServerCertSans)
		return nil
	}

	// Update puck-mcp.yaml first.  If the cert regeneration fails afterwards,
	// the next puck-mcp startup will regenerate using the new SAN list.
	if err := updateServerCertSansYAML(*cfgPath, newSans); err != nil {
		return fmt.Errorf("update %s: %w", *cfgPath, err)
	}

	// Load CA and regenerate the server cert.
	ca, err := pki.EnsureCA(cfg.CACertPath, cfg.CAKeyPath)
	if err != nil {
		return fmt.Errorf("load CA: %w", err)
	}
	if _, err := pki.RegenerateServerCert(ca, cfg.ServerCertPath, cfg.ServerKeyPath, newSans); err != nil {
		return fmt.Errorf("regenerate server cert: %w", err)
	}

	fmt.Println("Server cert regenerated with new SAN list:")
	printSANs(os.Stdout, "current", newSans)
	fmt.Println("")
	fmt.Println("Restart puck-mcp for the new cert to take effect:")
	fmt.Println("  - Claude Code stdio mode: quit Claude Code and reopen.")
	fmt.Println("  - systemd:                sudo systemctl restart puck-mcp")
	fmt.Println("  - launchd:                sudo launchctl kickstart -k system/io.puck.mcp")
	fmt.Println("")
	fmt.Println("Agents continue to trust the new cert because it is signed by the same CA;")
	fmt.Println("no re-enrollment is required.")
	return nil
}

// printSANs writes a small labelled SAN list to w.
func printSANs(w *os.File, label string, sans []string) {
	fmt.Fprintf(w, "  %s:\n", label)
	if len(sans) == 0 {
		fmt.Fprintln(w, "    (none)")
		return
	}
	for _, s := range sans {
		fmt.Fprintf(w, "    - %s\n", s)
	}
}

// dedupeSANs preserves first-seen order while dropping duplicates and any
// whitespace-only entries.  Net result is stable across repeated runs.
func dedupeSANs(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// updateServerCertSansYAML rewrites the server_cert_sans field in the
// puck-mcp.yaml at path, preserving every other field and most comments.
// Uses the yaml.v3 Node API so comments and field order survive.  If the
// file isn't a valid yaml top-level mapping, returns an error rather than
// guessing — re-marshalling a typed Config struct would strip comments and
// drop unknown fields, which is worse than failing loudly.
func updateServerCertSansYAML(path string, sans []string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return fmt.Errorf("parse yaml: %w", err)
	}
	if root.Kind != yaml.DocumentNode || len(root.Content) == 0 {
		return fmt.Errorf("unexpected yaml shape: top-level is not a document")
	}
	mapping := root.Content[0]
	if mapping.Kind != yaml.MappingNode {
		return fmt.Errorf("unexpected yaml shape: top-level is not a mapping")
	}

	newSeq := &yaml.Node{
		Kind: yaml.SequenceNode,
		// Style 0 = block (default). yaml.v3 has no exported BlockStyle constant.
	}
	for _, s := range sans {
		newSeq.Content = append(newSeq.Content, &yaml.Node{
			Kind:  yaml.ScalarNode,
			Tag:   "!!str",
			Value: s,
			Style: yaml.DoubleQuotedStyle,
		})
	}

	// Mapping nodes alternate key, value, key, value, ...
	found := false
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		k := mapping.Content[i]
		if k.Kind == yaml.ScalarNode && k.Value == "server_cert_sans" {
			mapping.Content[i+1] = newSeq
			found = true
			break
		}
	}
	if !found {
		// Append at end if the key isn't present (uncommon but possible).
		mapping.Content = append(mapping.Content, &yaml.Node{
			Kind:  yaml.ScalarNode,
			Tag:   "!!str",
			Value: "server_cert_sans",
		}, newSeq)
	}

	out, err := yaml.Marshal(&root)
	if err != nil {
		return fmt.Errorf("marshal yaml: %w", err)
	}
	// Write atomically.
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, out, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// readServerCertSANs returns the DNS + IP SANs from the cert at path, in a
// single string slice with IPs converted to their canonical String() form.
func readServerCertSANs(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("not a PEM file: %s", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	var sans []string
	sans = append(sans, cert.DNSNames...)
	for _, ip := range cert.IPAddresses {
		sans = append(sans, ip.String())
	}
	sort.Strings(sans)
	return sans, nil
}
