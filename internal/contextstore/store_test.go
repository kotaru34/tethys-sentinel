package contextstore

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kotaru34/tethys-sentinel/internal/domain"
)

func TestBundleScopesInventoryAndRedactsAddresses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "context.json")
	content := `{"policy":"policy","instructions":"instructions","hosts":[{"name":"dns01","role":"dns","addresses":["192.0.2.53"]},{"name":"pve01","role":"hypervisor","addresses":["192.0.2.54"]}],"runbooks":[{"id":"dns","targets":["dns01"],"content":"dns runbook"},{"id":"pve","targets":["pve01"],"content":"pve runbook"}]}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := store.Bundle(domain.Grant{ID: "g1", Targets: []string{"dns01"}, Permissions: domain.Permissions{Exec: true}})
	if err != nil {
		t.Fatal(err)
	}
	if bundle.TrustLevel != domain.Trust0 || bundle.Version == "" {
		t.Fatalf("unexpected bundle metadata: %#v", bundle)
	}
	joined := ""
	for _, doc := range bundle.Documents {
		if !doc.ReadOnly || doc.TrustLevel != domain.Trust0 || doc.SHA256 == "" {
			t.Fatalf("document is not authoritative/read-only: %#v", doc)
		}
		joined += doc.Path + "\n" + doc.Content + "\n"
	}
	if !strings.Contains(joined, "dns01") || strings.Contains(joined, "pve01") || strings.Contains(joined, "pve runbook") {
		t.Fatalf("context leaked out-of-scope inventory: %s", joined)
	}
	if strings.Contains(joined, "192.0.2.53") || strings.Contains(joined, "\"addresses\"") {
		t.Fatalf("agent context exposed host network addresses: %s", joined)
	}

	snapshot, _, err := store.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Hosts) != 2 || len(snapshot.Hosts[0].Addresses) != 1 || snapshot.Hosts[0].Addresses[0] != "192.0.2.53" {
		t.Fatalf("privileged operator snapshot lost host addresses: %#v", snapshot.Hosts)
	}
}
