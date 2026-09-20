package egresspolicy

import "testing"

func TestVerifyPVEActivation(t *testing.T) {
	cluster := []byte("[OPTIONS]\n\nenable: 1\n")
	vm := []byte("boot: order=scsi0\nnet0: virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0,firewall=1\n")
	if err := VerifyPVEActivation(cluster, vm, "net0"); err != nil {
		t.Fatalf("valid PVE activation rejected: %v", err)
	}
}

func TestVerifyPVEActivationFailsClosed(t *testing.T) {
	goodCluster := []byte("[OPTIONS]\nenable: 1\n")
	goodVM := []byte("net0: virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0,firewall=1\n")

	tests := []struct {
		name    string
		cluster []byte
		vm      []byte
		net     string
	}{
		{"datacenter disabled", []byte("[OPTIONS]\nenable: 0\n"), goodVM, "net0"},
		{"datacenter option missing", []byte("[OPTIONS]\npolicy_in: DROP\n"), goodVM, "net0"},
		{"nic firewall disabled", goodCluster, []byte("net0: virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0,firewall=0\n"), "net0"},
		{"nic flag missing", goodCluster, []byte("net0: virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0\n"), "net0"},
		{"nic missing", goodCluster, []byte("net1: virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0,firewall=1\n"), "net0"},
		{"unsafe nic name", goodCluster, goodVM, "net0\nnet1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := VerifyPVEActivation(tt.cluster, tt.vm, tt.net); err == nil {
				t.Fatal("unsafe/inactive PVE firewall configuration accepted")
			}
		})
	}
}

func TestPVEOptionEnableMustBeInsideOptionsSection(t *testing.T) {
	cluster := []byte("[RULES]\nenable: 1\n\n[OPTIONS]\npolicy_out: DROP\n")
	vm := []byte("net0: virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0,firewall=1\n")
	if err := VerifyPVEActivation(cluster, vm, "net0"); err == nil {
		t.Fatal("enable outside [OPTIONS] was accepted as Datacenter firewall activation")
	}
}
