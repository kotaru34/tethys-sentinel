package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/kotaru34/tethys-sentinel/internal/egresspolicy"
	"github.com/kotaru34/tethys-sentinel/internal/sshtarget"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "sentinel-egress-policy:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("sentinel-egress-policy", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	targetsPath := fs.String("targets", "", "protected SSH target inventory JSON")
	controlURL := fs.String("control", "", "literal-IP HTTPS Control Plane URL")
	format := fs.String("format", "pve", "output format: pve or json")
	checkPath := fs.String("check", "", "compare rendered output byte-for-byte with this file")
	pveClusterFW := fs.String("pve-cluster-fw", "", "Proxmox Datacenter firewall file to verify")
	pveVMConfig := fs.String("pve-vm-config", "", "Proxmox worker VM config file to verify")
	pveNet := fs.String("pve-net", "", "worker VM network interface to verify, for example net0")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	if strings.TrimSpace(*targetsPath) == "" || strings.TrimSpace(*controlURL) == "" {
		return errors.New("-targets and -control are required")
	}
	activationArgs := []string{strings.TrimSpace(*pveClusterFW), strings.TrimSpace(*pveVMConfig), strings.TrimSpace(*pveNet)}
	if someButNotAll(activationArgs) {
		return errors.New("-pve-cluster-fw, -pve-vm-config and -pve-net must be supplied together")
	}

	store, err := sshtarget.Open(*targetsPath)
	if err != nil {
		return fmt.Errorf("open target inventory: %w", err)
	}
	policy, err := egresspolicy.Build(*controlURL, store.List())
	if err != nil {
		return err
	}

	var rendered []byte
	switch strings.ToLower(strings.TrimSpace(*format)) {
	case "pve":
		rendered, err = egresspolicy.RenderPVE(policy)
	case "json":
		rendered, err = policy.JSON()
		if err == nil {
			rendered = append(rendered, '\n')
		}
	default:
		return errors.New("-format must be pve or json")
	}
	if err != nil {
		return err
	}

	if path := strings.TrimSpace(*checkPath); path != "" {
		current, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read check file: %w", err)
		}
		if !bytes.Equal(current, rendered) {
			hash, _ := policy.SHA256()
			return fmt.Errorf("egress policy drift detected for %s (expected policy_sha256=%s)", path, hash)
		}
	}

	if activationArgs[0] != "" {
		clusterFW, err := os.ReadFile(activationArgs[0])
		if err != nil {
			return fmt.Errorf("read Proxmox cluster firewall: %w", err)
		}
		vmConfig, err := os.ReadFile(activationArgs[1])
		if err != nil {
			return fmt.Errorf("read Proxmox VM config: %w", err)
		}
		if err := egresspolicy.VerifyPVEActivation(clusterFW, vmConfig, activationArgs[2]); err != nil {
			return fmt.Errorf("Proxmox firewall activation check failed: %w", err)
		}
	}

	if strings.TrimSpace(*checkPath) != "" {
		return nil
	}
	_, err = os.Stdout.Write(rendered)
	return err
}

func someButNotAll(values []string) bool {
	present := 0
	for _, value := range values {
		if value != "" {
			present++
		}
	}
	return present != 0 && present != len(values)
}
