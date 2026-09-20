package egresspolicy

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"strings"
)

func VerifyPVEActivation(clusterFirewall, vmConfig []byte, netName string) error {
	netName = strings.TrimSpace(netName)
	if !safeNetName(netName) {
		return errors.New("PVE network interface must be net followed by digits, for example net0")
	}
	if !pveOptionEnabled(clusterFirewall, "enable") {
		return errors.New("Proxmox Datacenter firewall is not enabled in cluster firewall options")
	}

	prefix := netName + ":"
	scanner := bufio.NewScanner(bytes.NewReader(vmConfig))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || !strings.HasPrefix(line, prefix) {
			continue
		}
		value := strings.TrimSpace(strings.TrimPrefix(line, prefix))
		for _, field := range strings.Split(value, ",") {
			if strings.TrimSpace(field) == "firewall=1" {
				return nil
			}
		}
		return fmt.Errorf("Proxmox VM interface %s does not have firewall=1", netName)
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read Proxmox VM config: %w", err)
	}
	return fmt.Errorf("Proxmox VM interface %s was not found", netName)
}

func pveOptionEnabled(data []byte, option string) bool {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	inOptions := false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			inOptions = strings.EqualFold(line, "[OPTIONS]")
			continue
		}
		if !inOptions {
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok || strings.TrimSpace(key) != option {
			continue
		}
		return strings.TrimSpace(value) == "1"
	}
	return false
}

func safeNetName(value string) bool {
	if len(value) < 4 || !strings.HasPrefix(value, "net") {
		return false
	}
	for _, r := range value[3:] {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
