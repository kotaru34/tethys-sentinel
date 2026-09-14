package contextstore

// Snapshot returns the validated authoritative context and its content version
// without applying any grant-specific filtering. It is intended only for the
// privileged operator read surface; AI-facing callers continue to use Bundle.
func (s *Store) Snapshot() (Config, string, error) {
	cfg, version, err := s.load()
	if err != nil {
		return Config{}, "", err
	}
	return cloneConfig(cfg), version, nil
}

func cloneConfig(in Config) Config {
	out := in
	out.Hosts = make([]Host, len(in.Hosts))
	for i, host := range in.Hosts {
		out.Hosts[i] = host
		out.Hosts[i].Services = append([]string(nil), host.Services...)
		out.Hosts[i].Addresses = append([]string(nil), host.Addresses...)
	}
	out.Runbooks = make([]Runbook, len(in.Runbooks))
	for i, runbook := range in.Runbooks {
		out.Runbooks[i] = runbook
		out.Runbooks[i].Targets = append([]string(nil), runbook.Targets...)
	}
	return out
}
