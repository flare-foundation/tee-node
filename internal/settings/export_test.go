package settings

import "net"

// ServeListener serves on ln instead of the configured port so tests avoid fixed ports.
func (pc *ConfigServer) ServeListener(ln net.Listener) error {
	return pc.server.Serve(ln)
}

// SetPorts exposes the guarded port assignment to tests.
func SetPorts(sign, extension int) error {
	return setPorts(sign, extension)
}

// ConfigurePortsFromEnv exposes the environment-driven port configuration to tests.
func ConfigurePortsFromEnv() error {
	return configurePorts()
}
