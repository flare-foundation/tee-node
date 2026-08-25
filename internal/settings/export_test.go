package settings

import "net"

// ServeListener serves on ln instead of the configured port so tests avoid fixed ports.
func (pc *ConfigServer) ServeListener(ln net.Listener) error {
	return pc.server.Serve(ln)
}
