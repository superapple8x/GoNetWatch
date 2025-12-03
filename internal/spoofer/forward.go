package spoofer

import (
	"fmt"
	"os/exec"
	"runtime"
)

// EnableIPForwarding enables the kernel's IP forwarding feature.
// Currently supports Linux via sysctl.
func EnableIPForwarding() error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("ip forwarding not implemented for %s", runtime.GOOS)
	}

	cmd := exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to enable ip forwarding: %v (%s)", err, string(output))
	}
	return nil
}

// DisableIPForwarding disables the kernel's IP forwarding feature.
func DisableIPForwarding() error {
	if runtime.GOOS != "linux" {
		return nil // No-op for non-Linux to avoid errors on cleanup
	}

	cmd := exec.Command("sysctl", "-w", "net.ipv4.ip_forward=0")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to disable ip forwarding: %v (%s)", err, string(output))
	}
	return nil
}

