package tasks

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

func RunPowerShellScript(script string) string {
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
		"$script = [Console]::In.ReadToEnd(); Invoke-Expression $script")

	cmd.Stdin = strings.NewReader(script)

	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr

	err := cmd.Run()

	if err != nil {
		return fmt.Sprintf("Error: %v, Output: %s", err, stderr.String())
	}

	return out.String()
}
