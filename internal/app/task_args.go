package app

import "strings"

func buildThreatCaptureArgs(command managedCaptureCommand) ([]string, error) {
	iface := strings.TrimSpace(command.Interface)
	count := strings.TrimSpace(command.Count)
	if iface == "" || count == "" {
		return nil, newBadRequestError("Missing interface or count")
	}

	args := []string{appConfig.PacketAnalyzerScriptArg(), "capture", "-i", iface, "-c", count}
	if port := strings.TrimSpace(command.Port); port != "" {
		args = append(args, "-p", port)
	}
	if provider := strings.TrimSpace(command.Provider); provider != "" {
		args = append(args, "--provider", provider)
	}
	if apiBase := strings.TrimSpace(command.APIBase); apiBase != "" {
		args = append(args, "--api-base", apiBase)
	}
	if model := strings.TrimSpace(command.Model); model != "" {
		args = append(args, "--model", model)
	}
	return args, nil
}

func buildLANMonitorArgs(command managedCaptureCommand) ([]string, error) {
	iface := strings.TrimSpace(command.Interface)
	if iface == "" {
		return nil, newBadRequestError("Missing interface")
	}

	args := []string{appConfig.LANMonitorScriptArg(), "-i", iface}
	if command.NoThreatIntel == "true" {
		args = append(args, "--no-threat-intel")
	}
	return args, nil
}

func nicNamesFromCommand(command nicMonitorCommand) []string {
	return command.NICNames()
}

func buildNICMonitorArgs(command nicMonitorCommand) ([]string, error) {
	if len(nicNamesFromCommand(command)) == 0 {
		return nil, newBadRequestError("Missing nics")
	}
	return []string{appConfig.NICMonitorScriptArg(), "--mode", "interactive", "--db", resolveNICDatabasePath()}, nil
}
