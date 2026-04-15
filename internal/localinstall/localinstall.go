// Package localinstall runs admin-curated MSI/EXE installers from a
// local disk path or UNC share. The framework (InnoSetup, NSIS, MSI,
// Squirrel, WiX Burn, InstallShield, Advanced Installer) is detected by
// inspecting the PE resource table + a byte-pattern search over the
// first ~2 MB of the file; the matching silent-install flag set is
// picked from a built-in table.
//
// This is the "option 2" fallback in the update cascade: packages that
// neither winget nor Chocolatey carry, but that the admin has staged on
// a trusted share. Because the installer is admin-curated (hash + path
// recorded in the local_installers table), the trust surface is the
// share itself, not a public URL.
//
// Cross-platform file list: detect.go + run.go carry the real work, a
// tiny _other.go stub keeps cmd/server cross-compiling on Linux (the
// server never calls Run — only the Windows agent does).
package localinstall

// Framework is the canonical tag used in DB rows and wire payloads.
// Keep the string values stable; they're persisted.
type Framework string

const (
	FrameworkMSI                Framework = "msi"
	FrameworkInno               Framework = "inno"
	FrameworkNSIS               Framework = "nsis"
	FrameworkWixBurn            Framework = "wix_burn"
	FrameworkSquirrel           Framework = "squirrel"
	FrameworkInstallShield      Framework = "installshield"
	FrameworkAdvancedInstaller  Framework = "advanced_installer"
	FrameworkUnknown            Framework = "unknown"
)

// Detection is the result of inspecting an installer file: which
// framework it is and which silent args Corrivex intends to pass.
// Admins can override the args via the local_installers row.
type Detection struct {
	Framework  Framework
	SilentArgs []string // already-split, ready to hand to exec.Command
	Reason     string   // human label explaining why this framework was picked
}

// DefaultSilentArgs returns the baseline silent-install arguments for
// each framework. The agent appends the installer path at the head of
// the slice (msiexec is a special case — it IS the program, the .msi
// path is an argument).
func DefaultSilentArgs(fw Framework) []string {
	switch fw {
	case FrameworkMSI, FrameworkAdvancedInstaller:
		// msiexec is invoked as the program; caller decides.
		return []string{"/qn", "/norestart"}
	case FrameworkInno:
		return []string{"/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART"}
	case FrameworkNSIS:
		return []string{"/S"}
	case FrameworkWixBurn:
		return []string{"/quiet", "/norestart"}
	case FrameworkSquirrel:
		return []string{"--silent"}
	case FrameworkInstallShield:
		// InstallShield's MSI-backed variant. The /v"/qn /norestart"
		// form gets passed through to the embedded MSI.
		return []string{"/s", "/v\"/qn /norestart\""}
	}
	return nil
}

// ParseArgsOverride splits an admin-provided string into an argument
// list. Rules kept intentionally simple: whitespace-delimited, quoted
// substrings preserved verbatim (after the outer quotes are stripped).
// Empty / whitespace-only input returns nil so callers can fall back
// to DefaultSilentArgs.
func ParseArgsOverride(raw string) []string {
	if len(raw) == 0 {
		return nil
	}
	var out []string
	var buf []byte
	inQuote := false
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		switch {
		case c == '"':
			inQuote = !inQuote
		case c == ' ' && !inQuote:
			if len(buf) > 0 {
				out = append(out, string(buf))
				buf = buf[:0]
			}
		default:
			buf = append(buf, c)
		}
	}
	if len(buf) > 0 {
		out = append(out, string(buf))
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
