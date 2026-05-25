//go:build windows

package localinstall

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
)

// Detect inspects an installer file and classifies which framework
// built it. The returned Detection carries the canonical silent-arg
// set; the caller may still override those per-installer.
//
// Heuristic order (cheap → expensive):
//   1. .msi extension  → MSI
//   2. Read first 2 MB of the PE  → scan for framework fingerprints
//   3. Nothing matched → Framework=unknown, SilentArgs=nil
//
// Nothing in here opens the registry or parses the full PE structure;
// byte-pattern match against the PE resource-table region is enough to
// separate the common installers.
func Detect(path string) (Detection, error) {
	if strings.HasSuffix(strings.ToLower(path), ".msi") {
		return Detection{
			Framework:  FrameworkMSI,
			SilentArgs: DefaultSilentArgs(FrameworkMSI),
			Reason:     "MSI by extension",
		}, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return Detection{}, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	// Fingerprints below live in PE string tables / resources. 2 MB is
	// generous for any bootstrapper (real installers are multi-MB but
	// these headers are in the first MB). Read-ahead also lets pattern
	// matches span arbitrary offsets without a second syscall.
	buf := make([]byte, 2*1024*1024)
	n, err := io.ReadFull(f, buf)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return Detection{}, fmt.Errorf("read %s: %w", path, err)
	}
	buf = buf[:n]

	// Order matters — check the most specific signatures first so we
	// don't mis-label e.g. a WiX-bundled MSI as Advanced Installer.
	for _, probe := range []struct {
		fw      Framework
		needles [][]byte
		reason  string
	}{
		{FrameworkInno, [][]byte{[]byte("Inno Setup Setup Data"), []byte("Inno Setup")}, "Inno Setup fingerprint"},
		// NSIS 3.x signature bytes + "Nullsoft Install System" string.
		{FrameworkNSIS, [][]byte{[]byte("Nullsoft Install System"), []byte("NSIS.Library")}, "NSIS fingerprint"},
		{FrameworkWixBurn, [][]byte{[]byte("WixBundleManifest"), []byte("wixstdba.dll")}, "WiX Burn bundle fingerprint"},
		{FrameworkSquirrel, [][]byte{[]byte("Squirrel.Windows"), []byte("Update.exe")}, "Squirrel (Electron) fingerprint"},
		{FrameworkInstallShield, [][]byte{[]byte("InstallShield"), []byte("ISBEW64.exe")}, "InstallShield fingerprint"},
		{FrameworkAdvancedInstaller, [][]byte{[]byte("Advanced Installer"), []byte("Caphyon")}, "Advanced Installer fingerprint"},
	} {
		for _, n := range probe.needles {
			if bytes.Contains(buf, n) {
				return Detection{
					Framework:  probe.fw,
					SilentArgs: DefaultSilentArgs(probe.fw),
					Reason:     probe.reason,
				}, nil
			}
		}
	}

	return Detection{
		Framework: FrameworkUnknown,
		Reason:    "no framework fingerprint matched",
	}, nil
}
