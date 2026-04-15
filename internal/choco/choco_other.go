//go:build !windows

// Stub so cmd/server can cross-compile on Linux even though the agent
// that actually calls Chocolatey is Windows-only.
package choco

type Package struct {
	Name      string `json:"name"`
	ID        string `json:"id"`
	Version   string `json:"version"`
	Available string `json:"available"`
	Source    string `json:"source"`
}

func Find() string                                      { return "" }
func IsInstalled() bool                                 { return false }
func ListInstalled() ([]Package, error)                 { return nil, nil }
func ListUpgrades() ([]Package, error)                  { return nil, nil }
func RunInstall(id, version string) (string, int)       { return "", 0 }
func RunUpgrade(id string) (string, int)                { return "", 0 }
func RunUpgradeAll() (string, int)                      { return "", 0 }
func RunUninstall(id string) (string, int)              { return "", 0 }
func EnsureChoco(logf func(string, ...any)) error       { return nil }
func ExitCodeResult(code int) string                    { return "" }
