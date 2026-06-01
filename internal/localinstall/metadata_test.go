package localinstall

import "testing"

func TestAnalyzePathExtractsNameAndVersion(t *testing.T) {
	got := AnalyzePath(`\\srv\share\Notepad++-8.6.7-x64-setup.exe`)
	if got.Name != "Notepad++" {
		t.Fatalf("name=%q", got.Name)
	}
	if got.Version != "8.6.7" {
		t.Fatalf("version=%q", got.Version)
	}
}

func TestAnalyzePathHandlesMSI(t *testing.T) {
	got := AnalyzePath(`\\srv\share\Vendor App 2025.1.4.msi`)
	if got.Name != "Vendor App" {
		t.Fatalf("name=%q", got.Name)
	}
	if got.Version != "2025.1.4" {
		t.Fatalf("version=%q", got.Version)
	}
}
