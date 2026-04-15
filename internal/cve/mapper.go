// Package cve scans installed-software inventories against public CVE
// feeds (OSV, NVD) and the CISA KEV catalog, caching results in the
// database so a fleet of N hosts running the same package version costs
// exactly one API query.
package cve

import (
	"regexp"
	"strings"
)

// CPE is the minimal identity needed to query the NVD. Full CPE 2.3 strings
// have many more fields but NVD's cpeMatchString takes just vendor:product
// and we can leave the rest as wildcards.
type CPE struct {
	Vendor  string
	Product string
}

// wingetToCPE is a hand-curated map from common winget package IDs to their
// CPE vendor/product. NVD CPE names are notoriously inconsistent (Mozilla
// is "mozilla", but Notepad++ is "notepad++"), so there is no reliable
// algorithmic mapping — curation is the only way.
//
// Coverage target: the ~80 most common winget-installed apps on a Windows
// admin fleet. Unmapped IDs fall back to a fuzzy guess (see GuessCPE).
var wingetToCPE = map[string]CPE{
	// Browsers
	"Mozilla.Firefox":                   {"mozilla", "firefox"},
	"Mozilla.Firefox.ESR":               {"mozilla", "firefox_esr"},
	"Mozilla.Thunderbird":               {"mozilla", "thunderbird"},
	"Google.Chrome":                     {"google", "chrome"},
	"Google.Chrome.EXE":                 {"google", "chrome"},
	"Microsoft.Edge":                    {"microsoft", "edge"},
	"Microsoft.Edge.Beta":               {"microsoft", "edge"},
	"Brave.Brave":                       {"brave", "brave_browser"},
	"Opera.Opera":                       {"opera", "opera_browser"},
	"Vivaldi.Vivaldi":                   {"vivaldi", "vivaldi"},

	// Dev tools / editors
	"Microsoft.VisualStudioCode":        {"microsoft", "visual_studio_code"},
	"Microsoft.VisualStudio.2022.Community":  {"microsoft", "visual_studio_2022"},
	"Microsoft.VisualStudio.2022.Professional":{"microsoft", "visual_studio_2022"},
	"Microsoft.VisualStudio.2022.Enterprise": {"microsoft", "visual_studio_2022"},
	"Notepad++.Notepad++":               {"notepad++", "notepad++"},
	"JetBrains.IntelliJIDEA.Community":  {"jetbrains", "intellij_idea"},
	"JetBrains.IntelliJIDEA.Ultimate":   {"jetbrains", "intellij_idea"},
	"JetBrains.PyCharm.Community":       {"jetbrains", "pycharm"},
	"JetBrains.PyCharm.Professional":    {"jetbrains", "pycharm"},
	"JetBrains.GoLand":                  {"jetbrains", "goland"},
	"JetBrains.WebStorm":                {"jetbrains", "webstorm"},
	"Sublimehq.SublimeText.4":           {"sublimehq", "sublime_text"},

	// Runtimes / SDKs
	"OpenJS.NodeJS":                     {"nodejs", "node.js"},
	"OpenJS.NodeJS.LTS":                 {"nodejs", "node.js"},
	"Python.Python.3.11":                {"python", "python"},
	"Python.Python.3.12":                {"python", "python"},
	"Python.Python.3.13":                {"python", "python"},
	"GoLang.Go":                         {"golang", "go"},
	"Rustlang.Rustup":                   {"rust-lang", "rust"},
	"Oracle.JDK.17":                     {"oracle", "jdk"},
	"Oracle.JDK.21":                     {"oracle", "jdk"},
	"EclipseAdoptium.Temurin.17.JDK":    {"eclipse", "temurin"},
	"EclipseAdoptium.Temurin.21.JDK":    {"eclipse", "temurin"},
	"Microsoft.DotNet.SDK.8":            {"microsoft", ".net"},
	"Microsoft.DotNet.Runtime.8":        {"microsoft", ".net"},

	// Archivers
	"7zip.7zip":                         {"7-zip", "7-zip"},
	"WinRAR.WinRAR":                     {"rarlab", "winrar"},

	// Comms / meetings
	"SlackTechnologies.Slack":           {"slack", "slack"},
	"Microsoft.Teams":                   {"microsoft", "teams"},
	"Zoom.Zoom":                         {"zoom", "zoom"},
	"Discord.Discord":                   {"discord", "discord"},
	"Telegram.TelegramDesktop":          {"telegram", "telegram_desktop"},
	"WhatsApp.WhatsApp":                 {"whatsapp", "whatsapp"},

	// Utilities
	"VideoLAN.VLC":                      {"videolan", "vlc_media_player"},
	"OBSProject.OBSStudio":              {"obsproject", "obs_studio"},
	"Audacity.Audacity":                 {"audacityteam", "audacity"},
	"GIMP.GIMP":                         {"gimp", "gimp"},
	"Inkscape.Inkscape":                 {"inkscape", "inkscape"},
	"BlenderFoundation.Blender":         {"blender", "blender"},
	"Git.Git":                           {"git-scm", "git"},
	"GitHub.cli":                        {"github", "cli"},
	"Docker.DockerDesktop":              {"docker", "docker_desktop"},
	"PuTTY.PuTTY":                       {"putty", "putty"},
	"WinSCP.WinSCP":                     {"martin_prikryl", "winscp"},
	"Mobatek.MobaXterm":                 {"mobatek", "mobaxterm"},
	"Wireshark.Wireshark":               {"wireshark", "wireshark"},

	// Security / password managers
	"AgileBits.1Password":               {"1password", "1password"},
	"Bitwarden.Bitwarden":               {"bitwarden", "bitwarden"},
	"KeePassXCTeam.KeePassXC":           {"keepassxc", "keepassxc"},
	"Yubico.YubikeyManager":             {"yubico", "yubikey_manager"},
	"Malwarebytes.Malwarebytes":         {"malwarebytes", "malwarebytes"},

	// Office
	"Microsoft.Office":                  {"microsoft", "office"},
	"Microsoft.365Apps":                 {"microsoft", "365_apps"},
	"Adobe.Acrobat.Reader.64-bit":       {"adobe", "acrobat_reader"},
	"Adobe.Acrobat.Reader.32-bit":       {"adobe", "acrobat_reader"},
	"LibreOffice.LibreOffice":           {"libreoffice", "libreoffice"},
	"TheDocumentFoundation.LibreOffice": {"libreoffice", "libreoffice"},
	"Apache.OpenOffice":                 {"apache", "openoffice"},

	// Cloud tooling
	"Amazon.AWSCLI":                     {"amazon", "aws_cli"},
	"Microsoft.AzureCLI":                {"microsoft", "azure_cli"},
	"Google.CloudSDK":                   {"google", "cloud_sdk"},
	"Kubernetes.kubectl":                {"kubernetes", "kubernetes"},
	"Helm.Helm":                         {"helm", "helm"},
	"Hashicorp.Terraform":               {"hashicorp", "terraform"},
	"Hashicorp.Vagrant":                 {"hashicorp", "vagrant"},

	// Media
	"Spotify.Spotify":                   {"spotify", "spotify"},
	"iTunes.iTunes":                     {"apple", "itunes"},
	"Apple.iTunes":                      {"apple", "itunes"},

	// File sync
	"Dropbox.Dropbox":                   {"dropbox", "dropbox"},
	"Google.Drive":                      {"google", "drive"},
	"Microsoft.OneDrive":                {"microsoft", "onedrive"},
}

var fuzzyCleanup = regexp.MustCompile(`\.\d+(\.\d+)*$`)

// LookupCPE returns the curated CPE for a winget ID, or the fuzzy guess
// (second return value is true if the mapping is curated, false if fuzzy).
// Callers can choose to skip fuzzy matches to avoid false positives on
// obscure IDs.
func LookupCPE(wingetID string) (CPE, bool) {
	if cpe, ok := wingetToCPE[wingetID]; ok {
		return cpe, true
	}
	return GuessCPE(wingetID), false
}

// GuessCPE splits "Vendor.Product[.Edition]" → "vendor:product". Strips
// trailing version-ish suffixes like ".3.11" or ".2022" so Python.Python.3.12
// → {python, python} instead of {python, python_3_12}.
func GuessCPE(wingetID string) CPE {
	id := strings.TrimSpace(wingetID)
	if id == "" {
		return CPE{}
	}
	// Strip trailing version chunks.
	for {
		clean := fuzzyCleanup.ReplaceAllString(id, "")
		if clean == id {
			break
		}
		id = clean
	}
	parts := strings.SplitN(id, ".", 2)
	if len(parts) == 1 {
		// No vendor portion — use the same string for both (covers single-word
		// IDs like "CMake" or "Wireshark").
		v := strings.ToLower(parts[0])
		return CPE{Vendor: v, Product: v}
	}
	vendor := strings.ToLower(parts[0])
	// Product may contain further dots (e.g. "Visual.Studio") — collapse to
	// underscores since that's what NVD uses.
	product := strings.ToLower(strings.ReplaceAll(parts[1], ".", "_"))
	return CPE{Vendor: vendor, Product: product}
}

// ApplyUserMap merges a user-supplied winget-ID → "vendor:product" map into
// the defaults. Empty lines and lines starting with '#' are ignored. Format
// per line: `Winget.ID  vendor:product` (whitespace-separated). Silently
// skips malformed lines.
func ApplyUserMap(raw string) {
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		vp := strings.SplitN(fields[1], ":", 2)
		if len(vp) != 2 || vp[0] == "" || vp[1] == "" {
			continue
		}
		wingetToCPE[fields[0]] = CPE{Vendor: strings.ToLower(vp[0]), Product: strings.ToLower(vp[1])}
	}
}
