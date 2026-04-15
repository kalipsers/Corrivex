// Package version is the single source of truth for the Corrivex release
// number. The string follows Semantic Versioning (MAJOR.MINOR.PATCH).
//
// The build scripts also override this via:
//
//	go build -ldflags "-X github.com/markov/corrivex/internal/version.Version=<v>"
//
// so the same constant flows into the agent, the server, the dashboard, the
// `--version` flag, and the Windows file properties (via goversioninfo).
//
// See versioning.md for the bump rules and release procedure.
package version

// Version is the semver of this build. Bump on every change.
var Version = "1.6.0"
