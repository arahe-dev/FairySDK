// Package version holds the single source of truth for the FairySDK
// release version, shared by the CLI, the HTTP User-Agent and
// machine-readable run metadata.
package version

// Version is the current FairySDK release version.
const Version = "0.3.0"

// UserAgent is the User-Agent sent by HTTP and HTTP/3 probes.
const UserAgent = "fairy/" + Version + " (+https://github.com/arahe-dev/fairy)"
