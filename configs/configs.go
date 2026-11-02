package configs

import _ "embed"

// DefaultConfigYAML embeds the default singctl.yaml template.
//
//go:embed singctl.yaml
var DefaultConfigYAML []byte
