package deploy

import "embed"

//go:embed templates/*
var templateFiles embed.FS
