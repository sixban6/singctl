package deploy

import "embed"

//go:embed templates/*
var TemplateFiles embed.FS
