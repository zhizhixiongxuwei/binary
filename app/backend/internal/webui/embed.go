package webui

import "embed"

// Dist is replaced with the Vue production build by app/Dockerfile.
//
//go:embed dist/*
var Dist embed.FS
