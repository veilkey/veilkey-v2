package api

import (
	"embed"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

//go:embed ui_dist/* ui_dist/assets/*
var adminUIDist embed.FS

func uiDevDir() string {
	return strings.TrimSpace(os.Getenv("VEILKEY_UI_DEV_DIR"))
}

func devUIIndex() ([]byte, bool) {
	devDir := uiDevDir()
	if devDir == "" {
		return nil, false
	}
	for _, name := range []string{"index.html", "admin_vue_preview.html"} {
		path := filepath.Join(devDir, name)
		if body, err := os.ReadFile(path); err == nil {
			return body, true
		}
	}
	return nil, false
}

func embeddedUIIndex() ([]byte, bool) {
	body, err := fs.ReadFile(adminUIDist, "ui_dist/index.html")
	if err != nil {
		return nil, false
	}
	return body, true
}

func devUIAssetsDir() string {
	devDir := uiDevDir()
	if devDir == "" {
		return ""
	}
	assetsDir := filepath.Join(devDir, "assets")
	if info, err := os.Stat(assetsDir); err == nil && info.IsDir() {
		return assetsDir
	}
	return ""
}

func embeddedUIAssets() (fs.FS, bool) {
	sub, err := fs.Sub(adminUIDist, "ui_dist/assets")
	if err != nil {
		return nil, false
	}
	return sub, true
}
