package containerarchive

import (
	"archive/tar"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
)

const (
	FormatDockerTAR = "docker-tar"
	FormatOCITAR    = "oci-tar"

	maxMetadataBytes = 4 << 20
	maxTarEntries    = 20000
)

type dockerManifestEntry struct {
	Config   string   `json:"Config"`
	RepoTags []string `json:"RepoTags"`
	Layers   []string `json:"Layers"`
}

type ociLayout struct {
	ImageLayoutVersion string `json:"imageLayoutVersion"`
}

type ociIndex struct {
	SchemaVersion int `json:"schemaVersion"`
}

// InspectTAR 根据归档内部结构区分 Docker save 与 OCI image-layout，而不是相信 .tar/.img 后缀。
// 普通 TAR 返回 ok=false；只解析有上限的小型元数据成员，镜像层正文由 archive/tar 流式跳过，
// 并同时限制总条目数，避免仅为格式识别就展开大层或耗尽内存。
func InspectTAR(filename string) (format string, ok bool, err error) {
	file, err := os.Open(filename)
	if err != nil {
		return "", false, fmt.Errorf("open tar for container inspection: %w", err)
	}
	defer file.Close()

	reader := tar.NewReader(file)
	memberNames := make(map[string]struct{})
	var dockerManifest []dockerManifestEntry
	var layout ociLayout
	var index ociIndex
	var dockerManifestSeen, layoutSeen, indexSeen, blobSeen bool

	for ordinal := 1; ; ordinal++ {
		header, nextErr := reader.Next()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			return "", false, fmt.Errorf("read tar for container inspection: %w", nextErr)
		}
		if ordinal > maxTarEntries {
			return "", false, fmt.Errorf("container tar entry limit exceeded")
		}
		name := cleanTarName(header.Name)
		if name == "" {
			continue
		}
		memberNames[name] = struct{}{}
		if strings.HasPrefix(name, "blobs/sha256/") && len(strings.TrimPrefix(name, "blobs/sha256/")) == 64 {
			blobSeen = true
		}
		if !header.FileInfo().Mode().IsRegular() || header.Size < 0 || header.Size > maxMetadataBytes {
			continue
		}
		switch name {
		case "manifest.json":
			body, readErr := io.ReadAll(io.LimitReader(reader, maxMetadataBytes+1))
			if readErr != nil || int64(len(body)) > maxMetadataBytes {
				return "", false, fmt.Errorf("read docker manifest: %w", readErr)
			}
			if json.Unmarshal(body, &dockerManifest) == nil {
				dockerManifestSeen = true
			}
		case "oci-layout":
			body, readErr := io.ReadAll(io.LimitReader(reader, maxMetadataBytes+1))
			if readErr != nil || int64(len(body)) > maxMetadataBytes {
				return "", false, fmt.Errorf("read OCI layout: %w", readErr)
			}
			if json.Unmarshal(body, &layout) == nil {
				layoutSeen = true
			}
		case "index.json":
			body, readErr := io.ReadAll(io.LimitReader(reader, maxMetadataBytes+1))
			if readErr != nil || int64(len(body)) > maxMetadataBytes {
				return "", false, fmt.Errorf("read OCI index: %w", readErr)
			}
			if json.Unmarshal(body, &index) == nil {
				indexSeen = true
			}
		}
	}

	if layoutSeen && indexSeen && blobSeen && layout.ImageLayoutVersion == "1.0.0" && index.SchemaVersion == 2 {
		return FormatOCITAR, true, nil
	}
	if dockerManifestSeen && validDockerManifest(dockerManifest, memberNames) {
		return FormatDockerTAR, true, nil
	}
	return "", false, nil
}

func cleanTarName(value string) string {
	// 元数据内的成员引用也按不可信路径处理，拒绝绝对路径和向上穿越。
	value = strings.TrimPrefix(strings.ReplaceAll(value, "\\", "/"), "./")
	cleaned := path.Clean(value)
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") || strings.HasPrefix(cleaned, "/") {
		return ""
	}
	return cleaned
}

func validDockerManifest(manifest []dockerManifestEntry, members map[string]struct{}) bool {
	// 仅出现 manifest.json 不足以证明是 Docker save；配置和每个 layer 都必须真实存在于同一 TAR。
	if len(manifest) == 0 {
		return false
	}
	for _, image := range manifest {
		config := cleanTarName(image.Config)
		if config == "" || len(image.Layers) == 0 {
			return false
		}
		if _, exists := members[config]; !exists {
			return false
		}
		for _, rawLayer := range image.Layers {
			layer := cleanTarName(rawLayer)
			if layer == "" {
				return false
			}
			if _, exists := members[layer]; !exists {
				return false
			}
		}
	}
	return true
}
