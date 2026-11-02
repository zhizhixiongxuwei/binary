package app

import (
	"context"
	"fmt"
	"path"
	"sort"
	"strings"
	"unicode/utf8"
)

type inventoryGroup struct {
	count   int
	files   []string
	symbols map[string]int
}

// architectureInventory compresses the complete indexed file/symbol catalog
// into a bounded, directory-level view for the macro architecture prompt.
func (s *taskService) architectureInventory(ctx context.Context, projectID string, budget int) (string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT sf.id, sf.logical_path, ss.name
        FROM source_files sf LEFT JOIN source_symbols ss ON ss.source_file_id = sf.id AND ss.symbol_kind = 'function'
        WHERE sf.source_project_id = ? AND sf.state = 'ready' ORDER BY sf.logical_path, ss.start_line`, projectID)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	groups := map[string]*inventoryGroup{}
	lastFile := ""
	totalFiles := 0
	for rows.Next() {
		var id, logicalPath string
		var name *string
		if err := rows.Scan(&id, &logicalPath, &name); err != nil {
			return "", err
		}
		dir := path.Dir(logicalPath)
		group := groups[dir]
		if group == nil {
			group = &inventoryGroup{symbols: map[string]int{}}
			groups[dir] = group
		}
		if id != lastFile {
			group.count++
			totalFiles++
			if len(group.files) < 5 {
				group.files = append(group.files, truncateSearch(path.Base(logicalPath), 80))
			}
			lastFile = id
		}
		if name != nil && *name != "" {
			group.symbols[*name]++
		}
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if groups[keys[i]].count == groups[keys[j]].count {
			return keys[i] < keys[j]
		}
		return groups[keys[i]].count > groups[keys[j]].count
	})
	var output strings.Builder
	fmt.Fprintf(&output, "文件总数=%d；目录总数=%d；按文件数排序的目录概览：\n", totalFiles, len(groups))
	for _, key := range keys {
		group := groups[key]
		names := make([]string, 0, len(group.symbols))
		for name := range group.symbols {
			names = append(names, name)
		}
		sort.Slice(names, func(i, j int) bool {
			if group.symbols[names[i]] == group.symbols[names[j]] {
				return names[i] < names[j]
			}
			return group.symbols[names[i]] > group.symbols[names[j]]
		})
		if len(names) > 8 {
			names = names[:8]
		}
		line := fmt.Sprintf("目录=%s 文件数=%d 示例文件=%s 常见函数=%s\n", truncateSearch(key, 160), group.count, strings.Join(group.files, ","), strings.Join(names, ","))
		if utf8.RuneCountInString(output.String())+utf8.RuneCountInString(line) > budget {
			fmt.Fprintf(&output, "其余目录=%d；文件均已计入总数，但清单因输入限制压缩。\n", len(keys)-indexOfDirectory(keys, key))
			break
		}
		output.WriteString(line)
	}
	return output.String(), nil
}

func indexOfDirectory(keys []string, value string) int {
	for i, key := range keys {
		if key == value {
			return i
		}
	}
	return len(keys)
}
