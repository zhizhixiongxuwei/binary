package app

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"html"
	"strconv"
	"strings"
	"time"
	"unicode"
)

const reportSchemaVersion = "binaryscan-report-v3"

var reportSeverities = []string{"critical", "high", "medium", "low", "info", "unknown"}

func buildReportSummary(runs, findings []map[string]any) map[string]any {
	severityCounts := map[string]int{
		"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0,
	}
	runCounts := map[string]int{
		"total": len(runs), "complete": 0, "partial": 0, "unsupported": 0,
		"failed": 0, "cancelled": 0, "other": 0,
	}
	affectedFiles := make(map[string]struct{})
	rules := make(map[string]struct{})
	for _, run := range runs {
		status := strings.ToLower(reportText(run["status"]))
		if _, known := runCounts[status]; known && status != "total" && status != "other" {
			runCounts[status]++
		} else {
			runCounts["other"]++
		}
	}
	for _, finding := range findings {
		severity := strings.ToLower(reportText(finding["severity"]))
		if _, known := severityCounts[severity]; !known {
			severity = "unknown"
		}
		severityCounts[severity]++
		if path := reportText(finding["path"]); path != "" {
			affectedFiles[path] = struct{}{}
		}
		if ruleID := reportText(finding["ruleId"]); ruleID != "" {
			rules[ruleID] = struct{}{}
		}
	}
	return map[string]any{
		"findingCount":      len(findings),
		"affectedFileCount": len(affectedFiles),
		"ruleCount":         len(rules),
		"severityCounts":    severityCounts,
		"runCounts":         runCounts,
	}
}

func buildHTMLReport(snapshot map[string]any) []byte {
	task := reportMap(snapshot["task"])
	summary := reportMap(snapshot["summary"])
	severityCounts := reportMap(summary["severityCounts"])
	runs := reportMapSlice(snapshot["runs"])
	findings := reportMapSlice(snapshot["findings"])
	generatedAt := reportTimeText(snapshot["generatedAt"])

	var output strings.Builder
	output.WriteString(`<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">`)
	output.WriteString(`<meta name="viewport" content="width=device-width,initial-scale=1">`)
	output.WriteString(`<title>BinaryScan 分析报告</title><style>`)
	output.WriteString(`:root{color-scheme:light;--ink:#17212b;--muted:#64737d;--line:#dbe3e7;--soft:#f5f7f8;--brand:#116d68;--brand2:#084f4b}`)
	output.WriteString(`*{box-sizing:border-box}body{margin:0;background:#eef2f3;color:var(--ink);font:14px/1.65 system-ui,-apple-system,"Segoe UI","Microsoft YaHei",sans-serif}`)
	output.WriteString(`main{max-width:1120px;margin:28px auto;padding:0 24px 48px}.masthead{padding:30px 34px;border-radius:12px;color:#fff;background:linear-gradient(135deg,var(--brand2),var(--brand));box-shadow:0 12px 30px #173b3920}`)
	output.WriteString(`.eyebrow{margin:0 0 6px;letter-spacing:.14em;font-size:11px;font-weight:700;opacity:.78}.masthead h1{margin:0;font-size:30px;line-height:1.25}.subtitle{margin:7px 0 0;opacity:.88}`)
	output.WriteString(`section.panel{margin-top:18px;padding:22px 24px;border:1px solid var(--line);border-radius:10px;background:#fff;box-shadow:0 3px 12px #24424a0b}h2{margin:0 0 15px;font-size:19px}h3{margin:0;font-size:15px}`)
	output.WriteString(`.summary{display:grid;grid-template-columns:repeat(6,minmax(90px,1fr));gap:10px}.metric{padding:13px;border:1px solid var(--line);border-radius:8px;background:var(--soft)}.metric span{display:block;color:var(--muted);font-size:11px}.metric strong{font-size:22px}`)
	output.WriteString(`.critical strong,.severity-critical{color:#8c1531}.high strong,.severity-high{color:#ba372e}.medium strong,.severity-medium{color:#9b6500}.low strong,.severity-low{color:#257255}.info strong,.severity-info{color:#356b91}`)
	output.WriteString(`dl.metadata{display:grid;grid-template-columns:180px minmax(0,1fr);margin:0;border-top:1px solid var(--line)}dl.metadata div{display:contents}dt,dd{padding:9px 10px;border-bottom:1px solid var(--line)}dt{color:var(--muted);background:var(--soft);font-weight:600}dd{margin:0;overflow-wrap:anywhere}`)
	output.WriteString(`table{width:100%;border-collapse:collapse}th,td{padding:9px 10px;border:1px solid var(--line);text-align:left;vertical-align:top}th{color:#43545d;background:var(--soft);font-size:12px}td{overflow-wrap:anywhere}`)
	output.WriteString(`code,pre{font-family:ui-monospace,SFMono-Regular,Consolas,"Liberation Mono",monospace}.hash{font-size:12px}.finding{margin-top:14px;padding:18px;border:1px solid var(--line);border-left:4px solid #91a0a7;border-radius:8px}.finding.severity-critical{border-left-color:#8c1531}.finding.severity-high{border-left-color:#ba372e}.finding.severity-medium{border-left-color:#c0830a}.finding.severity-low{border-left-color:#39836a}`)
	output.WriteString(`.finding-head{display:flex;align-items:flex-start;justify-content:space-between;gap:16px}.badge{flex:0 0 auto;padding:2px 8px;border-radius:99px;background:var(--soft);font-size:11px;font-weight:800}.finding-meta{display:flex;flex-wrap:wrap;gap:7px 14px;margin:8px 0;color:var(--muted);font-size:12px}.location{margin:10px 0 0;padding:7px 9px;border-radius:5px;background:#eef5f4;overflow-wrap:anywhere}`)
	output.WriteString(`pre{max-height:480px;overflow:auto;margin:12px 0 0;padding:13px 15px;border-radius:7px;color:#eaf5f3;background:#152526;white-space:pre-wrap;overflow-wrap:anywhere}details{margin-top:10px}details pre{color:#24363c;background:#f2f5f6}.empty{color:var(--muted)}.warning{padding:10px 12px;border-left:4px solid #c0830a;background:#fff7df}`)
	output.WriteString(`@media(max-width:760px){main{padding:0 12px 30px}.masthead{padding:22px}.summary{grid-template-columns:repeat(2,1fr)}dl.metadata{grid-template-columns:120px minmax(0,1fr)}.run-tool{display:none}}`)
	output.WriteString(`@media print{body{background:#fff}main{max-width:none;margin:0;padding:0}.masthead{border-radius:0;box-shadow:none}section.panel{box-shadow:none;break-inside:auto}.finding{break-inside:avoid}pre{max-height:none;overflow:visible}details{display:block}details>summary{display:none}details:not([open])>*{display:block}}`)
	output.WriteString(`</style></head><body><main>`)
	output.WriteString(`<header class="masthead"><p class="eyebrow">BINARYSCAN · STATIC ANALYSIS</p><h1>二进制安全分析报告</h1><p class="subtitle">`)
	output.WriteString(html.EscapeString(reportDisplayText(task["displayName"])))
	output.WriteString(` · 生成于 ` + html.EscapeString(generatedAt) + ` · ` + reportSchemaVersion + `</p></header>`)

	output.WriteString(`<section class="panel"><h2>执行摘要</h2><div class="summary">`)
	writeHTMLMetric(&output, "全部问题", reportText(summary["findingCount"]), "")
	for _, severity := range []string{"critical", "high", "medium", "low", "info"} {
		writeHTMLMetric(&output, reportSeverityLabel(severity), reportText(severityCounts[severity]), severity)
	}
	output.WriteString(`</div><p class="empty">涉及 ` + html.EscapeString(reportDisplayText(summary["affectedFileCount"])) + ` 个文件、` + html.EscapeString(reportDisplayText(summary["ruleCount"])) + ` 条规则；本报告为生成时刻的不可变快照。</p></section>`)

	output.WriteString(`<section class="panel"><h2>任务信息</h2><dl class="metadata">`)
	writeHTMLMetadata(&output, "任务名称", task["displayName"], false)
	writeHTMLMetadata(&output, "任务 ID", task["id"], true)
	writeHTMLMetadata(&output, "任务状态", task["status"], false)
	writeHTMLMetadata(&output, "识别格式", task["detectedFormat"], false)
	writeHTMLMetadata(&output, "输入 SHA-256", task["inputSha256"], true)
	writeHTMLMetadata(&output, "任务创建时间", reportTimeText(task["createdAt"]), false)
	writeHTMLMetadata(&output, "报告生成时间", generatedAt, false)
	writeHTMLMetadata(&output, "Schema", reportSchemaVersion, true)
	output.WriteString(`</dl></section>`)

	output.WriteString(`<section class="panel"><h2>检测运行（` + strconv.Itoa(len(runs)) + `）</h2>`)
	if len(runs) == 0 {
		output.WriteString(`<p class="empty">没有运行记录。</p>`)
	} else {
		output.WriteString(`<table><thead><tr><th>类型</th><th>状态</th><th class="run-tool">检测工具</th><th>结果质量</th><th>完成时间</th></tr></thead><tbody>`)
		for _, run := range runs {
			output.WriteString(`<tr><td>` + html.EscapeString(reportDisplayText(run["kind"])) + `</td><td>` + html.EscapeString(reportDisplayText(run["status"])) + `</td>`)
			output.WriteString(`<td class="run-tool">` + html.EscapeString(reportToolText(run)) + `</td><td>` + html.EscapeString(reportDisplayText(run["resultQuality"])) + `</td><td>` + html.EscapeString(reportTimeText(run["completedAt"])) + `</td></tr>`)
		}
		output.WriteString(`</tbody></table>`)
	}
	output.WriteString(`</section>`)

	output.WriteString(`<section class="panel"><h2>漏洞明细（` + strconv.Itoa(len(findings)) + `）</h2>`)
	if truncated, _ := snapshot["findingsTruncated"].(bool); truncated {
		output.WriteString(`<p class="warning"><strong>注意：</strong>漏洞明细已达到 50,000 条报告上限，当前内容已截断。</p>`)
	}
	if len(findings) == 0 {
		output.WriteString(`<p class="empty">所选检测运行没有返回漏洞结果。</p>`)
	}
	for index, finding := range findings {
		writeHTMLFinding(&output, index+1, finding)
	}
	output.WriteString(`</section></main></body></html>`)
	return []byte(output.String())
}

func writeHTMLMetric(output *strings.Builder, label, value, className string) {
	output.WriteString(`<div class="metric ` + html.EscapeString(className) + `"><span>` + html.EscapeString(label) + `</span><strong>` + html.EscapeString(reportDisplayText(value)) + `</strong></div>`)
}

func writeHTMLMetadata(output *strings.Builder, label string, value any, code bool) {
	output.WriteString(`<div><dt>` + html.EscapeString(label) + `</dt><dd>`)
	if code {
		output.WriteString(`<code class="hash">` + html.EscapeString(reportDisplayText(value)) + `</code>`)
	} else {
		output.WriteString(html.EscapeString(reportDisplayText(value)))
	}
	output.WriteString(`</dd></div>`)
}

func writeHTMLFinding(output *strings.Builder, number int, finding map[string]any) {
	severity := reportSeverity(finding["severity"])
	ruleID := reportDisplayText(finding["ruleId"])
	output.WriteString(`<article class="finding severity-` + severity + `"><div class="finding-head"><h3>` + strconv.Itoa(number) + `. ` + html.EscapeString(reportDisplayText(finding["title"])) + `</h3>`)
	output.WriteString(`<span class="badge severity-` + severity + `">` + html.EscapeString(strings.ToUpper(severity)) + `</span></div>`)
	output.WriteString(`<div class="finding-meta"><span>规则：<code>` + html.EscapeString(ruleID) + `</code></span><span>类型：` + html.EscapeString(reportDisplayText(finding["type"])) + `</span><span>语言：` + html.EscapeString(reportDisplayText(finding["language"])) + `</span><span>CWE：` + html.EscapeString(reportDisplayText(finding["cwe"])) + `</span></div>`)
	output.WriteString(`<p>` + html.EscapeString(reportDisplayText(finding["message"])) + `</p>`)
	if location := reportSourceLocation(finding); location != "" {
		// 离线报告只保留稳定的位置文本，不输出会解析成 file:///tasks/... 的站内链接。
		output.WriteString(`<p class="location"><strong>源码位置：</strong><code>` + html.EscapeString(location) + `</code></p>`)
	}
	if snippet := reportText(finding["snippet"]); snippet != "" {
		output.WriteString(`<pre><code>` + html.EscapeString(snippet) + `</code></pre>`)
	}
	if evidence := reportJSONText(finding["evidence"]); evidence != "" && evidence != "null" && evidence != "{}" {
		output.WriteString(`<details><summary>查看检测证据</summary><pre><code>` + html.EscapeString(evidence) + `</code></pre></details>`)
	}
	output.WriteString(`</article>`)
}

func buildDOCXReport(snapshot map[string]any) ([]byte, error) {
	var body bytes.Buffer
	archive := zip.NewWriter(&body)
	files := []struct {
		name string
		body string
	}{
		{"[Content_Types].xml", docxContentTypesXML},
		{"_rels/.rels", docxPackageRelationshipsXML},
		{"docProps/core.xml", docxCorePropertiesXML(snapshot)},
		{"word/_rels/document.xml.rels", docxDocumentRelationshipsXML},
		{"word/styles.xml", docxStylesXML},
		{"word/header1.xml", docxHeaderXML},
		{"word/footer1.xml", docxFooterXML},
		{"word/document.xml", docxDocumentXML(snapshot)},
	}
	for _, file := range files {
		writer, err := archive.Create(file.name)
		if err != nil {
			_ = archive.Close()
			return nil, err
		}
		if _, err := writer.Write([]byte(file.body)); err != nil {
			_ = archive.Close()
			return nil, err
		}
	}
	if err := archive.Close(); err != nil {
		return nil, err
	}
	return body.Bytes(), nil
}

func docxDocumentXML(snapshot map[string]any) string {
	task := reportMap(snapshot["task"])
	summary := reportMap(snapshot["summary"])
	severityCounts := reportMap(summary["severityCounts"])
	runs := reportMapSlice(snapshot["runs"])
	findings := reportMapSlice(snapshot["findings"])

	var body strings.Builder
	body.WriteString(docxParagraph("BINARYSCAN  /  STATIC ANALYSIS", "Eyebrow"))
	body.WriteString(docxParagraph("二进制安全分析报告", "Title"))
	body.WriteString(docxParagraph(reportDisplayText(task["displayName"])+"  ·  生成于 "+reportTimeText(snapshot["generatedAt"])+"  ·  "+reportSchemaVersion, "Subtitle"))
	body.WriteString(docxParagraph("本报告汇总所选检测运行在生成时刻的结果。报告为不可变快照，源码位置以文件路径、行号和列号记录。", "BodyText"))

	body.WriteString(docxParagraph("执行摘要", "Heading1"))
	body.WriteString(docxTable(
		[][]string{{"全部问题", "严重", "高危", "中危", "低危", "提示"}, {
			reportDisplayText(summary["findingCount"]), reportDisplayText(severityCounts["critical"]),
			reportDisplayText(severityCounts["high"]), reportDisplayText(severityCounts["medium"]),
			reportDisplayText(severityCounts["low"]), reportDisplayText(severityCounts["info"]),
		}}, []int{1560, 1560, 1560, 1560, 1560, 1560}, true, true))
	body.WriteString(docxParagraph("涉及 "+reportDisplayText(summary["affectedFileCount"])+" 个文件、"+reportDisplayText(summary["ruleCount"])+" 条规则。", "BodyText"))

	body.WriteString(docxParagraph("任务信息", "Heading1"))
	body.WriteString(docxKeyValueTable([][]string{
		{"任务名称", reportDisplayText(task["displayName"])},
		{"任务 ID", reportDisplayText(task["id"])},
		{"任务状态", reportDisplayText(task["status"])},
		{"识别格式", reportDisplayText(task["detectedFormat"])},
		{"输入 SHA-256", reportDisplayText(task["inputSha256"])},
		{"任务创建时间", reportTimeText(task["createdAt"])},
		{"报告生成时间", reportTimeText(snapshot["generatedAt"])},
		{"Schema", reportSchemaVersion},
	}))

	body.WriteString(docxParagraph("检测运行（"+strconv.Itoa(len(runs))+"）", "Heading1"))
	if len(runs) == 0 {
		body.WriteString(docxParagraph("没有运行记录。", "Muted"))
	} else {
		rows := [][]string{{"类型", "状态", "检测工具", "结果质量", "完成时间"}}
		for _, run := range runs {
			rows = append(rows, []string{reportDisplayText(run["kind"]), reportDisplayText(run["status"]), reportToolText(run), reportDisplayText(run["resultQuality"]), reportTimeText(run["completedAt"])})
		}
		body.WriteString(docxTable(rows, []int{1500, 1200, 2400, 1500, 2760}, true, false))
	}

	body.WriteString(docxParagraph("漏洞明细（"+strconv.Itoa(len(findings))+"）", "Heading1"))
	if truncated, _ := snapshot["findingsTruncated"].(bool); truncated {
		body.WriteString(docxParagraph("注意：漏洞明细已达到 50,000 条报告上限，当前内容已截断。", "Warning"))
	}
	if len(findings) == 0 {
		body.WriteString(docxParagraph("所选检测运行没有返回漏洞结果。", "Muted"))
	}
	for index, finding := range findings {
		body.WriteString(docxFindingXML(index+1, finding))
	}
	body.WriteString(`<w:sectPr><w:headerReference w:type="default" r:id="rId2"/><w:footerReference w:type="default" r:id="rId3"/><w:pgSz w:w="12240" w:h="15840"/><w:pgMar w:top="1440" w:right="1440" w:bottom="1440" w:left="1440" w:header="708" w:footer="708" w:gutter="0"/><w:cols w:space="708"/><w:docGrid w:linePitch="360"/></w:sectPr>`)
	return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>` + body.String() + `</w:body></w:document>`
}

func docxFindingXML(number int, finding map[string]any) string {
	severity := reportSeverity(finding["severity"])
	var body strings.Builder
	body.WriteString(docxParagraph(strconv.Itoa(number)+". ["+strings.ToUpper(severity)+"] "+reportDisplayText(finding["title"]), "Heading2"))
	body.WriteString(docxKeyValueTable([][]string{
		{"严重级别", reportSeverityLabel(severity)},
		{"规则 ID", reportDisplayText(finding["ruleId"])},
		{"问题类型", reportDisplayText(finding["type"])},
		{"语言", reportDisplayText(finding["language"])},
		{"CWE", reportDisplayText(finding["cwe"])},
		{"外部编号", reportDisplayText(finding["externalId"])},
	}))
	body.WriteString(docxParagraph("问题说明", "Heading3"))
	body.WriteString(docxParagraph(reportDisplayText(finding["message"]), "BodyText"))
	if location := reportSourceLocation(finding); location != "" {
		body.WriteString(docxParagraph("源码位置："+location, "Location"))
	}
	if snippet := reportText(finding["snippet"]); snippet != "" {
		body.WriteString(docxParagraph("相关代码", "Heading3"))
		body.WriteString(docxCodeParagraph(snippet))
	}
	if evidence := reportJSONText(finding["evidence"]); evidence != "" && evidence != "null" && evidence != "{}" {
		body.WriteString(docxParagraph("检测证据", "Heading3"))
		body.WriteString(docxCodeParagraph(evidence))
	}
	return body.String()
}

func docxKeyValueTable(rows [][]string) string {
	return docxTable(rows, []int{2200, 7160}, false, true)
}

func docxTable(rows [][]string, widths []int, header, keepTogether bool) string {
	var output strings.Builder
	output.WriteString(`<w:tbl><w:tblPr><w:tblW w:w="9360" w:type="dxa"/><w:tblInd w:w="120" w:type="dxa"/><w:tblLayout w:type="fixed"/><w:tblCellMar><w:top w:w="80" w:type="dxa"/><w:start w:w="120" w:type="dxa"/><w:bottom w:w="80" w:type="dxa"/><w:end w:w="120" w:type="dxa"/></w:tblCellMar><w:tblBorders><w:top w:val="single" w:sz="4" w:color="D7DEE2"/><w:left w:val="single" w:sz="4" w:color="D7DEE2"/><w:bottom w:val="single" w:sz="4" w:color="D7DEE2"/><w:right w:val="single" w:sz="4" w:color="D7DEE2"/><w:insideH w:val="single" w:sz="4" w:color="D7DEE2"/><w:insideV w:val="single" w:sz="4" w:color="D7DEE2"/></w:tblBorders></w:tblPr><w:tblGrid>`)
	for _, width := range widths {
		output.WriteString(`<w:gridCol w:w="` + strconv.Itoa(width) + `"/>`)
	}
	output.WriteString(`</w:tblGrid>`)
	for rowIndex, row := range rows {
		output.WriteString(`<w:tr>`)
		for cellIndex, width := range widths {
			value := ""
			if cellIndex < len(row) {
				value = row[cellIndex]
			}
			isHeader := header && rowIndex == 0
			isLabel := !header && cellIndex == 0
			output.WriteString(`<w:tc><w:tcPr><w:tcW w:w="` + strconv.Itoa(width) + `" w:type="dxa"/>`)
			if isHeader || isLabel {
				output.WriteString(`<w:shd w:val="clear" w:color="auto" w:fill="F2F4F7"/>`)
			}
			keepNext := keepTogether && rowIndex < len(rows)-1
			output.WriteString(`</w:tcPr>` + docxTableParagraph(value, isHeader || isLabel, keepNext) + `</w:tc>`)
		}
		output.WriteString(`</w:tr>`)
	}
	output.WriteString(`</w:tbl>`)
	return output.String()
}

func docxTableParagraph(value string, bold, keepNext bool) string {
	boldXML := ""
	if bold {
		boldXML = `<w:b/>`
	}
	keepNextXML := ""
	if keepNext {
		keepNextXML = `<w:keepNext/>`
	}
	return `<w:p><w:pPr>` + keepNextXML + `<w:spacing w:after="0" w:line="240" w:lineRule="auto"/></w:pPr><w:r><w:rPr>` + boldXML + `<w:rFonts w:ascii="Calibri" w:hAnsi="Calibri" w:eastAsia="Microsoft YaHei"/><w:sz w:val="20"/><w:szCs w:val="20"/></w:rPr><w:t xml:space="preserve">` + xmlText(singleLine(value)) + `</w:t></w:r></w:p>`
}

func docxParagraph(value, style string) string {
	return `<w:p><w:pPr><w:pStyle w:val="` + style + `"/></w:pPr><w:r><w:t xml:space="preserve">` + xmlText(singleLine(value)) + `</w:t></w:r></w:p>`
}

func docxCodeParagraph(value string) string {
	lines := strings.Split(strings.ReplaceAll(value, "\r\n", "\n"), "\n")
	var output strings.Builder
	output.WriteString(`<w:p><w:pPr><w:pStyle w:val="CodeBlock"/></w:pPr>`)
	for index, line := range lines {
		if index > 0 {
			output.WriteString(`<w:r><w:br/></w:r>`)
		}
		output.WriteString(`<w:r><w:t xml:space="preserve">` + xmlText(line) + `</w:t></w:r>`)
	}
	output.WriteString(`</w:p>`)
	return output.String()
}

func reportMap(value any) map[string]any {
	if result, ok := value.(map[string]any); ok {
		return result
	}
	if values, ok := value.(map[string]int); ok {
		result := make(map[string]any, len(values))
		for key, item := range values {
			result[key] = item
		}
		return result
	}
	return map[string]any{}
}

func reportMapSlice(value any) []map[string]any {
	if result, ok := value.([]map[string]any); ok {
		return result
	}
	items, ok := value.([]any)
	if !ok {
		return nil
	}
	result := make([]map[string]any, 0, len(items))
	for _, item := range items {
		if mapped, ok := item.(map[string]any); ok {
			result = append(result, mapped)
		}
	}
	return result
}

func reportText(value any) string {
	if value == nil {
		return ""
	}
	return strings.TrimSpace(fmt.Sprint(value))
}

func reportDisplayText(value any) string {
	if text := reportText(value); text != "" {
		return text
	}
	return "—"
}

func reportTimeText(value any) string {
	switch typed := value.(type) {
	case time.Time:
		return typed.Local().Format("2006-01-02 15:04:05 MST")
	case *time.Time:
		if typed != nil {
			return typed.Local().Format("2006-01-02 15:04:05 MST")
		}
	}
	text := reportText(value)
	if text == "" {
		return "—"
	}
	if parsed, err := time.Parse(time.RFC3339Nano, text); err == nil {
		return parsed.Local().Format("2006-01-02 15:04:05 MST")
	}
	return text
}

func reportSeverity(value any) string {
	severity := strings.ToLower(reportText(value))
	for _, candidate := range reportSeverities {
		if severity == candidate {
			return severity
		}
	}
	return "unknown"
}

func reportSeverityLabel(severity string) string {
	labels := map[string]string{"critical": "严重", "high": "高危", "medium": "中危", "low": "低危", "info": "提示", "unknown": "未知"}
	if label := labels[severity]; label != "" {
		return label
	}
	return labels["unknown"]
}

func reportToolText(run map[string]any) string {
	name := reportText(run["toolName"])
	version := reportText(run["toolVersion"])
	if name == "" {
		return "—"
	}
	if version == "" {
		return name
	}
	return name + " " + version
}

func reportSourceLocation(finding map[string]any) string {
	path := reportText(finding["path"])
	if path == "" {
		return ""
	}
	line := reportText(finding["startLine"])
	column := reportText(finding["startColumn"])
	if line == "" {
		return path
	}
	if column == "" {
		return path + ":" + line
	}
	return path + ":" + line + ":" + column
}

func reportJSONText(value any) string {
	if value == nil {
		return ""
	}
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return reportText(value)
	}
	return string(encoded)
}

func singleLine(value string) string {
	value = strings.ReplaceAll(value, "\r\n", " ")
	value = strings.ReplaceAll(value, "\r", " ")
	return strings.ReplaceAll(value, "\n", " ")
}

func xmlText(value string) string {
	var cleaned strings.Builder
	for _, char := range value {
		if char == '\t' || char == '\n' || char == '\r' || unicode.IsGraphic(char) || char == ' ' {
			cleaned.WriteRune(char)
		}
	}
	return html.EscapeString(cleaned.String())
}

func docxCorePropertiesXML(snapshot map[string]any) string {
	created := time.Now().UTC().Format(time.RFC3339)
	if value, ok := snapshot["generatedAt"].(time.Time); ok {
		created = value.UTC().Format(time.RFC3339)
	}
	return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:dcmitype="http://purl.org/dc/dcmitype/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><dc:title>BinaryScan 二进制安全分析报告</dc:title><dc:creator>BinaryScan</dc:creator><dc:subject>静态分析检测结果</dc:subject><cp:keywords>BinaryScan,二进制分析,漏洞检测</cp:keywords><dcterms:created xsi:type="dcterms:W3CDTF">` + created + `</dcterms:created><dcterms:modified xsi:type="dcterms:W3CDTF">` + created + `</dcterms:modified></cp:coreProperties>`
}

const docxContentTypesXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/><Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/><Override PartName="/word/header1.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.header+xml"/><Override PartName="/word/footer1.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.footer+xml"/></Types>`

const docxPackageRelationshipsXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/></Relationships>`

const docxDocumentRelationshipsXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/header" Target="header1.xml"/><Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/footer" Target="footer1.xml"/></Relationships>`

const docxHeaderXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:hdr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:p><w:pPr><w:pBdr><w:bottom w:val="single" w:sz="4" w:space="4" w:color="D7DEE2"/></w:pBdr><w:spacing w:after="80"/></w:pPr><w:r><w:rPr><w:color w:val="64737D"/><w:sz w:val="18"/><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri" w:eastAsia="Microsoft YaHei"/></w:rPr><w:t>BinaryScan · 二进制安全分析报告</w:t></w:r></w:p></w:hdr>`

const docxFooterXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:ftr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:p><w:pPr><w:jc w:val="center"/><w:pBdr><w:top w:val="single" w:sz="4" w:space="4" w:color="D7DEE2"/></w:pBdr></w:pPr><w:r><w:rPr><w:color w:val="64737D"/><w:sz w:val="18"/><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri" w:eastAsia="Microsoft YaHei"/></w:rPr><w:t>第 </w:t></w:r><w:fldSimple w:instr=" PAGE "><w:r><w:rPr><w:color w:val="64737D"/><w:sz w:val="18"/></w:rPr><w:t>1</w:t></w:r></w:fldSimple><w:r><w:rPr><w:color w:val="64737D"/><w:sz w:val="18"/></w:rPr><w:t> 页</w:t></w:r></w:p></w:ftr>`

const docxStylesXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:docDefaults><w:rPrDefault><w:rPr><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri" w:eastAsia="Microsoft YaHei"/><w:sz w:val="22"/><w:szCs w:val="22"/><w:color w:val="17212B"/></w:rPr></w:rPrDefault><w:pPrDefault><w:pPr><w:spacing w:after="120" w:line="264" w:lineRule="auto"/></w:pPr></w:pPrDefault></w:docDefaults><w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/><w:qFormat/></w:style><w:style w:type="paragraph" w:styleId="Eyebrow"><w:name w:val="Eyebrow"/><w:basedOn w:val="Normal"/><w:pPr><w:spacing w:before="0" w:after="80"/><w:keepNext/></w:pPr><w:rPr><w:b/><w:color w:val="116D68"/><w:sz w:val="18"/><w:spacing w:val="24"/></w:rPr></w:style><w:style w:type="paragraph" w:styleId="Title"><w:name w:val="Title"/><w:basedOn w:val="Normal"/><w:qFormat/><w:pPr><w:spacing w:before="0" w:after="100"/><w:keepNext/></w:pPr><w:rPr><w:b/><w:color w:val="084F4B"/><w:sz w:val="40"/><w:szCs w:val="40"/></w:rPr></w:style><w:style w:type="paragraph" w:styleId="Subtitle"><w:name w:val="Subtitle"/><w:basedOn w:val="Normal"/><w:pPr><w:spacing w:after="240"/><w:pBdr><w:bottom w:val="single" w:sz="8" w:space="10" w:color="116D68"/></w:pBdr></w:pPr><w:rPr><w:color w:val="64737D"/><w:sz w:val="20"/></w:rPr></w:style><w:style w:type="paragraph" w:styleId="BodyText"><w:name w:val="Body Text"/><w:basedOn w:val="Normal"/><w:qFormat/><w:pPr><w:spacing w:after="120" w:line="264" w:lineRule="auto"/></w:pPr></w:style><w:style w:type="paragraph" w:styleId="Heading1"><w:name w:val="heading 1"/><w:basedOn w:val="Normal"/><w:next w:val="BodyText"/><w:qFormat/><w:pPr><w:keepNext/><w:keepLines/><w:spacing w:before="320" w:after="160"/><w:outlineLvl w:val="0"/></w:pPr><w:rPr><w:b/><w:color w:val="2E74B5"/><w:sz w:val="32"/><w:szCs w:val="32"/></w:rPr></w:style><w:style w:type="paragraph" w:styleId="Heading2"><w:name w:val="heading 2"/><w:basedOn w:val="Normal"/><w:next w:val="BodyText"/><w:qFormat/><w:pPr><w:keepNext/><w:keepLines/><w:spacing w:before="240" w:after="120"/><w:outlineLvl w:val="1"/></w:pPr><w:rPr><w:b/><w:color w:val="2E74B5"/><w:sz w:val="26"/><w:szCs w:val="26"/></w:rPr></w:style><w:style w:type="paragraph" w:styleId="Heading3"><w:name w:val="heading 3"/><w:basedOn w:val="Normal"/><w:next w:val="BodyText"/><w:qFormat/><w:pPr><w:keepNext/><w:spacing w:before="160" w:after="80"/><w:outlineLvl w:val="2"/></w:pPr><w:rPr><w:b/><w:color w:val="1F4D78"/><w:sz w:val="24"/><w:szCs w:val="24"/></w:rPr></w:style><w:style w:type="paragraph" w:styleId="Muted"><w:name w:val="Muted"/><w:basedOn w:val="BodyText"/><w:rPr><w:color w:val="64737D"/><w:i/></w:rPr></w:style><w:style w:type="paragraph" w:styleId="Warning"><w:name w:val="Warning"/><w:basedOn w:val="BodyText"/><w:pPr><w:shd w:val="clear" w:fill="FFF4CE"/><w:ind w:left="160" w:right="160"/><w:spacing w:before="80" w:after="120"/></w:pPr><w:rPr><w:b/><w:color w:val="7A4D00"/></w:rPr></w:style><w:style w:type="paragraph" w:styleId="Location"><w:name w:val="Location"/><w:basedOn w:val="BodyText"/><w:pPr><w:shd w:val="clear" w:fill="EEF5F4"/><w:ind w:left="160" w:right="160"/><w:spacing w:before="80" w:after="120"/></w:pPr><w:rPr><w:rFonts w:ascii="Consolas" w:hAnsi="Consolas" w:eastAsia="Microsoft YaHei"/><w:sz w:val="19"/><w:color w:val="084F4B"/></w:rPr></w:style><w:style w:type="paragraph" w:styleId="CodeBlock"><w:name w:val="Code Block"/><w:basedOn w:val="Normal"/><w:pPr><w:shd w:val="clear" w:fill="F2F4F7"/><w:ind w:left="180" w:right="180"/><w:spacing w:before="80" w:after="140" w:line="240" w:lineRule="auto"/><w:keepLines/></w:pPr><w:rPr><w:rFonts w:ascii="Consolas" w:hAnsi="Consolas" w:eastAsia="Microsoft YaHei"/><w:sz w:val="18"/><w:szCs w:val="18"/><w:color w:val="24363C"/></w:rPr></w:style></w:styles>`
