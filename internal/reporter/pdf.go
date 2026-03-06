// Package reporter provides PDF output for PQCAT scan results.
// This is a zero-dependency PDF generator built directly on the PDF 1.4
// specification — no external libraries required. This ensures the binary
// works in air-gapped federal environments with no package manager access.
package reporter

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/soqucoin-labs/pqcat/internal/models"
)

// pdfDoc builds PDF documents from scratch using raw PDF objects.
type pdfDoc struct {
	buf     bytes.Buffer
	objects []int          // byte offsets of each object
	pages   []int          // object numbers of page objects
	fonts   map[string]int // font name -> object number
}

// WritePDF generates a professional Crypto Bill of Health PDF report.
func WritePDF(path string, result *models.ScanResult, score *models.ComplianceScore) error {
	doc := &pdfDoc{fonts: make(map[string]int)}

	// Build content lines for the report
	content := buildReportContent(result, score)

	// Generate PDF
	doc.writeHeader()

	// Object 1: Catalog
	doc.beginObject(1)
	doc.buf.WriteString("<< /Type /Catalog /Pages 2 0 R >>\n")
	doc.endObject()

	// Object 2: Pages
	doc.beginObject(2)
	doc.buf.WriteString("<< /Type /Pages /Kids [3 0 R] /Count 1 >>\n")
	doc.endObject()

	// Object 3: Page (US Letter: 612 x 792 points)
	doc.beginObject(3)
	doc.buf.WriteString("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] ")
	doc.buf.WriteString("/Contents 6 0 R ")
	doc.buf.WriteString("/Resources << /Font << /F1 4 0 R /F2 5 0 R >> >> >>\n")
	doc.endObject()

	// Object 4: Helvetica font (standard PDF font, always available)
	doc.beginObject(4)
	doc.buf.WriteString("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>\n")
	doc.endObject()

	// Object 5: Helvetica-Bold
	doc.beginObject(5)
	doc.buf.WriteString("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>\n")
	doc.endObject()

	// Object 6: Page content stream
	stream := buildPDFStream(content)
	doc.beginObject(6)
	doc.buf.WriteString(fmt.Sprintf("<< /Length %d >>\nstream\n%sendstream\n", len(stream), stream))
	doc.endObject()

	doc.writeXref(6)
	doc.writeTrailer(6)

	return os.WriteFile(path, doc.buf.Bytes(), 0644)
}

// writeHeader writes the PDF file header.
func (d *pdfDoc) writeHeader() {
	d.buf.WriteString("%PDF-1.4\n%\xe2\xe3\xcf\xd3\n") // Binary comment for PDF readers
}

// beginObject starts a new PDF object and records its byte offset.
func (d *pdfDoc) beginObject(num int) {
	// Extend objects slice if needed
	for len(d.objects) < num {
		d.objects = append(d.objects, 0)
	}
	d.objects[num-1] = d.buf.Len()
	d.buf.WriteString(fmt.Sprintf("%d 0 obj\n", num))
}

// endObject closes a PDF object.
func (d *pdfDoc) endObject() {
	d.buf.WriteString("endobj\n\n")
}

// writeXref writes the cross-reference table.
func (d *pdfDoc) writeXref(numObjects int) {
	d.objects = append([]int{0}, d.objects[:numObjects]...) // Prepend free object
	xrefOffset := d.buf.Len()
	d.buf.WriteString(fmt.Sprintf("xref\n0 %d\n", numObjects+1))
	d.buf.WriteString("0000000000 65535 f \n")
	for i := 1; i <= numObjects; i++ {
		d.buf.WriteString(fmt.Sprintf("%010d 00000 n \n", d.objects[i]))
	}
	d.buf.WriteString(fmt.Sprintf("startxref\n%d\n", xrefOffset))
}

// writeTrailer writes the PDF trailer.
func (d *pdfDoc) writeTrailer(numObjects int) {
	d.buf.WriteString(fmt.Sprintf("trailer\n<< /Size %d /Root 1 0 R >>\n%%%%EOF\n", numObjects+1))
}

// reportLine represents a line of content in the PDF.
type reportLine struct {
	text     string
	fontSize float64
	bold     bool
	color    [3]float64 // RGB 0-1
	indent   float64    // left margin offset
	spacing  float64    // extra spacing after this line
}

// buildReportContent assembles all the text lines for the report.
func buildReportContent(result *models.ScanResult, score *models.ComplianceScore) []reportLine {
	var lines []reportLine

	black := [3]float64{0, 0, 0}
	gray := [3]float64{0.4, 0.4, 0.4}
	red := [3]float64{0.85, 0.15, 0.15}
	green := [3]float64{0.1, 0.7, 0.2}
	yellow := [3]float64{0.85, 0.65, 0.0}
	blue := [3]float64{0.1, 0.3, 0.7}

	// —— HEADER ——
	lines = append(lines, reportLine{
		text: "CRYPTO BILL OF HEALTH", fontSize: 20, bold: true, color: black, spacing: 4,
	})
	lines = append(lines, reportLine{
		text: "Post-Quantum Compliance Assessment Report", fontSize: 10, color: gray, spacing: 2,
	})
	lines = append(lines, reportLine{
		text: fmt.Sprintf("PQCAT v%s  |  Soqucoin Labs Inc.", version), fontSize: 8, color: gray, spacing: 12,
	})

	// —— SCAN INFO ——
	lines = append(lines, reportLine{
		text: "SCAN DETAILS", fontSize: 11, bold: true, color: blue, spacing: 4,
	})
	lines = append(lines, reportLine{
		text: fmt.Sprintf("Target:          %s", result.Target), fontSize: 9, color: black, indent: 10,
	})
	lines = append(lines, reportLine{
		text: fmt.Sprintf("Scan Type:       %s", result.ScanType), fontSize: 9, color: black, indent: 10,
	})
	lines = append(lines, reportLine{
		text: fmt.Sprintf("Date:            %s", result.Timestamp.Format("2006-01-02 15:04:05 MST")), fontSize: 9, color: black, indent: 10,
	})
	lines = append(lines, reportLine{
		text: fmt.Sprintf("Duration:        %s", result.Duration.Round(time.Millisecond)), fontSize: 9, color: black, indent: 10, spacing: 12,
	})

	// —— SCORE ——
	if score != nil {
		scoreColor := red
		scoreLabel := "CRITICAL"
		if score.Overall >= 80 {
			scoreColor = green
			scoreLabel = "GOOD"
		} else if score.Overall >= 60 {
			scoreColor = yellow
			scoreLabel = "NEEDS ATTENTION"
		} else if score.Overall >= 40 {
			scoreColor = yellow
			scoreLabel = "AT RISK"
		}

		lines = append(lines, reportLine{
			text: "PQC READINESS SCORE", fontSize: 11, bold: true, color: blue, spacing: 4,
		})
		lines = append(lines, reportLine{
			text:     fmt.Sprintf("%.0f / 100  —  %s", score.Overall, scoreLabel),
			fontSize: 16, bold: true, color: scoreColor, indent: 10, spacing: 6,
		})

		// Zone breakdown
		redCount := score.ZoneCounts[models.ZoneRed]
		yellowCount := score.ZoneCounts[models.ZoneYellow]
		greenCount := score.ZoneCounts[models.ZoneGreen]

		lines = append(lines, reportLine{
			text:     fmt.Sprintf("RED (Quantum Vulnerable):        %d assets", redCount),
			fontSize: 9, color: red, indent: 10,
		})
		lines = append(lines, reportLine{
			text:     fmt.Sprintf("YELLOW (Transitional):           %d assets", yellowCount),
			fontSize: 9, color: yellow, indent: 10,
		})
		lines = append(lines, reportLine{
			text:     fmt.Sprintf("GREEN (CNSA 2.0 Compliant):      %d assets", greenCount),
			fontSize: 9, color: green, indent: 10, spacing: 6,
		})

		lines = append(lines, reportLine{
			text:     fmt.Sprintf("Framework:  %s", strings.ToUpper(score.Framework)),
			fontSize: 8, color: gray, indent: 10, spacing: 2,
		})
		lines = append(lines, reportLine{
			text:     fmt.Sprintf("Total Assets:  %d", score.TotalAssets),
			fontSize: 8, color: gray, indent: 10, spacing: 10,
		})

		// Next deadline
		if score.NextDeadline != nil {
			lines = append(lines, reportLine{
				text: "COMPLIANCE TIMELINE", fontSize: 11, bold: true, color: blue, spacing: 4,
			})
			lines = append(lines, reportLine{
				text:     fmt.Sprintf("Next Milestone:  %s", score.NextDeadline.Milestone),
				fontSize: 9, color: black, indent: 10,
			})
			lines = append(lines, reportLine{
				text: fmt.Sprintf("Deadline:        %s  (%d days remaining)",
					score.NextDeadline.Deadline.Format("January 2, 2006"),
					score.NextDeadline.DaysLeft),
				fontSize: 9, color: red, indent: 10, spacing: 10,
			})
		}

		// Priority actions
		if len(score.TopActions) > 0 {
			lines = append(lines, reportLine{
				text: "PRIORITY MIGRATION ACTIONS", fontSize: 11, bold: true, color: blue, spacing: 4,
			})
			for _, action := range score.TopActions {
				lines = append(lines, reportLine{
					text:     fmt.Sprintf("%d.  %s  [%s]", action.Priority, action.Description, action.Complexity),
					fontSize: 9, color: black, indent: 10, spacing: 1,
				})
			}
			lines = append(lines, reportLine{text: "", fontSize: 6, spacing: 8})
		}
	}

	// —— ASSET DETAIL ——
	if len(result.Assets) > 0 {
		lines = append(lines, reportLine{
			text: "CRYPTOGRAPHIC ASSET INVENTORY", fontSize: 11, bold: true, color: blue, spacing: 4,
		})

		// Table header
		lines = append(lines, reportLine{
			text:     fmt.Sprintf("%-8s %-24s %s", "ZONE", "ALGORITHM", "LOCATION"),
			fontSize: 8, bold: true, color: gray, indent: 10, spacing: 2,
		})

		// Show assets (limit to avoid page overflow for now)
		maxAssets := 35
		if len(result.Assets) < maxAssets {
			maxAssets = len(result.Assets)
		}

		for i := 0; i < maxAssets; i++ {
			asset := result.Assets[i]
			assetColor := red
			zoneLabel := "RED"
			switch asset.Zone {
			case models.ZoneYellow:
				assetColor = yellow
				zoneLabel = "YLW"
			case models.ZoneGreen:
				assetColor = green
				zoneLabel = "GRN"
			}

			loc := asset.Location
			if len(loc) > 50 {
				loc = loc[:47] + "..."
			}

			lines = append(lines, reportLine{
				text:     fmt.Sprintf("%-8s %-24s %s", zoneLabel, asset.Algorithm, loc),
				fontSize: 7, color: assetColor, indent: 10,
			})
		}

		if len(result.Assets) > maxAssets {
			lines = append(lines, reportLine{
				text: fmt.Sprintf("... and %d more assets (see JSON report for complete inventory)",
					len(result.Assets)-maxAssets),
				fontSize: 7, color: gray, indent: 10, spacing: 8,
			})
		}
	}

	// —— FOOTER ——
	lines = append(lines, reportLine{text: "", fontSize: 8, spacing: 8})
	lines = append(lines, reportLine{
		text:     fmt.Sprintf("Generated: %s", time.Now().Format("2006-01-02 15:04:05 MST")),
		fontSize: 7, color: gray,
	})
	lines = append(lines, reportLine{
		text:     "Soqucoin Labs Inc.  |  228 Park Ave S, Pmb 85451, New York, NY 10003",
		fontSize: 7, color: gray,
	})
	lines = append(lines, reportLine{
		text:     "CONFIDENTIAL — For authorized recipients only",
		fontSize: 7, bold: true, color: red,
	})

	return lines
}

// buildPDFStream converts report lines into a PDF content stream.
func buildPDFStream(lines []reportLine) string {
	var buf bytes.Buffer

	// Start at top of page with margins
	leftMargin := 50.0
	topY := 742.0 // 792 - 50 top margin
	y := topY

	buf.WriteString("BT\n") // Begin text

	for _, line := range lines {
		if line.text == "" {
			y -= line.spacing
			continue
		}

		// Set font
		fontName := "/F1" // Helvetica
		if line.bold {
			fontName = "/F2" // Helvetica-Bold
		}
		buf.WriteString(fmt.Sprintf("%s %.1f Tf\n", fontName, line.fontSize))

		// Set color
		buf.WriteString(fmt.Sprintf("%.3f %.3f %.3f rg\n", line.color[0], line.color[1], line.color[2]))

		// Position and draw text
		x := leftMargin + line.indent
		buf.WriteString(fmt.Sprintf("%.1f %.1f Td\n", x, y))

		// Escape special PDF characters
		escaped := escapePDFString(line.text)
		buf.WriteString(fmt.Sprintf("(%s) Tj\n", escaped))

		// Move to next line
		lineHeight := line.fontSize * 1.4
		y -= lineHeight + line.spacing

		// Reset position for absolute positioning
		buf.WriteString(fmt.Sprintf("%.1f %.1f Td\n", -x, -y-lineHeight-line.spacing))
	}

	buf.WriteString("ET\n") // End text

	return buf.String()
}

// escapePDFString escapes special characters in PDF strings.
func escapePDFString(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "(", "\\(")
	s = strings.ReplaceAll(s, ")", "\\)")
	return s
}
