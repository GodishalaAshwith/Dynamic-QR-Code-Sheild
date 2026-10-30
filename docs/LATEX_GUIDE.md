# LaTeX Compilation Guide

This repository includes two LaTeX documents designed for academic submission and publication:
1. **Academic Project Report:** Located at `report/project_report.tex`
2. **Sample Research Paper:** Located at `paper/research_paper.tex`

Both files are free of emojis, follow standard academic formatting, and rely on standard CTAN packages supported out-of-the-box in TeX Live, MiKTeX, MacTeX, and Overleaf.

---

## 1. Document Overview

### Project Report (`report/project_report.tex`)
- **Document Class:** `report` (12pt, A4 paper)
- **Target Audience:** Course examiners, laboratory evaluators, university project committees.
- **Key Sections:**
  - Formal Title Page (Serverless Computing - Professional Elective 6)
  - Abstract and Table of Contents
  - Chapter 1: Introduction and Problem Definition (Quishing mechanics and persistent server compute inefficiencies)
  - Chapter 2: Course Outcome Traceability Matrix (CO1 to CO5 mapped to syllabus units)
  - Chapter 3: System Architecture and Design (Topology diagram, dual-layer caching, FaaS lifecycle)
  - Chapter 4: Core Implementation Modules (Tracer algorithm, 8-rule scoring matrix, URLhaus integration, DynamoDB TTL)
  - Chapter 5: Security Architecture and IAM Policies (Least-privilege policy listing, DoS/slowloris bounds)
  - Chapter 6: Empirical Evaluation and Test Results (Acceptance test verification, latency benchmark distributions)
  - Chapter 7: Conclusion and Future Scope
  - Bibliography

### Research Paper (`paper/research_paper.tex`)
- **Document Class:** `IEEEtran` (10pt, conference, two-column layout)
- **Title:** *QR-Shield: A Serverless Ephemeral Architecture for Zero-Day Phishing Mitigation in Dynamic QR Codes*
- **Target Audience:** Academic conferences, workshop submissions (e.g., IEEE CLOUD, ACM CCS Workshop, Serverless Computing Symposia).
- **Key Sections:**
  - Abstract & Index Terms
  - Section I: Introduction
  - Section II: Threat Model and Design Goals
  - Section III: System Architecture
  - Section IV: Detection Methodology (Formal Algorithm pseudocode & additive mathematical scoring formulation)
  - Section V: Experimental Evaluation (Latency benchmarks $N=500$, acceptance scenario verification)
  - Section VI: Security Considerations and Trade-Offs (Slowloris resilience, headless browser exclusion trade-off)
  - Section VII: Conclusion
  - References (IEEE format)

---

## 2. Compilation Instructions

### Option A: Overleaf (Recommended for Fast PDF Generation)
1. Log in to [Overleaf](https://www.overleaf.com/).
2. Create a new blank project (e.g., "QR-Shield Report" or "QR-Shield Research Paper").
3. Upload `project_report.tex` or `research_paper.tex`.
4. Ensure the compiler is set to **pdfLaTeX** (Menu -> Compiler -> pdfLaTeX).
5. Click **Recompile**. The PDF will render immediately.

### Option B: Command Line (Linux, macOS, WSL)
Ensure you have `texlive-latex-extra` or equivalent installed:

```bash
# Compile Project Report (run twice to generate Table of Contents cross-references)
cd "Dynamic QR Code Sheild/report"
pdflatex project_report.tex
pdflatex project_report.tex

# Compile Research Paper
cd "../paper"
pdflatex research_paper.tex
pdflatex research_paper.tex
```

Or using `latexmk` for automatic multi-pass compilation:
```bash
latexmk -pdf project_report.tex
latexmk -pdf research_paper.tex
```

### Option C: Windows (MiKTeX or TeX Live)
1. Open `project_report.tex` or `research_paper.tex` in TeXstudio, TeXworks, or VS Code (with LaTeX Workshop extension).
2. Select **pdfLaTeX** as the build tool.
3. If prompted to install missing packages, allow MiKTeX to install automatically.
4. Press `F5` or `Build & View` to generate the PDF.

---

## 3. Package Dependencies

The following packages are referenced by the documents (all standard in TeX Live and Overleaf):
- `amsmath`, `amssymb`, `amsfonts` (Mathematical equations and matrices)
- `booktabs`, `tabularx` (Clean academic tables)
- `listings`, `xcolor` (Source code listings and syntax highlighting)
- `algorithm`, `algorithmic` / `algpseudocode` (Algorithmic pseudocode formatting)
- `hyperref` (Clickable internal cross-references and URLs)
- `geometry`, `fancyhdr` (Page margins, headers, and footers for the report)
- `microtype` (Typographic micro-adjustments)
- `IEEEtran` (IEEE conference template class for the paper)

