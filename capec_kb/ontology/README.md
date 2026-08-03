# Automotive Cybersecurity Knowledge Base Pipeline

A production-grade, fully traceable automotive cybersecurity knowledge base pipeline compliant with ISO/SAE 21434 and UNECE R155.

## Architecture

```
Parser → Cleaner → LLM Enricher → Validator → Embedder → Graph → Mapper
```

## Pipeline Stages

| Stage | Module | Description |
|-------|--------|-------------|
| 1 | `parser/capec_parser.py` | Parses CAPEC v3.9 XML from MITRE |
| 2 | `parser/r155_parser.py` | Extracts R155 from official PDF |
| 3 | `cleaner/capec_cleaner.py` | Normalizes and flags automotive-relevant CAPEC |
| 4 | `cleaner/r155_structurer.py` | Structures R155 sections, threats, mitigations |
| 5 | `ontology/automotive_ontology.py` | Builds automotive ontology from ISO/SAE 21434 |
| 6 | `enricher/llm_enricher.py` | Constrained LLM enrichment (automotive CAPEC only) |
| 7 | `validator/r155_validator.py` | Validates R155 for no invention, traceability |
| 8 | `validator/output_validator.py` | Validates CAPEC: cyber properties, STRIDE, steps |
| 9 | `embedder/embedder.py` | Generates semantic embeddings |
| 10 | `graph/graph_builder.py` | Builds CAPEC and automotive knowledge graphs |
| 11 | `mapper/stride_mapper.py` | Maps CAPEC/R155 to STRIDE categories |
| 12 | `mapper/r155_capec_mapper.py` | Links R155 threats to CAPEC patterns |
| 13 | `mitigations/mitigations_builder.py` | Builds mitigations database |

## Installation

```bash
pip install -r requirements.txt
```

## Configuration

**Linux/macOS:**
```bash
export ANTHROPIC_API_KEY=your_key
```

**Windows:**
```powershell
setx ANTHROPIC_API_KEY "your_key"
```

> The pipeline runs without an API key — LLM enrichment is skipped if no key is set.

## Run

```bash
python main.py
```

## Output Files

| File | Description |
|------|-------------|
| `output/capec_nodes.json` | Raw parsed CAPEC attack patterns |
| `output/capec_enriched.json` | LLM-enriched CAPEC with automotive context |
| `output/r155_raw.json` | Raw extracted R155 data from PDF |
| `output/r155_structured.json` | Structured R155 sections/threats/mitigations |
| `output/r155_validated.json` | Validated R155 (traceability enforced) |
| `output/automotive_ontology.json` | Automotive systems/interfaces/cyber properties |
| `output/mitigations.json` | Mitigations database (R155 + ISO 21434) |
| `output/embeddings.npy` | Semantic embeddings for CAPEC nodes |
| `output/stride_capec.json` | STRIDE-to-CAPEC and R155-to-STRIDE mappings |
| `output/validation_report.json` | Full validation report |
| `output/capec_graph.json` | CAPEC knowledge graph (node-link format) |
| `output/automotive_graph.json` | Automotive system graph |
| `output/r155_capec_mapping.json` | R155 threats linked to CAPEC patterns |
| `output/provenance_report.json` | Pipeline provenance trace |

## R155 PDF

The pipeline automatically downloads the R155 PDF from UNECE. If the download fails, place the PDF manually at:

```
output/R155.pdf
```

Then re-run `python main.py`.

## Traceability

Every output entry includes a `provenance` block:

```json
{
  "source": "UNECE R155",
  "section": "7.2.1",
  "document": "UN Regulation No. 155",
  "url": "...",
  "extraction_method": "pdf_parsing"
}
```

## Global Rules Enforced

- No manual CAPEC — parsed programmatically from MITRE XML
- No invented R155 — extracted from official PDF only
- LLM constrained — no hallucination, no invented systems
- All outputs validated — cyber properties, STRIDE, attack steps
- Full traceability — every entry has provenance

## Project Structure

```
capec_kb/
├── main.py
├── requirements.txt
├── README.md
├── config/
│   └── settings.py
├── parser/
│   ├── capec_parser.py
│   └── r155_parser.py
├── cleaner/
│   ├── capec_cleaner.py
│   └── r155_structurer.py
├── enricher/
│   └── llm_enricher.py
├── validator/
│   ├── r155_validator.py
│   └── output_validator.py
├── embedder/
│   └── embedder.py
├── graph/
│   └── graph_builder.py
├── mapper/
│   ├── stride_mapper.py
│   └── r155_capec_mapper.py
├── ontology/
│   └── automotive_ontology.py
├── mitigations/
│   └── mitigations_builder.py
├── provenance/
│   └── provenance_tracker.py
└── storage/
    └── storage.py
```
