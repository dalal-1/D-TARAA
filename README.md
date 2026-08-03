# ISO/SAE 21434 TARA Report Pipeline

Automated TARA reporting pipeline — produces a full HTML report + Neo4j Cypher import script from deterministic JSON engine outputs.

## Setup

```bash
pip install openai
```

## Data

Place all JSON files in the `data/` directory:

```
data/
  architecture.json
  assets.json
  damage_scenarios.json
  threat_scenarios.json
  attack_paths.json
  attack_trees.json
  capec_nodes.json
  r155_raw.json
  semantic_graphs.json
```

## Run

**With LLM (OpenAI GPT-4o):**
```bash
export OPENAI_API_KEY=sk-...
python pipeline.py
```

**Without LLM (offline / test):**
```bash
python pipeline.py --no-llm
```

**All options:**
```bash
python pipeline.py --help

  --no-llm          Skip OpenAI calls (uses raw descriptions from JSON)
  --max-paths N     Max attack paths to render per report (default: 30)
  --max-trees N     Max attack trees to render (default: 12)
  --max-graphs N    Max semantic graphs to render (default: 10)
```

## Output

```
output/
  tara_report.html       Full ISO/SAE 21434 TARA report (self-contained HTML)
  neo4j_import.cypher    Neo4j Cypher script — run in Neo4j Browser or cypher-shell
  svg/
    architecture.svg     System architecture DFD
    tree_AT-XX.svg       Attack tree per threat scenario
    sg_TS-XX.svg         Semantic traversal graph per threat scenario
```

## Neo4j Import

```bash
cypher-shell -u neo4j -p <password> --file output/neo4j_import.cypher
```

Or paste into Neo4j Browser.

**Graph labels:** ECU · Interface · TrustZone · Asset · DamageScenario · ThreatScenario · AttackPath · AttackStep · CAPEC

**Key queries:**
```cypher
// Damage scenario → all threat scenarios
MATCH (ds:DamageScenario)<-[:REALIZES]-(ts:ThreatScenario)
WHERE ds.id = 'DS-01' RETURN ds, ts;

// Threat scenario → all attack paths
MATCH (ts:ThreatScenario)-[:HAS_PATH]->(ap:AttackPath)
WHERE ts.id = 'TS-01' RETURN ts, ap;

// Full attack chain with steps
MATCH (ap:AttackPath)-[:HAS_STEP]->(s:AttackStep)
WHERE ap.id = 'AP-01' RETURN ap, s ORDER BY s.step_number;

// All paths targeting AUTOPILOT
MATCH (ap:AttackPath)-[:TARGETS_ECU]->(e:ECU)
WHERE e.id = 'AUTOPILOT' RETURN ap, e;

// Attack surface frequency
MATCH (s:AttackStep) RETURN s.surface, count(s) ORDER BY count(s) DESC;
```

## Report Sections

| § | Section |
|---|---------|
| 1 | Executive Summary |
| 2 | Item Definition |
| 3 | System Architecture DFD |
| 4 | ECU Inventory |
| 5 | Asset Register |
| 6 | Damage Scenarios |
| 7 | Threat Scenarios |
| 8 | Attack Paths |
| 9 | Attack Tree Visualizations |
| 10 | Semantic Graph Visualizations |
| 11 | CAPEC + R155 Traceability |
| 12 | Mitigation Catalogue |
| 13 | Cybersecurity Case (ISO 21434 §6.4.7) |

## Module Overview

| File | Role |
|------|------|
| `pipeline.py` | Main orchestrator — run this |
| `config.py` | Paths, model, constants |
| `loader.py` | JSON data loading + indices |
| `llm.py` | OpenAI GPT-4o calls |
| `diagrams.py` | SVG diagram generators |
| `report_builder.py` | HTML section builders |
| `neo4j_export.py` | Cypher script generator |
