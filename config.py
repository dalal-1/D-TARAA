import os
from pathlib import Path

DATA_DIR = Path(__file__).parent / "data"
OUTPUT_DIR = Path(__file__).parent / "output"
OUTPUT_DIR.mkdir(exist_ok=True)

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_MODEL = "gpt-4o"

ITEM_ID = "ITEM-DRIVER-SAFETY-CRITICAL-PATH"
ITEM_NAME = "Driver Physical Safety During Automated Driving"
ONTOLOGY_VERSION = "1.0.0"
GENERATION_DATE = __import__("datetime").date.today().isoformat()

DATA_FILES = {
    "architecture":      DATA_DIR / "architecture.json",
    "assets":            DATA_DIR / "assets.json",
    "damage_scenarios":  DATA_DIR / "damage_scenarios.json",
    "threat_scenarios":  DATA_DIR / "threat_scenarios.json",
    "attack_paths":      DATA_DIR / "attack_paths.json",
    "attack_trees":      DATA_DIR / "attack_trees.json",
    "capec_nodes":       DATA_DIR / "capec_nodes.json",
    "r155_raw":          DATA_DIR / "r155_raw.json",
    "semantic_graphs":   DATA_DIR / "semantic_graphs.json",
}

TRUST_COLORS = {1: "#ff3b6b", 2: "#ff9500", 3: "#ffcc00", 4: "#39ff14"}
STRIDE_COLORS = {
    "Spoofing":               "#ff3b6b",
    "Tampering":              "#ff6b35",
    "Repudiation":            "#ff9500",
    "Information Disclosure": "#ffcc00",
    "Denial of Service":      "#00d4ff",
    "Elevation of Privilege": "#bf5fff",
}
SURFACE_COLORS = {
    "wireless_interface":  "#ff3b6b",
    "in_vehicle_network":  "#ff9500",
    "diagnostic_interface":"#ffcc00",
    "physical_access":     "#00d4ff",
}
