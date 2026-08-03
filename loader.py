import json
from config import DATA_FILES

_cache = {}

def load(key):
    if key not in _cache:
        with open(DATA_FILES[key]) as f:
            _cache[key] = json.load(f)
    return _cache[key]

def all_data():
    return {k: load(k) for k in DATA_FILES}

def capec_index():
    return {c["capec_id"]: c for c in load("capec_nodes")}

def r155_threat_index():
    r = load("r155_raw")
    return {t["id"]: t for t in r.get("threats", [])}

def r155_mitigation_index():
    r = load("r155_raw")
    return {m["mitigation_id"]: m for m in r.get("mitigations", [])} if "mitigations" in r else {}

def asset_index():
    return {a["asset_id"]: a for a in load("assets")}

def ts_index():
    return {t["threat_id"]: t for t in load("threat_scenarios")}

def ds_index():
    return {d["damage_id"]: d for d in load("damage_scenarios")}

def paths_by_threat():
    result = {}
    for p in load("attack_paths"):
        result.setdefault(p["threat_id"], []).append(p)
    return result

def trees_by_threat():
    result = {}
    for t in load("attack_trees"):
        result.setdefault(t["threat_id"], t)
    return result

def sg_by_threat():
    result = {}
    for s in load("semantic_graphs"):
        result.setdefault(s["threat_id"], s)
    return result
