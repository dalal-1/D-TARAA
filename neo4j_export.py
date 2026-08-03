import json
from pathlib import Path
from config import OUTPUT_DIR
import loader

def build_cypher() -> str:
    assets    = loader.load("assets")
    ds_list   = loader.load("damage_scenarios")
    ts_list   = loader.load("threat_scenarios")
    ap_list   = loader.load("attack_paths")
    at_list   = loader.load("attack_trees")
    arch      = loader.load("architecture")
    capec_idx = loader.capec_index()
    r155      = loader.load("r155_raw")

    lines = []
    lines.append("// ========================================================")
    lines.append("// ISO/SAE 21434 TARA – Neo4j Knowledge Graph Import Script")
    lines.append("// ========================================================")
    lines.append("")
    lines.append("// --- Constraints ---")
    for label in ["ECU","Asset","DamageScenario","ThreatScenario",
                  "AttackPath","AttackStep","CAPEC","TrustZone","Interface"]:
        lines.append(f"CREATE CONSTRAINT IF NOT EXISTS FOR (n:{label}) REQUIRE n.id IS UNIQUE;")
    lines.append("")

    lines.append("// --- TrustZones ---")
    for tz in arch["trust_zones"]:
        p = _props({"id": tz["id"], "trust_level": tz["trust_level"]})
        lines.append(f"MERGE (n:TrustZone {{{p}}});")
    lines.append("")

    lines.append("// --- ECUs ---")
    for ecu in arch["ecus"]:
        p = _props({"id": ecu["id"], "trust_zone": ecu["trust_zone"]})
        lines.append(f"MERGE (n:ECU {{{p}}});")
        lines.append(f"MATCH (e:ECU {{id:'{ecu['id']}'}}), (tz:TrustZone {{id:'{ecu['trust_zone']}'}}) "
                     f"MERGE (e)-[:IN_ZONE]->(tz);")
    lines.append("")

    lines.append("// --- Interfaces ---")
    for iface in arch["external_interfaces"]:
        p = _props({"id": iface["id"], "type": iface["type"],
                    "exposed": iface.get("exposed", False),
                    "attacker_profile": iface.get("attacker_profile","")})
        lines.append(f"MERGE (n:Interface {{{p}}});")
    lines.append("")

    lines.append("// --- Assets ---")
    for a in assets:
        p = _props({"id": a["asset_id"], "name": a["name"],
                    "asset_type": a.get("asset_type",""),
                    "cia": ",".join(a.get("cia_properties",[]))})
        lines.append(f"MERGE (n:Asset {{{p}}});")
        for ecu in a.get("mapped_ecus",[]):
            lines.append(f"MATCH (a:Asset {{id:'{a['asset_id']}'}}), (e:ECU {{id:'{ecu}'}}) "
                         f"MERGE (a)-[:HOSTED_ON]->(e);")
    lines.append("")

    lines.append("// --- CAPEC Nodes ---")
    capec_ids_used = set()
    for ts in ts_list:
        for c in ts.get("capec_refs",[]):
            capec_ids_used.add(str(c))
    for cid in capec_ids_used:
        c = capec_idx.get(cid, {})
        p = _props({"id": f"CAPEC-{cid}", "capec_id": cid,
                    "name": c.get("name","")[:80], "severity": c.get("severity",""),
                    "likelihood": c.get("likelihood","")})
        lines.append(f"MERGE (n:CAPEC {{{p}}});")
    lines.append("")

    lines.append("// --- Damage Scenarios ---")
    for ds in ds_list:
        p = _props({"id": ds["damage_id"], "title": ds["title"][:100],
                    "functional_domain": ds.get("functional_domain","")})
        lines.append(f"MERGE (n:DamageScenario {{{p}}});")
        for aid in ds.get("affected_assets",[]):
            lines.append(f"MATCH (d:DamageScenario {{id:'{ds['damage_id']}'}}), (a:Asset {{id:'{aid}'}}) "
                         f"MERGE (d)-[:AFFECTS]->(a);")
    lines.append("")

    lines.append("// --- Threat Scenarios ---")
    for ts in ts_list:
        p = _props({"id": ts["threat_id"], "title": ts["title"][:100],
                    "compromised_property": ts.get("compromised_property",""),
                    "stride": ",".join(ts.get("stride_categories",[])),
                    "directly_reachable": ts.get("is_directly_remote_reachable", False),
                    "transitively_reachable": ts.get("is_transitively_remote_reachable", False)})
        lines.append(f"MERGE (n:ThreatScenario {{{p}}});")
        lines.append(f"MATCH (ts:ThreatScenario {{id:'{ts['threat_id']}'}}), "
                     f"(a:Asset {{id:'{ts['target_asset_id']}'}}) MERGE (ts)-[:TARGETS]->(a);")
        for dsid in ts.get("damage_scenario_ids",[]):
            lines.append(f"MATCH (ts:ThreatScenario {{id:'{ts['threat_id']}'}}), "
                         f"(ds:DamageScenario {{id:'{dsid}'}}) MERGE (ts)-[:REALIZES]->(ds);")
        for cid in ts.get("capec_refs",[]):
            lines.append(f"MATCH (ts:ThreatScenario {{id:'{ts['threat_id']}'}}), "
                         f"(c:CAPEC {{id:'CAPEC-{cid}'}}) MERGE (ts)-[:HAS_CAPEC]->(c);")
        for ecu in ts.get("mapped_ecus",[]):
            lines.append(f"MATCH (ts:ThreatScenario {{id:'{ts['threat_id']}'}}), "
                         f"(e:ECU {{id:'{ecu}'}}) MERGE (ts)-[:MAPPED_TO]->(e);")
    lines.append("")

    lines.append("// --- Attack Paths & Steps ---")
    for ap in ap_list:
        p = _props({"id": ap["path_id"], "threat_id": ap["threat_id"],
                    "path_type": ap.get("path_type",""),
                    "entry_point": ap.get("entry_point",""),
                    "target_ecu": ap.get("target_ecu",""),
                    "total_trust_gain": ap.get("total_trust_gain",0),
                    "path_length": ap.get("path_length",0)})
        lines.append(f"MERGE (n:AttackPath {{{p}}});")
        lines.append(f"MATCH (ap:AttackPath {{id:'{ap['path_id']}'}}), "
                     f"(ts:ThreatScenario {{id:'{ap['threat_id']}'}}) MERGE (ts)-[:HAS_PATH]->(ap);")
        tgt = ap.get("target_ecu","")
        if tgt:
            lines.append(f"MATCH (ap:AttackPath {{id:'{ap['path_id']}'}}), "
                         f"(e:ECU {{id:'{tgt}'}}) MERGE (ap)-[:TARGETS_ECU]->(e);")
        for step in ap.get("steps",[]):
            sid = f"{ap['path_id']}-{step['step_id']}"
            sp = _props({"id": sid, "step_number": step["step_number"],
                         "stride": step.get("stride_label",""),
                         "capec_id": step.get("capec_id",""),
                         "src": step.get("src_node",""),
                         "dst": step.get("dst_node",""),
                         "trust_transition": step.get("trust_transition",""),
                         "surface": step.get("exploited_surface",""),
                         "plausibility": step.get("plausibility_flag","")})
            lines.append(f"MERGE (n:AttackStep {{{sp}}});")
            lines.append(f"MATCH (ap:AttackPath {{id:'{ap['path_id']}'}}), "
                         f"(s:AttackStep {{id:'{sid}'}}) MERGE (ap)-[:HAS_STEP]->(s);")
            if step.get("src_node") and step.get("dst_node"):
                lines.append(f"MATCH (s:AttackStep {{id:'{sid}'}}), "
                             f"(src:ECU {{id:'{step['src_node']}'}}) MERGE (s)-[:FROM_NODE]->(src);")
                lines.append(f"MATCH (s:AttackStep {{id:'{sid}'}}), "
                             f"(dst:ECU {{id:'{step['dst_node']}'}}) MERGE (s)-[:TO_NODE]->(dst);")
    lines.append("")

    lines.append("// ========================================================")
    lines.append("// USEFUL QUERIES")
    lines.append("// ========================================================")
    lines.append("")
    lines.append("// Explore damage scenario and its threat scenarios:")
    lines.append("// MATCH (ds:DamageScenario)<-[:REALIZES]-(ts:ThreatScenario) WHERE ds.id = 'DS-01' RETURN ds, ts;")
    lines.append("")
    lines.append("// Explore threat scenario and all attack paths:")
    lines.append("// MATCH (ts:ThreatScenario)-[:HAS_PATH]->(ap:AttackPath) WHERE ts.id = 'TS-01' RETURN ts, ap;")
    lines.append("")
    lines.append("// Full attack path with steps:")
    lines.append("// MATCH (ap:AttackPath)-[:HAS_STEP]->(s:AttackStep) WHERE ap.id = 'AP-01' RETURN ap, s ORDER BY s.step_number;")
    lines.append("")
    lines.append("// Trust escalation paths:")
    lines.append("// MATCH (s:AttackStep) WHERE s.trust_transition CONTAINS '→' AND s.trust_transition <> s.trust_transition RETURN s;")
    lines.append("")
    lines.append("// All paths through a specific ECU:")
    lines.append("// MATCH (ap:AttackPath)-[:TARGETS_ECU]->(e:ECU) WHERE e.id = 'AUTOPILOT' RETURN ap, e;")
    lines.append("")
    lines.append("// Attack surface coverage:")
    lines.append("// MATCH (s:AttackStep) RETURN s.surface, count(s) ORDER BY count(s) DESC;")

    return "\n".join(lines)

def _props(d: dict) -> str:
    parts = []
    for k, v in d.items():
        if isinstance(v, bool):
            parts.append(f"{k}: {str(v).lower()}")
        elif isinstance(v, (int, float)):
            parts.append(f"{k}: {v}")
        else:
            escaped = str(v).replace("'", "\\'").replace("\\", "\\\\")
            parts.append(f"{k}: '{escaped}'")
    return ", ".join(parts)

def export(out_path: Path = None) -> Path:
    if out_path is None:
        out_path = OUTPUT_DIR / "neo4j_import.cypher"
    cypher = build_cypher()
    out_path.write_text(cypher)
    return out_path
