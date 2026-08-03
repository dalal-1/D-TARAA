from __future__ import annotations

import json
import sys
import time
from collections import Counter, defaultdict
from dataclasses import asdict
from pathlib import Path

def _banner(msg: str) -> None:
    print(f"  {msg}")

def _step(msg: str) -> None:
    print(f"\n[STEP] {msg}")

def _unwrap(raw, key="scenarios"):
    if isinstance(raw, dict):
        return raw.get(key, [])
    return raw

def run_pipeline(
    arch_path: str | None = None,
    capec_path: str | None = None,
    r155_path: str | None = None,
    parsed_threats_path: str | None = None,
    out_dir: str | None = None,
) -> None:
    _script_dir = Path(__file__).resolve().parent
    _capec_kb   = _script_dir / "capec_kb"
    if not _capec_kb.exists():
        _capec_kb = _script_dir.parent / "capec_kb"
    if not _capec_kb.exists():
        raise FileNotFoundError(
            f"Cannot locate capec_kb/ relative to {_script_dir}. "
            "Place corrected_run.py next to the capec_kb/ folder."
        )

    ontology_dir = _capec_kb / "ontology"
    risk_dir     = _capec_kb / "risk"
    data_dir     = _capec_kb / "output"
    _out_dir     = Path(out_dir) if out_dir else (data_dir / "outputs")
    _out_dir.mkdir(parents=True, exist_ok=True)

    for p in [str(ontology_dir), str(risk_dir)]:
        if p not in sys.path:
            sys.path.insert(0, p)

    _data_dir = _script_dir / "data"

    if arch_path is None:
        _arch_candidate = data_dir / "architecture.json"
        if not _arch_candidate.exists() and _data_dir.exists():
            _arch_candidate = _data_dir / "architecture.json"
        arch_path = str(_arch_candidate)
    if capec_path is None:
        _capec_candidate = data_dir / "capec_nodes.json"
        if not _capec_candidate.exists() and _data_dir.exists():
            _capec_candidate = _data_dir / "capec_nodes.json"
        capec_path = str(_capec_candidate)
    if r155_path is None:
        _r155_candidate = data_dir / "r155_raw.json"
        if not _r155_candidate.exists() and _data_dir.exists():
            _r155_candidate = _data_dir / "r155_raw.json"
        r155_path = str(_r155_candidate)
    if parsed_threats_path is None:
        _pt_candidate = data_dir / "parsed_threats.json"
        if not _pt_candidate.exists() and _data_dir.exists():
            _pt_candidate = _data_dir / "parsed_threats.json"
        parsed_threats_path = str(_pt_candidate)
    capec_enrichment_path = str(data_dir / "capec_enrichment.json")
    capec_xml_path = data_dir / "capec_latest.xml"
    if not capec_xml_path.exists():
        capec_xml_path = data_dir / "capec_v3.9.xml"

    if capec_xml_path.exists():
        _step("0c/9  CAPEC Enrichment Regeneration")
        sys.path.insert(0, str(risk_dir))
        from capec_enricher import enrich_from_xml
        enrich_from_xml(capec_xml_path, output_path=capec_enrichment_path)
        print(f"  → capec_enrichment.json regenerated from {capec_xml_path.name}")
    else:
        _banner("WARNING: capec_latest.xml not found — using cached capec_enrichment.json")

    onto_path   = _out_dir / "functional_automotive_ontology.json"
    assets_out  = _out_dir / "assets.json"
    damage_out  = _out_dir / "damage_scenarios.json"
    threat_out  = _out_dir / "threat_scenarios.json"
    goals_out   = _out_dir / "cybersecurity_goals.json"
    graphs_out  = _out_dir / "semantic_graphs.json"
    paths_out   = _out_dir / "attack_paths.json"
    trees_out   = _out_dir / "attack_trees.json"
    impact_out  = _out_dir / "impact_ratings.json"
    feasib_out  = _out_dir / "attack_feasibility.json"
    risk_out    = _out_dir / "risk.json"

    t0 = time.time()
    _banner("TARA ENGINE PIPELINE  —  ISO/SAE 21434 / HEAVENS 2.0")

    _step("0/9  Ontology Generation")
    from functional_ontology_generator import generate_full_ontology
    generate_full_ontology(arch_path, str(onto_path), capec_path)
    ontology_raw = json.loads(onto_path.read_text())
    n_nodes = len(ontology_raw.get("nodes", ontology_raw if isinstance(ontology_raw, list) else []))
    print(f"  → {n_nodes} ontology nodes → {onto_path}")

    _step("0b/9  R155 Mitigation Correction")
    from r155_mitigation_builder import apply_mitigation_corrections
    corrected_r155 = apply_mitigation_corrections(Path(r155_path), write_back=True, verbose=True)
    mits_total    = len(corrected_r155.get("mitigations", []))
    mits_covered  = sum(1 for m in corrected_r155.get("mitigations", []) if m.get("protects_against"))
    mits_ref_ok   = sum(1 for m in corrected_r155.get("mitigations", []) if m.get("r155_ref"))
    mits_cyber_ok = sum(1 for m in corrected_r155.get("mitigations", []) if m.get("cyber_properties"))
    print(f"  → {mits_covered}/{mits_total} mitigations with protects_against")
    print(f"  → {mits_ref_ok}/{mits_total}  mitigations with r155_ref")
    print(f"  → {mits_cyber_ok}/{mits_total} mitigations with cyber_properties")

    _step("1/9  Asset Enumeration")
    from asset_enumerator import enumerate_assets, assets_to_dict
    assets        = enumerate_assets(onto_path)
    assets_result = assets_to_dict(assets)
    assets_out.write_text(json.dumps(assets_result, indent=2))
    print(f"  → {len(assets)} assets → {assets_out}")
    type_ctr = Counter(a.asset_type for a in assets)
    for t, c in sorted(type_ctr.items()):
        print(f"     {t:30s}: {c}")
    ciaa_counts = {
        k: sum(1 for a in assets if a.ciaa_properties.get(k))
        for k in ["confidentiality", "integrity", "availability", "authenticity"]
    }
    print(f"  CIAA coverage: {ciaa_counts}")

    _step("2/9  Damage Scenario Generation")
    from damage_scenario_generator import generate_damage_scenarios
    damage_scenarios, _ds_prov = generate_damage_scenarios(onto_path, assets_out)
    damage_list: list[dict] = []
    for s in damage_scenarios:
        d = asdict(s)
        ids = d.pop("source_ontology_ids", [])
        d["source_ontology_id"] = ids[0] if ids else ""
        damage_list.append(d)
    damage_out.write_text(json.dumps(damage_list, indent=2))
    print(f"  → {len(damage_scenarios)} damage scenarios → {damage_out}")
    ecu_covered = sum(1 for s in damage_scenarios if s.affected_ecus)
    print(f"     with affected_ecus: {ecu_covered}/{len(damage_scenarios)}")
    domain_ctr = Counter(s.functional_domain for s in damage_scenarios)
    for k, v in sorted(domain_ctr.items()):
        print(f"     {k:30s}: {v}")
    sfop_ctr = Counter(s.sfop_category for s in damage_scenarios)
    slvl_ctr = Counter(s.safety_level   for s in damage_scenarios)
    print(f"  SFOP distribution  : {dict(sfop_ctr)}")
    print(f"  Safety levels      : {dict(slvl_ctr)}")

    _step("3/9  Threat Scenario Generation")
    from threat_scenario_generator import generate_threat_scenarios, scenarios_to_output as ts_to_output
    threat_scenarios, ts_prov = generate_threat_scenarios(
        ontology_path=onto_path,
        assets_path=assets_out,
        damage_scenarios_path=damage_out,
        r155_path=Path(r155_path),
        capec_nodes_path=Path(capec_path),
        capec_enrichment_path=Path(capec_enrichment_path),
        architecture_path=Path(arch_path),
        parsed_threats_path=Path(parsed_threats_path),
    )
    ts_list: list[dict] = [asdict(s) for s in threat_scenarios]
    threat_out.write_text(json.dumps(ts_list, indent=2))
    ts_result = ts_list
    print(f"  → {len(threat_scenarios)} threat scenarios → {threat_out}")
    prop_ctr = Counter(s.compromised_property for s in threat_scenarios)
    for k, v in sorted(prop_ctr.items()):
        print(f"     {k:30s}: {v}")
    empty_stride      = sum(1 for s in threat_scenarios if not s.stride_categories)
    direct_remote     = sum(1 for s in threat_scenarios if s.is_directly_remote_reachable)
    transitive_remote = sum(
        1 for s in threat_scenarios
        if s.is_transitively_remote_reachable and not s.is_directly_remote_reachable
    )
    print(f"     empty STRIDE         : {empty_stride}/{len(threat_scenarios)}")
    print(f"     directly remote      : {direct_remote}")
    print(f"     transitively remote  : {transitive_remote}")

    _step("3b/9  Cybersecurity Goal Generation")
    from cybersecurity_goal_generator import (
        generate_cybersecurity_goals,
        goals_to_dict,
        inject_goal_ids,
    )
    cybersec_goals = generate_cybersecurity_goals(
        onto_path, damage_out, threat_out, Path(r155_path)
    )
    goals_list = goals_to_dict(cybersec_goals)
    goals_out.write_text(json.dumps(goals_list, indent=2))
    print(f"  → {len(cybersec_goals)} cybersecurity goals → {goals_out}")
    ciaa_dist = Counter(g.ciaa_property for g in cybersec_goals)
    sfop_dist = Counter(g.sfop_category for g in cybersec_goals)
    slvl_dist = Counter(g.safety_level  for g in cybersec_goals)
    for k, v in sorted(ciaa_dist.items()):
        print(f"     {k:30s}: {v}")
    print(f"     SFOP  : {dict(sfop_dist)}")
    print(f"     Levels: {dict(slvl_dist)}")
    ecu_bound = sum(1 for g in cybersec_goals if g.mapped_ecus)
    mit_total = sum(len(g.r155_mitigations) for g in cybersec_goals)
    mit_ref   = sum(1 for g in cybersec_goals for m in g.r155_mitigations if m.get("r155_ref"))
    mit_cyber = sum(1 for g in cybersec_goals for m in g.r155_mitigations if m.get("cyber_properties"))
    print(f"     goals with mapped_ecus        : {ecu_bound}/{len(cybersec_goals)}")
    print(f"     mitigations with r155_ref     : {mit_ref}/{mit_total}")
    print(f"     mitigations with cyber_props  : {mit_cyber}/{mit_total}")

    inject_goal_ids(goals_out, threat_out)
    print(f"  → cybersecurity_goal_ids back-injected into {threat_out}")

    ts_result = json.loads(threat_out.read_text())

    _step("4/9  Attack Semantic Graph Construction")
    from attack_semantic_graph import build_attack_semantic_graph, graph_to_dict
    graphs: list[dict] = []
    for ts in ts_result:
        g = build_attack_semantic_graph(ts, onto_path, Path(arch_path))
        graphs.append(graph_to_dict(g))
    graphs_out.write_text(json.dumps(graphs, indent=2))
    print(f"  → {len(graphs)} semantic graphs → {graphs_out}")
    if graphs:
        distinct_topologies = len(
            set(tuple(sorted(e["edge_id"] for e in g["graph_edges"])) for g in graphs)
        )
        physical_only = sum(1 for g in graphs if g["is_physical_sensor_threat"])
        edge_counts   = [len(g["graph_edges"]) for g in graphs]
        avg_edges     = sum(edge_counts) / len(edge_counts) if edge_counts else 0
        print(f"     distinct topologies      : {distinct_topologies}/{len(graphs)}")
        print(f"     physical-only threats    : {physical_only}")
        print(f"     avg edges per graph      : {avg_edges:.1f}")

    _step("5/9  Attack Path Generation")
    from attack_path_generator import generate_attack_paths, paths_to_dict, _reset_path_counter
    _reset_path_counter()
    ts_index: dict[str, dict] = {ts["threat_id"]: ts for ts in ts_result}
    all_ap_dicts: list[dict] = []
    for graph in graphs:
        ts = ts_index.get(graph["threat_id"])
        if not ts:
            continue
        paths, _stats = generate_attack_paths(graph, Path(capec_path), ts)
        all_ap_dicts.extend(paths_to_dict(paths))
    paths_out.write_text(json.dumps(all_ap_dicts, indent=2))
    print(f"  → {len(all_ap_dicts)} attack paths → {paths_out}")
    if all_ap_dicts:
        pt_ctr           = Counter(p["path_type"] for p in all_ap_dicts)
        for k, v in sorted(pt_ctr.items()):
            print(f"     {k:35s}: {v}")
        report_eligible  = sum(1 for p in all_ap_dicts if p.get("report_eligible"))
        has_implausible  = sum(1 for p in all_ap_dicts if p.get("has_implausible_steps"))
        total_steps      = sum(len(p["steps"]) for p in all_ap_dicts)
        null_asset_steps = sum(1 for p in all_ap_dicts for s in p["steps"] if not s.get("target_asset"))
        unique_capec     = set(c for p in all_ap_dicts for c in p["capec_ids_used"])
        zero_path_ts     = set(ts["threat_id"] for ts in ts_result) - set(p["threat_id"] for p in all_ap_dicts)
        print(f"     report_eligible          : {report_eligible}/{len(all_ap_dicts)}")
        print(f"     has_implausible_steps    : {has_implausible}/{len(all_ap_dicts)}")
        print(f"     steps with null asset    : {null_asset_steps}/{total_steps}")
        print(f"     unique CAPECs used       : {len(unique_capec)}")
        print(f"     threats with zero paths  : {len(zero_path_ts)}")
        if zero_path_ts:
            graph_index = {g["threat_id"]: g for g in graphs}
            print(f"\n  Zero-path threat diagnostics")
            for tid in sorted(zero_path_ts):
                g            = graph_index.get(tid, {})
                entry_nodes  = g.get("entry_nodes", [])
                target_nodes = g.get("target_nodes", [])
                edge_count   = len(g.get("graph_edges", []))
                phys_tmpls   = len(g.get("physical_attack_templates", []))
                cia          = g.get("compromised_property", "?")
                is_phys_only = g.get("is_physical_sensor_threat", False)
                print(
                    f"     {tid}: cia={cia}, edges={edge_count}, "
                    f"entry={len(entry_nodes)}, target={len(target_nodes)}, "
                    f"phys_templates={phys_tmpls}, phys_only={is_phys_only}"
                )
            print()

    _step("6/9  Attack Tree Generation")
    from attack_tree_generator import build_attack_tree, tree_to_dict, _reset_counters
    _reset_counters()
    cybersec_goals_dicts = json.loads(goals_out.read_text())
    damage_list_for_trees = json.loads(damage_out.read_text())
    paths_by_ts: dict[str, list[dict]] = defaultdict(list)
    for p in all_ap_dicts:
        paths_by_ts[p["threat_id"]].append(p)
    trees: list[dict] = []
    for ts in ts_result:
        ts_paths = paths_by_ts.get(ts["threat_id"], [])
        tree     = build_attack_tree(ts_paths, ts, cybersec_goals_dicts, damage_list_for_trees)
        trees.append(tree_to_dict(tree))
    trees_out.write_text(json.dumps(trees, indent=2))
    print(f"  → {len(trees)} attack trees → {trees_out}")
    shared       = sum(1 for t in trees if t["shared_prefix_detected"])
    leaves_total = sum(t["leaf_count"] for t in trees)
    ds_bound     = sum(1 for t in trees if t.get("damage_scenario_id"))
    print(f"     shared-prefix trees              : {shared}")
    print(f"     total leaf nodes                 : {leaves_total}")
    print(f"     trees with damage_scenario_id    : {ds_bound}/{len(trees)}")

    _step("7/9  Impact Rating Computation")
    import impact as impact_engine
    impact_engine._reset_counter()
    damage_raw: list[dict] = json.loads(damage_out.read_text())
    damage_raw = _unwrap(damage_raw, "scenarios")
    ds_index_imp = impact_engine.build_ds_index(damage_raw)
    ts_to_ds_map = impact_engine.build_ts_to_ds_map(ts_result, ds_index_imp)
    impact_results: list[dict] = []
    for ts in ts_result:
        ts_id     = ts.get("threat_id", "")
        linked_ds = ts_to_ds_map.get(ts_id, [])
        record    = impact_engine.compute_threat_impact(ts_id, linked_ds)
        impact_results.append(impact_engine.threat_impact_to_dict(record))
    impact_out.write_text(json.dumps(impact_results, indent=2))
    total_ir       = len(impact_results)
    rating_dist_ir = Counter(r["impact_rating"]      for r in impact_results)
    conf_dist_ir   = Counter(r["overall_confidence"] for r in impact_results)
    no_ds_ir       = sum(1 for r in impact_results if not r["per_ds_ratings"])
    print(f"  → {total_ir} impact records → {impact_out}")
    print(f"     Rating distribution    : {dict(rating_dist_ir)}")
    print(f"     Confidence distribution: {dict(conf_dist_ir)}")
    print(f"     Records with no DS link: {no_ds_ir}/{total_ir}")

    _step("8/9  Attack Feasibility Computation")
    import attack_feasibility as af_engine
    af_engine._reset_counter()
    capec_enrichment_data: dict = json.loads(Path(capec_enrichment_path).read_text())
    # v1.5.0 : UNE feasibility record par threat scenario, agrégée sur TOUS les
    # attack paths de ce threat, tous arbres confondus.
    # ISO/SAE 21434 [RQ-08-11] NOTE 2 ; HEAVENS 2.0 Fig. 3 et sec. 4.2.2/4.2.5.
    feasib_records = af_engine.compute_feasibility_all_threats(
        trees, all_ap_dicts, ts_index,
        capec_enrichment=capec_enrichment_data,
    )
    feasib_results: list[dict] = [
        af_engine.feasibility_to_dict(r) for r in feasib_records
    ]
    feasib_out.write_text(json.dumps(feasib_results, indent=2))
    total_af         = len(feasib_results)
    rating_dist_af   = Counter(r["attack_feasibility_rating"] for r in feasib_results)
    conf_dist_af     = Counter(r["overall_confidence"]        for r in feasib_results)
    no_paths_af      = sum(1 for r in feasib_results if not r["per_path_ratings"])
    total_path_rat   = sum(len(r["per_path_ratings"]) for r in feasib_results)
    se_capec_primary = sum(
        1 for r in feasib_results
        for pf in r["per_path_ratings"]
        if pf["SE"]["source"] == "capec_primary"
    )
    print(f"  → {total_af} feasibility records → {feasib_out}")
    print(f"     Rating distribution       : {dict(rating_dist_af)}")
    print(f"     Confidence distribution   : {dict(conf_dist_af)}")
    print(f"     Records with no paths     : {no_paths_af}/{total_af}")
    print(f"     Total path-level ratings  : {total_path_rat}")
    print(f"     SE from CAPEC primary     : {se_capec_primary}/{total_path_rat}")

    _step("9/9  Risk Computation  (HEAVENS 2.0 Table 8)")
    import risk as risk_engine
    risk_engine._reset_counter()
    risk_records = risk_engine.compute_risk(
        impact_records=impact_results,
        feasibility_records=feasib_results,
        damage_scenarios=damage_raw,
        threat_scenarios=ts_result,
        attack_trees=trees,
    )
    risk_output = [risk_engine.risk_to_dict(r) for r in risk_records]
    risk_out.write_text(json.dumps(risk_output, indent=2))
    total_rk    = len(risk_records)
    level_dist  = Counter(r.risk_level                for r in risk_records)
    value_dist  = Counter(r.risk_value                for r in risk_records)
    conf_dist_r = Counter(r.confidence                for r in risk_records)
    af_dist_r   = Counter(r.attack_feasibility_rating for r in risk_records)
    imp_dist_r  = Counter(r.impact_rating             for r in risk_records)
    print(f"  → {total_rk} risk records → {risk_out}")
    print(f"     Risk level distribution   : {dict(level_dist)}")
    print(f"     Risk value distribution   : {dict(value_dist)}")
    print(f"     Confidence distribution   : {dict(conf_dist_r)}")
    print(f"     Attack feasibility dist   : {dict(af_dist_r)}")
    print(f"     Impact rating dist        : {dict(imp_dist_r)}")

    elapsed = time.time() - t0
    _banner(f"PIPELINE COMPLETE  [{elapsed:.1f}s]")
    print(f"  Ontology nodes         : {n_nodes}")
    print(f"  Assets                 : {len(assets)}")
    print(f"  Damage Scenarios       : {len(damage_scenarios)}")
    print(f"  Threat Scenarios       : {len(threat_scenarios)}")
    print(f"  Cybersecurity Goals    : {len(cybersec_goals)}")
    print(f"  Semantic Graphs        : {len(graphs)}")
    print(f"  Attack Paths           : {len(all_ap_dicts)}")
    print(f"  Attack Trees           : {len(trees)}")
    print(f"  Impact Records         : {total_ir}")
    print(f"  Feasibility Records    : {total_af}")
    print(f"  Risk Records           : {total_rk}")
    print(f"\n  Output directory       : {_out_dir.resolve()}")

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="TARA Pipeline Orchestrator  —  ISO/SAE 21434 / HEAVENS 2.0")
    parser.add_argument("--arch",           default=None, help="Path to architecture.json")
    parser.add_argument("--capec",          default=None, help="Path to capec_nodes.json")
    parser.add_argument("--r155",           default=None, help="Path to r155_raw.json")
    parser.add_argument("--parsed_threats", default=None, help="Path to parsed_threats.json")
    parser.add_argument("--out_dir",        default=None, help="Output directory for all generated files")
    args = parser.parse_args()

    run_pipeline(
        arch_path=args.arch,
        capec_path=args.capec,
        r155_path=args.r155,
        parsed_threats_path=args.parsed_threats,
        out_dir=args.out_dir,
    )