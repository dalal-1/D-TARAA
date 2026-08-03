from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional
from collections import defaultdict


@dataclass
class TreeNode:
    node_id: str
    node_type: str
    label: str
    goal: str
    threat_id: Optional[str] = None
    stride_label: Optional[str] = None
    capec_id: Optional[str] = None
    capec_name: Optional[str] = None
    trust_transition: Optional[str] = None
    exploited_surface: Optional[str] = None
    attack_step_ref: Optional[str] = None
    path_ref: Optional[str] = None
    children: list["TreeNode"] = field(default_factory=list)
    is_shared_prefix: bool = False


@dataclass
class AttackTree:
    tree_id: str
    damage_scenario_id: str
    covered_threat_ids: list[str]
    damage_scenario_title: str
    sfop_category: str
    harm_category: str
    safety_level: str
    financial_impact: str
    operational_impact: str
    privacy_impact: str
    heavens_category: str
    heavens_controllability: str
    heavens_controllability_propagated: bool
    heavens_identification_purpose: str
    heavens_degradation_mode: str
    heavens_fallback_profile_class: str
    heavens_sae_automation_level: str
    heavens_damage_digest: str
    root: TreeNode
    path_count: int
    eligible_path_count: int
    leaf_count: int
    max_depth: int
    unique_capec_ids: list[str]
    unique_surfaces: list[str]
    unique_threat_ids: list[str]
    shared_prefix_detected: bool
    shared_prefix_length: int
    pruning_coverage_note: str
    rationale: str


_node_counter: int = 0
_tree_counter: int = 0


def _reset_counters() -> None:
    global _node_counter, _tree_counter
    _node_counter = 0
    _tree_counter = 0


def _next_node_id() -> str:
    global _node_counter
    _node_counter += 1
    return f"Node {_node_counter}"


def _next_tree_id() -> str:
    global _tree_counter
    _tree_counter += 1
    return f"AT-{_tree_counter:02d}"


def _build_leaf(step: dict, path_id: str, threat_id: str) -> TreeNode:
    stride = step.get("stride_label", "")
    capec_id = step.get("capec_id")
    capec_name = step.get("capec_name")
    surface = step.get("exploited_surface", "")
    step_id = step.get("step_id", "")
    label = step.get("action", f"Attack step {step_id}")

    return TreeNode(
        node_id=_next_node_id(),
        node_type="LEAF",
        label=label,
        goal=_leaf_goal(stride, step.get("dst_node", ""), step.get("target_asset")),
        threat_id=threat_id,
        stride_label=stride,
        capec_id=capec_id,
        capec_name=capec_name,
        trust_transition=step.get("trust_transition"),
        exploited_surface=surface,
        attack_step_ref=step_id,
        path_ref=path_id,
    )


def _leaf_goal(stride: str, dst_node: str, target_asset: Optional[str]) -> str:
    if target_asset:
        return f"Compromise {target_asset} via {stride} on {dst_node}"
    return f"Reach {dst_node} via {stride}"


def _step_tuple(step: dict) -> tuple[str, str, str, str, str]:
    return (
        step.get("src_node", ""),
        step.get("dst_node", ""),
        step.get("stride_label", ""),
        step.get("exploited_surface", ""),
        step.get("capec_id", "") or "",
    )


def _detect_shared_prefix(paths: list[dict]) -> int:
    if len(paths) < 2:
        return 0

    by_type: dict[str, list[dict]] = defaultdict(list)
    for p in paths:
        by_type[p.get("path_type", "unknown")].append(p)

    best = 0
    for ptype, group in by_type.items():
        if len(group) < 2:
            continue
        step_sequences = [p.get("steps", []) for p in group]
        if not all(step_sequences):
            continue
        min_len = min(len(seq) for seq in step_sequences)
        if min_len == 0:
            continue

        shared_length = 0
        for pos in range(min_len):
            tuples_at_pos = [_step_tuple(seq[pos]) for seq in step_sequences]
            if all(t == tuples_at_pos[0] for t in tuples_at_pos):
                shared_length = pos + 1
            else:
                break
        if shared_length > best:
            best = shared_length

    return best


def _build_and_node_for_path(path: dict) -> TreeNode:
    path_id = path["path_id"]
    threat_id = path.get("threat_id", "")
    path_type = path.get("path_type", "unknown")
    entry = path.get("entry_point", "?")
    target = path.get("target_ecu", "?")
    steps = path.get("steps", [])
    label = f"Path [{path_type}]: {entry} → {target} ({len(steps)} steps)"
    goal = f"Complete sequential attack from {entry} to {target}"
    leaf_nodes = [_build_leaf(step, path_id, threat_id) for step in steps]

    return TreeNode(
        node_id=_next_node_id(),
        node_type="AND",
        label=label,
        goal=goal,
        threat_id=threat_id,
        path_ref=path_id,
        children=leaf_nodes,
    )


def _collect_pruning_note(paths: list[dict]) -> str:
    notes = set()
    for p in paths:
        note = p.get("rationale", "")
        if "partial_coverage" in note or "default traversal" in note.lower():
            notes.add("upstream_path_pruning_detected")
        if p.get("has_implausible_steps"):
            notes.add("implausible_steps_present")
        if p.get("trust_boundary_violations"):
            notes.add("trust_boundary_violations_present")
    return "; ".join(sorted(notes)) if notes else "full_coverage"


def build_attack_tree_for_ds(
    ds: dict,
    paths: list[dict],
    covered_threat_ids: list[str],
    pruning_coverage_note: str = "",
) -> AttackTree:
    ds_id = ds["damage_id"]
    ds_title = ds.get("title", ds_id)
    sfop = ds.get("sfop_category", "Operational")
    harm_cat = ds.get("harm_category", "operational_disruption")
    safety_level = ds.get("safety_level", "S1")
    financial_impact = ds.get("financial_impact", "F1")
    operational_impact = ds.get("operational_impact", "O1")
    privacy_impact = ds.get("privacy_impact", "P0")

    heavens_category = ds.get("heavens_category", "O")
    heavens_controllability = ds.get("heavens_controllability", "C0")
    heavens_controllability_propagated = bool(ds.get("heavens_controllability_propagated", False))
    heavens_identification_purpose = ds.get("heavens_identification_purpose", "general_security_relevance")
    heavens_degradation_mode = ds.get("heavens_degradation_mode", "safe_state_default")
    heavens_fallback_profile_class = ds.get("heavens_fallback_profile_class", "unknown")
    heavens_sae_automation_level = ds.get("heavens_sae_automation_level", "SAE_L0_L4")
    heavens_damage_digest = ds.get("heavens_damage_digest", "")

    root_label = f"[ROOT] {ds_title}"
    root_goal = (
        f"Achieve damage scenario {ds_id}: {sfop} impact "
        f"via harm category {harm_cat} "
        f"[HEAVENS {heavens_category} / {heavens_controllability}]"
    )

    root = TreeNode(
        node_id=_next_node_id(),
        node_type="ROOT",
        label=root_label,
        goal=root_goal,
        children=[],
    )

    eligible_paths = [p for p in paths if p.get("report_eligible", True)]
    all_path_count = len(paths)
    eligible_path_count = len(eligible_paths)

    resolved_pruning_note = pruning_coverage_note or _collect_pruning_note(paths)

    if not paths:
        root.children = [TreeNode(
            node_id=_next_node_id(),
            node_type="LEAF",
            label="No attack paths derived for this damage scenario",
            goal="N/A",
        )]
        return AttackTree(
            tree_id=_next_tree_id(),
            damage_scenario_id=ds_id,
            covered_threat_ids=covered_threat_ids,
            damage_scenario_title=ds_title,
            sfop_category=sfop,
            harm_category=harm_cat,
            safety_level=safety_level,
            financial_impact=financial_impact,
            operational_impact=operational_impact,
            privacy_impact=privacy_impact,
            heavens_category=heavens_category,
            heavens_controllability=heavens_controllability,
            heavens_controllability_propagated=heavens_controllability_propagated,
            heavens_identification_purpose=heavens_identification_purpose,
            heavens_degradation_mode=heavens_degradation_mode,
            heavens_fallback_profile_class=heavens_fallback_profile_class,
            heavens_sae_automation_level=heavens_sae_automation_level,
            heavens_damage_digest=heavens_damage_digest,
            root=root,
            path_count=0,
            eligible_path_count=0,
            leaf_count=0,
            max_depth=1,
            unique_capec_ids=[],
            unique_surfaces=[],
            unique_threat_ids=covered_threat_ids,
            shared_prefix_detected=False,
            shared_prefix_length=0,
            pruning_coverage_note=resolved_pruning_note,
            rationale=f"No attack paths available for DS {ds_id}.",
        )

    render_paths = eligible_paths if eligible_paths else paths
    shared_prefix_length = _detect_shared_prefix(render_paths)
    shared_prefix_detected = shared_prefix_length > 0

    or_node = TreeNode(
        node_id=_next_node_id(),
        node_type="OR",
        label=f"[OR] Alternative attack paths for {ds_id}",
        goal=f"Any one of {len(render_paths)} eligible paths achieves the damage scenario",
        children=[],
    )

    by_type: dict[str, list[dict]] = defaultdict(list)
    for p in render_paths:
        by_type[p.get("path_type", "unknown")].append(p)

    for ptype, group in by_type.items():
        group_prefix_len = _detect_shared_prefix(group)
        group_prefix_detected = group_prefix_len > 0 and len(group) >= 2

        if group_prefix_detected:
            shared_steps = group[0]["steps"][:group_prefix_len]
            shared_leaves: list[TreeNode] = []

            for pos, shared_step in enumerate(shared_steps):
                step_id = shared_step.get("step_id", "")
                shared_path_ids = [p["path_id"] for p in group]
                shared_threat_ids = list(dict.fromkeys(p.get("threat_id", "") for p in group))
                shared_threat_id = shared_threat_ids[0] if shared_threat_ids else ""
                shared_leaf = TreeNode(
                    node_id=_next_node_id(),
                    node_type="LEAF",
                    label=f"[SHARED] {shared_step.get('action', 'Shared step')}",
                    goal=f"Common step {pos + 1}: reach {shared_step.get('dst_node', '?')}",
                    threat_id=shared_threat_id,
                    stride_label=shared_step.get("stride_label"),
                    capec_id=shared_step.get("capec_id"),
                    capec_name=shared_step.get("capec_name"),
                    trust_transition=shared_step.get("trust_transition"),
                    exploited_surface=shared_step.get("exploited_surface"),
                    attack_step_ref=step_id,
                    path_ref="|".join(shared_path_ids),
                    is_shared_prefix=True,
                )
                shared_leaves.append(shared_leaf)

            group_or = TreeNode(
                node_id=_next_node_id(),
                node_type="OR",
                label=f"[OR] Divergent {ptype} paths after shared prefix",
                goal=f"Any divergent continuation after {group_prefix_len}-step shared prefix",
                children=[],
            )
            for path in group:
                remaining = path.get("steps", [])[group_prefix_len:]
                if not remaining:
                    continue
                divergent_and = TreeNode(
                    node_id=_next_node_id(),
                    node_type="AND",
                    label=f"[AND] Divergent path {path['path_index'] + 1}: {ptype}",
                    goal=f"Complete path {path['path_id']} after shared prefix ({group_prefix_len} steps)",
                    threat_id=path.get("threat_id", ""),
                    path_ref=path["path_id"],
                    children=[_build_leaf(s, path["path_id"], path.get("threat_id", "")) for s in remaining],
                )
                group_or.children.append(divergent_and)

            converge_and = TreeNode(
                node_id=_next_node_id(),
                node_type="AND",
                label=f"[AND] [{ptype}] Shared prefix ({group_prefix_len} steps) then divergent paths",
                goal=f"Attacker establishes {ptype} foothold then chooses divergent path",
                children=shared_leaves + [group_or],
            )
            or_node.children.append(converge_and)

        else:
            for path in group:
                and_node = _build_and_node_for_path(path)
                or_node.children.append(and_node)

    if len(or_node.children) == 1:
        root.children = or_node.children
    else:
        root.children = [or_node]

    all_leaves: list[TreeNode] = []
    all_capec: set[str] = set()
    all_surfaces: set[str] = set()
    all_threat_ids: set[str] = set()

    def _collect_leaves(node: TreeNode, depth: int, depths: list[int]) -> None:
        if node.node_type == "LEAF":
            all_leaves.append(node)
            if node.capec_id:
                all_capec.add(node.capec_id)
            if node.exploited_surface:
                all_surfaces.add(node.exploited_surface)
            if node.threat_id:
                all_threat_ids.add(node.threat_id)
            depths.append(depth)
        for child in node.children:
            _collect_leaves(child, depth + 1, depths)

    depths: list[int] = []
    _collect_leaves(root, 0, depths)
    max_depth = max(depths) if depths else 0

    return AttackTree(
        tree_id=_next_tree_id(),
        damage_scenario_id=ds_id,
        covered_threat_ids=covered_threat_ids,
        damage_scenario_title=ds_title,
        sfop_category=sfop,
        harm_category=harm_cat,
        safety_level=safety_level,
        financial_impact=financial_impact,
        operational_impact=operational_impact,
        privacy_impact=privacy_impact,
        heavens_category=heavens_category,
        heavens_controllability=heavens_controllability,
        heavens_controllability_propagated=heavens_controllability_propagated,
        heavens_identification_purpose=heavens_identification_purpose,
        heavens_degradation_mode=heavens_degradation_mode,
        heavens_fallback_profile_class=heavens_fallback_profile_class,
        heavens_sae_automation_level=heavens_sae_automation_level,
        heavens_damage_digest=heavens_damage_digest,
        root=root,
        path_count=all_path_count,
        eligible_path_count=eligible_path_count,
        leaf_count=len(all_leaves),
        max_depth=max_depth,
        unique_capec_ids=sorted(all_capec),
        unique_surfaces=sorted(all_surfaces),
        unique_threat_ids=sorted(all_threat_ids),
        shared_prefix_detected=shared_prefix_detected,
        shared_prefix_length=shared_prefix_length,
        pruning_coverage_note=resolved_pruning_note,
        rationale=(
            f"Tree generated per-DS for {ds_id}. "
            f"Covered threat IDs: {covered_threat_ids}. "
            f"Total paths: {all_path_count}, eligible: {eligible_path_count}. "
            f"Structure: {'shared-prefix AND→OR' if shared_prefix_detected else 'OR→AND'}. "
            f"Leaf count: {len(all_leaves)}, max depth: {max_depth}. "
            f"HEAVENS: category={heavens_category}, controllability={heavens_controllability}, "
            f"degradation={heavens_degradation_mode}, fallback={heavens_fallback_profile_class}, "
            f"SAE={heavens_sae_automation_level}."
        ),
    )


def tree_to_dict(tree: AttackTree) -> dict:
    def _node_to_dict(node: TreeNode) -> dict:
        d = asdict(node)
        d["children"] = [_node_to_dict(c) for c in node.children]
        return d
    d = asdict(tree)
    d["root"] = _node_to_dict(tree.root)
    return d


def build_attack_tree(
    ts_paths: list[dict],
    ts: dict,
    cybersecurity_goals: list[dict],
    damage_scenarios: Optional[list[dict]] = None,
) -> "AttackTree":
    threat_id = ts.get("threat_id", "")

    ds_id: str = ""
    covered_threat_ids: list[str] = []

    for goal in cybersecurity_goals:
        linked = goal.get("linked_ts_ids", [])
        if threat_id in linked:
            candidate_ds = goal.get("damage_scenario_id", "")
            if candidate_ds and not ds_id:
                ds_id = candidate_ds
            for tid in linked:
                if tid not in covered_threat_ids:
                    covered_threat_ids.append(tid)

    if not ds_id:
        ds_id = ts.get("damage_scenario_id") or threat_id
    if not covered_threat_ids:
        covered_threat_ids = [threat_id] if threat_id else []

    ds_record: Optional[dict] = None
    if damage_scenarios:
        for d in damage_scenarios:
            if d.get("damage_id") == ds_id:
                ds_record = d
                break

    if ds_record:
        ds: dict = {
            "damage_id":                          ds_record["damage_id"],
            "title":                              ds_record.get("title", ds_id),
            "sfop_category":                      ds_record.get("sfop_category", "Operational"),
            "harm_category":                      ds_record.get("harm_category", "operational_disruption"),
            "safety_level":                       ds_record.get("safety_level", "S1"),
            "financial_impact":                   ds_record.get("financial_impact", "F1"),
            "operational_impact":                 ds_record.get("operational_impact", "O1"),
            "privacy_impact":                     ds_record.get("privacy_impact", "P0"),
            "heavens_category":                   ds_record.get("heavens_category", "O"),
            "heavens_controllability":            ds_record.get("heavens_controllability", "C0"),
            "heavens_controllability_propagated": ds_record.get("heavens_controllability_propagated", False),
            "heavens_identification_purpose":     ds_record.get("heavens_identification_purpose", "general_security_relevance"),
            "heavens_degradation_mode":           ds_record.get("heavens_degradation_mode", "safe_state_default"),
            "heavens_fallback_profile_class":     ds_record.get("heavens_fallback_profile_class", "unknown"),
            "heavens_sae_automation_level":       ds_record.get("heavens_sae_automation_level", "SAE_L0_L4"),
            "heavens_damage_digest":              ds_record.get("heavens_damage_digest", ""),
        }
    else:
        ds = {
            "damage_id":                          ds_id,
            "title":                              ts.get("damage_scenario_title") or ts.get("title") or ds_id,
            "sfop_category":                      ts.get("sfop_category", "Operational"),
            "harm_category":                      ts.get("harm_category", "operational_disruption"),
            "safety_level":                       ts.get("safety_level", "S1"),
            "financial_impact":                   ts.get("financial_impact", "F1"),
            "operational_impact":                 ts.get("operational_impact", "O1"),
            "privacy_impact":                     ts.get("privacy_impact", "P0"),
            "heavens_category":                   ts.get("heavens_category", "O"),
            "heavens_controllability":            ts.get("heavens_controllability", "C0"),
            "heavens_controllability_propagated": ts.get("heavens_controllability_propagated", False),
            "heavens_identification_purpose":     ts.get("heavens_identification_purpose", "general_security_relevance"),
            "heavens_degradation_mode":           ts.get("heavens_degradation_mode", "safe_state_default"),
            "heavens_fallback_profile_class":     ts.get("heavens_fallback_profile_class", "unknown"),
            "heavens_sae_automation_level":       ts.get("heavens_sae_automation_level", "SAE_L0_L4"),
            "heavens_damage_digest":              ts.get("heavens_damage_digest", ""),
        }

    pruning_note = _collect_pruning_note(ts_paths)
    return build_attack_tree_for_ds(ds, ts_paths, covered_threat_ids, pruning_coverage_note=pruning_note)


if __name__ == "__main__":
    import sys

    paths_path = sys.argv[1] if len(sys.argv) > 1 else "attack_paths.json"
    ds_path    = sys.argv[2] if len(sys.argv) > 2 else "damage_scenarios.json"
    goals_path = sys.argv[3] if len(sys.argv) > 3 else "cybersecurity_goals.json"
    out_path   = sys.argv[4] if len(sys.argv) > 4 else "attack_trees.json"

    with open(paths_path) as f:
        all_paths = json.load(f)
    with open(ds_path) as f:
        damage_scenarios = json.load(f)
    with open(goals_path) as f:
        cybersecurity_goals = json.load(f)

    _reset_counters()

    goal_ds_to_ts: dict[str, list[str]] = defaultdict(list)
    for g in cybersecurity_goals:
        g_ds_id = g.get("damage_scenario_id")
        if g_ds_id:
            for ts_id in g.get("linked_ts_ids", []):
                if ts_id not in goal_ds_to_ts[g_ds_id]:
                    goal_ds_to_ts[g_ds_id].append(ts_id)

    paths_by_ts: dict[str, list[dict]] = defaultdict(list)
    for p in all_paths:
        paths_by_ts[p["threat_id"]].append(p)

    ds_index: dict[str, dict] = {d["damage_id"]: d for d in damage_scenarios}

    trees: list[dict] = []
    for ds in sorted(damage_scenarios, key=lambda d: d["damage_id"]):
        ds_id = ds["damage_id"]
        ts_ids = goal_ds_to_ts.get(ds_id, [])
        ds_paths: list[dict] = []
        for ts_id in ts_ids:
            ds_paths.extend(paths_by_ts.get(ts_id, []))
        seen_path_ids: set[str] = set()
        deduped_paths: list[dict] = []
        for p in ds_paths:
            if p["path_id"] not in seen_path_ids:
                seen_path_ids.add(p["path_id"])
                deduped_paths.append(p)
        pruning_note = _collect_pruning_note(deduped_paths)
        tree = build_attack_tree_for_ds(ds, deduped_paths, ts_ids, pruning_coverage_note=pruning_note)
        trees.append(tree_to_dict(tree))

    with open(out_path, "w") as f:
        json.dump(trees, f, indent=2)

    total = len(trees)
    with_paths = sum(1 for t in trees if t["path_count"] > 0)
    partial = sum(1 for t in trees if "pruning" in t.get("pruning_coverage_note", ""))
    implausible_flagged = sum(1 for t in trees if "implausible" in t.get("pruning_coverage_note", ""))

    print(f"[attack_tree_generator] Generated {total} attack trees → {out_path}")
    print(f"  Trees with paths:                  {with_paths}/{total}")
    print(f"  Trees without paths:               {total - with_paths}/{total}")
    print(f"  Trees with upstream pruning flag:  {partial}/{total}")
    print(f"  Trees with implausible path flag:  {implausible_flagged}/{total}")
    print(f"  DS coverage:                       {total}/{total}")