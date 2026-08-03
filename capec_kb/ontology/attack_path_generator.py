from __future__ import annotations
import json
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional

@dataclass
class AttackStep:
    step_id: str
    step_number: int
    action: str
    stride_label: str
    capec_id: Optional[str]
    capec_name: Optional[str]
    src_node: str
    dst_node: str
    trust_transition: str
    trust_delta: int
    exploited_surface: str
    target_asset: Optional[str]
    protocol: str
    edge_type: str
    plausibility_flag: str
    rationale: str

@dataclass
class AttackPath:
    path_id: str
    threat_id: str
    path_index: int
    path_type: str
    steps: list[AttackStep]
    total_trust_gain: int
    entry_point: str
    target_ecu: str
    strike_surfaces: list[str]
    stride_sequence: list[str]
    capec_ids_used: list[str]
    path_length: int
    bus_lateral_hops: int
    has_implausible_steps: bool
    report_eligible: bool
    rationale: str
    trust_boundary_violations: list[str]

@dataclass
class PathGenerationStats:
    threat_id: str
    entry_nodes_total: int
    entry_nodes_explored: int
    entry_nodes_skipped_by_cap: int
    paths_accepted: int
    paths_pruned_by_global_cap: int
    paths_pruned_by_entry_cap: int
    paths_pruned_by_dedup: int
    paths_pruned_by_depth: int
    paths_pruned_by_lateral_cap: int
    trust_boundary_violations_detected: int
    max_depth_used: int
    max_lateral_hops_used: int
    default_traversal_params_used: bool
    coverage_note: str

_ENTRY_SURFACE_STRIDE: dict[str, str] = {
    "wireless_interface": "Spoofing",
    "remote_network": "Spoofing",
    "diagnostic_interface": "Elevation of Privilege",
}

_TRUST_DIR_STRIDE: dict[str, str] = {
    "LOW_TO_HIGH": "Elevation of Privilege",
    "HIGH_TO_LOW": "Tampering",
    "SAME_ZONE": "Tampering",
}

_LATERAL_SURFACE_STRIDE: dict[str, str] = {
    "in_vehicle_network": "Tampering",
    "physical_access": "Tampering",
}

_STRIDE_SURFACE_CAPEC: dict[tuple[str, str], list[str]] = {
    ("Spoofing", "wireless_interface"): ["194", "196", "309"],
    ("Spoofing", "in_vehicle_network"): ["186", "39", "276"],
    ("Spoofing", "diagnostic_interface"): ["194", "196"],
    ("Spoofing", "physical_access"): ["389", "194"],
    ("Tampering", "in_vehicle_network"): ["276", "39", "186"],
    ("Tampering", "diagnostic_interface"): ["180", "122"],
    ("Tampering", "physical_access"): ["638", "624"],
    ("Elevation of Privilege", "diagnostic_interface"): ["121", "180", "122"],
    ("Elevation of Privilege", "wireless_interface"): ["309", "3"],
    ("Information Disclosure", "wireless_interface"): ["157", "158"],
    ("Information Disclosure", "in_vehicle_network"): ["157", "186"],
    ("Information Disclosure", "diagnostic_interface"): ["157"],
    ("DoS", "in_vehicle_network"): ["119", "125", "276"],
    ("DoS", "diagnostic_interface"): ["119", "122"],
    ("DoS", "wireless_interface"): ["119"],
    ("Repudiation", "in_vehicle_network"): ["60"],
    ("Repudiation", "diagnostic_interface"): ["60"],
}

_SENSOR_PHYSICAL_CAPEC: dict[str, list[str]] = {
    "radar": ["194", "389", "621"],
    "camera": ["389", "157", "624"],
    "sensor": ["194", "389", "624"],
    "lidar": ["389", "621"],
    "accel": ["194", "624"],
    "speed": ["194", "39"],
    "impact": ["624", "194"],
    "pressure": ["624", "194"],
}

def _assign_stride_for_step(
    edge: dict,
    step_index: int,
    total_steps: int,
    cia: str,
    entry_surface: str,
) -> str:
    surface = edge.get("attack_surface", "in_vehicle_network")
    trust_dir = edge.get("trust_direction", "SAME_ZONE")
    edge_type = edge.get("edge_type", "direct_flow")
    is_last = step_index == total_steps - 1

    if is_last:
        cia_stride = {
            "Integrity": "Tampering",
            "Availability": "DoS",
            "Confidentiality": "Information Disclosure",
            "Authorization": "Elevation of Privilege",
            "Authenticity": "Spoofing",
        }
        stride = cia_stride.get(cia, "Tampering")
        if stride == "Elevation of Privilege" and surface not in (
            "diagnostic_interface",
            "wireless_interface",
        ):
            privileged_entry = entry_surface in (
                "wireless_interface",
                "remote_network",
                "diagnostic_interface",
            )
            if not privileged_entry:
                stride = "Tampering"
        return stride

    if step_index == 0:
        first_stride = _ENTRY_SURFACE_STRIDE.get(surface)
        if first_stride:
            return first_stride

    if trust_dir == "LOW_TO_HIGH":
        if surface == "in_vehicle_network":
            return "Tampering"
        return "Elevation of Privilege"
    if trust_dir == "HIGH_TO_LOW":
        return "Tampering"
    if edge_type in ("bus_injection", "bus_lateral"):
        return _LATERAL_SURFACE_STRIDE.get(surface, "Tampering")

    return _TRUST_DIR_STRIDE.get(trust_dir, "Tampering")

def _resolve_capec_for_step(
    stride: str,
    surface: str,
    capec_lookup: dict[str, dict],
    ts_capec_refs: list[dict],
) -> tuple[Optional[str], Optional[str]]:
    preferred = _STRIDE_SURFACE_CAPEC.get((stride, surface), [])
    for cid in preferred:
        if cid in capec_lookup:
            return cid, capec_lookup[cid].get("name", "")
    for ref in ts_capec_refs:
        cid = str(ref.get("capec_id", ""))
        if cid in preferred:
            return cid, ref.get("name", capec_lookup.get(cid, {}).get("name", ""))
    if preferred:
        return preferred[0], f"CAPEC-{preferred[0]}"
    if ts_capec_refs:
        ref = ts_capec_refs[0]
        cid = str(ref.get("capec_id", ""))
        return cid, ref.get("name", "")
    return None, None

def _step_action(stride: str, src: str, dst: str, surface: str, trust_dir: str, edge_type: str) -> str:
    surface_label = surface.replace("_", " ")
    if stride == "Spoofing":
        return (
            f"Attacker impersonates a trusted source on {surface_label}, "
            f"injecting crafted messages targeting {dst}"
        )
    if stride == "Elevation of Privilege":
        return (
            f"Attacker escalates privileges from {src} to {dst}, "
            f"crossing trust boundary via {surface_label}"
        )
    if stride == "Tampering":
        if edge_type == "bus_injection":
            return (
                f"Compromised {src} injects unauthorised CAN frames onto shared bus "
                f"accepted by {dst} due to absent message authentication"
            )
        if trust_dir == "HIGH_TO_LOW":
            return f"Attacker on {src} injects tampered data downstream to {dst} via {surface_label}"
        return f"Attacker tampers with data flow from {src} to {dst} via {surface_label}"
    if stride == "DoS":
        return f"Attacker floods {dst} via {surface_label} to exhaust resources and deny service"
    if stride == "Information Disclosure":
        return f"Attacker intercepts data flowing from {src} to {dst} on {surface_label}"
    if stride == "Repudiation":
        return f"Attacker replays or forges session tokens between {src} and {dst} via {surface_label}"
    return f"Attacker moves from {src} to {dst} via {surface_label}"

def _classify_path_type(path_edges: list[dict]) -> str:
    surfaces = [e.get("attack_surface", "") for e in path_edges]
    if "wireless_interface" in surfaces:
        return "remote_wireless"
    if "diagnostic_interface" in surfaces:
        return "physical_diagnostic"
    if "physical_access" in surfaces:
        return "physical_hardware"
    return "lateral_movement"

def _build_trust_zone_map(arch: Optional[dict]) -> dict[str, int]:
    if not arch:
        return {}
    return {
        tz["id"]: tz.get("trust_level", 0)
        for tz in arch.get("trust_zones", [])
    }

def _build_ecu_zone_map(arch: Optional[dict]) -> dict[str, str]:
    if not arch:
        return {}
    return {
        ecu["id"]: ecu.get("trust_zone", "")
        for ecu in arch.get("ecus", [])
    }

def _check_trust_boundary_violations(
    edge_seq: list[dict],
    ecu_zone_map: dict[str, str],
    trust_zone_map: dict[str, int],
) -> list[str]:
    if not ecu_zone_map or not trust_zone_map:
        return []

    violations: list[str] = []
    for edge in edge_seq:
        src = edge.get("src", "")
        dst = edge.get("dst", "")
        edge_trust_src = edge.get("trust_src", "")
        edge_trust_dst = edge.get("trust_dst", "")
        edge_delta = edge.get("trust_delta", 0)

        arch_zone_src = ecu_zone_map.get(src, "")
        arch_zone_dst = ecu_zone_map.get(dst, "")

        if arch_zone_src and edge_trust_src and arch_zone_src != edge_trust_src:
            violations.append(
                f"trust_zone_mismatch: edge {src}->{dst} declares trust_src={edge_trust_src} "
                f"but architecture assigns {src} to {arch_zone_src}"
            )

        if arch_zone_dst and edge_trust_dst and arch_zone_dst != edge_trust_dst:
            violations.append(
                f"trust_zone_mismatch: edge {src}->{dst} declares trust_dst={edge_trust_dst} "
                f"but architecture assigns {dst} to {arch_zone_dst}"
            )

        arch_level_src = trust_zone_map.get(arch_zone_src, -1)
        arch_level_dst = trust_zone_map.get(arch_zone_dst, -1)

        if arch_level_src >= 0 and arch_level_dst >= 0:
            arch_delta = arch_level_dst - arch_level_src
            if edge_delta != 0 and arch_delta != 0 and (edge_delta > 0) != (arch_delta > 0):
                violations.append(
                    f"trust_delta_direction_conflict: edge {src}->{dst} declares delta={edge_delta} "
                    f"but architecture trust levels imply delta={arch_delta} "
                    f"(src zone {arch_zone_src} level={arch_level_src}, "
                    f"dst zone {arch_zone_dst} level={arch_level_dst})"
                )

    return violations

_path_counter: int = 0
_global_step_fingerprints: set[tuple] = set()

def _reset_path_counter() -> None:
    global _path_counter, _global_step_fingerprints
    _path_counter = 0
    _global_step_fingerprints = set()

def _next_path_id() -> str:
    global _path_counter
    _path_counter += 1
    return f"AP-{_path_counter:02d}"

def _dfs_paths(
    adj: dict[str, list[dict]],
    start: str,
    targets: set[str],
    max_depth: int = 6,
    max_paths: int = 5,
    max_lateral_hops: int = 2,
) -> tuple[list[list[dict]], int, int]:
    results: list[list[dict]] = []
    pruned_by_depth: int = 0
    pruned_by_lateral: int = 0
    stack: list[tuple[str, list[dict], set[str], int]] = [(start, [], {start}, 0)]

    while stack:
        node, path, visited, lateral_hops = stack.pop()

        if node in targets and path:
            if len(results) < max_paths:
                results.append(path)
            else:
                pruned_by_depth += 1
            continue

        if len(path) >= max_depth:
            if node in targets:
                if len(results) < max_paths:
                    results.append(path)
                else:
                    pruned_by_depth += 1
            else:
                pruned_by_depth += 1
            continue

        for edge in adj.get(node, []):
            dst = edge["dst"]
            if dst in visited:
                continue
            edge_type = edge.get("edge_type", "direct_flow")
            new_lateral = lateral_hops + (1 if edge_type == "bus_lateral" else 0)
            if new_lateral > max_lateral_hops:
                pruned_by_lateral += 1
                continue
            new_visited = visited | {dst}
            new_path = path + [edge]
            stack.append((dst, new_path, new_visited, new_lateral))

    return results, pruned_by_depth, pruned_by_lateral

def _backfill_step_assets(steps: list[AttackStep], target_asset: str) -> list[AttackStep]:
    for step in steps:
        if step.target_asset is None:
            step.target_asset = target_asset
    return steps

def _generate_physical_paths(
    semantic_graph: dict,
    capec_lookup: dict[str, dict],
    threat_scenario: dict,
) -> list[AttackPath]:
    templates = semantic_graph.get("physical_attack_templates", [])
    if not templates:
        return []

    ts_id = semantic_graph["threat_id"]
    target_asset = semantic_graph["target_asset"]
    cia = semantic_graph["compromised_property"]
    ts_capec_refs = threat_scenario.get("capec_refs", [])

    paths: list[AttackPath] = []
    cia_stride = {
        "Integrity": "Tampering",
        "Availability": "DoS",
        "Confidentiality": "Information Disclosure",
        "Authorization": "Elevation of Privilege",
        "Authenticity": "Spoofing",
    }
    terminal_stride = cia_stride.get(cia, "Tampering")

    for idx, template in enumerate(templates):
        node = template["target_node"]
        capec_ids = template.get("capec_ids", [])
        capec_id = capec_ids[0] if capec_ids else None
        capec_name = capec_lookup.get(capec_id, {}).get("name", f"CAPEC-{capec_id}") if capec_id else None

        step = AttackStep(
            step_id="STEP-001",
            step_number=1,
            action=template.get("description", f"Attacker physically manipulates {node}"),
            stride_label=terminal_stride,
            capec_id=capec_id,
            capec_name=capec_name,
            src_node=node,
            dst_node=node,
            trust_transition="physical_access",
            trust_delta=0,
            exploited_surface="physical_access",
            target_asset=target_asset,
            protocol="PHYSICAL/NONE",
            edge_type="physical_template",
            plausibility_flag="sensor_physical_attack",
            rationale=(
                f"Physical sensor attack template applied: no network topology edge exists "
                f"from an external entry point to {node}. "
                f"Physical signal injection is documented in ISO 21434 §15 threat category."
            ),
        )

        ap = AttackPath(
            path_id=_next_path_id(),
            threat_id=ts_id,
            path_index=900 + idx,
            path_type="physical_hardware",
            steps=[step],
            total_trust_gain=0,
            entry_point=node,
            target_ecu=node,
            strike_surfaces=["physical_access"],
            stride_sequence=[terminal_stride],
            capec_ids_used=[capec_id] if capec_id else [],
            path_length=1,
            bus_lateral_hops=0,
            has_implausible_steps=False,
            report_eligible=True,
            rationale=(
                f"Physical-layer attack path generated from template for {node}. "
                f"No topology traversal required."
            ),
            trust_boundary_violations=[],
        )
        paths.append(ap)

    return paths

_DEFAULT_MAX_DEPTH = 7
_DEFAULT_MAX_LATERAL_HOPS = 2

def generate_attack_paths(
    semantic_graph: dict,
    capec_path: str | Path,
    threat_scenario: dict,
    arch: Optional[dict] = None,
    path_cap: int = 5,
    paths_per_entry_cap: int = 2,
    max_depth: Optional[int] = None,
    max_lateral_hops: Optional[int] = None,
) -> tuple[list[AttackPath], PathGenerationStats]:
    global _global_step_fingerprints

    using_default_depth = max_depth is None
    using_default_lateral = max_lateral_hops is None
    max_depth = max_depth if max_depth is not None else _DEFAULT_MAX_DEPTH
    max_lateral_hops = max_lateral_hops if max_lateral_hops is not None else _DEFAULT_MAX_LATERAL_HOPS
    default_traversal_params_used = using_default_depth or using_default_lateral

    with open(capec_path, "r", encoding="utf-8") as f:
        capec_nodes_raw = json.load(f)

    capec_lookup: dict[str, dict] = {str(c["capec_id"]): c for c in capec_nodes_raw}

    entry_nodes = sorted(semantic_graph["entry_nodes"])
    target_nodes = set(semantic_graph["target_nodes"])
    ts_id = semantic_graph["threat_id"]
    target_asset = semantic_graph["target_asset"]
    cia = semantic_graph["compromised_property"]
    ts_capec_refs = threat_scenario.get("capec_refs", [])

    ecu_zone_map = _build_ecu_zone_map(arch)
    trust_zone_map = _build_trust_zone_map(arch)

    adj: dict[str, list[dict]] = defaultdict(list)
    for edge in semantic_graph.get("graph_edges", []):
        adj[edge["src"]].append({
            "src": edge["src"],
            "dst": edge["dst"],
            "protocol": edge["protocol"],
            "trust_src": edge["trust_src"],
            "trust_dst": edge["trust_dst"],
            "trust_delta": edge["trust_delta"],
            "trust_direction": edge["trust_direction"],
            "attack_surface": edge["attack_surface"],
            "flow_id": edge["flow_id"],
            "edge_type": edge.get("edge_type", "direct_flow"),
            "plausibility_flag": edge.get("plausibility_flag", ""),
        })

    all_paths: list[AttackPath] = []
    path_index = 0

    stat_entries_total = len(entry_nodes)
    stat_entries_explored = 0
    stat_entries_skipped = 0
    stat_pruned_global_cap = 0
    stat_pruned_entry_cap = 0
    stat_pruned_dedup = 0
    stat_pruned_depth = 0
    stat_pruned_lateral = 0
    stat_tb_violations = 0

    def _entry_surface(entry: str) -> str:
        for edge in semantic_graph.get("graph_edges", []):
            if edge["src"] == entry:
                return edge["attack_surface"]
        return "in_vehicle_network"

    entry_surface_map = {e: _entry_surface(e) for e in entry_nodes}

    for entry in entry_nodes:
        if path_index >= path_cap:
            stat_entries_skipped += len(entry_nodes) - stat_entries_explored
            break

        stat_entries_explored += 1
        entry_surface = entry_surface_map.get(entry)

        edge_paths, pruned_depth, pruned_lateral = _dfs_paths(
            adj, entry, target_nodes,
            max_depth=max_depth,
            max_paths=paths_per_entry_cap,
            max_lateral_hops=max_lateral_hops,
        )
        stat_pruned_depth += pruned_depth
        stat_pruned_lateral += pruned_lateral

        accepted_from_entry = 0

        for edge_seq in edge_paths:
            if path_index >= path_cap:
                stat_pruned_global_cap += len(edge_paths) - accepted_from_entry
                break
            if not edge_seq:
                continue

            steps: list[AttackStep] = []
            total_trust_gain = 0
            surfaces_used: set[str] = set()
            stride_seq: list[str] = []
            capec_ids_used: list[str] = []
            lateral_hops = 0
            path_implausible = False

            for i, edge in enumerate(edge_seq):
                is_last = i == len(edge_seq) - 1
                edge_type = edge.get("edge_type", "direct_flow")
                plausibility = edge.get("plausibility_flag", "")
                if "implausible" in plausibility:
                    path_implausible = True

                stride = _assign_stride_for_step(
                    edge, i, len(edge_seq), cia,
                    entry_surface or edge.get("attack_surface", ""),
                )

                capec_id, capec_name = _resolve_capec_for_step(
                    stride, edge["attack_surface"], capec_lookup, ts_capec_refs,
                )

                action = _step_action(
                    stride,
                    edge["src"], edge["dst"],
                    edge["attack_surface"],
                    edge["trust_direction"],
                    edge_type,
                )

                trust_trans = f"trust({edge['trust_src']}) → trust({edge['trust_dst']})"

                step = AttackStep(
                    step_id=f"STEP-{i + 1:03d}",
                    step_number=i + 1,
                    action=action,
                    stride_label=stride,
                    capec_id=capec_id,
                    capec_name=capec_name,
                    src_node=edge["src"],
                    dst_node=edge["dst"],
                    trust_transition=trust_trans,
                    trust_delta=edge["trust_delta"],
                    exploited_surface=edge["attack_surface"],
                    target_asset=target_asset if is_last else None,
                    protocol=edge["protocol"],
                    edge_type=edge_type,
                    plausibility_flag=plausibility,
                    rationale=(
                        f"Edge type: {edge_type}. "
                        f"Trust delta={edge['trust_delta']}. "
                        f"Surface={edge['attack_surface']}. "
                        f"Direction={edge['trust_direction']}. "
                        f"Plausibility={plausibility or 'unknown'}."
                    ),
                )
                steps.append(step)
                surfaces_used.add(edge["attack_surface"])
                stride_seq.append(stride)
                if edge["trust_delta"] > 0:
                    total_trust_gain += edge["trust_delta"]
                if capec_id:
                    capec_ids_used.append(capec_id)
                if edge_type == "bus_lateral":
                    lateral_hops += 1

            steps = _backfill_step_assets(steps, target_asset)

            final_node = edge_seq[-1]["dst"] if edge_seq else entry
            path_type = _classify_path_type(edge_seq)

            if path_type != "physical_hardware":
                step_fingerprint = (ts_id, cia) + tuple((s.src_node, s.dst_node) for s in steps)
                if step_fingerprint in _global_step_fingerprints:
                    stat_pruned_dedup += 1
                    continue
                _global_step_fingerprints.add(step_fingerprint)

            tb_violations = _check_trust_boundary_violations(edge_seq, ecu_zone_map, trust_zone_map)
            if tb_violations:
                stat_tb_violations += len(tb_violations)

            ap = AttackPath(
                path_id=_next_path_id(),
                threat_id=ts_id,
                path_index=path_index,
                path_type=path_type,
                steps=steps,
                total_trust_gain=total_trust_gain,
                entry_point=entry,
                target_ecu=final_node,
                strike_surfaces=sorted(surfaces_used),
                stride_sequence=stride_seq,
                capec_ids_used=list(set(capec_ids_used)),
                path_length=len(steps),
                bus_lateral_hops=lateral_hops,
                has_implausible_steps=path_implausible,
                report_eligible=not path_implausible,
                rationale=(
                    f"Path derived from topology DFS on threat-scoped semantic graph for {ts_id}. "
                    f"Entry: {entry}, Target: {final_node}. "
                    f"Trust gain: {total_trust_gain}. Surfaces: {sorted(surfaces_used)}. "
                    f"Bus lateral hops: {lateral_hops}. "
                    f"Implausible steps: {path_implausible}. "
                    f"Trust boundary violations: {len(tb_violations)}."
                ),
                trust_boundary_violations=tb_violations,
            )
            all_paths.append(ap)
            path_index += 1
            accepted_from_entry += 1

        remaining_in_entry = len(edge_paths) - accepted_from_entry
        if path_index < path_cap and remaining_in_entry > 0:
            stat_pruned_entry_cap += remaining_in_entry

    physical_paths = _generate_physical_paths(semantic_graph, capec_lookup, threat_scenario)
    all_paths.extend(physical_paths)

    total_pruned = (
        stat_pruned_global_cap
        + stat_pruned_entry_cap
        + stat_pruned_dedup
        + stat_pruned_depth
        + stat_pruned_lateral
    )

    if total_pruned == 0 and not default_traversal_params_used:
        coverage_note = "full_coverage: no paths were pruned by any constraint"
    else:
        parts = []
        if default_traversal_params_used:
            defaults_used = []
            if using_default_depth:
                defaults_used.append(f"max_depth={max_depth} (default)")
            if using_default_lateral:
                defaults_used.append(f"max_lateral_hops={max_lateral_hops} (default)")
            parts.append("WARNING: default traversal params used — " + ", ".join(defaults_used))
        if stat_pruned_global_cap:
            parts.append(f"{stat_pruned_global_cap} by global cap (cap={path_cap})")
        if stat_pruned_entry_cap:
            parts.append(f"{stat_pruned_entry_cap} by per-entry cap (cap={paths_per_entry_cap})")
        if stat_pruned_dedup:
            parts.append(f"{stat_pruned_dedup} by intra-cia deduplication")
        if stat_pruned_depth:
            parts.append(f"{stat_pruned_depth} by max_depth={max_depth}")
        if stat_pruned_lateral:
            parts.append(f"{stat_pruned_lateral} by max_lateral_hops={max_lateral_hops}")
        coverage_note = "partial_coverage: " + "; ".join(parts)

    stats = PathGenerationStats(
        threat_id=ts_id,
        entry_nodes_total=stat_entries_total,
        entry_nodes_explored=stat_entries_explored,
        entry_nodes_skipped_by_cap=stat_entries_skipped,
        paths_accepted=path_index,
        paths_pruned_by_global_cap=stat_pruned_global_cap,
        paths_pruned_by_entry_cap=stat_pruned_entry_cap,
        paths_pruned_by_dedup=stat_pruned_dedup,
        paths_pruned_by_depth=stat_pruned_depth,
        paths_pruned_by_lateral_cap=stat_pruned_lateral,
        trust_boundary_violations_detected=stat_tb_violations,
        max_depth_used=max_depth,
        max_lateral_hops_used=max_lateral_hops,
        default_traversal_params_used=default_traversal_params_used,
        coverage_note=coverage_note,
    )

    return all_paths, stats

def paths_to_dict(paths: list[AttackPath]) -> list[dict]:
    return [asdict(p) for p in paths]

def stats_to_dict(stats: PathGenerationStats) -> dict:
    return {
        "threat_id": stats.threat_id,
        "entry_nodes_total": stats.entry_nodes_total,
        "entry_nodes_explored": stats.entry_nodes_explored,
        "entry_nodes_skipped_by_cap": stats.entry_nodes_skipped_by_cap,
        "paths_accepted": stats.paths_accepted,
        "paths_pruned_by_global_cap": stats.paths_pruned_by_global_cap,
        "paths_pruned_by_entry_cap": stats.paths_pruned_by_entry_cap,
        "paths_pruned_by_dedup": stats.paths_pruned_by_dedup,
        "paths_pruned_by_depth": stats.paths_pruned_by_depth,
        "paths_pruned_by_lateral_cap": stats.paths_pruned_by_lateral_cap,
        "trust_boundary_violations_detected": stats.trust_boundary_violations_detected,
        "max_depth_used": stats.max_depth_used,
        "max_lateral_hops_used": stats.max_lateral_hops_used,
        "default_traversal_params_used": stats.default_traversal_params_used,
        "coverage_note": stats.coverage_note,
    }

if __name__ == "__main__":
    import sys
    from collections import Counter

    graphs_path  = sys.argv[1] if len(sys.argv) > 1 else "semantic_graphs.json"
    ts_path      = sys.argv[2] if len(sys.argv) > 2 else "threat_scenarios.json"
    capec_path   = sys.argv[3] if len(sys.argv) > 3 else "capec_nodes.json"
    out_path     = sys.argv[4] if len(sys.argv) > 4 else "attack_paths.json"
    arch_path    = sys.argv[5] if len(sys.argv) > 5 else "architecture.json"
    stats_path   = sys.argv[6] if len(sys.argv) > 6 else "attack_path_generation_stats.json"

    with open(graphs_path) as f:
        graphs = json.load(f)
    with open(ts_path) as f:
        threat_scenarios = json.load(f)

    arch: Optional[dict] = None
    try:
        with open(arch_path) as f:
            arch = json.load(f)
    except FileNotFoundError:
        print(f"[attack_path_generator] WARNING: architecture file not found at {arch_path} — trust boundary validation disabled")

    ts_list = threat_scenarios.get("scenarios", threat_scenarios) if isinstance(threat_scenarios, dict) else threat_scenarios
    ts_index = {ts["threat_id"]: ts for ts in ts_list}
    _reset_path_counter()

    all_paths: list[dict] = []
    all_stats: list[dict] = []

    for graph in sorted(graphs, key=lambda g: g["threat_id"]):
        ts = ts_index.get(graph["threat_id"])
        if not ts:
            continue
        paths, stats = generate_attack_paths(graph, capec_path, ts, arch=arch)
        all_paths.extend(paths_to_dict(paths))
        all_stats.append(stats_to_dict(stats))

    with open(out_path, "w") as f:
        json.dump(all_paths, f, indent=2)

    with open(stats_path, "w") as f:
        json.dump(all_stats, f, indent=2)

    print(f"[attack_path_generator] Generated {len(all_paths)} attack paths → {out_path}")
    print(f"[attack_path_generator] Generation stats → {stats_path}")

    types = Counter(p["path_type"] for p in all_paths)
    for k, v in sorted(types.items()):
        print(f"  {k:25s}: {v}")

    report_eligible = sum(1 for p in all_paths if p["report_eligible"])
    implausible     = sum(1 for p in all_paths if p["has_implausible_steps"])
    tb_flagged      = sum(1 for p in all_paths if p.get("trust_boundary_violations"))
    total_steps     = sum(len(p["steps"]) for p in all_paths)
    null_assets     = sum(1 for p in all_paths for s in p["steps"] if not s.get("target_asset"))

    total_pruned = sum(
        s["paths_pruned_by_global_cap"]
        + s["paths_pruned_by_entry_cap"]
        + s["paths_pruned_by_dedup"]
        + s["paths_pruned_by_depth"]
        + s["paths_pruned_by_lateral_cap"]
        for s in all_stats
    )
    default_param_warnings = sum(1 for s in all_stats if s["default_traversal_params_used"])
    partial_coverage = sum(1 for s in all_stats if s["coverage_note"].startswith("partial_coverage"))

    print(f"  report_eligible:              {report_eligible}/{len(all_paths)}")
    print(f"  has_implausible_steps:        {implausible}/{len(all_paths)}")
    print(f"  trust_boundary_violations:    {tb_flagged}/{len(all_paths)} paths flagged")
    print(f"  steps with null target_asset: {null_assets}/{total_steps}")
    print(f"  total paths pruned:           {total_pruned}")
    print(f"  threat scenarios with partial coverage:   {partial_coverage}/{len(all_stats)}")
    print(f"  threat scenarios using default traversal: {default_param_warnings}/{len(all_stats)}")