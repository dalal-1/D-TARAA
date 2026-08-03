from __future__ import annotations

import json
from collections import defaultdict, deque
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional


@dataclass
class GraphNode:
    node_id: str
    node_type: str
    trust_level: int
    trust_zone: str
    attack_surfaces: list[str]
    is_entry_point: bool
    is_target: bool
    is_physical_only: bool
    ontology_ids: list[str]
    functional_domains: list[str]


@dataclass
class GraphEdge:
    edge_id: str
    src: str
    dst: str
    protocol: str
    direction: str
    trust_src: int
    trust_dst: int
    trust_delta: int
    trust_direction: str
    attack_surface: str
    flow_id: str
    edge_type: str
    plausibility_flag: str


@dataclass
class TrustBoundaryCrossing:
    src_ecu: str
    dst_ecu: str
    src_trust: int
    dst_trust: int
    direction: str


@dataclass
class PhysicalAttackTemplate:
    template_id: str
    target_node: str
    attack_type: str
    capec_ids: list[str]
    description: str


@dataclass
class AttackSemanticGraph:
    threat_id: str
    target_asset: str
    compromised_property: str
    source_ontology_id: str

    entry_nodes: list[str]
    target_nodes: list[str]
    traversal_nodes: list[str]

    graph_nodes: list[GraphNode]
    graph_edges: list[GraphEdge]
    trust_boundary_crossings: list[TrustBoundaryCrossing]
    physical_attack_templates: list[PhysicalAttackTemplate]

    reachable_attack_surfaces: list[str]
    topology_source: str
    is_physical_sensor_threat: bool


_PROTOCOL_SURFACE: dict[str, str] = {
    "CAN": "in_vehicle_network",
    "CAN-FD": "in_vehicle_network",
    "ETH": "diagnostic_interface",
    "UDS": "diagnostic_interface",
    "BLE": "wireless_interface",
    "PWR": "physical_access",
    "DIGITAL": "physical_access",
    "ANALOG": "physical_access",
    "NONE": "in_vehicle_network",
}

_PHYSICAL_SENSOR_CAPEC: dict[str, list[str]] = {
    "radar": ["194", "389", "621"],
    "camera": ["389", "157", "624"],
    "sensor": ["194", "389", "624"],
    "lidar": ["389", "621"],
}

_DOMAIN_FUNCTIONAL_GROUP: dict[str, str] = {
    "NETWORK_GATEWAYING": "GATEWAY",
    "AUTOMATED_DRIVING_CONTROL": "MOTION",
    "PERCEPTION_AND_SENSING": "SENSING",
    "VEHICLE_MOTION_CONTROL": "MOTION",
    "OCCUPANT_SAFETY_SYSTEMS": "SAFETY",
    "POWERTRAIN_MANAGEMENT": "MOTION",
    "VEHICLE_ACCESS_CONTROL": "ACCESS",
    "DIAGNOSTIC_AND_SERVICE": "DIAGNOSTIC",
    "BIOMETRIC_MONITORING": "SENSING",
    "CHARGING_AND_ENERGY": "ENERGY",
}

_COMPATIBLE_GROUPS: frozenset[frozenset] = frozenset({
    frozenset({"MOTION", "MOTION"}),
    frozenset({"GATEWAY", "MOTION"}),
    frozenset({"GATEWAY", "SAFETY"}),
    frozenset({"GATEWAY", "SENSING"}),
    frozenset({"GATEWAY", "ACCESS"}),
    frozenset({"GATEWAY", "DIAGNOSTIC"}),
    frozenset({"GATEWAY", "ENERGY"}),
    frozenset({"ACCESS", "GATEWAY"}),
    frozenset({"DIAGNOSTIC", "MOTION"}),
    frozenset({"DIAGNOSTIC", "GATEWAY"}),
    frozenset({"SENSING", "MOTION"}),
    frozenset({"MOTION", "SAFETY"}),
    frozenset({"ENERGY", "MOTION"}),
})


def _protocol_to_surface(protocol_dict: dict) -> str:
    transport = protocol_dict.get("transport", "NONE")
    application = protocol_dict.get("application", "NONE")
    if application and application != "NONE":
        return _PROTOCOL_SURFACE.get(application, _PROTOCOL_SURFACE.get(transport, "in_vehicle_network"))
    return _PROTOCOL_SURFACE.get(transport, "in_vehicle_network")


def _build_trust_zone_map(arch: dict) -> dict[str, dict]:
    tz_levels: dict[str, int] = {tz["id"]: tz["trust_level"] for tz in arch["trust_zones"]}
    ecu_map: dict[str, dict] = {}
    for ecu in arch["ecus"]:
        tz = ecu["trust_zone"]
        ecu_map[ecu["id"]] = {
            "trust_zone": tz,
            "trust_level": tz_levels.get(tz, 0),
        }
    for iface in arch["external_interfaces"]:
        tz = iface["trust_zone"]
        ecu_map[iface["id"]] = {
            "trust_zone": tz,
            "trust_level": tz_levels.get(tz, 0),
            "exposed": iface.get("exposed", False),
            "attacker_profile": iface.get("attacker_profile", "physical"),
        }
    return ecu_map


def _build_ontology_ecu_index(nodes: list[dict]) -> dict[str, list[dict]]:
    idx: dict[str, list[dict]] = defaultdict(list)
    for node in nodes:
        for ecu in node.get("mapped_ecus", []):
            idx[ecu].append(node)
    return idx


def _get_ecu_functional_group(ecu_id: str, ont_ecu_idx: dict[str, list[dict]]) -> str:
    for node in ont_ecu_idx.get(ecu_id, []):
        domain = node.get("functional_domain", "")
        group = _DOMAIN_FUNCTIONAL_GROUP.get(domain)
        if group:
            return group
    return "UNKNOWN"


def _bus_edge_is_plausible(
    src: str,
    dst: str,
    ont_ecu_idx: dict[str, list[dict]],
) -> tuple[bool, str]:
    src_group = _get_ecu_functional_group(src, ont_ecu_idx)
    dst_group = _get_ecu_functional_group(dst, ont_ecu_idx)
    pair = frozenset({src_group, dst_group})
    if src_group == "GATEWAY" or dst_group == "GATEWAY":
        return True, "gateway_mediated"
    if src_group == dst_group:
        return True, "same_domain"
    if pair in _COMPATIBLE_GROUPS:
        return True, "cross_domain_compatible"
    return False, f"implausible_{src_group}_to_{dst_group}"


def _build_directed_adjacency(
    arch: dict,
    trust_map: dict[str, dict],
    ont_ecu_idx: dict[str, list[dict]],
) -> dict[str, list[dict]]:
    adj: dict[str, list[dict]] = defaultdict(list)
    seen_direct: set[str] = set()

    for flow in arch.get("data_flows", []):
        src = flow["source"]
        dst = flow["destination"]
        proto = flow.get("protocol", {"transport": "CAN", "application": "NONE"})
        direction = flow.get("direction", "oneway")
        edge_key = f"{src}→{dst}"
        if edge_key not in seen_direct:
            seen_direct.add(edge_key)
            adj[src].append({
                "dst": dst,
                "protocol": proto,
                "flow_id": flow["id"],
                "direction": direction,
                "edge_type": "direct_flow",
                "plausibility_flag": "direct_data_flow",
            })
        if direction == "bidirectional":
            rev_key = f"{dst}→{src}"
            if rev_key not in seen_direct:
                seen_direct.add(rev_key)
                adj[dst].append({
                    "dst": src,
                    "protocol": proto,
                    "flow_id": flow["id"] + "_REV",
                    "direction": "oneway",
                    "edge_type": "direct_flow",
                    "plausibility_flag": "direct_data_flow_reverse",
                })

    for bus in arch.get("communication_buses", []):
        bus_ecus = bus.get("connected_ecus", [])
        proto = bus.get("protocol", {"transport": "CAN", "application": "NONE"})
        for src in bus_ecus:
            for dst in bus_ecus:
                if src == dst:
                    continue
                edge_key = f"{src}→{dst}"
                if edge_key in seen_direct:
                    continue
                plausible, flag = _bus_edge_is_plausible(src, dst, ont_ecu_idx)
                edge_type = "bus_injection" if plausible else "bus_lateral"
                adj[src].append({
                    "dst": dst,
                    "protocol": proto,
                    "flow_id": f"{bus['id']}_{src}_{dst}",
                    "direction": "oneway",
                    "edge_type": edge_type,
                    "plausibility_flag": flag,
                })

    return adj


_SURFACE_ENTRY_PRIORITY: dict[str, int] = {
    "wireless":   1,   # BLE, Wi-Fi, RF — highest attacker priority
    "remote":     1,   # VEHICLE_NETWORK (telematics-exposed)
    "local":      2,   # short-range wireless
    "physical":   3,   # OBD / diagnostic Ethernet (requires physical presence)
}


def _identify_legitimate_entry_points(
    arch: dict,
    trust_map: dict[str, dict],
    target_ecus: list[str],
) -> list[str]:
    """
    Return exposed external interfaces sorted by attacker surface priority.

    Priority order:
        1. wireless / remote  (BLE, VEHICLE_NETWORK)
        2. local              (short-range)
        3. physical/diagnostic (OBD, DIAG_ETH)

    Sorting ensures that when the path generator caps at N entry points the
    most realistic remote/wireless entries are tried first, preventing
    diagnostic paths from crowding out all other surface types.
    """
    target_set = set(target_ecus)
    candidates: list[tuple[int, str]] = []  # (priority, iface_id)

    for iface in arch.get("external_interfaces", []):
        iface_id = iface["id"]
        if iface_id in target_set:
            continue
        trust_info = trust_map.get(iface_id, {})
        trust_level = trust_info.get("trust_level", 999)
        if not (trust_level <= 1 or iface.get("exposed")):
            continue

        attacker_profile = iface.get("attacker_profile", "physical")
        priority = _SURFACE_ENTRY_PRIORITY.get(attacker_profile, 3)
        candidates.append((priority, iface_id))

    # Sort by priority (ascending = highest priority first)
    candidates.sort(key=lambda x: x[0])
    entries = [iface_id for _, iface_id in candidates]

    # Also include very-low-trust ECUs as fallback entries
    ecu_ids = {e["id"] for e in arch.get("ecus", [])}
    for flow in arch.get("data_flows", []):
        src = flow["source"]
        if src in ecu_ids:
            trust_level = trust_map.get(src, {}).get("trust_level", 999)
            if trust_level <= 1 and src not in target_set and src not in entries:
                entries.append(src)

    return entries


def _build_edge_obj(
    node: str,
    edge_info: dict,
    trust_map: dict[str, dict],
) -> GraphEdge:
    dst = edge_info["dst"]
    edge_key = f"{node}→{dst}"
    src_trust = trust_map.get(node, {}).get("trust_level", 0)
    dst_trust = trust_map.get(dst, {}).get("trust_level", 0)
    delta = dst_trust - src_trust
    src_zone = trust_map.get(node, {}).get("trust_zone", "?")
    dst_zone = trust_map.get(dst, {}).get("trust_zone", "?")

    if src_zone == dst_zone:
        trust_dir = "SAME_ZONE"
    elif delta < 0:
        trust_dir = "HIGH_TO_LOW"
    else:
        trust_dir = "LOW_TO_HIGH"

    proto = edge_info["protocol"]
    surface = _protocol_to_surface(proto)
    proto_str = f"{proto.get('transport', '?')}/{proto.get('application', 'NONE')}"

    return GraphEdge(
        edge_id=f"EDGE-{edge_key.replace('→', '-')}",
        src=node,
        dst=dst,
        protocol=proto_str,
        direction=edge_info.get("direction", "oneway"),
        trust_src=src_trust,
        trust_dst=dst_trust,
        trust_delta=delta,
        trust_direction=trust_dir,
        attack_surface=surface,
        flow_id=edge_info.get("flow_id", ""),
        edge_type=edge_info.get("edge_type", "direct_flow"),
        plausibility_flag=edge_info.get("plausibility_flag", ""),
    )


def _bfs_threat_scoped(
    entry_nodes: list[str],
    target_nodes: list[str],
    adj: dict[str, list[dict]],
    trust_map: dict[str, dict],
    max_depth: int = 8,
) -> tuple[list[str], list[GraphEdge], list[TrustBoundaryCrossing]]:
    """
    Path-constrained subgraph extraction.

    Only nodes and edges that lie on at least one plausible path from an
    entry node to a target node are included in the subgraph.  This makes
    every threat's graph topology threat-specific rather than global.

    Algorithm:
      1. Forward BFS  → forward_reachable[node] = set of targets reachable from node
      2. Backward BFS → backward_reachable[node] = set of entries that can reach node
      3. Keep edge (u→v) iff:
           - u is forward-reachable from some entry
           - v can reach some target
         i.e. the edge sits on a path from entry → target
    """
    target_set = set(target_nodes)
    entry_set = set(entry_nodes)

    # --- Step 1: forward reachability from each entry, tracking which targets are reached ---
    # forward_reach: node → set of targets reachable from that node
    forward_reach: dict[str, set[str]] = defaultdict(set)

    def _forward_bfs_from(start: str) -> None:
        q: deque[tuple[str, int]] = deque([(start, 0)])
        visited_fwd: set[str] = {start}
        while q:
            node, depth = q.popleft()
            if depth >= max_depth:
                continue
            if node in target_set:
                # propagate target upward through the call chain by marking start
                forward_reach[start].add(node)
            for ei in adj.get(node, []):
                dst = ei["dst"]
                if dst not in visited_fwd:
                    visited_fwd.add(dst)
                    q.append((dst, depth + 1))
                    if dst in target_set:
                        forward_reach[start].add(dst)

    for entry in entry_nodes:
        _forward_bfs_from(entry)

    # Only keep entries that can actually reach at least one target
    viable_entries = [e for e in entry_nodes if forward_reach[e]]
    if not viable_entries:
        viable_entries = entry_nodes  # fallback — keep all entries

    # --- Step 2: forward reachability SET from viable entries (which nodes are on-path) ---
    # on_path_from_entry[node] = True if node is forward-reachable from a viable entry
    on_path_from_entry: set[str] = set(viable_entries)
    q2: deque[tuple[str, int]] = deque((e, 0) for e in viable_entries)
    while q2:
        node, depth = q2.popleft()
        if depth >= max_depth:
            continue
        for ei in adj.get(node, []):
            dst = ei["dst"]
            if dst not in on_path_from_entry:
                on_path_from_entry.add(dst)
                q2.append((dst, depth + 1))

    # --- Step 3: backward reachability from targets ---
    # backward_reach[node] = True if at least one target is reachable from node
    reverse_adj: dict[str, list[dict]] = defaultdict(list)
    for src_node, edges in adj.items():
        for ei in edges:
            reverse_adj[ei["dst"]].append({**ei, "dst": src_node})

    can_reach_target: set[str] = set(target_nodes)
    bq: deque[str] = deque(target_nodes)
    while bq:
        node = bq.popleft()
        for ei in reverse_adj.get(node, []):
            pred = ei["dst"]
            if pred not in can_reach_target:
                can_reach_target.add(pred)
                bq.append(pred)

    # --- Step 4: build subgraph — only edges where src ∈ on_path_from_entry AND dst ∈ can_reach_target ---
    all_edges: list[GraphEdge] = []
    crossings: list[TrustBoundaryCrossing] = []
    seen_edges: set[str] = set()
    included_nodes: set[str] = set(viable_entries) | set(target_nodes)

    for node in list(on_path_from_entry):
        for ei in adj.get(node, []):
            dst = ei["dst"]
            # Edge must lie on a valid path: node reachable from entry AND dst can reach target
            if node not in on_path_from_entry:
                continue
            if dst not in can_reach_target:
                continue
            edge_key = f"{node}→{dst}"
            if edge_key in seen_edges:
                continue
            seen_edges.add(edge_key)

            edge = _build_edge_obj(node, ei, trust_map)
            all_edges.append(edge)
            included_nodes.add(node)
            included_nodes.add(dst)

            if edge.trust_direction != "SAME_ZONE":
                crossings.append(TrustBoundaryCrossing(
                    src_ecu=node,
                    dst_ecu=dst,
                    src_trust=edge.trust_src,
                    dst_trust=edge.trust_dst,
                    direction=edge.trust_direction,
                ))

    return list(included_nodes), all_edges, crossings


def _build_physical_templates(
    target_ecus: list[str],
    arch: dict,
    ont_ecu_idx: dict[str, list[dict]],
) -> list[PhysicalAttackTemplate]:
    templates: list[PhysicalAttackTemplate] = []

    iface_map: dict[str, dict] = {i["id"]: i for i in arch.get("external_interfaces", [])}
    ecu_inbound_ifaces: dict[str, list[str]] = defaultdict(list)
    for flow in arch.get("data_flows", []):
        if flow["source"] in iface_map and flow["destination"] not in iface_map:
            ecu_inbound_ifaces[flow["destination"]].append(flow["source"])

    ecu_ids_set = {e["id"] for e in arch.get("ecus", [])}

    for ecu in target_ecus:
        if ecu not in ecu_ids_set:
            continue

        inbound = ecu_inbound_ifaces.get(ecu, [])
        has_network_inbound = any(
            iface_map.get(i, {}).get("attacker_profile") in {"remote", "local"}
            for i in inbound
        )

        if not inbound or (inbound and not has_network_inbound):
            ecu_lower = ecu.lower()
            capec_ids: list[str] = []
            for kw, cids in _PHYSICAL_SENSOR_CAPEC.items():
                if kw in ecu_lower:
                    capec_ids = cids
                    break
            if not capec_ids:
                capec_ids = _PHYSICAL_SENSOR_CAPEC["sensor"]

            templates.append(PhysicalAttackTemplate(
                template_id=f"PHYS-{ecu}",
                target_node=ecu,
                attack_type="physical_signal_manipulation",
                capec_ids=capec_ids,
                description=(
                    f"Attacker physically positions a signal injection or spoofing device "
                    f"to manipulate inputs to {ecu}. No network topology edge required; "
                    f"this is a single-step physical-layer attack."
                ),
            ))

    return templates


def build_attack_semantic_graph(
    threat_scenario: dict,
    ontology_path: str | Path,
    architecture_path: str | Path,
) -> AttackSemanticGraph:
    with open(ontology_path) as f:
        ontology = json.load(f)
    with open(architecture_path) as f:
        arch = json.load(f)

    nodes: list[dict] = ontology["nodes"]
    trust_map = _build_trust_zone_map(arch)
    ont_ecu_idx = _build_ontology_ecu_index(nodes)
    adj = _build_directed_adjacency(arch, trust_map, ont_ecu_idx)

    target_ecus: list[str] = threat_scenario.get("mapped_ecus", [])
    target_set = set(target_ecus)

    entry_nodes = _identify_legitimate_entry_points(arch, trust_map, target_ecus)

    entry_nodes = [e for e in entry_nodes if e not in target_set]

    physical_templates = _build_physical_templates(target_ecus, arch, ont_ecu_idx)
    is_physical_sensor_threat = len(physical_templates) > 0 and len(entry_nodes) == 0

    reachable, edges, crossings = _bfs_threat_scoped(
        entry_nodes, target_ecus, adj, trust_map, max_depth=8
    )

    # reachable now contains ONLY nodes on valid entry→target paths
    reachable_set = set(reachable) | set(target_ecus)

    arch_ecu_ids = {e["id"] for e in arch.get("ecus", [])}
    arch_iface_ids = {i["id"] for i in arch.get("external_interfaces", [])}

    graph_nodes: list[GraphNode] = []
    seen_gnodes: set[str] = set()

    for nid in reachable_set:
        if nid in seen_gnodes:
            continue
        seen_gnodes.add(nid)

        tm = trust_map.get(nid, {})
        mapped_onts = ont_ecu_idx.get(nid, [])
        ont_ids = [n["ontology_id"] for n in mapped_onts]
        ont_domains = list({n["functional_domain"] for n in mapped_onts})
        ont_surfaces: list[str] = []
        for n in mapped_onts:
            ont_surfaces.extend(n.get("attack_surface_classes", []))

        if nid in arch_ecu_ids:
            ntype = "ecu"
        elif nid in arch_iface_ids:
            ntype = "interface"
        else:
            ntype = "external"

        node_is_physical_only = nid in target_set and any(
            t.target_node == nid for t in physical_templates
        )

        gn = GraphNode(
            node_id=nid,
            node_type=ntype,
            trust_level=tm.get("trust_level", 0),
            trust_zone=tm.get("trust_zone", "UNKNOWN"),
            attack_surfaces=list(set(ont_surfaces)),
            is_entry_point=nid in entry_nodes,
            is_target=nid in target_set,
            is_physical_only=node_is_physical_only,
            ontology_ids=ont_ids,
            functional_domains=ont_domains,
        )
        graph_nodes.append(gn)

    all_surfaces = sorted({e.attack_surface for e in edges})
    if physical_templates:
        if "physical_access" not in all_surfaces:
            all_surfaces.append("physical_access")

    traversal_nodes = [
        n for n in reachable
        if n not in entry_nodes and n not in target_set
    ]

    oid = threat_scenario["source_ontology_id"]
    target_asset = threat_scenario["target_asset_name"]

    return AttackSemanticGraph(
        threat_id=threat_scenario["threat_id"],
        target_asset=target_asset,
        compromised_property=threat_scenario["compromised_property"],
        source_ontology_id=oid,
        entry_nodes=entry_nodes,
        target_nodes=target_ecus,
        traversal_nodes=traversal_nodes,
        graph_nodes=graph_nodes,
        graph_edges=edges,
        trust_boundary_crossings=crossings,
        physical_attack_templates=physical_templates,
        reachable_attack_surfaces=all_surfaces,
        topology_source="ontology_topology_v2.0 + architecture.json",
        is_physical_sensor_threat=is_physical_sensor_threat,
    )


def graph_to_dict(graph: AttackSemanticGraph) -> dict:
    return asdict(graph)


if __name__ == "__main__":
    import sys

    ts_path = sys.argv[1] if len(sys.argv) > 1 else "threat_scenarios.json"
    onto_path = sys.argv[2] if len(sys.argv) > 2 else "functional_automotive_ontology.json"
    arch_path = sys.argv[3] if len(sys.argv) > 3 else "architecture.json"
    out_path = sys.argv[4] if len(sys.argv) > 4 else "semantic_graphs.json"

    with open(ts_path) as f:
        threat_scenarios = json.load(f)

    graphs = []
    for ts in threat_scenarios:
        g = build_attack_semantic_graph(ts, onto_path, arch_path)
        graphs.append(graph_to_dict(g))

    with open(out_path, "w") as f:
        json.dump(graphs, f, indent=2)

    print(f"[attack_semantic_graph] Built {len(graphs)} semantic graphs → {out_path}")

    if graphs:
        edge_counts = [len(g["graph_edges"]) for g in graphs]
        entry_counts = [len(g["entry_nodes"]) for g in graphs]
        physical = sum(1 for g in graphs if g["is_physical_sensor_threat"])
        identical = len(set(
            tuple(sorted(e["edge_id"] for e in g["graph_edges"])) for g in graphs
        ))
        print(f"  Distinct graph topologies: {identical}")
        print(f"  Physical-only threats: {physical}")
        print(f"  Avg edges per graph: {sum(edge_counts)/len(edge_counts):.1f}")
        print(f"  Avg entry nodes: {sum(entry_counts)/len(entry_counts):.1f}")