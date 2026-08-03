import json
import textwrap
import math
from pathlib import Path
from config import OUTPUT_DIR, TRUST_COLORS, STRIDE_COLORS, SURFACE_COLORS

def _svg_header(w, h):
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" '
            f'width="{w}" height="{h}" style="background:#060a0f;font-family:\'Share Tech Mono\',monospace;">')

def _svg_footer():
    return "</svg>"

def _hex_to_rgba(h, a=0.15):
    h = h.lstrip("#")
    r,g,b = int(h[0:2],16), int(h[2:4],16), int(h[4:6],16)
    return f"rgba({r},{g},{b},{a})"

def architecture_svg(arch: dict, out_path: Path) -> Path:
    trust_zones = {tz["id"]: tz for tz in arch["trust_zones"]}
    ecus = arch["ecus"]
    interfaces = arch["external_interfaces"]
    buses = arch["communication_buses"]

    W, H = 1200, 800
    lines = [_svg_header(W, H)]
    lines.append('<defs>')
    lines.append('<marker id="arr" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">'
                 '<path d="M0,0 L0,6 L8,3 z" fill="#00d4ff" opacity="0.6"/></marker>')
    for tz_id, color in [("TZ-ADAS","#39ff14"),("TZ-BRAKE","#ff3b6b"),
                          ("TZ-STEERING","#ff9500"),("TZ-POWERTRAIN","#ffcc00"),
                          ("TZ-SRS","#bf5fff"),("TZ-BODY","#00d4ff"),
                          ("TZ-SENSOR","#ff6b35"),("TZ-VNET","#5a7a99")]:
        r,g,b = int(color[1:3],16),int(color[3:5],16),int(color[5:7],16)
        lines.append(f'<linearGradient id="g{tz_id}" x1="0" y1="0" x2="1" y2="1">'
                     f'<stop offset="0%" stop-color="rgba({r},{g},{b},0.18)"/>'
                     f'<stop offset="100%" stop-color="rgba({r},{g},{b},0.06)"/></linearGradient>')
    lines.append('</defs>')

    tz_layout = {
        "TZ-ADAS":      (60,  60,  220, 180, "#39ff14"),
        "TZ-SENSOR":    (60,  280, 220, 160, "#ff6b35"),
        "TZ-BRAKE":     (320, 60,  200, 160, "#ff3b6b"),
        "TZ-STEERING":  (320, 260, 200, 160, "#ff9500"),
        "TZ-POWERTRAIN":(560, 60,  220, 360, "#ffcc00"),
        "TZ-SRS":       (560, 460, 220, 200, "#bf5fff"),
        "TZ-BODY":      (820, 60,  220, 220, "#00d4ff"),
        "TZ-VNET":      (820, 320, 220, 200, "#5a7a99"),
    }

    for tz_id,(x,y,w,h,color) in tz_layout.items():
        tl = trust_zones.get(tz_id, {}).get("trust_level", 1)
        lines.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="4" '
                     f'fill="url(#g{tz_id})" stroke="{color}" stroke-width="1.5" stroke-opacity="0.5"/>')
        lines.append(f'<text x="{x+8}" y="{y+16}" font-size="9" fill="{color}" opacity="0.8" '
                     f'letter-spacing="1">{tz_id} · TL{tl}</text>')

    ecu_positions = {}
    tz_ecu_map = {}
    for ecu in ecus:
        tz_ecu_map.setdefault(ecu["trust_zone"], []).append(ecu["id"])

    for tz_id,(x,y,w,h,color) in tz_layout.items():
        ecu_list = tz_ecu_map.get(tz_id, [])
        for i, eid in enumerate(ecu_list):
            ex = x + 20 + (i % 2) * 90
            ey = y + 30 + (i // 2) * 55
            ecu_positions[eid] = (ex + 35, ey + 14)
            lines.append(f'<rect x="{ex}" y="{ey}" width="70" height="28" rx="3" '
                         f'fill="#0c1218" stroke="{color}" stroke-width="1"/>')
            label = eid[:10] + ".." if len(eid) > 12 else eid
            lines.append(f'<text x="{ex+35}" y="{ey+18}" font-size="7.5" fill="{color}" '
                         f'text-anchor="middle" font-weight="bold">{label}</text>')

    iface_positions = {
        "VEHICLE_NETWORK": (1080, 150),
        "OBD_INTERFACE":   (1080, 250),
        "BLE_INTERFACES":  (1080, 350),
        "DIAG_ETHERNET":   (1080, 450),
        "ADAS_SENSORS":    (160, 480),
        "SPEED_SENSORS":   (160, 530),
        "IMPACT_SENSORS":  (600, 680),
        "PRESSURE_SENSORS":(680, 680),
        "ACCEL_SENSOR":    (160, 580),
        "RESTRAINT_ACTUATORS":(680, 700),
        "HV_DISCONNECT":   (650, 160),
    }

    for iid, (ix, iy) in iface_positions.items():
        iface = next((i for i in interfaces if i["id"] == iid), None)
        color = "#ff3b6b" if (iface and iface.get("exposed")) else "#5a7a99"
        lines.append(f'<polygon points="{ix},{iy-10} {ix+12},{iy+10} {ix-12},{iy+10}" '
                     f'fill="none" stroke="{color}" stroke-width="1.5"/>')
        lines.append(f'<text x="{ix}" y="{iy+22}" font-size="7" fill="{color}" '
                     f'text-anchor="middle">{iid[:12]}</text>')

    drawn_edges = set()
    for bus in buses:
        color = "#ff9500" if "CHASSIS" in bus["id"] else ("#00d4ff" if "VEHICLE" in bus["id"] else "#bf5fff")
        connected = bus["connected_ecus"]
        for i in range(len(connected)-1):
            e1 = connected[i]; e2 = connected[i+1]
            if e1 in ecu_positions and e2 in ecu_positions:
                key = tuple(sorted([e1,e2]))
                if key not in drawn_edges:
                    drawn_edges.add(key)
                    x1,y1 = ecu_positions[e1]; x2,y2 = ecu_positions[e2]
                    lines.append(f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" '
                                 f'stroke="{color}" stroke-width="1" stroke-opacity="0.5" '
                                 f'stroke-dasharray="4,3" marker-end="url(#arr)"/>')

    for bus in buses:
        color = "#ff9500" if "CHASSIS" in bus["id"] else ("#00d4ff" if "VEHICLE" in bus["id"] else "#bf5fff")
        label = bus["id"]
        if bus["connected_ecus"]:
            cx_list = [ecu_positions[e][0] for e in bus["connected_ecus"] if e in ecu_positions]
            cy_list = [ecu_positions[e][1] for e in bus["connected_ecus"] if e in ecu_positions]
            if cx_list:
                mx = sum(cx_list)//len(cx_list)
                my = sum(cy_list)//len(cy_list)
                lines.append(f'<rect x="{mx-30}" y="{my-8}" width="60" height="14" rx="2" '
                             f'fill="#060a0f" stroke="{color}" stroke-width="0.5" opacity="0.8"/>')
                lines.append(f'<text x="{mx}" y="{my+4}" font-size="7" fill="{color}" '
                             f'text-anchor="middle">{label}</text>')

    exposed = [i for i in interfaces if i.get("exposed")]
    lines.append(f'<rect x="1040" y="120" width="150" height="20" rx="2" fill="rgba(255,59,107,0.1)" stroke="#ff3b6b" stroke-width="0.5"/>')
    lines.append(f'<text x="1115" y="133" font-size="8" fill="#ff3b6b" text-anchor="middle" letter-spacing="1">ATTACK SURFACES</text>')
    for i,(iid,(ix,iy)) in enumerate(iface_positions.items()):
        iface = next((fi for fi in interfaces if fi["id"] == iid), None)
        if iface and iface.get("exposed"):
            lines.append(f'<line x1="1040" y1="{150+i*8}" x2="{ix}" y2="{iy}" '
                         f'stroke="#ff3b6b" stroke-width="0.5" stroke-opacity="0.3" stroke-dasharray="2,4"/>')

    legend_x = 60
    lines.append(f'<text x="{legend_x}" y="740" font-size="8" fill="#5a7a99" letter-spacing="1">TRUST ZONES ▸</text>')
    for i,(tz,(x,y,w,h,color)) in enumerate(tz_layout.items()):
        lx = legend_x + 100 + i*120
        lines.append(f'<rect x="{lx}" y="730" width="8" height="8" fill="{color}" opacity="0.6"/>')
        lines.append(f'<text x="{lx+12}" y="739" font-size="7.5" fill="{color}">{tz}</text>')

    lines.append(f'<text x="600" y="778" font-size="9" fill="#5a7a99" text-anchor="middle" letter-spacing="2">'
                 f'ITEM: DRIVER PHYSICAL SAFETY DURING AUTOMATED DRIVING · ISO/SAE 21434 ARCHITECTURE DFD'
                 f'</text>')

    lines.append(_svg_footer())
    out_path.write_text("\n".join(lines))
    return out_path


def attack_tree_svg(tree: dict, out_path: Path, max_depth: int = 4) -> Path:
    W, H = 1000, 600

    def collect_nodes(node, depth=0, parent_x=None, nodes=None, edges=None, x_counter=None):
        if nodes is None: nodes=[]; edges=[]; x_counter=[0]
        if depth > max_depth: return nodes, edges
        nid = node["node_id"]
        node_type = node.get("node_type","")
        stride = node.get("stride_label")
        capec = node.get("capec_id")
        color = ("#00d4ff" if node_type=="ROOT" else
                 "#ff9500" if node_type=="OR" else
                 "#bf5fff" if node_type=="AND" else
                 STRIDE_COLORS.get(stride,"#5a7a99") if stride else "#5a7a99")
        x = x_counter[0] * 110 + 60
        y = depth * 110 + 60
        x_counter[0] += 1
        nodes.append({"id":nid,"x":x,"y":y,"type":node_type,"color":color,
                      "label":node.get("label","")[:40],"stride":stride,"capec":capec})
        if parent_x is not None:
            edges.append({"x1":parent_x[0],"y1":parent_x[1],"x2":x,"y2":y,"color":color})
        for child in node.get("children",[]):
            collect_nodes(child, depth+1, (x,y), nodes, edges, x_counter)
        return nodes, edges

    nodes, edges = collect_nodes(tree["root"])
    max_x = max((n["x"] for n in nodes), default=W) + 100
    max_y = max((n["y"] for n in nodes), default=H) + 80
    W2, H2 = max(W, max_x), max(H, max_y)

    lines = [_svg_header(W2, H2)]
    lines.append('<defs><marker id="ta" markerWidth="6" markerHeight="6" refX="5" refY="3" orient="auto">'
                 '<path d="M0,0 L0,6 L6,3 z" fill="#5a7a99"/></marker></defs>')

    lines.append(f'<text x="{W2//2}" y="22" font-size="10" fill="#00d4ff" text-anchor="middle" '
                 f'letter-spacing="1">{tree["threat_title"][:80]}</text>')
    lines.append(f'<text x="{W2//2}" y="38" font-size="8" fill="#5a7a99" text-anchor="middle">'
                 f'Paths: {tree["path_count"]} · Leaves: {tree["leaf_count"]} · Max depth: {tree["max_depth"]}'
                 f'</text>')

    for e in edges:
        lines.append(f'<line x1="{e["x1"]}" y1="{e["y1"]}" x2="{e["x2"]}" y2="{e["y2"]}" '
                     f'stroke="{e["color"]}" stroke-width="1" stroke-opacity="0.5" '
                     f'marker-end="url(#ta)"/>')

    for n in nodes:
        r = 22 if n["type"] in ("ROOT","OR","AND") else 16
        lines.append(f'<circle cx="{n["x"]}" cy="{n["y"]}" r="{r}" '
                     f'fill="#0c1218" stroke="{n["color"]}" stroke-width="1.5"/>')
        lines.append(f'<text x="{n["x"]}" y="{n["y"]-3}" font-size="8" fill="{n["color"]}" '
                     f'text-anchor="middle" font-weight="bold">{n["type"]}</text>')
        if n["stride"]:
            lines.append(f'<text x="{n["x"]}" y="{n["y"]+10}" font-size="6.5" fill="{n["color"]}" '
                         f'text-anchor="middle">{n["stride"][:1]}</text>')
        label = n["label"][:28] + ".." if len(n["label"])>30 else n["label"]
        lines.append(f'<text x="{n["x"]}" y="{n["y"]+r+12}" font-size="7" fill="#5a7a99" '
                     f'text-anchor="middle">{label}</text>')

    lines.append(_svg_footer())
    out_path.write_text("\n".join(lines))
    return out_path


def semantic_graph_svg(sg: dict, out_path: Path) -> Path:
    raw_nodes = sg.get("graph_nodes", [])
    if raw_nodes and isinstance(raw_nodes[0], dict):
        all_nodes = [n["node_id"] for n in raw_nodes]
        entry_set = {n["node_id"] for n in raw_nodes if n.get("is_entry_point")}
        target_set = {n["node_id"] for n in raw_nodes if n.get("is_target")}
    else:
        all_nodes = list(set(sg.get("entry_nodes",[]) +
                             sg.get("traversal_nodes",[]) + sg.get("target_nodes",[])))
        entry_set  = set(sg.get("entry_nodes",[]))
        target_set = set(sg.get("target_nodes",[]))
    traversal_set = set(all_nodes) - entry_set - target_set

    n = len(all_nodes)
    W, H = 900, 600
    cx, cy = W//2, H//2 - 30

    node_pos = {}
    for i, nid in enumerate(all_nodes):
        angle = 2 * math.pi * i / n
        r = 220
        if nid in entry_set: r = 260
        if nid in target_set: r = 80
        x = cx + r * math.cos(angle)
        y = cy + r * math.sin(angle)
        node_pos[nid] = (x, y)

    lines = [_svg_header(W, H)]
    lines.append('<defs><marker id="sa" markerWidth="6" markerHeight="6" refX="5" refY="3" orient="auto">'
                 '<path d="M0,0 L0,6 L6,3 z" fill="#00d4ff" opacity="0.6"/></marker></defs>')

    tc = sg.get("trust_boundary_crossings",[])
    for edge in sg.get("graph_edges", [])[:60]:
        src = edge.get("src") or edge.get("source")
        dst = edge.get("dst") or edge.get("target")
        if src and dst and src in node_pos and dst in node_pos:
            x1,y1 = node_pos[src]; x2,y2 = node_pos[dst]
            lines.append(f'<line x1="{x1:.0f}" y1="{y1:.0f}" x2="{x2:.0f}" y2="{y2:.0f}" '
                         f'stroke="#00d4ff" stroke-width="0.8" stroke-opacity="0.25" '
                         f'marker-end="url(#sa)"/>')

    for nid, (x, y) in node_pos.items():
        if nid in target_set:
            color="#ff3b6b"; r=18; fw="bold"
        elif nid in entry_set:
            color="#39ff14"; r=16; fw="bold"
        else:
            color="#ff9500"; r=12; fw="normal"
        lines.append(f'<circle cx="{x:.0f}" cy="{y:.0f}" r="{r}" '
                     f'fill="#0c1218" stroke="{color}" stroke-width="1.5"/>')
        label = nid[:12] + ".." if len(nid)>14 else nid
        lines.append(f'<text x="{x:.0f}" y="{y+r+12:.0f}" font-size="7.5" fill="{color}" '
                     f'text-anchor="middle" font-weight="{fw}">{label}</text>')

    lines.append(f'<text x="{cx}" y="{cy}" font-size="9" fill="#00d4ff" text-anchor="middle" '
                 f'opacity="0.4">{sg["target_asset"]}</text>')
    lines.append(f'<text x="{cx}" y="{cy+14}" font-size="7.5" fill="#5a7a99" text-anchor="middle">'
                 f'{sg["compromised_property"]}</text>')

    for label, color, y_off in [("● Entry","#39ff14",H-50),("● Traversal","#ff9500",H-50),("● Target","#ff3b6b",H-50)]:
        pass
    lines.append(f'<text x="20" y="{H-40}" font-size="8" fill="#39ff14">● Entry nodes</text>')
    lines.append(f'<text x="130" y="{H-40}" font-size="8" fill="#ff9500">● Traversal</text>')
    lines.append(f'<text x="230" y="{H-40}" font-size="8" fill="#ff3b6b">● Target ECU</text>')
    lines.append(f'<text x="{W//2}" y="{H-20}" font-size="8" fill="#5a7a99" text-anchor="middle">'
                 f'Semantic Graph · {sg["threat_id"]} · {sg["target_asset"]}</text>')

    lines.append(_svg_footer())
    out_path.write_text("\n".join(lines))
    return out_path
