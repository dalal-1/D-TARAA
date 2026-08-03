import json, uuid, argparse, sys, os, re
from collections import defaultdict
SHAPE_W      = 150
SHAPE_H      = 75
MIN_DIM      = 60
MIN_COORD    = 80

ECU_COLS_MAX = 3
ECU_GAP_X    = 240
ECU_GAP_Y    = 170

ZONE_COLS    = 2
ZONE_GAP_X   = 240
ZONE_GAP_Y   = 240
BORDER_PAD   = 90

X_START      = 120
Y_START      = 120

EXT_GAP_Y      = 130
EXT_COL_GAP_X  = 260
EXT_PAD_X      = 300
MAX_EXT_ROWS   = 12
EXT_BND_PAD    = 60

LANE_OFFSET     = 55
BUNDLE_SPREAD   = 2
CORRIDOR_OUTER  = 200


def _cx(v):  return max(MIN_COORD, int(round(v)))
def _cy(v):  return max(MIN_COORD, int(round(v)))
def _cw(v):  return max(MIN_DIM,   int(round(v)))
def _ch(v):  return max(MIN_DIM,   int(round(v)))
def _cf(v):  return max(MIN_COORD, int(round(v)))




class GuidRegistry:
    def __init__(self):
        self._seen: dict = {}

    def alloc(self, seed: str) -> str:
        g = str(uuid.uuid5(uuid.NAMESPACE_DNS, seed))
        if g in self._seen and self._seen[g] != seed:
            raise ValueError(f"GUID collision: '{seed}' vs '{self._seen[g]}' → {g}")
        self._seen[g] = seed
        return g

X_ABS = 'xmlns="http://schemas.datacontract.org/2004/07/ThreatModeling.Model.Abstracts"'
X_KB  = 'xmlns:b="http://schemas.datacontract.org/2004/07/ThreatModeling.KnowledgeBase"'
X_XSD = 'xmlns:c="http://www.w3.org/2001/XMLSchema"'
X_ARR = 'xmlns:a="http://schemas.microsoft.com/2003/10/Serialization/Arrays"'

def _xe(s):
    """Escape XML special characters in a string."""
    return (str(s)
            .replace('&', '&amp;')
            .replace('<', '&lt;')
            .replace('>', '&gt;')
            .replace('"', '&quot;')
            .replace("'", '&apos;'))

def ph(dn):
    return (f'<a:anyType i:type="b:HeaderDisplayAttribute" {X_KB}>'
            f'<b:DisplayName>{_xe(dn)}</b:DisplayName>'
            f'<b:Name/><b:Value i:nil="true"/></a:anyType>')

def ps(dn, name, value=''):
    nm = f'<b:Name>{name}</b:Name>' if name else '<b:Name/>'
    return (f'<a:anyType i:type="b:StringDisplayAttribute" {X_KB}>'
            f'<b:DisplayName>{_xe(dn)}</b:DisplayName>{nm}'
            f'<b:Value i:type="c:string" {X_XSD}>{_xe(value)}</b:Value></a:anyType>')

def pb(dn, name, value=False):
    return (f'<a:anyType i:type="b:BooleanDisplayAttribute" {X_KB}>'
            f'<b:DisplayName>{_xe(dn)}</b:DisplayName><b:Name>{_xe(name)}</b:Name>'
            f'<b:Value i:type="c:boolean" {X_XSD}>{str(value).lower()}</b:Value>'
            f'</a:anyType>')

def pl(dn, name, options, sel=0):
    opts = ''.join(f'<a:string>{o}</a:string>' for o in options)
    return (f'<a:anyType i:type="b:ListDisplayAttribute" {X_KB}>'
            f'<b:DisplayName>{_xe(dn)}</b:DisplayName><b:Name>{_xe(name)}</b:Name>'
            f'<b:Value i:type="a:ArrayOfstring">{opts}</b:Value>'
            f'<b:SelectedIndex>{sel}</b:SelectedIndex></a:anyType>')

def _pp(name):
    return ''.join([
        ph('Generic Process'), ps('Name', '', name),
        pb('Out Of Scope', ''),
        ps('Reason For Out Of Scope', ''),
        ph('Configurable Attributes'),
        pl('Code Type', 'codeType', ['Not Selected','Managed','Unmanaged']),
        pl('Running As', 'runningAs', ['Not Selected','Kernel','System',
            'Network Service','Local Service','Administrator',
            'Standard User With Elevation','Standard User Without Elevation',
            'Windows Store App']),
        pl('Isolation Level', 'Isolation', ['Not Selected','AppContainer',
            'Low Integrity Level',
            'Microsoft Office Isolated Conversion Environment (MOICE)','Sandbox']),
        pl('Accepts Input From', 'acceptsInputFrom', ['Not Selected',
            'Any Remote User or Entity','Kernel, System, or Local Admin',
            'Local or Network Service','Local Standard User With Elevation',
            'Local Standard User Without Elevation',
            'Windows Store Apps or App Container Processes','Nothing','Other']),
        pl('Implements or Uses an Authentication Mechanism',
            'implementsAuthentication', ['Not Selected','Yes','No'], 0),
        pl('Uses a Session-based Authentication Mechanism',
            'sessionBasedAuth', ['Not Selected','Yes','No'], 0),
    ])

def _pei(name):
    return ''.join([
        ph('External Interactor'), ps('Name', '', name),
        pb('Out Of Scope', ''),
        ps('Reason For Out Of Scope', ''),
    ])

def _pbb(name):
    return ''.join([
        ph('Trust Boundary'), ps('Name', '', name),
        pb('Out Of Scope', ''),
        ps('Reason For Out Of Scope', ''),
    ])

def _pdf(name):
    return ''.join([
        ph('Data Flow'), ps('Name', '', name),
        pb('Out Of Scope', '71f3d9aa-b8ef-4e54-8126-607a1d903103'),
        ps('Reason For Out Of Scope', '752473b6-52d4-4776-9a24-202153f7d579'),
        ph('Configurable Attributes'),
        pl('Protocol', 'protocol',
            ['Not Selected','HTTP','HTTPS','TCP','UDP','IPC','Other']),
    ])

def _tail(type_id, h, x, y, w):
    """All coordinates clamped at the single XML-emission point."""
    return (f'<TypeId {X_ABS}>{type_id}</TypeId>'
            f'<Height {X_ABS}>{_ch(h)}</Height>'
            f'<Left {X_ABS}>{_cx(x)}</Left>'
            f'<Top {X_ABS}>{_cy(y)}</Top>'
            f'<Width {X_ABS}>{_cw(w)}</Width>')

def _kv(guid, ser_id, itype, body):
    return (f'<a:KeyValueOfguidanyType>'
            f'<a:Key {X_ARR}>{guid}</a:Key>'
            f'<a:Value z:Id="{ser_id}" i:type="{itype}">{body}</a:Value>'
            f'</a:KeyValueOfguidanyType>')

def shape_process(guid, ser_id, name, x, y, w=SHAPE_W, h=SHAPE_H):
    body = (f'<GenericTypeId {X_ABS}>GE.P</GenericTypeId>'
            f'<Guid {X_ABS}>{guid}</Guid>'
            f'<Properties {X_ABS}>{_pp(name)}</Properties>'
            + _tail('GE.P', h, x, y, w))
    return _kv(guid, ser_id, 'StencilEllipse', body)

def shape_ei(guid, ser_id, name, x, y, w=SHAPE_W, h=SHAPE_H):
    body = (f'<GenericTypeId {X_ABS}>GE.EI</GenericTypeId>'
            f'<Guid {X_ABS}>{guid}</Guid>'
            f'<Properties {X_ABS}>{_pei(name)}</Properties>'
            + _tail('GE.EI', h, x, y, w))
    return _kv(guid, ser_id, 'StencilRectangle', body)

def shape_boundary(guid, ser_id, name, x, y, w, h):
    body = (f'<GenericTypeId {X_ABS}>GE.TB.B</GenericTypeId>'
            f'<Guid {X_ABS}>{guid}</Guid>'
            f'<Properties {X_ABS}>{_pbb(name)}</Properties>'
            + _tail('GE.TB.B', h, x, y, w))
    return _kv(guid, ser_id, 'BorderBoundary', body)

def shape_flow(guid, ser_id, name, src_guid, dst_guid,
               sx, sy, dx, dy, port_src='East', port_dst='West',
               hx=None, hy=None):
    sx, sy = _cf(sx), _cf(sy)
    dx, dy = _cf(dx), _cf(dy)
    hx = _cf(hx if hx is not None else (sx+dx)//2)
    hy = _cf(hy if hy is not None else (sy+dy)//2)
    body = (f'<GenericTypeId {X_ABS}>GE.DF</GenericTypeId>'
            f'<Guid {X_ABS}>{guid}</Guid>'
            f'<Properties {X_ABS}>{_pdf(name)}</Properties>'
            f'<TypeId {X_ABS}>GE.DF</TypeId>'
            f'<HandleX {X_ABS}>{hx}</HandleX>'
            f'<HandleY {X_ABS}>{hy}</HandleY>'
            f'<PortSource {X_ABS}>{port_src}</PortSource>'
            f'<PortTarget {X_ABS}>{port_dst}</PortTarget>'
            f'<SourceGuid {X_ABS}>{src_guid}</SourceGuid>'
            f'<SourceX {X_ABS}>{sx}</SourceX>'
            f'<SourceY {X_ABS}>{sy}</SourceY>'
            f'<TargetGuid {X_ABS}>{dst_guid}</TargetGuid>'
            f'<TargetX {X_ABS}>{dx}</TargetX>'
            f'<TargetY {X_ABS}>{dy}</TargetY>')
    return _kv(guid, ser_id, 'Connector', body)


def _req_str_id(obj, path, errors):
    if 'id' not in obj or not isinstance(obj['id'], str) or not obj['id'].strip():
        errors.append(f"{path}: missing/invalid 'id'")

def validate_strict(archi):
    errors, warnings = [], []
    if not isinstance(archi, dict): return ["Root must be dict"], []
    for label in ('ecus','data_flows','trust_zones','external_interfaces','communication_buses'):
        if not isinstance(archi.get(label,[]), list):
            errors.append(f"'{label}' must be a list")
    if errors: return errors, warnings

    ecu_ids, iface_ids, zone_ids, bus_ids = [], [], [], []
    for i,e in enumerate(archi.get('ecus',[])):
        if not isinstance(e,dict): errors.append(f"ecus[{i}] not object"); continue
        _req_str_id(e,f"ecus[{i}]",errors)
        if isinstance(e.get('id'),str): ecu_ids.append(e['id'])
    for i,it in enumerate(archi.get('external_interfaces',[])):
        if not isinstance(it,dict): errors.append(f"ifaces[{i}] not object"); continue
        _req_str_id(it,f"ifaces[{i}]",errors)
        if isinstance(it.get('id'),str): iface_ids.append(it['id'])
    for i,z in enumerate(archi.get('trust_zones',[])):
        if not isinstance(z,dict): errors.append(f"zones[{i}] not object"); continue
        _req_str_id(z,f"zones[{i}]",errors)
        if isinstance(z.get('id'),str): zone_ids.append(z['id'])
    for i,b in enumerate(archi.get('communication_buses',[])):
        if not isinstance(b,dict): errors.append(f"buses[{i}] not object"); continue
        _req_str_id(b,f"buses[{i}]",errors)
        if isinstance(b.get('id'),str): bus_ids.append(b['id'])

    def _dup(xs):
        seen,d=set(),set()
        for x in xs: (d if x in seen else seen).add(x)
        return sorted(d)

    for label,ids in [('ECU',ecu_ids),('iface',iface_ids),('zone',zone_ids),('bus',bus_ids)]:
        if _dup(ids): errors.append(f"Duplicate {label} IDs: {_dup(ids)}")

    coll = sorted(set(ecu_ids)&set(iface_ids))
    if coll: errors.append(f"ID collision ECU/iface: {coll}")

    all_known = set(ecu_ids)|set(iface_ids)|set(bus_ids)
    zones_set = set(zone_ids)
    for e in archi.get('ecus',[]):
        tz = e.get('trust_zone','')
        if tz and tz not in zones_set:
            warnings.append(f"ECU '{e.get('id','?')}' refs unknown zone '{tz}'")

    for i,fl in enumerate(archi.get('data_flows',[])):
        if not isinstance(fl,dict): errors.append(f"flows[{i}] not object"); continue
        for k in ('source','destination'):
            v=fl.get(k)
            if not isinstance(v,str) or not v.strip(): errors.append(f"flows[{i}] missing '{k}'")
            elif v not in all_known and v not in zones_set:
                warnings.append(f"Flow '{fl.get('id',i)}' {k}='{v}' unknown")

    return errors, warnings


def ceil_div(a, b):
   
    return max(1, (a + b - 1) // b) if a > 0 else 1

def rect_center(r):
    x,y,w,h = r
    return (x+w/2.0, y+h/2.0)

def anchor_on_rect(rect, port):
    x,y,w,h = rect
    cx,cy = x+w/2.0, y+h/2.0
    pt = {'East':(x+w,cy),'West':(x,cy),'North':(cx,y),'South':(cx,y+h)}.get(port,(cx,cy))
    return (_cf(pt[0]), _cf(pt[1]))

def port_by_direction(sx, sy, dx, dy):
    if abs(dx-sx) >= abs(dy-sy):
        return ('East','West') if dx>=sx else ('West','East')
    return ('South','North') if dy>=sy else ('North','South')

def rect_contains_point(r, px, py):
    x,y,w,h = r
    return (x<=px<=x+w) and (y<=py<=y+h)

def build_corridors(zone_rect: dict) -> dict:
    
    if not zone_rect:
        return {'h': [200, 400], 'v': [200, 600]}

    top   = min(y   for (x,y,w,h) in zone_rect.values())
    bot   = max(y+h for (x,y,w,h) in zone_rect.values())
    left  = min(x   for (x,y,w,h) in zone_rect.values())
    right = max(x+w for (x,y,w,h) in zone_rect.values())

    all_y = sorted(set([y   for (x,y,w,h) in zone_rect.values()] +
                       [y+h for (x,y,w,h) in zone_rect.values()]))
    all_x = sorted(set([x   for (x,y,w,h) in zone_rect.values()] +
                       [x+w for (x,y,w,h) in zone_rect.values()]))

    h_corr = []
    above = top - CORRIDOR_OUTER
    if above > MIN_COORD: h_corr.append(above)
    h_corr.append(bot + CORRIDOR_OUTER)
    for a, b in zip(all_y, all_y[1:]):
        if b - a > MIN_DIM * 2:
            mid = (a + b) / 2.0
            if all(not rect_contains_point(r, left+10, mid) for r in zone_rect.values()):
                if mid > MIN_COORD: h_corr.append(mid)

    v_corr = []
    before = left - CORRIDOR_OUTER
    if before > MIN_COORD: v_corr.append(before)
    v_corr.append(right + CORRIDOR_OUTER)
    for a, b in zip(all_x, all_x[1:]):
        if b - a > MIN_DIM * 2:
            mid = (a + b) / 2.0
            if all(not rect_contains_point(r, mid, top+10) for r in zone_rect.values()):
                if mid > MIN_COORD: v_corr.append(mid)

    if not h_corr: h_corr = [bot + CORRIDOR_OUTER]
    if not v_corr: v_corr = [right + CORRIDOR_OUTER]

    return {
        'h': sorted(set(max(MIN_COORD, int(c)) for c in h_corr)),
        'v': sorted(set(max(MIN_COORD, int(c)) for c in v_corr)),
    }

def corridor_handle(sx, sy, dx, dy, corridors, lane):
    if abs(dx-sx) >= abs(dy-sy):
        y = min(corridors['h'], key=lambda yy: abs(yy-(sy+dy)/2))
        y = _cf(y + lane * LANE_OFFSET * BUNDLE_SPREAD)
        return (_cf((sx+dx)/2), y)
    x = min(corridors['v'], key=lambda xx: abs(xx-(sx+dx)/2))
    x = _cf(x + lane * LANE_OFFSET * BUNDLE_SPREAD)
    return (x, _cf((sy+dy)/2))

def best_zone_for_bus(bus, zone_to_ecus):
    connected = set(bus.get('connected_ecus', []))
    best, best_n = None, 0
    for zid, lst in zone_to_ecus.items():
        n = sum(1 for e in lst if e in connected)
        if n > best_n: best_n, best = n, zid
    return best if best_n >= 2 else None

def _is_external_zone(zid: str) -> bool:
    return 'EXTERNAL' in zid.upper()

def zone_display_name(zid: str, zones_meta: dict) -> str:
  
    z = zones_meta.get(zid, {}) if isinstance(zones_meta, dict) else {}
    name = (z.get('name') or zid).strip()
    tl = z.get('trust_level', None)
    if isinstance(tl, int):
        return f"{name} (Trust Level {tl})"
    return name

def _proto_label(proto) -> str:
    """Return a clean 'CAN' or 'CAN/UDS' string from a protocol dict or string."""
    if isinstance(proto, dict):
        t = proto.get('transport', '')
        a = proto.get('application', 'NONE')
        return t if (not a or a.upper() == 'NONE') else f"{t}/{a}"
    return str(proto) if proto else ''

def flow_display_name(fl: dict) -> str:
    fid   = (fl.get('id') or '').strip()
    nm    = (fl.get('name') or '').strip()
    proto = _proto_label(fl.get('protocol', ''))
    base  = nm or fid or "DataFlow"
    return f"{base} [{proto}]" if proto else base

def build_from_template(archi, ref_path):
    GR = GuidRegistry()
    ref = open(ref_path, encoding='utf-8').read()

    item_def  = archi.get('item_definition', {}) or {}
    item_name = item_def.get('item_name', 'Threat Model')
    item_desc = item_def.get('description', '')

    ecus_raw   = archi.get('ecus', [])
    flows_raw  = archi.get('data_flows', [])
    zones_lst  = archi.get('trust_zones', [])
    ifaces_raw = archi.get('external_interfaces', [])
    buses_raw  = archi.get('communication_buses', [])

    zones_meta = {z['id']: z for z in zones_lst
                  if isinstance(z,dict) and isinstance(z.get('id'),str)}
    ecu_map  = {e['id']: e for e in ecus_raw
                if isinstance(e,dict) and isinstance(e.get('id'),str)}
    iface_map= {i['id']: i for i in ifaces_raw
                if isinstance(i,dict) and isinstance(i.get('id'),str)}
    bus_map  = {b['id']: b for b in buses_raw
                if isinstance(b,dict) and isinstance(b.get('id'),str)}

    
    max_ser = 0
    for m in re.finditer(r'z:Id="i(\d+)"', ref):
        try: max_ser = max(max_ser, int(m.group(1)))
        except: pass
    _ser = [max_ser + 1]
    def sid(): s=f'i{_ser[0]}'; _ser[0]+=1; return s

   
    ext_shapes = {}   
    alias_map  = {}   
    for iid, iface in iface_map.items():
        hb = iface.get('hosted_by', None)
        hosts = hb if isinstance(hb,list) else ([hb] if isinstance(hb,str) else [])
        if len(hosts) > 1:
            nids = []
            for h in hosts:
                nid = f"{iid}__{h}"
                ext_shapes[nid] = f"{iface.get('name',iid)} [{h}]"
                nids.append(nid)
            alias_map[iid] = nids
        else:
            ext_shapes[iid] = iface.get('name', iid)
            alias_map[iid]  = [iid]

   
    zones = dict(zones_meta)
    for ecu in ecu_map.values():
        zid = ecu.get('trust_zone','') or 'UNASSIGNED'
        if zid not in zones:
            zones[zid] = {'id': zid, 'name': zid}

   
    z2e = defaultdict(list)
    for eid, ecu in ecu_map.items():
        z2e[ecu.get('trust_zone','') or 'UNASSIGNED'].append(eid)

    BUS_ZONE_ID = '__BUS_BOUNDARY__'
    bus_zone = {}
    for bid, bus in bus_map.items():
        z = best_zone_for_bus(bus, z2e)
        bus_zone[bid] = z if z else BUS_ZONE_ID
    if any(z == BUS_ZONE_ID for z in bus_zone.values()):
        zones[BUS_ZONE_ID] = {'id': BUS_ZONE_ID, 'name': 'Communication Buses'}

   
    zone_to_nodes = defaultdict(list)
    for eid in ecu_map:
        zid = ecu_map[eid].get('trust_zone','') or 'UNASSIGNED'
        zone_to_nodes[zid].append(eid)
    for bid in bus_map:
        zone_to_nodes[bus_zone[bid]].append(bid)

   
    zone_order = sorted(
        [z for z in zone_to_nodes if len(zone_to_nodes[z]) > 0 and not _is_external_zone(z)],
        key=lambda z: (z=='UNASSIGNED', z==BUS_ZONE_ID, z.lower())
    )

    
    guid = {}
    for eid in ecu_map:      guid[eid] = GR.alloc(f"ECU::{eid}")
    for bid in bus_map:      guid[bid] = GR.alloc(f"BUS::{bid}")
    for nid in ext_shapes:   guid[nid] = GR.alloc(f"EXT::{nid}")
    for zid in zone_order:   guid[zid] = GR.alloc(f"ZONE::{zid}")

    TZ_EXT_ID   = '__TZ_EXTERNAL_BOUNDARY__'
    TZ_EXT_NAME = 'External Untrusted Zone (Trust Level 0)'
    guid[TZ_EXT_ID] = GR.alloc(f"ZONE::{TZ_EXT_ID}")

    _fc = [0]
    def next_flow_guid(seed):
        _fc[0] += 1
        return GR.alloc(f"FLOW::{seed}::{_fc[0]}")

  
    zone_size = {}
    for zid in zone_order:
        n    = len(zone_to_nodes[zid])
        cols = min(ECU_COLS_MAX, max(1, n))
        rows = ceil_div(n, cols)
        iw   = max(0, (cols-1)) * ECU_GAP_X + SHAPE_W
        ih   = max(0, (rows-1)) * ECU_GAP_Y + SHAPE_H
        zone_size[zid] = (_cw(iw + 2*BORDER_PAD), _ch(ih + 2*BORDER_PAD), cols)

    cur_x, cur_y, row_h, col_i = X_START, Y_START, 0, 0
    zone_pos = {}
    for zid in zone_order:
        w, h, _ = zone_size[zid]
        if col_i >= ZONE_COLS:
            cur_x, cur_y, row_h, col_i = X_START, cur_y+row_h+ZONE_GAP_Y, 0, 0
        zone_pos[zid] = (_cx(cur_x), _cy(cur_y))
        cur_x += w + ZONE_GAP_X
        row_h  = max(row_h, h)
        col_i += 1

    node_rect = {}
    node_zone = {}
    zone_rect = {}

    for zid in zone_order:
        zx, zy = zone_pos[zid]
        w, h, cols = zone_size[zid]
        for i, nid in enumerate(zone_to_nodes[zid]):
            c, r = i % cols, i // cols
            x = _cx(zx + BORDER_PAD + c * ECU_GAP_X)
            y = _cy(zy + BORDER_PAD + r * ECU_GAP_Y)
            node_rect[nid] = (x, y, SHAPE_W, SHAPE_H)
            node_zone[nid] = zid
        zone_rect[zid] = (zx, zy, w, h)

   
    z_right = max((x+w for (x,y,w,h) in zone_rect.values()), default=X_START+800)
    z_top   = min((y   for (x,y,w,h) in zone_rect.values()), default=Y_START)

    ext_x0  = _cx(z_right + EXT_PAD_X)
    ext_ids = sorted(ext_shapes.keys())

    for i, nid in enumerate(ext_ids):
        col = i // MAX_EXT_ROWS
        row = i %  MAX_EXT_ROWS
        x = _cx(ext_x0 + col * (SHAPE_W + EXT_COL_GAP_X))
        y = _cy(z_top  + row * EXT_GAP_Y)
        node_rect[nid] = (x, y, SHAPE_W, SHAPE_H)
        node_zone[nid] = '__EXTERNAL__'

    def _ext_bnd():
        if not ext_ids:
            return (_cx(ext_x0), _cy(z_top), _cw(300), _ch(400))
        xs = [node_rect[n][0]                 for n in ext_ids if n in node_rect]
        ys = [node_rect[n][1]                 for n in ext_ids if n in node_rect]
        xe = [node_rect[n][0]+node_rect[n][2] for n in ext_ids if n in node_rect]
        ye = [node_rect[n][1]+node_rect[n][3] for n in ext_ids if n in node_rect]
        if not xs: return (_cx(ext_x0), _cy(z_top), _cw(300), _ch(400))
        bx = _cx(min(xs) - EXT_BND_PAD)
        by = _cy(min(ys) - EXT_BND_PAD)
        bw = _cw(max(xe) - min(xs) + 2 * EXT_BND_PAD)
        bh = _ch(max(ye) - min(ys) + 2 * EXT_BND_PAD)
        for n in ext_ids:
            if n not in node_rect: continue
            nx,ny,nw,nh = node_rect[n]
            if nx < bx: bx = _cx(nx - EXT_BND_PAD)
            if ny < by: by = _cy(ny - EXT_BND_PAD)
            if nx+nw > bx+bw: bw = _cw(nx+nw-bx + EXT_BND_PAD)
            if ny+nh > by+bh: bh = _ch(ny+nh-by + EXT_BND_PAD)
        return (bx, by, bw, bh)

   
    corridors = build_corridors(zone_rect)

 
    borders = []

 
    for zid in zone_order:
        zx,zy,zw,zh = zone_rect[zid]
        zname = zone_display_name(zid, zones_meta) if zid in zones_meta else zones.get(zid,{}).get('name',zid)
        borders.append(shape_boundary(guid[zid], sid(), zname, zx,zy,zw,zh))

    
    eb = _ext_bnd()
    borders.append(shape_boundary(guid[TZ_EXT_ID], sid(), TZ_EXT_NAME,
                                  eb[0],eb[1],eb[2],eb[3]))

   
    for eid, ecu in ecu_map.items():
        x,y,w,h = node_rect[eid]
        borders.append(shape_process(guid[eid], sid(), ecu.get('name',eid), x,y,w,h))

   
    for bid, bus in bus_map.items():
        if bid not in node_rect: continue
        x,y,w,h = node_rect[bid]
        proto = bus.get('protocol', '')
        if isinstance(proto, dict):
            t = proto.get('transport', '')
            a = proto.get('application', 'NONE')
            proto_str = t if (not a or a.upper() == 'NONE') else f"{t}/{a}"
        else:
            proto_str = str(proto)
        bus_name = bus.get('name', bid)
        label = f"Bus: {_xe(bus_name)} ({_xe(proto_str)})" if proto_str else f"Bus: {_xe(bus_name)}"
        borders.append(shape_process(guid[bid], sid(), label, x,y,w+40,h))

   
    for nid in ext_ids:
        if nid not in node_rect: continue
        x,y,w,h = node_rect[nid]
        borders.append(shape_ei(guid[nid], sid(), ext_shapes[nid], x,y,w,h))

    lines = []
    bundle_lane = defaultdict(int)

    def emit_flow(seed, fname, src_nid, dst_nid):
        if src_nid not in node_rect or dst_nid not in node_rect:
            return
        if src_nid not in guid: guid[src_nid] = GR.alloc(f"EXT::{src_nid}")
        if dst_nid not in guid: guid[dst_nid] = GR.alloc(f"EXT::{dst_nid}")

        fguid = next_flow_guid(seed)
        sx0,sy0 = rect_center(node_rect[src_nid])
        dx0,dy0 = rect_center(node_rect[dst_nid])
        ps_, pd_ = port_by_direction(sx0,sy0,dx0,dy0)
        sx,sy = anchor_on_rect(node_rect[src_nid], ps_)
        dx,dy = anchor_on_rect(node_rect[dst_nid], pd_)
        zs = node_zone.get(src_nid,'__EXTERNAL__')
        zd = node_zone.get(dst_nid,'__EXTERNAL__')
        bkey = (zs,zd,ps_,pd_)
        lane = bundle_lane[bkey]; bundle_lane[bkey]+=1
        hx,hy = corridor_handle(sx,sy,dx,dy,corridors,lane)
        lines.append(shape_flow(
            fguid, sid(), fname,
            guid[src_nid], guid[dst_nid],
            sx,sy,dx,dy, port_src=ps_, port_dst=pd_, hx=hx, hy=hy
        ))

   
    render_cfg = archi.get("_render", {}) if isinstance(archi.get("_render", {}), dict) else {}
    bus_flow_mode = (render_cfg.get("bus_flow_mode") or "oneway").lower()
    if bus_flow_mode not in ("none", "oneway", "bidir"):
        bus_flow_mode = "oneway"

    if bus_flow_mode != "none":
        for bid, bus in bus_map.items():
            proto = bus.get('protocol', '')
            if isinstance(proto, dict):
                t = proto.get('transport', '')
                a = proto.get('application', 'NONE')
                proto_str = t if (not a or a.upper() == 'NONE') else f"{t}/{a}"
            else:
                proto_str = str(proto)
            lbl = f"{bus.get('name', bid)} ({proto_str})" if proto_str else bus.get('name', bid)
            for eid in bus.get('connected_ecus',[]):
                if eid not in ecu_map:
                    continue
               
                emit_flow(f"ecu_to_bus::{eid}::{bid}", lbl, eid, bid)
                if bus_flow_mode == "bidir":
                    emit_flow(f"bus_to_ecu::{bid}::{eid}", lbl, bid, eid)

   
    def resolve_one(raw_id):
       
        if raw_id in node_rect:
            return [raw_id]
        if raw_id in alias_map:
            res = [n for n in alias_map[raw_id] if n in node_rect]
            return res if res else []
        return []

   
    for fl in flows_raw:
        if not isinstance(fl,dict): continue
        src_raw = fl.get('source','')
        dst_raw = fl.get('destination','')
        if not src_raw or not dst_raw: continue

        fname   = flow_display_name(fl)
        flow_id = fl.get('id', f"{src_raw}::{dst_raw}")

       
        src_iface = fl.get('source_interface', '')
        if src_iface:
            src_nodes = resolve_one(src_iface)
        else:
            src_nodes = resolve_one(src_raw)

        
        dst_iface = fl.get('destination_interface', '')
        if dst_iface:
            dst_nodes = resolve_one(dst_iface)
        else:
            dst_nodes = resolve_one(dst_raw)

        if not src_nodes or not dst_nodes:
            continue  

        for s in src_nodes:
            for d in dst_nodes:
                emit_flow(f"df::{flow_id}::{s}::{d}", fname, s, d)

    out = ref

    def _replace(text, pfx, close_tag, content):
        i0=text.find(pfx)
        if i0<0: raise RuntimeError(f"Template missing '{pfx}'")
        i1=text.find('>',i0)+1; i2=text.find(close_tag,i1)
        if i2<0: raise RuntimeError(f"Template missing '{close_tag}'")
        return text[:i1]+content+text[i2:]

   
    out = _replace(out,'<Borders xmlns:a=','</Borders>',''.join(borders))
    out = _replace(out,'<Lines xmlns:a=',  '</Lines>',  ''.join(lines))

    h0=out.find('<Header>'); h1=out.find('</Header>')
    if h0>=0 and h1>h0: out=out[:h0+len('<Header>')]+item_name+out[h1:]

    out = re.sub(
        r'(<b:Value i:type="c:string" xmlns:c="http://www\.w3\.org/2001/XMLSchema">)'
        r'[^<]*(</b:Value></a:anyType></Properties><TypeId)',
        r'\g<1>'+item_name+r'\g<2>', out, count=1)

    meta = ''.join([
        '<MetaInformation><Assumptions/><Contributors/><ExternalDependencies/>',
        f'<HighLevelSystemDescription>{item_desc}</HighLevelSystemDescription>',
        '<Owner>TARA Automation</Owner><Reviewer/>',
        f'<ThreatModelName>{item_name}</ThreatModelName></MetaInformation>'])
    mi0=out.find('<MetaInformation>'); mi1=out.find('</MetaInformation>')
    if mi0>=0 and mi1>mi0:
        out=out[:mi0]+meta+out[mi1+len('</MetaInformation>'):]

    ti0=out.find('<ThreatInstances')
    if ti0>=0:
        ti_oe=out.find('>',ti0)+1; ti_ce=out.find('</ThreatInstances>',ti_oe)
        if ti_ce>=0:
            ti_ce+=len('</ThreatInstances>')
            out=out[:ti0]+out[ti0:ti_oe].rstrip('>')+'/>' +out[ti_ce:]

    return out




def main():
    p = argparse.ArgumentParser(description='Architecture JSON -> MTMT .tm7 (v6.4 — exact 1 arrow per flow)')
    p.add_argument('--input',        '-i', default='data/architecture.json')
    p.add_argument('--output',       '-o', default='architecture.tm7')
    p.add_argument('--ref',          '-r', default='templates/ref.tm7')
    p.add_argument('--validate-only',      action='store_true')
    args = p.parse_args()

    for path, label in [(args.input,'Input JSON'),(args.ref,'Reference tm7')]:
        if not os.path.exists(path):
            print(f'[ERROR] {label} not found: {path}', file=sys.stderr); sys.exit(1)

    with open(args.input, encoding='utf-8') as f:
        try:   archi=json.load(f)
        except json.JSONDecodeError as ex:
            print(f'[ERROR] JSON: {ex}', file=sys.stderr); sys.exit(1)

    errors, warnings = validate_strict(archi)
    if warnings:
        print('WARNINGS:')
        for w in warnings: print(f'  {w}')
    if errors:
        print('[✗] ERRORS:', file=sys.stderr)
        for e in errors: print(f'    {e}', file=sys.stderr)
        sys.exit(1)
    print('Validation passed')
    if args.validate_only: sys.exit(0)

    try:
        xml = build_from_template(archi, args.ref)
    except ValueError as ex:
        print(f'[ERROR] GUID collision: {ex}', file=sys.stderr); sys.exit(2)

    with open(args.output, 'w', encoding='utf-8') as f:
        f.write(xml)
    print(f'Written: {args.output}  ({os.path.getsize(args.output)/1024:.1f} KB)')


if __name__ == '__main__':
    main()