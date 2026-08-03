import json
import sys
from pathlib import Path
from collections import defaultdict

from ontology_taxonomy import (
    FUNCTIONAL_DOMAINS,
    SUBDOMAIN_MAP,
    CYBERSECURITY_DOMAIN_MAP,
    CONSEQUENCE_DOMAIN_MAP,
)


KNOWN_ATTACK_SURFACES = {
    "in_vehicle_network",
    "diagnostic_interface",
    "physical_access",
    "wireless_interface",
    "remote_network",
}

REQUIRED_NODE_FIELDS = {
    "ontology_id",
    "functional_domain",
    "subdomains",
    "confidence",
    "mapped_ecus",
    "mapped_interfaces",
    "inference_evidence",
    "cybersecurity_properties",
    "functional_consequences",
    "damage_scenario_seeds",
    "attack_surface_classes",
    "asset_target_properties",
    "reachable_threat_actor_classes",
    "entry_point",
    "provenance",
    "topology",
    "capec_cwe_refs",
}

REQUIRED_PROVENANCE_FIELDS = {
    "source",
    "reference_standards",
    "justification",
    "inference_method",
    "deterministic",
}

REQUIRED_CYBER_FIELDS = {
    "primary",
    "secondary",
    "derivation",
}

REQUIRED_EVIDENCE_FIELDS = {
    "trust_zone_signal",
    "data_flow_role",
    "interface_proximity",
    "protocol_signal",
    "bus_membership",
    "lexical_tokens",
    "actuator_sensor_role",
}

REQUIRED_ENTRY_POINT_FIELDS = {
    "is_entry_point",
    "entry_point_types",
    "externally_reachable",
    "reachability_derivation",
    "transitive_remote_reachable",
}

CONFIDENCE_MINIMUM = 0.10
CONFIDENCE_WARNING = 0.40

KNOWN_DIAGNOSTIC_ALIASES = {"AUTOPILOT", "RADAR", "LIDAR", "CAMERA"}
SAFETY_CRITICAL_DOMAINS = {
    "VEHICLE_MOTION_CONTROL",
    "OCCUPANT_SAFETY_SYSTEMS",
    "AUTOMATED_DRIVING_CONTROL",
    "POWERTRAIN_MANAGEMENT",
    "PERCEPTION_AND_SENSING",
}

VALID_ACTOR_CLASSES = {
    "remote_attacker",
    "nearby_attacker",
    "physical_attacker",
    "service_technician",
    "insider_attacker",
    "supply_chain_attacker",
}

HARM_TERMINUS_WORDS = {
    "harm", "collision", "death", "injury", "fire", "theft",
    "violation", "breach", "loss", "damage", "risk", "stranding",
    "electrocution", "hazard", "fatality", "compromise",
}

NETWORK_EXPOSED_SURFACE_SIGNALS = {"remote_network", "wireless_interface"}

SUPPRESSED_FALSE_POSITIVES = {"39"}


class OntologyValidator:
    def __init__(self, ontology):
        self.ontology = ontology
        self.errors = []
        self.warnings = []
        self.passed = []

    def _error(self, node_id, msg):
        self.errors.append(f"[ERROR] {node_id}: {msg}")

    def _warn(self, node_id, msg):
        self.warnings.append(f"[WARN]  {node_id}: {msg}")

    def _pass(self, node_id, msg):
        self.passed.append(f"[OK]    {node_id}: {msg}")

    def validate_schema(self, node):
        nid = node.get("ontology_id", "UNKNOWN")
        missing = REQUIRED_NODE_FIELDS - set(node.keys())
        if missing:
            self._error(nid, f"Missing required fields: {sorted(missing)}")
        else:
            self._pass(nid, "Schema fields present")

        provenance = node.get("provenance", {})
        missing_prov = REQUIRED_PROVENANCE_FIELDS - set(provenance.keys())
        if missing_prov:
            self._error(nid, f"Missing provenance fields: {sorted(missing_prov)}")

        cyber = node.get("cybersecurity_properties", {})
        missing_cyber = REQUIRED_CYBER_FIELDS - set(cyber.keys())
        if missing_cyber:
            self._error(nid, f"Missing cybersecurity_properties fields: {sorted(missing_cyber)}")

        evidence = node.get("inference_evidence", {})
        missing_ev = REQUIRED_EVIDENCE_FIELDS - set(evidence.keys())
        if missing_ev:
            self._warn(nid, f"Missing inference_evidence fields: {sorted(missing_ev)}")

    def validate_domain(self, node):
        nid = node.get("ontology_id", "UNKNOWN")
        domain = node.get("functional_domain")
        if domain not in FUNCTIONAL_DOMAINS:
            self._error(nid, f"Unknown functional_domain: {domain}")
        else:
            self._pass(nid, f"functional_domain '{domain}' is valid")

        subdomains = node.get("subdomains", [])
        valid_subs = set(SUBDOMAIN_MAP.get(domain, []))
        for sub in subdomains:
            if sub not in valid_subs:
                self._warn(nid, f"Subdomain '{sub}' not in taxonomy for domain '{domain}'")

    def validate_dual_domain(self, node):
        nid = node.get("ontology_id", "UNKNOWN")
        domain = node.get("functional_domain")
        dual = node.get("dual_domain")
        if domain == "NETWORK_GATEWAYING" and dual is None:
            self._warn(
                nid,
                "NETWORK_GATEWAYING node has null dual_domain; "
                "gateway nodes typically carry a secondary operational domain for threat scenario routing"
            )
        elif dual is not None and dual not in FUNCTIONAL_DOMAINS:
            self._warn(nid, f"dual_domain '{dual}' not in known FUNCTIONAL_DOMAINS")
        elif dual is not None:
            self._pass(nid, f"dual_domain '{dual}' populated")

    def validate_confidence(self, node):
        nid = node.get("ontology_id", "UNKNOWN")
        confidence = node.get("confidence", 0.0)
        if confidence < CONFIDENCE_MINIMUM:
            self._error(nid, f"Confidence {confidence} below minimum {CONFIDENCE_MINIMUM}")
        elif confidence < CONFIDENCE_WARNING:
            self._warn(nid, f"Confidence {confidence} below warning threshold {CONFIDENCE_WARNING}")
        else:
            self._pass(nid, f"Confidence {confidence} acceptable")

        if confidence < 0.75:
            domain = node.get("functional_domain", "")
            if domain in SAFETY_CRITICAL_DOMAINS:
                self._warn(
                    nid,
                    f"Safety-critical domain node has confidence {confidence} < 0.75. "
                    "Generation layer must not demote domain classification on confidence alone; "
                    "low confidence reflects evidence tension, not domain ambiguity."
                )

    def validate_attack_surfaces(self, node):
        nid = node.get("ontology_id", "UNKNOWN")
        surfaces = node.get("attack_surface_classes", [])
        unknown = set(surfaces) - KNOWN_ATTACK_SURFACES
        if unknown:
            self._warn(nid, f"Unrecognized attack_surface_classes: {sorted(unknown)}")
        if not surfaces:
            self._error(nid, "No attack_surface_classes defined")
        else:
            self._pass(nid, f"attack_surface_classes: {surfaces}")

        mapped_ifaces = node.get("mapped_interfaces", [])
        if any("VEHICLE_NETWORK" in i or "NETWORK" in i for i in mapped_ifaces):
            if "remote_network" not in surfaces:
                self._warn(
                    nid,
                    "Node is adjacent to a network-type external interface but 'remote_network' "
                    "is absent from attack_surface_classes. Verify interface exposure flag."
                )

    def validate_consequences(self, node):
        nid = node.get("ontology_id", "UNKNOWN")
        domain = node.get("functional_domain")
        consequences = node.get("functional_consequences", [])
        damage_seeds = node.get("damage_scenario_seeds", [])

        if not consequences:
            self._error(nid, "No functional_consequences defined")
        else:
            self._pass(nid, f"{len(consequences)} consequences defined")

        if not damage_seeds:
            self._warn(nid, "No damage_scenario_seeds defined")
        else:
            for seed in damage_seeds:
                has_harm = any(w in seed.lower() for w in HARM_TERMINUS_WORDS)
                if not has_harm:
                    self._warn(
                        nid,
                        f"Damage seed lacks explicit harm terminus (ISO 21434 Cl.15.3 requires "
                        f"adverse consequence, not attack description): '{seed[:80]}'"
                    )

        if domain in SAFETY_CRITICAL_DOMAINS and "safety_function_unavailability" not in consequences:
            integrity_key = f"integrity_loss_in_{domain.lower()}"
            if integrity_key not in consequences:
                self._warn(nid, f"Safety-critical domain '{domain}' has no integrity or availability consequence")

    def validate_cybersecurity_properties(self, node):
        nid = node.get("ontology_id", "UNKNOWN")
        domain = node.get("functional_domain")
        cyber = node.get("cybersecurity_properties", {})
        primary = cyber.get("primary", [])
        secondary = cyber.get("secondary", [])

        expected = CYBERSECURITY_DOMAIN_MAP.get(domain, {}).get("primary", [])
        missing_props = set(expected) - set(primary)
        if missing_props:
            self._warn(nid, f"Missing expected primary cyber properties: {sorted(missing_props)}")
        else:
            self._pass(nid, "Cybersecurity properties aligned with taxonomy")

        subdomains = node.get("subdomains", [])
        if "occupant_sensing" in subdomains:
            all_props = set(primary) | set(secondary)
            if "Confidentiality" not in all_props:
                self._warn(
                    nid,
                    "occupant_sensing subdomain carries biometric asset targets; "
                    "Confidentiality must appear in cybersecurity_properties.secondary"
                )

        if domain == "POWERTRAIN_MANAGEMENT":
            all_props = set(primary) | set(secondary)
            if "Confidentiality" not in all_props:
                self._warn(
                    nid,
                    "POWERTRAIN_MANAGEMENT carries BMS state and charging session data; "
                    "Confidentiality should appear in cybersecurity_properties.secondary for "
                    "energy_storage and energy_transfer subdomains"
                )

    def validate_topology(self, node):
        nid = node.get("ontology_id", "UNKNOWN")
        topology = node.get("topology")
        if not isinstance(topology, dict):
            self._error(nid, "topology field missing or not a dict")
            return
        required_topo_fields = {"connected_ecus", "via_buses", "via_flows", "trust_boundary_crossings"}
        missing = required_topo_fields - set(topology.keys())
        if missing:
            self._error(nid, f"topology missing fields: {sorted(missing)}")
        else:
            self._pass(nid, "topology fields present including trust_boundary_crossings")

        crossings = topology.get("trust_boundary_crossings", [])
        escalation_count = 0
        for i, c in enumerate(crossings):
            for req in ("src_ecu", "dst_ecu", "src_trust_level", "dst_trust_level"):
                if req not in c:
                    self._error(nid, f"trust_boundary_crossings[{i}] missing '{req}'")
            direction = c.get("direction", "")
            if direction == "LOW_TO_HIGH_ESCALATION":
                escalation_count += 1

        if escalation_count > 0:
            self._pass(nid, f"{escalation_count} LOW_TO_HIGH_ESCALATION trust crossings annotated (attack path seeds)")

        connected = topology.get("connected_ecus", [])
        via_buses = topology.get("via_buses", [])
        via_flows = topology.get("via_flows", [])
        if not connected and not via_buses and not via_flows:
            domain = node.get("functional_domain", "")
            if domain in SAFETY_CRITICAL_DOMAINS:
                self._warn(
                    nid,
                    "Node is topologically isolated (no connected_ecus, via_buses, or via_flows); "
                    "attack path generation will be limited to direct physical access only. "
                    "Verify bus membership and data flows in architecture.json."
                )

    def validate_capec_refs(self, node):
        nid = node.get("ontology_id", "UNKNOWN")
        refs = node.get("capec_cwe_refs")
        if refs is None:
            self._error(nid, "capec_cwe_refs field missing")
        elif not isinstance(refs, list):
            self._error(nid, "capec_cwe_refs must be a list")
        else:
            if len(refs) == 0:
                self._warn(nid, "capec_cwe_refs is empty")
            else:
                self._pass(nid, f"capec_cwe_refs: {len(refs)} reference(s) present")
                for i, ref in enumerate(refs):
                    for req in ("capec_id", "capec_name", "abstraction", "join_dimensions", "cwe_ids", "severity", "likelihood"):
                        if req not in ref:
                            self._warn(nid, f"capec_cwe_refs[{i}] missing field '{req}'")
                    severity = ref.get("severity", "")
                    likelihood = ref.get("likelihood", "")
                    if isinstance(severity, str) and severity.strip() == "":
                        self._warn(nid, f"capec_cwe_refs[{i}] CAPEC-{ref.get('capec_id')} has empty severity; expected 'Unknown' sentinel")
                    if isinstance(likelihood, str) and likelihood.strip() == "":
                        self._warn(nid, f"capec_cwe_refs[{i}] CAPEC-{ref.get('capec_id')} has empty likelihood; expected 'Unknown' sentinel")
                    capec_id = ref.get("capec_id", "")
                    if capec_id in SUPPRESSED_FALSE_POSITIVES:
                        self._error(
                            nid,
                            f"capec_cwe_refs[{i}] CAPEC-{capec_id} ({ref.get('capec_name')}) is on the "
                            f"false-positive suppression list and must not appear in output. "
                            f"Replace with CAPEC-94 or CAPEC-141 for message integrity bypass scenarios."
                        )
                    if capec_id and any(kw in ref.get("capec_name","").lower() for kw in
                            ("sql", "xss", "cross-site", "csrf", "bgp", "dns blocking", "dhcp", "phishing",
                             "spear phishing", "ssi injection", "browser", "clickjack", "http cookie")):
                        self._warn(nid, f"capec_cwe_refs[{i}] CAPEC-{capec_id} appears non-automotive: {ref.get('capec_name')}")

    def validate_asset_target_properties(self, node):
        nid = node.get("ontology_id", "UNKNOWN")
        atp = node.get("asset_target_properties")
        if atp is None:
            self._error(nid, "asset_target_properties field missing")
        elif not isinstance(atp, dict):
            self._error(nid, "asset_target_properties must be a dict")
        elif not atp:
            self._warn(nid, "asset_target_properties is empty")
        else:
            self._pass(nid, f"asset_target_properties: {len(atp)} CIA axes defined")

        if atp:
            cyber = node.get("cybersecurity_properties", {})
            primary_props = set(cyber.get("primary", []))
            atp_keys = set(atp.keys())
            missing_coverage = primary_props - atp_keys
            if missing_coverage:
                self._warn(nid, f"asset_target_properties missing coverage for primary properties: {sorted(missing_coverage)}")

    def validate_threat_actor_classes(self, node):
        nid = node.get("ontology_id", "UNKNOWN")
        actors = node.get("reachable_threat_actor_classes")
        if actors is None:
            self._error(nid, "reachable_threat_actor_classes field missing")
        elif not isinstance(actors, list):
            self._error(nid, "reachable_threat_actor_classes must be a list")
        elif not actors:
            self._warn(nid, "reachable_threat_actor_classes is empty")
        else:
            unknown = set(actors) - VALID_ACTOR_CLASSES
            if unknown:
                self._warn(nid, f"Unknown actor classes: {sorted(unknown)}")
            else:
                self._pass(nid, f"reachable_threat_actor_classes: {actors}")

        if actors:
            surfaces = node.get("attack_surface_classes", [])
            entry = node.get("entry_point", {})
            transitive = entry.get("transitive_remote_reachable", False)
            has_network_surface = any(s in NETWORK_EXPOSED_SURFACE_SIGNALS for s in surfaces)
            if (has_network_surface or transitive) and "remote_attacker" not in actors:
                self._error(
                    nid,
                    "Node has remote_network or wireless_interface attack surface "
                    "(or transitive_remote_reachable=True) but 'remote_attacker' is absent "
                    "from reachable_threat_actor_classes"
                )

    def validate_entry_point(self, node):
        nid = node.get("ontology_id", "UNKNOWN")
        ep = node.get("entry_point")
        if ep is None:
            self._error(nid, "entry_point field missing")
        elif not isinstance(ep, dict):
            self._error(nid, "entry_point must be a dict")
        else:
            missing = REQUIRED_ENTRY_POINT_FIELDS - set(ep.keys())
            if missing:
                self._error(nid, f"entry_point missing fields: {sorted(missing)}")
            else:
                self._pass(
                    nid,
                    f"entry_point: is_entry_point={ep.get('is_entry_point')}, "
                    f"externally_reachable={ep.get('externally_reachable')}, "
                    f"transitive_remote_reachable={ep.get('transitive_remote_reachable')}"
                )

    def validate_lexical_confidence(self, node):
        nid = node.get("ontology_id", "UNKNOWN")
        evidence = node.get("inference_evidence", {})
        lex = evidence.get("lexical_tokens", {})
        if not lex:
            return
        matched = lex.get("matched_vocabulary", [])
        if not matched:
            self._warn(nid, "lexical_tokens matched no vocabulary entries")

    def validate_diagnostic_bleed(self, node):
        nid = node.get("ontology_id", "UNKNOWN")
        domain = node.get("functional_domain")
        ecus = node.get("mapped_ecus", [])

        if domain == "DIAGNOSTIC_AND_SERVICE":
            suspicious = [e for e in ecus if e.upper() in KNOWN_DIAGNOSTIC_ALIASES]
            if suspicious:
                self._error(
                    nid,
                    f"ECU(s) {suspicious} classified as DIAGNOSTIC_AND_SERVICE "
                    f"but appear to be primary-function ECUs"
                )

    def validate_merge_integrity(self, nodes):
        seen_ecus = defaultdict(list)
        for node in nodes:
            for ecu in node.get("mapped_ecus", []):
                seen_ecus[ecu].append(node["ontology_id"])

        for ecu, node_ids in seen_ecus.items():
            if len(node_ids) > 1:
                self._error("MERGE", f"ECU '{ecu}' appears in multiple nodes: {node_ids}")

    def validate_provenance(self, node):
        nid = node.get("ontology_id", "UNKNOWN")
        provenance = node.get("provenance", {})
        if not provenance.get("justification"):
            self._error(nid, "Empty provenance justification")
        if not provenance.get("source"):
            self._warn(nid, "No provenance source references")
        if not provenance.get("reference_standards"):
            self._warn(nid, "No reference standards listed")
        if provenance.get("deterministic") is not True:
            self._warn(nid, "Inference not marked as deterministic")
        else:
            self._pass(nid, "Provenance deterministic flag set")

    def validate_ontology_ids(self, nodes):
        seen_ids = []
        for node in nodes:
            nid = node.get("ontology_id", "MISSING")
            if nid in seen_ids:
                self._error(nid, "Duplicate ontology_id detected")
            else:
                seen_ids.append(nid)

    def validate_duplicate_damage_seeds(self, nodes):
        seed_to_nodes = defaultdict(list)
        for node in nodes:
            nid = node.get("ontology_id", "UNKNOWN")
            for seed in node.get("damage_scenario_seeds", []):
                seed_to_nodes[seed].append(nid)
        for seed, node_ids in seed_to_nodes.items():
            if len(node_ids) > 1:
                self._warn(
                    "GLOBAL",
                    f"Duplicate damage seed across nodes {node_ids}: '{seed[:80]}'. "
                    "Instance differentiation required before damage scenario generation."
                )

    def validate_capec_likelihood_coverage(self, nodes):
        total = 0
        unknown_lik = 0
        for node in nodes:
            for ref in node.get("capec_cwe_refs", []):
                total += 1
                if ref.get("likelihood", "Unknown") == "Unknown":
                    unknown_lik += 1
        if total > 0:
            pct = round(100 * unknown_lik / total)
            if pct > 30:
                self._warn(
                    "GLOBAL",
                    f"{unknown_lik}/{total} ({pct}%) CAPEC refs have Unknown likelihood. "
                    "Attack tree scorer must impute likelihood from R155 risk ratings or "
                    "flag affected branches as unscored."
                )
            else:
                self._pass("GLOBAL", f"CAPEC likelihood coverage: {total - unknown_lik}/{total} scored")

    def run(self):
        nodes = self.ontology.get("nodes", [])
        if not nodes:
            self._error("ONTOLOGY", "No nodes found in ontology")
            return self._report()

        self.validate_ontology_ids(nodes)
        self.validate_merge_integrity(nodes)
        self.validate_duplicate_damage_seeds(nodes)
        self.validate_capec_likelihood_coverage(nodes)

        for node in nodes:
            self.validate_schema(node)
            self.validate_domain(node)
            self.validate_dual_domain(node)
            self.validate_confidence(node)
            self.validate_attack_surfaces(node)
            self.validate_consequences(node)
            self.validate_cybersecurity_properties(node)
            self.validate_topology(node)
            self.validate_capec_refs(node)
            self.validate_asset_target_properties(node)
            self.validate_threat_actor_classes(node)
            self.validate_entry_point(node)
            self.validate_diagnostic_bleed(node)
            self.validate_provenance(node)
            self.validate_lexical_confidence(node)

        return self._report()

    def _report(self):
        total = len(self.errors) + len(self.warnings) + len(self.passed)
        report = {
            "summary": {
                "total_checks": total,
                "errors": len(self.errors),
                "warnings": len(self.warnings),
                "passed": len(self.passed),
                "valid": len(self.errors) == 0,
            },
            "errors": self.errors,
            "warnings": self.warnings,
            "passed": self.passed,
        }
        return report


def validate_ontology_file(ontology_path, output_path=None):
    with open(ontology_path, "r") as f:
        ontology = json.load(f)

    validator = OntologyValidator(ontology)
    report = validator.run()

    print(f"\nOntology Validation Report")
    print(f"==========================")
    print(f"Nodes:    {ontology.get('node_count', '?')}")
    print(f"Checks:   {report['summary']['total_checks']}")
    print(f"Errors:   {report['summary']['errors']}")
    print(f"Warnings: {report['summary']['warnings']}")
    print(f"Passed:   {report['summary']['passed']}")
    print(f"Valid:    {report['summary']['valid']}")

    if report["errors"]:
        print("\nERRORS:")
        for e in report["errors"]:
            print(f"  {e}")

    if report["warnings"]:
        print("\nWARNINGS:")
        for w in report["warnings"]:
            print(f"  {w}")

    if output_path:
        import os
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(report, f, indent=2)
        print(f"\nValidation report written → {output_path}")

    return report


if __name__ == "__main__":
    ontology_path = sys.argv[1] if len(sys.argv) > 1 else "output/functional_automotive_ontology.json"
    output_path = sys.argv[2] if len(sys.argv) > 2 else "output/validation_report.json"
    report = validate_ontology_file(ontology_path, output_path)
    sys.exit(0 if report["summary"]["valid"] else 1)