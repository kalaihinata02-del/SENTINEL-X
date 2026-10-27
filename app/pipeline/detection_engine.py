import re
import os
import glob
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional, Tuple
from collections import defaultdict
import strictyaml

from app.models.log_event import NormalizedEvent
from app.models.rule import DetectionRule, DetectionCondition, DetectionLogic, MitreAttack
from app.models.alert import Alert

class DetectionEngine:
    """
    Detection Engineering Engine.
    Evaluates normalized events against YAML detection rules, maintaining sliding
    stateful windows for threshold correlation, and generates structured Alerts.
    """

    def __init__(self, rules_dir: str = "rules"):
        self.rules_dir = rules_dir
        self.rules: Dict[str, DetectionRule] = {}
        # Stateful sliding windows: rule_id -> group_key -> list of (timestamp, NormalizedEvent)
        self.state_windows: Dict[str, Dict[str, List[Tuple[datetime, NormalizedEvent]]]] = defaultdict(lambda: defaultdict(list))
        # Alert suppression / cooldown: rule_id + group_key -> last_alert_time
        self.last_alerted: Dict[str, datetime] = {}
        self.suppression_window_seconds = 30
        self.load_rules()

    def load_rules(self) -> int:
        """Loads and parses all YAML rules from the rules directory."""
        self.rules.clear()
        if not os.path.exists(self.rules_dir):
            os.makedirs(self.rules_dir, exist_ok=True)
            return 0

        rule_files = glob.glob(os.path.join(self.rules_dir, "*.yaml")) + glob.glob(os.path.join(self.rules_dir, "*.yml"))
        for filepath in rule_files:
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    content = f.read()
                    data = strictyaml.load(content).data
                    rule = self._parse_rule_dict(data)
                    self.rules[rule.id] = rule
            except Exception as e:
                print(f"[DetectionEngine] Error loading rule {filepath}: {e}")

        print(f"[DetectionEngine] Loaded {len(self.rules)} detection rules.")
        return len(self.rules)

    def _parse_rule_dict(self, d: Dict[str, Any]) -> DetectionRule:
        """Converts raw parsed YAML dictionary into a strongly-typed DetectionRule."""
        mitre_data = d.get("mitre_attack", {})
        mitre = MitreAttack(
            tactic=mitre_data.get("tactic", "Unknown"),
            technique_id=mitre_data.get("technique_id", "T0000"),
            technique_name=mitre_data.get("technique_name", "Unknown")
        )

        det_data = d.get("detection", {})
        cond_list = []
        for c in det_data.get("conditions", []):
            cond_list.append(DetectionCondition(
                field=c.get("field"),
                operator=c.get("operator", "equals"),
                value=c.get("value")
            ))

        # Handle group_by as list or string
        group_by = det_data.get("group_by", [])
        if isinstance(group_by, str):
            group_by = [group_by]

        det_logic = DetectionLogic(
            conditions=cond_list,
            condition_logic=det_data.get("condition_logic", "all"),
            threshold=int(det_data.get("threshold", 1)),
            time_window_seconds=int(det_data.get("time_window_seconds", 60)),
            group_by=group_by
        )

        return DetectionRule(
            id=d.get("id"),
            title=d.get("title"),
            description=d.get("description", ""),
            category=d.get("category", "general"),
            severity=d.get("severity", "medium").lower(),
            status=d.get("status", "enabled").lower(),
            author=d.get("author", "SOC Detection Engineering"),
            mitre_attack=mitre,
            detection=det_logic,
            recommended_response=d.get("recommended_response", "Investigate affected systems and contain."),
            soar_playbook=d.get("soar_playbook"),
            tags=d.get("tags", [])
        )

    def evaluate_event(self, event: NormalizedEvent) -> List[Alert]:
        """
        Evaluates a normalized event against all enabled rules.
        Returns any generated alerts.
        """
        alerts: List[Alert] = []

        for rule in self.rules.values():
            if rule.status != "enabled":
                continue

            matches = self._check_conditions(rule.detection, event)
            if not matches:
                continue

            # If threshold is 1 (immediate rule), trigger alert directly
            if rule.detection.threshold <= 1:
                alert = self._create_alert(rule, [event])
                alerts.append(alert)
                continue

            # Multi-event correlation with stateful sliding window
            group_key = self._get_group_key(rule.detection.group_by, event)
            now = event.timestamp or datetime.now(timezone.utc)
            cutoff = now - timedelta(seconds=rule.detection.time_window_seconds)

            # Clean and append to window
            window = self.state_windows[rule.id][group_key]
            # Prune events older than cutoff
            self.state_windows[rule.id][group_key] = [
                (ts, ev) for (ts, ev) in window if ts >= cutoff
            ]
            self.state_windows[rule.id][group_key].append((now, event))

            current_window = self.state_windows[rule.id][group_key]
            if len(current_window) >= rule.detection.threshold:
                # Check suppression cooldown
                suppression_key = f"{rule.id}:{group_key}"
                last_time = self.last_alerted.get(suppression_key)
                if last_time and (now - last_time).total_seconds() < self.suppression_window_seconds:
                    continue  # suppress duplicate alert storm

                self.last_alerted[suppression_key] = now
                evidence_events = [ev for (_, ev) in current_window]
                alert = self._create_alert(rule, evidence_events)
                alerts.append(alert)

                # Reset window after triggering
                self.state_windows[rule.id][group_key] = []

        return alerts

    def _check_conditions(self, logic: DetectionLogic, event: NormalizedEvent) -> bool:
        """Tests whether an event satisfies the conditions in DetectionLogic."""
        results = []
        for cond in logic.conditions:
            val = getattr(event, cond.field, None)
            if val is None and cond.field in event.metadata:
                val = event.metadata.get(cond.field)
            if not val and cond.field == "process_command_line":
                val = event.raw_log

            matched = self._eval_single_condition(val, cond.operator, cond.value)
            results.append(matched)

        if not results:
            return False

        if logic.condition_logic == "any":
            return any(results)
        return all(results)

    def _eval_single_condition(self, field_val: Any, op: str, expected_val: Any) -> bool:
        """Evaluates an individual operator condition."""
        if op == "exists":
            return field_val is not None and field_val != ""

        if field_val is None:
            return False

        s_field = str(field_val).lower()
        s_expected = str(expected_val).lower()

        if op == "equals":
            return s_field == s_expected
        elif op == "not_equals":
            return s_field != s_expected
        elif op == "contains":
            return s_expected in s_field
        elif op == "not_contains":
            return s_expected not in s_field
        elif op == "regex":
            try:
                return bool(re.search(expected_val, str(field_val), re.IGNORECASE))
            except Exception:
                return False
        elif op == "in_list":
            if isinstance(expected_val, list):
                return any(str(x).lower() == s_field for x in expected_val)
            return s_field in s_expected
        elif op == "greater_than":
            try:
                return float(field_val) > float(expected_val)
            except Exception:
                return False
        elif op == "less_than":
            try:
                return float(field_val) < float(expected_val)
            except Exception:
                return False

        return False

    def _get_group_key(self, group_by_fields: List[str], event: NormalizedEvent) -> str:
        if not group_by_fields:
            return "global"
        parts = []
        for field in group_by_fields:
            val = getattr(event, field, None)
            parts.append(str(val or "unknown"))
        return ":".join(parts)

    def _create_alert(self, rule: DetectionRule, evidence: List[NormalizedEvent]) -> Alert:
        latest = evidence[-1]
        entities = {
            "src_ip": latest.src_ip,
            "dest_ip": latest.dest_ip,
            "user": latest.actor_user,
            "hostname": latest.hostname,
            "process_name": latest.process_name,
        }
        # Filter None entities
        entities = {k: v for k, v in entities.items() if v is not None}

        return Alert(
            rule_id=rule.id,
            rule_title=rule.title,
            severity=rule.severity,
            category=rule.category,
            mitre_attack={
                "tactic": rule.mitre_attack.tactic,
                "technique_id": rule.mitre_attack.technique_id,
                "technique_name": rule.mitre_attack.technique_name
            },
            entities=entities,
            event_count=len(evidence),
            evidence_event_ids=[e.event_id for e in evidence],
            evidence_events=[e.model_dump(mode="json") for e in evidence],
            recommended_response=rule.recommended_response,
            soar_playbook=rule.soar_playbook
        )
