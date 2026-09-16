from codeguard.severity import Severity
from codeguard.tools.diff_position import map_finding_to_diff_position
from codeguard.tools.models import Finding


def test_maps_finding_line_and_path_directly_to_right_side():
    finding = Finding.create(file="app/db.py", start_line=12, end_line=12, severity=Severity.HIGH,
                              source_tool="bandit", rule_id="B608", message="sql injection")
    pos = map_finding_to_diff_position(finding)
    assert pos.path == "app/db.py"
    assert pos.line == 12
    assert pos.side == "RIGHT"
