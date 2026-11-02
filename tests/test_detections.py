from datetime import datetime
from analyzer import (
    parse_ssh_line,
    detect_brute_force,
    detect_port_scan,
    detect_path_traversal,
    detect_impossible_travel,
    validate_coverage,
)

def test_parse_ssh_line_extracts_failed_status():
    line = "Oct 31 20:59:11 linux-target sshd[1234]: Failed password for root from 203.0.113.45 port 51000 ssh2"
    result = parse_ssh_line(line)
    assert result["status"] == "Failed"
    assert result["user"] == "root"
    assert result["ip"] == "203.0.113.45"

def test_detect_brute_force_finds_attack():
    # Arrange: build fake input data, no real file needed
    fake_logs = {
        ("root", "203.0.113.45"): [
            {"timestamp": datetime(2026, 1, 1, 10, 0, 0), "status": "Failed", "user": "root", "ip": "203.0.113.45"},
            {"timestamp": datetime(2026, 1, 1, 10, 0, 10), "status": "Failed", "user": "root", "ip": "203.0.113.45"},
            {"timestamp": datetime(2026, 1, 1, 10, 0, 20), "status": "Failed", "user": "root", "ip": "203.0.113.45"},
            {"timestamp": datetime(2026, 1, 1, 10, 0, 30), "status": "Failed", "user": "root", "ip": "203.0.113.45"},
            {"timestamp": datetime(2026, 1, 1, 10, 0, 40), "status": "Failed", "user": "root", "ip": "203.0.113.45"},
        ]
    }

    # Act: run the function under test
    alerts = detect_brute_force(fake_logs)

    # Assert: check the result
    assert len(alerts) == 1
    assert alerts[0]["mitre_attack_id"] == "T1110.001"

def test_detect_port_scan_finds_attack():
    # Arrange: build fake input data, no real file needed
    fake_logs = {
        "203.0.113.45": [
            {"timestamp": datetime(2026, 1, 1, 10, 0, 0), "ip": "203.0.113.45", "path": "/index.html", "status": "404"},
            {"timestamp": datetime(2026, 1, 1, 10, 0, 10), "ip": "203.0.113.45", "path": "/index.html", "status": "404"},
            {"timestamp": datetime(2026, 1, 1, 10, 0, 20), "ip": "203.0.113.45", "path": "/index.html", "status": "404"},
            {"timestamp": datetime(2026, 1, 1, 10, 0, 30), "ip": "203.0.113.45", "path": "/index.html", "status": "404"},
            {"timestamp": datetime(2026, 1, 1, 10, 0, 40), "ip": "203.0.113.45", "path": "/index.html", "status": "404"},
            {"timestamp": datetime(2026, 1, 1, 10, 0, 50), "ip": "203.0.113.45", "path": "/index.html", "status": "404"},
            {"timestamp": datetime(2026, 1, 1, 10, 1, 00), "ip": "203.0.113.45", "path": "/index.html", "status": "404"},
            {"timestamp": datetime(2026, 1, 1, 10, 1, 10), "ip": "203.0.113.45", "path": "/index.html", "status": "404"},
            {"timestamp": datetime(2026, 1, 1, 10, 1, 20), "ip": "203.0.113.45", "path": "/index.html", "status": "404"},
            {"timestamp": datetime(2026, 1, 1, 10, 1, 30), "ip": "203.0.113.45", "path": "/index.html", "status": "404"},
            {"timestamp": datetime(2026, 1, 1, 10, 1, 40), "ip": "203.0.113.45", "path": "/index.html", "status": "404"},
            {"timestamp": datetime(2026, 1, 1, 10, 1, 50), "ip": "203.0.113.45", "path": "/index.html", "status": "404"},
            {"timestamp": datetime(2026, 1, 1, 10, 2, 00), "ip": "203.0.113.45", "path": "/index.html", "status": "404"},
        ]
    }

    # Act: run the function under test
    alerts = detect_port_scan(fake_logs)

    # Assert: check the result
    assert len(alerts) == 1
    assert alerts[0]["mitre_attack_id"] == "T1595.002"

def test_detect_path_traversal_finds_attack():
    # Arrange: a list of requests, with at least one traversal path
    fake_logs = [
        {
            "timestamp": datetime(2026, 1, 1, 10, 0, 0),
            "ip": "203.0.113.45",
            "path": "/../../etc/passwd",
            "status": "200",
        }
    ]

    # Act: run the function under test
    alerts = detect_path_traversal(fake_logs)

    # Assert: at least one alert, tagged as file discovery
    assert len(alerts) >= 1
    assert alerts[0]["mitre_attack_id"] == "T1083"

def test_detect_impossible_travel_finds_attack():
    # Arrange: one user with two logins from different countries, close in time
    fake_logs = {
        "arthur": [
            {"timestamp": datetime(2026, 1, 1, 10, 0, 0), "ip": "203.0.113.200"},
            {"timestamp": datetime(2026, 1, 1, 10, 30, 0), "ip": "45.76.100.50"},
        ]
    }

    # Act: run the function under test
    alerts = detect_impossible_travel(fake_logs)

    # Assert: check the result
    assert len(alerts) == 1
    assert alerts[0]["mitre_attack_id"] == "T1078"

def test_detect_brute_force_ignores_stale_outlier():
    fake_logs = {
        ("root", "203.0.113.45"): [
            {"timestamp": datetime(2026, 1, 1, 10, 0, 0), "status": "Failed", "user": "root", "ip": "203.0.113.45"},
            {"timestamp": datetime(2026, 1, 1, 10, 0, 10), "status": "Failed", "user": "root", "ip": "203.0.113.45"},
            {"timestamp": datetime(2026, 1, 1, 10, 0, 20), "status": "Failed", "user": "root", "ip": "203.0.113.45"},
            {"timestamp": datetime(2026, 1, 1, 10, 0, 30), "status": "Failed", "user": "root", "ip": "203.0.113.45"},
            {"timestamp": datetime(2026, 1, 1, 10, 0, 40), "status": "Failed", "user": "root", "ip": "203.0.113.45"},
            {"timestamp": datetime(2026, 1, 1, 11, 30, 0), "status": "Failed", "user": "root", "ip": "203.0.113.45"}
        ]
    }

    # Act: run the function under test
    alerts = detect_brute_force(fake_logs)

    # Assert: check the result
    assert len(alerts) == 1

def test_detect_port_scan_ignores_stale_outlier():
    fake_logs = {
        "203.0.113.45": [
            {"timestamp": datetime(2026, 1, 1, 10, 0, 0), "ip": "203.0.113.45", "path": "/index.html", "status": "404"},
            {"timestamp": datetime(2026, 1, 1, 10, 0, 10), "ip": "203.0.113.45", "path": "/index.html", "status": "404"},
            {"timestamp": datetime(2026, 1, 1, 10, 0, 20), "ip": "203.0.113.45", "path": "/index.html", "status": "404"},
            {"timestamp": datetime(2026, 1, 1, 10, 0, 30), "ip": "203.0.113.45", "path": "/index.html", "status": "404"},
            {"timestamp": datetime(2026, 1, 1, 10, 0, 40), "ip": "203.0.113.45", "path": "/index.html", "status": "404"},
            {"timestamp": datetime(2026, 1, 1, 10, 0, 50), "ip": "203.0.113.45", "path": "/index.html", "status": "404"},
            {"timestamp": datetime(2026, 1, 1, 10, 1, 00), "ip": "203.0.113.45", "path": "/index.html", "status": "404"},
            {"timestamp": datetime(2026, 1, 1, 10, 1, 10), "ip": "203.0.113.45", "path": "/index.html", "status": "404"},
            {"timestamp": datetime(2026, 1, 1, 10, 1, 20), "ip": "203.0.113.45", "path": "/index.html", "status": "404"},
            {"timestamp": datetime(2026, 1, 1, 10, 1, 30), "ip": "203.0.113.45", "path": "/index.html", "status": "404"},
            {"timestamp": datetime(2026, 1, 1, 10, 27, 15), "ip": "203.0.113.45", "path": "/index.html", "status": "404"},
        ]
    }

    # Act: run the function under test
    alerts = detect_port_scan(fake_logs)

    # Assert: check the result
    assert len(alerts) == 1

def test_validate_coverage_detects_missed_attack():
    # Arrange: two brute-force attacks; the alert list only covers the first
    ground_truth = [
        {
            "attack_type": "brute_force",
            "mitre_attack_id": "T1110.001",
            "ip_address": "203.0.113.45",
            "user": "root",
        },
        {
            "attack_type": "brute_force",
            "mitre_attack_id": "T1110.001",
            "ip_address": "198.51.100.10",
            "user": "admin",
        },
    ]
    alerts = [
        {
            "rule_id": "BRUTE_SSH_LOGIN",
            "severity": "HIGH",
            "user": "root",
            "ip": "203.0.113.45",
            "failed_attempts": 5,
            "mitre_attack_id": "T1110.001",
        }
    ]

    # Act
    missed = validate_coverage(alerts, ground_truth)

    # Assert: the second attack was not covered
    assert len(missed) == 1

