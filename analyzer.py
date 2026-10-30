import json
from datetime import datetime

def parse_ssh_line(line):
    parts = line.split()
    text_with_year = "2026 " + parts[0] + " " + parts[1] + " " + parts[2]
    timestamp = datetime.strptime(text_with_year, "%Y %b %d %H:%M:%S")
    status = parts[5]
    user = parts[8]
    ip = parts[10]
    return {
        "timestamp": timestamp,
        "status": status,
        "user": user,
        "ip": ip,
    }

def load_ssh_logs(file_path):
    parsed_lines = []
    with open(file_path, "r") as f:
        for line in f:
            line_clean = line.strip()
            parsed_line = parse_ssh_line(line_clean)
            parsed_lines.append(parsed_line)
    return parsed_lines


def group_failed_logins_by_user_ip(logs):
    grouped_logs = {}
    for log in logs:
        key = (log["user"], log["ip"])
        if log["status"] == "Failed":
            if key not in grouped_logs:
                grouped_logs[key] = []
            grouped_logs[key].append(log)
    return grouped_logs

def detect_brute_force(grouped_logs, threshold=5, window_minutes=10):
    alerts = []
    for key, failures in grouped_logs.items():
        user, ip = key
        if len(failures) >= threshold:
            first_timestamp = failures[0]["timestamp"]
            last_timestamp = failures[-1]["timestamp"]
            duration = (last_timestamp - first_timestamp).total_seconds()
            if duration <= window_minutes * 60:
                alerts.append({
                    "rule_id": "BRUTE_SSH_LOGIN",
                    "severity": "HIGH",
                    "user": user,
                    "ip": ip,
                    "failed_attempts": len(failures),
                    "mitre_attack_id": "T1110.001",
                })
    return alerts

def validate_against_ground_truth(alerts, ground_truth_path):
    with open(ground_truth_path, "r") as f:
        ground_truth = json.load(f)
    detected = False
    for alert in alerts:
        for gt in ground_truth:
            if alert["ip"] == gt["ip_address"] and alert["mitre_attack_id"] == gt["mitre_attack_id"]:
                detected = True
                break
    if detected:
        print("Attack detected successfully")
    else:
        print("Attack not detected")
    return detected

def parse_nginx_line(line):
    parts = line.split()
    ip = parts[0]
    path = parts[5]
    status = parts[7]
    timestamp = datetime.strptime(parts[3].strip("[]"), "%d/%b/%Y:%H:%M:%S")
    return {
        "timestamp": timestamp,
        "ip": ip,
        "path": path,
        "status": status,
    }

def load_nginx_logs(file_path):
    parsed_lines = []
    with open(file_path, "r") as f:
        for line in f:
            line_clean = line.strip()
            parsed_line = parse_nginx_line(line_clean)
            parsed_lines.append(parsed_line)
    return parsed_lines

def group_requests_by_ip(logs):
    grouped_logs = {}
    for log in logs:
        key = log["ip"]
        if key not in grouped_logs:
            grouped_logs[key] = []
        grouped_logs[key].append(log)
    return grouped_logs

def detect_port_scan(grouped_logs, threshold=10, window_minutes=5):
    alerts = []
    for ip, requests in grouped_logs.items():
        fails_404 =[]
        for request in requests:
            if request["status"] == "404":
                fails_404.append(request)
        if len(fails_404) >= threshold:
            first_timestamp = fails_404[0]["timestamp"]
            last_timestamp = fails_404[-1]["timestamp"]
            duration = (last_timestamp - first_timestamp).total_seconds()
            if duration <= window_minutes * 60:
                alerts.append({
                    "rule_id": "PORT_SCAN",
                    "severity": "HIGH",
                    "ip": ip,
                    "scan_count": len(fails_404),
                    "mitre_attack_id": "T1595.002",
        })
    return alerts

def detect_path_traversal(nginx_logs):
    alerts = []
    for log in nginx_logs:
        if "../" in log["path"] or "%2f" in log["path"]:
            alerts.append({
                "rule_id": "PATH_TRAVERSAL",
                "severity": "HIGH",
                "ip": log["ip"],
                "path": log["path"],
                "mitre_attack_id": "T1083",
            })
    return alerts

if __name__ == "__main__":
    logs = load_ssh_logs("sample_logs/auth.log")
    grouped = group_failed_logins_by_user_ip(logs)
    alerts = detect_brute_force(grouped)
    print(alerts)
    validate_against_ground_truth(alerts, "sample_logs/ground_truth.json")

    nginx_logs = load_nginx_logs("sample_logs/access.log")
    print(f"Loaded {len(nginx_logs)} nginx lines")
    print(nginx_logs[0])

    grouped_web = group_requests_by_ip(nginx_logs)
    print(grouped_web.keys())
    for ip, requests in grouped_web.items():
        print(ip, len(requests))

    nginx_logs = load_nginx_logs("sample_logs/access.log")
    grouped_web = group_requests_by_ip(nginx_logs)
    scan_alerts = detect_port_scan(grouped_web)
    print(scan_alerts) 
    validate_against_ground_truth(scan_alerts, "sample_logs/ground_truth.json")

    traversal_alerts = detect_path_traversal(nginx_logs)
    print(traversal_alerts)
    validate_against_ground_truth(traversal_alerts, "sample_logs/ground_truth.json")

    