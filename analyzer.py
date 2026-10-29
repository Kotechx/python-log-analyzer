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
            if alert["user"] == ground_truth["user"] and alert["ip"] == ground_truth["ip_address"]:
                detected = True
                break
    if detected:
        print("Attack detected successfully")
    else:
        print("Attack not detected")
    return detected

if __name__ == "__main__":
    logs = load_ssh_logs("sample_logs/auth.log")
    grouped = group_failed_logins_by_user_ip(logs)
    alerts = detect_brute_force(grouped)
    print(alerts)
    validate_against_ground_truth(alerts, "sample_logs/ground_truth.json")