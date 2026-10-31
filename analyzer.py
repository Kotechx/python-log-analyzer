import json
from datetime import datetime


IP_COUNTRY_MAP = {
    "203.0.113.200": "Canada",
    "45.76.100.50": "Russia",
    "192.168.1.50": "Canada",
}

def get_country_from_ip(ip):
    return IP_COUNTRY_MAP.get(ip, "Unknown")

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
            for i in range(len(failures)):
                if i >= threshold - 1:
                    window_start = failures[i - (threshold - 1)]["timestamp"]
                    window_end = failures[i]["timestamp"]
                    duration = (window_end - window_start).total_seconds()
                    if duration <= window_minutes * 60:
                        alerts.append({
                            "rule_id": "BRUTE_SSH_LOGIN",
                            "severity": "HIGH",
                            "user": user,
                            "ip": ip,
                            "failed_attempts": threshold,
                            "mitre_attack_id": "T1110.001",
                        })
                        break
    return alerts

def validate_against_ground_truth(alerts, ground_truth_path):
    with open(ground_truth_path, "r") as f:
        ground_truth = json.load(f)
    detected = False
    for alert in alerts:
        for gt in ground_truth:
            same_mitre = alert.get("mitre_attack_id") == gt.get("mitre_attack_id")
            same_ip = alert.get("ip") is not None and alert.get("ip") == gt.get("ip_address")
            same_user = alert.get("user") is not None and alert.get("user") == gt.get("user")
            if same_mitre and (same_ip or same_user):
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

def group_successful_logins_by_user(logs):
    grouped_logs = {}
    for log in logs:
        if log["status"] == "Accepted":
            key = log["user"]
            if key not in grouped_logs:
                grouped_logs[key] = []
            grouped_logs[key].append(log)
    return grouped_logs

def detect_impossible_travel(grouped_users,window_minutes=60):
    alerts = []
    for user, logins in grouped_users.items():
        for i in range(len(logins)):
            for j in range(i+1, len(logins)):
                login1 = logins[i]
                login2 = logins[j]
                different_ip = login1["ip"] != login2["ip"]
                different_country = get_country_from_ip(login1["ip"]) != get_country_from_ip(login2["ip"])
                within_window = abs((login2["timestamp"] - login1["timestamp"]).total_seconds()) <= window_minutes * 60
                if different_ip and different_country and within_window:
                    alerts.append({
                        "rule_id": "IMPOSSIBLE_TRAVEL",
                        "severity": "HIGH",
                        "user": user,
                        "ip1": login1["ip"],
                        "ip2": login2["ip"],
                        "mitre_attack_id": "T1078",
                    })
    return alerts

if __name__ == "__main__":
    # Load both log sources once
    ssh_logs = load_ssh_logs("sample_logs/auth.log")
    nginx_logs = load_nginx_logs("sample_logs/access.log")

    # Group data the way each detection needs it
    failed_by_user_ip = group_failed_logins_by_user_ip(ssh_logs)
    successful_by_user = group_successful_logins_by_user(ssh_logs)
    requests_by_ip = group_requests_by_ip(nginx_logs)

    # Run the four detections
    brute_force_alerts = detect_brute_force(failed_by_user_ip)
    scan_alerts = detect_port_scan(requests_by_ip)
    traversal_alerts = detect_path_traversal(nginx_logs)
    travel_alerts = detect_impossible_travel(successful_by_user)

    # Combine all alerts and save to a file
    all_alerts = brute_force_alerts + scan_alerts + traversal_alerts + travel_alerts
    with open("alerts.json", "w") as f:
        json.dump(all_alerts, f, indent=2)

    # Validate each detection against the ground truth
    print("--- Validation against ground truth ---")
    validate_against_ground_truth(brute_force_alerts, "sample_logs/ground_truth.json")
    validate_against_ground_truth(scan_alerts, "sample_logs/ground_truth.json")
    validate_against_ground_truth(traversal_alerts, "sample_logs/ground_truth.json")
    validate_against_ground_truth(travel_alerts, "sample_logs/ground_truth.json")

    print(f"\n{len(all_alerts)} alerts written to alerts.json")