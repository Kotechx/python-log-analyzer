import os, random, json
from datetime import datetime, timedelta

def ssh_failed_line(timestamp, user, ip):
    formatted_time = timestamp.strftime("%b %d %H:%M:%S")
    return f"{formatted_time} linux-target sshd[1234]: Failed password for {user} from {ip} port 51000 ssh2"

def ssh_accepted_line(timestamp, user, ip):
    formatted_time = timestamp.strftime("%b %d %H:%M:%S")
    return f"{formatted_time} linux-target sshd[1234]: Accepted password for {user} from {ip} port 51003 ssh2"

def generate_brute_force_burst(start_time,user,ip):
    lines = []
    for i in range(5):
        timestamp = start_time + timedelta(seconds=i*10)
        line = ssh_failed_line(timestamp, user, ip)
        lines.append(line)
        
    current_time = timestamp + timedelta(seconds=10)
    line = ssh_accepted_line(current_time, user, ip)
    lines.append(line)

    return lines

def generate_normal_logs(start_time,num_days):
    list_of_lines = []
    list_of_users = ["root", "admin", "user", "test", "guest"]
    ip_address = "192.168.1.50"
    for i in range(num_days):
        for j in range(3):
            user = random.choice(list_of_users)
            timestamp = start_time + timedelta(days=i, hours=j)
            line = ssh_accepted_line(timestamp, user, ip_address)
            list_of_lines.append(line)

    return list_of_lines



def nginx_line(timestamp, ip, path, status):
    formatted_time = timestamp.strftime("%d/%b/%Y:%H:%M:%S")
    return f"{ip} - - [{formatted_time}] \"GET {path} HTTP/1.1\" {status} 512"
    
def generate_scan_burst(start_time, ip):
    lines = []
    for i in range(20):
        timestamp = start_time + timedelta(seconds=i*2)
        path = f"/path{i}"
        line = nginx_line(timestamp, ip, path, 404)
        lines.append(line)
    return lines

def generate_normal_web_traffic(start_time, num_days):
    lines = []
    for i in range(num_days):
        for j in range(5):
            timestamp = start_time + timedelta(days=i, hours=j)
            common_path = random.choice(["/index.html", "/login.php", "/logout.php", "/register.php", "/user.php"])
            line = nginx_line(timestamp, "192.168.1.50", common_path, 200)
            lines.append(line)
    return lines

def generate_traversal_burst(start_time, ip):
    lines = []
    paths = ["/../../../etc/passwd", "/../../../../etc/shadow", "/..%2f..%2f..%2fetc%2fpasswd"]
    for i in range(len(paths)):
        timestamp = start_time + timedelta(seconds=i*5)
        path = paths[i]
        line = nginx_line(timestamp, ip, path, 403)
        lines.append(line)
    return lines



if __name__ == "__main__":
    os.makedirs("sample_logs", exist_ok=True)
    start_time = datetime.now()
    attack_time = start_time + timedelta(days=3, hours=2)
    scan_time = start_time + timedelta(days=5, hours=3)
    traversal_time = start_time + timedelta(days=6, hours=1)
    burst = generate_brute_force_burst(attack_time, "root", "203.0.113.45")
    normal = generate_normal_logs(start_time, 7)
    scan_burst = generate_scan_burst(scan_time, "198.51.100.23")
    web_normal = generate_normal_web_traffic(start_time, 7)
    traversal_burst = generate_traversal_burst(traversal_time, "203.0.113.99")
    ground_truth = [
        {"attack_type": "brute_force","mitre_attack_id": "T1110.001","ip_address": "203.0.113.45","user": "root","start_time": attack_time.isoformat()},
        {"attack_type": "port_scan","mitre_attack_id": "T1595.002","ip_address": "198.51.100.23","start_time": scan_time.isoformat()},
        {"attack_type": "path_traversal", "mitre_attack_id": "T1083", "ip_address": "203.0.113.99", "start_time": traversal_time.isoformat()}
    ]
    with open("sample_logs/auth.log", "w") as f:
        for line in burst + normal:
            f.write(line + "\n")

    with open("sample_logs/access.log", "w") as f:
        for line in scan_burst + web_normal + traversal_burst:
            f.write(line + "\n")

    with open("sample_logs/ground_truth.json", "w") as f:
        json.dump(ground_truth, f, indent=2)

    


    

    
    
    

    


