import os, random
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




if __name__ == "__main__":
    os.makedirs("sample_logs", exist_ok=True)
    burst = generate_brute_force_burst(datetime.now(), "root", "203.0.113.45")
    for line in burst:
        print(line)

    with open("sample_logs/auth.log", "w") as f:
        for line in burst:
            f.write(line + "\n")

    
    normal = generate_normal_logs(datetime.now(), 2)
    for line in normal:
        print(line)
