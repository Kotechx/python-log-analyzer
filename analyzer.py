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

if __name__ == "__main__":
    test_line = "Oct 31 20:59:11 linux-target sshd[1234]: Failed password for root from 203.0.113.45 port 51000 ssh2"
    result = parse_ssh_line(test_line)
    print(result)