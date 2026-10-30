from analyzer import parse_ssh_line

def test_parse_ssh_line_extracts_failed_status():
    line = "Oct 31 20:59:11 linux-target sshd[1234]: Failed password for root from 203.0.113.45 port 51000 ssh2"
    result = parse_ssh_line(line)
    assert result["status"] == "Failed"
    assert result["user"] == "root"
    assert result["ip"] == "203.0.113.45"