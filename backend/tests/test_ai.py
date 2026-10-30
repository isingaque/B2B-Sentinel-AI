from types import SimpleNamespace
from app.ai import classify, embed, pick_runbooks

DATA = [
 ("HighCPUUsage", "CPU utilization exceeded 95% on server", "server", "critical"),
 ("LowDiskSpace", "disk filesystem free space below 10%", "server", "warning"),
 ("HighMemory", "memory ram usage high", "server", "warning"),
 ("ServerFailure", "server node is down and unavailable", "server", "critical"),
 ("CPULoad", "cpu load average increased", "server", "warning"),
 ("DiskSpace", "filesystem usage 90%", "server", "warning"),
 ("PacketLoss", "network packet loss over 15%", "network", "warning"),
 ("NetworkDown", "network gateway is unavailable", "network", "critical"),
 ("RouterFailure", "router down on production network", "network", "critical"),
 ("DNSFailure", "dns unavailable on network", "network", "critical"),
 ("InterfaceLatency", "network interface high latency", "network", "warning"),
 ("LinkError", "network packet loss warning", "network", "warning"),
 ("PostgreSQLDown", "postgres database connection refused", "database", "critical"),
 ("DatabaseSlow", "database sql query high latency", "database", "warning"),
 ("MySQLDown", "mysql database down", "database", "critical"),
 ("DBConnection", "database connection refused", "database", "critical"),
 ("ReplicationLag", "postgres replica high lag", "database", "warning"),
 ("SQLWarning", "sql query slow warning", "database", "warning"),
 ("NginxDown", "nginx service down http 502", "application", "critical"),
 ("APIDown", "api backend http 503 unavailable", "application", "critical"),
 ("NginxLatency", "nginx http request high latency", "application", "warning"),
 ("AppError", "application exception errors increased", "application", "info"),
 ("HTTPWarning", "frontend app HTTP warning threshold", "application", "warning"),
 ("ServiceOutage", "application nginx not responding", "application", "critical"),
]

def test_classifier_benchmark():
    correct = 0
    for name, description, category, severity in DATA:
        result = classify({"alert_name":name,"description":description,"labels":{}})
        correct += result["category"] == category and result["severity"] == severity
    accuracy = correct / len(DATA)
    assert accuracy >= .90, f"Synthetic test accuracy: {accuracy:.1%}"

def test_prometheus_metadata_priority():
    got = classify({"alert_name":"Something", "labels":{"category":"network","severity":"critical"}})
    assert got["category"] == "network" and got["priority"] == "P1" and got["confidence"] >= .9

def test_embedding_is_fixed_and_normalized():
    vector = embed("PostgreSQL недоступен")
    assert len(vector) == 384
    assert 0.99 <= sum(x*x for x in vector) <= 1.01

def test_runbook_retrieval_and_empty_result():
    r = SimpleNamespace(is_active=True, category="database", severity="critical",
        title="PostgreSQL failure", condition_text="postgres connection refused database down",
        embedding=embed("PostgreSQL failure postgres connection refused database down"))
    alert={"alert_name":"PostgreSQLDown", "description":"postgres database connection refused", "labels":{}}
    cls=classify(alert)
    ranking=pick_runbooks(alert,cls,[r])
    assert ranking and ranking[0][0] is r
    assert pick_runbooks(alert,cls,[]) == []
