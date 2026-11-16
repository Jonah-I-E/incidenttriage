"""Builds data/labeled_alerts.json: synthetic sample alerts with known category/severity/team.
Labels live under "label" and are never shown to the analyzer."""
import json
from pathlib import Path

T = "2026-11-16T09:{:02d}:00Z"
rows = []
def g(i, service, message, err=None, sev=None, host=None, *, cat, pri, team=None, dup_of=None):
    rows.append({"alert_id": f"A{i:03d}", "source": "datadog", "timestamp": T.format(i % 60), "service": service,
                 "host": host or f"{service}-01", "message": message, "error_details": err, "severity": sev,
                 "label": {"category": cat, "severity": pri, "team": team, "duplicate_of": dup_of}})
def prom(i, alertname, service, summary, desc, sev, *, cat, pri, team=None):
    rows.append({"fingerprint": f"P{i:03d}", "startsAt": T.format(i % 60),
                 "labels": {"alertname": alertname, "service": service, "instance": f"{service}-node{i}", "severity": sev},
                 "annotations": {"summary": summary, "description": desc},
                 "label": {"category": cat, "severity": pri, "team": team}})
def ticket(i, subject, body, service="unknown", *, cat, pri, team=None):
    rows.append({"ticket_id": f"T{i:03d}", "created_at": T.format(i % 60), "subject": subject, "body": body,
                 "service": service, "reporter": "helpdesk",
                 "label": {"category": cat, "severity": pri, "team": team}})

# network
g(1, "edge-router", "BGP session to upstream ISP-B down", "neighbor 203.0.113.9 state Idle", "critical", cat="network", pri="critical")
g(2, "office-vpn", "VPN tunnel flapping between HQ and DC2", "IKE SA renegotiated 14 times in 10m", "warning", cat="network", pri="medium")
prom(3, "PacketLoss", "core-switch", "Packet loss 12% on uplink eth1/49", "Sustained packet loss over 5 minutes", "warning", cat="network", pri="high")
g(4, "dns", "NXDOMAIN responses for internal zone corp.local spiking", "resolver ns2 returning NXDOMAIN for 40% of queries", "error", cat="network", pri="high")
g(5, "dns", "Stale DNS cache on app-07 after record change", "resolver still returns old IP", "warning", cat="network", pri="low")
# database
g(6, "orders-db", "PostgreSQL replication lag 340s on replica-2", "WAL replay behind primary", "warning", cat="database", pri="medium")
g(7, "orders-db", "Primary database unreachable - orders-db primary down", "connection refused on 5432; failover not triggered", "critical", cat="database", pri="critical")
prom(8, "MySQLTooManyConnections", "billing-mysql", "MySQL too many connections", "max_connections 500 reached, new connections rejected", "critical", cat="database", pri="high")
g(9, "inventory-db", "Deadlock detected in inventory update transaction", "ERROR: deadlock detected, process 4411 waits for ShareLock", "error", cat="database", pri="high")
g(10, "analytics-db", "Slow query warning: report query took 48s", "SELECT ... FROM events GROUP BY ...", "warning", cat="database", pri="low")
# application
g(11, "checkout-api", "HTTP 500 error rate above 25% on /checkout", "NullPointerException in PaymentService.charge", "error", cat="application", pri="critical")
g(12, "user-service", "Unhandled exception in profile update endpoint", "Traceback ... KeyError: 'avatar_url'", "error", cat="application", pri="medium")
prom(13, "PodCrashLooping", "notification-svc", "notification-svc pod in CrashLoopBackOff", "Container exited with code 1: panic: nil map assignment", "critical", cat="application", pri="high")
ticket(14, "Login page shows 'Something went wrong'", "Several users report the login page throws an internal server error since this morning's deploy.", "auth-web", cat="application", pri="high")
g(15, "search-api", "Deployment failed health check, rollback completed", "readiness probe failed for v2.3.1; previous version restored", "warning", cat="application", pri="low")
# performance
g(16, "catalog-api", "p99 latency above 2.5s for 10 minutes", "baseline 300ms", "warning", cat="performance", pri="high")
g(17, "email-worker", "Queue backlog: email worker stuck, 12k messages pending", "consumer not processing since 08:51", "warning", cat="performance", pri="medium")
prom(18, "KafkaConsumerLag", "events-pipeline", "Consumer lag rising on topic clicks", "lag 250k messages and increasing", "warning", cat="performance", pri="medium")
g(19, "web-frontend", "Apdex dropped to 0.71 on product pages", "slow page render, TTFB 1.9s", "warning", cat="performance", pri="medium")
g(20, "reports", "Slow response time on monthly report endpoint", "average 6s vs 2s baseline, internal users only", "info", cat="performance", pri="low")
# security
g(21, "bastion", "Brute force: 1,240 failed SSH login attempts from 198.51.100.23", "sshd: Failed password for root", "warning", cat="security", pri="high")
g(22, "endpoint-av", "Ransomware behavior detected on FIN-LAPTOP-22", "mass file rename *.locked; process quarantined", "critical", cat="security", pri="critical")
prom(23, "WAFBlockSpike", "public-web", "WAF blocked 3k SQL injection attempts", "Requests blocked by rule 942100 from multiple IPs", "warning", cat="security", pri="medium")
ticket(24, "Suspicious email with invoice attachment", "An employee forwarded a suspicious email asking to enable macros. Nobody opened it.", cat="security", pri="low")
g(25, "iam", "Unauthorized access attempt to admin API with revoked token", "403 for token issued to former contractor", "error", cat="security", pri="high")
# infrastructure
g(26, "web-07", "Disk usage at 88% on /var", "filesystem /var 88% used", "warning", host="web-07", cat="infrastructure", pri="medium")
g(27, "db-backup", "Nightly backup job failed for file server", "rsync exit code 23", "error", cat="infrastructure", pri="medium")
prom(28, "KubeNodeNotReady", "k8s", "Node worker-12 NotReady", "kubelet stopped posting node status", "warning", cat="infrastructure", pri="high")
g(29, "batch-03", "No space left on device writing to /data", "filesystem /data 100% used, jobs failing", "critical", cat="infrastructure", pri="high")
g(30, "lb-cert", "TLS certificate for api.example.com expiring in 21 days", None, "info", cat="infrastructure", pri="low")
g(31, "hv-02", "Redundant power supply failure on hypervisor hv-02", "PSU2 status: failed, PSU1 OK", "warning", cat="infrastructure", pri="medium")
g(32, "app-12", "Kernel panic, host rebooted unexpectedly", "kernel BUG at mm/slub.c", "critical", cat="infrastructure", pri="high")
# ambiguous -> human review expected
ticket(33, "Something is weird with the system", "Things feel off today, not sure what. Can someone take a look?", cat="unknown", pri="low", team="Triage Desk")
g(34, "misc", "Check status", "heartbeat missing value", None, cat="unknown", pri="low", team="Triage Desk")
ticket(35, "Customer says app 'not working'", "Customer on phone says the app is not working for them, no other details.", cat="unknown", pri="medium", team="Triage Desk")
# duplicates of A011 and A026 within the window (should be folded)
for k, base in enumerate(["A011", "A011", "A011", "A026"]):
    src = next(r for r in rows if r.get("alert_id") == base)
    d = dict(src, alert_id=f"D{k:03d}", timestamp=src["timestamp"].replace(":00Z", f":{10+k}Z"),
             label=dict(src["label"], duplicate_of=base))
    if base == "A011": d["message"] = "HTTP 500 error rate above 31% on /checkout"
    rows.append(d)

TEAM = {"network": "Network Operations", "database": "Database Team", "application": "Application On-Call",
        "performance": "SRE", "security": "Security Operations", "infrastructure": "Infrastructure / Platform"}
for r in rows:
    r["label"]["team"] = r["label"]["team"] or TEAM[r["label"]["category"]]
Path(__file__).with_name("labeled_alerts.json").write_text(json.dumps(rows, indent=1))
print(len(rows), "alerts written")
