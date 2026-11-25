"""Amostras sintéticas e artefatos derivados do laboratório Sentinel."""

from __future__ import annotations

import csv
import io
import ipaddress
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SAMPLE_DIR = ROOT / "sample-data"
RUNNABLE_DIR = SAMPLE_DIR / "runnable"
ADX_PATH = SAMPLE_DIR / "adx" / "create-and-ingest.kql"
ARM_DIR = ROOT / "detections" / "arm"
KQL_BUILD = ROOT / ".kql-build"

TABLES = (
    "SigninLogs",
    "AuditLogs",
    "SecurityEvent",
    "CommonSecurityLog",
    "UrlClickEvents",
)

LAB_TABLE = {
    "SigninLogs": "LabSigninLogs",
    "AuditLogs": "LabAuditLogs",
    "SecurityEvent": "LabSecurityEvent",
    "CommonSecurityLog": "LabCommonSecurityLog",
    "UrlClickEvents": "LabUrlClickEvents",
}

SIGNIN_COLUMNS = [
    "TimeGenerated",
    "UserPrincipalName",
    "UserDisplayName",
    "AppDisplayName",
    "IPAddress",
    "Location",
    "ResultType",
    "ResultDescription",
    "ClientAppUsed",
    "UserAgent",
    "AuthenticationRequirement",
    "ConditionalAccessStatus",
]

SECURITY_COLUMNS = [
    "TimeGenerated",
    "EventID",
    "Computer",
    "Account",
    "AccountType",
    "Activity",
    "LogonType",
    "IpAddress",
    "WorkstationName",
    "Process",
    "CommandLine",
    "ObjectName",
    "AccessList",
    "AccessMask",
]

CEF_COLUMNS = [
    "TimeGenerated",
    "DeviceVendor",
    "DeviceProduct",
    "DeviceAction",
    "SourceIP",
    "DestinationIP",
    "SourcePort",
    "DestinationPort",
    "Protocol",
    "SentBytes",
    "ReceivedBytes",
    "SourceUserName",
    "DeviceName",
]

AUDIT_COLUMNS = [
    "TimeGenerated",
    "Category",
    "OperationName",
    "Result",
    "CorrelationId",
    "InitiatedBy",
    "TargetResources",
]

URL_COLUMNS = [
    "TimeGenerated",
    "AccountUpn",
    "Url",
    "ActionType",
    "IPAddress",
    "NetworkMessageId",
    "Workload",
]

COLUMN_TYPES = {
    "TimeGenerated": "datetime",
    "EventID": "long",
    "LogonType": "long",
    "SourcePort": "long",
    "DestinationPort": "long",
    "SentBytes": "long",
    "ReceivedBytes": "long",
    "InitiatedBy": "dynamic",
    "TargetResources": "dynamic",
}

SCHEMAS = {
    "SigninLogs": SIGNIN_COLUMNS,
    "SecurityEvent": SECURITY_COLUMNS,
    "CommonSecurityLog": CEF_COLUMNS,
    "AuditLogs": AUDIT_COLUMNS,
    "UrlClickEvents": URL_COLUMNS,
}

CSV_TABLES = (
    "SigninLogs",
    "SecurityEvent",
    "CommonSecurityLog",
    "UrlClickEvents",
)

FILE_STEM = {
    "SigninLogs": "signinlogs",
    "SecurityEvent": "securityevent",
    "CommonSecurityLog": "commonsecuritylog",
    "AuditLogs": "auditlogs",
    "UrlClickEvents": "urlclickevents",
}


def stamp(hour: int, minute: int, second: int = 0) -> str:
    return f"2026-03-16T{hour:02d}:{minute:02d}:{second:02d}Z"


def signin(
    when: str,
    upn: str,
    display: str,
    app: str,
    ip: str,
    location: str,
    result: str,
    client: str = "Browser",
) -> dict:
    description = "Sucesso" if result == "0" else "Falha de senha"
    return {
        "TimeGenerated": when,
        "UserPrincipalName": upn,
        "UserDisplayName": display,
        "AppDisplayName": app,
        "IPAddress": ip,
        "Location": location,
        "ResultType": result,
        "ResultDescription": description,
        "ClientAppUsed": client,
        "UserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "AuthenticationRequirement": "singleFactorAuthentication",
        "ConditionalAccessStatus": "notApplied",
    }


def security(**fields) -> dict:
    row = {column: "" for column in SECURITY_COLUMNS}
    row["EventID"] = 0
    row["LogonType"] = 0
    row.update(fields)
    return row


def cef(**fields) -> dict:
    row = {column: "" for column in CEF_COLUMNS}
    row["SourcePort"] = 0
    row["DestinationPort"] = 0
    row["SentBytes"] = 0
    row["ReceivedBytes"] = 0
    row["DeviceVendor"] = "LabFirewall"
    row["DeviceProduct"] = "LabGateway"
    row["Protocol"] = "TCP"
    row["DeviceName"] = "fw-lab-01"
    row.update(fields)
    return row


def audit(when: str, result: str, correlation: str, actor: str, target: str, role: str) -> dict:
    return {
        "TimeGenerated": when,
        "Category": "RoleManagement",
        "OperationName": "Add member to role",
        "Result": result,
        "CorrelationId": correlation,
        "InitiatedBy": {"user": {"userPrincipalName": actor}},
        "TargetResources": [
            {"type": "User", "userPrincipalName": target, "displayName": target.split("@")[0]},
            {"type": "Role", "displayName": role},
        ],
    }


def build_samples() -> dict[str, list[dict]]:
    signins: list[dict] = []
    for index in range(12):
        signins.append(
            signin(
                stamp(8, 0, index),
                "ana.costa@contoso-lab.example",
                "Ana Costa",
                "Portal de Vendas" if index < 8 else "Correio",
                "203.0.113.10",
                "Brasil",
                "50126",
            )
        )
    signins.append(
        signin(
            stamp(8, 40),
            "ana.costa@contoso-lab.example",
            "Ana Costa",
            "Portal de Vendas",
            "192.0.2.10",
            "Brasil",
            "0",
        )
    )
    for index in range(1, 11):
        signins.append(
            signin(
                stamp(9, index),
                f"user{index:02d}@contoso-lab.example",
                f"Usuario {index:02d}",
                "Office 365",
                "198.51.100.23",
                "Estados Unidos",
                "50126",
            )
        )
    signins.append(
        signin(
            stamp(9, 30),
            "user04@contoso-lab.example",
            "Usuario 04",
            "Correio",
            "198.51.100.23",
            "Estados Unidos",
            "50126",
            client="IMAP4",
        )
    )
    for minute in (0, 2):
        signins.append(
            signin(
                stamp(10, minute),
                "bruno.lima@contoso-lab.example",
                "Bruno Lima",
                "Portal de Vendas",
                "192.0.2.30",
                "Brasil",
                "50126",
            )
        )
    signins.extend(
        [
            signin(stamp(11, 0), "carla.nunes@contoso-lab.example", "Carla Nunes", "Portal de Vendas", "192.0.2.20", "Brasil", "0"),
            signin(stamp(11, 35), "carla.nunes@contoso-lab.example", "Carla Nunes", "Portal de Vendas", "198.51.100.77", "Japao", "0"),
            signin(stamp(12, 0), "diego.souza@contoso-lab.example", "Diego Souza", "Portal de Vendas", "192.0.2.45", "Brasil", "0"),
            signin(stamp(22, 30), "diego.souza@contoso-lab.example", "Diego Souza", "Portal de Vendas", "198.51.100.90", "Portugal", "0"),
        ]
    )

    events: list[dict] = []
    for index in range(30):
        events.append(
            security(
                TimeGenerated=stamp(15, 10, index),
                EventID=4663,
                Computer="FS01.contoso-lab.example",
                Account="CONTOSO\\svc-backup",
                AccountType="User",
                Activity="4663 - An attempt was made to access an object.",
                ObjectName=f"\\\\FS01\\financeiro\\arquivo-{index:02d}.xlsx",
                AccessList="%%1537 DELETE",
                AccessMask="0x10000",
            )
        )
    for index, name in enumerate(("rascunho.tmp", "notas.tmp")):
        events.append(
            security(
                TimeGenerated=stamp(15, index),
                EventID=4663,
                Computer="WKS01.contoso-lab.example",
                Account="CONTOSO\\ana.costa",
                AccountType="User",
                Activity="4663 - An attempt was made to access an object.",
                ObjectName=f"\\\\WKS01\\temp\\{name}",
                AccessList="%%1537 DELETE",
                AccessMask="0x10000",
            )
        )
    events.extend(
        [
            security(
                TimeGenerated=stamp(10, 15),
                EventID=4624,
                Computer="WKS01.contoso-lab.example",
                Account="CONTOSO\\ana.costa",
                AccountType="User",
                Activity="4624 - An account was successfully logged on.",
                LogonType=10,
                IpAddress="192.0.2.10",
                WorkstationName="WKS01",
            ),
            security(
                TimeGenerated=stamp(23, 40),
                EventID=4624,
                Computer="WKS-ADM.contoso-lab.example",
                Account="CONTOSO\\admin.soc",
                AccountType="User",
                Activity="4624 - An account was successfully logged on.",
                LogonType=10,
                IpAddress="203.0.113.15",
                WorkstationName="WKS-ADM",
            ),
            security(
                TimeGenerated=stamp(23, 10),
                EventID=4624,
                Computer="WKS02.contoso-lab.example",
                Account="CONTOSO\\diego.souza",
                AccountType="User",
                Activity="4624 - An account was successfully logged on.",
                LogonType=2,
                IpAddress="10.10.10.8",
                WorkstationName="WKS02",
            ),
            security(
                TimeGenerated=stamp(11, 5),
                EventID=4688,
                Computer="FS01.contoso-lab.example",
                Account="CONTOSO\\svc-backup",
                AccountType="User",
                Activity="4688 - A new process has been created.",
                Process="powershell.exe",
                CommandLine="powershell.exe -File C:\\scripts\\backup.ps1",
            ),
            security(
                TimeGenerated=stamp(23, 50),
                EventID=4688,
                Computer="WKS01.contoso-lab.example",
                Account="CONTOSO\\ana.costa",
                AccountType="User",
                Activity="4688 - A new process has been created.",
                Process="powershell.exe",
                CommandLine="powershell.exe -nop -w hidden -enc SQBFAFgA",
            ),
        ]
    )

    flows: list[dict] = []
    for index in range(6):
        flows.append(
            cef(
                TimeGenerated=stamp(13, index),
                DeviceAction="Deny",
                SourceIP="203.0.113.40",
                DestinationIP="10.10.10.20",
                SourcePort=51000 + index,
                DestinationPort=3389,
            )
        )
    for index in range(2):
        flows.append(
            cef(
                TimeGenerated=stamp(13, 10 + index),
                DeviceAction="Deny",
                SourceIP="203.0.113.40",
                DestinationIP="10.10.10.20",
                SourcePort=52000 + index,
                DestinationPort=22,
            )
        )
    for index in range(3):
        flows.append(
            cef(
                TimeGenerated=stamp(13, 20 + index),
                DeviceAction="Allow",
                SourceIP="10.10.10.5",
                DestinationIP="10.10.10.20",
                SourcePort=53000 + index,
                DestinationPort=3389,
                SourceUserName="CONTOSO\\admin.soc",
            )
        )
    flows.extend(
        [
            cef(
                TimeGenerated=stamp(14, 5),
                DeviceAction="Allow",
                SourceIP="10.10.10.50",
                DestinationIP="203.0.113.80",
                SourcePort=54000,
                DestinationPort=443,
                SentBytes=250_000_000,
                ReceivedBytes=4096,
                SourceUserName="CONTOSO\\svc-backup",
            ),
            cef(
                TimeGenerated=stamp(14, 20),
                DeviceAction="Allow",
                SourceIP="10.10.10.50",
                DestinationIP="192.0.2.40",
                SourcePort=54001,
                DestinationPort=443,
                SentBytes=20_000,
                ReceivedBytes=800,
                SourceUserName="CONTOSO\\svc-backup",
            ),
        ]
    )

    audits = [
        audit(
            stamp(16, 0),
            "success",
            "lab-corr-0001",
            "admin.soc@contoso-lab.example",
            "bruno.lima@contoso-lab.example",
            "Global Administrator",
        ),
        audit(
            stamp(16, 30),
            "success",
            "lab-corr-0002",
            "admin.soc@contoso-lab.example",
            "estagiario.lab@contoso-lab.example",
            "Directory Readers",
        ),
        audit(
            stamp(16, 40),
            "failure",
            "lab-corr-0003",
            "admin.soc@contoso-lab.example",
            "carla.nunes@contoso-lab.example",
            "Security Administrator",
        ),
        audit(
            stamp(23, 10),
            "success",
            "lab-corr-0004",
            "admin.soc@contoso-lab.example",
            "diego.souza@contoso-lab.example",
            "User Administrator",
        ),
    ]

    clicks = [
        {
            "TimeGenerated": stamp(17, 0),
            "AccountUpn": "ana.costa@contoso-lab.example",
            "Url": "https://login-verify.example.xyz/mailbox",
            "ActionType": "ClickAllowed",
            "IPAddress": "192.0.2.10",
            "NetworkMessageId": "lab-msg-0001",
            "Workload": "Email",
        },
        {
            "TimeGenerated": stamp(17, 5),
            "AccountUpn": "bruno.lima@contoso-lab.example",
            "Url": "https://micr0soft-secure.top/login",
            "ActionType": "ClickAllowed",
            "IPAddress": "192.0.2.30",
            "NetworkMessageId": "lab-msg-0002",
            "Workload": "Email",
        },
        {
            "TimeGenerated": stamp(17, 10),
            "AccountUpn": "carla.nunes@contoso-lab.example",
            "Url": "https://fatura.example.ru/pay",
            "ActionType": "ClickBlocked",
            "IPAddress": "192.0.2.20",
            "NetworkMessageId": "lab-msg-0003",
            "Workload": "Email",
        },
        {
            "TimeGenerated": stamp(17, 20),
            "AccountUpn": "ana.costa@contoso-lab.example",
            "Url": "https://intranet.contoso-lab.example/portal",
            "ActionType": "ClickAllowed",
            "IPAddress": "192.0.2.10",
            "NetworkMessageId": "lab-msg-0004",
            "Workload": "Email",
        },
        {
            "TimeGenerated": stamp(17, 30),
            "AccountUpn": "diego.souza@contoso-lab.example",
            "Url": "https://learn.microsoft.com/pt-br/training",
            "ActionType": "ClickAllowed",
            "IPAddress": "192.0.2.45",
            "NetworkMessageId": "lab-msg-0005",
            "Workload": "Email",
        },
    ]

    return {
        "SigninLogs": signins,
        "SecurityEvent": events,
        "CommonSecurityLog": flows,
        "AuditLogs": audits,
        "UrlClickEvents": clicks,
    }


def kql_literal(value, column: str) -> str:
    kind = COLUMN_TYPES.get(column, "string")
    if kind == "datetime":
        return f"datetime({value})"
    if kind == "long":
        return str(int(value))
    if kind == "dynamic":
        payload = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
        return f"dynamic({payload})"
    text = str(value).replace("\\", "\\\\").replace('"', '\\"')
    return f'"{text}"'


def datatable_block(table: str, rows: list[dict]) -> str:
    columns = SCHEMAS[table]
    header = ",\n    ".join(f"{column}: {COLUMN_TYPES.get(column, 'string')}" for column in columns)
    body = []
    for row in rows:
        body.append("    " + ", ".join(kql_literal(row[column], column) for column in columns))
    joined = ",\n".join(body)
    return f"let {table} = datatable (\n    {header}\n)\n[\n{joined}\n];"


def referenced_tables(query: str) -> list[str]:
    found = []
    for table in TABLES:
        if re.search(rf"\b{table}\b", query):
            found.append(table)
    return found


def runnable_query(query: str, samples: dict[str, list[dict]]) -> str:
    blocks = [datatable_block(table, samples[table]) for table in referenced_tables(query)]
    header = (
        "// Consulta pronta para teste neste laboratório.\n"
        "// Os eventos são sintéticos. O let vale só para esta execução e não grava dados.\n"
    )
    return header + "\n".join(blocks) + "\n" + query.strip() + "\n"


def csv_text(rows: list[dict], columns: list[str]) -> str:
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=columns, extrasaction="ignore", lineterminator="\n")
    writer.writeheader()
    for row in rows:
        flat = {}
        for column in columns:
            value = row[column]
            if isinstance(value, (dict, list)):
                flat[column] = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
            else:
                flat[column] = value
        writer.writerow(flat)
    return buffer.getvalue()


def write_json(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(rows, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def write_csv(path: Path, rows: list[dict], columns: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            flat = {}
            for column in columns:
                value = row[column]
                if isinstance(value, (dict, list)):
                    flat[column] = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
                else:
                    flat[column] = value
            writer.writerow(flat)


def arm_template(rule: dict) -> dict:
    operators = {"gt": "GreaterThan", "lt": "LessThan", "eq": "Equal"}
    properties = {
        "displayName": rule["name"],
        "description": rule["description"].strip(),
        "severity": rule["severity"],
        "enabled": False,
        "query": rule["query"].strip(),
        "queryFrequency": iso_duration(rule["queryFrequency"]),
        "queryPeriod": iso_duration(rule["queryPeriod"]),
        "triggerOperator": operators[rule["triggerOperator"]],
        "triggerThreshold": rule["triggerThreshold"],
        "suppressionDuration": "PT1H",
        "suppressionEnabled": False,
        "tactics": rule["tactics"],
        "techniques": rule["relevantTechniques"],
        "entityMappings": rule["entityMappings"],
        "eventGroupingSettings": rule["eventGroupingSettings"],
        "incidentConfiguration": {
            "createIncident": True,
            "groupingConfiguration": {
                "enabled": False,
                "reopenClosedIncident": False,
                "lookbackDuration": "PT5H",
                "matchingMethod": "AllEntities",
                "groupByEntities": [],
                "groupByAlertDetails": [],
                "groupByCustomDetails": [],
            },
        },
    }
    if "customDetails" in rule:
        properties["customDetails"] = rule["customDetails"]
    if "alertDetailsOverride" in rule:
        properties["alertDetailsOverride"] = rule["alertDetailsOverride"]
    return {
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
        "contentVersion": "1.0.0.0",
        "parameters": {
            "workspaceName": {
                "type": "string",
                "metadata": {
                    "description": "Nome do workspace de Log Analytics do laboratório."
                },
            }
        },
        "resources": [
            {
                "type": "Microsoft.OperationalInsights/workspaces/providers/alertRules",
                "apiVersion": "2023-02-01-preview",
                "name": f"[concat(parameters('workspaceName'), '/Microsoft.SecurityInsights/', '{rule['id']}')]",
                "kind": "Scheduled",
                "properties": properties,
            }
        ],
    }


def iso_duration(span: str) -> str:
    amount = int(span[:-1])
    unit = span[-1]
    if unit == "m":
        return f"PT{amount}M"
    if unit == "h":
        return f"PT{amount}H"
    if unit == "d":
        return f"P{amount}D"
    raise ValueError(span)


def adx_script(samples: dict[str, list[dict]]) -> str:
    parts = [
        "// Comandos de controle para um cluster gratuito do Azure Data Explorer.",
        "// Os registros sao sinteticos e os nomes das tabelas levam o prefixo Lab.",
        "// Nao execute isto em um cluster de producao.",
        "",
    ]
    for table, rows in samples.items():
        lab_name = LAB_TABLE[table]
        columns = ", ".join(
            f"{column}: {COLUMN_TYPES.get(column, 'string')}" for column in SCHEMAS[table]
        )
        parts.append(f".create-merge table {lab_name} ({columns})")
        parts.append(f".ingest inline into table {lab_name} with (format=\"json\") <|")
        for row in rows:
            parts.append(json.dumps(row, ensure_ascii=False, separators=(",", ":")))
        parts.append("")
    return "\n".join(parts).rstrip() + "\n"


def generated_files(rules: list[tuple[str, dict]], hunts: list[tuple[str, dict]]) -> dict[Path, str]:
    samples = build_samples()
    files: dict[Path, str] = {}
    for table, rows in samples.items():
        stem = FILE_STEM[table]
        files[SAMPLE_DIR / f"{stem}.json"] = json.dumps(rows, ensure_ascii=False, indent=2) + "\n"
        if table in CSV_TABLES:
            # CSV e escrito a parte porque o comparador de texto usa o mesmo writer.
            pass
    files[ADX_PATH] = adx_script(samples)
    for table in CSV_TABLES:
        stem = FILE_STEM[table]
        files[SAMPLE_DIR / f"{stem}.csv"] = csv_text(samples[table], SCHEMAS[table])
    for stem, rule in rules:
        files[RUNNABLE_DIR / f"{stem}.kql"] = runnable_query(rule["query"], samples)
        files[ARM_DIR / f"{stem}.json"] = json.dumps(arm_template(rule), ensure_ascii=False, indent=2) + "\n"
    for stem, hunt in hunts:
        files[RUNNABLE_DIR / f"{stem}.kql"] = runnable_query(hunt["query"], samples)
    return files


def write_generated(rules: list[tuple[str, dict]], hunts: list[tuple[str, dict]]) -> None:
    for path, content in generated_files(rules, hunts).items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")


def check_generated(rules: list[tuple[str, dict]], hunts: list[tuple[str, dict]]) -> list[str]:
    errors = []
    expected = generated_files(rules, hunts)
    for path, content in expected.items():
        if not path.exists():
            errors.append(f"Arquivo gerado ausente: {path.relative_to(ROOT)}")
            continue
        current = path.read_text(encoding="utf-8")
        if current != content:
            errors.append(f"Arquivo gerado desatualizado: {path.relative_to(ROOT)}")
    return errors


def emit_kql_for_lint(documents: list[tuple[str, str]], workbook_queries: list[tuple[str, str]]) -> None:
    if KQL_BUILD.exists():
        for old in KQL_BUILD.rglob("*.kql"):
            old.unlink()
    for label, query in documents:
        path = KQL_BUILD / f"{label}.kql"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(query.strip() + "\n", encoding="utf-8")
    for label, query in workbook_queries:
        rendered = query.replace(
            "{TimeRange}",
            "between (datetime(2026-03-16T00:00:00Z) .. datetime(2026-03-17T00:00:00Z))",
        )
        path = KQL_BUILD / "workbook" / f"{label}.kql"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(rendered.strip() + "\n", encoding="utf-8")


def extract_int(query: str, name: str) -> int:
    match = re.search(rf"let {name} = (\d+);", query)
    if not match:
        raise ValueError(name)
    return int(match.group(1))


def extract_strings(query: str, name: str) -> list[str]:
    match = re.search(rf"let {name} = dynamic\(\[(.*?)\]\);", query, re.S)
    if not match:
        raise ValueError(name)
    return re.findall(r'"([^"]+)"', match.group(1))


def extract_ints(query: str, name: str) -> list[int]:
    match = re.search(rf"let {name} = dynamic\(\[(.*?)\]\);", query, re.S)
    if not match:
        raise ValueError(name)
    return [int(value) for value in re.findall(r"\d+", match.group(1))]


def _private(address: str) -> bool:
    # Espelha ipv4_is_private do Kusto (RFC 1918, loopback e link-local).
    # O ipaddress do Python tambem marca rede de documentacao como privada,
    # e essas redes sao de proposito tratadas como origem externa no laboratorio.
    ip = ipaddress.ip_address(address)
    networks = (
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("127.0.0.0/8"),
        ipaddress.ip_network("169.254.0.0/16"),
    )
    return any(ip in network for network in networks)


def _hour(value: str) -> int:
    return int(value[11:13])


def _minutes(later: str, earlier: str) -> int:
    def to_minutes(value: str) -> int:
        hour = int(value[11:13])
        minute = int(value[14:16])
        second = int(value[17:19])
        return hour * 60 + minute + (1 if second else 0) // 60

    return to_minutes(later) - to_minutes(earlier)


def assert_sample_behavior(rules: dict[str, dict], hunts: dict[str, dict]) -> list[str]:
    samples = build_samples()
    errors: list[str] = []
    signins = samples["SigninLogs"]
    events = samples["SecurityEvent"]
    flows = samples["CommonSecurityLog"]
    audits = samples["AuditLogs"]
    clicks = samples["UrlClickEvents"]

    def expect(name: str, actual, expected) -> None:
        if actual != expected:
            errors.append(f"Amostra nao fecha com {name}: obtido {actual}, esperado {expected}")

    failure = {"0", "50125", "50140"}
    brute_threshold = extract_int(rules["brute-force-signin"]["query"], "failureThreshold")
    grouped: dict[tuple[str, str], int] = {}
    for row in signins:
        if row["ResultType"] in failure or not row["UserPrincipalName"] or not row["IPAddress"]:
            continue
        key = (row["UserPrincipalName"], row["IPAddress"])
        grouped[key] = grouped.get(key, 0) + 1
    brute_hits = [key for key, count in grouped.items() if count >= brute_threshold]
    expect("forca bruta", brute_hits, [("ana.costa@contoso-lab.example", "203.0.113.10")])

    user_threshold = extract_int(rules["password-spray-signin"]["query"], "userThreshold")
    spray_threshold = extract_int(rules["password-spray-signin"]["query"], "failureThreshold")
    by_ip: dict[str, set[str]] = {}
    ip_count: dict[str, int] = {}
    for row in signins:
        if row["ResultType"] in failure or not row["IPAddress"] or not row["UserPrincipalName"]:
            continue
        by_ip.setdefault(row["IPAddress"], set()).add(row["UserPrincipalName"])
        ip_count[row["IPAddress"]] = ip_count.get(row["IPAddress"], 0) + 1
    spray_hits = [
        ip
        for ip, users in by_ip.items()
        if len(users) >= user_threshold and ip_count[ip] >= spray_threshold
    ]
    expect("password spray", spray_hits, ["198.51.100.23"])

    max_minutes = extract_int(rules["impossible-travel"]["query"], "maxMinutes")
    successes = [
        row
        for row in signins
        if row["ResultType"] == "0" and row["UserPrincipalName"] and row["Location"] and row["IPAddress"]
    ]
    successes.sort(key=lambda row: (row["UserPrincipalName"], row["TimeGenerated"]))
    travel = []
    for previous, current in zip(successes, successes[1:]):
        if previous["UserPrincipalName"] != current["UserPrincipalName"]:
            continue
        if previous["Location"] == current["Location"]:
            continue
        delta = _minutes(current["TimeGenerated"], previous["TimeGenerated"])
        if 0 <= delta <= max_minutes:
            travel.append(current["UserPrincipalName"])
    expect("viagem impossivel", travel, ["carla.nunes@contoso-lab.example"])

    admin_ports = set(extract_ints(rules["suspicious-admin-port-inbound"]["query"], "adminPorts"))
    attempt_threshold = extract_int(rules["suspicious-admin-port-inbound"]["query"], "attemptThreshold")
    denied = ("deny", "denied", "drop", "dropped", "block", "blocked")
    attempts: dict[tuple[str, str], int] = {}
    for row in flows:
        if row["DestinationPort"] not in admin_ports:
            continue
        if str(row["DeviceAction"]).lower() not in denied:
            continue
        if _private(row["SourceIP"]):
            continue
        key = (row["SourceIP"], row["DestinationIP"])
        attempts[key] = attempts.get(key, 0) + 1
    admin_hits = [key for key, count in attempts.items() if count >= attempt_threshold]
    expect("porta administrativa", admin_hits, [("203.0.113.40", "10.10.10.20")])

    delete_threshold = extract_int(rules["mass-file-deletion"]["query"], "deleteThreshold")
    deleted: dict[tuple[str, str], set[str]] = {}
    for row in events:
        if row["EventID"] != 4663:
            continue
        access = row["AccessList"]
        if "DELETE" not in access and "%%1537" not in access:
            continue
        key = (row["Account"], row["Computer"])
        deleted.setdefault(key, set()).add(row["ObjectName"])
    delete_hits = [key for key, objects in deleted.items() if len(objects) >= delete_threshold]
    expect("exclusao em massa", delete_hits, [("CONTOSO\\svc-backup", "FS01.contoso-lab.example")])

    byte_threshold = extract_int(rules["outbound-exfil-volume"]["query"], "byteThreshold")
    allowed = ("allow", "allowed", "accept", "accepted")
    volume: dict[tuple[str, str, str], int] = {}
    for row in flows:
        if str(row["DeviceAction"]).lower() not in allowed or row["SentBytes"] <= 0:
            continue
        if _private(row["DestinationIP"]):
            continue
        key = (row["SourceIP"], row["DestinationIP"], row["SourceUserName"])
        volume[key] = volume.get(key, 0) + row["SentBytes"]
    exfil_hits = [key for key, total in volume.items() if total >= byte_threshold]
    expect(
        "exfiltracao",
        exfil_hits,
        [("10.10.10.50", "203.0.113.80", "CONTOSO\\svc-backup")],
    )

    privileged = set(extract_strings(rules["privileged-role-assignment"]["query"], "privilegedRoles"))
    role_hits = []
    for row in audits:
        if row["Category"].lower() != "rolemanagement":
            continue
        if "add member to role" not in row["OperationName"].lower():
            continue
        if row["Result"].lower() != "success":
            continue
        target = ""
        role = ""
        for resource in row["TargetResources"]:
            if resource["type"].lower() == "user":
                target = resource["userPrincipalName"]
            if resource["type"].lower() == "role":
                role = resource["displayName"]
        actor = row["InitiatedBy"]["user"]["userPrincipalName"]
        if role in privileged and target and actor:
            role_hits.append((target, role))
    expect(
        "funcao privilegiada",
        role_hits,
        [
            ("bruno.lima@contoso-lab.example", "Global Administrator"),
            ("diego.souza@contoso-lab.example", "User Administrator"),
        ],
    )

    tlds = set(extract_strings(rules["phishing-url-click"]["query"], "suspiciousTlds"))
    tokens = extract_strings(rules["phishing-url-click"]["query"], "lookalikeTokens")
    phish = []
    for row in clicks:
        if row["ActionType"].lower() != "clickallowed":
            continue
        domain = row["Url"].split("/")[2].lower()
        if domain.endswith("contoso-lab.example"):
            continue
        tld = domain.rsplit(".", 1)[-1]
        if tld in tlds or any(token in domain for token in tokens):
            phish.append(domain)
    expect("phishing", phish, ["login-verify.example.xyz", "micr0soft-secure.top"])

    legacy = [row for row in signins if row["ClientAppUsed"] == "IMAP4"]
    expect("caca legado", len(legacy), 1)

    multi = {}
    for row in signins:
        if row["ResultType"] in failure:
            continue
        bucket = multi.setdefault(row["UserPrincipalName"], {"apps": set(), "count": 0})
        bucket["apps"].add(row["AppDisplayName"])
        bucket["count"] += 1
    multi_hits = [
        user
        for user, bucket in multi.items()
        if len(bucket["apps"]) >= 2 and bucket["count"] >= 5
    ]
    expect("caca varios aplicativos", multi_hits, ["ana.costa@contoso-lab.example"])

    after_logon = [
        row["Account"]
        for row in events
        if row["EventID"] == 4624 and row["LogonType"] in (3, 10) and (_hour(row["TimeGenerated"]) < 8 or _hour(row["TimeGenerated"]) >= 19)
    ]
    expect("caca logon fora do horario", after_logon, ["CONTOSO\\admin.soc"])

    encoded = [
        row["Account"]
        for row in events
        if row["EventID"] == 4688
        and ("powershell" in row["Process"] or "pwsh" in row["Process"])
        and any(token in row["CommandLine"].lower() for token in ("-enc", "-encodedcommand", "frombase64string"))
    ]
    expect("caca powershell", encoded, ["CONTOSO\\ana.costa"])

    after_roles = [
        row["CorrelationId"]
        for row in audits
        if row["Result"].lower() == "success" and (_hour(row["TimeGenerated"]) < 8 or _hour(row["TimeGenerated"]) >= 19)
    ]
    expect("caca funcao fora do horario", after_roles, ["lab-corr-0004"])

    domains = []
    for row in clicks:
        if row["ActionType"].lower() != "clickallowed":
            continue
        domain = row["Url"].split("/")[2].lower()
        if not domain.endswith("contoso-lab.example"):
            domains.append(domain)
    expect(
        "caca dominios",
        sorted(domains),
        ["learn.microsoft.com", "login-verify.example.xyz", "micr0soft-secure.top"],
    )

    if not hunts:
        errors.append("Nenhuma caca carregada.")
    return errors
