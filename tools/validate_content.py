#!/usr/bin/env python3
"""Valida o laboratório Sentinel: schema, MITRE, amostras e artefatos."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator, FormatChecker

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lab_content

ROOT = lab_content.ROOT
IDENTIFIERS = {
    "Account": {
        "Name",
        "FullName",
        "NTDomain",
        "DnsDomain",
        "UPNSuffix",
        "Sid",
        "AadTenantId",
        "AadUserId",
        "PUID",
        "IsDomainJoined",
        "DisplayName",
        "ObjectGuid",
    },
    "Host": {
        "DnsDomain",
        "NTDomain",
        "HostName",
        "FullName",
        "NetBiosName",
        "AzureID",
        "OMSAgentID",
        "OSFamily",
        "OSVersion",
        "IsDomainJoined",
    },
    "IP": {"Address"},
    "URL": {"Url"},
    "Process": {"ProcessId", "CommandLine", "ElevationToken", "CreationTimeUtc"},
    "DNS": {"DomainName"},
    "File": {"Directory", "Name"},
    "FileHash": {"Algorithm", "Value"},
    "CloudApplication": {"AppId", "Name", "InstanceName"},
    "AzureResource": {"ResourceId"},
    "Malware": {"Name", "Category"},
    "Mailbox": {"MailboxPrimaryAddress", "DisplayName", "Upn", "ExternalDirectoryObjectId", "RiskLevel"},
    "SecurityGroup": {"DistinguishedName", "SID", "ObjectGuid"},
    "RegistryKey": {"Hive", "Key"},
    "RegistryValue": {"Name", "Value", "ValueType"},
}

RUNBOOK_HEADINGS = (
    "## Objetivo",
    "## SLA",
    "## Passos do N1",
    "## Falsos positivos",
    "## Escalação para o N2",
    "## Contenção",
)

SECRET_PATTERNS = (
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"(?i)accountkey\s*="),
)

SPAN_SECONDS = {"m": 60, "h": 3600, "d": 86400}


def load_yaml_dir(folder: Path) -> list[tuple[str, dict]]:
    documents = []
    for path in sorted(folder.glob("*.yaml")):
        documents.append((path.stem, yaml.safe_load(path.read_text(encoding="utf-8"))))
    return documents


def schema_for(name: str) -> Draft202012Validator:
    payload = json.loads((ROOT / "schemas" / name).read_text(encoding="utf-8"))
    return Draft202012Validator(payload, format_checker=FormatChecker())


def span_seconds(value: str) -> int:
    return int(value[:-1]) * SPAN_SECONDS[value[-1]]


def technique_allowlist() -> set[str]:
    found = set()
    for line in (ROOT / "schemas" / "mitre-techniques.txt").read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        found.add(line)
    return found


def validate_entities(label: str, document: dict, errors: list[str]) -> None:
    query = document["query"]
    for mapping in document["entityMappings"]:
        entity = mapping["entityType"]
        allowed = IDENTIFIERS.get(entity)
        if allowed is None:
            errors.append(f"{label}: tipo de entidade desconhecido {entity}")
            continue
        for field in mapping["fieldMappings"]:
            if field["identifier"] not in allowed:
                errors.append(f"{label}: identificador {field['identifier']} invalido para {entity}")
            column = field["columnName"]
            if not re.search(rf"\b{re.escape(column)}\b", query):
                errors.append(f"{label}: coluna de entidade {column} nao aparece na consulta")
    override = document.get("alertDetailsOverride") or {}
    for key in ("alertDisplayNameFormat", "alertDescriptionFormat"):
        template = override.get(key)
        if not template:
            continue
        placeholders = re.findall(r"\{\{\s*([A-Za-z][A-Za-z0-9_]*)\s*\}\}", template)
        if len(placeholders) > 3:
            errors.append(f"{label}: {key} tem mais de 3 campos dinamicos")
        for column in placeholders:
            if not re.search(rf"\b{re.escape(column)}\b", query):
                errors.append(f"{label}: campo dinamico {column} nao aparece na consulta")
    for column in (document.get("customDetails") or {}).values():
        if not re.search(rf"\b{re.escape(column)}\b", query):
            errors.append(f"{label}: customDetails aponta para coluna ausente {column}")


def validate_rules(rules: list[tuple[str, dict]], errors: list[str]) -> None:
    validator = schema_for("analytic-rule.schema.json")
    allow = technique_allowlist()
    seen = set()
    for stem, rule in rules:
        for problem in validator.iter_errors(rule):
            errors.append(f"detections/{stem}.yaml: {problem.message}")
        if not isinstance(rule, dict):
            continue
        if rule.get("id") in seen:
            errors.append(f"detections/{stem}.yaml: id duplicado")
        seen.add(rule.get("id"))
        for technique in rule.get("relevantTechniques", []):
            if technique not in allow:
                errors.append(f"detections/{stem}.yaml: tecnica fora da lista {technique}")
        if "queryFrequency" in rule and "queryPeriod" in rule:
            if span_seconds(rule["queryFrequency"]) > span_seconds(rule["queryPeriod"]):
                errors.append(f"detections/{stem}.yaml: queryFrequency maior que queryPeriod")
        validate_entities(f"detections/{stem}.yaml", rule, errors)
        if "timestamp" in rule.get("query", "") and stem:
            pass
        runbook = ROOT / "playbooks" / "runbooks" / f"{stem}.md"
        if not runbook.exists():
            errors.append(f"Runbook ausente para {stem}")
        else:
            text = runbook.read_text(encoding="utf-8")
            for heading in RUNBOOK_HEADINGS:
                if heading not in text:
                    errors.append(f"{runbook.relative_to(ROOT)} sem o titulo {heading}")


def validate_hunts(hunts: list[tuple[str, dict]], errors: list[str]) -> None:
    validator = schema_for("hunting-query.schema.json")
    allow = technique_allowlist()
    seen = set()
    for stem, hunt in hunts:
        for problem in validator.iter_errors(hunt):
            errors.append(f"hunting/{stem}.yaml: {problem.message}")
        if not isinstance(hunt, dict):
            continue
        if hunt.get("id") in seen:
            errors.append(f"hunting/{stem}.yaml: id duplicado")
        seen.add(hunt.get("id"))
        for technique in hunt.get("relevantTechniques", []):
            if technique not in allow:
                errors.append(f"hunting/{stem}.yaml: tecnica fora da lista {technique}")
        if "timestamp" not in hunt.get("query", ""):
            errors.append(f"hunting/{stem}.yaml: a consulta precisa projetar timestamp")
        validate_entities(f"hunting/{stem}.yaml", hunt, errors)


def validate_workbook(errors: list[str]) -> list[tuple[str, str]]:
    path = ROOT / "workbooks" / "soc-overview.json"
    queries: list[tuple[str, str]] = []
    if not path.exists():
        errors.append("Workbook ausente")
        return queries
    workbook = json.loads(path.read_text(encoding="utf-8"))
    if workbook.get("version") != "Notebook/1.0":
        errors.append("Workbook sem version Notebook/1.0")
    items = workbook.get("items")
    if not isinstance(items, list) or not items:
        errors.append("Workbook sem itens")
        return queries
    blob = json.dumps(workbook, ensure_ascii=False)
    for token in ("AlertSeverity", "CompromisedEntity", "SigninLogs", "ResultType", "SecurityAlert"):
        if token not in blob:
            errors.append(f"Workbook nao cobre {token}")
    for index, item in enumerate(items):
        content = item.get("content") or {}
        query = content.get("query")
        if item.get("type") == 3 and isinstance(query, str):
            queries.append((f"item-{index}", query))
    if len(queries) < 3:
        errors.append("Workbook precisa de ao menos tres consultas")
    return queries


def validate_playbook(errors: list[str]) -> None:
    path = ROOT / "playbooks" / "enrich-ip-notify.json"
    if not path.exists():
        errors.append("Playbook ausente")
        return
    template = json.loads(path.read_text(encoding="utf-8"))
    if "deploymentTemplate.json" not in template.get("$schema", ""):
        errors.append("Playbook sem schema ARM")
    resources = template.get("resources") or []
    types = {resource.get("type") for resource in resources}
    if "Microsoft.Logic/workflows" not in types:
        errors.append("Playbook sem Logic App")
    if "Microsoft.Web/connections" not in types:
        errors.append("Playbook sem conexao de API")
    blob = json.dumps(template)
    for token in ("/incident-creation", "/entities/ip", "TeamsWebhookUrl", "NotificationEmail", "/v2/Mail"):
        if token not in blob:
            errors.append(f"Playbook sem {token}")
    parameters = template.get("parameters") or {}
    webhook = parameters.get("TeamsWebhookUrl") or {}
    if webhook.get("type") != "securestring":
        errors.append("TeamsWebhookUrl precisa ser securestring")
    if "defaultValue" in webhook:
        errors.append("TeamsWebhookUrl nao deve ter valor padrao")


def validate_infra(errors: list[str]) -> None:
    path = ROOT / "infra" / "main.bicep"
    if not path.exists():
        errors.append("Bicep ausente")
        return
    text = path.read_text(encoding="utf-8")
    for token in ("Microsoft.OperationalInsights/workspaces", "SecurityInsights", "OMSGallery/SecurityInsights"):
        if token not in text:
            errors.append(f"infra/main.bicep sem {token}")


def validate_readme(rules: list[tuple[str, dict]], errors: list[str]) -> None:
    path = ROOT / "README.md"
    if not path.exists():
        errors.append("README ausente")
        return
    text = path.read_text(encoding="utf-8")
    lowered = text.lower()
    for token in ("sintét", "mermaid", "datatable", "kleidson almeida santos", "mitre"):
        if token not in lowered:
            errors.append(f"README sem a marca '{token}'")
    for _, rule in rules:
        if rule["name"] not in text:
            errors.append(f"README sem a deteccao {rule['name']}")
        for technique in rule["relevantTechniques"]:
            if technique not in text:
                errors.append(f"README sem a tecnica {technique}")


def scan_forbidden(errors: list[str]) -> None:
    roots = (
        ROOT / "detections",
        ROOT / "hunting",
        ROOT / "playbooks",
        ROOT / "sample-data",
        ROOT / "workbooks",
        ROOT / "infra",
        ROOT / "README.md",
    )
    files: list[Path] = []
    for entry in roots:
        if entry.is_file():
            files.append(entry)
        elif entry.is_dir():
            files.extend(path for path in entry.rglob("*") if path.is_file())
    for path in files:
        text = path.read_text(encoding="utf-8", errors="ignore")
        for pattern in SECRET_PATTERNS:
            if pattern.search(text):
                errors.append(f"Possivel segredo em {path.relative_to(ROOT)}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true", help="Regrava amostras, KQL executavel e ARM.")
    args = parser.parse_args()

    rules = load_yaml_dir(ROOT / "detections")
    hunts = load_yaml_dir(ROOT / "hunting")
    errors: list[str] = []
    if len(rules) < 6:
        errors.append("Esperava ao menos seis deteccoes")
    if len(hunts) < 4:
        errors.append("Esperava ao menos quatro cacadas")

    if args.write:
        lab_content.write_generated(rules, hunts)
    else:
        errors.extend(lab_content.check_generated(rules, hunts))

    validate_rules(rules, errors)
    validate_hunts(hunts, errors)
    errors.extend(lab_content.assert_sample_behavior({stem: rule for stem, rule in rules}, {stem: hunt for stem, hunt in hunts}))
    workbook_queries = validate_workbook(errors)
    validate_playbook(errors)
    validate_infra(errors)
    validate_readme(rules, errors)
    scan_forbidden(errors)

    documents = [(f"detections/{stem}", rule["query"]) for stem, rule in rules]
    documents += [(f"hunting/{stem}", hunt["query"]) for stem, hunt in hunts]
    lab_content.emit_kql_for_lint(documents, workbook_queries)

    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        print(f"{len(errors)} problema(s).", file=sys.stderr)
        return 1
    print(f"Conteudo validado: {len(rules)} deteccoes, {len(hunts)} cacadas.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
