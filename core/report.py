# core/report.py
"""
Generador de informes HTML y Markdown a partir de session_db.

Uso:
    from core.report import generate_report
    path = generate_report(target_ip, fmt="html", output="informe.html")
"""

import os
import datetime
from core.session_db import get_targets, get_findings, get_credentials


# ── Clasificación de hallazgos por severidad ──────────────────────────────────

_SEVERITY = {
    # Crítico
    "null_session":            "CRÍTICO",
    "signing_not_required":    "CRÍTICO",
    "smb1_enabled":            "CRÍTICO",
    "sam_dumped":              "CRÍTICO",
    "lsa_dumped":              "CRÍTICO",
    "dcsync":                  "CRÍTICO",
    "as_rep_roasting":         "CRÍTICO",
    "kerberoasting":           "CRÍTICO",
    "unconstrained_deleg":     "CRÍTICO",
    "shadow_creds":            "CRÍTICO",
    "rbcd_attack":             "CRÍTICO",
    # Alto
    "file_downloaded":         "ALTO",
    "share_found":             "ALTO",
    "ntlm_relay_possible":     "ALTO",
    "exec_ok":                 "ALTO",
    "shell_ok":                "ALTO",
    "gpp_password":            "ALTO",
    "constrained_deleg":       "ALTO",
    # Medio
    "signing_required":        "MEDIO",
    "anonymous_ldap":          "MEDIO",
    "ldap_accessible":         "MEDIO",
    "smb_accessible":          "MEDIO",
    # Info
    "share_accessible":        "INFO",
    "host_reachable":          "INFO",
}

_SEVERITY_ORDER = {"CRÍTICO": 0, "ALTO": 1, "MEDIO": 2, "INFO": 3, "?": 4}
_SEVERITY_COLOR = {
    "CRÍTICO": "#e74c3c",
    "ALTO":    "#e67e22",
    "MEDIO":   "#f1c40f",
    "INFO":    "#27ae60",
    "?":       "#95a5a6",
}


def _severity(finding_type: str) -> str:
    for key, sev in _SEVERITY.items():
        if key in finding_type.lower():
            return sev
    return "?"


def _sort_key(finding: dict) -> int:
    return _SEVERITY_ORDER.get(_severity(finding["finding_type"]), 99)


# ── Recopilación de datos ─────────────────────────────────────────────────────

def _collect(target_ip: str | None) -> dict:
    """Devuelve findings, credentials y targets para el informe."""
    if target_ip:
        targets  = [t for t in get_targets() if t["ip"] == target_ip]
        findings = sorted(get_findings(target_ip), key=_sort_key)
        creds    = get_credentials(target_ip, only_valid=False)
    else:
        targets  = get_targets()
        findings = []
        creds    = []
        for t in targets:
            tfinds = sorted(get_findings(t["ip"]), key=_sort_key)
            for f in tfinds:
                f["_ip"] = t["ip"]
            findings += tfinds
            tcreds = get_credentials(t["ip"], only_valid=False)
            for c in tcreds:
                c["_ip"] = t["ip"]
            creds += tcreds

    return {"targets": targets, "findings": findings, "creds": creds}


# ── Generador HTML ────────────────────────────────────────────────────────────

_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Lobera — Informe {title}</title>
  <style>
    :root {{
      --bg: #1a1a2e; --surface: #16213e; --border: #0f3460;
      --text: #e0e0e0; --dim: #888; --accent: #e94560;
    }}
    body   {{ background: var(--bg); color: var(--text); font-family: 'Segoe UI', monospace; margin: 0; padding: 1rem 2rem; }}
    h1     {{ color: var(--accent); border-bottom: 1px solid var(--border); padding-bottom: .4rem; }}
    h2     {{ color: #4fc3f7; margin-top: 2rem; }}
    table  {{ width: 100%; border-collapse: collapse; margin-bottom: 1.5rem; font-size: .9rem; }}
    th     {{ background: var(--border); text-align: left; padding: .4rem .6rem; }}
    td     {{ padding: .35rem .6rem; border-bottom: 1px solid var(--border); word-break: break-word; }}
    tr:hover td {{ background: rgba(255,255,255,.04); }}
    .badge {{ display: inline-block; padding: .15rem .5rem; border-radius: 3px;
              font-weight: bold; font-size: .8rem; color: #fff; }}
    .ts    {{ color: var(--dim); font-size: .8rem; }}
    .section {{ background: var(--surface); border: 1px solid var(--border); border-radius: 6px; padding: 1rem; margin-bottom: 1.5rem; }}
    footer {{ color: var(--dim); font-size: .8rem; text-align: right; margin-top: 2rem; }}
  </style>
</head>
<body>
  <h1>🐺 Lobera — Informe de seguridad</h1>
  <p><strong>Objetivo:</strong> {title} &nbsp;·&nbsp; <strong>Fecha:</strong> {date}</p>

  {targets_section}
  {findings_section}
  {creds_section}

  <footer>Generado por Lobera &middot; {date}</footer>
</body>
</html>
"""

def _badge(sev: str) -> str:
    color = _SEVERITY_COLOR.get(sev, "#95a5a6")
    return f'<span class="badge" style="background:{color}">{sev}</span>'


def _html_findings(findings: list, show_ip: bool = False) -> str:
    if not findings:
        return "<p><em>Sin hallazgos registrados.</em></p>"
    cols = (["IP"] if show_ip else []) + ["Protocolo", "Tipo", "Severidad", "Detalle", "Timestamp"]
    rows = ""
    for f in findings:
        sev = _severity(f["finding_type"])
        ip_cell = f"<td>{f.get('_ip','')}</td>" if show_ip else ""
        rows += (
            f"<tr>{ip_cell}"
            f"<td>{f['protocol']}</td>"
            f"<td><code>{f['finding_type']}</code></td>"
            f"<td>{_badge(sev)}</td>"
            f"<td>{f['detail']}</td>"
            f"<td class='ts'>{f['timestamp']}</td></tr>\n"
        )
    headers = "".join(f"<th>{c}</th>" for c in cols)
    return f"<table><tr>{headers}</tr>{rows}</table>"


def _html_creds(creds: list, show_ip: bool = False) -> str:
    if not creds:
        return "<p><em>Sin credenciales registradas.</em></p>"
    cols = (["IP"] if show_ip else []) + ["Usuario", "Tipo", "Válida", "Fuente", "Timestamp"]
    rows = ""
    for c in creds:
        ip_cell = f"<td>{c.get('_ip','')}</td>" if show_ip else ""
        valid   = "✅" if c.get("valid") else "❌"
        rows += (
            f"<tr>{ip_cell}"
            f"<td><strong>{c['user']}</strong></td>"
            f"<td>{c.get('type','-')}</td>"
            f"<td>{valid}</td>"
            f"<td>{c.get('source','-')}</td>"
            f"<td class='ts'>{c.get('timestamp','')}</td></tr>\n"
        )
    headers = "".join(f"<th>{c}</th>" for c in cols)
    return f"<table><tr>{headers}</tr>{rows}</table>"


def _build_html(data: dict, target_ip: str | None) -> str:
    title = target_ip or "todos los objetivos"
    date  = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    show_ip = target_ip is None

    # Targets
    tbl_t = ""
    if data["targets"]:
        rows = "".join(
            f"<tr><td>{t['ip']}</td><td>{t.get('domain') or '-'}</td>"
            f"<td>{t.get('hostname') or '-'}</td><td class='ts'>{t.get('first_seen','')}</td></tr>"
            for t in data["targets"]
        )
        tbl_t = (
            f"<div class='section'><h2>Objetivos</h2>"
            f"<table><tr><th>IP</th><th>Dominio</th><th>Hostname</th><th>Primera vez</th></tr>"
            f"{rows}</table></div>"
        )

    findings_html = (
        f"<div class='section'><h2>Hallazgos ({len(data['findings'])})</h2>"
        f"{_html_findings(data['findings'], show_ip)}</div>"
    )
    creds_html = (
        f"<div class='section'><h2>Credenciales ({len(data['creds'])})</h2>"
        f"{_html_creds(data['creds'], show_ip)}</div>"
    )

    return _HTML_TEMPLATE.format(
        title=title,
        date=date,
        targets_section=tbl_t,
        findings_section=findings_html,
        creds_section=creds_html,
    )


# ── Generador Markdown ────────────────────────────────────────────────────────

def _build_markdown(data: dict, target_ip: str | None) -> str:
    title = target_ip or "todos los objetivos"
    date  = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    show_ip = target_ip is None
    lines = [
        f"# 🐺 Lobera — Informe de seguridad",
        f"",
        f"**Objetivo:** {title}  ",
        f"**Fecha:** {date}",
        f"",
    ]

    if data["targets"]:
        lines += ["## Objetivos", ""]
        lines.append("| IP | Dominio | Hostname | Primera vez |")
        lines.append("|----|---------|----------|-------------|")
        for t in data["targets"]:
            lines.append(f"| {t['ip']} | {t.get('domain') or '-'} | {t.get('hostname') or '-'} | {t.get('first_seen','')} |")
        lines.append("")

    lines += [f"## Hallazgos ({len(data['findings'])})", ""]
    if data["findings"]:
        ip_col = "| IP " if show_ip else ""
        lines.append(f"{ip_col}| Protocolo | Tipo | Severidad | Detalle | Timestamp |")
        lines.append(f"{ip_col}|-----------|------|-----------|---------|-----------|")
        for f in data["findings"]:
            sev   = _severity(f["finding_type"])
            ip_c  = f"| {f.get('_ip','')} " if show_ip else ""
            lines.append(
                f"{ip_c}| {f['protocol']} | `{f['finding_type']}` | **{sev}** | {f['detail']} | {f['timestamp']} |"
            )
    else:
        lines.append("*Sin hallazgos registrados.*")
    lines.append("")

    lines += [f"## Credenciales ({len(data['creds'])})", ""]
    if data["creds"]:
        ip_col = "| IP " if show_ip else ""
        lines.append(f"{ip_col}| Usuario | Tipo | Válida | Fuente | Timestamp |")
        lines.append(f"{ip_col}|---------|------|--------|--------|-----------|")
        for c in data["creds"]:
            ip_c  = f"| {c.get('_ip','')} " if show_ip else ""
            valid = "✅" if c.get("valid") else "❌"
            lines.append(
                f"{ip_c}| {c['user']} | {c.get('type','-')} | {valid} | {c.get('source','-')} | {c.get('timestamp','')} |"
            )
    else:
        lines.append("*Sin credenciales registradas.*")
    lines.append("")
    lines.append(f"---")
    lines.append(f"*Generado por Lobera · {date}*")

    return "\n".join(lines)


# ── API pública ────────────────────────────────────────────────────────────────

def generate_report(target_ip: str | None = None,
                    fmt: str = "html",
                    output: str | None = None) -> str:
    """
    Genera un informe y lo escribe en disco.
    Retorna la ruta del fichero generado.

    Args:
        target_ip: IP a reportar, o None para todos los objetivos.
        fmt:       "html" (default) o "md".
        output:    ruta de salida; si None se genera automáticamente.
    """
    data = _collect(target_ip)

    if fmt == "md":
        content = _build_markdown(data, target_ip)
        ext     = "md"
    else:
        content = _build_html(data, target_ip)
        ext     = "html"

    if output is None:
        stamp  = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        suffix = target_ip.replace(".", "_") if target_ip else "all"
        output = f"lobera_report_{suffix}_{stamp}.{ext}"

    os.makedirs(os.path.dirname(os.path.abspath(output)), exist_ok=True) if os.path.dirname(output) else None
    with open(output, "w", encoding="utf-8") as f:
        f.write(content)

    return output
