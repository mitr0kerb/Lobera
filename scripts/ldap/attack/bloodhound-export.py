# scripts/ldap/attack/bloodhound-export.py

import json
import os
from datetime import datetime, timezone

from scripts.base import BaseScript
from core.output import print_result, print_table, console

try:
    from modules.ldap import LDAPModule
    _LDAP_AVAILABLE = True
except ImportError:
    _LDAP_AVAILABLE = False


class Script(BaseScript):
    name        = "bloodhound-export"
    protocol    = "ldap"
    category    = "attack"
    description = (
        "Exporta datos del dominio en formato compatible con BloodHound CE: "
        "usuarios, grupos, equipos y relaciones de membresía. "
        "Genera ficheros JSON en el directorio de salida."
    )
    requires_auth = True

    EXAMPLES = [
        {
            "flag":  "-t / -u / -p / -d",
            "desc":  "Credenciales de cualquier usuario del dominio",
            "good":  "lobera.py ldap --script=bloodhound-export -t 10.129.1.5 -u iker -p 'Pass1' -d CORP.LOCAL",
            "bad":   "lobera.py ldap --script=bloodhound-export -t 10.129.1.5  [sin credenciales no funciona]",
        },
        {
            "flag":  "--out-dir",
            "desc":  "Directorio donde guardar los JSON (default: loot/<IP>/bloodhound/)",
            "good":  "lobera.py ldap --script=bloodhound-export -t 10.129.1.5 -u iker -p 'Pass1' -d CORP.LOCAL --out-dir ./bh_output",
            "bad":   "lobera.py ldap --script=bloodhound-export -t 10.129.1.5 -u iker -p 'Pass1' -d CORP.LOCAL  [guarda en loot/ por defecto, no te olvides de copiarlo]",
        },
    ]

    # Versión del formato BloodHound CE
    _BH_VERSION = 6

    def run(self, **kwargs):
        if not _LDAP_AVAILABLE:
            print_result("LDAP", str(self.target.ip), "fail",
                         "modules/ldap.py no encontrado")
            return None

        ldap = LDAPModule(
            self.target, self.creds,
            use_ssl=kwargs.get("ldaps", False),
            port=kwargs.get("port"),
        )
        if not ldap.connect():
            return None

        out_dir = kwargs.get("out_dir") or os.path.join(
            "loot", str(self.target.ip), "bloodhound"
        )
        os.makedirs(out_dir, exist_ok=True)

        try:
            console.print("[bold cyan]Recopilando datos del dominio...[/bold cyan]")

            domain_info = ldap.get_domain_info()
            users       = ldap.get_all_users()
            groups      = ldap.get_all_groups()
            computers   = ldap.get_all_computers()

            domain_name = domain_info.get("domain", "").upper()
            domain_sid  = domain_info.get("sid", "")
            ts_now      = int(datetime.now(tz=timezone.utc).timestamp())

            # ---- Fichero: users.json ----------------------------------------
            bh_users = []
            for u in users:
                upn = "{}@{}".format(u["user"], domain_name)
                bh_users.append({
                    "ObjectIdentifier": u["sid"],
                    "AllowedToDelegate": [],
                    "PrimaryGroupSID": None,
                    "Properties": {
                        "name":           upn,
                        "domain":         domain_name,
                        "domainsid":      domain_sid,
                        "distinguishedname": u["dn"],
                        "samaccountname": u["user"],
                        "enabled":        u["enabled"],
                        "lastlogon":      u["last_logon"],
                        "pwdlastset":     u["pwd_last_set"],
                        "serviceprincipalnames": u["spns"],
                        "hasspn":         bool(u["spns"]),
                        "admincount":     u["admin_count"] == 1,
                        "dontreqpreauth": u["no_preauth"],
                        "description":    u["description"],
                    },
                    "Aces":        [],
                    "SPNTargets":  [],
                    "HasSIDHistory": [],
                    "IsDeleted":   False,
                })

            users_out = {
                "data": bh_users,
                "meta": {
                    "methods": 0,
                    "type":    "users",
                    "count":   len(bh_users),
                    "version": self._BH_VERSION,
                },
            }
            self._write_json(out_dir, "users.json", users_out)
            print_result("LDAP", str(self.target.ip), "ok",
                         "users.json: {} usuarios".format(len(bh_users)))

            # ---- Fichero: groups.json ----------------------------------------
            bh_groups = []
            for g in groups:
                members_bh = []
                for m_dn in g["members"]:
                    # Tipo heurístico por el OU del DN
                    if "OU=Domain Controllers" in m_dn or m_dn.endswith("$"):
                        mtype = "Computer"
                    elif "CN=Users" in m_dn or "OU=Users" in m_dn:
                        mtype = "User"
                    else:
                        mtype = "Group"
                    members_bh.append({"ObjectIdentifier": m_dn, "ObjectType": mtype})

                bh_groups.append({
                    "ObjectIdentifier": g["sid"],
                    "Properties": {
                        "name":              "{}@{}".format(g["name"], domain_name),
                        "domain":            domain_name,
                        "domainsid":         domain_sid,
                        "distinguishedname": g["dn"],
                        "samaccountname":    g["name"],
                        "admincount":        g["admin_count"] == 1,
                        "description":       g["description"],
                    },
                    "Members": members_bh,
                    "Aces":    [],
                    "IsDeleted": False,
                })

            groups_out = {
                "data": bh_groups,
                "meta": {
                    "methods": 0,
                    "type":    "groups",
                    "count":   len(bh_groups),
                    "version": self._BH_VERSION,
                },
            }
            self._write_json(out_dir, "groups.json", groups_out)
            print_result("LDAP", str(self.target.ip), "ok",
                         "groups.json: {} grupos".format(len(bh_groups)))

            # ---- Fichero: computers.json -------------------------------------
            bh_computers = []
            for c in computers:
                fqdn = c["dns"] or "{}.{}".format(c["name"].rstrip("$"), domain_name)
                bh_computers.append({
                    "ObjectIdentifier": c["sid"],
                    "AllowedToDelegate": [],
                    "AllowedToAct":      [],
                    "PrimaryGroupSID":   None,
                    "Properties": {
                        "name":              fqdn.upper(),
                        "domain":            domain_name,
                        "domainsid":         domain_sid,
                        "distinguishedname": c["dn"],
                        "samaccountname":    c["name"],
                        "enabled":           c["enabled"],
                        "operatingsystem":   c["os"],
                        "lastlogon":         c["last_logon"],
                        "unconstraineddelegation": c["unconstrained_deleg"],
                        "serviceprincipalnames":   c["spns"],
                    },
                    "Aces":      [],
                    "Sessions":  {"Results": [], "Collected": False},
                    "IsDeleted": False,
                })

            computers_out = {
                "data": bh_computers,
                "meta": {
                    "methods": 0,
                    "type":    "computers",
                    "count":   len(bh_computers),
                    "version": self._BH_VERSION,
                },
            }
            self._write_json(out_dir, "computers.json", computers_out)
            print_result("LDAP", str(self.target.ip), "ok",
                         "computers.json: {} equipos".format(len(bh_computers)))

            # ---- Fichero: domains.json ---------------------------------------
            domains_out = {
                "data": [{
                    "ObjectIdentifier": domain_sid,
                    "Properties": {
                        "name":              domain_name,
                        "domain":            domain_name,
                        "domainsid":         domain_sid,
                        "distinguishedname": domain_info.get("dn", ""),
                        "functionallevel":   domain_info.get("functional_level", ""),
                    },
                    "Trusts":        [],
                    "Aces":          [],
                    "Links":         [],
                    "ChildObjects":  [],
                    "GPOChanges":    {"AffectedComputers": [], "DcomUsers": [],
                                     "LocalAdmins": [], "PSRemoteUsers": [],
                                     "RemoteDesktopUsers": []},
                    "IsDeleted":     False,
                }],
                "meta": {
                    "methods": 0,
                    "type":    "domains",
                    "count":   1,
                    "version": self._BH_VERSION,
                },
            }
            self._write_json(out_dir, "domains.json", domains_out)
            print_result("LDAP", str(self.target.ip), "ok",
                         "domains.json: dominio {}".format(domain_name))

            # Resumen
            console.print(
                "\n[bold green]Export completo en:[/bold green] {}\n"
                "[dim]→ En BloodHound CE: Upload Data → selecciona los 4 JSON[/dim]".format(
                    os.path.abspath(out_dir))
            )

            return {
                "out_dir": out_dir,
                "users": len(bh_users),
                "groups": len(bh_groups),
                "computers": len(bh_computers),
            }

        finally:
            ldap.disconnect()

    @staticmethod
    def _write_json(directory, filename, data):
        path = os.path.join(directory, filename)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
