# modules/rpc.py

from impacket.dcerpc.v5 import transport, samr, lsat, lsad
from impacket.dcerpc.v5.dtypes import MAXIMUM_ALLOWED
from impacket.dcerpc.v5.samr import SID_NAME_USE
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.nt_errors import STATUS_MORE_ENTRIES
from core.output import print_result, print_table, print_check
from core import session_db

RPC_PIPES = {
    "samr": r'\pipe\samr',
    "lsarpc": r'\pipe\lsarpc',
}

BIND_UUIDS = {
    "samr": samr.MSRPC_UUID_SAMR,
    "lsarpc": lsat.MSRPC_UUID_LSAT,
}

# Sentinela de "nunca" para OLD_LARGE_INTEGER/LARGE_INTEGER relativos
# (0x8000000000000000 como entero con signo de 64 bits = -9223372036854775808)
_NEVER_SENTINEL = -0x8000000000000000


class RPCModule:
    def __init__(self, target, creds):
        self.target = target      # instancia de Target
        self.creds = creds        # instancia de Creds
        self.dce = None
        self.rpctransport = None
        self.current_pipe = None      # "samr" | "lsarpc" -- el pipe actualmente bindeado
        self.server_handle = None     # handle de servidor SAMR (hSamrConnect)
        self.policy_handle = None     # handle de politica LSARPC (hLsarOpenPolicy2)
        self.domain_handle = None     # handle de dominio SAMR abierto (hSamrOpenDomain)
        self.domain_name = None       # nombre del dominio actualmente abierto en SAMR
        self.domain_sid = None        # SID del dominio actualmente abierto en SAMR

    def _proto(self):
        return "RPC"

    # ------------------------------------------------------------------
    # Conexion / bind
    # ------------------------------------------------------------------

    def connect(self, pipe="samr"):
        """
        Abre un named pipe MSRPC sobre IPC$ (ncacn_np) y hace bind al interfaz
        indicado. A diferencia de SMBModule, aqui connect() es TAMBIEN login():
        el pipe MSRPC exige autenticacion (o null session) para poder siquiera
        abrirse, asi que no existe un "connect sin credenciales" independiente
        como en SMB puro.

        pipe: "samr"   -> SamrXxx: enumeracion de usuarios/grupos y politica
                           de contrasenas/bloqueo.
              "lsarpc"  -> LsarXxx: resolucion de SIDs<->nombres y SID del
                           dominio via la interfaz de politica LSA.
        """
        if pipe not in RPC_PIPES:
            print_result(self._proto(), self.target.ip, "fail", f"pipe RPC desconocido: {pipe}")
            return False

        try:
            string_binding = r'ncacn_np:%s[%s]' % (self.target.ip, RPC_PIPES[pipe])
            self.rpctransport = transport.DCERPCTransportFactory(string_binding)
            self.rpctransport.setRemoteHost(self.target.ip)
            if hasattr(self.rpctransport, "set_dport"):
                self.rpctransport.set_dport(445)

            if hasattr(self.rpctransport, "set_credentials"):
                if self.creds.hash:
                    # Mismo criterio que SMBModule.login(): solo se usa la
                    # parte NT del hash, LM se deja vacio (ver ADR de smb.py).
                    nthash = self.creds.hash.split(":")[-1]
                    self.rpctransport.set_credentials(
                        self.creds.user, "", self.creds.domain, "", nthash
                    )
                else:
                    self.rpctransport.set_credentials(
                        self.creds.user or "", self.creds.password or "", self.creds.domain or ""
                    )

            self.dce = self.rpctransport.get_dce_rpc()
            self.dce.connect()
            self.dce.bind(BIND_UUIDS[pipe])
            self.current_pipe = pipe

            session_db.save_target(self.target.ip, domain=self.target.domain)
            print_result(self._proto(), self.target.ip, "ok", f"bind correcto sobre IPC$ a {RPC_PIPES[pipe]}")
            return True

        except Exception as e:
            self.dce = None
            self.current_pipe = None
            reason = e.getErrorString()[0] if hasattr(e, "getErrorString") else str(e)
            print_result(self._proto(), self.target.ip, "fail", f"no se pudo bindear {pipe}: [bold white]{reason}[/bold white]")
            return False

    def close(self):
        """Cierra la conexion DCERPC actual, si hay una abierta."""
        if self.dce is not None:
            try:
                self.dce.disconnect()
            except Exception:
                pass
        self.dce = None
        self.current_pipe = None
        self.server_handle = None
        self.policy_handle = None
        self.domain_handle = None

    def _require_pipe(self, pipe):
        if self.dce is None or self.current_pipe != pipe:
            print_result(self._proto(), self.target.ip, "fail",
                         f"esta operacion requiere connect(pipe='{pipe}') primero")
            return False
        return True

    # ------------------------------------------------------------------
    # SAMR -- handles internos
    # ------------------------------------------------------------------

    def _get_server_handle(self):
        if self.server_handle is None:
            resp = samr.hSamrConnect(self.dce)
            self.server_handle = resp['ServerHandle']
        return self.server_handle

    def enum_domains(self, silent=False):
        """
        Lista los dominios SAM visibles en el servidor (pipe 'samr').
        En una maquina no-DC casi siempre solo aparece "Builtin" y el nombre
        NetBIOS local; en un DC aparece tambien el dominio AD real.
        Equivalente a `rpcclient> enumdomains`.
        """
        if not self._require_pipe("samr"):
            return []

        try:
            server_handle = self._get_server_handle()
            resp = samr.hSamrEnumerateDomainsInSamServer(self.dce, server_handle)
            domains = [str(d['Name']) for d in resp['Buffer']['Buffer']]

            if not silent:
                print_table(f"Dominios SAM en {self.target.ip}", ["Dominio"], [(d,) for d in domains])
            for d in domains:
                session_db.save_finding(self.target.ip, "RPC", "samr_domain", d)
            return domains

        except Exception as e:
            reason = e.getErrorString()[0] if hasattr(e, "getErrorString") else str(e)
            if not silent:
                print_result(self._proto(), self.target.ip, "fail", f"Failed, reason: [bold white]{reason}[/bold white]")
            return []

    def open_domain(self, domain_name=None):
        """
        Abre un handle de dominio SAMR (hSamrLookupDomainInSamServer +
        hSamrOpenDomain) y guarda su SID. Si domain_name es None, elige
        automaticamente el primer dominio NO "Builtin" devuelto por
        enum_domains() (o "Builtin" si es el unico disponible).
        Requiere connect(pipe='samr') previo. Rellena self.domain_handle,
        self.domain_name y self.domain_sid; devuelve el handle o None.
        """
        if not self._require_pipe("samr"):
            return None

        try:
            server_handle = self._get_server_handle()

            if domain_name is None:
                domains = self.enum_domains(silent=True)
                if not domains:
                    print_result(self._proto(), self.target.ip, "fail", "no se encontro ningun dominio que abrir")
                    return None
                non_builtin = [d for d in domains if d.lower() != "builtin"]
                domain_name = non_builtin[0] if non_builtin else domains[0]

            resp = samr.hSamrLookupDomainInSamServer(self.dce, server_handle, domain_name)
            domain_id = resp['DomainId']

            resp = samr.hSamrOpenDomain(self.dce, serverHandle=server_handle, domainId=domain_id)
            self.domain_handle = resp['DomainHandle']
            self.domain_name = domain_name
            self.domain_sid = domain_id.formatCanonical()

            session_db.save_finding(self.target.ip, "RPC", "domain_sid", f"{domain_name}: {self.domain_sid}")
            print_result(self._proto(), self.target.ip, "ok", f"dominio '{domain_name}' abierto, SID {self.domain_sid}")
            return self.domain_handle

        except Exception as e:
            reason = e.getErrorString()[0] if hasattr(e, "getErrorString") else str(e)
            print_result(self._proto(), self.target.ip, "fail", f"no se pudo abrir el dominio: [bold white]{reason}[/bold white]")
            return None

    def _ensure_domain(self, domain_name):
        """Abre el dominio si aun no hay uno abierto, o si se pide uno distinto al ya abierto."""
        if self.domain_handle is None or (domain_name and domain_name != self.domain_name):
            return self.open_domain(domain_name) is not None
        return True

    # ------------------------------------------------------------------
    # SAMR -- enumeracion
    # ------------------------------------------------------------------

    def enum_users(self, domain_name=None, silent=False):
        """
        Enumera todos los usuarios del dominio abierto via SAMR, paginando
        con STATUS_MORE_ENTRIES. Equivalente a `rpcclient> enumdomusers`.
        Devuelve una lista de tuplas (rid, nombre).
        """
        if not self._require_pipe("samr"):
            return []
        if not self._ensure_domain(domain_name):
            return []

        users = []
        try:
            enumeration_context = 0
            status = STATUS_MORE_ENTRIES
            while status == STATUS_MORE_ENTRIES:
                try:
                    resp = samr.hSamrEnumerateUsersInDomain(
                        self.dce, self.domain_handle, enumerationContext=enumeration_context
                    )
                except DCERPCException as e:
                    if "STATUS_MORE_ENTRIES" not in str(e):
                        raise
                    resp = e.get_packet()

                for entry in resp['Buffer']['Buffer']:
                    users.append((entry['RelativeId'], str(entry['Name'])))

                enumeration_context = resp['EnumerationContext']
                status = resp['ErrorCode']

        except Exception as e:
            reason = e.getErrorString()[0] if hasattr(e, "getErrorString") else str(e)
            if not silent:
                print_result(self._proto(), self.target.ip, "fail", f"Failed, reason: [bold white]{reason}[/bold white]")
            return users

        if not silent:
            print_table(f"Usuarios de {self.domain_name} en {self.target.ip}", ["RID", "Usuario"], users)

        if users:
            names = ", ".join(name for _, name in users)
            session_db.save_finding(self.target.ip, "RPC", "samr_users", f"{len(users)} usuario(s) en {self.domain_name}: {names}")
            if not silent:
                print_result(self._proto(), self.target.ip, "pwned", f"{len(users)} usuario(s) enumerados vía SAMR")
        elif not silent:
            print_result(self._proto(), self.target.ip, "info", "ningun usuario enumerado")

        return users

    def enum_groups(self, domain_name=None, silent=False):
        """
        Enumera todos los grupos del dominio abierto via SAMR, paginando
        con STATUS_MORE_ENTRIES. Equivalente a `rpcclient> enumdomgroups`.
        Devuelve una lista de tuplas (rid, nombre).
        """
        if not self._require_pipe("samr"):
            return []
        if not self._ensure_domain(domain_name):
            return []

        groups = []
        try:
            enumeration_context = 0
            status = STATUS_MORE_ENTRIES
            while status == STATUS_MORE_ENTRIES:
                try:
                    resp = samr.hSamrEnumerateGroupsInDomain(
                        self.dce, self.domain_handle, enumerationContext=enumeration_context
                    )
                except DCERPCException as e:
                    if "STATUS_MORE_ENTRIES" not in str(e):
                        raise
                    resp = e.get_packet()

                for entry in resp['Buffer']['Buffer']:
                    groups.append((entry['RelativeId'], str(entry['Name'])))

                enumeration_context = resp['EnumerationContext']
                status = resp['ErrorCode']

        except Exception as e:
            reason = e.getErrorString()[0] if hasattr(e, "getErrorString") else str(e)
            if not silent:
                print_result(self._proto(), self.target.ip, "fail", f"Failed, reason: [bold white]{reason}[/bold white]")
            return groups

        if not silent:
            print_table(f"Grupos de {self.domain_name} en {self.target.ip}", ["RID", "Grupo"], groups)

        if groups:
            names = ", ".join(name for _, name in groups)
            session_db.save_finding(self.target.ip, "RPC", "samr_groups", f"{len(groups)} grupo(s) en {self.domain_name}: {names}")
            if not silent:
                print_result(self._proto(), self.target.ip, "pwned", f"{len(groups)} grupo(s) enumerados vía SAMR")
        elif not silent:
            print_result(self._proto(), self.target.ip, "info", "ningun grupo enumerado")

        return groups

    # ------------------------------------------------------------------
    # SAMR -- politica de contrasenas / bloqueo
    # ------------------------------------------------------------------

    @staticmethod
    def _old_large_int_to_signed(old_large_int):
        """HighPart/LowPart (OLD_LARGE_INTEGER) -> entero con signo de 64 bits."""
        value = (old_large_int['HighPart'] << 32) | (old_large_int['LowPart'] & 0xFFFFFFFF)
        if value >= 0x8000000000000000:
            value -= 0x10000000000000000
        return value

    @staticmethod
    def _relative_100ns_to_human(value, unit="days"):
        """Convierte un intervalo relativo en unidades de 100ns (negativo,
        convencion MS-SAMR/MS-LSAD) a texto legible. 0 = sin restriccion,
        el sentinela de 64 bits con signo = "nunca"."""
        if value == 0:
            return "0"
        if value <= _NEVER_SENTINEL:
            return "nunca"
        seconds = abs(value) / 10_000_000
        if unit == "days":
            return f"{seconds / 86400:.1f} dia(s)"
        return f"{seconds / 60:.1f} minuto(s)"

    def get_password_policy(self, domain_name=None):
        """
        Consulta la politica de contrasenas y de bloqueo de cuenta del
        dominio abierto via SAMR (DomainPasswordInformation +
        DomainLockoutInformation). Equivalente a `rpcclient> getdompwinfo`
        mas la parte de lockout de `querydominfo`.
        Devuelve un dict, o None si falla.
        """
        if not self._require_pipe("samr"):
            return None
        if not self._ensure_domain(domain_name):
            return None

        try:
            resp = samr.hSamrQueryInformationDomain(
                self.dce, self.domain_handle,
                domainInformationClass=samr.DOMAIN_INFORMATION_CLASS.DomainPasswordInformation
            )
            pw = resp['Buffer']['Password']

            resp = samr.hSamrQueryInformationDomain(
                self.dce, self.domain_handle,
                domainInformationClass=samr.DOMAIN_INFORMATION_CLASS.DomainLockoutInformation
            )
            lockout = resp['Buffer']['Lockout']

            props = pw['PasswordProperties']
            policy = {
                "min_password_length": pw['MinPasswordLength'],
                "password_history_length": pw['PasswordHistoryLength'],
                "complexity_required": bool(props & samr.DOMAIN_PASSWORD_COMPLEX),
                "cleartext_storage_allowed": bool(props & samr.DOMAIN_PASSWORD_STORE_CLEARTEXT),
                "max_password_age": self._relative_100ns_to_human(self._old_large_int_to_signed(pw['MaxPasswordAge']), "days"),
                "min_password_age": self._relative_100ns_to_human(self._old_large_int_to_signed(pw['MinPasswordAge']), "days"),
                "lockout_threshold": lockout['LockoutThreshold'],
                "lockout_duration": self._relative_100ns_to_human(lockout['LockoutDuration']['Data'], "minutes"),
                "lockout_observation_window": self._relative_100ns_to_human(lockout['LockoutObservationWindow']['Data'], "minutes"),
            }

            rows = [(k, str(v)) for k, v in policy.items()]
            print_table(f"Politica de contrasenas - {self.domain_name} en {self.target.ip}", ["Parametro", "Valor"], rows)

            detail = (f"min_len={policy['min_password_length']} "
                      f"complexity={policy['complexity_required']} "
                      f"lockout_threshold={policy['lockout_threshold']}")
            session_db.save_finding(self.target.ip, "RPC", "password_policy", detail)
            print_check(f"Umbral de bloqueo: {policy['lockout_threshold']} intento(s) fallido(s)",
                        ok=policy['lockout_threshold'] > 0)

            return policy

        except Exception as e:
            reason = e.getErrorString()[0] if hasattr(e, "getErrorString") else str(e)
            print_result(self._proto(), self.target.ip, "fail", f"Failed, reason: [bold white]{reason}[/bold white]")
            return None

    # ------------------------------------------------------------------
    # LSARPC -- politica / resolucion SID<->nombre
    # ------------------------------------------------------------------

    def _get_policy_handle(self):
        if self.policy_handle is None:
            resp = lsad.hLsarOpenPolicy2(self.dce, MAXIMUM_ALLOWED | lsat.POLICY_LOOKUP_NAMES)
            self.policy_handle = resp['PolicyHandle']
        return self.policy_handle

    def get_domain_sid(self):
        """
        Resuelve el SID del dominio (cuenta local, "Account Domain") via
        LSARPC (pipe 'lsarpc'), sin necesidad de tener un handle SAMR
        abierto. Equivalente al SID que muestra `rpcclient> lsaquery`.
        Devuelve el SID como string canonico ("S-1-5-21-...") o None.
        """
        if not self._require_pipe("lsarpc"):
            return None

        try:
            policy_handle = self._get_policy_handle()
            resp = lsad.hLsarQueryInformationPolicy2(
                self.dce, policy_handle, lsad.POLICY_INFORMATION_CLASS.PolicyAccountDomainInformation
            )
            info = resp['PolicyInformation']['PolicyAccountDomainInfo']
            sid = info['DomainSid'].formatCanonical()
            domain_name = str(info['DomainName'])

            session_db.save_finding(self.target.ip, "RPC", "domain_sid", f"{domain_name}: {sid}")
            print_result(self._proto(), self.target.ip, "ok", f"SID del dominio '{domain_name}': {sid}")
            return sid

        except Exception as e:
            reason = e.getErrorString()[0] if hasattr(e, "getErrorString") else str(e)
            print_result(self._proto(), self.target.ip, "fail", f"Failed, reason: [bold white]{reason}[/bold white]")
            return None

    def lookup_names(self, names):
        """
        Resuelve una lista de nombres ("DOMINIO\\usuario" o solo "usuario")
        a sus SIDs via LSARPC. Equivalente a `rpcclient> lookupnames`.
        Devuelve una lista de tuplas (nombre, sid, tipo).
        """
        if not self._require_pipe("lsarpc"):
            return []

        results = []
        try:
            policy_handle = self._get_policy_handle()
            try:
                resp = lsat.hLsarLookupNames(self.dce, policy_handle, names)
            except DCERPCException as e:
                if "STATUS_NONE_MAPPED" in str(e):
                    print_result(self._proto(), self.target.ip, "info", "ningun nombre pudo resolverse")
                    return []
                if "STATUS_SOME_NOT_MAPPED" not in str(e):
                    raise
                resp = e.get_packet()

            domains = resp['ReferencedDomains']['Domains']
            for name, item in zip(names, resp['TranslatedSids']['Sids']):
                if item['Use'] == SID_NAME_USE.SidTypeUnknown:
                    continue
                domain_sid = domains[item['DomainIndex']]['Sid'].formatCanonical()
                sid = f"{domain_sid}-{item['RelativeId']}"
                type_name = SID_NAME_USE.enumItems(item['Use']).name
                results.append((name, sid, type_name))

        except Exception as e:
            reason = e.getErrorString()[0] if hasattr(e, "getErrorString") else str(e)
            print_result(self._proto(), self.target.ip, "fail", f"Failed, reason: [bold white]{reason}[/bold white]")
            return results

        if results:
            print_table(f"Resolucion de nombres en {self.target.ip}", ["Nombre", "SID", "Tipo"], results)
            for name, sid, type_name in results:
                session_db.save_finding(self.target.ip, "RPC", "lookup_name", f"{name} -> {sid} ({type_name})")

        return results

    def lookup_sids(self, sids):
        """
        Resuelve una lista de SIDs ("S-1-5-21-...-1000") a nombres via
        LSARPC. Equivalente a `rpcclient> lookupsids`, y a la tecnica de
        RID cycling/bruteforce de lookupsid.py cuando se itera un rango
        de RIDs sobre el mismo SID de dominio.
        Devuelve una lista de tuplas (sid, nombre, tipo).
        """
        if not self._require_pipe("lsarpc"):
            return []

        results = []
        try:
            policy_handle = self._get_policy_handle()
            try:
                resp = lsat.hLsarLookupSids(self.dce, policy_handle, sids, lsat.LSAP_LOOKUP_LEVEL.LsapLookupWksta)
            except DCERPCException as e:
                if "STATUS_NONE_MAPPED" in str(e):
                    print_result(self._proto(), self.target.ip, "info", "ningun SID pudo resolverse")
                    return []
                if "STATUS_SOME_NOT_MAPPED" not in str(e):
                    raise
                resp = e.get_packet()

            domains = resp['ReferencedDomains']['Domains']
            for sid, item in zip(sids, resp['TranslatedNames']['Names']):
                if item['Use'] == SID_NAME_USE.SidTypeUnknown:
                    continue
                domain_name = str(domains[item['DomainIndex']]['Name'])
                full_name = f"{domain_name}\\{item['Name']}"
                type_name = SID_NAME_USE.enumItems(item['Use']).name
                results.append((sid, full_name, type_name))

        except Exception as e:
            reason = e.getErrorString()[0] if hasattr(e, "getErrorString") else str(e)
            print_result(self._proto(), self.target.ip, "fail", f"Failed, reason: [bold white]{reason}[/bold white]")
            return results

        if results:
            print_table(f"Resolucion de SIDs en {self.target.ip}", ["SID", "Nombre", "Tipo"], results)
            for sid, full_name, type_name in results:
                session_db.save_finding(self.target.ip, "RPC", "lookup_sid", f"{sid} -> {full_name} ({type_name})")

        return results
