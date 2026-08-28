#!/usr/bin/env python3
# lobera.py

import argparse
import sys

from modules.rpc import RPCModule
from core.session_db import init_db, get_targets, get_findings, get_credentials, delete_target
from core.target import Target
from core.credentials import Creds
from core.output import console, print_table
from core import auth
from scripts import loader as scripts_loader
from utils.banner import show_banner
from rich.table import Table
from rich.tree import Tree


# ============================================================
# Helpers comunes
# ============================================================

def add_common_target_args(parser):
    """Argumentos comunes a toda acción de módulos de ataque (target, credenciales).
    -t no es 'required' a nivel de argparse para permitir '--example' sin target;
    se valida a mano en cada acción real con require_target()."""
    parser.add_argument("-t", "--target", default=None, help="IP o hostname del objetivo (obligatorio salvo con --example)")
    parser.add_argument("-u", "--user", default="", help="Usuario")
    parser.add_argument("-p", "--password", default="", help="Contraseña")
    parser.add_argument("-H", "--hash", default=None, help="Hash NT (o LM:NT) para pass-the-hash")
    parser.add_argument("-d", "--domain", default="", help="Dominio")
    parser.add_argument("--timeout", type=int, default=5, help="Timeout de conexión en segundos (default: 5)")


def require_target(args):
    """Valida que se haya dado -t cuando la acción va a ejecutarse de verdad."""
    if not args.target:
        console.print("[red]Falta -t/--target (obligatorio salvo con --example).[/red]")
        return False
    return True


def parse_csv(raw):
    if raw is None:
        return None
    if raw == "":
        return []
    return [item.strip() for item in raw.split(",") if item.strip()]


def detect_hash_format(secret, secret_type):
    """Clasifica el formato de un secreto guardado para mostrarlo de forma legible."""
    if secret_type == "null":
        return "null session"
    if secret_type == "password":
        return "texto claro"
    if secret_type == "hash":
        if ":" in secret:
            lm, nt = secret.split(":", 1)
            if len(nt) == 32:
                return "LM:NTLM (NT hash 32 hex)"
            return "LM:NT (formato no estándar)"
        if len(secret) == 32:
            return "NTLM (NT hash, 32 hex)"
        return f"hash ({len(secret)} caracteres, formato no reconocido)"
    return secret_type


# ============================================================
# Parser
# ============================================================

def build_parser():
    parser = argparse.ArgumentParser(
        prog="lobera",
        description="Lobera - herramienta modular de enumeración y ataques AD"
    )
    subparsers = parser.add_subparsers(dest="module", metavar="módulo")

    # ============================================================
    # ============================================================
    # Módulo: smb (protocolo -> scripts por familia, sin subcomandos)
    # ============================================================
    smb_parser = subparsers.add_parser(
        "smb",
        help="SMB: sin argumentos lista familias/scripts; usa --script o --script-fam para ejecutar"
    )
    add_common_target_args(smb_parser)
    smb_parser.add_argument("--script", default=None,
                             help="Ejecuta un script concreto por su nombre (ver 'lobera.py smb')")
    smb_parser.add_argument("--script-fam", default=None, metavar="FAM1/FAM2",
                             help="Ejecuta TODOS los scripts de una o varias familias, separadas por '/' "
                                  "(ver 'lobera.py smb')")
    smb_parser.add_argument("--example", action="store_true",
                             help="Muestra ejemplos de uso del script indicado en --script "
                                  "(o de cada script de --script-fam)")
    # Flags específicos de scripts concretos. Ya no hay subparser por acción,
    # así que se declaran todos aquí (opcionales) y cada script coge de
    # kwargs solo los que necesita, ignorando el resto.
    smb_parser.add_argument("--share", metavar="SHARE", default=None,
                             help="[spider] Share concreto a rastrear. Si se omite, rastrea todos los no especiales")
    smb_parser.add_argument("--ext", default=None,
                             help="[spider] Extensiones a buscar, separadas por coma. Vacío ('') = sin filtro")
    smb_parser.add_argument("--keywords", default=None,
                             help="[spider] Palabras clave a buscar en nombres de fichero, separadas por coma")
    smb_parser.add_argument("--depth", type=int, default=5,
                             help="[spider] Profundidad máxima de recursión (default: 5)")
    smb_parser.add_argument("--userlist", default=None, metavar="FILE",
                             help="[password-spray] Fichero con un usuario por línea")

    # Módulo: kerberos
    # ============================================================
    kerberos_parser = subparsers.add_parser(
        "kerberos",
        help="Kerberos: sin argumentos lista familias/scripts; usa --script o --script-fam para ejecutar"
    )
    add_common_target_args(kerberos_parser)
    kerberos_parser.add_argument("--script", default=None,
                                  help="Ejecuta un script concreto por su nombre (ver 'lobera.py kerberos')")
    kerberos_parser.add_argument("--script-fam", default=None, metavar="FAM1/FAM2",
                                  help="Ejecuta TODOS los scripts de una o varias familias, separadas por '/'")
    kerberos_parser.add_argument("--example", action="store_true",
                                  help="Muestra ejemplos de uso del script indicado en --script")
    # ── Enumeración ───────────────────────────────────────────────────────
    kerberos_parser.add_argument("--userlist", default=None, metavar="FILE",
                                  help="[user-enum / asrep-roasting] Fichero con un usuario por línea")
    kerberos_parser.add_argument("--spn", default=None, metavar="SPN",
                                  help="[kerberoasting / silver-ticket / constrained-s4u] SPN objetivo "
                                       "(formato servicio/host o servicio/host:puerto)")
    # ── Tickets ──────────────────────────────────────────────────────────
    kerberos_parser.add_argument("--ccache", default=None, metavar="FILE",
                                  help="[pass-the-ticket] Ruta a fichero .ccache (MIT Kerberos)")
    kerberos_parser.add_argument("--kirbi", default=None, metavar="FILE",
                                  help="[pass-the-ticket] Ruta a fichero .kirbi (Windows/Mimikatz)")
    kerberos_parser.add_argument("--krbtgt-hash", default=None, metavar="HASH",
                                  help="[golden-ticket / diamond / sapphire] NT hash de krbtgt "
                                       "(32 hex chars o LM:NT)")
    kerberos_parser.add_argument("--service-hash", default=None, metavar="HASH",
                                  help="[silver-ticket] NT hash de la cuenta de servicio objetivo")
    kerberos_parser.add_argument("--domain-sid", default=None, metavar="SID",
                                  help="[golden / silver / sam-spoofing] SID del dominio "
                                       "(formato S-1-5-21-A-B-C, sin el RID final)")
    kerberos_parser.add_argument("--user-id", type=int, default=500, metavar="RID",
                                  help="[golden / diamond] RID del usuario a impersonar (default: 500 = Administrator)")
    kerberos_parser.add_argument("--groups", default=None, metavar="RIDS",
                                  help="[golden / diamond] RIDs de grupos separados por coma "
                                       "(default: 512,513,518,519,520)")
    # ── Delegación / Impersonación ────────────────────────────────────────
    kerberos_parser.add_argument("--target-user", default=None, metavar="USER",
                                  help="[constrained-s4u / sapphire / shadow-creds / rbcd / sam-spoofing] "
                                       "Usuario a impersonar en el servicio destino")
    kerberos_parser.add_argument("--target-computer", default=None, metavar="HOST",
                                  help="[rbcd] Nombre NetBIOS del equipo objetivo (sin FQDN)")
    kerberos_parser.add_argument("--attacker-account", default=None, metavar="ACCOUNT",
                                  help="[rbcd / kerber-loss] Cuenta bajo control del atacante "
                                       "(máquina con $, ej. EVIL01$)")
    # ── Certificados / AD CS ──────────────────────────────────────────────
    kerberos_parser.add_argument("--cert", default=None, metavar="FILE",
                                  help="[pkinit] Ruta al fichero PEM con clave privada (y opcionalmente cert)")
    kerberos_parser.add_argument("--pfx", default=None, metavar="FILE",
                                  help="[pkinit / adcs] Fichero PKCS#12 (.pfx/.p12) con clave + certificado")
    kerberos_parser.add_argument("--template", default=None, metavar="NAME",
                                  help="[adcs] Nombre de la plantilla de certificado a abusar (ESC1)")
    kerberos_parser.add_argument("--ca", default=None, metavar="NAME",
                                  help="[adcs] Nombre de la Certificate Authority (CN de la CA)")
    kerberos_parser.add_argument("--alt-name", default=None, metavar="UPN",
                                  help="[adcs] UPN a incluir en el SAN del certificado ESC1 "
                                       "(ej. Administrator@corp.local)")
    # ── Exploits ──────────────────────────────────────────────────────────
    kerberos_parser.add_argument("--dc-name", default=None, metavar="NAME",
                                  help="[sam-spoofing] Nombre NetBIOS del DC (sin $). "
                                       "Si se omite, se autodetecta via DNS.")
    kerberos_parser.add_argument("--user-sid", default=None, metavar="SID",
                                  help="[ms14-068] SID completo del usuario atacante "
                                       "(ej. S-1-5-21-A-B-C-1103). Obtenible con whoami /user.")
    kerberos_parser.add_argument("--vector", default=None, metavar="VECTOR",
                                  help="[kerber-loss] Vector de ataque: "
                                       "dos-colision | ntlm-downgrade | spn-jacking")

    # Módulo: db (consulta de la base de datos de sesión)
    # ============================================================
    db_parser = subparsers.add_parser("db", help="Consulta la base de datos de sesión (objetivos, credenciales, hallazgos)")
    db_subparsers = db_parser.add_subparsers(dest="db_action", metavar="acción")

    # --- db targets ---
    db_targets_parser = db_subparsers.add_parser("targets", help="Lista todos los objetivos vistos hasta ahora")
    db_targets_parser.add_argument("--example", action="store_true", help="Muestra ejemplos de uso y sale")

    # --- db findings ---
    db_findings_parser = db_subparsers.add_parser("findings", help="Lista los hallazgos guardados para un objetivo")
    db_findings_parser.add_argument("-t", "--target", default=None,
                                     help="IP del objetivo (obligatorio salvo con --example)")
    db_findings_parser.add_argument("--protocol", default=None,
                                     help="Filtra por protocolo (ej: SMB, RPC)")
    db_findings_parser.add_argument("--example", action="store_true", help="Muestra ejemplos de uso y sale")

    # --- db creds ---
    db_creds_parser = db_subparsers.add_parser("creds", help="Lista credenciales guardadas para un objetivo")
    db_creds_parser.add_argument("-t", "--target", default=None,
                                  help="IP del objetivo (obligatorio salvo con --example)")
    db_creds_parser.add_argument("--all", action="store_true",
                                  help="Incluye también credenciales marcadas como no válidas (por defecto solo válidas)")
    db_creds_parser.add_argument("--show-secret", action="store_true",
                                  help="Muestra el secreto (contraseña/hash) en texto plano. Por defecto se oculta.")
    db_creds_parser.add_argument("--example", action="store_true", help="Muestra ejemplos de uso y sale")

    # --- db delete ---
    db_delete_parser = db_subparsers.add_parser("delete", help="Borra TODO lo guardado para un objetivo (irreversible)")
    db_delete_parser.add_argument("-t", "--target", default=None,
                                   help="IP del objetivo a borrar (obligatorio salvo con --example)")
    db_delete_parser.add_argument("--yes", action="store_true",
                                   help="Salta la confirmación interactiva (para uso en scripts)")
    db_delete_parser.add_argument("--example", action="store_true", help="Muestra ejemplos de uso y sale")

    # ============================================================
    # Módulo: rpc
    # ============================================================
    rpc_parser = subparsers.add_parser("rpc", help="Enumeración RPC (SAMR/LSARPC sobre IPC$)")
    rpc_subparsers = rpc_parser.add_subparsers(dest="rpc_action", metavar="acción")

    # --- rpc enum ---
    rpc_enum_parser = rpc_subparsers.add_parser("enum", help="Enumeración vía SAMR: dominios, usuarios, grupos, política de contraseñas")
    add_common_target_args(rpc_enum_parser)
    rpc_enum_parser.add_argument("--example", action="store_true", help="Muestra ejemplos de uso y sale")
    rpc_enum_parser.add_argument("--domains", action="store_true", help="Lista los dominios SAM visibles en el servidor")
    rpc_enum_parser.add_argument("--users", action="store_true", help="Enumera los usuarios del dominio (SamrEnumerateUsersInDomain)")
    rpc_enum_parser.add_argument("--groups", action="store_true", help="Enumera los grupos del dominio (SamrEnumerateGroupsInDomain)")
    rpc_enum_parser.add_argument("--policy", action="store_true", help="Consulta política de contraseñas y bloqueo de cuenta del dominio")
    rpc_enum_parser.add_argument("--domain-name", default=None, metavar="DOM",
                                  help="Dominio SAM sobre el que enumerar (por defecto: se autodetecta el primero no-Builtin)")

    # --- rpc lookup ---
    rpc_lookup_parser = rpc_subparsers.add_parser("lookup", help="Resolución de SIDs<->nombres vía LSARPC")
    add_common_target_args(rpc_lookup_parser)
    rpc_lookup_parser.add_argument("--example", action="store_true", help="Muestra ejemplos de uso y sale")
    rpc_lookup_parser.add_argument("--sid", action="store_true",
                                    help="Muestra el SID del dominio (LSA PolicyAccountDomainInformation)")
    rpc_lookup_parser.add_argument("--names", default=None, metavar="LISTA",
                                    help="Nombres a resolver a SID, separados por coma (ej: Administrator,jsmith)")
    rpc_lookup_parser.add_argument("--sids", default=None, metavar="LISTA",
                                    help="SIDs a resolver a nombre, separados por coma")

    # ============================================================
    return parser


# ============================================================
# Ejemplos (--example) — smb ahora se autodocumenta por script
# (ver atributo `examples` en cada clase de scripts/smb/<familia>/).
# db y rpc siguen el modelo anterior por ahora (no migrados en esta fase).
# ============================================================

EXAMPLES = {
    "db": {
        "targets": [
            {"flag": "(sin flags)",
             "desc": "Lista todos los objetivos guardados hasta ahora",
             "good": "db targets",
             "bad": "db targets -t 10.129.1.5  [-t no existe en 'targets', esta accion lista TODOS, no filtra por uno]"},
        ],
        "findings": [
            {"flag": "-t / --target",
             "desc": "Filtra hallazgos por objetivo (obligatorio salvo con --example)",
             "good": "db findings -t 10.129.1.5",
             "bad": "db findings  [sin -t, no sabe de que objetivo mostrar hallazgos]"},
            {"flag": "--protocol",
             "desc": "Filtra ademas por protocolo concreto",
             "good": "db findings -t 10.129.1.5 --protocol SMB",
             "bad": "db findings -t 10.129.1.5 --protocol smb  [minusculas: el filtro no encontrara 'SMB' guardado en mayusculas]"},
        ],
        "creds": [
            {"flag": "-t / --target",
             "desc": "Filtra credenciales por objetivo (obligatorio salvo con --example)",
             "good": "db creds -t 10.129.1.5",
             "bad": "db creds  [sin -t, no sabe de que objetivo mostrar credenciales]"},
            {"flag": "--all",
             "desc": "Incluye credenciales invalidas, no solo las que funcionaron",
             "good": "db creds -t 10.129.1.5 --all  [util para ver tambien intentos fallidos de spray]",
             "bad": "db creds -t 10.129.1.5 --all --show-secret  [combinar ambos en pantalla compartida expone credenciales de mas]"},
            {"flag": "--show-secret",
             "desc": "Muestra la contrasena/hash en texto plano (oculto por defecto)",
             "good": "db creds -t 10.129.1.5 --show-secret  [en tu propia terminal privada]",
             "bad": "db creds -t 10.129.1.5 --show-secret  [en una sesion compartida/grabada -> expone credenciales reales]"},
        ],
        "delete": [
            {"flag": "-t / --target",
             "desc": "Borra TODO lo guardado (targets, credenciales, findings, log) de ese objetivo",
             "good": "db delete -t 10.129.1.5  [pide confirmacion antes de borrar]",
             "bad": "db delete -t 10.129.1.5 --yes  [salta confirmacion sin haber revisado antes que datos hay guardados]"},
            {"flag": "--yes",
             "desc": "Salta la confirmacion interactiva",
             "good": "db delete -t 10.129.1.5 --yes  [en un script automatizado de limpieza tras cada engagement]",
             "bad": "db delete -t 10.129.1.5 --yes  [en uso manual normal: te arriesgas a borrar el objetivo equivocado sin darte cuenta]"},
        ],
    },
    "rpc": {
        "enum": [
            {"flag": "-t / --target",
             "desc": "IP o hostname del objetivo (obligatorio salvo con --example)",
             "good": "rpc enum -t 10.129.1.5 --domains",
             "bad": "rpc enum --domains  [sin -t, falla: es obligatorio salvo con --example]"},
            {"flag": "-u / --user",
             "desc": "Usuario para autenticar el pipe MSRPC. Vacío = intenta null session",
             "good": "rpc enum -t 10.129.1.5 -u jsmith -p 'Pass123!' --users",
             "bad": "rpc enum -t 10.129.1.5 --users  [sin -u, muchos DC actuales deniegan SAMR anónimo -> falla]"},
            {"flag": "-p / --password",
             "desc": "Contraseña en texto claro (junto a -u)",
             "good": "rpc enum -t 10.129.1.5 -u jsmith -p 'Pass123!' --users",
             "bad": "rpc enum -t 10.129.1.5 -u jsmith -p 'Pass123!' -H aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c --users  [-p y -H juntos: usa solo uno]"},
            {"flag": "-H / --hash",
             "desc": "Pass-the-hash (formato NT o LM:NT) en vez de contraseña",
             "good": "rpc enum -t 10.129.1.5 -u administrator -H aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c --users",
             "bad": "rpc enum -t 10.129.1.5 -H aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c --users  [sin -u, Lobera no sabe qué usuario autenticar con ese hash]"},
            {"flag": "-d / --domain",
             "desc": "Dominio NetBIOS corto para autenticación NTLM del pipe (NO es el dominio SAM a enumerar, ver --domain-name)",
             "good": "rpc enum -t 10.129.1.5 -u jsmith -p 'Pass123!' -d CORP --users",
             "bad": "rpc enum -t 10.129.1.5 -u jsmith -p 'Pass123!' -d corp.local --users  [FQDN completo en vez de NetBIOS corto: puede dar falso fallo de login]"},
            {"flag": "--timeout",
             "desc": "Timeout de conexión en segundos (default: 5)",
             "good": "rpc enum -t 10.129.1.5 --timeout 10 --domains  [red lenta o VPN de HTB]",
             "bad": "rpc enum -t 10.129.1.5 --timeout 0 --domains  [0 puede provocar fallo inmediato en vez de esperar la conexión]"},
            {"flag": "--domains",
             "desc": "Lista los dominios SAM visibles (Builtin + dominio real si aplica)",
             "good": "rpc enum -t 10.129.1.5 -u jsmith -p 'Pass123!' --domains",
             "bad": "rpc enum -t 10.129.1.5 -u jsmith -p 'Pass123!' --domains --domain-name CORP  [--domain-name no aplica a --domains, que siempre lista TODOS]"},
            {"flag": "--users",
             "desc": "Enumera usuarios del dominio (requiere que SAMR no esté restringido, ver RestrictAnonymous)",
             "good": "rpc enum -t 10.129.1.5 -u jsmith -p 'Pass123!' --users",
             "bad": "rpc enum -t 10.129.1.5 --users  [sin credenciales, muy probable Access Denied en DCs modernos]"},
            {"flag": "--groups",
             "desc": "Enumera grupos del dominio",
             "good": "rpc enum -t 10.129.1.5 -u jsmith -p 'Pass123!' --groups",
             "bad": "rpc enum -t 10.129.1.5 -u jsmith -p 'Pass123!' --domains --groups --domain-name Builtin  [enumerar grupos de Builtin rara vez es útil, casi siempre se quiere el dominio real]"},
            {"flag": "--policy",
             "desc": "Política de contraseñas y bloqueo de cuenta (min length, historial, lockout...)",
             "good": "rpc enum -t 10.129.1.5 -u jsmith -p 'Pass123!' --policy  [útil ANTES de un password spray, para no bloquear cuentas]",
             "bad": "rpc enum -t 10.129.1.5 --policy  [sin credenciales puede fallar en DCs que exigen auth para SAMR]"},
            {"flag": "--domain-name",
             "desc": "Fuerza el dominio SAM sobre el que enumerar usuarios/grupos/política. Por defecto se autodetecta el primero no-Builtin",
             "good": "rpc enum -t 10.129.1.5 -u jsmith -p 'Pass123!' --users --domain-name CORP",
             "bad": "rpc enum -t 10.129.1.5 -u jsmith -p 'Pass123!' --users --domain-name corp.local  [debe ser el nombre NetBIOS SAM, no el FQDN]"},
        ],
        "lookup": [
            {"flag": "-t / --target",
             "desc": "IP o hostname del objetivo (obligatorio salvo con --example)",
             "good": "rpc lookup -t 10.129.1.5 --sid",
             "bad": "rpc lookup --sid  [sin -t, falla: es obligatorio salvo con --example]"},
            {"flag": "-u / --user",
             "desc": "Usuario para autenticar el pipe MSRPC. Vacío = intenta null session",
             "good": "rpc lookup -t 10.129.1.5 -u jsmith -p 'Pass123!' --names administrator",
             "bad": "rpc lookup -t 10.129.1.5 --names administrator  [sin -u, muchos DC deniegan LSA lookup anónimo]"},
            {"flag": "-p / --password",
             "desc": "Contraseña en texto claro (junto a -u)",
             "good": "rpc lookup -t 10.129.1.5 -u jsmith -p 'Pass123!' --sid",
             "bad": "rpc lookup -t 10.129.1.5 -u jsmith --sid  [sin -p, login con contraseña vacía probablemente falle]"},
            {"flag": "-H / --hash",
             "desc": "Pass-the-hash (formato NT o LM:NT) en vez de contraseña",
             "good": "rpc lookup -t 10.129.1.5 -u administrator -H aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c --sid",
             "bad": "rpc lookup -t 10.129.1.5 -H aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c --sid  [sin -u, Lobera no sabe qué usuario autenticar con ese hash]"},
            {"flag": "-d / --domain",
             "desc": "Dominio NetBIOS corto para autenticación NTLM del pipe",
             "good": "rpc lookup -t 10.129.1.5 -u jsmith -p 'Pass123!' -d CORP --sid",
             "bad": "rpc lookup -t 10.129.1.5 -u jsmith -p 'Pass123!' -d corp.local --sid  [FQDN completo en vez de NetBIOS corto: puede dar falso fallo de login]"},
            {"flag": "--timeout",
             "desc": "Timeout de conexión en segundos (default: 5)",
             "good": "rpc lookup -t 10.129.1.5 --timeout 10 --sid",
             "bad": "rpc lookup -t 10.129.1.5 --timeout 0 --sid  [0 puede provocar fallo inmediato en vez de esperar la conexión]"},
            {"flag": "--sid",
             "desc": "Muestra el SID del dominio, útil como base para construir SIDs de usuario a mano (S-1-5-21-...-RID) o para RID cycling",
             "good": "rpc lookup -t 10.129.1.5 -u jsmith -p 'Pass123!' --sid",
             "bad": "rpc lookup -t 10.129.1.5 -u jsmith -p 'Pass123!' --sid --names administrator  [mezclar --sid con --names es válido pero rara vez necesario, --sid ya da la base para construir SIDs a mano]"},
            {"flag": "--names",
             "desc": "Resuelve nombre(s) de usuario/grupo a SID(s)",
             "good": "rpc lookup -t 10.129.1.5 -u jsmith -p 'Pass123!' --names administrator,jsmith",
             "bad": "rpc lookup -t 10.129.1.5 -u jsmith -p 'Pass123!' --names 'CORP\\administrator con espacios'  [nombres con espacios sin comillas internas correctas pueden partirse mal en el CSV]"},
            {"flag": "--sids",
             "desc": "Resuelve SID(s) a nombre(s). Combínalo con --sid para construir SIDs de RID conocidos (500=Administrator, 501=Guest...)",
             "good": "rpc lookup -t 10.129.1.5 -u jsmith -p 'Pass123!' --sids S-1-5-21-1111-2222-3333-500",
             "bad": "rpc lookup -t 10.129.1.5 -u jsmith -p 'Pass123!' --sids 500  [500 es solo el RID, no un SID completo: falla al parsear]"},
        ],
    },
}


def show_examples(module, action):
    examples = EXAMPLES.get(module, {}).get(action, [])
    if not examples:
        console.print(f"[yellow]No hay ejemplos registrados para '{module} {action}' todavia.[/yellow]")
        return

    table = Table(title=f"Ejemplos - {module} {action}")
    table.add_column("Parametro", style="cyan")
    table.add_column("Que hace")
    table.add_column("[green]Buen uso[/green]")
    table.add_column("[red]Mal uso[/red]")

    for ex in examples:
        table.add_row(ex["flag"], ex["desc"], ex["good"], ex["bad"])

    console.print(table)


# ============================================================
# ============================================================
# Acciones: smb (protocolo -> scripts por familia)
# ============================================================

def _build_target_creds(args):
    target = Target(ip=args.target, domain=args.domain, timeout=args.timeout)
    creds = Creds(user=args.user, password=args.password, domain=args.domain, hash=args.hash)
    return target, creds


def build_script_kwargs(args):
    """Flags específicos de scripts (declarados a nivel de protocolo) que se
    reenvían tal cual a script.run(**kwargs). Cada script coge lo suyo e
    ignora el resto."""
    return {
        "share": args.share,
        "ext": args.ext,
        "keywords": args.keywords,
        "depth": args.depth,
        "userlist": args.userlist,
    }


def build_script_kwargs_kerberos(args):
    """Flags específicos de kerberos — cada script coge los que necesita."""
    return {
        # Enumeración
        "userlist":         getattr(args, "userlist", None),
        "spn":              getattr(args, "spn", None),
        # Tickets
        "ccache":           getattr(args, "ccache", None),
        "kirbi":            getattr(args, "kirbi", None),
        "krbtgt_hash":      getattr(args, "krbtgt_hash", None),
        "service_hash":     getattr(args, "service_hash", None),
        "domain_sid":       getattr(args, "domain_sid", None),
        "user_id":          getattr(args, "user_id", 500),
        "groups":           getattr(args, "groups", None),
        # Delegación / impersonación
        "target_user":      getattr(args, "target_user", None),
        "target_computer":  getattr(args, "target_computer", None),
        "attacker_account": getattr(args, "attacker_account", None),
        # Certificados / AD CS
        "cert":             getattr(args, "cert", None),
        "pfx":              getattr(args, "pfx", None),
        "template":         getattr(args, "template", None),
        "ca":               getattr(args, "ca", None),
        "alt_name":         getattr(args, "alt_name", None),
        # Exploits
        "dc_name":          getattr(args, "dc_name", None),
        "user_sid":         getattr(args, "user_sid", None),
        "vector":           getattr(args, "vector", None),
    }


def print_protocol_tree(protocol):
    """Árbol de familias -> scripts de un protocolo. Se muestra cuando el
    protocolo se invoca sin --script ni --script-fam."""
    tree_data = scripts_loader.get_tree(protocol)
    if not tree_data:
        console.print(f"[yellow]No hay scripts cargados todavia para el protocolo '{protocol}'.[/yellow]")
        console.print(f"Añade alguno en scripts/{protocol}/<familia>/ (ver scripts/base.py).")
        return

    tree = Tree(f"[bold cyan]{protocol}[/bold cyan]")
    for category, scripts_in_cat in tree_data.items():
        branch = tree.add(f"[bold yellow]{category}[/bold yellow]")
        for name, description in scripts_in_cat:
            branch.add(f"[bold]{name}[/bold] — {description}")

    console.print(tree)
    console.print(f"\n[dim]Uso: lobera.py {protocol} --script=<nombre> | "
                   f"--script-fam=<familia1/familia2> -t <target> ...[/dim]")
    console.print(f"[dim]Flags comunes a todos los scripts: -t/-u/-p/-H/-d/--timeout. "
                   f"Detalle de un script: lobera.py {protocol} --script=<nombre> --example[/dim]")


def show_script_example(protocol, name):
    registry = scripts_loader.discover_scripts(protocol=protocol)
    script_cls = registry.get(name)
    if script_cls is None:
        console.print(f"[red]No existe ningun script '{name}' en el protocolo '{protocol}'.[/red]")
        return

    console.print(f"\n[bold cyan]{name}[/bold cyan] ({script_cls.category}) — {script_cls.description}")

    if not script_cls.examples:
        console.print("[dim]Este script no tiene ejemplos adicionales registrados; "
                       "usa los flags comunes -t/-u/-p/-H/-d/--timeout.[/dim]")
        return

    table = Table(title=f"Ejemplos — {protocol} --script={name}")
    table.add_column("Parametro", style="cyan")
    table.add_column("Que hace")
    table.add_column("[green]Buen uso[/green]")
    table.add_column("[red]Mal uso[/red]")
    for ex in script_cls.examples:
        table.add_row(ex["flag"], ex["desc"], ex["good"], ex["bad"])
    console.print(table)


def run_single_script(protocol, name, target, creds, kwargs):
    registry = scripts_loader.discover_scripts(protocol=protocol)
    script_cls = registry.get(name)
    if script_cls is None:
        console.print(f"[red]No existe ningun script '{name}' en el protocolo '{protocol}'. "
                       f"Usa 'lobera.py {protocol}' para ver los disponibles.[/red]")
        return

    script = script_cls(target, creds)
    console.print(f"[cyan]Ejecutando script '{name}' ({script_cls.category})...[/cyan]\n")
    script.run(**kwargs)


def run_family_scripts(protocol, families, target, creds, kwargs):
    to_run = {}
    for fam in families:
        fam_scripts = scripts_loader.get_by_category(protocol, fam)
        if not fam_scripts:
            console.print(f"[red]No hay scripts en la familia '{fam}' del protocolo '{protocol}'.[/red]")
            continue
        to_run.update(fam_scripts)

    if not to_run:
        return

    console.print(f"[cyan]Ejecutando {len(to_run)} script(s) de la(s) familia(s) "
                   f"{'/'.join(families)}...[/cyan]\n")

    for name, script_cls in sorted(to_run.items()):
        console.print(f"[bold cyan]--- {name} ({script_cls.category}) ---[/bold cyan]")
        script = script_cls(target, creds)
        try:
            script.run(**kwargs)
        except Exception as e:
            console.print(f"[red]Error ejecutando '{name}': {e}[/red]")
        console.print()


def run_smb(args):
    protocol = "smb"

    if args.script and args.script_fam:
        console.print("[red]No combines --script y --script-fam en la misma llamada.[/red]")
        return

    if not args.script and not args.script_fam:
        if getattr(args, "example", False):
            console.print("[yellow]--example necesita --script=<nombre> o --script-fam=<familia> "
                           "para saber de que mostrar ejemplos.[/yellow]")
        print_protocol_tree(protocol)
        return

    if getattr(args, "example", False):
        if args.script:
            show_script_example(protocol, args.script)
        else:
            for fam in args.script_fam.split("/"):
                if not fam:
                    continue
                console.print(f"\n[bold cyan]--- Familia: {fam} ---[/bold cyan]")
                fam_scripts = scripts_loader.get_by_category(protocol, fam)
                if not fam_scripts:
                    console.print(f"[yellow]No hay scripts en la familia '{fam}'.[/yellow]")
                    continue
                for name in sorted(fam_scripts):
                    show_script_example(protocol, name)
        return

    if not require_target(args):
        return

    target, creds = _build_target_creds(args)
    kwargs = build_script_kwargs(args)

    if args.script:
        run_single_script(protocol, args.script, target, creds, kwargs)
    else:
        families = [f for f in args.script_fam.split("/") if f]
        run_family_scripts(protocol, families, target, creds, kwargs)


def run_kerberos(args):
    protocol = "kerberos"

    if args.script and args.script_fam:
        console.print("[red]No combines --script y --script-fam en la misma llamada.[/red]")
        return

    if not args.script and not args.script_fam:
        if getattr(args, "example", False):
            console.print("[yellow]--example necesita --script=<nombre> o --script-fam=<familia>.[/yellow]")
        print_protocol_tree(protocol)
        return

    if getattr(args, "example", False):
        if args.script:
            show_script_example(protocol, args.script)
        else:
            for fam in args.script_fam.split("/"):
                if not fam:
                    continue
                console.print(f"\n[bold cyan]--- Familia: {fam} ---[/bold cyan]")
                fam_scripts = scripts_loader.get_by_category(protocol, fam)
                if not fam_scripts:
                    console.print(f"[yellow]No hay scripts en la familia '{fam}'.[/yellow]")
                    continue
                for name in sorted(fam_scripts):
                    show_script_example(protocol, name)
        return

    # Scripts que NO requieren -t (solo necesitan -d y credenciales)
    NO_TARGET_SCRIPTS = {
        "golden-ticket",   # forja local, no habla con el KDC
        "silver-ticket",   # forja local
        "pass-the-ticket", # importa un fichero local
    }
    script_name = args.script or ""
    if script_name not in NO_TARGET_SCRIPTS:
        if not require_target(args):
            return

    target, creds = _build_target_creds(args)
    kwargs = build_script_kwargs_kerberos(args)

    if args.script:
        run_single_script(protocol, args.script, target, creds, kwargs)
    else:
        families = [f for f in args.script_fam.split("/") if f]
        run_family_scripts(protocol, families, target, creds, kwargs)


# Acciones: rpc
# ============================================================
 
def run_rpc_enum(args):
    if not require_target(args):
        return
    target = Target(ip=args.target, domain=args.domain, timeout=args.timeout)
    creds = Creds(user=args.user, password=args.password, domain=args.domain, hash=args.hash)
    rpc = RPCModule(target, creds)
 
    if not (args.domains or args.users or args.groups or args.policy):
        console.print("[yellow]No se ha pedido nada que enumerar: usa --domains, --users, --groups o --policy.[/yellow]")
        return
 
    if not rpc.connect(pipe="samr"):
        return
 
    if args.domains:
        rpc.enum_domains()
    if args.users:
        rpc.enum_users(domain_name=args.domain_name)
    if args.groups:
        rpc.enum_groups(domain_name=args.domain_name)
    if args.policy:
        rpc.get_password_policy(domain_name=args.domain_name)
 
    rpc.close()
 
 
def run_rpc_lookup(args):
    if not require_target(args):
        return
 
    names = parse_csv(args.names)
    sids = parse_csv(args.sids)
 
    if not (args.sid or names or sids):
        console.print("[yellow]No se ha pedido nada que resolver: usa --sid, --names o --sids.[/yellow]")
        return
 
    target = Target(ip=args.target, domain=args.domain, timeout=args.timeout)
    creds = Creds(user=args.user, password=args.password, domain=args.domain, hash=args.hash)
    rpc = RPCModule(target, creds)
 
    if not rpc.connect(pipe="lsarpc"):
        return
 
    if args.sid:
        rpc.get_domain_sid()
    if names:
        rpc.lookup_names(names)
    if sids:
        rpc.lookup_sids(sids)
 
    rpc.close()
 
 
RPC_ACTIONS = {
    "enum": run_rpc_enum,
    "lookup": run_rpc_lookup,
}
 
 
def run_rpc(args):
    action = RPC_ACTIONS.get(args.rpc_action)
    if action is None:
        console.print("[yellow]No se ha especificado ninguna accion de RPC.[/yellow]")
        console.print("Acciones disponibles: [bold]enum, lookup[/bold]")
        console.print("Uso: [dim]lobera.py rpc <accion> -h[/dim] para ver las opciones de cada una.\n")
        return
 
    if getattr(args, "example", False):
        show_examples("rpc", args.rpc_action)
        return
 
    action(args)


# ============================================================
# Acciones: db
# ============================================================

def run_db_targets(args):
    targets = get_targets()
    if not targets:
        console.print("[yellow]Todavia no hay ningun objetivo guardado en la base de datos.[/yellow]")
        return

    rows = [(t["ip"], t["domain"] or "-", t["hostname"] or "-", t["first_seen"]) for t in targets]
    print_table("Objetivos vistos", ["IP", "Dominio", "Hostname", "Primera vez visto"], rows)


def run_db_findings(args):
    if not args.target:
        console.print("[red]Falta -t/--target (obligatorio salvo con --example).[/red]")
        return

    findings = get_findings(args.target)
    if args.protocol:
        findings = [f for f in findings if f["protocol"] == args.protocol]

    if not findings:
        console.print(f"[yellow]No hay hallazgos guardados para {args.target}"
                       f"{' con protocolo ' + args.protocol if args.protocol else ''}.[/yellow]")
        return

    rows = [(f["protocol"], f["finding_type"], f["detail"], f["timestamp"]) for f in findings]
    print_table(f"Hallazgos para {args.target}", ["Protocolo", "Tipo", "Detalle", "Timestamp"], rows)


def run_db_creds(args):
    if not args.target:
        console.print("[red]Falta -t/--target (obligatorio salvo con --example).[/red]")
        return

    creds = get_credentials(args.target, only_valid=not args.all)
    if not creds:
        console.print(f"[yellow]No hay credenciales guardadas para {args.target}"
                       f"{' (validas)' if not args.all else ''}.[/yellow]")
        return

    rows = []
    for c in creds:
        secret_display = c["secret"] if args.show_secret else ("*" * 8 if c["secret"] else "")
        hash_format = detect_hash_format(c["secret"], c["secret_type"])
        valid_str = "Si" if c["valid"] else "No"
        rows.append((c["user"] or "(vacio)", secret_display, hash_format, valid_str, c["source"], c["timestamp"]))

    print_table(f"Credenciales para {args.target}",
                ["Usuario", "Secreto", "Formato", "Valida", "Origen", "Timestamp"], rows)

    if not args.show_secret and creds:
        console.print("[dim]Secretos ocultos por defecto. Usa --show-secret para verlos en texto plano.[/dim]")


def run_db_delete(args):
    if not args.target:
        console.print("[red]Falta -t/--target (obligatorio salvo con --example).[/red]")
        return

    # Mostramos primero un resumen de lo que hay, para que la persona sepa qué va a perder
    findings = get_findings(args.target)
    creds = get_credentials(args.target, only_valid=False)
    targets = [t for t in get_targets() if t["ip"] == args.target]

    if not targets and not findings and not creds:
        console.print(f"[yellow]No hay nada guardado para {args.target}. Nada que borrar.[/yellow]")
        return

    console.print(f"[bold red]Vas a borrar TODO lo guardado para {args.target}:[/bold red]")
    console.print(f"  • {len(targets)} registro(s) de target")
    console.print(f"  • {len(creds)} credencial(es)")
    console.print(f"  • {len(findings)} finding(s)")
    console.print("[bold red]Esta acción es irreversible.[/bold red]\n")

    if not args.yes:
        answer = console.input("¿Estás seguro? Escribe [bold]sí[/bold] para confirmar: ").strip().lower()
        if answer not in ("si", "sí", "s", "yes", "y"):
            console.print("[yellow]Cancelado, no se ha borrado nada.[/yellow]")
            return

    counts = delete_target(args.target)
    total = sum(counts.values())
    console.print(f"[green]Borrado completo: {total} fila(s) eliminadas de {args.target}.[/green]")


DB_ACTIONS = {
    "targets": run_db_targets,
    "findings": run_db_findings,
    "creds": run_db_creds,
    "delete": run_db_delete,
}


def run_db(args):
    action = DB_ACTIONS.get(args.db_action)
    if action is None:
        console.print("[yellow]No se ha especificado ninguna accion de db.[/yellow]")
        console.print("Acciones disponibles: [bold]targets, findings, creds[/bold]")
        console.print("Uso: [dim]lobera.py db <accion> -h[/dim] para ver las opciones de cada una.\n")
        return

    if getattr(args, "example", False):
        show_examples("db", args.db_action)
        return

    action(args)


# ============================================================
# Entry point
# ============================================================

def main():
    # Banner y comprobacion/creacion de la base de datos SIEMPRE se ejecutan
    # primero, antes de parsear argumentos -> asi salen incluso si faltan
    # argumentos obligatorios o si se ejecuta "lobera.py" sin nada.
    show_banner()
    is_first_run = init_db()

    # Login obligatorio contra la tabla 'auth' antes de permitir cualquier
    # operacion. Si es la primera ejecucion, init_db() ya genero el usuario
    # y mostro la contrasena temporal en el panel de bienvenida.
    if not auth.login():
        sys.exit(1)

    parser = build_parser()
    args = parser.parse_args()

    if args.module is None:
        # En la primera ejecucion el usuario ya ha visto de sobra (lobo,
        # credenciales, login, cambio de contrasena) -> no le añadimos
        # encima el aviso de "falta modulo" si solo estaba probando el
        # arranque sin dar ningun argumento todavia.
        if not is_first_run:
            console.print("[yellow]No se ha especificado ningun modulo.[/yellow]")
            console.print("Modulos disponibles: [bold]smb, kerberos, rpc, db[/bold]")
            console.print("Uso: [dim]lobera.py <modulo> -h[/dim] para ver las acciones de cada uno.\n")
        return
    
    if args.module == "smb":
        run_smb(args)
    elif args.module == "kerberos":
        run_kerberos(args)
    elif args.module == "rpc":
        run_rpc(args)
    elif args.module == "db":
        run_db(args)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[dim]Interrumpido por el usuario.[/dim]")
