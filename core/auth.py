# core/auth.py

import getpass
from datetime import datetime
from core.output import console
from core import session_db

MAX_ATTEMPTS = 3
MIN_PASSWORD_LENGTH = 8
SESSION_TTL_MINUTES = 480  # 8 horas


def _prompt_password_change():
    console.print("\n[bold yellow]Debes cambiar la contraseña antes de continuar.[/bold yellow]")
    while True:
        new_pwd = getpass.getpass("Nueva contraseña: ")
        confirm_pwd = getpass.getpass("Confirma la nueva contraseña: ")
        if new_pwd != confirm_pwd:
            console.print("[red]Las contraseñas no coinciden. Inténtalo de nuevo.[/red]")
            continue
        if len(new_pwd) < MIN_PASSWORD_LENGTH:
            console.print(f"[red]La contraseña debe tener al menos {MIN_PASSWORD_LENGTH} caracteres.[/red]")
            continue
        session_db.change_password(new_pwd)
        console.print("[green]Contraseña actualizada correctamente.[/green]\n")
        return


def login():
    """
    Exige login contra la tabla 'auth' de session_db antes de permitir
    cualquier operación de Lobera. Muestra el tiempo restante de sesión
    si ya hay una activa.
    """
    auth_info = session_db.get_auth()
    if auth_info is None:
        return True

    active_until = session_db.get_active_session()
    if active_until:
        now            = datetime.now()
        remaining_secs = int((active_until - now).total_seconds())
        hours, rem     = divmod(remaining_secs, 3600)
        mins           = rem // 60
        tiempo         = f"{hours}h {mins}m" if hours > 0 else f"{mins}m"
        expira         = active_until.strftime("%H:%M")
        console.print(
            f"[green]Sesión activa — expira a las {expira} ({tiempo} restantes).[/green]\n"
        )
        return True

    console.print("[bold cyan]Inicio de sesión requerido[/bold cyan]")
    for attempt in range(1, MAX_ATTEMPTS + 1):
        username = console.input("Usuario: ").strip()
        password = getpass.getpass("Contraseña: ")

        if session_db.verify_login(username, password):
            # Cambio de contraseña ANTES de abrir sesión
            if auth_info["must_change_password"]:
                _prompt_password_change()
            session_db.start_session(SESSION_TTL_MINUTES)
            console.print(f"[green]Bienvenido, {username}.[/green]\n")
            return True

        remaining = MAX_ATTEMPTS - attempt
        if remaining > 0:
            console.print(f"[red]Credenciales incorrectas. Intentos restantes: {remaining}[/red]")
        else:
            console.print("[bold red]Demasiados intentos fallidos. Saliendo.[/bold red]")

    return False
