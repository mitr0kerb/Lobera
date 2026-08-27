# core/auth.py

import getpass
from core.output import console
from core import session_db

MAX_ATTEMPTS = 3
MIN_PASSWORD_LENGTH = 8
SESSION_TTL_MINUTES = 480  # 8 horas — una sesión de trabajo


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
    cualquier operación de Lobera. Se llama desde lobera.py justo después
    de init_db() y antes de parsear ningún subcomando.
    Devuelve True si el login fue correcto, False si se agotaron los intentos.
    """
    auth_info = session_db.get_auth()
    if auth_info is None:
        # No debería ocurrir si init_db() ya corrió antes, pero por seguridad
        # no bloqueamos el arranque si por lo que sea la tabla no existe aún.
        return True

    active_until = session_db.get_active_session()
    if active_until:
        console.print(f"[green]Sesión activa (expira a las {active_until.strftime('%H:%M')}).[/green]\n")
        return True

    console.print("[bold cyan]Inicio de sesión requerido[/bold cyan]")

    for attempt in range(1, MAX_ATTEMPTS + 1):
        username = console.input("Usuario: ").strip()
        password = getpass.getpass("Contraseña: ")

        if session_db.verify_login(username, password):
            console.print(f"[green]Bienvenido, {username}.[/green]\n")
            if auth_info["must_change_password"]:
                _prompt_password_change()
            session_db.start_session(SESSION_TTL_MINUTES)
            return True

        remaining = MAX_ATTEMPTS - attempt
        if remaining > 0:
            console.print(f"[red]Credenciales incorrectas. Intentos restantes: {remaining}[/red]")
        else:
            console.print("[bold red]Demasiados intentos fallidos. Saliendo.[/bold red]")

    return False
