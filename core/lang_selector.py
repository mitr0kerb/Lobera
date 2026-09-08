# core/lang_selector.py
from core.i18n import T, set_lang, get_lang
from core.output import console


def select_language_interactive() -> str:
    """Muestra el selector de idioma y devuelve 'es' o 'en'."""
    console.print()
    console.print("[bold cyan]" + T("lang_prompt") + "[/bold cyan]")
    console.print()
    console.print(T("lang_option_es"))
    console.print(T("lang_option_en"))
    console.print()

    while True:
        try:
            choice = console.input("  > ").strip()
        except (EOFError, KeyboardInterrupt):
            choice = "1"
        if choice == "1":
            set_lang("es")
            console.print()
            console.print("[green]" + T("lang_saved_es") + "[/green]")
            console.print()
            return "es"
        elif choice == "2":
            set_lang("en")
            console.print()
            console.print("[green]" + T("lang_saved_en") + "[/green]")
            console.print()
            return "en"
        else:
            console.print("[red]" + T("lang_invalid") + "[/red]")


def apply_lang_from_db(lang: str):
    """Carga el idioma guardado en session_db al arrancar."""
    if lang in ("es", "en"):
        set_lang(lang)


def cmd_change_lang(lang: str) -> bool:
    """Cambia el idioma via --lang=es/en. Devuelve True si fue exitoso."""
    lang = lang.strip().lower()
    if lang not in ("es", "en"):
        console.print(f"[red]Idioma no válido: '{lang}'. Usa 'es' o 'en'.[/red]")
        return False
    set_lang(lang)
    console.print("[green]" + T("lang_changed_" + lang) + "[/green]")
    return True
