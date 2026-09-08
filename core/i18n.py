# core/i18n.py
"""
Sistema de internacionalización de Lobera.
Uso:
    from core.i18n import T, set_lang, get_lang
    print(T("banner_subtitle"))
    set_lang("en")
"""

_STRINGS = {
    "lang_prompt":           {"es": "Elige tu idioma / Choose your language",  "en": "Elige tu idioma / Choose your language"},
    "lang_option_es":        {"es": "  [1] Español",  "en": "  [1] Español"},
    "lang_option_en":        {"es": "  [2] English",  "en": "  [2] English"},
    "lang_saved_es":         {"es": "Idioma guardado: Español. Puedes cambiarlo con --lang=en",  "en": "Idioma guardado: Español. Puedes cambiarlo con --lang=en"},
    "lang_saved_en":         {"es": "Language saved: English. Change it with --lang=es",  "en": "Language saved: English. Change it with --lang=es"},
    "lang_invalid":          {"es": "Opción no válida. Escribe 1 o 2.",  "en": "Invalid option. Type 1 or 2."},
    "lang_changed_es":       {"es": "Idioma cambiado a Español.",  "en": "Language changed to Spanish."},
    "lang_changed_en":       {"es": "Idioma cambiado a Inglés.",  "en": "Language changed to English."},
    "banner_subtitle":       {"es": "Herramienta modular de pentest sobre Active Directory",  "en": "Modular Active Directory pentest toolkit"},
    "db_welcome":            {"es": "Bienvenido a Lobera",  "en": "Welcome to Lobera"},
    "db_first_run":          {"es": "Primera ejecución detectada en este equipo.",  "en": "First run detected on this machine."},
    "db_table_created":      {"es": "Tabla creada",  "en": "Table created"},
    "db_path_label":         {"es": "Ruta",  "en": "Path"},
    "db_ready_title":        {"es": "Base de datos lista",  "en": "Session database ready"},
    "db_ready_body": {
        "es": (
            "Aquí se guardará memoria persistente entre ejecuciones:\n"
            "  • Objetivos escaneados\n"
            "  • Credenciales válidas encontradas\n"
            "  • Hallazgos por protocolo\n\n"
            "Retoma un engagement donde lo dejaste."
        ),
        "en": (
            "Persistent memory is saved between runs:\n"
            "  • Scanned targets\n"
            "  • Valid credentials found\n"
            "  • Findings per protocol\n\n"
            "Resume an engagement where you left off."
        ),
    },
    "no_module":             {"es": "No se ha especificado ningún módulo.",  "en": "No module specified."},
    "modules_available":     {"es": "Módulos disponibles",  "en": "Available modules"},
    "usage_list":            {"es": "árbol de scripts disponibles",  "en": "list available scripts"},
    "usage_script":          {"es": "ver parámetros / ejecutar",  "en": "show parameters / run"},
    "usage_fam":             {"es": "ejecutar toda una familia",  "en": "run an entire family"},
    "usage_scanner":         {"es": "autopwn scanner",  "en": "autopwn scanner"},
    "usage_shell":           {"es": "consola interactiva",  "en": "interactive shell"},
    "script_not_found":      {"es": "Script '{name}' no encontrado para '{proto}'.",  "en": "Script '{name}' not found for '{proto}'."},
    "family_not_found":      {"es": "Familia '{fam}' no encontrada para '{proto}'.",  "en": "Family '{fam}' not found for '{proto}'."},
    "families_available":    {"es": "Familias disponibles",  "en": "Available families"},
    "see_list":              {"es": "Usa: python3 lobera.py {proto}  para ver los disponibles.",  "en": "Use: python3 lobera.py {proto}  to see available scripts."},
    "required_params":       {"es": "PARÁMETROS REQUERIDOS",  "en": "REQUIRED PARAMETERS"},
    "optional_params":       {"es": "PARÁMETROS OPCIONALES",  "en": "OPTIONAL PARAMETERS"},
    "usage_example":         {"es": "EJEMPLO DE USO",  "en": "USAGE EXAMPLE"},
    "missing_params":        {"es": "Faltan parámetros obligatorios",  "en": "Missing required parameters"},
    "add_and_retry":         {"es": "Añádelos al comando y vuelve a ejecutar.",  "en": "Add them to the command and run again."},
    "default_label":         {"es": "default",  "en": "default"},
    "mutually_exclusive":    {"es": "son mutuamente excluyentes.",  "en": "are mutually exclusive."},
    "script_selected":       {"es": "SCRIPT SELECCIONADO",  "en": "SELECTED SCRIPT"},
    "family_selected":       {"es": "FAMILIA SELECCIONADA",  "en": "SELECTED FAMILY"},
    "running_family":        {"es": "EJECUTANDO FAMILIA",  "en": "RUNNING FAMILY"},
    "running":               {"es": "Ejecutando",  "en": "Running"},
    "done":                  {"es": "Fin",  "en": "Done"},
    "family_done":           {"es": "Familia '{fam}' completada",  "en": "Family '{fam}' completed"},
    "script_load_error":     {"es": "No se pudo cargar el script.",  "en": "Could not load the script."},
    "import_error":          {"es": "Error importando script",  "en": "Error importing script"},
    "script_interrupted":    {"es": "Script interrumpido.",  "en": "Script interrupted."},
    "script_error":          {"es": "Error",  "en": "Error"},
    "omitted_missing":       {"es": "omitido, faltan",  "en": "skipped, missing"},
    "omitted_load":          {"es": "no se pudo cargar.",  "en": "could not be loaded."},
    "shell_help_list":       {"es": "Lista los scripts agrupados por familia",  "en": "List scripts grouped by family"},
    "shell_help_load":       {"es": "Carga un script individual",  "en": "Load a single script"},
    "shell_help_load_fam":   {"es": "Carga y ejecuta todos los scripts de una familia",  "en": "Load and run all scripts in a family"},
    "shell_help_params":     {"es": "Muestra los parámetros actuales",  "en": "Show current parameters"},
    "shell_help_set":        {"es": "Asigna un parámetro",  "en": "Set a parameter"},
    "shell_help_unset":      {"es": "Elimina un parámetro",  "en": "Clear a parameter"},
    "shell_help_run":        {"es": "Ejecuta el script cargado",  "en": "Run the loaded script"},
    "shell_help_clear":      {"es": "Limpia la pantalla",  "en": "Clear the screen"},
    "shell_help_exit":       {"es": "Sale de la consola",  "en": "Exit the shell"},
    "shell_no_script":       {"es": "No hay ningún script cargado. Usa 'load <script>'.",  "en": "No script loaded. Use 'load <script>'."},
    "shell_unknown_cmd":     {"es": "Comando desconocido",  "en": "Unknown command"},
    "shell_type_help":       {"es": "escribe 'help'",  "en": "type 'help'"},
    "shell_exiting":         {"es": "Saliendo...",  "en": "Exiting..."},
    "shell_usage_set":       {"es": "Uso: set <parámetro> <valor>",  "en": "Usage: set <parameter> <value>"},
    "shell_usage_load":      {"es": "Uso: load <nombre-script>",  "en": "Usage: load <script-name>"},
    "shell_usage_load_fam":  {"es": "Uso: load-fam <familia>",  "en": "Usage: load-fam <family>"},
    "shell_script_loaded":   {"es": "SCRIPT CARGADO",  "en": "SCRIPT LOADED"},
    "shell_mandatory_missing": {"es": "Falta parámetro obligatorio",  "en": "Missing required parameter"},
    "shell_set_with":        {"es": "→ set {key} <valor>",  "en": "→ set {key} <value>"},
    "shell_write_commands":  {"es": "Escribe 'help' para ver comandos",  "en": "Type 'help' to see commands"},
    "shell_family_params":   {"es": "Parámetros compartidos para la familia",  "en": "Shared parameters for the family"},
    "shell_optional_skip":   {"es": "(enter para omitir los opcionales)",  "en": "(press enter to skip optional fields)"},
    "shell_required_mark":   {"es": "es obligatorio.",  "en": "is required."},
    "shell_skip_optional":   {"es": "enter para omitir",  "en": "press enter to skip"},
    "shell_set_deleted":     {"es": "eliminado.",  "en": "cleared."},
    "shell_set_not_defined": {"es": "no estaba definido.",  "en": "was not defined."},
    "shell_not_recognized":  {"es": "Script '{name}' no reconocido.",  "en": "Script '{name}' not recognized."},
    "scanner_title":         {"es": "Autopwn Scanner",  "en": "Autopwn Scanner"},
    "scanner_params_title":  {"es": "Parámetros del scan",  "en": "Scan parameters"},
    "scanner_verbosity":     {"es": "Nivel de detalle",  "en": "Verbosity level"},
    "scanner_verb_basic":    {"es": "[1] Básico   — solo hallazgos críticos",  "en": "[1] Basic    — critical findings only"},
    "scanner_verb_normal":   {"es": "[2] Normal   — hallazgos + acciones (recomendado)",  "en": "[2] Normal   — findings + actions (recommended)"},
    "scanner_verb_debug":    {"es": "[3] Debug    — todo el output de cada script",  "en": "[3] Debug    — full output of each script"},
    "scanner_verb_prompt":   {"es": "Elige nivel [2]: ",  "en": "Choose level [2]: "},
    "scanner_verb_invalid":  {"es": "Opción no válida.",  "en": "Invalid option."},
    "scanner_output":        {"es": "Destino de resultados",  "en": "Output destination"},
    "scanner_output_db":     {"es": "[s] Guardar en base de datos (recomendado)",  "en": "[s] Save to session database (recommended)"},
    "scanner_output_file":   {"es": "[n] Exportar a fichero (json, yaml)",  "en": "[n] Export to file (json, yaml)"},
    "scanner_output_prompt": {"es": "Opción [s]: ",  "en": "Option [s]: "},
    "scanner_fmt_prompt":    {"es": "Formato [json]: ",  "en": "Format [json]: "},
    "scanner_file_prompt":   {"es": "Nombre del fichero: ",  "en": "Filename: "},
    "scanner_summary":       {"es": "RESUMEN DEL SCAN",  "en": "SCAN SUMMARY"},
    "scanner_criticals":     {"es": "Hallazgos críticos",  "en": "Critical findings"},
    "scanner_oks":           {"es": "Verificaciones OK",  "en": "Checks passed"},
    "scanner_omitted":       {"es": "omitido (faltan parámetros)",  "en": "skipped (missing parameters)"},
    "scanner_phase":         {"es": "FASE",  "en": "PHASE"},
    "scanner_exporting":     {"es": "Exportando resultados a",  "en": "Exporting results to"},
    "scanner_exported":      {"es": "Resultados guardados en",  "en": "Results saved to"},
    "db_no_targets":         {"es": "No hay ningún objetivo guardado.",  "en": "No targets saved yet."},
    "db_no_findings":        {"es": "Sin hallazgos para",  "en": "No findings for"},
    "db_no_creds":           {"es": "Sin credenciales para",  "en": "No credentials for"},
    "db_nothing_saved":      {"es": "Nada guardado para",  "en": "Nothing saved for"},
    "db_delete_title":       {"es": "Vas a borrar TODO para",  "en": "You are about to delete EVERYTHING for"},
    "db_delete_irreversible":{"es": "Irreversible.",  "en": "Irreversible."},
    "db_delete_confirm":     {"es": "¿Estás seguro? Escribe sí para confirmar: ",  "en": "Are you sure? Type yes to confirm: "},
    "db_deleted":            {"es": "Borrado",  "en": "Deleted"},
    "db_rows_deleted":       {"es": "fila(s) eliminadas.",  "en": "row(s) deleted."},
    "db_cancelled":          {"es": "Cancelado.",  "en": "Cancelled."},
    "db_secrets_hidden":     {"es": "Secretos ocultos. Usa --show-secret para verlos.",  "en": "Secrets hidden. Use --show-secret to reveal them."},
    "db_actions":            {"es": "Acciones disponibles",  "en": "Available actions"},
    "db_targets_header":     {"es": "Objetivos vistos",  "en": "Seen targets"},
    "db_findings_header":    {"es": "Hallazgos para",  "en": "Findings for"},
    "db_creds_header":       {"es": "Credenciales para",  "en": "Credentials for"},
    "col_ip":                {"es": "IP",  "en": "IP"},
    "col_domain":            {"es": "Dominio",  "en": "Domain"},
    "col_hostname":          {"es": "Hostname",  "en": "Hostname"},
    "col_first_seen":        {"es": "Primera vez",  "en": "First seen"},
    "col_protocol":          {"es": "Protocolo",  "en": "Protocol"},
    "col_type":              {"es": "Tipo",  "en": "Type"},
    "col_detail":            {"es": "Detalle",  "en": "Detail"},
    "col_timestamp":         {"es": "Timestamp",  "en": "Timestamp"},
    "col_user":              {"es": "Usuario",  "en": "User"},
    "col_secret":            {"es": "Secreto",  "en": "Secret"},
    "col_valid":             {"es": "Válida",  "en": "Valid"},
    "col_origin":            {"es": "Origen",  "en": "Origin"},
    "col_yes":               {"es": "Sí",  "en": "Yes"},
    "col_no":                {"es": "No",  "en": "No"},
    "label_target":          {"es": "IP/hostname del objetivo",  "en": "Target IP/hostname"},
    "label_user":            {"es": "Usuario",  "en": "Username"},
    "label_password":        {"es": "Contraseña",  "en": "Password"},
    "label_hash":            {"es": "Hash NT (LM:NT o NT solo)",  "en": "NT hash (LM:NT or NT only)"},
    "label_domain":          {"es": "Dominio FQDN",  "en": "Domain FQDN"},
    "label_timeout":         {"es": "Timeout de conexión (segundos)",  "en": "Connection timeout (seconds)"},
    "label_port":            {"es": "Puerto del servicio",  "en": "Service port"},
    "label_userlist":        {"es": "Ruta al fichero de usuarios",  "en": "Path to userlist file"},
    "label_passlist":        {"es": "Ruta al fichero de contraseñas",  "en": "Path to password list"},
    "label_wordlist":        {"es": "Wordlist genérica",  "en": "Generic wordlist"},
    "label_delay":           {"es": "Delay entre intentos (segundos)",  "en": "Delay between attempts (seconds)"},
    "label_command":         {"es": "Comando OS a ejecutar",  "en": "OS command to execute"},
    "label_query":           {"es": "Query SQL arbitraria",  "en": "Arbitrary SQL query"},
    "label_attacker_ip":     {"es": "IP del atacante",  "en": "Attacker IP"},
    "label_share":           {"es": "Share SMB concreto",  "en": "Specific SMB share"},
    "label_spn":             {"es": "SPN objetivo",  "en": "Target SPN"},
    "label_ccache":          {"es": "Ruta al fichero .ccache",  "en": "Path to .ccache file"},
    "label_krbtgt_hash":     {"es": "Hash NT del krbtgt",  "en": "krbtgt NT hash"},
    "label_domain_sid":      {"es": "SID del dominio (S-1-5-21-...)",  "en": "Domain SID (S-1-5-21-...)"},
    "label_ldaps":           {"es": "Usar LDAPS",  "en": "Use LDAPS"},
    "label_path":            {"es": "Ruta HTTP inicial",  "en": "Initial HTTP path"},
    "label_listener":        {"es": "IP del listener",  "en": "Listener IP"},
    "label_instance":        {"es": "Nombre de instancia (MSSQL)",  "en": "Instance name (MSSQL)"},
    "label_sni":             {"es": "Server Name Indication (TLS)",  "en": "Server Name Indication (TLS)"},
    "err_no_target":         {"es": "Falta -t/--target.",  "en": "Missing -t/--target."},
    "err_no_userlist":       {"es": "userlist no especificado.",  "en": "userlist not specified."},
    "err_read_file":         {"es": "No se pudo leer",  "en": "Could not read"},
    "err_no_connection":     {"es": "no hay conexión activa",  "en": "no active connection"},
    "err_unknown_module":    {"es": "Módulo desconocido",  "en": "Unknown module"},
}

_current_lang = "es"

def set_lang(lang: str):
    global _current_lang
    if lang in ("es", "en"):
        _current_lang = lang

def get_lang() -> str:
    return _current_lang

def T(key: str, **kwargs) -> str:
    entry = _STRINGS.get(key)
    if entry is None:
        return key
    text = entry.get(_current_lang, entry.get("es", key))
    if kwargs:
        text = text.format(**kwargs)
    return text

def TLabel(param_name: str) -> str:
    return T("label_" + param_name)
