# tests/test_session_db.py

from core.session_db import init_db, save_target, save_credential, save_finding, get_findings, get_credentials
from core.output import print_table

init_db()

save_target("10.129.61.52", domain="testlab.local")
save_finding("10.129.61.52", "SMB", "null_session", "null session permitida")
save_credential("10.129.61.52", "iker", "", "null", valid=True, source="smb_login")

findings = get_findings("10.129.61.52")
rows = [(f["protocol"], f["finding_type"], f["detail"], f["timestamp"]) for f in findings]
print_table("Findings guardados", ["Protocolo", "Tipo", "Detalle", "Timestamp"], rows)

creds = get_credentials("10.129.61.52")
rows = [(c["user"], c["secret_type"], c["source"], c["timestamp"]) for c in creds]
print_table("Credenciales válidas guardadas", ["Usuario", "Tipo", "Origen", "Timestamp"], rows)
