# tests/test_smb.py

import getpass
from core.session_db import init_db, get_findings
from core.target import Target
from core.credentials import Creds
from modules.smb import SMBModule
from core.output import print_table

init_db()

user = getpass.getuser()
target = Target(ip="10.129.61.89", timeout=5)
creds = Creds(user=user, password="")

smb = SMBModule(target, creds)
if smb.connect():
    smb.check_signing()
    if smb.login():
        smb.list_shares()
        smb.spider_all_shares()

findings = get_findings("10.129.61.89")
rows = [(f["protocol"], f["finding_type"], f["detail"]) for f in findings]
print_table("Findings guardados en la DB", ["Protocolo", "Tipo", "Detalle"], rows)
