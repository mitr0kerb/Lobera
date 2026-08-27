# tests/test_smb_shell.py

import getpass
from core.target import Target
from core.credentials import Creds
from modules.smb import SMBModule
from modules.smb_shell import SMBShell

user = getpass.getuser()
target = Target(ip="10.129.61.52", timeout=5)
creds = Creds(user=user, password="")

smb = SMBModule(target, creds)
if smb.connect():
    if smb.login():
        shell = SMBShell(smb)
        shell.run()
