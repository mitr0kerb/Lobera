<p align="center">
  <img src="docs/lobera_logo.png" alt="Lobera logo" width="220"/>
</p>

<h1 align="center">Lobera</h1>

<p align="center">
  <strong>Active Directory enumeration & attack toolkit</strong><br/>
  Built from scratch on top of <code>impacket</code> — understand the protocols, not just the tools.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.10%2B-blue?style=flat-square"/>
  <img src="https://img.shields.io/badge/protocols-SMB%20·%20Kerberos%20·%20LDAP%20·%20RPC%20·%20WinRM%20·%20SSH%20·%20SSL%20·%20HTTP%20·%20FTP%20·%20MSSQL-red?style=flat-square"/>
  <img src="https://img.shields.io/badge/status-active-green?style=flat-square"/>
</p>


---
## IMPORTANT ⚠️
This is a beta version, many of the scripts are not fully-tested on full-working systems, they may appear issues that will be fixed in next updates. If you find any issue please let me know mailing me:
📧 mitr0kerb@gmail.com
---

## What is Lobera?

Lobera is a modular Active Directory pentest toolkit designed as a learning platform. Every protocol — SMB, Kerberos, LDAP, RPC, WinRM, SSH, SSL, HTTP/S, FTP, MSSQL — is implemented from scratch on top of `impacket` so you understand what packet goes to what port and why.

It is **not** a wrapper around CrackMapExec. Every call maps to a real protocol operation.

---

## Installation

```bash
git clone git@github.com:mitr0kerb/Lobera.git
cd Lobera
pip install -r requirements.txt
python3 lobera.py
```

**Requirements:** Python 3.10+, impacket, rich, pyfiglet, pycryptodomex, pyasn1, pywinrm.

---

## Three modes

Lobera has three independent ways to operate. Use whichever fits your workflow.

### 1. Classic mode — direct CLI

The fastest way to run a single script or an entire family. No shell, no prompts — everything is a flag.

```bash
# List all scripts for a protocol
python3 lobera.py smb

# Show required and optional parameters for a script
python3 lobera.py smb --script=null-session

# Run the script once all required params are provided
python3 lobera.py smb --script=shares -t 10.10.10.5 -u iker -p Pass123!

# Run an entire family at once
python3 lobera.py ldap --script-fam=enum -t 10.10.10.5 -d CORP.LOCAL -u iker -p Pass123!
```

When you run `--script=<name>` without all required parameters, Lobera prints a usage card:

```
SHARES  — SMB / enum

REQUIRED PARAMETERS

  *  --target <value>     (Target IP/hostname)
  *  --user   <value>     (Username)

OPTIONAL PARAMETERS

  ·  --password <value>   (Password)
  ·  --hash     <value>   (NT hash — pass-the-hash)
  ·  --timeout  <value>   (default: 5)

EXAMPLE

  python3 lobera.py smb --script=shares --target <target> --user <user>

Missing required parameters: --target, --user
Add them to the command and run again.
```

Once all required parameters are present in the command, the script runs immediately — no further interaction needed.

### 2. Interactive shell — per-protocol console

A persistent REPL for each protocol. Set parameters once and run multiple scripts without retyping them.

```bash
python3 lobera.py smb --interactive-shell
python3 lobera.py kerberos --interactive-shell
python3 lobera.py mssql --interactive-shell
```

Inside the shell:

```
smb-shell > list
smb-shell > load shares
smb-shell(shares) > set target 10.10.10.5
smb-shell(shares) > set user iker
smb-shell(shares) > run
smb-shell(shares) > load gpp-password
smb-shell(shares) > run          ← target/user already set, reused
```

Shell commands:

| Command | Description |
|---|---|
| `list` | Show all scripts grouped by family |
| `load <script>` | Load a script and see its parameters |
| `load-fam <family>` | Load and run all scripts in a family |
| `set <key> <value>` | Set a parameter |
| `unset <key>` | Clear a parameter |
| `params` | Show current parameter values |
| `run` | Execute the loaded script |
| `clear` | Clear screen |
| `exit` | Exit the shell |

### 3. Autopwn scanner — automated multi-phase scan

The scanner runs all relevant scripts for a protocol in order, phase by phase. It asks for parameters interactively, evaluates conditions (has credentials? has a userlist? has a ccache?), and skips steps whose conditions are not met.

```bash
python3 lobera.py smb --scanner
python3 lobera.py kerberos --scanner
python3 lobera.py ldap --scanner
```

The scanner collects: target, credentials, optional wordlists — then runs through phases automatically and prints a summary at the end. Results are saved to the session database.

---

## Supported protocols

| Protocol | Port | Color | Families |
|---|---|---|---|
| SMB | 445 | green | enum · attack |
| Kerberos | 88 | magenta | enum · extraction · tickets · delegation · credentials · exploits |
| LDAP | 389/636 | yellow | enum · attack · exploit |
| RPC | 135 | blue | enum · attack · exploit |
| WinRM | 5985/5986 | cyan | enum · attack · exploit |
| SSH | 22 | turquoise | enum · attack · exploit |
| SSL | 443+ | gold | enum · attack |
| HTTP | 80 | bright cyan | enum · attack · exploit · post |
| HTTPS | 443 | deep sky blue | enum · attack · exploit · post |
| FTP | 21 | orange | enum · attack · exploit · post |
| MSSQL | 1433 | bright red | enum · attack · exploit · post |

---

## Session database

Every finding, credential, and target is saved automatically to a local SQLite database (`lobera.db`). Results persist across sessions.

```bash
# List all seen targets
python3 lobera.py db targets

# Show all findings for a target
python3 lobera.py db findings -t 10.10.10.5

# Show valid credentials
python3 lobera.py db creds -t 10.10.10.5

# Show credentials with secrets visible
python3 lobera.py db creds -t 10.10.10.5 --show-secret

# Delete all data for a target
python3 lobera.py db delete -t 10.10.10.5
```

---

## Writing a custom script

Every script is a Python file with a single class that inherits from `BaseScript`. Drop it in the right folder and Lobera discovers it automatically on next run — no registration needed.

### File location

```
scripts/
  <protocol>/
    <family>/
      your_script.py
```

Example: `scripts/smb/enum/my_check.py`

### Script structure

```python
# scripts/smb/enum/my_check.py

from scripts.base import BaseScript
from modules.smb import SMBModule
from core.output import print_result, print_table
from core import session_db


class Script(BaseScript):
    name        = "my-check"          # used in --script=my-check and the tree
    protocol    = "smb"
    category    = "enum"
    description = "One-line description shown in the script tree."

    def run(self, **kwargs):
        # kwargs contains all extra parameters (port, userlist, etc.)
        # self.target  → Target(ip, domain, timeout)
        # self.creds   → Creds(user, password, domain, hash)

        port = int(kwargs.get("port") or 445)

        mod = SMBModule(self.target, self.creds)
        if not mod.connect(port=port):
            return None

        try:
            # ... your logic here ...
            result = mod.some_operation()

            print_result("SMB", self.target.ip, "ok", "Operation succeeded")
            session_db.save_finding(self.target.ip, "SMB", "my_check", str(result))

            return result
        finally:
            mod.disconnect()
```

### Class contract

| Attribute / method | Required | Description |
|---|---|---|
| `name` | yes | Script identifier (kebab-case). Must be unique per protocol. |
| `protocol` | yes | Protocol name in lowercase (`smb`, `ldap`, etc.) |
| `category` | yes | Family name (`enum`, `attack`, `exploit`, `post`) |
| `description` | yes | One-line description shown in the tree and parameter card |
| `run(self, **kwargs)` | yes | Main entry point. Return `None` on failure, any value on success. |

### BaseScript internals

```python
class BaseScript:
    def __init__(self, target: Target, creds: Creds):
        self.target = target
        self.creds  = creds

    def run(self, **kwargs):
        raise NotImplementedError
```

### Adding parameters to the shell and classic mode

Create or update `scripts/<protocol>/shell_params.py`:

```python
SCRIPT_PARAMS = {
    "my-check": {
        "description": "One-line description.",
        "required": ["target"],
        "optional": ["user", "password", "port", "timeout"],
        "defaults": {"port": 445, "timeout": 5},
        "example": [
            "set target 10.10.10.5",
            "run",
        ],
    },
}

PARAM_LABELS = {
    "target":  "Target IP/hostname",
    "port":    "SMB port (default: 445)",
    "timeout": "Connection timeout (seconds)",
}
```

Without a `shell_params.py` entry the script still runs — Lobera just shows minimal parameter info.

### Adding the script to the autopwn scanner

Edit `scripts/<protocol>/scan_params.py` and add an entry to `SCAN_ORDER`:

```python
SCAN_ORDER = [
    ...
    {"script": "my-check", "condition": None},           # always runs
    {"script": "my-check", "condition": "has_auth"},     # only if credentials present
    ...
]
```

Available conditions (defined in `ScanContext`):

| Condition | True when |
|---|---|
| `None` | Always |
| `has_auth` | `user` and (`password` or `hash`) are set |
| `has_userlist` | A valid userlist file path is provided |
| `has_shares` | The shares script found at least one non-special share |
| `has_ccache` | A `.ccache` file is available (given or generated by overpass-the-hash) |
| `has_krbtgt_sid` | Both `krbtgt_hash` and `domain_sid` are provided |

Custom conditions can be added to the protocol's `ScanContext` subclass.

---

## Authentication

On first run, Lobera creates an encrypted local session. You set a master password — credentials are stored with PBKDF2-HMAC-SHA256. Sessions expire after 8 hours.

---

## Target platforms

- Linux (Kali, Parrot) — primary
- macOS (Apple Silicon, via ARM64 VM) — tested
- Windows — not tested

---

## Disclaimer

Lobera is a personal educational project. Use it only on systems you own or have explicit written permission to test. Unauthorized use against third-party systems is illegal.

---

## Author

**mitr0kerb** — built as a hands-on deep-dive into Active Directory protocols.

## Collaborations

If you would like to contribute new scripts, modules, or improvements, you can contact:

📧 mitr0kerb@gmail.com
