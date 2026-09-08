# scripts/smb/enum/spider.py

from scripts.base import BaseScript
from modules.smb import SMBModule


def _parse_csv(raw):
    if raw is None:
        return None
    if raw == "":
        return []
    return [item.strip() for item in raw.split(",") if item.strip()]


class SpiderScript(BaseScript):
    name = "spider"
    description = "Rastrea shares SMB y descarga ficheros interesantes por extensión/keyword"
    examples = [
        {"flag": "--share",
         "desc": "Restringe el rastreo a un único share. Si se omite, rastrea TODOS los shares no especiales",
         "good": "smb --script=spider -t 10.129.1.5 -u iker --share Users",
         "bad": "smb --script=spider -t 10.129.1.5 -u iker --share ADMIN$"},
        {"flag": "--ext",
         "desc": "Extensiones a buscar separadas por coma; vacío = sin filtro",
         "good": "smb --script=spider -t 10.129.1.5 -u iker --ext .kdbx,.txt",
         "bad": "smb --script=spider -t 10.129.1.5 -u iker --ext ''"},
        {"flag": "--keywords",
         "desc": "Palabras clave a buscar en nombres de fichero",
         "good": "smb --script=spider -t 10.129.1.5 -u iker --keywords password,backup",
         "bad": "smb --script=spider -t 10.129.1.5 -u iker --keywords a,e,i"},
        {"flag": "--depth",
         "desc": "Profundidad máxima de recursión (default: 5)",
         "good": "smb --script=spider -t 10.129.1.5 -u iker --depth 3",
         "bad": "smb --script=spider -t 10.129.1.5 -u iker --depth 20"},
        {"flag": "--no-confirm",
         "desc": "Descarga sin pedir confirmación (por defecto siempre pregunta)",
         "good": "smb --script=spider -t 10.129.1.5 -u iker --no-confirm",
         "bad": "smb --script=spider -t 10.129.1.5 -u iker --no-confirm --ext ''"},
    ]

    def run(self, **kwargs):
        smb = SMBModule(self.target, self.creds)
        if not smb.connect():
            return
        if not smb.login():
            return

        share      = kwargs.get("share")
        extensions = _parse_csv(kwargs.get("ext"))
        keywords   = _parse_csv(kwargs.get("keywords"))
        _raw_depth = kwargs.get("depth")
        depth      = _raw_depth if _raw_depth is not None else 5
        # confirm=True por defecto — el usuario puede desactivarlo con no_confirm=True
        confirm    = not kwargs.get("no_confirm", False)

        spider_kwargs = {"max_depth": depth, "keywords": keywords, "confirm": confirm}
        if extensions is not None:
            spider_kwargs["extensions"] = extensions

        if share:
            results = smb.spider_share(share, **spider_kwargs)
        else:
            results = smb.spider_all_shares(**spider_kwargs)

        smb.disconnect()
        return results
