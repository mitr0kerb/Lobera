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
         "bad": "smb --script=spider -t 10.129.1.5 -u iker --share ADMIN$  [shares especiales rara vez tienen contenido de usuario]"},
        {"flag": "--ext",
         "desc": "Extensiones a buscar separadas por coma; vacío ('') = sin filtro de extensión",
         "good": "smb --script=spider -t 10.129.1.5 -u iker --ext .kdbx,.txt",
         "bad": "smb --script=spider -t 10.129.1.5 -u iker --ext ''  [descarga TODO, puede tardar mucho y llenar disco]"},
        {"flag": "--keywords",
         "desc": "Palabras clave a buscar en nombres de fichero, separadas por coma",
         "good": "smb --script=spider -t 10.129.1.5 -u iker --keywords password,backup",
         "bad": "smb --script=spider -t 10.129.1.5 -u iker --keywords a,e,i  [keywords tan cortas generan falsos positivos masivos]"},
        {"flag": "--depth",
         "desc": "Profundidad máxima de recursión (default: 5)",
         "good": "smb --script=spider -t 10.129.1.5 -u iker --depth 3  [suficiente para perfiles de usuario típicos]",
         "bad": "smb --script=spider -t 10.129.1.5 -u iker --depth 20  [en C$ puede tardar muchísimo]"},
    ]

    def run(self, **kwargs):
        smb = SMBModule(self.target, self.creds)
        if not smb.connect():
            return
        if not smb.login():
            return

        share = kwargs.get("share")
        extensions = _parse_csv(kwargs.get("ext"))
        keywords = _parse_csv(kwargs.get("keywords"))
        # Usar "is not None" en vez de "or" — depth=0 es un valor válido
        # (sin recursión). kwargs.get("depth") or 5 silenciaría el 0.
        _raw_depth = kwargs.get("depth")
        depth = _raw_depth if _raw_depth is not None else 5

        spider_kwargs = {"max_depth": depth, "keywords": keywords}
        if extensions is not None:
            spider_kwargs["extensions"] = extensions

        if share:
            results = smb.spider_share(share, **spider_kwargs)
        else:
            results = smb.spider_all_shares(**spider_kwargs)
        smb.disconnect()
        return results
