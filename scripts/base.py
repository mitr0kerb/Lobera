# scripts/base.py

class BaseScript:
    """
    Clase base que debe heredar cualquier script colocado en
    scripts/<protocolo>/<familia>/.

    El loader (scripts/loader.py) descubre automáticamente cualquier clase que:
      - herede de BaseScript (pero no sea BaseScript en sí)
      - tenga 'name' definido (no None)

    'protocol' y 'category' los asigna el loader según la ruta de carpetas
    que contiene el fichero (scripts/<protocol>/<category>/archivo.py) --
    no hace falta declararlos a mano, el loader manda siempre.
    """
    name = None           # identificador único usado en --script, ej: "shares"
    protocol = None       # lo asigna el loader según la carpeta de protocolo (ej. "smb")
    category = None       # lo asigna el loader según la carpeta de familia (ej. "enum")
    description = ""      # una línea, se muestra en el árbol de listado

    # Ejemplos de uso propios de ESTE script, mismo formato que antes se
    # centralizaba en un EXAMPLES global: lista de {"flag","desc","good","bad"}.
    # Documenta aquí solo los flags que este script usa de verdad -- los
    # comunes (-t/-u/-p/-H/-d/--timeout) se explican una vez en el árbol de
    # listado del protocolo, no hace falta repetirlos salvo caso especial.
    examples = []

    def __init__(self, target, creds):
        self.target = target
        self.creds = creds

    def run(self, **kwargs):
        """
        Punto de entrada del script. 'kwargs' contiene TODOS los flags
        opcionales declarados a nivel de protocolo (ej. --share, --ext,
        --userlist...) -- el script debe coger solo los que le interesan
        con kwargs.get(...) e ignorar el resto.
        """
        raise NotImplementedError(f"{self.__class__.__name__} debe implementar run()")
