# core/connection.py

import time


def with_retries(func, max_attempts=3, delay=1):

    """
    Ejecuta func() reintentando si lanza excepción.
    func debe ser una llamada sin argumentos: usa lambda para pasarle los suyos.
    Ej: with_retries(lambda: smb_module.connect(), max_attempts=3)
    """

    last_exception = None

    for attempt in range(1, max_attempts + 1):
        try:
            return func()
        except Exception as e:
            last_exception = e
            if attempt < max_attempts:
                time.sleep(delay)

    raise last_exception
