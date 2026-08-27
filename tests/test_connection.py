# tests/test_connection.py

from core.connection import with_retries

# Caso 1: función que siempre falla -> debe agotar intentos y relanzar
contador = {"intentos": 0}

def funcion_que_falla():
    contador["intentos"] += 1
    raise ConnectionError(f"fallo simulado (intento {contador['intentos']})")

try:
    with_retries(funcion_que_falla, max_attempts=3, delay=0)
except ConnectionError as e:
    print(f"Excepción relanzada correctamente tras {contador['intentos']} intentos: {e}")

# Caso 2: función que falla las dos primeras veces y luego funciona
contador2 = {"intentos": 0}

def funcion_que_a_veces_falla():
    contador2["intentos"] += 1
    if contador2["intentos"] < 3:
        raise ConnectionError("fallo temporal")
    return "conexión OK"

resultado = with_retries(funcion_que_a_veces_falla, max_attempts=5, delay=0)
print(f"Resultado: {resultado} (en {contador2['intentos']} intentos)")
