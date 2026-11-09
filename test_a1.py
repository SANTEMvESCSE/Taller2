"""Pruebas unitarias para el Algoritmo A1 (Cadena de claves simétrica).

Verifica los 4 casos de prueba de la plantilla de resultados del taller:
- A1-01: Determinismo de la derivación con HKDF-SHA256.
- A1-02: Unicidad de 10 claves derivadas para 10 índices distintos.
- A1-03: Cifrado y descifrado correcto de 10 mensajes distintos con AES-GCM.
- A1-04: Borrado efectivo e irrecuperabilidad de una clave ya usada.
"""

from __future__ import annotations

import csv
import json
import os
from pathlib import Path
import pytest

from a1_cadena import (
    CadenaClaves,
    avanzar_cadena,
    cifrar,
    derivar_clave,
    descifrar,
)

BASE_DIR = Path(__file__).resolve().parent
LOG_JSON_PATH = BASE_DIR / "log_pruebas.json"
RESULTADOS_CSV_PATH = BASE_DIR / "resultados.csv"

PLANTILLA_FILAS = [
    ("A1-01", "A1", "determinismo", "Misma cadena e índice producen la misma clave", "misma clave"),
    ("A1-02", "A1", "unicidad", "10 claves de mensaje distintas", "10 claves distintas"),
    ("A1-03", "A1", "cifrado", "Cifrar y descifrar 10 mensajes", "10/10 correctos"),
    ("A1-04", "A1", "borrado", "Clave usada y luego borrada no se recupera", "no recuperable"),
    ("A2-01", "A2", "descifrado", "Descifrar los 6 mensajes", "6/6 correctos"),
    ("A2-02", "A2", "integridad", "Un byte alterado del ciphertext", "rechazado"),
    ("A2-03", "A2", "repetición", "Mensaje reenviado", "rechazado"),
    ("A2-04", "A2", "forward secrecy", "Estado robado tras mensaje 3 no descifra mensaje 1", "no descifrable"),
    ("A2-05", "A2", "post-compromise", "Estado robado antes del cambio de dirección no descifra tras él", "no descifrable"),
]


def _registrar_resultado(
    id_prueba: str, esperado: str, obtenido: str, estado: str, comentario: str
) -> None:
    """Actualiza log_pruebas.json y resultados.csv con el resultado de la prueba."""
    registros: dict[str, dict[str, str]] = {}
    if LOG_JSON_PATH.exists():
        try:
            datos = json.loads(LOG_JSON_PATH.read_text(encoding="utf-8"))
            for item in datos:
                registros[item["prueba"]] = item
        except Exception:
            registros = {}

    registros[id_prueba] = {
        "prueba": id_prueba,
        "esperado": esperado,
        "obtenido": obtenido,
        "estado": estado,
    }
    orden = [fila[0] for fila in PLANTILLA_FILAS]
    lista_ordenada = [registros[k] for k in orden if k in registros]
    LOG_JSON_PATH.write_text(
        json.dumps(lista_ordenada, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    comentarios_previos: dict[str, str] = {}
    if RESULTADOS_CSV_PATH.exists():
        try:
            with RESULTADOS_CSV_PATH.open("r", encoding="utf-8", newline="") as f:
                for row in csv.DictReader(f):
                    if row.get("id_prueba") and row.get("comentario"):
                        comentarios_previos[row["id_prueba"]] = row["comentario"]
        except Exception:
            pass
    comentarios_previos[id_prueba] = comentario

    with RESULTADOS_CSV_PATH.open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                "id_prueba",
                "algoritmo",
                "propiedad",
                "descripcion",
                "esperado",
                "obtenido",
                "estado",
                "comentario",
            ]
        )
        for pid, alg, prop, desc, esp in PLANTILLA_FILAS:
            reg = registros.get(pid)
            obt = reg["obtenido"] if reg else ""
            est = reg["estado"] if reg else ""
            com = comentarios_previos.get(pid, "")
            writer.writerow([pid, alg, prop, desc, esp, obt, est, com])


def test_A1_01() -> None:
    """A1-01 (determinismo): Misma cadena e índice producen la misma clave.

    Esperado: "misma clave" | Obtenido: "misma clave" | Estado: "OK"
    """
    semilla = os.urandom(32)
    indice = 7

    clave_1 = derivar_clave(semilla, indice)
    clave_2 = derivar_clave(semilla, indice)

    esperado = "misma clave"
    obtenido = "misma clave" if (clave_1 == clave_2 and len(clave_1) == 32) else "clave distinta"
    estado = "OK" if obtenido == esperado else "FALLA"
    _registrar_resultado(
        "A1-01",
        esperado,
        obtenido,
        estado,
        "HKDF-SHA256 determinista produce identica clave de 32 bytes",
    )
    assert obtenido == esperado


def test_A1_02() -> None:
    """A1-02 (unicidad): 10 claves de mensaje distintas para 10 índices/pasos.

    Esperado: "10 claves distintas" | Obtenido: "10 claves distintas" | Estado: "OK"
    """
    semilla = os.urandom(32)
    claves_por_indice = [derivar_clave(semilla, i) for i in range(10)]

    # También verificamos el avance paso a paso de la cadena (ratchet)
    gestor = CadenaClaves(semilla)
    claves_ratchet = [gestor.generar_siguiente_clave()[1] for _ in range(10)]

    num_unicas_indice = len(set(claves_por_indice))
    num_unicas_ratchet = len(set(claves_ratchet))

    esperado = "10 claves distintas"
    obtenido = (
        "10 claves distintas"
        if (num_unicas_indice == 10 and num_unicas_ratchet == 10)
        else f"{min(num_unicas_indice, num_unicas_ratchet)} claves distintas"
    )
    estado = "OK" if obtenido == esperado else "FALLA"
    _registrar_resultado(
        "A1-02",
        esperado,
        obtenido,
        estado,
        "Las 10 claves derivadas en la cadena son criptograficamente unicas",
    )
    assert obtenido == esperado


def test_A1_03() -> None:
    """A1-03 (cifrado): Cifrar y descifrar 10 mensajes distintos con sus claves derivadas.

    Esperado: "10/10 correctos" | Obtenido: "10/10 correctos" | Estado: "OK"
    """
    semilla = os.urandom(32)
    mensajes = [f"Mensaje confidencial #{i}: prueba de cifrado AES-GCM" for i in range(10)]
    correctos = 0

    cadena_actual = semilla
    for i, mensaje_original in enumerate(mensajes):
        cadena_actual, clave_msg = avanzar_cadena(cadena_actual, i)
        datos_cifrados = cifrar(clave_msg, mensaje_original)
        texto_recuperado = descifrar(clave_msg, datos_cifrados)
        if texto_recuperado == mensaje_original and datos_cifrados[:12] != datos_cifrados[12:]:
            correctos += 1

    esperado = "10/10 correctos"
    obtenido = f"{correctos}/10 correctos"
    estado = "OK" if obtenido == esperado else "FALLA"
    _registrar_resultado(
        "A1-03",
        esperado,
        obtenido,
        estado,
        "Cifrado y descifrado autenticado AES-256-GCM exitoso en los 10 mensajes",
    )
    assert obtenido == esperado


def test_A1_04() -> None:
    """A1-04 (borrado): Clave usada y luego borrada no se recupera desde el gestor de cadena.

    Esperado: "no recuperable" | Obtenido: "no recuperable" | Estado: "OK"
    """
    semilla = os.urandom(32)
    gestor = CadenaClaves(semilla)

    # Se usa y borra la clave del índice 0
    clave_usada = gestor.usar_y_borrar_clave(0)
    mensaje_cifrado = cifrar(clave_usada, "Secreto efímero")
    assert descifrar(clave_usada, mensaje_cifrado) == "Secreto efímero"

    # Intentar recuperarla o volver a usarla desde el gestor debe lanzar KeyError
    recuperable = True
    try:
        gestor.recuperar_clave(0)
    except KeyError:
        recuperable = False

    # Tampoco debe poder recalcularse con el estado actual de la cadena interna
    _, clave_recalculada_desde_estado_actual = avanzar_cadena(gestor._cadena_actual, 0)
    assert clave_recalculada_desde_estado_actual != clave_usada

    esperado = "no recuperable"
    obtenido = "no recuperable" if not recuperable else "recuperable"
    estado = "OK" if obtenido == esperado else "FALLA"
    _registrar_resultado(
        "A1-04",
        esperado,
        obtenido,
        estado,
        "Clave efimera eliminada tras su uso y cadena avanzada irreversiblemente",
    )
    assert obtenido == esperado


A1_01 = test_A1_01
A1_02 = test_A1_02
A1_03 = test_A1_03
A1_04 = test_A1_04
