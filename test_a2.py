"""Pruebas unitarias para el Algoritmo A2: Double Ratchet reducido (A2-01 a A2-05)."""

from __future__ import annotations

import os
import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from a2_ratchet import Ratchet
from test_a1 import _registrar_resultado


def _crear_par_participantes() -> tuple[Ratchet, Ratchet]:
    """Inicializa a Alice y Bob compartiendo una clave raíz de 32 bytes."""
    clave_raiz = os.urandom(32)
    bob = Ratchet(clave_raiz)
    alice = Ratchet(clave_raiz, clave_publica_remota=bob.clave_publica)
    return alice, bob


def test_A2_01() -> None:
    """A2-01 (descifrado): 6 mensajes con cambio de dirección X25519 (6/6 correctos)."""
    alice, bob = _crear_par_participantes()
    pub_inicial_bob = bob.clave_publica
    pub_inicial_alice = alice.clave_publica

    mensajes_originales = [
        "Mensaje 1: Hola Bob",
        "Mensaje 2: Reporte inicial",
        "Mensaje 3: Fin de ráfaga inicial",
        "Mensaje 4: Hola Alice, cambio de dirección",
        "Mensaje 5: Confirmación desde Bob",
        "Mensaje 6: Respuesta final de Alice tras rotación",
    ]
    descifrados: list[str] = []

    # Mensajes 1..3: Alice -> Bob
    for texto in mensajes_originales[:3]:
        paquete = alice.enviar(texto)
        descifrados.append(bob.recibir(paquete))

    # Cambio de dirección 1 (Bob -> Alice): obliga a Bob a generar nuevo par X25519
    nueva_pub_bob = bob.cambiar_direccion()
    assert nueva_pub_bob != pub_inicial_bob

    for texto in mensajes_originales[3:5]:
        paquete = bob.enviar(texto)
        descifrados.append(alice.recibir(paquete))

    # Cambio de dirección 2 (Alice -> Bob): obliga a Alice a generar nuevo par X25519
    nueva_pub_alice = alice.cambiar_direccion()
    assert nueva_pub_alice != pub_inicial_alice

    paquete_6 = alice.enviar(mensajes_originales[5])
    descifrados.append(bob.recibir(paquete_6))

    aciertos = sum(
        1 for orig, dec in zip(mensajes_originales, descifrados) if orig == dec
    )
    esperado = "6/6 correctos"
    obtenido = f"{aciertos}/6 correctos"
    estado = "OK" if obtenido == esperado else "FALLA"
    _registrar_resultado(
        "A2-01",
        esperado,
        obtenido,
        estado,
        "Intercambio de 6 mensajes con rotacion de claves X25519 descifrado al 100%",
    )

    assert obtenido == esperado
    assert estado == "OK"


def test_A2_02() -> None:
    """A2-02 (integridad): Un byte alterado del ciphertext es rechazado."""
    alice, bob = _crear_par_participantes()
    paquete = alice.enviar("Mensaje confidencial íntegro")

    # Alterar 1 byte del ciphertext
    ciphertext_alterado = bytearray(paquete["ciphertext"])
    ciphertext_alterado[0] ^= 0x01
    paquete_alterado = {
        **paquete,
        "ciphertext": bytes(ciphertext_alterado),
    }

    esperado = "rechazado"
    try:
        bob.recibir(paquete_alterado)
        obtenido = "aceptado"
    except ValueError as exc:
        assert "Integridad fallida" in str(exc)
        obtenido = "rechazado"

    estado = "OK" if obtenido == esperado else "FALLA"
    _registrar_resultado(
        "A2-02",
        esperado,
        obtenido,
        estado,
        "Etiqueta de autenticacion AES-GCM detecta alteracion de 1 byte y rechaza paquete",
    )
    assert obtenido == esperado
    assert estado == "OK"


def test_A2_03() -> None:
    """A2-03 (repetición): Mensaje reenviado es rechazado."""
    alice, bob = _crear_par_participantes()
    paquete = alice.enviar("Orden de pago única #001")

    # Primera recepción legítima
    assert bob.recibir(paquete) == "Orden de pago única #001"

    # Reenvío del mismo paquete (ataque de replay)
    esperado = "rechazado"
    try:
        bob.recibir(paquete)
        obtenido = "aceptado"
    except ValueError as exc:
        assert "repetido" in str(exc).lower()
        obtenido = "rechazado"

    estado = "OK" if obtenido == esperado else "FALLA"
    _registrar_resultado(
        "A2-03",
        esperado,
        obtenido,
        estado,
        "Control anti-replay detecta identificador duplicado y rechaza mensaje reenviado",
    )
    assert obtenido == esperado
    assert estado == "OK"


def test_A2_04() -> None:
    """A2-04 (forward secrecy): Estado robado tras mensaje 3 no descifra mensaje 1."""
    alice, bob = _crear_par_participantes()

    paquete_1 = alice.enviar("Mensaje 1 histórico")
    paquete_2 = alice.enviar("Mensaje 2 intermedio")
    paquete_3 = alice.enviar("Mensaje 3 actual")

    assert bob.recibir(paquete_1) == "Mensaje 1 histórico"
    assert bob.recibir(paquete_2) == "Mensaje 2 intermedio"
    assert bob.recibir(paquete_3) == "Mensaje 3 actual"

    # El atacante roba el estado de Bob después de haber procesado el mensaje 3
    estado_robado = bob.clonar_estado()
    # Incluso si el atacante limpia el registro anti-replay o intenta derivar claves
    estado_robado.mensajes_recibidos.clear()

    esperado = "no descifrable"
    fallo_ratchet = False
    try:
        estado_robado.recibir(paquete_1)
    except ValueError as exc:
        assert "forward secrecy" in str(exc).lower()
        fallo_ratchet = True

    # Verificación criptográfica directa: la clave de cadena actual tampoco abre el mensaje 1
    fallo_cripto = False
    assert estado_robado.recv_chain_key is not None
    _, mk_posterior = Ratchet._kdf_ck(estado_robado.recv_chain_key)
    aad_1 = Ratchet._construir_aad(paquete_1["dh_pub"], paquete_1["num_msg"])
    try:
        AESGCM(mk_posterior).decrypt(
            paquete_1["nonce"], paquete_1["ciphertext"], aad_1
        )
    except InvalidTag:
        fallo_cripto = True

    obtenido = "no descifrable" if (fallo_ratchet and fallo_cripto) else "descifrado"
    estado = "OK" if obtenido == esperado else "FALLA"
    _registrar_resultado(
        "A2-04",
        esperado,
        obtenido,
        estado,
        "Avance unidireccional HKDF y borrado de MK impiden descifrar mensajes previos",
    )

    assert obtenido == esperado
    assert estado == "OK"


def test_A2_05() -> None:
    """A2-05 (post-compromise): Estado robado antes del cambio de dirección no descifra tras él."""
    alice, bob = _crear_par_participantes()

    # Mensajes 1..3 antes del cambio de dirección
    for i in range(1, 4):
        p = alice.enviar(f"Mensaje previo {i}")
        assert bob.recibir(p) == f"Mensaje previo {i}"

    # El atacante roba el estado de Bob ANTES del cambio de dirección X25519
    estado_robado_antes = bob.clonar_estado()

    # Cambio de dirección: Bob genera nuevo par X25519 efímero que el atacante no posee
    bob.cambiar_direccion()
    p4 = bob.enviar("Mensaje 4 tras rotación de Bob")
    p5 = bob.enviar("Mensaje 5 tras rotación de Bob")
    assert alice.recibir(p4) == "Mensaje 4 tras rotación de Bob"
    assert alice.recibir(p5) == "Mensaje 5 tras rotación de Bob"

    # Alice responde cambiando de dirección hacia la nueva clave pública X25519 de Bob
    alice.cambiar_direccion()
    p6_post_rotacion = alice.enviar("Mensaje 6 protegido post-compromiso")

    # El receptor legítimo (Bob) sí puede descifrar el mensaje 6
    assert bob.recibir(p6_post_rotacion) == "Mensaje 6 protegido post-compromiso"

    # El atacante con el estado robado antes del cambio de dirección intenta descifrar p6
    esperado = "no descifrable"
    try:
        estado_robado_antes.recibir(p6_post_rotacion)
        obtenido = "descifrado"
    except ValueError:
        obtenido = "no descifrable"

    estado = "OK" if obtenido == esperado else "FALLA"
    _registrar_resultado(
        "A2-05",
        esperado,
        obtenido,
        estado,
        "Nuevo par efimero X25519 en cambio de direccion renueva clave raiz y bloquea estado robado",
    )
    assert obtenido == esperado
    assert estado == "OK"


A2_01 = test_A2_01
A2_02 = test_A2_02
A2_03 = test_A2_03
A2_04 = test_A2_04
A2_05 = test_A2_05
