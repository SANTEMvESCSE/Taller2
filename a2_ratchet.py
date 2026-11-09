"""Sprint 3 - Algoritmo A2: Double Ratchet reducido (X25519 + HKDF-SHA256 + AES-256-GCM).

Implementación académica del protocolo Double Ratchet reducido para el taller
"Seguridad en Messenger". Combina:
1. Ratchet simétrico (KDF de cadena con HKDF-SHA256) para Forward Secrecy en cada mensaje.
2. Ratchet Diffie-Hellman efímero (X25519) al cambiar de dirección para Post-Compromise Security.
3. Cifrado autenticado AEAD (AES-256-GCM) con datos asociados (clave pública DH + índice).
"""

from __future__ import annotations

import os
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class Ratchet:
    """Participante del protocolo Double Ratchet reducido."""

    _INFO_ROOT = b"A2-DoubleRatchet-RootKDF"
    _INFO_CHAIN = b"A2-DoubleRatchet-ChainKDF"

    def __init__(
        self,
        clave_raiz: bytes,
        par_dh_propio: X25519PrivateKey | None = None,
        clave_publica_remota: bytes | None = None,
    ) -> None:
        """Inicializa el estado del participante con una clave raíz de 32 bytes.

        Si no se provee `par_dh_propio`, genera un par efímero X25519 nuevo.
        Si se provee `clave_publica_remota`, inicializa las cadenas iniciales
        de envío y recepción mediante un paso Diffie-Hellman sobre la clave raíz.
        """
        if not isinstance(clave_raiz, (bytes, bytearray)) or len(clave_raiz) != 32:
            raise ValueError("La clave_raiz debe tener exactamente 32 bytes.")

        self.root_key: bytes = bytes(clave_raiz)
        self.dh_private: X25519PrivateKey = (
            par_dh_propio if par_dh_propio is not None else X25519PrivateKey.generate()
        )
        self.dh_remote_pub: bytes | None = None
        self.send_chain_key: bytes | None = None
        self.recv_chain_key: bytes | None = None
        self.send_count: int = 0
        self.recv_count: int = 0
        self.mensajes_recibidos: set[tuple[bytes, int, bytes]] = set()

        if clave_publica_remota is not None:
            self.dh_remote_pub = bytes(clave_publica_remota)
            secreto_dh = self._calcular_dh(self.dh_private, self.dh_remote_pub)
            self.root_key, cadena_inicial = self._kdf_rk(self.root_key, secreto_dh)
            self.send_chain_key = cadena_inicial
            self.recv_chain_key = cadena_inicial

    @property
    def clave_publica(self) -> bytes:
        """Retorna los 32 bytes crudos de la clave pública X25519 actual."""
        return self.dh_private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    @staticmethod
    def _calcular_dh(clave_privada: X25519PrivateKey, clave_publica_bytes: bytes) -> bytes:
        """Calcula el secreto compartido X25519 de 32 bytes."""
        clave_publica = X25519PublicKey.from_public_bytes(clave_publica_bytes)
        return clave_privada.exchange(clave_publica)

    @classmethod
    def _kdf_rk(cls, root_key: bytes, dh_secret: bytes) -> tuple[bytes, bytes]:
        """KDF de clave raíz (HKDF-SHA256): deriva (nueva_root_key, nueva_chain_key)."""
        material = HKDF(
            algorithm=SHA256(),
            length=64,
            salt=root_key,
            info=cls._INFO_ROOT,
        ).derive(dh_secret)
        return material[:32], material[32:]

    @classmethod
    def _kdf_ck(cls, chain_key: bytes) -> tuple[bytes, bytes]:
        """KDF de cadena simétrica (HKDF-SHA256): deriva (nueva_chain_key, message_key)."""
        material = HKDF(
            algorithm=SHA256(),
            length=64,
            salt=None,
            info=cls._INFO_CHAIN,
        ).derive(chain_key)
        return material[:32], material[32:]

    @staticmethod
    def _construir_aad(dh_pub: bytes, num_msg: int) -> bytes:
        """Construye los datos asociados autenticados (AAD) del encabezado."""
        return dh_pub + num_msg.to_bytes(4, byteorder="big")

    def cambiar_direccion(self, clave_publica_remota: bytes | None = None) -> bytes:
        """Ejecuta el ratchet Diffie-Hellman generando un nuevo par de claves X25519.

        Actualiza `root_key`, deriva una nueva `send_chain_key`, reinicia el contador
        de envío y descarta la clave privada y cadena de envío anteriores.
        Retorna los 32 bytes de la nueva clave pública X25519 propia.
        """
        if clave_publica_remota is not None:
            self.dh_remote_pub = bytes(clave_publica_remota)

        if self.dh_remote_pub is None:
            raise ValueError(
                "Se requiere clave_publica_remota para ejecutar cambiar_direccion."
            )

        self.dh_private = X25519PrivateKey.generate()
        secreto_dh = self._calcular_dh(self.dh_private, self.dh_remote_pub)
        self.root_key, self.send_chain_key = self._kdf_rk(self.root_key, secreto_dh)
        self.send_count = 0
        return self.clave_publica

    def enviar(self, texto: str) -> dict:
        """Avanza la cadena de envío, cifra `texto` con AES-256-GCM y descarta `mk`.

        Retorna un diccionario con `dh_pub`, `num_msg`, `nonce` y `ciphertext`.
        """
        if self.send_chain_key is None:
            if self.dh_remote_pub is None:
                raise ValueError(
                    "No hay cadena de envío ni clave pública remota configurada."
                )
            self.cambiar_direccion(self.dh_remote_pub)

        assert self.send_chain_key is not None
        self.send_chain_key, mk = self._kdf_ck(self.send_chain_key)
        num_msg = self.send_count
        self.send_count += 1

        dh_pub = self.clave_publica
        nonce = os.urandom(12)
        aad = self._construir_aad(dh_pub, num_msg)

        try:
            ciphertext = AESGCM(mk).encrypt(nonce, texto.encode("utf-8"), aad)
        finally:
            mk = b"\x00" * 32
            del mk

        return {
            "dh_pub": dh_pub,
            "num_msg": num_msg,
            "nonce": nonce,
            "ciphertext": ciphertext,
        }

    def recibir(self, paquete: dict) -> str:
        """Procesa un paquete recibido verificando repetición, forward secrecy e integridad.

        - Rechaza paquetes repetidos.
        - Si detecta una nueva clave pública X25519 del emisor, ejecuta el paso DH de
          recepción para sincronizar `root_key` y derivar la nueva `recv_chain_key`.
        - Rechaza índices de mensajes pasados cuyas claves ya fueron descartadas.
        - Avanza `recv_chain_key`, descifra y autentica con AES-256-GCM, y descarta `mk`.
        """
        dh_pub = bytes(paquete["dh_pub"])
        num_msg = int(paquete["num_msg"])
        nonce = bytes(paquete["nonce"])
        ciphertext = bytes(paquete["ciphertext"])

        id_mensaje = (dh_pub, num_msg, nonce)
        if id_mensaje in self.mensajes_recibidos:
            raise ValueError("Mensaje repetido rechazado")

        cambio_dh = dh_pub != self.dh_remote_pub or self.recv_chain_key is None
        root_key_candidata = self.root_key
        if cambio_dh:
            secreto_dh = self._calcular_dh(self.dh_private, dh_pub)
            root_key_candidata, cadena_recepcion = self._kdf_rk(
                self.root_key, secreto_dh
            )
            indice_esperado = 0
        else:
            assert self.recv_chain_key is not None
            cadena_recepcion = self.recv_chain_key
            indice_esperado = self.recv_count

        if num_msg < indice_esperado:
            raise ValueError("Clave pasada descartada: forward secrecy")
        if num_msg > indice_esperado:
            raise ValueError("Mensaje fuera de orden no soportado en versión reducida")

        nueva_cadena_recepcion, mk = self._kdf_ck(cadena_recepcion)
        aad = self._construir_aad(dh_pub, num_msg)

        try:
            plaintext = AESGCM(mk).decrypt(nonce, ciphertext, aad)
        except InvalidTag as exc:
            raise ValueError("Integridad fallida: ciphertext alterado") from exc
        finally:
            mk = b"\x00" * 32
            del mk

        if cambio_dh:
            self.dh_remote_pub = dh_pub
            self.root_key = root_key_candidata
        self.recv_chain_key = nueva_cadena_recepcion
        self.recv_count = indice_esperado + 1
        self.mensajes_recibidos.add(id_mensaje)

        return plaintext.decode("utf-8")

    def clonar_estado(self) -> "Ratchet":
        """Crea una copia exacta e independiente del estado actual en memoria.

        Útil en pruebas de seguridad para simular el robo del estado interno de un
        participante en un instante específico (Forward Secrecy y Post-Compromise).
        """
        bytes_privada = self.dh_private.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        clon = Ratchet(
            clave_raiz=self.root_key,
            par_dh_propio=X25519PrivateKey.from_private_bytes(bytes_privada),
        )
        clon.dh_remote_pub = self.dh_remote_pub
        clon.send_chain_key = self.send_chain_key
        clon.recv_chain_key = self.recv_chain_key
        clon.send_count = self.send_count
        clon.recv_count = self.recv_count
        clon.mensajes_recibidos = set(self.mensajes_recibidos)
        return clon
