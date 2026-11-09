"""Módulo A1: Cadena de claves simétrica (Symmetric Key Ratchet) para Seguridad en Messenger.

Implementa la derivación de claves por mensaje mediante HKDF-SHA256, el cifrado
autenticado con AES-256-GCM y un gestor de cadena de claves con borrado seguro
para garantizar secreto hacia adelante (Forward Secrecy) en la cadena simétrica.
"""

from __future__ import annotations

import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

NONCE_SIZE = 12
KEY_SIZE = 32


def derivar_clave(cadena: bytes, indice: int) -> bytes:
    """Deriva una clave de mensaje de 32 bytes usando HKDF-SHA256.

    Para un mismo par ``(cadena, indice)`` siempre produce la misma clave
    (determinismo), y para índices distintos produce claves criptográficamente
    independientes (unicidad).

    Args:
        cadena: Clave de cadena simétrica de entrada (bytes, recomendado 32 bytes).
        indice: Índice entero no negativo del mensaje dentro de la cadena.

    Returns:
        Clave derivada de 32 bytes apta para AES-256-GCM.

    Raises:
        TypeError: Si ``cadena`` no es ``bytes`` o ``indice`` no es ``int``.
        ValueError: Si ``cadena`` está vacía o ``indice`` es negativo.
    """
    if not isinstance(cadena, (bytes, bytearray)):
        raise TypeError("La clave de cadena debe ser de tipo bytes.")
    if not isinstance(indice, int) or isinstance(indice, bool):
        raise TypeError("El índice debe ser un número entero.")
    if len(cadena) == 0:
        raise ValueError("La clave de cadena no puede estar vacía.")
    if indice < 0:
        raise ValueError("El índice no puede ser negativo.")

    info = f"A1-clave-mensaje:{indice}".encode("utf-8")
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=None,
        info=info,
    )
    return hkdf.derive(bytes(cadena))


def avanzar_cadena(cadena: bytes, indice: int = 0) -> tuple[bytes, bytes]:
    """Avanza un paso la cadena simétrica (ratchet) de forma unidireccional.

    A partir de la clave de cadena actual genera:
    1. La siguiente clave de cadena (usando HKDF-SHA256 con contexto de rotación).
    2. La clave de mensaje correspondiente al paso ``indice``.

    Args:
        cadena: Clave de cadena actual en bytes.
        indice: Índice del paso actual (por defecto 0).

    Returns:
        Tupla ``(nueva_cadena, clave_mensaje)`` de 32 bytes cada una.
    """
    clave_mensaje = derivar_clave(cadena, indice)
    hkdf_cadena = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=None,
        info=f"A1-avance-cadena:{indice}".encode("utf-8"),
    )
    nueva_cadena = hkdf_cadena.derive(bytes(cadena))
    return nueva_cadena, clave_mensaje


def cifrar(clave: bytes, texto: str | bytes) -> bytes:
    """Cifra un mensaje con AES-GCM usando un nonce aleatorio de 12 bytes.

    Args:
        clave: Clave simétrica de 32 bytes (AES-256).
        texto: Mensaje en texto plano (``str`` en UTF-8 o ``bytes``).

    Returns:
        Bytes concatenados ``nonce (12 bytes) + ciphertext_con_tag``.

    Raises:
        ValueError: Si la clave no tiene 32 bytes.
    """
    if not isinstance(clave, (bytes, bytearray)) or len(clave) != KEY_SIZE:
        raise ValueError("La clave debe tener exactamente 32 bytes para AES-256-GCM.")

    datos = texto.encode("utf-8") if isinstance(texto, str) else bytes(texto)
    nonce = os.urandom(NONCE_SIZE)
    aesgcm = AESGCM(bytes(clave))
    ciphertext = aesgcm.encrypt(nonce, datos, None)
    return nonce + ciphertext


def descifrar(clave: bytes, datos_cifrados: bytes) -> str:
    """Descifra datos producidos por :func:`cifrar` y devuelve el texto UTF-8.

    Extrae los primeros 12 bytes como nonce y descifra el resto empleando
    AES-256-GCM.

    Args:
        clave: Clave simétrica de 32 bytes (AES-256).
        datos_cifrados: Secuencia ``nonce (12 bytes) + ciphertext_con_tag``.

    Returns:
        Texto plano descifrado como cadena ``str`` en UTF-8.

    Raises:
        ValueError: Si la clave o los datos cifrados tienen longitud inválida.
        cryptography.exceptions.InvalidTag: Si la autenticación GCM falla.
    """
    if not isinstance(clave, (bytes, bytearray)) or len(clave) != KEY_SIZE:
        raise ValueError("La clave debe tener exactamente 32 bytes para AES-256-GCM.")
    if not isinstance(datos_cifrados, (bytes, bytearray)) or len(datos_cifrados) <= NONCE_SIZE:
        raise ValueError("Los datos cifrados son demasiado cortos para contener nonce y tag.")

    nonce = bytes(datos_cifrados[:NONCE_SIZE])
    ciphertext = bytes(datos_cifrados[NONCE_SIZE:])
    aesgcm = AESGCM(bytes(clave))
    texto_bytes = aesgcm.decrypt(nonce, ciphertext, None)
    return texto_bytes.decode("utf-8")


class CadenaClaves:
    """Gestor de cadena simétrica de claves (KDF Ratchet) con borrado de claves usadas.

    Avanza la clave de cadena de forma unidireccional mediante HKDF-SHA256 y
    elimina las claves de mensaje una vez utilizadas, impidiendo su recuperación
    o recálculo desde el estado actual.
    """

    def __init__(self, semilla: bytes | None = None) -> None:
        """Inicializa la cadena de claves con una semilla de 32 bytes.

        Args:
            semilla: Clave de cadena inicial de 32 bytes. Si es ``None``, se
                genera aleatoriamente con ``os.urandom(32)``.
        """
        if semilla is None:
            semilla = os.urandom(KEY_SIZE)
        if not isinstance(semilla, (bytes, bytearray)) or len(semilla) != KEY_SIZE:
            raise ValueError("La semilla inicial debe tener exactamente 32 bytes.")
        self._cadena_actual: bytes = bytes(semilla)
        self._indice_actual: int = 0
        self._claves_activas: dict[int, bytes] = {}
        self._claves_borradas: set[int] = set()

    @property
    def indice_actual(self) -> int:
        """Retorna el siguiente índice a derivar en la cadena."""
        return self._indice_actual

    def generar_siguiente_clave(self) -> tuple[int, bytes]:
        """Avanza el estado interno de la cadena y registra la clave del paso actual.

        Returns:
            Tupla ``(indice, clave_mensaje)`` generada en este paso.
        """
        indice = self._indice_actual
        nueva_cadena, clave_msg = avanzar_cadena(self._cadena_actual, indice)
        self._cadena_actual = nueva_cadena
        self._indice_actual += 1
        self._claves_activas[indice] = clave_msg
        return indice, clave_msg

    def usar_y_borrar_clave(self, indice: int) -> bytes:
        """Obtiene la clave de un índice y la borra inmediatamente del almacén.

        Si el índice aún no ha sido derivado, avanza la cadena hasta dicho índice.
        Una vez entregada, la clave se elimina de memoria y no puede volver a
        consultarse ni recalcularse desde ``_cadena_actual``.

        Args:
            indice: Índice de la clave de mensaje que se va a consumir y borrar.

        Returns:
            La clave de mensaje de 32 bytes antes de ser eliminada del gestor.

        Raises:
            KeyError: Si la clave para ``indice`` ya fue usada y borrada.
            ValueError: Si ``indice`` es negativo.
        """
        if indice < 0:
            raise ValueError("El índice no puede ser negativo.")
        if indice in self._claves_borradas:
            raise KeyError(f"La clave del índice {indice} ya fue usada y borrada; no es recuperable.")

        while self._indice_actual <= indice:
            self.generar_siguiente_clave()

        if indice not in self._claves_activas:
            raise KeyError(f"La clave del índice {indice} no está disponible.")

        clave = self._claves_activas.pop(indice)
        self._claves_borradas.add(indice)
        return clave

    def borrar_clave(self, indice: int) -> None:
        """Borra explícitamente la clave asociada a ``indice`` del gestor.

        Args:
            indice: Índice de la clave a eliminar.

        Raises:
            KeyError: Si la clave no existe o ya fue borrada previamente.
        """
        if indice in self._claves_borradas or indice not in self._claves_activas:
            raise KeyError(f"La clave del índice {indice} no existe o ya fue borrada.")
        del self._claves_activas[indice]
        self._claves_borradas.add(indice)

    def recuperar_clave(self, indice: int) -> bytes:
        """Intenta recuperar una clave almacenada en el gestor para ``indice``.

        Args:
            indice: Índice de la clave solicitada.

        Returns:
            Clave de 32 bytes si aún está activa y no ha sido borrada.

        Raises:
            KeyError: Si la clave ya fue usada/borrada o no se encuentra en el gestor.
        """
        if indice in self._claves_borradas:
            raise KeyError(f"La clave del índice {indice} fue borrada y no es recuperable.")
        if indice not in self._claves_activas:
            raise KeyError(f"La clave del índice {indice} no existe en el almacén activo.")
        return self._claves_activas[indice]
