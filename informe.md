# Informe Técnico de Implementación y Análisis: Seguridad en Messenger

**Taller:** Seguridad en Messenger — (Documentación e Informe)

---

## Qué se implementó

En este taller se diseñó e implementó en Python 3 un prototipo funcional en memoria de los componentes criptográficos centrales del protocolo Signal, dividido en dos módulos incrementales (`a1_cadena.py` y `a2_ratchet.py`) y verificado mediante una suite automatizada de 9 pruebas en `test_a1.py` y `test_a2.py`.

1. **Actividad A1 — Cadena de Claves Simétrica y Cifrado Autenticado (`a1_cadena.py`):**
   * **Derivación determinista unidireccional (`derivar_clave(cadena, indice)` y `avanzar_cadena(cadena, indice)`):** Se implementó el paso del trinquete simétrico (*Symmetric-Key Ratchet*) utilizando `HKDF` con `SHA-256` (según RFC 5869) provisto por la biblioteca estándar `cryptography`. A partir de una clave de cadena $CK_i$ de 32 bytes y el índice contextual del mensaje, se derivan de forma determinista y criptográficamente independiente $CK_{i+1}$ (32 bytes) y $MK_i$ (32 bytes).
   * **Cifrado y descifrado autenticado (`cifrar(clave, texto)` / `descifrar(clave, datos_cifrados)`):** Se implementó cifrado autenticado con datos asociados (AEAD) mediante `AES-256-GCM` (`AESGCM`). Cada operación genera un `nonce` aleatorio criptográficamente seguro de 12 bytes (`os.urandom(12)`), cifra el texto plano en UTF-8 y adjunta la etiqueta de autenticación GCM (*tag* de 16 bytes) retornando `nonce + ciphertext`.
   * **Destrucción de claves usadas (`CadenaClaves`):** La clase `CadenaClaves` encapsula el avance del estado $CK_i \to CK_{i+1}$ con métodos como `generar_siguiente_clave()`, `usar_y_borrar_clave(indice)` y `recuperar_clave(indice)`, eliminando del almacén activo cada clave utilizada e impidiendo su recuperación posterior (`KeyError`).

2. **Actividad A2 — Double Ratchet Reducido con Rotación DH (`a2_ratchet.py`):**
   * **Clase `Ratchet` (`enviar`, `recibir`, `cambiar_direccion`):** Modela el estado criptográfico de cada participante (Alice y Bob) manteniendo una clave raíz compartida (*Root Key*, $RK$), cadenas independientes de envío (`send_chain_key`) y recepción (`recv_chain_key`), el par de claves efímeras Diffie-Hellman sobre curva elíptica `X25519`, contadores de secuencia y un registro de identificadores procesados para protección anti-replay.
   * **Rotación de pares efímeros X25519 (`cambiar_direccion`):** Al cambiar la dirección del flujo de mensajes, el participante genera un nuevo par de claves efímeras sobre `X25519` (`X25519PrivateKey.generate()`) y calcula un nuevo secreto compartido Diffie-Hellman con la clave pública remota. Dicho secreto se procesa con `HKDF-SHA256` junto a la clave raíz actual $RK_n$ para derivar una nueva clave raíz $RK_{n+1}$ y una nueva clave de cadena de envío fresca.
   * **Simulación de 6 mensajes en memoria y propiedades de seguridad (`test_a2.py`):** Se simuló en un único proceso en memoria el intercambio de 6 mensajes entre dos participantes con cambio de dirección, verificando experimentalmente:
     * **Descifrado de 6 mensajes (`A2-01`):** Los 6 mensajes se descifran de extremo a extremo (`6/6 correctos`).
     * **Integridad GCM (`A2-02`):** La alteración de 1 byte en el `ciphertext` es detectada por la etiqueta GCM y rechazada (`rechazado`).
     * **Protección Anti-Replay (`A2-03`):** El reenvío de un paquete ya recibido es detectado y rechazado (`rechazado`).
     * **Forward Secrecy (`A2-04`):** El estado robado tras el mensaje 3 no puede descifrar el mensaje 1 histórico porque las claves previas fueron descartadas y la cadena avanzó unidireccionalmente (`no descifrable`).
     * **Post-Compromise Security (`A2-05`):** El estado robado antes del cambio de dirección no puede descifrar los mensajes posteriores a la generación del nuevo par `X25519` (`no descifrable`).

3. **Cumplimiento Ético y Legal (Ley 1581 de 2012):**
   Toda la experimentación se ejecutó exclusivamente en memoria RAM local en un único proceso, sin probar aplicaciones reales ni servicios de terceros, y sin usar credenciales, números telefónicos ni datos reales de usuarios.

---

## Diferencias

Aunque el prototipo implementado reproduce fielmente los principios matemáticos de derivación de claves y rotación Diffie-Hellman de Signal, presenta diferencias arquitectónicas importantes respecto al protocolo Signal completo de producción:

| Característica | Prototipo Implementado (`a1_cadena.py` / `a2_ratchet.py`) | Protocolo Signal de Producción (Especificación Oficial) |
| :--- | :--- | :--- |
| **Acuerdo inicial de claves** | Clave raíz inicial ($RK_0$) y clave de cadena ($CK_0$) precompartidas directamente en memoria al instanciar `Alice` y `Bob`. | Protocolo **X3DH (Extended Triple Diffie-Hellman)** asíncrono con claves de identidad (*Identity Keys*), *Signed PreKeys*, *One-Time PreKeys* y soporte post-cuántico **PQXDH** (KEM Kyber). |
| **Estructura de cadenas por participante** | Una clave de cadena activa sincronizada y rotación explícita mediante llamada a `cambiar_direccion()`. | Dos cadenas simétricas separadas por participante (*Sending Chain* y *Receiving Chain*) que avanzan automáticamente al recibir una nueva clave pública DH en la cabecera del mensaje. |
| **Mensajes fuera de orden o perdidos** | Asume entrega en orden o rechazo de paquetes antiguos cuyas claves ya fueron consumidas. | Almacén temporal acotado **`MKSKIPPED`** que guarda en diccionario las claves $MK_i$ de mensajes saltados hasta un límite máximo (`MAX_SKIP`) para tolerar reordenamiento en redes reales. |
| **Autenticación de cabeceras (AAD)** | El paquete transporta `(num_mensaje, nonce, ct, pub_efimera)` y valida integridad sobre el *ciphertext* con AES-GCM. | Vincula obligatoriamente la cabecera completa del protocolo (clave pública DH, número de mensaje $N$ y longitud de cadena previa $PN$) como **Associated Data (AAD)** en AEAD, e incluye la variante **Header Encryption** para ocultar metadatos de trinquete. |
| **Gestión multi-dispositivo** | Comunicación estrictamente punto a punto entre 1 instancia de Alice y 1 instancia de Bob. | Algoritmo **Sesame** para gestión de múltiples sesiones concurrentes por usuario (teléfono, escritorio, tableta) y protocolo **Sender Keys** para grupos eficientes. |

---

## Limitaciones

El alcance del prototipo desarrollado conlleva las siguientes limitaciones técnicas inherentes a su diseño académico:

1. **Ejecución en un único proceso en memoria sin capa de red ni persistencia:**
   Alice y Bob coexisten dentro del mismo espacio de direcciones del intérprete de Python y se intercambian tuplas directamente por referencia de memoria. No existe serialización de red (Protobuf/JSON sobre TLS/WebSockets), manejo de latencia, fragmentación de paquetes ni almacenamiento seguro de estado en base de datos local cifrada (como SQLCipher).
2. **Garantías limitadas de borrado seguro de memoria en Python (*Garbage Collection*):**
   En Python, los objetos de tipo `bytes` son **inmutables**. Aunque el código elimina las referencias (`del mk`), sobrescribe buffers mutables (`bytearray`) y avanza los punteros de estado, el recolector de basura de CPython no garantiza el borrado inmediato con ceros (*zeroization*) de las páginas de memoria física subyacentes antes de ser liberadas o paginadas a disco (*swap*). En una implementación de producción en C/Rust (como `libsignal`), se utilizan funciones como `sodium_memzero` o `explicit_bzero` junto con bloqueo de páginas en RAM (`mlock`) para evitar fugas por volcados de memoria (*core dumps*).
3. **Supuesto de canal síncrono y coordinación explícita de turnos:**
   En `a2_ratchet.py`, la rotación del trinquete Diffie-Hellman se invoca explícitamente mediante `cambiar_direccion(otro)` coordinando las referencias entre ambos objetos. En un entorno distribuido real donde ambos usuarios pueden escribir simultáneamente (*double send*), la resolución de colisiones de trinquetes requiere el flujo asíncrono completo basándose únicamente en las cabeceras recibidas por red.
4. **Ausencia de autenticación de identidad y verificación fuera de banda:**
   El prototipo asume que las claves públicas `X25519` intercambiadas pertenecen legítimamente a Alice y Bob. No implementa firmas digitales sobre las claves efímeras ni el cálculo de *Safety Numbers* (huellas numéricas o códigos QR) para mitigar ataques *Man-in-the-Middle* activos en el canal de distribución de claves.
