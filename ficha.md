# Ficha Técnica: Cifrado de Extremo a Extremo (E2EE) y Secreto Hacia Adelante (Forward Secrecy)

**Taller:** Seguridad en Messenger — (Investigación Teórica)

---

## Definición

El **Cifrado de Extremo a Extremo (End-to-End Encryption, E2EE)** es un paradigma criptográfico de comunicación en el cual únicamente los extremos comunicantes (emisor y receptor legítimos) poseen las claves criptográficas necesarias para cifrar y descifrar el contenido de los mensajes. Ningún intermediario en la ruta de transmisión —incluyendo proveedores de servicios de Internet (ISP), servidores de mensajería en la nube, enrutadores o atacantes en la red (*Man-in-the-Middle*)— tiene acceso al texto plano ni a las claves privadas de sesión.

* **¿Qué protege E2EE?**
  * **Confidencialidad en tránsito y en reposo en servidores intermediarios:** Garantiza que el contenido útil (*payload*) viaje cifrado mediante esquemas autenticados (como `AES-256-GCM` o `ChaCha20-Poly1305`).
  * **Integridad y autenticidad del origen:** Mediante códigos de autenticación de mensajes o cifrado autenticado con datos asociados (AEAD), detecta cualquier alteración accidental o maliciosa de los paquetes en tránsito.

* **¿Qué NO protege E2EE?**
  * **Metadatos de comunicación:** E2EE cifra el contenido del mensaje, pero generalmente no oculta quién se comunica con quién, las marcas de tiempo (*timestamps*), el tamaño de los paquetes, las direcciones IP ni la frecuencia de interacción (análisis de tráfico).
  * **Compromiso de los puntos finales (*Endpoint Compromise*):** Si el dispositivo de Alice o Bob está infectado con *malware*, *spyware*, *keyloggers* o sufre acceso físico no autorizado, el atacante puede leer los mensajes antes de ser cifrados o después de ser descifrados en pantalla/base de datos local.
  * **Suplantación sin verificación de identidad:** Si los usuarios no verifican las huellas criptográficas (*Safety Numbers* / *Key Transparency*) fuera de banda, un servidor malicioso podría montar un ataque de intermediario activo sustituyendo las claves públicas durante el registro inicial.

---

## Amenaza

El **Secreto Hacia Adelante (Forward Secrecy — FS)**, también denominado *Perfect Forward Secrecy (PFS)*, es una propiedad de seguridad de los protocolos de establecimiento y gestión de claves que garantiza que el compromiso de las claves privadas de largo plazo o del estado criptográfico actual de un participante **no compromete la confidencialidad de las claves de sesión ni de los mensajes cifrados en el pasado**.

* **Amenaza específica que mitiga:**
  Mitiga el ataque de **captura pasiva masiva con descifrado diferido (*"Harvest Now, Decrypt Later"* / compromiso retrospectivo)**. En un sistema sin *Forward Secrecy* (por ejemplo, cifrado estático con una única clave simétrica compartida o transporte RSA clásico sin claves efímeras), un adversario puede interceptar y almacenar todo el tráfico cifrado durante meses o años y, posteriormente, mediante robo, orden judicial, vulnerabilidad de software o coerción, obtener la clave privada actual del dispositivo y descifrar retroactivamente **todo el historial de conversaciones pasadas**. Con *Forward Secrecy*, las claves utilizadas para cifrar cada mensaje pasado ya han sido destruidas irreversiblemente y no pueden reconstruirse desde el estado actual.

* **Diferencia complementaria con *Post-Compromise Security* (Future Secrecy):**
  Mientras que *Forward Secrecy* protege las comunicaciones **pasadas** frente a un compromiso de estado **presente**, la **Seguridad Post-Compromiso (*Post-Compromise Security* / *Future Secrecy* / *Self-Healing*)** protege las comunicaciones **futuras** tras un compromiso pasado: mediante el intercambio continuo de nuevos pares de claves efímeras Diffie-Hellman (DH), si un atacante roba el estado en el instante $t_0$ pero pierde el acceso activo al dispositivo, el protocolo se "autorrepara" en los siguientes turnos de conversación e impide al atacante descifrar los mensajes futuros.

---

## Mecanismo

El protocolo **Signal** materializa el *Forward Secrecy* por mensaje y la *Post-Compromise Security* por turno combinando dos engranajes criptográficos dentro del algoritmo **Double Ratchet**:

1. **Symmetric-Key Ratchet (Trinquete de Clave Simétrica con KDF unidireccional):**
   Cada participante mantiene una clave de cadena (*Chain Key*, $CK_i$) para el envío y otra para la recepción. Por cada mensaje $i$ transmitido, la clave de cadena avanza un paso mediante una función de derivación de claves criptográfica (específicamente **HKDF** basada en HMAC-SHA256) que produce simultáneamente la siguiente clave de cadena y una clave efímera única para ese mensaje (*Message Key*, $MK_i$):
   $$CK_{i+1},\; MK_i = \text{KDF}(CK_i)$$
   * **Unidireccionalidad (Preimagen):** Debido a que HKDF se construye sobre funciones hash criptográficas unidireccionales (HMAC-SHA256), es computacionalmente inviable invertir la función para obtener $CK_i$ o $MK_i$ a partir de $CK_{i+1}$.
   * **Destrucción inmediata:** Una vez cifrado (o descifrado y verificado) el mensaje $i$, tanto $MK_i$ como el estado anterior $CK_i$ se eliminan inmediatamente de la memoria del dispositivo, conservando únicamente $CK_{i+1}$.

2. **Diffie-Hellman Ratchet (Trinquete Asimétrico sobre Curva Elíptica X25519):**
Cada vez que cambia la dirección de la conversación (un interlocutor responde al otro), el emisor genera un nuevo par de claves efímeras Diffie-Hellman sobre la curva Curve25519 (X25519) y adjunta su nueva clave pública en la cabecera del mensaje. Ambos extremos calculan un nuevo secreto compartido $\text{DH}_{\text{out}}$ y actualizan su clave raíz (Root Key, $RK$) junto con una nueva clave de cadena inicial ($CK_0$):
```math
RK_{n+1}, CK_0 = \text{KDF}(RK_n, \text{DH}(dh_{\text{priv}}, dh_{\text{remota}}))
```
Esta inyección periódica de entropía fresca asegura que incluso si un atacante extrajo $CK_i$ en un turno previo, no podrá calcular las claves del siguiente turno sin conocer la clave privada efímera recién generada.

---

## Fuentes

1. **Cohn-Gordon, K., Cremers, C., Dowling, B., Garratt, L., & Stebila, D.** (2017). *A Formal Security Analysis of the Signal Messaging Protocol*. En Proceedings of the 2017 IEEE European Symposium on Security and Privacy (EuroS&P), pp. 451–466. París, Francia: IEEE. DOI: `10.1109/EuroSP.2017.27`.
2. **Perrin, T., & Marlinspike, M.** (2016). *The Double Ratchet Algorithm* (Revision 1, 2016-11-20). Open Whisper Systems / Signal Specifications. Disponible en: https://signal.org/docs/specifications/doubleratchet/
3. **Krawczyk, H., & Eronen, P.** (2010). *HMAC-based Extract-and-Expand Key Derivation Function (HKDF)*. RFC 5869, Internet Engineering Task Force (IETF). DOI: `10.17487/RFC5869`. Disponible en: https://datatracker.ietf.org/doc/html/rfc5869
4. **Marlinspike, M., & Perrin, T.** (2016). *The X3DH Key Agreement Protocol* (Revision 1, 2016-11-04). Open Whisper Systems / Signal Specifications. Disponible en: https://signal.org/docs/specifications/x3dh/
