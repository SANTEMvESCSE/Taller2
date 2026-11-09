# Taller: Seguridad en Messenger (Signal Protocol — KDF Chain & Double Ratchet)

> **Aviso Ético y Legal:** Este repositorio contiene una implementación **exclusivamente académica y educativa** desarrollada para el taller de *Seguridad en Messenger*. Todas las pruebas se ejecutan localmente en memoria RAM sin transmitir tráfico por red ni procesar datos personales reales, en estricto cumplimiento de las normas éticas de ciberseguridad y de la **Ley 1581 de 2012** (Protección de Datos Personales en Colombia).

---

## Estructura del Proyecto

El proyecto está organizado en el directorio raíz con los siguientes archivos:

```text
TallerMessengers/
├── ficha.md              # Jueves 5: Ficha de 1 página sobre E2EE y Forward Secrecy
├── a1_cadena.py          # Viernes 6: Cadena de claves simétrica (derivar_clave, cifrar, descifrar, CadenaClaves)
├── test_a1.py            # Viernes 6: Pruebas unitarias de A1 (test_A1_01 a test_A1_04)
├── a2_ratchet.py         # Sábado 7: Double Ratchet reducido (clase Ratchet: enviar, recibir, cambiar_direccion)
├── test_a2.py            # Sábado 7: Pruebas unitarias de A2 (test_A2_01 a test_A2_05)
├── resultados.csv        # Domingo 8: Tabla oficial de resultados con las 9 filas evaluadas
├── log_pruebas.json      # Domingo 8: Registro estructurado en JSON con una entrada por prueba
├── informe.md            # Lunes 9: Informe corto (Qué se implementó, Diferencias, Limitaciones)
└── README.md             # Lunes 9: Guía de instalación y comando único de ejecución
```

---

## Requisitos del Sistema

* **Python:** `3.11` o superior.
* **Paquetes requeridos:**
  * `cryptography` (primitivas criptográficas `HKDF`, `SHA256`, `AESGCM` y curva elíptica `X25519`).
  * `pytest` (framework de ejecución y verificación de pruebas unitarias e integración).

---

## Instalación de Dependencias

Ejecuta el siguiente comando exacto en la terminal desde la carpeta del proyecto para instalar las dependencias necesarias:

```bash
python -m pip install cryptography pytest
```

---

## Ejecución de las Pruebas y Generación de Evidencias

Para ejecutar las **9 pruebas automatizadas** (`A1-01` a `A1-04` y `A2-01` a `A2-05`) y generar automáticamente los archivos de evidencia `log_pruebas.json` y `resultados.csv`, ejecuta el siguiente comando único:

```bash
python -m pytest -q
```

También puedes ejecutar directamente los módulos individuales para observar la demostración en consola:

```bash
python a1_cadena.py
python a2_ratchet.py
```

---

## Tabla Resumen de las 9 Pruebas Automatizadas

Las suites en `test_a1.py` y `test_a2.py` verifican las propiedades criptográficas de los algoritmos A1 y A2 según la plantilla oficial de resultados:

| ID Prueba | Función Pytest | Algoritmo | Propiedad | Descripción | Esperado | Obtenido | Estado |
| :---: | :--- | :---: | :--- | :--- | :---: | :---: | :---: |
| **`A1-01`** | `test_A1_01` | A1 | `determinismo` | Misma cadena e índice producen la misma clave | `misma clave` | `misma clave` | `OK` |
| **`A1-02`** | `test_A1_02` | A1 | `unicidad` | 10 claves de mensaje distintas | `10 claves distintas` | `10 claves distintas` | `OK` |
| **`A1-03`** | `test_A1_03` | A1 | `cifrado` | Cifrar y descifrar 10 mensajes | `10/10 correctos` | `10/10 correctos` | `OK` |
| **`A1-04`** | `test_A1_04` | A1 | `borrado` | Clave usada y luego borrada no se recupera | `no recuperable` | `no recuperable` | `OK` |
| **`A2-01`** | `test_A2_01` | A2 | `descifrado` | Descifrar los 6 mensajes | `6/6 correctos` | `6/6 correctos` | `OK` |
| **`A2-02`** | `test_A2_02` | A2 | `integridad` | Un byte alterado del ciphertext | `rechazado` | `rechazado` | `OK` |
| **`A2-03`** | `test_A2_03` | A2 | `repetición` | Mensaje reenviado | `rechazado` | `rechazado` | `OK` |
| **`A2-04`** | `test_A2_04` | A2 | `forward secrecy` | Estado robado tras mensaje 3 no descifra mensaje 1 | `no descifrable` | `no descifrable` | `OK` |
| **`A2-05`** | `test_A2_05` | A2 | `post-compromise` | Estado robado antes del cambio de dirección no descifra tras él | `no descifrable` | `no descifrable` | `OK` |
