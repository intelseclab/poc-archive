# vamp-forticheck

**VampSecure Labs — Security Research Division**  
Scanner de vulnerabilidades críticas en dispositivos FortiOS/FortiGate.

---

## Descripción

Herramienta de auditoría de seguridad para evaluar la exposición de dispositivos Fortinet
frente a cuatro vulnerabilidades críticas públicamente documentadas. Diseñada para uso
exclusivo en entornos autorizados (pentesting, Red Team, auditorías contratadas).

Realiza detección asíncrona de múltiples objetivos de forma concurrente mediante AsyncIO y
aiohttp, con salida Rich en consola y generación de informes en JSON y HTML.

## CVEs analizados

| CVE | CVSS | Descripción |
|-----|------|-------------|
| CVE-2018-13379 | 9.8 | Path traversal pre-auth en SSL-VPN |
| CVE-2022-40684 | 9.8 | Bypass de autenticación en API REST |
| CVE-2023-27997 | 9.2 | Heap overflow pre-auth en SSL-VPN |
| CVE-2024-21762 | 9.6 | Out-of-bounds write en proxy SSL |

## Requisitos

- Python 3.9+
- Dependencias: `aiohttp>=3.9.0`, `rich>=13.7.0`

## Instalación

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Uso

```bash
# Escanear un único objetivo
python3 vamp_forticheck.py https://fortigate.ejemplo.com

# Escanear múltiples objetivos desde fichero
python3 vamp_forticheck.py -f scope.txt

# Limitar concurrencia y generar informe
python3 vamp_forticheck.py -f scope.txt --concurrency 5 --output-json informe.json --output-html informe.html
```

## Opciones

| Opción | Descripción |
|--------|-------------|
| `target` | URL o IP del objetivo |
| `-f / --file` | Fichero con lista de objetivos (uno por línea) |
| `--concurrency` | Peticiones concurrentes (por defecto: 10) |
| `--timeout` | Timeout por petición en segundos (por defecto: 10) |
| `--output-json` | Guardar resultados en JSON |
| `--output-html` | Guardar informe en HTML |
| `--no-verify-ssl` | Deshabilitar verificación TLS |

## Salida

La herramienta genera una tabla Rich en consola con el resultado de cada CVE por objetivo,
indicando `VULNERABLE`, `PARCHADO`, `NO APLICA` o `ERROR`. Los informes HTML incluyen
estilo oscuro con detalles técnicos y plantilla orientativa de PoC.

## Aviso legal

**Uso exclusivo en sistemas de tu propiedad o con autorización escrita del propietario.**  
El uso no autorizado puede constituir un delito. VampSecure Studios no se responsabiliza
del uso indebido de esta herramienta.

---

© VampSecure Studios — VampSecure Labs Security Research Division  
Licencia: MIT
