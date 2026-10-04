import os
import re
import json
import time
import random
import argparse
import asyncio
import hashlib
import ipaddress
import sys
import importlib.util
import subprocess
import platform
from dataclasses import dataclass, asdict
from typing import Optional
from urllib.parse import quote

# httpx se carga después del chequeo de dependencias.
httpx = None
AsyncProxyTransport = None


#                  PROXY CHECKER {VERSION}
#                    @Flippy2x
#
# Uso previsto:
#   Comprobación de proxies autorizados.
#
# Características:
#   - Async + httpx
#   - Concurrencia controlada
#   - Rate limiter optimizado
#   - Reintentos inteligentes
#   - IP de salida
#   - Geolocalización de IP de salida
#   - ISP / ASN
#   - Consistencia / rotación de IP
#   - Latencia / jitter
#   - Anonimato heurístico
#   - Score 0-100
#   - Calidad
#   - Resume
#   - Resultados TXT por estado y protocolo
#   - Configuración externa
#   - Selector de archivos
#


VERSION = "V7.9.6"
STATE_FILE = ".proxy_checker_state.json"
LANGUAGE = "es"

DEFAULT_WORKERS = 50
DEFAULT_TIMEOUT = 8.0
DEFAULT_CONNECT_TIMEOUT = 4.0
DEFAULT_REINTENTOS = 2
DEFAULT_MAX_LATENCIA = 4.0
DEFAULT_RATE = 20.0

DEFAULT_JITTER_MIN = 0.03
DEFAULT_JITTER_MAX = 0.10

PENDING_FACTOR = 4
MAX_REDIRECTS = 3

# Número mínimo de servicios IP que deben confirmar
MIN_IP_CONFIRMATIONS = 2

# Tercer servicio solamente cuando sea necesario
USE_THIRD_IP_CHECK = True

# Pruebas de estabilidad adicionales
STABILITY_TESTS = 3

# SERVICIOS

# Pool de servicios independientes para confirmar la IP de salida.
# V7.6 usa los adicionales como fallback: no consulta todos si ya
# alcanzó el mínimo de confirmaciones configurado.
IP_TEST_URLS = [
    "https://api.ipify.org",
    "https://httpbin.org/ip",
    "https://api.myip.com",
    "https://httpbin.io/ip",
    "https://ipconfig.io/ip",
]

GOOGLE_TEST_URL = (
    "https://www.google.com/generate_204"
)

# Prueba web decisiva: confirma navegación HTTPS real + contenido.
# Se mantiene separada del 204 porque el 204 no contiene HTML.
WEB_TEST_URL = "https://google.com"
WEB_TEST_TIMEOUT = 10.0
WEB_EXPECTED_TITLE = "google"

ANONYMITY_TEST_URL = (
    "https://httpbin.org/get"
)

# Servicio de información de IP.
# Se consulta directamente usando la IP de salida obtenida.
GEOLOCATION_URL = (
    "https://ipwho.is/{ip}"
)


# PROTOCOLOS

PROTOCOLOS = (
    "http",
    "https",
    "socks4",
    "socks5",
)

PREFIXES = {
    "http://": "http",
    "https://": "https",
    "socks4://": "socks4",
    "socks4a://": "socks4",
    "socks5://": "socks5",
    "socks5h://": "socks5",
}


# USER AGENTS

USER_AGENTS = [
    (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/140.0.0.0 Safari/537.36"
    ),
    (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:142.0) "
        "Gecko/20100101 Firefox/142.0"
    ),
    (
        "Mozilla/5.0 (X11; Linux x86_64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/140.0.0.0 Safari/537.36"
    ),
    (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/605.1.15 (KHTML, like Gecko) "
        "Version/18.6 Safari/605.1.15"
    ),
]


# ERRORES

TEMPORARY_ERRORS = {
    "timeout",
    "connection_error",
    "proxy_error",
    "request_error",
    "rate_limited",
    "service_unavailable",
}

DEAD_PRIORITY = [
    "proxy_error",
    "connection_error",
    "timeout",
    "no_ip",
    "http_error",
    "request_error",
    "no_body",
]


# HEADERS ANONIMATO

ANONYMITY_HEADERS = {
    "via",
    "forwarded",
    "x-forwarded-for",
    "x-forwarded",
    "x-real-ip",
    "client-ip",
    "x-client-ip",
    "proxy-connection",
    "x-proxy-id",
}


# COLORES

RESET = "\033[0m"
BOLD = "\033[1m"

GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
CYAN = "\033[96m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
WHITE = "\033[97m"


def color(texto, codigo):
    return f"{codigo}{texto}{RESET}"


def obtener_user_agent():
    return random.choice(USER_AGENTS)


# IDIOMA / ESTADO LOCAL / NOVEDADES

TEXTS = {
    "select_language": {"es": "Selecciona tu idioma", "en": "Select your language"},
    "spanish": {"es": "Español", "en": "Spanish"},
    "english": {"es": "Inglés", "en": "English"},
    "choose": {"es": "Selecciona", "en": "Select"},
    "deps": {"es": "DEPENDENCIAS", "en": "DEPENDENCIES"},
    "checking_deps": {"es": "Comprobando dependencias...", "en": "Checking dependencies..."},
    "missing_deps": {"es": "Faltan dependencias necesarias.", "en": "Required dependencies are missing."},
    "install_auto": {"es": "¿Instalar automáticamente las dependencias faltantes? [S/n]: ", "en": "Install missing dependencies automatically? [Y/n]: "},
    "installing": {"es": "Instalando dependencias...", "en": "Installing dependencies..."},
    "installed": {"es": "Dependencias instaladas correctamente.", "en": "Dependencies installed successfully."},
    "install_failed": {"es": "La instalación automática falló.", "en": "Automatic installation failed."},
    "python_old": {"es": "Se requiere Python 3.10 o superior.", "en": "Python 3.10 or newer is required."},
    "ready": {"es": "Entorno listo.", "en": "Environment ready."},
    "continue": {"es": "Presiona ENTER para continuar...", "en": "Press ENTER to continue..."},
    "whats_new": {"es": "NOVEDADES", "en": "WHAT'S NEW"},
    "added": {"es": "AGREGADO", "en": "ADDED"},
    "improved": {"es": "MEJORADO", "en": "IMPROVED"},
    "fixed": {"es": "CORREGIDO", "en": "FIXED"},
    "old_warning": {"es": "ADVERTENCIA DE VERSIÓN", "en": "VERSION WARNING"},
    "installed_version": {"es": "Versión instalada", "en": "Installed version"},
    "latest_known": {"es": "Última versión conocida", "en": "Latest known version"},
    "old_note": {"es": "Esta versión puede contener errores ya corregidos en versiones posteriores.", "en": "This version may contain issues fixed in later releases."},
    "self_test": {"es": "DIAGNÓSTICO / SELF-TEST", "en": "DIAGNOSTICS / SELF-TEST"},
    "os": {"es": "Sistema operativo", "en": "Operating system"},
    "write_access": {"es": "Permiso de escritura", "en": "Write access"},
    "config_ok": {"es": "Configuración", "en": "Configuration"},
    "status_ready": {"es": "Diagnóstico: OK — iniciando checker...", "en": "Diagnostics: OK — starting checker..."},
    "authorized": {"es": "Uso autorizado solamente.", "en": "Authorized use only."},
}

CHANGELOG = {
    "V7.9.6": {
        "added": {
            "es": [
                "Fallback de validación: si los servicios de IP fallan, una rama puede continuar hacia HTTPS real + Google 204 antes de decidir DEAD/INDETERMINATE.",
                "Diagnóstico diferencia fallos de servicios IP de fallos reales de transporte/protocolo.",
            ],
            "en": [
                "Validation fallback: if IP services fail, a branch may continue to real HTTPS + Google 204 before deciding DEAD/INDETERMINATE.",
                "Diagnostics distinguish IP-service failures from real transport/protocol failures.",
            ],
        },
        "improved": {
            "es": [
                "no_ip deja de ser una sentencia DEAD automática cuando existe evidencia web real suficiente.",
                "VALID/SLOW sigue exigiendo HTTPS real; no se desactiva la verificación TLS ni se regalan resultados LIVE.",
            ],
            "en": [
                "no_ip is no longer an automatic DEAD sentence when enough real-web evidence exists.",
                "VALID/SLOW still requires real HTTPS; TLS verification remains enabled and LIVE results are not granted artificially.",
            ],
        },
        "fixed": {
            "es": [
                "Corregida la regresión donde proxies previamente funcionales podían terminar DEAD solo porque ipify/httpbin no devolvían IP.",
                "Cierre Ctrl+C reforzado para consumir cancelaciones y grupos de excepciones durante el apagado de HTTPX/AnyIO.",
                "Novedades usa la estructura estándar compatible con el visor interno.",
            ],
            "en": [
                "Fixed a regression where previously functional proxies could become DEAD only because ipify/httpbin did not return an IP.",
                "Ctrl+C shutdown hardened to consume cancellations and exception groups while HTTPX/AnyIO is shutting down.",
                "What's New uses the standard structure expected by the internal viewer.",
            ],
        },
    },
    "V7.9.5": {
        "added": {
            "es": [
                "Regresión de validación: AUTO vuelve al orden progresivo estable de V7.8.3 para no descartar proxies funcionales antes de confirmar transporte/IP.",
                "SOCKS4 conserva el transporte dedicado agregado en V7.9.x.",
            ],
            "en": [
                "Validation regression fix: AUTO restores the stable V7.8.3 progressive order so functional proxies are not discarded before transport/IP confirmation.",
                "SOCKS4 keeps the dedicated transport introduced in V7.9.x.",
            ],
        },
        "improved": {
            "es": [
                "HTTPS real sigue siendo obligatorio para VALID/SLOW, pero deja de ser el primer filtro absoluto del pipeline.",
                "La clasificación vuelve a basarse en evidencia progresiva: IP, conectividad, HTTPS real y métricas de estabilidad.",
            ],
            "en": [
                "Real HTTPS remains mandatory for VALID/SLOW, but is no longer the absolute first pipeline gate.",
                "Classification returns to progressive evidence: IP, connectivity, real HTTPS and stability metrics.",
            ],
        },
        "fixed": {
            "es": [
                "Corregido el panel NOVEDADES vacío de V7.9.4.",
                "Corregida la regresión V7.9 que podía convertir fallos HTTPS tempranos en DEAD/INDETERMINATE antes de completar evidencia suficiente.",
            ],
            "en": [
                "Fixed the empty WHAT'S NEW panel from V7.9.4.",
                "Fixed the V7.9 regression that could turn early HTTPS failures into DEAD/INDETERMINATE before enough evidence was collected.",
            ],
        },
    },
    "V7.9.4": {
        "es": [
            "Clasificación por evidencia: evita convertir cualquier excepción en DEAD.",
            "Fallos temporales repetidos y consistentes pueden cerrarse como DEAD; señales mixtas quedan INDETERMINATE.",
            "SOCKS4 conserva transporte dedicado y distingue incompatibilidad remota de problemas locales.",
            "AUTO mantiene el pipeline por etapas para conservar velocidad sin relajar VALID/SLOW.",
        ],
        "en": [
            "Evidence-based classification avoids turning every exception into DEAD.",
            "Repeated consistent transient failures may close as DEAD; mixed signals remain INDETERMINATE.",
            "SOCKS4 keeps its dedicated transport and separates remote incompatibility from local failures.",
            "AUTO keeps the staged pipeline to preserve speed without relaxing VALID/SLOW.",
        ],
    },
    "V7.9.3": {
        "added": {
            "es": [
                "SOCKS4 real mediante un transporte dedicado compatible con SOCKS4/SOCKS4a.",
            ],
            "en": [
                "Real SOCKS4 support through a dedicated SOCKS4/SOCKS4a-compatible transport.",
            ],
        },
        "improved": {
            "es": [
                "AUTO mantiene el pipeline rápido por etapas y reserva las métricas secundarias para ramas funcionales.",
                "INDETERMINATE se reserva para fallos realmente ambiguos, locales o de servicios externos.",
                "Fallos repetidos de conexión, proxy, request o timeout pasan a DEAD tras agotar los reintentos.",
            ],
            "en": [
                "AUTO keeps the fast staged pipeline and reserves secondary metrics for functional branches.",
                "INDETERMINATE is reserved for genuinely ambiguous, local, or external-service failures.",
                "Repeated connection, proxy, request, or timeout failures become DEAD after retries are exhausted.",
            ],
        },
        "fixed": {
            "es": ["El test SOCKS4 ya no depende del esquema SOCKS4 no soportado por el transporte SOCKS5 de httpx."],
            "en": ["SOCKS4 testing no longer depends on the SOCKS4 scheme unsupported by httpx's SOCKS5 transport."],
        },
    },
    "V7.9.1": {
        "added": {
            "es": [
                "AUTO FULL ofrece comprobación exhaustiva de HTTP, HTTPS, SOCKS4 y SOCKS5 para máxima precisión.",
                "La guía rápida explica AUTO optimizado, AUTO FULL y la validación por etapas de V7.9.",
            ],
            "en": [
                "AUTO FULL provides exhaustive HTTP, HTTPS, SOCKS4 and SOCKS5 checking for maximum precision.",
                "The quick guide now explains optimized AUTO, AUTO FULL and V7.9 staged validation.",
            ],
        },
        "improved": {
            "es": [
                "Los errores locales de esquema SOCKS4 no se presentan como evidencia de que el proxy remoto esté DEAD.",
                "AUTO optimizado conserva la validación fuerte y corta métricas secundarias cuando una rama ya falló de forma decisiva.",
            ],
            "en": [
                "Local SOCKS4 scheme errors are no longer presented as evidence that the remote proxy is DEAD.",
                "Optimized AUTO keeps strong validation while skipping secondary metrics after a decisive branch failure.",
            ],
        },
        "fixed": {
            "es": ["Restaurada la opción AUTO FULL exhaustiva junto al AUTO optimizado."],
            "en": ["Restored the exhaustive AUTO FULL option alongside optimized AUTO."],
        },
    },
    "V7.9.0": {
        "added": {
            "es": [
                "Validación por etapas: una prueba HTTPS decisiva filtra protocolos incompatibles antes de ejecutar métricas secundarias.",
                "AUTO conserva la detección multiprotocolo, pero las ramas incompatibles terminan temprano sin ejecutar el pipeline completo.",
            ],
            "en": [
                "Staged validation: a decisive HTTPS test filters incompatible protocols before secondary metrics run.",
                "AUTO keeps multi-protocol detection while incompatible branches stop early instead of running the full pipeline.",
            ],
        },
        "improved": {
            "es": [
                "Menos solicitudes inútiles sin reducir los requisitos para VALID/SLOW.",
                "PING/LAT usa mediciones homogéneas de servicios IP y estabilidad; la carga web decisiva ya no se mezcla en esa media.",
                "Geolocalización, anonimato y estabilidad solo se ejecutan después de confirmar navegación HTTPS real.",
                "Limpieza conservadora de comentarios obsoletos sin cambiar formatos, Resume ni archivos de salida.",
            ],
            "en": [
                "Fewer unnecessary requests without lowering VALID/SLOW requirements.",
                "PING/LAT uses homogeneous IP-service and stability measurements; the decisive web load is no longer mixed into that average.",
                "Geolocation, anonymity and stability run only after real HTTPS navigation is confirmed.",
                "Conservative cleanup of stale comments without changing formats, Resume, or output files.",
            ],
        },
        "fixed": {
            "es": [
                "Las ramas con protocolo incorrecto dejan de gastar comprobaciones de IP, geo, anonimato y estabilidad antes de fallar.",
            ],
            "en": [
                "Wrong-protocol branches no longer spend IP, geo, anonymity, and stability checks before failing.",
            ],
        },
    },
    "V7.8.3": {
        "added": {
            "es": [
                "Diagnóstico detallado para errores de protocolo durante la creación o uso del cliente proxy.",
            ],
            "en": [
                "Detailed diagnostics for protocol errors while creating or using the proxy client.",
            ],
        },
        "improved": {
            "es": [
                "Los ValueError deterministas conservan su causa real y evitan reintentos completos innecesarios.",
                "El diagnóstico final separa errores de protocolo de la categoría genérica OTHER.",
            ],
            "en": [
                "Deterministic ValueError failures now preserve their real cause and avoid unnecessary full retries.",
                "Final diagnostics now separates protocol errors from the generic OTHER category.",
            ],
        },
        "fixed": {
            "es": [
                "SOCKS4 ya no oculta la causa técnica detrás de un simple ValueError.",
            ],
            "en": [
                "SOCKS4 no longer hides the technical cause behind a plain ValueError.",
            ],
        },
    },
    "V7.8.2": {
        "added": {
            "es": [
                "Configuración ahora indica que los ajustes avanzados se editan desde config.json.",
            ],
            "en": [
                "Settings now explains that advanced options are edited in config.json.",
            ],
        },
        "improved": {
            "es": [
                "La pantalla CONFIGURATION/CONFIGURACIÓN respeta completamente el idioma seleccionado.",
            ],
            "en": [
                "The CONFIGURATION/SETTINGS summary now fully follows the selected language.",
            ],
        },
        "fixed": {
            "es": [
                "El contador Procesados ahora muestra solo los tests procesados de la lista y modo actuales.",
            ],
            "en": [
                "Processed now counts only tests belonging to the current list and mode.",
            ],
        },
    },
    "V7.8.1": {
        "added": {
            "es": [
                "Validación y normalización segura de config.json.",
                "Resume compatible con proxies autenticados sin alterar la línea visible de resultados.",
            ],
            "en": [
                "Safe config.json validation and normalization.",
                "Resume support for authenticated proxies without changing the visible result line.",
            ],
        },
        "improved": {
            "es": [
                "resumen.txt ahora respeta el idioma Español/English.",
                "Explorador TXT conectado a la función existente correcta.",
            ],
            "en": [
                "resumen.txt now follows the selected Spanish/English language.",
                "TXT explorer now calls the correct existing function.",
            ],
        },
        "fixed": {
            "es": [
                "Corregido NameError al abrir el mini explorador TXT.",
                "Corregido Continue/Resume para proxies con usuario y contraseña.",
                "Valores inválidos de config.json ya no pueden crear Semaphore(0) ni rangos incoherentes.",
            ],
            "en": [
                "Fixed NameError when opening the TXT mini explorer.",
                "Fixed Continue/Resume for username/password proxies.",
                "Invalid config.json values can no longer create Semaphore(0) or inconsistent ranges.",
            ],
        },
    },
    "V7.8.0": {
        "added": {
            "es": [
                "Estadísticas finales por protocolo sin crear archivos adicionales.",
                "Diagnóstico agrupado de fallos para analizar falsos positivos y negativos.",
                "Velocidad reciente NOW y promedio global AVG durante el escaneo.",
            ],
            "en": [
                "Final per-protocol statistics without creating extra files.",
                "Grouped failure diagnostics to analyze false positives and negatives.",
                "Recent NOW speed and global AVG speed during scans.",
            ],
        },
        "improved": {
            "es": [
                "ETA suavizada usando ritmo reciente y promedio global.",
                "Interfaz final más informativa manteniendo una línea por resultado.",
                "Separación entre estado funcional y calidad SCORE.",
            ],
            "en": [
                "Smoother ETA using recent and global average throughput.",
                "More informative final UI while preserving one-line results.",
                "Functional status kept separate from SCORE quality.",
            ],
        },
        "fixed": {
            "es": [
                "Eliminado resumen.json; se conserva resumen.txt y el estado interno de Resume.",
            ],
            "en": [
                "Removed resumen.json; resumen.txt and internal Resume state are preserved.",
            ],
        },
    },
    "V7.7.0": {
        "added": {
            "es": [
                "Interfaz base Español / English con preferencia local.",
                "Aviso de novedades mostrado una sola vez por versión.",
                "Gestor de dependencias con instalación automática confirmada.",
                "Diagnóstico local de Python, dependencias, sistema y escritura.",
                "Estado local independiente de los resultados y de Resume.",
            ],
            "en": [
                "Spanish / English base interface with local preference.",
                "What's New notice shown only once per version.",
                "Dependency manager with confirmed automatic installation.",
                "Local diagnostics for Python, dependencies, OS and write access.",
                "Local state independent from results and Resume.",
            ],
        },
        "improved": {
            "es": [
                "Versionado centralizado para evitar textos de versiones antiguas.",
                "Inicio preparado para futuras advertencias de versiones obsoletas.",
            ],
            "en": [
                "Centralized versioning to avoid stale version labels.",
                "Startup prepared for future outdated-version warnings.",
            ],
        },
        "fixed": {
            "es": ["Etiquetas heredadas de V7.6.5 en la guía y cierre."],
            "en": ["Legacy V7.6.5 labels in the guide and completion message."],
        },
    },
    "V7.7.3": {
        "added": {
            "es": ["Cierre visual profesional con resumen final y mensajes de guardado."],
            "en": ["Professional closing screen with final summary and save messages."],
        },
        "improved": {
            "es": ["Colores de terminal más consistentes en resultados, progreso y cierre."],
            "en": ["More consistent terminal colors for results, progress and shutdown."],
        },
        "fixed": {
            "es": ["Limpieza asíncrona reforzada al finalizar o interrumpir un escaneo."],
            "en": ["Stronger asynchronous cleanup when a scan finishes or is interrupted."],
        },
    }
}


def t(clave):
    data = TEXTS.get(clave, {})
    return data.get(LANGUAGE) or data.get("es") or clave


def ruta_estado_local():
    base = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base, STATE_FILE)


def cargar_estado_local():
    ruta = ruta_estado_local()
    try:
        with open(ruta, "r", encoding="utf-8") as archivo:
            data = json.load(archivo)
            return data if isinstance(data, dict) else {}
    except (OSError, ValueError, TypeError):
        return {}


def guardar_estado_local(estado):
    ruta = ruta_estado_local()
    try:
        with open(ruta, "w", encoding="utf-8") as archivo:
            json.dump(estado, archivo, ensure_ascii=False, indent=4)
        return True
    except OSError:
        return False


def seleccionar_idioma(estado):
    global LANGUAGE
    guardado = estado.get("language")
    if guardado in {"es", "en"}:
        LANGUAGE = guardado
        return

    print()
    print(color("╔════════════════════════════════════════════════════════════╗", CYAN))
    print(color("║                  SELECT LANGUAGE / IDIOMA                  ║", CYAN))
    print(color("╠════════════════════════════════════════════════════════════╣", CYAN))
    print("║ [1] Español                                                ║")
    print("║ [2] English                                                ║")
    print(color("╚════════════════════════════════════════════════════════════╝", CYAN))
    while True:
        opcion = input("\nSelecciona / Select [1/2]: ").strip()
        if opcion in {"", "1"}:
            LANGUAGE = "es"
            break
        if opcion == "2":
            LANGUAGE = "en"
            break
        print(color("[!] 1 / 2", YELLOW))
    estado["language"] = LANGUAGE
    guardar_estado_local(estado)




def seleccionar_idioma_inicio():
    """Muestra el selector de idioma en cada inicio del programa."""
    global LANGUAGE

    while True:
        print()
        print(color("╔════════════════════════════════════════════════════════════╗", CYAN))
        print(color("║                  IDIOMA / LANGUAGE                        ║", CYAN))
        print(color("╠════════════════════════════════════════════════════════════╣", CYAN))
        print(f"  {color('[1]', GREEN)} Español")
        print(f"  {color('[2]', GREEN)} English")
        print(color("╚════════════════════════════════════════════════════════════╝", CYAN))

        opcion = input(color("> ", CYAN)).strip()

        if opcion == "1":
            LANGUAGE = "es"
            break
        if opcion == "2":
            LANGUAGE = "en"
            break

        print(color("[!] Opción inválida / Invalid option.", RED))

    # Keep the chosen language in state for consistency, although startup asks every time.
    estado = cargar_estado_local()
    estado["language"] = LANGUAGE
    guardar_estado_local(estado)
    return LANGUAGE

def cambiar_idioma():
    """Permite cambiar manualmente el idioma y guardar la preferencia."""
    global LANGUAGE

    estado = cargar_estado_local()

    while True:
        print()
        print(color("╔════════════════════════════════════════════════════════════╗", CYAN))
        print(color("║                  SELECT LANGUAGE / IDIOMA                  ║", CYAN))
        print(color("╠════════════════════════════════════════════════════════════╣", CYAN))
        print(f"  {color('[1]', GREEN)} Español")
        print(f"  {color('[2]', GREEN)} English")
        print(f"  {color('[0]', YELLOW)} Volver / Back")
        print(color("╚════════════════════════════════════════════════════════════╝", CYAN))

        opcion = input(color("> ", CYAN)).strip()

        if opcion == "1":
            LANGUAGE = "es"
            break
        if opcion == "2":
            LANGUAGE = "en"
            break
        if opcion == "0":
            return False

        print(color("[!] Opción inválida / Invalid option.", RED))

    estado["language"] = LANGUAGE
    guardar_estado_local(estado)

    mensaje = (
        "[✓] Idioma cambiado a Español."
        if LANGUAGE == "es"
        else "[✓] Language changed to English."
    )
    print(color(mensaje, GREEN))
    return True

def mostrar_novedades_si_corresponde(estado):
    if estado.get("last_seen_version") == VERSION:
        return
    cambios = CHANGELOG.get(VERSION)
    if not cambios:
        estado["last_seen_version"] = VERSION
        guardar_estado_local(estado)
        return
    print()
    print(color("╔════════════════════════════════════════════════════════════╗", MAGENTA))
    titulo = f"{t('whats_new')} — {VERSION}"
    print(color(f"║ {titulo:^58} ║", MAGENTA))
    print(color("╠════════════════════════════════════════════════════════════╣", MAGENTA))
    for grupo, simbolo in (("added", "+"), ("improved", "~"), ("fixed", "✓")):
        items = cambios.get(grupo, {}).get(LANGUAGE, [])
        if not items:
            continue
        print(f"[{simbolo}] {t(grupo)}")
        for item in items:
            print(f"    • {item}")
    print(color("╚════════════════════════════════════════════════════════════╝", MAGENTA))
    input(color(t("continue"), GREEN))
    estado["last_seen_version"] = VERSION
    estado["latest_known_version"] = VERSION
    guardar_estado_local(estado)


def version_tuple(version):
    numeros = re.findall(r"\d+", str(version))
    return tuple(int(n) for n in numeros[:3])


def advertir_version_antigua(estado):
    ultima = estado.get("latest_known_version")
    if not ultima or version_tuple(ultima) <= version_tuple(VERSION):
        return
    print()
    print(color(f"[!] {t('old_warning')}", YELLOW))
    print(f"    {t('installed_version')}: {VERSION}")
    print(f"    {t('latest_known')}: {ultima}")
    print(f"    {t('old_note')}")
    problemas = estado.get("known_issues", {}).get(VERSION, [])
    for problema in problemas:
        print(f"    • {problema}")
    print()


def diagnostico_local(config_path="config.json"):
    python_ok = sys.version_info >= (3, 10)
    httpx_ok = importlib.util.find_spec("httpx") is not None
    socks_ok = importlib.util.find_spec("socksio") is not None
    socks4_ok = importlib.util.find_spec("httpx_socks") is not None
    base = os.path.dirname(os.path.abspath(__file__))
    escritura = os.access(base, os.W_OK)
    config_ok = True
    if os.path.isfile(config_path):
        try:
            with open(config_path, "r", encoding="utf-8") as archivo:
                json.load(archivo)
        except Exception:
            config_ok = False
    print()
    print(color(f"=== {t('self_test')} ===", CYAN))
    checks = [
        (f"Python {platform.python_version()}", python_ok),
        ("httpx", httpx_ok),
        ("SOCKS5", socks_ok),
        ("SOCKS4", socks4_ok),
        (f"{t('os')}: {platform.system()} {platform.release()}", True),
        (t("write_access"), escritura),
        (t("config_ok"), config_ok),
    ]
    for nombre, ok in checks:
        marca = color("[✓]", GREEN) if ok else color("[×]", RED)
        print(f"{marca} {nombre}")
    if all(ok for _, ok in checks):
        print(color(f"\n[✓] {t('status_ready')}", GREEN))
    print()
    return all(ok for _, ok in checks)


# CONFIGURACIÓN

@dataclass
class Config:
    workers: int = DEFAULT_WORKERS
    timeout: float = DEFAULT_TIMEOUT
    connect_timeout: float = DEFAULT_CONNECT_TIMEOUT
    retries: int = DEFAULT_REINTENTOS
    max_latency: float = DEFAULT_MAX_LATENCIA
    rate: float = DEFAULT_RATE

    jitter_min: float = DEFAULT_JITTER_MIN
    jitter_max: float = DEFAULT_JITTER_MAX

    stability_tests: int = STABILITY_TESTS

    min_ip_confirmations: int = (
        MIN_IP_CONFIRMATIONS
    )

    third_ip_check: bool = (
        USE_THIRD_IP_CHECK
    )


def guardar_resumen_txt(
    carpeta,
    tareas,
    tiempo_total,
):
    ruta = os.path.join(carpeta, "resumen.txt")
    velocidad = (
        stats["tested"] / tiempo_total
        if tiempo_total > 0
        else 0
    )

    if LANGUAGE == "es":
        lineas = [
            f"PROXY CHECKER {VERSION} - RESUMEN",
            "=" * 46,
            f"Total de tareas       : {len(tareas):,}",
            f"Procesados            : {stats['tested']:,}",
            f"Validos               : {stats['valid']:,}",
            f"Lentos                : {stats['slow']:,}",
            f"Muertos               : {stats['dead']:,}",
            f"Indeterminados        : {stats['indeterminate']:,}",
            "",
            f"Excellent             : {stats['excellent']:,}",
            f"Good                  : {stats['good']:,}",
            f"Fair                  : {stats['fair']:,}",
            f"Poor / Very Poor      : {stats['poor']:,}",
            "",
            f"Velocidad             : {velocidad:.2f}/s",
            f"Tiempo total          : {formato_tiempo(tiempo_total)}",
            "",
            "LEYENDA RAPIDA",
            "-" * 46,
            "VALID         = proxy funcional, web HTTPS confirmada y latencia aceptable.",
            "SLOW          = web HTTPS confirmada, pero supera la latencia maxima.",
            "DEAD          = no establecio una conexion valida.",
            "INDETERMINATE = no hubo evidencia suficiente para clasificarlo.",
            "",
            "ELITE         = sin cabeceras tipicas de proxy detectadas.",
            "ANONYMOUS     = se detectan indicios de proxy.",
            "TRANSPARENT   = puede revelar IP original/uso del proxy.",
            "UNKNOWN       = anonimato no determinado.",
            "N/A           = dato que no llego a obtenerse.",
            "",
        ]
    else:
        lineas = [
            f"PROXY CHECKER {VERSION} - SUMMARY",
            "=" * 46,
            f"Total tasks           : {len(tareas):,}",
            f"Processed             : {stats['tested']:,}",
            f"Valid                 : {stats['valid']:,}",
            f"Slow                  : {stats['slow']:,}",
            f"Dead                  : {stats['dead']:,}",
            f"Indeterminate         : {stats['indeterminate']:,}",
            "",
            f"Excellent             : {stats['excellent']:,}",
            f"Good                  : {stats['good']:,}",
            f"Fair                  : {stats['fair']:,}",
            f"Poor / Very Poor      : {stats['poor']:,}",
            "",
            f"Speed                 : {velocidad:.2f}/s",
            f"Total time            : {formato_tiempo(tiempo_total)}",
            "",
            "QUICK LEGEND",
            "-" * 46,
            "VALID         = working proxy, HTTPS web confirmed and acceptable latency.",
            "SLOW          = HTTPS web confirmed, but above the latency limit.",
            "DEAD          = no valid connection was established.",
            "INDETERMINATE = not enough evidence was available to classify it.",
            "",
            "ELITE         = no typical proxy headers detected.",
            "ANONYMOUS     = proxy indicators were detected.",
            "TRANSPARENT   = may reveal the original IP/proxy usage.",
            "UNKNOWN       = anonymity could not be determined.",
            "N/A           = data could not be obtained.",
            "",
        ]

    with open(ruta, "w", encoding="utf-8") as archivo:
        archivo.write("\n".join(lineas))

    return ruta


# ESTADÍSTICAS

stats = {
    "tested": 0,
    "valid": 0,
    "slow": 0,
    "dead": 0,
    "indeterminate": 0,

    "excellent": 0,
    "good": 0,
    "fair": 0,
    "poor": 0,

    "start_time": 0.0,

    # Métricas de sesión (solo memoria; no crean archivos adicionales).
    "protocols": {
        protocolo: {"tested": 0, "valid": 0, "slow": 0, "dead": 0, "indeterminate": 0}
        for protocolo in PROTOCOLOS
    },
    "failure_reasons": {},
    "speed_samples": [],
}

stats_lock = asyncio.Lock()


# RATE LIMITER OPTIMIZADO

class RateLimiter:

    def __init__(self, rate):
        self.rate = max(
            0.1,
            float(rate),
        )

        self.interval = (
            1.0 / self.rate
        )

        self.lock = asyncio.Lock()
        self.next_allowed = 0.0

    async def wait(self):

        async with self.lock:

            ahora = time.perf_counter()

            permitido = max(
                ahora,
                self.next_allowed,
            )

            self.next_allowed = (
                permitido
                + self.interval
            )

        espera = permitido - ahora

        if espera > 0:
            await asyncio.sleep(
                espera
            )

        jitter = random.uniform(
            DEFAULT_JITTER_MIN,
            DEFAULT_JITTER_MAX,
        )

        if jitter > 0:
            await asyncio.sleep(
                jitter
            )


# BANNER

def mostrar_banner():

    print()

    print(
        color(
            "╔════════════════════════════════════════════════════════════╗",
            CYAN,
        )
    )

    print(
        color("║", CYAN)
        + color(
            f"                 PROXY CHECKER {VERSION}",
            BOLD,
        )
        + "                         "
        + color("║", CYAN)
    )

    print(
        color("║", CYAN)
        + " " * 25
        + color("@Flippy2x", MAGENTA)
        + " " * 25
        + color("║", CYAN)
    )

    print(
        color(
            "╠════════════════════════════════════════════════════════════╣",
            CYAN,
        )
    )

    print(
        color("║", CYAN)
        + " "
        + color(
            "ASYNC • FAST • GEO • SCORE • RANKING",
            WHITE,
        )
        + " "
        + color("║", CYAN)
    )

    print(
        color("║", CYAN)
        + " "
        + color(
            "STABILITY • ANONYMITY • RESUME • ANALYTICS",
            WHITE,
        )
        + " "
        + color("║", CYAN)
    )

    print(
        color(
            "╚════════════════════════════════════════════════════════════╝",
            CYAN,
        )
    )

    print()


# IP

def ip_valida(valor):

    try:
        ipaddress.ip_address(valor)
        return True

    except ValueError:
        return False


def host_valido(valor):
    """
    Acepta una IP válida o un hostname DNS sintácticamente válido.
    No realiza una resolución DNS aquí; eso queda a cargo del cliente
    cuando se prueba realmente el proxy.
    """
    valor = valor.strip().rstrip(".")

    if not valor or len(valor) > 253:
        return False

    if ip_valida(valor):
        return True

    etiquetas = valor.split(".")

    for etiqueta in etiquetas:
        if not etiqueta or len(etiqueta) > 63:
            return False

        if not re.fullmatch(
            r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?",
            etiqueta,
        ):
            return False

    return True


def puerto_valido(valor):
    try:
        puerto = int(valor)
    except (TypeError, ValueError):
        return False

    return 1 <= puerto <= 65535


def extraer_ip(texto):

    texto = texto.strip()

    if not texto:
        return None

    try:

        data = json.loads(texto)

        if isinstance(data, dict):

            for clave in (
                "ip",
                "origin",
            ):

                valor = data.get(
                    clave
                )

                if not valor:
                    continue

                for candidato in re.split(
                    r"[\s,]+",
                    str(valor),
                ):

                    candidato = (
                        candidato.strip()
                    )

                    if ip_valida(
                        candidato
                    ):
                        return candidato

    except Exception:
        pass

    encontrados = re.findall(
        r"(?<![\d.])"
        r"(?:\d{1,3}\.){3}\d{1,3}"
        r"(?![\d.])",
        texto,
    )

    for ip in encontrados:

        if ip_valida(ip):
            return ip

    return None


# PROXY ENTRY

@dataclass(frozen=True)
class ProxyEntry:

    host: str
    port: int

    username: Optional[str] = None
    password: Optional[str] = None

    protocolo: Optional[str] = None

    @property
    def proxy(self):

        return (
            f"{self.host}:"
            f"{self.port}"
        )

    @property
    def tiene_auth(self):

        return (
            self.username is not None
            and
            self.password is not None
        )

    @property
    def auth_fingerprint(self):

        if not self.tiene_auth:
            return "NOAUTH"

        contenido = (
            f"{self.username}:"
            f"{self.password}"
        )

        return hashlib.sha256(
            contenido.encode(
                "utf-8"
            )
        ).hexdigest()[:16]


# PARSER

def parsear_proxy(linea):
    """
    Formatos admitidos:
      host:port
      hostname:port
      host:port:user:pass
      hostname:port:user:pass
      user:pass:host:port
      user:pass:hostname:port

    También conserva los prefijos del V7:
      http://
      https://
      socks4:// / socks4a://
      socks5:// / socks5h://
    """

    texto = linea.strip()

    if not texto or texto.startswith("#"):
        return None

    texto = texto.strip('"').strip("'")
    protocolo = None
    texto_lower = texto.lower()

    for prefijo, proto in PREFIXES.items():
        if texto_lower.startswith(prefijo):
            protocolo = proto
            texto = texto[len(prefijo):]
            break

    texto = texto.strip().rstrip("/")
    partes = texto.split(":")

    username = None
    password = None

    # host:port / hostname:port
    if len(partes) == 2:
        host, port_text = partes

    # 4 campos:
    #   host:port:user:pass
    #   user:pass:host:port
    elif len(partes) == 4:
        p1, p2, p3, p4 = (
            parte.strip()
            for parte in partes
        )

        # Primero intentamos el formato histórico del V7:
        # host:port:user:pass
        if (
            host_valido(p1)
            and puerto_valido(p2)
            and p3
            and p4
        ):
            host = p1
            port_text = p2
            username = p3
            password = p4

        # Después:
        # user:pass:host:port
        elif (
            p1
            and p2
            and host_valido(p3)
            and puerto_valido(p4)
        ):
            username = p1
            password = p2
            host = p3
            port_text = p4

        else:
            return None

    else:
        return None

    host = host.strip()
    port_text = port_text.strip()

    if not host_valido(host):
        return None

    if not puerto_valido(port_text):
        return None

    port = int(port_text)

    return ProxyEntry(
        host=host,
        port=port,
        username=username,
        password=password,
        protocolo=protocolo,
    )


# CONSTRUIR URL

def construir_proxy_url(
    entry,
    protocolo,
):

    if protocolo not in PROTOCOLOS:
        raise ValueError(
            f"Protocolo desconocido: "
            f"{protocolo}"
        )

    auth = ""

    if entry.tiene_auth:

        usuario = quote(
            entry.username,
            safe="",
        )

        password = quote(
            entry.password,
            safe="",
        )

        auth = (
            f"{usuario}:"
            f"{password}@"
        )

    return (
        f"{protocolo}://"
        f"{auth}"
        f"{entry.host}:"
        f"{entry.port}"
    )


# RESULTADO BASE

def resultado_base(
    entry,
    protocolo,
):

    return {

        "proxy": entry.proxy,
        "protocolo": protocolo,

        "estado": "dead",

        "score": 0,
        "calidad": "UNKNOWN",

        "latencias": [],

        "latencia_min": 0,
        "latencia_media": 0,
        "latencia_max": 0,

        "jitter": 0,

        "ips": [],
        "ip_salida": "",

        "ip_consistente": False,
        "ip_rotatoria": False,

        "confirmaciones": 0,

        "google_ok": False,
        "google_tipo": "",

        "anonimato": "UNKNOWN",
        "anonimato_detalle": "",

        "pais": "",
        "codigo_pais": "",
        "region": "",
        "ciudad": "",
        "isp": "",
        "asn": "",

        "estabilidad": 0,

        "detalle": "no_confirmado",

        "auth": entry.tiene_auth,

        "auth_fingerprint":
            entry.auth_fingerprint,
    }


def resultado_dead(
    entry,
    protocolo,
    detalle="no_confirmado",
):

    resultado = resultado_base(
        entry,
        protocolo,
    )

    resultado["detalle"] = detalle

    return resultado


def resultado_indeterminado(
    entry,
    protocolo,
    detalle="servicio_temporal",
):

    resultado = resultado_base(
        entry,
        protocolo,
    )

    resultado["estado"] = (
        "indeterminate"
    )

    resultado["detalle"] = detalle

    return resultado


# ERROR

def resultado_error(
    tipo,
    latencia=0,
    **extra,
):

    return {
        "ok": False,
        "respuesta": None,
        "latencia": latencia,
        "tipo": tipo,
        **extra,
    }


def es_error_temporal(tipo):

    return (
        tipo in TEMPORARY_ERRORS
    )


def fallo_concluyente_tras_reintentos(tipo):
    """Indica si un fallo repetido puede cerrar la rama como DEAD.

    V7.9.4 evita los dos extremos que vimos en pruebas reales: mandar casi
    todo a INDETERMINATE o convertir cualquier excepción en DEAD. Los fallos
    transitorios solo son concluyentes cuando se repiten de forma consistente.
    """
    return tipo in {
        "connection_error",
        "proxy_error",
        "request_error",
        "timeout",
    }


def firma_fallo(tipo):
    texto = str(tipo or "").strip()
    return texto.split(":", 1)[0].strip().lower()


def es_fallo_local_o_externo(tipo):
    t = str(tipo or "").lower()
    return any(x in t for x in (
        "transport unavailable",
        "local_protocol_error",
        "rate_limited",
        "service_unavailable",
        "web_rate_limited",
        "web_service_unavailable",
    ))


def es_fallo_protocolo_claro(tipo):
    t = str(tipo or "").lower()
    return any(x in t for x in (
        "unexpected reply version",
        "malformed reply",
        "connection closed unexpectedly",
        "wrong_version_number",
        "wrong version number",
        "web_content_mismatch",
        "no_ip",
    ))


def decidir_fallo_final(historial, detalle):
    """Devuelve 'dead' o 'indeterminate' usando evidencia acumulada.

    - errores del propio checker/servicios externos => INDET
    - incompatibilidad clara de protocolo/contenido => DEAD
    - fallo temporal repetido con la misma firma => DEAD
    - señales mezcladas/ambiguas => INDET
    """
    if es_fallo_local_o_externo(detalle):
        return "indeterminate"
    if es_fallo_protocolo_claro(detalle):
        return "dead"

    firmas = [firma_fallo(x) for x in historial if x]
    if len(firmas) >= 2 and len(set(firmas)) == 1:
        if fallo_concluyente_tras_reintentos(firmas[-1]):
            return "dead"

    return "indeterminate"


# CLIENTE

def crear_cliente(
    entry,
    protocolo,
    config,
):

    timeout = httpx.Timeout(
        timeout=config.timeout,
        connect=config.connect_timeout,
    )

    proxy_url = construir_proxy_url(entry, protocolo)

    # httpx/socksio cubre SOCKS5, pero no SOCKS4. Para SOCKS4 usamos
    # httpx-socks, que implementa SOCKS4/SOCKS4a de forma nativa y mantiene
    # el mismo AsyncClient/pipeline que el resto del checker.
    if protocolo == "socks4":
        if AsyncProxyTransport is None:
            raise RuntimeError("SOCKS4 transport unavailable: httpx-socks missing")
        transport = AsyncProxyTransport.from_url(proxy_url)
        return httpx.AsyncClient(
            transport=transport,
            verify=True,
            follow_redirects=True,
            max_redirects=MAX_REDIRECTS,
            timeout=timeout,
            trust_env=False,
        )

    return httpx.AsyncClient(
        proxy=proxy_url,
        verify=True,
        follow_redirects=True,
        max_redirects=MAX_REDIRECTS,
        timeout=timeout,
        limits=httpx.Limits(
            max_connections=4,
            max_keepalive_connections=2,
        ),
        trust_env=False,
    )


# REQUEST

async def hacer_request(
    client,
    url,
    rate_limiter,
    allow_redirects=True,
    timeout=None,
):

    await rate_limiter.wait()

    inicio = time.perf_counter()

    try:

        respuesta = await client.get(

            url,

            headers={
                "User-Agent":
                    obtener_user_agent(),

                "Accept":
                    "*/*",

                "Accept-Language":
                    "en-US,en;q=0.9",

                "Cache-Control":
                    "no-cache",

                "Pragma":
                    "no-cache",
            },

            follow_redirects=
                allow_redirects,

            timeout=timeout,
        )

        latencia = (
            time.perf_counter()
            - inicio
        )

        return {
            "ok": True,
            "respuesta": respuesta,
            "latencia": latencia,
            "tipo": "success",
        }

    except httpx.ProxyError:

        return resultado_error(
            "proxy_error"
        )

    except (
        httpx.ConnectTimeout,
        httpx.ReadTimeout,
        httpx.WriteTimeout,
        httpx.PoolTimeout,
    ):

        return resultado_error(
            "timeout"
        )

    except httpx.ConnectError:

        return resultado_error(
            "connection_error"
        )

    except (
        httpx.RemoteProtocolError,
        httpx.HTTPError,
    ):

        return resultado_error(
            "request_error"
        )

    except Exception as error:

        detalle = str(error).strip()
        tipo = type(error).__name__

        if detalle:
            tipo = f"{tipo}: {detalle[:180]}"

        return resultado_error(
            tipo
        )


# IP SERVICE

async def probar_ip_service(
    client,
    url,
    rate_limiter,
):

    resultado = await hacer_request(
        client,
        url,
        rate_limiter,
    )

    if not resultado["ok"]:
        return resultado

    respuesta = resultado[
        "respuesta"
    ]

    status = (
        respuesta.status_code
    )

    latencia = resultado[
        "latencia"
    ]

    if status == 429:

        return resultado_error(
            "rate_limited",
            latencia,
            status=status,
        )

    if 500 <= status <= 599:

        return resultado_error(
            "service_unavailable",
            latencia,
            status=status,
        )

    if not 200 <= status <= 299:

        return resultado_error(
            "http_error",
            latencia,
            status=status,
        )

    try:

        texto = respuesta.text

    except Exception:

        return resultado_error(
            "no_body",
            latencia,
            status=status,
        )

    ip = extraer_ip(texto)

    if not ip:

        return resultado_error(
            "no_ip",
            latencia,
            status=status,
        )

    return {
        "ok": True,
        "ip": ip,
        "latencia": latencia,
        "tipo": "success",
        "status": status,
    }


# PRUEBA IP OPTIMIZADA

async def probar_ips(
    client,
    rate_limiter,
    config,
):

    urls = IP_TEST_URLS.copy()
    random.shuffle(urls)

    objetivo = max(
        1,
        config.min_ip_confirmations,
    )

    # Primer lote: hasta "objetivo" servicios independientes
    # en paralelo. Normalmente son 2.
    primeras = urls[:objetivo]

    resultados = await asyncio.gather(
        *(
            probar_ip_service(
                client,
                url,
                rate_limiter,
            )
            for url in primeras
        ),
        return_exceptions=False,
    )

    def contar_exitosos():
        return sum(
            1
            for resultado in resultados
            if resultado.get("ok")
            and resultado.get("ip")
        )

    # Si ya hay suficientes respuestas reales, no hacemos
    # peticiones extra. Las IP pueden diferir en proxies rotatorios;
    # esa situación se analiza después con la lógica existente.
    if contar_exitosos() >= objetivo:
        return resultados

    # Fallback V7.6: si una fuente falla, probar proveedores
    # adicionales uno por uno hasta conseguir consenso de
    # conectividad o agotar el pool.
    if config.third_ip_check:
        for url in urls[len(primeras):]:
            resultado = await probar_ip_service(
                client,
                url,
                rate_limiter,
            )
            resultados.append(resultado)

            if contar_exitosos() >= objetivo:
                break

    return resultados


# GOOGLE

async def probar_google(
    client,
    rate_limiter,
):

    resultado = await hacer_request(
        client,
        GOOGLE_TEST_URL,
        rate_limiter,
        allow_redirects=False,
    )

    if not resultado["ok"]:

        return {
            "ok": False,
            "latencia":
                resultado["latencia"],
            "tipo":
                resultado["tipo"],
        }

    status = resultado[
        "respuesta"
    ].status_code

    if status == 204:

        return {
            "ok": True,
            "latencia":
                resultado["latencia"],
            "tipo":
                "success",
        }

    if status == 429:

        tipo = "rate_limited"

    elif 500 <= status <= 599:

        tipo = "service_unavailable"

    else:

        tipo = (
            f"google_status_{status}"
        )

    return {
        "ok": False,
        "latencia":
            resultado["latencia"],
        "tipo": tipo,
    }


# PRUEBA WEB HTTPS DECISIVA

async def probar_web_real(
    client,
    rate_limiter,
):
    """
    Comprueba que el proxy pueda navegar por HTTPS de verdad:
    - conexión/túnel HTTPS
    - redirects
    - respuesta HTTP útil
    - HTML recibido
    - título esperado
    Una sola petición cubre estas comprobaciones para no saturar la proxy.
    """

    resultado = await hacer_request(
        client,
        WEB_TEST_URL,
        rate_limiter,
        allow_redirects=True,
        timeout=WEB_TEST_TIMEOUT,
    )

    if not resultado.get("ok"):
        return {
            "ok": False,
            "latencia": resultado.get("latencia", 0),
            "tipo": resultado.get("tipo", "web_request_error"),
            "status": resultado.get("status"),
        }

    respuesta = resultado["respuesta"]
    status = respuesta.status_code
    latencia = resultado["latencia"]

    if status == 429:
        return {
            "ok": False,
            "latencia": latencia,
            "tipo": "web_rate_limited",
            "status": status,
        }

    if 500 <= status <= 599:
        return {
            "ok": False,
            "latencia": latencia,
            "tipo": "web_service_unavailable",
            "status": status,
        }

    if not 200 <= status <= 399:
        return {
            "ok": False,
            "latencia": latencia,
            "tipo": f"web_status_{status}",
            "status": status,
        }

    try:
        html = respuesta.text or ""
    except Exception:
        return {
            "ok": False,
            "latencia": latencia,
            "tipo": "web_no_body",
            "status": status,
        }

    # Equivalente conceptual a comprobar que el título de la página
    # contiene "Google", sin exigir mayúsculas/minúsculas exactas.
    match = re.search(
        r"<title[^>]*>\s*(.*?)\s*</title>",
        html,
        flags=re.IGNORECASE | re.DOTALL,
    )

    titulo = (
        re.sub(r"\s+", " ", match.group(1)).strip()
        if match
        else ""
    )

    if WEB_EXPECTED_TITLE not in titulo.lower():
        return {
            "ok": False,
            "latencia": latencia,
            "tipo": "web_content_mismatch",
            "status": status,
            "titulo": titulo[:120],
        }

    return {
        "ok": True,
        "latencia": latencia,
        "tipo": "success",
        "status": status,
        "titulo": titulo[:120],
    }


# ANONIMATO

def detectar_anonymity(
    respuesta,
    ip_salida,
):

    if respuesta is None:

        return (
            "UNKNOWN",
            "sin_respuesta",
        )

    try:

        headers = {
            str(k).lower():
                str(v)

            for k, v
            in respuesta.headers.items()
        }

        encontrados = [

            header

            for header
            in ANONYMITY_HEADERS

            if header in headers
        ]

        texto_headers = (
            json.dumps(
                headers,
                ensure_ascii=False,
            )
            .lower()
        )

        ips = re.findall(
            r"(?<![\d.])"
            r"(?:\d{1,3}\.){3}\d{1,3}"
            r"(?![\d.])",
            texto_headers,
        )

        ips_distintas = [

            ip

            for ip in ips

            if ip_valida(ip)
            and ip != ip_salida
        ]

        if ips_distintas:

            return (
                "TRANSPARENT",
                "ip_detectada_en_headers",
            )

        if encontrados:

            return (
                "ANONYMOUS",
                "headers_proxy_detectados",
            )

        return (
            "ELITE",
            "sin_headers_proxy_obvios",
        )

    except Exception:

        return (
            "UNKNOWN",
            "error_clasificacion",
        )


async def probar_anonymity(
    client,
    rate_limiter,
    ip_salida,
):

    resultado = await hacer_request(
        client,
        ANONYMITY_TEST_URL,
        rate_limiter,
    )

    if not resultado["ok"]:

        return {
            "nivel": "UNKNOWN",
            "detalle":
                resultado["tipo"],
        }

    respuesta = resultado[
        "respuesta"
    ]

    if not (
        200 <=
        respuesta.status_code
        <= 299
    ):

        return {
            "nivel": "UNKNOWN",
            "detalle":
                f"http_{respuesta.status_code}",
        }

    nivel, detalle = (
        detectar_anonymity(
            respuesta,
            ip_salida,
        )
    )

    return {
        "nivel": nivel,
        "detalle": detalle,
    }


# GEOLOCALIZACIÓN

async def geolocalizar_ip(
    ip,
    geo_client,
    geo_cache,
    geo_lock,
):

    if not ip:
        return {}

    async with geo_lock:

        if ip in geo_cache:

            return geo_cache[ip]

    url = GEOLOCATION_URL.format(
        ip=ip
    )

    try:

        respuesta = await geo_client.get(
            url,
            timeout=5.0,
        )

        if respuesta.status_code != 200:

            return {}

        data = respuesta.json()

        if not data.get(
            "success",
            False,
        ):
            return {}

        connection = (
            data.get(
                "connection"
            )
            or {}
        )

        resultado = {

            "pais":
                data.get(
                    "country",
                    "",
                ),

            "codigo_pais":
                data.get(
                    "country_code",
                    "",
                ),

            "region":
                data.get(
                    "region",
                    "",
                ),

            "ciudad":
                data.get(
                    "city",
                    "",
                ),

            "isp":
                connection.get(
                    "isp",
                    "",
                ),

            "asn":
                str(
                    connection.get(
                        "asn",
                        "",
                    )
                ),
        }

        async with geo_lock:

            geo_cache[ip] = resultado

        return resultado

    except Exception:

        return {}


# LATENCIA

def calcular_latencias(
    latencias,
):

    if not latencias:

        return (
            0,
            0,
            0,
        )

    minimo = min(
        latencias
    )

    media = (
        sum(latencias)
        / len(latencias)
    )

    maximo = max(
        latencias
    )

    return (
        minimo,
        media,
        maximo,
    )


def calcular_jitter(
    latencias,
):

    if len(latencias) < 2:
        return 0

    media = (
        sum(latencias)
        / len(latencias)
    )

    diferencias = [

        abs(
            latencia
            - media
        )

        for latencia
        in latencias
    ]

    return (
        sum(diferencias)
        / len(diferencias)
    )


# ESTABILIDAD

async def comprobar_estabilidad(
    client,
    rate_limiter,
    ip_inicial,
    config,
):

    if not ip_inicial:

        return {
            "ips": [],
            "latencias": [],
            "estabilidad": 0,
        }

    ips = [ip_inicial]
    latencias = []

    for _ in range(
        max(
            0,
            config.stability_tests - 1,
        )
    ):

        resultado = (
            await probar_ip_service(
                client,
                random.choice(
                    IP_TEST_URLS
                ),
                rate_limiter,
            )
        )

        if resultado.get("ok"):

            ips.append(
                resultado["ip"]
            )

            latencias.append(
                resultado["latencia"]
            )

    if len(ips) <= 1:

        return {
            "ips": ips,
            "latencias":
                latencias,
            "estabilidad": 0,
        }

    principal = ips[0]

    iguales = sum(
        ip == principal
        for ip in ips
    )

    estabilidad = (
        iguales
        / len(ips)
        * 100
    )

    return {
        "ips": ips,
        "latencias":
            latencias,
        "estabilidad":
            estabilidad,
    }


# SCORE

def calcular_score(
    latencia,
    jitter,
    estabilidad,
    anonimato,
    google_ok,
    confirmaciones,
):

    score = 0.0

    # Latencia: 35 puntos

    if latencia <= 0.5:
        score += 35

    elif latencia <= 1:
        score += 32

    elif latencia <= 2:
        score += 27

    elif latencia <= 3:
        score += 20

    elif latencia <= 4:
        score += 12

    else:
        score += 5

    # Estabilidad: 25 puntos

    score += (
        estabilidad
        * 0.25
    )

    # Jitter: 10 puntos

    if jitter <= 0.1:
        score += 10

    elif jitter <= 0.3:
        score += 8

    elif jitter <= 0.6:
        score += 5

    elif jitter <= 1:
        score += 2

    # Anonimato: 15 puntos

    if anonimato == "ELITE":
        score += 15

    elif anonimato == "ANONYMOUS":
        score += 10

    elif anonimato == "TRANSPARENT":
        score += 2

    # Google: 10 puntos

    if google_ok:
        score += 10

    # Confirmaciones: 5 puntos

    if confirmaciones >= 3:
        score += 5

    elif confirmaciones >= 2:
        score += 4

    elif confirmaciones == 1:
        score += 1

    return max(
        0,
        min(
            100,
            round(score),
        ),
    )


def calidad_score(score):

    if score >= 90:
        return "EXCELLENT"

    if score >= 75:
        return "GOOD"

    if score >= 50:
        return "FAIR"

    if score >= 25:
        return "POOR"

    return "VERY_POOR"


# COMPROBAR PROXY

async def comprobar_proxy(
    entry,
    protocolo,
    rate_limiter,
    geo_client,
    geo_cache,
    geo_lock,
    config,
):

    if protocolo not in PROTOCOLOS:

        return resultado_dead(
            entry,
            protocolo,
            "protocolo_invalido",
        )

    ultimo = None

    for intento in range(
        config.retries + 1
    ):

        try:

            async with crear_cliente(
                entry,
                protocolo,
                config,
            ) as client:

                # IP

                resultados_ip = (
                    await probar_ips(
                        client,
                        rate_limiter,
                        config,
                    )
                )

                exitosos = [

                    resultado

                    for resultado
                    in resultados_ip

                    if resultado.get(
                        "ok"
                    )
                    and resultado.get(
                        "ip"
                    )
                ]

                ips = [
                    resultado["ip"]
                    for resultado
                    in exitosos
                ]

                latencias = [

                    resultado[
                        "latencia"
                    ]

                    for resultado
                    in exitosos
                ]

                if not exitosos:

                    tipos = [
                        resultado.get("tipo", "")
                        for resultado in resultados_ip
                    ]

                    # V7.9.6: los endpoints de IP son evidencia auxiliar, no
                    # una sentencia de muerte. En pruebas reales vimos proxies
                    # que una versión validaba como SOCKS4/SOCKS5 y otra
                    # descartaba como no_ip solo porque ipify/httpbin fallaban.
                    # Antes de decidir, comprobamos transporte HTTPS real y
                    # una segunda petición de conectividad. TLS permanece
                    # verificado: no usamos verify=False.
                    web_fallback = await probar_web_real(
                        client,
                        rate_limiter,
                    )

                    if web_fallback.get("ok"):
                        google_fallback = await probar_google(
                            client,
                            rate_limiter,
                        )

                        latencias_fallback = [
                            web_fallback.get("latencia", 0),
                        ]
                        if google_fallback.get("latencia", 0) > 0:
                            latencias_fallback.append(
                                google_fallback["latencia"]
                            )

                        lat_min, lat_media, lat_max = calcular_latencias(
                            latencias_fallback
                        )
                        jitter = calcular_jitter(latencias_fallback)

                        # HTTPS real + contenido esperado demuestra que el
                        # transporte funciona. Google 204 aporta confirmación
                        # adicional cuando está disponible. Los campos IP/geo
                        # quedan vacíos en vez de inventarse.
                        estabilidad_fallback = 100 if google_fallback.get("ok") else 70
                        score = calcular_score(
                            lat_media,
                            jitter,
                            estabilidad_fallback,
                            "UNKNOWN",
                            google_fallback.get("ok", False),
                            0,
                        )
                        estado = (
                            "valid"
                            if lat_media <= config.max_latency
                            else "slow"
                        )

                        resultado = resultado_base(entry, protocolo)
                        resultado.update({
                            "estado": estado,
                            "score": score,
                            "calidad": calidad_score(score),
                            "latencias": latencias_fallback,
                            "latencia_min": lat_min,
                            "latencia_media": lat_media,
                            "latencia_max": lat_max,
                            "jitter": jitter,
                            "google_ok": google_fallback.get("ok", False),
                            "google_tipo": google_fallback.get("tipo", ""),
                            "web_ok": True,
                            "web_tipo": web_fallback.get("tipo", "success"),
                            "web_status": web_fallback.get("status"),
                            "estabilidad": estabilidad_fallback,
                            "detalle": "web_confirmada_sin_ip",
                        })
                        return resultado

                    # Si ni IP ni HTTPS real aportan evidencia suficiente,
                    # distinguimos incompatibilidad concluyente de fallos
                    # temporales/externos.
                    tipo_web = web_fallback.get("tipo", "web_check_failed")
                    if es_error_temporal(tipo_web) or any(
                        es_error_temporal(tipo) for tipo in tipos
                    ):
                        if intento < config.retries:
                            await asyncio.sleep(random.uniform(0.15, 0.5))
                            continue
                        return resultado_indeterminado(
                            entry,
                            protocolo,
                            f"ip_unavailable+{tipo_web}",
                        )

                    return resultado_dead(
                        entry,
                        protocolo,
                        f"no_ip+{tipo_web}",
                    )

                ip_salida = ips[0]

                ip_consistente = (
                    len(ips) >= 2
                    and len(set(ips)) == 1
                )

                # GEO

                geo = await geolocalizar_ip(

                    ip_salida,

                    geo_client,

                    geo_cache,

                    geo_lock,
                )

                # Google

                google = (
                    await probar_google(
                        client,
                        rate_limiter,
                    )
                )

                # Web HTTPS real.
                # VALID/SLOW exige superar esta prueba; el 204 por sí solo
                # ya no basta para considerar la proxy plenamente funcional.

                web = (
                    await probar_web_real(
                        client,
                        rate_limiter,
                    )
                )

                if not web["ok"]:
                    tipo_web = web.get(
                        "tipo",
                        "web_check_failed",
                    )

                    if (
                        es_error_temporal(tipo_web)
                        and intento < config.retries
                    ):
                        await asyncio.sleep(
                            random.uniform(
                                0.15,
                                0.5,
                            )
                        )
                        continue

                    if es_error_temporal(tipo_web):
                        return resultado_indeterminado(
                            entry,
                            protocolo,
                            tipo_web,
                        )

                    return resultado_dead(
                        entry,
                        protocolo,
                        tipo_web,
                    )

                latencias.append(
                    web["latencia"]
                )

                # Anonimato

                anonimato = (
                    await probar_anonymity(
                        client,
                        rate_limiter,
                        ip_salida,
                    )
                )

                # Estabilidad

                estabilidad = (
                    await comprobar_estabilidad(
                        client,
                        rate_limiter,
                        ip_salida,
                        config,
                    )
                )

                ips.extend(
                    estabilidad[
                        "ips"
                    ]
                )

                latencias.extend(
                    estabilidad[
                        "latencias"
                    ]
                )

                ip_rotatoria = (
                    len(
                        set(ips)
                    ) > 1
                )

                ip_consistente = (
                    len(set(ips)) == 1
                )

                (
                    lat_min,
                    lat_media,
                    lat_max,
                ) = calcular_latencias(
                    latencias
                )

                jitter = (
                    calcular_jitter(
                        latencias
                    )
                )

                score = calcular_score(

                    lat_media,

                    jitter,

                    estabilidad[
                        "estabilidad"
                    ],

                    anonimato[
                        "nivel"
                    ],

                    google["ok"],

                    len(exitosos),
                )

                calidad = (
                    calidad_score(
                        score
                    )
                )

                estado = (
                    "valid"
                    if lat_media
                    <= config.max_latency
                    else "slow"
                )

                detalle = (
                    "OK"
                    if estado
                    == "valid"
                    else "latencia_alta"
                )

                if ip_rotatoria:

                    detalle = (
                        "IP_rotatoria"
                    )

                return {

                    "proxy":
                        entry.proxy,

                    "protocolo":
                        protocolo,

                    "estado":
                        estado,

                    "score":
                        score,

                    "calidad":
                        calidad,

                    "latencias":
                        latencias,

                    "latencia_min":
                        lat_min,

                    "latencia_media":
                        lat_media,

                    "latencia_max":
                        lat_max,

                    "jitter":
                        jitter,

                    "ips":
                        ips,

                    "ip_salida":
                        ip_salida,

                    "ip_consistente":
                        ip_consistente,

                    "ip_rotatoria":
                        ip_rotatoria,

                    "confirmaciones":
                        len(exitosos),

                    "google_ok":
                        google["ok"],

                    "google_tipo":
                        google["tipo"],

                    "web_ok":
                        web["ok"],

                    "web_tipo":
                        web["tipo"],

                    "web_status":
                        web.get("status"),

                    "anonimato":
                        anonimato[
                            "nivel"
                        ],

                    "anonimato_detalle":
                        anonimato[
                            "detalle"
                        ],

                    "pais":
                        geo.get(
                            "pais",
                            "",
                        ),

                    "codigo_pais":
                        geo.get(
                            "codigo_pais",
                            "",
                        ),

                    "region":
                        geo.get(
                            "region",
                            "",
                        ),

                    "ciudad":
                        geo.get(
                            "ciudad",
                            "",
                        ),

                    "isp":
                        geo.get(
                            "isp",
                            "",
                        ),

                    "asn":
                        geo.get(
                            "asn",
                            "",
                        ),

                    "estabilidad":
                        estabilidad[
                            "estabilidad"
                        ],

                    "detalle":
                        detalle,

                    "auth":
                        entry.tiene_auth,

                    "auth_fingerprint":
                        entry.auth_fingerprint,
                }

        except Exception as error:

            nombre_error = type(error).__name__
            mensaje_error = str(error).strip()

            # V7.8.3: conservar la causa real. Antes, un fallo al crear el
            # cliente (especialmente en SOCKS4) terminaba reducido a
            # "ValueError", ocultando el motivo útil para el diagnóstico.
            ultimo = nombre_error
            if mensaje_error:
                ultimo = f"{nombre_error}: {mensaje_error[:180]}"

            # ValueError en esta capa ocurre antes/durante la configuración
            # del cliente y es determinista para la misma combinación
            # proxy/protocolo. Repetir el pipeline completo no lo corrige.
            if isinstance(error, ValueError):
                return resultado_dead(
                    entry,
                    protocolo,
                    ultimo,
                )

            if intento < config.retries:

                await asyncio.sleep(
                    random.uniform(
                        0.2,
                        0.6,
                    )
                )

                continue

            return resultado_dead(
                entry,
                protocolo,
                ultimo,
            )

    return resultado_dead(
        entry,
        protocolo,
        ultimo or "no_confirmado",
    )



# AUTO FULL — modo exhaustivo
async def comprobar_proxy_full(
    entry,
    protocolo,
    rate_limiter,
    geo_client,
    geo_cache,
    geo_lock,
    config,
):

    if protocolo not in PROTOCOLOS:

        return resultado_dead(
            entry,
            protocolo,
            "protocolo_invalido",
        )

    ultimo = None
    historial_fallos = []

    for intento in range(
        config.retries + 1
    ):

        try:

            async with crear_cliente(
                entry,
                protocolo,
                config,
            ) as client:

                # IP

                resultados_ip = (
                    await probar_ips(
                        client,
                        rate_limiter,
                        config,
                    )
                )

                exitosos = [

                    resultado

                    for resultado
                    in resultados_ip

                    if resultado.get(
                        "ok"
                    )
                    and resultado.get(
                        "ip"
                    )
                ]

                ips = [
                    resultado["ip"]
                    for resultado
                    in exitosos
                ]

                latencias = [

                    resultado[
                        "latencia"
                    ]

                    for resultado
                    in exitosos
                ]

                if not exitosos:

                    tipos = [

                        resultado.get(
                            "tipo",
                            "",
                        )

                        for resultado
                        in resultados_ip
                    ]

                    if any(
                        es_error_temporal(
                            tipo
                        )
                        for tipo
                        in tipos
                    ):

                        if intento < config.retries:

                            await asyncio.sleep(
                                random.uniform(
                                    0.15,
                                    0.5,
                                )
                            )

                            continue

                        return resultado_indeterminado(
                            entry,
                            protocolo,
                            tipos[0]
                            if tipos
                            else "sin_ip",
                        )

                    return resultado_dead(
                        entry,
                        protocolo,
                        "no_ip",
                    )

                ip_salida = ips[0]

                ip_consistente = (
                    len(ips) >= 2
                    and len(set(ips)) == 1
                )

                # GEO

                geo = await geolocalizar_ip(

                    ip_salida,

                    geo_client,

                    geo_cache,

                    geo_lock,
                )

                # Google

                google = (
                    await probar_google(
                        client,
                        rate_limiter,
                    )
                )

                # Web HTTPS real.
                # VALID/SLOW exige superar esta prueba; el 204 por sí solo
                # ya no basta para considerar la proxy plenamente funcional.

                web = (
                    await probar_web_real(
                        client,
                        rate_limiter,
                    )
                )

                if not web["ok"]:
                    tipo_web = web.get(
                        "tipo",
                        "web_check_failed",
                    )

                    if (
                        es_error_temporal(tipo_web)
                        and intento < config.retries
                    ):
                        await asyncio.sleep(
                            random.uniform(
                                0.15,
                                0.5,
                            )
                        )
                        continue

                    if es_error_temporal(tipo_web):
                        return resultado_indeterminado(
                            entry,
                            protocolo,
                            tipo_web,
                        )

                    return resultado_dead(
                        entry,
                        protocolo,
                        tipo_web,
                    )

                latencias.append(
                    web["latencia"]
                )

                # Anonimato

                anonimato = (
                    await probar_anonymity(
                        client,
                        rate_limiter,
                        ip_salida,
                    )
                )

                # Estabilidad

                estabilidad = (
                    await comprobar_estabilidad(
                        client,
                        rate_limiter,
                        ip_salida,
                        config,
                    )
                )

                ips.extend(
                    estabilidad[
                        "ips"
                    ]
                )

                latencias.extend(
                    estabilidad[
                        "latencias"
                    ]
                )

                ip_rotatoria = (
                    len(
                        set(ips)
                    ) > 1
                )

                ip_consistente = (
                    len(set(ips)) == 1
                )

                (
                    lat_min,
                    lat_media,
                    lat_max,
                ) = calcular_latencias(
                    latencias
                )

                jitter = (
                    calcular_jitter(
                        latencias
                    )
                )

                score = calcular_score(

                    lat_media,

                    jitter,

                    estabilidad[
                        "estabilidad"
                    ],

                    anonimato[
                        "nivel"
                    ],

                    google["ok"],

                    len(exitosos),
                )

                calidad = (
                    calidad_score(
                        score
                    )
                )

                estado = (
                    "valid"
                    if lat_media
                    <= config.max_latency
                    else "slow"
                )

                detalle = (
                    "OK"
                    if estado
                    == "valid"
                    else "latencia_alta"
                )

                if ip_rotatoria:

                    detalle = (
                        "IP_rotatoria"
                    )

                return {

                    "proxy":
                        entry.proxy,

                    "protocolo":
                        protocolo,

                    "estado":
                        estado,

                    "score":
                        score,

                    "calidad":
                        calidad,

                    "latencias":
                        latencias,

                    "latencia_min":
                        lat_min,

                    "latencia_media":
                        lat_media,

                    "latencia_max":
                        lat_max,

                    "jitter":
                        jitter,

                    "ips":
                        ips,

                    "ip_salida":
                        ip_salida,

                    "ip_consistente":
                        ip_consistente,

                    "ip_rotatoria":
                        ip_rotatoria,

                    "confirmaciones":
                        len(exitosos),

                    "google_ok":
                        google["ok"],

                    "google_tipo":
                        google["tipo"],

                    "web_ok":
                        web["ok"],

                    "web_tipo":
                        web["tipo"],

                    "web_status":
                        web.get("status"),

                    "anonimato":
                        anonimato[
                            "nivel"
                        ],

                    "anonimato_detalle":
                        anonimato[
                            "detalle"
                        ],

                    "pais":
                        geo.get(
                            "pais",
                            "",
                        ),

                    "codigo_pais":
                        geo.get(
                            "codigo_pais",
                            "",
                        ),

                    "region":
                        geo.get(
                            "region",
                            "",
                        ),

                    "ciudad":
                        geo.get(
                            "ciudad",
                            "",
                        ),

                    "isp":
                        geo.get(
                            "isp",
                            "",
                        ),

                    "asn":
                        geo.get(
                            "asn",
                            "",
                        ),

                    "estabilidad":
                        estabilidad[
                            "estabilidad"
                        ],

                    "detalle":
                        detalle,

                    "auth":
                        entry.tiene_auth,

                    "auth_fingerprint":
                        entry.auth_fingerprint,
                }

        except Exception as error:

            nombre_error = type(error).__name__
            mensaje_error = str(error).strip()

            # V7.8.3: conservar la causa real. Antes, un fallo al crear el
            # cliente (especialmente en SOCKS4) terminaba reducido a
            # "ValueError", ocultando el motivo útil para el diagnóstico.
            ultimo = nombre_error
            if mensaje_error:
                ultimo = f"{nombre_error}: {mensaje_error[:180]}"

            # ValueError en esta capa ocurre antes/durante la configuración
            # del cliente y es determinista para la misma combinación
            # proxy/protocolo. Repetir el pipeline completo no lo corrige.
            if isinstance(error, ValueError):
                return resultado_dead(
                    entry,
                    protocolo,
                    ultimo,
                )

            if protocolo == "socks4" and "transport unavailable" in mensaje_error.lower():
                return resultado_indeterminado(
                    entry, protocolo, "local_protocol_error: SOCKS4 transport unavailable"
                )

            historial_fallos.append(ultimo)

            if es_fallo_local_o_externo(ultimo):
                return resultado_indeterminado(entry, protocolo, ultimo)

            if es_fallo_protocolo_claro(ultimo):
                return resultado_dead(entry, protocolo, ultimo)

            if intento < config.retries:

                await asyncio.sleep(
                    random.uniform(
                        0.2,
                        0.6,
                    )
                )

                continue

            decision = decidir_fallo_final(historial_fallos, ultimo)
            if decision == "dead":
                return resultado_dead(entry, protocolo, ultimo)
            return resultado_indeterminado(entry, protocolo, ultimo)

    return resultado_indeterminado(
        entry,
        protocolo,
        ultimo or "no_confirmado",
    )


# CARGAR PROXIES

def cargar_proxies(ruta):

    print()

    print(
        color(
            "[+] Leyendo lista..."
            if LANGUAGE == "es"
            else "[+] Reading proxy list...",
            CYAN,
        )
    )

    entradas = []
    invalidas = 0

    with open(
        ruta,
        "r",
        encoding="utf-8",
        errors="ignore",
    ) as archivo:

        for linea in archivo:

            if (
                not linea.strip()
                or linea.strip().startswith("#")
            ):
                continue

            entry = parsear_proxy(
                linea
            )

            if entry:

                entradas.append(
                    entry
                )

            else:

                invalidas += 1

    originales = len(
        entradas
    )

    entradas = list(
        dict.fromkeys(
            entradas
        )
    )

    duplicados = (
        originales
        - len(entradas)
    )

    print(
        f"{color('[+]', GREEN)} "
        + (
            f"Entradas válidas: {originales:,}"
            if LANGUAGE == "es"
            else f"Valid entries: {originales:,}"
        )
    )

    print(
        f"{color('[+]', GREEN)} "
        + (
            f"Únicas: {len(entradas):,}"
            if LANGUAGE == "es"
            else f"Unique: {len(entradas):,}"
        )
    )

    print(
        f"{color('[+]', GREEN)} "
        + (
            f"Duplicados eliminados: {duplicados:,}"
            if LANGUAGE == "es"
            else f"Duplicates removed: {duplicados:,}"
        )
    )

    print(
        f"{color('[+]', YELLOW)} "
        + (
            f"Líneas inválidas: {invalidas:,}"
            if LANGUAGE == "es"
            else f"Invalid lines: {invalidas:,}"
        )
    )

    return entradas


# AGRUPAR

def agrupar_entradas(
    entradas
):

    grupos = {
        protocolo: []
        for protocolo
        in PROTOCOLOS
    }

    sin_protocolo = []

    for entry in entradas:

        if entry.protocolo in PROTOCOLOS:

            grupos[
                entry.protocolo
            ].append(entry)

        else:

            sin_protocolo.append(
                entry
            )

    return (
        grupos,
        sin_protocolo,
    )


# RESUME

RESUME_AUTH_FILE = ".resume_auth.txt"


def guardar_resume_auth(carpeta, resultado):
    """Guarda solo la identidad técnica necesaria para Resume de proxies con auth."""
    if not resultado.get("auth"):
        return
    auth_id = str(resultado.get("auth_fingerprint", "")).strip()
    proxy = str(resultado.get("proxy", "")).strip()
    protocolo = str(resultado.get("protocolo", "")).lower().strip()
    if not auth_id or not proxy or protocolo not in PROTOCOLOS:
        return
    ruta = os.path.join(carpeta, RESUME_AUTH_FILE)
    with open(ruta, "a", encoding="utf-8") as archivo:
        archivo.write(f"{proxy}|{protocolo}|{auth_id}\n")


def cargar_resume_auth(carpeta):
    procesados = set()
    ruta = os.path.join(carpeta, RESUME_AUTH_FILE)
    if not os.path.isfile(ruta):
        return procesados
    try:
        with open(ruta, "r", encoding="utf-8", errors="ignore") as archivo:
            for linea in archivo:
                partes = [parte.strip() for parte in linea.strip().split("|")]
                if len(partes) != 3:
                    continue
                proxy, protocolo, auth_id = partes
                if proxy and protocolo in PROTOCOLOS and auth_id:
                    procesados.add((proxy, protocolo, auth_id))
    except OSError:
        pass
    return procesados


def cargar_procesados(
    carpeta
):

    procesados = set()

    for nombre in (
        "validos.txt",
        "lentos.txt",
        "muertos.txt",
        "indeterminados.txt",
    ):

        ruta = os.path.join(
            carpeta,
            nombre,
        )

        if not os.path.isfile(
            ruta
        ):
            continue

        try:

            with open(
                ruta,
                "r",
                encoding="utf-8",
                errors="ignore",
            ) as archivo:

                for linea in archivo:

                    partes = [
                        parte.strip()
                        for parte
                        in linea.split("|")
                    ]

                    if len(partes) < 2:
                        continue

                    proxy = partes[0]

                    protocolo = (
                        partes[1]
                        .lower()
                    )

                    if protocolo not in PROTOCOLOS:
                        continue

                    auth_id = next(
                        (
                            parte.split(
                                "=",
                                1,
                            )[1]

                            for parte
                            in partes

                            if parte.startswith(
                                "AUTHID="
                            )
                        ),
                        "NOAUTH",
                    )

                    procesados.add(
                        (
                            proxy,
                            protocolo,
                            auth_id,
                        )
                    )

        except OSError:
            pass

    procesados.update(cargar_resume_auth(carpeta))
    return procesados


def clave_procesado(
    entry,
    protocolo,
):

    return (
        entry.proxy,
        protocolo,
        entry.auth_fingerprint,
    )


# TAREAS

def construir_tareas(
    entradas,
    modo,
    procesados,
):

    tareas = []

    grupos, sin_protocolo = (
        agrupar_entradas(
            entradas
        )
    )

    def agregar(
        entry,
        protocolo,
    ):

        clave = clave_procesado(
            entry,
            protocolo,
        )

        if clave not in procesados:

            tareas.append(
                (
                    entry,
                    protocolo,
                )
            )

    if modo not in {"auto", "auto_full"}:

        for entry in entradas:

            if (
                entry.protocolo
                and
                entry.protocolo != modo
            ):
                continue

            agregar(
                entry,
                modo,
            )

        return tareas

    if modo == "auto":
        # AUTO real: una unidad lógica por proxy. Dentro de la unidad se
        # comprueban solo los protocolos que aún no figuran en Resume.
        # El resultado puede conservar más de un protocolo funcional.
        for entry in entradas:
            protocolos_pendientes = tuple(
                protocolo
                for protocolo in PROTOCOLOS
                if clave_procesado(entry, protocolo) not in procesados
            )
            if protocolos_pendientes:
                tareas.append((entry, protocolos_pendientes))
        return tareas

    # AUTO FULL permanece exhaustivo: cada combinación proxy/protocolo es
    # una tarea independiente y visible.
    for entry in entradas:
        for protocolo in PROTOCOLOS:
            agregar(entry, protocolo)

    return tareas


# FORMATO DE RESULTADOS

def formatear_resultado(resultado):
    estado = str(resultado.get("estado", "")).upper()
    partes = [
        resultado["proxy"],
        resultado["protocolo"].upper(),
        estado,
    ]

    # Para proxies confirmados mostramos solo la información útil disponible.
    if estado in {"VALID", "SLOW"}:
        score = resultado.get("score")
        calidad = resultado.get("calidad", "")
        if score is not None:
            score_texto = f"SCORE={score}"
            if calidad and calidad != "UNKNOWN":
                score_texto += f" {calidad}"
            partes.append(score_texto)

        latencia = resultado.get("latencia_media", 0)
        if latencia and latencia > 0:
            partes.append(f"PING={latencia * 1000:.0f}ms")
            partes.append(f"LAT={latencia:.2f}s")

        ip = resultado.get("ip_salida")
        if ip:
            partes.append(f"IP={ip}")

        pais = resultado.get("codigo_pais", "")
        ciudad = resultado.get("ciudad", "")
        ubicacion = "/".join(valor for valor in (pais, ciudad) if valor)
        if ubicacion:
            partes.append(ubicacion)

        isp = resultado.get("isp")
        if isp:
            partes.append(f"ISP={isp}")

        anonimato = resultado.get("anonimato", "UNKNOWN")
        if anonimato and anonimato != "UNKNOWN":
            partes.append(f"ANON={anonimato}")

        if resultado.get("ip_rotatoria"):
            partes.append("ROTATING")

    else:
        # En DEAD/INDET el diagnóstico aporta más que campos vacíos.
        detalle = str(resultado.get("detalle", "")).strip()
        if detalle and detalle.lower() not in {"ok", "no_confirmado", "servicio_temporal"}:
            partes.append(detalle)

    return " | ".join(partes)


# GUARDAR TXT

def guardar_resultado(archivo, resultado):
    archivo.write(formatear_resultado(resultado) + "\n\n")
    archivo.flush()


def formatear_proxy_por_protocolo(resultado):
    """Devuelve una URL de proxy reutilizable según el protocolo confirmado."""
    protocolo = str(resultado.get("protocolo", "")).lower().strip()
    proxy = str(resultado.get("proxy", "")).strip()
    if protocolo not in PROTOCOLOS or not proxy:
        return None
    return f"{protocolo}://{proxy}"


def guardar_proxy_por_protocolo(archivos_protocolo, resultado):
    """Guarda únicamente proxies funcionales (VALID/SLOW) por protocolo."""
    if resultado.get("estado") not in {"valid", "slow"}:
        return
    protocolo = str(resultado.get("protocolo", "")).lower()
    archivo = archivos_protocolo.get(protocolo)
    linea = formatear_proxy_por_protocolo(resultado)
    if archivo is None or not linea:
        return
    archivo.write(linea + "\n")
    archivo.flush()


# MOSTRAR RESULTADO

def mostrar_resultado(resultado):
    estado = resultado["estado"]
    configuracion = {
        "valid": ("✓", GREEN, "VALID"),
        "slow": ("~", YELLOW, "SLOW"),
        "indeterminate": ("?", MAGENTA, "INDET"),
        "dead": ("×", RED, "DEAD"),
    }
    simbolo, codigo, etiqueta = configuracion.get(estado, ("?", WHITE, estado.upper()))
    linea = formatear_resultado(resultado)
    # Mantiene exactamente el contenido del resultado, pero hace más visible
    # el estado en terminal. Los TXT/JSON permanecen sin códigos ANSI.
    print(f"\n{color(f'[{simbolo}]', codigo)} {color(etiqueta, codigo)} {color('│', CYAN)} {linea}")


# ARCHIVOS

def abrir_archivos(
    carpeta
):

    os.makedirs(
        carpeta,
        exist_ok=True,
    )

    nombres = {
        "valid": "validos.txt",
        "slow": "lentos.txt",
        "dead": "muertos.txt",
        "indeterminate": "indeterminados.txt",
    }

    paths = {
        estado: os.path.join(carpeta, nombre)
        for estado, nombre in nombres.items()
    }

    archivos = {
        estado: open(ruta, "a", encoding="utf-8")
        for estado, ruta in paths.items()
    }

    return archivos, paths


def abrir_archivos_protocolos(carpeta):
    """Crea results/protocolos/{http,https,socks4,socks5}.txt."""
    carpeta_protocolos = os.path.join(carpeta, "protocolos")
    os.makedirs(carpeta_protocolos, exist_ok=True)
    paths = {
        protocolo: os.path.join(carpeta_protocolos, f"{protocolo}.txt")
        for protocolo in PROTOCOLOS
    }
    archivos = {
        protocolo: open(ruta, "a", encoding="utf-8")
        for protocolo, ruta in paths.items()
    }
    return archivos, paths


# RESUMEN JSON eliminado: resumen.txt es el resumen humano principal.

# ESTADÍSTICAS

async def procesar_resultado(
    resultado,
    archivos,
    archivos_protocolo=None,
    carpeta_resume=None,
    auto_full=False,
):

    async with stats_lock:

        stats["tested"] += 1

        estado = resultado[
            "estado"
        ]

        if estado == "valid":

            stats["valid"] += 1

        elif estado == "slow":

            stats["slow"] += 1

        elif estado == "indeterminate":

            stats[
                "indeterminate"
            ] += 1

        else:

            stats["dead"] += 1

        calidad = resultado.get(
            "calidad",
            "",
        )

        if calidad == "EXCELLENT":
            stats["excellent"] += 1

        elif calidad == "GOOD":
            stats["good"] += 1

        elif calidad == "FAIR":
            stats["fair"] += 1

        elif calidad in (
            "POOR",
            "VERY_POOR",
        ):
            stats["poor"] += 1

        protocolo = str(resultado.get("protocolo", "")).lower()
        if protocolo in stats["protocols"]:
            stats["protocols"][protocolo]["tested"] += 1
            if estado in stats["protocols"][protocolo]:
                stats["protocols"][protocolo][estado] += 1

        if estado in {"dead", "indeterminate"}:
            categoria = categoria_fallo(resultado.get("detalle", ""))
            stats["failure_reasons"][categoria] = (
                stats["failure_reasons"].get(categoria, 0) + 1
            )

    guardar_resultado(
        archivos[estado],
        resultado,
    )

    if archivos_protocolo:
        guardar_proxy_por_protocolo(
            archivos_protocolo,
            resultado,
        )

    if carpeta_resume:
        guardar_resume_auth(carpeta_resume, resultado)

    mostrar_resultado(
        resultado
    )


# DIAGNÓSTICO / MÉTRICAS DE SESIÓN

def categoria_fallo(detalle):
    """Agrupa detalles técnicos sin alterar la línea estándar de resultados."""
    texto = str(detalle or "").lower()
    if "auth" in texto or "407" in texto:
        return "AUTH"
    if "tls" in texto or "ssl" in texto or "certificate" in texto:
        return "TLS"
    if "timeout" in texto or "timed out" in texto:
        return "TIMEOUT"
    if "connect" in texto or "proxy_error" in texto:
        return "CONNECT"
    if "content" in texto or "no_body" in texto or "no_ip" in texto:
        return "CONTENT"
    if "http" in texto or "status" in texto:
        return "HTTP"
    if "rate" in texto or "service_unavailable" in texto:
        return "SERVICE"
    if (
        "valueerror" in texto
        or "unknown scheme" in texto
        or "unsupported protocol" in texto
        or "unsupported scheme" in texto
        or "protocol_error" in texto
    ):
        return "PROTOCOL"
    return "OTHER"


# PROGRESO

def formato_tiempo(
    segundos
):

    segundos = max(
        0,
        int(segundos),
    )

    horas, resto = divmod(
        segundos,
        3600,
    )

    minutos, segundos = (
        divmod(
            resto,
            60,
        )
    )

    return (
        f"{horas:02d}:"
        f"{minutos:02d}:"
        f"{segundos:02d}"
    )


async def mostrar_progreso(
    total
):

    async with stats_lock:

        procesados = stats[
            "tested"
        ]

        transcurrido = (
            time.perf_counter()
            - stats[
                "start_time"
            ]
        )

        velocidad = (
            procesados / transcurrido
            if transcurrido > 0
            else 0
        )

        ahora_muestra = time.perf_counter()
        muestras = stats["speed_samples"]
        muestras.append((ahora_muestra, procesados))
        # Ventana reciente de hasta 60 s; suficiente para estabilizar NOW sin
        # conservar historial ilimitado.
        limite = ahora_muestra - 60.0
        while len(muestras) > 2 and muestras[0][0] < limite:
            muestras.pop(0)

        velocidad_reciente = velocidad
        if len(muestras) >= 2:
            dt = muestras[-1][0] - muestras[0][0]
            dn = muestras[-1][1] - muestras[0][1]
            if dt > 0 and dn >= 0:
                velocidad_reciente = dn / dt

        restantes = max(0, total - procesados)

        # ETA suavizada: al inicio prima el promedio global; después combina
        # el ritmo reciente con el promedio para evitar saltos bruscos.
        if velocidad > 0 and velocidad_reciente > 0:
            velocidad_eta = (velocidad * 0.40) + (velocidad_reciente * 0.60)
        else:
            velocidad_eta = velocidad or velocidad_reciente

        eta = (
            restantes / velocidad_eta
            if velocidad_eta > 0
            else 0
        )

        porcentaje = (

            procesados
            / total
            * 100

            if total
            else 0
        )


        ok = color(
            f"OK {stats['valid']:,}",
            GREEN
        )

        slow = color(
            f"SLOW {stats['slow']:,}",
            YELLOW
        )

        dead = color(
            f"DEAD {stats['dead']:,}",
            RED
        )

        indet = color(
            f"INDET {stats['indeterminate']:,}",
            MAGENTA
        )

        porcentaje_color = color(
            f"[{porcentaje:6.2f}%]",
            CYAN
        )

        texto = (
            f"\r{porcentaje_color} "
            f"{procesados:,}/{total:,} TESTS | "
            f"{ok} | "
            f"{slow} | "
            f"{dead} | "
            f"{indet} | "
            f"NOW {velocidad_reciente:.2f}/s | "
            f"AVG {velocidad:.2f}/s | "
            f"ETA {formato_tiempo(eta)}"
        )

        print(
            texto,
            end="",
            flush=True
        )


# PROCESAMIENTO

def _prioridad_estado_auto(resultado):
    return {"valid": 4, "slow": 3, "indeterminate": 2, "dead": 1}.get(
        resultado.get("estado", "dead"), 0
    )


async def comprobar_proxy_auto(
    entry,
    protocolos,
    rate_limiter,
    geo_client,
    geo_cache,
    geo_lock,
    config,
):
    """Una unidad AUTO por proxy, conservando detección multiprotocolo.

    Las ramas comparten el limitador global y se ejecutan concurrentemente.
    No se considera LIVE por detección: cada rama pasa por comprobar_proxy,
    incluyendo HTTPS real y sus validaciones.
    """
    trabajos = [
        asyncio.create_task(
            comprobar_proxy(
                entry, protocolo, rate_limiter, geo_client,
                geo_cache, geo_lock, config
            )
        )
        for protocolo in protocolos
    ]
    try:
        resultados = await asyncio.gather(*trabajos, return_exceptions=True)
    finally:
        for task in trabajos:
            if not task.done():
                task.cancel()
        await asyncio.gather(*trabajos, return_exceptions=True)

    normalizados = []
    for protocolo, resultado in zip(protocolos, resultados):
        if isinstance(resultado, BaseException):
            detalle = f"{type(resultado).__name__}: {str(resultado)[:180]}"
            normalizados.append(resultado_indeterminado(entry, protocolo, detalle))
        else:
            normalizados.append(resultado)

    return normalizados


async def procesar_resultados_auto(
    resultados, archivos, archivos_protocolo=None, carpeta_resume=None
):
    """Guarda todas las ramas, pero cuenta una sola unidad AUTO por proxy."""
    if not resultados:
        return

    mejor = max(resultados, key=_prioridad_estado_auto)

    async with stats_lock:
        stats["tested"] += 1
        estado_mejor = mejor.get("estado", "dead")
        if estado_mejor == "valid":
            stats["valid"] += 1
        elif estado_mejor == "slow":
            stats["slow"] += 1
        elif estado_mejor == "indeterminate":
            stats["indeterminate"] += 1
        else:
            stats["dead"] += 1

        calidad = mejor.get("calidad", "")
        if calidad == "EXCELLENT": stats["excellent"] += 1
        elif calidad == "GOOD": stats["good"] += 1
        elif calidad == "FAIR": stats["fair"] += 1
        elif calidad in ("POOR", "VERY_POOR"): stats["poor"] += 1

        for resultado in resultados:
            protocolo = str(resultado.get("protocolo", "")).lower()
            estado = resultado.get("estado", "dead")
            if protocolo in stats["protocols"]:
                stats["protocols"][protocolo]["tested"] += 1
                if estado in stats["protocols"][protocolo]:
                    stats["protocols"][protocolo][estado] += 1
            if estado in {"dead", "indeterminate"}:
                categoria = categoria_fallo(resultado.get("detalle", ""))
                stats["failure_reasons"][categoria] = (
                    stats["failure_reasons"].get(categoria, 0) + 1
                )

    # Guardamos cada protocolo para que Continue sepa exactamente qué ramas
    # ya fueron comprobadas y para mantener los TXT por protocolo.
    for resultado in resultados:
        guardar_resultado(archivos[resultado["estado"]], resultado)
        if archivos_protocolo:
            guardar_proxy_por_protocolo(archivos_protocolo, resultado)
        if carpeta_resume:
            guardar_resume_auth(carpeta_resume, resultado)
        mostrar_resultado(resultado)


async def procesar_tareas(
    tareas,
    archivos,
    config,
    archivos_protocolo=None,
    carpeta_resume=None,
    auto_full=False,
):

    semaphore = asyncio.Semaphore(
        config.workers
    )

    total = len(
        tareas
    )

    geo_cache = {}
    geo_lock = asyncio.Lock()

    rate_limiter = RateLimiter(
        config.rate
    )

    geo_client = httpx.AsyncClient(
        timeout=5.0,
        trust_env=False,
    )

    async def worker(
        entry,
        protocolo,
    ):

        async with semaphore:

            if isinstance(protocolo, (tuple, list)):
                return await comprobar_proxy_auto(
                    entry, protocolo, rate_limiter, geo_client,
                    geo_cache, geo_lock, config
                )

            checker = comprobar_proxy_full if auto_full else comprobar_proxy
            return await checker(
                entry, protocolo, rate_limiter, geo_client, geo_cache,
                geo_lock, config
            )

    max_pending = max(
        config.workers,
        config.workers
        * PENDING_FACTOR,
    )

    indice = 0

    pendientes = set()

    metadata = {}

    try:

        while (
            indice < len(tareas)
            or pendientes
        ):

            while (

                indice < len(tareas)

                and
                len(pendientes)
                < max_pending

            ):

                entry, protocolo = (
                    tareas[indice]
                )

                task = asyncio.create_task(

                    worker(
                        entry,
                        protocolo,
                    )
                )

                pendientes.add(
                    task
                )

                metadata[task] = (
                    entry,
                    protocolo,
                )

                indice += 1

            if not pendientes:
                break

            completadas, pendientes = (
                await asyncio.wait(

                    pendientes,

                    return_when=
                        asyncio.FIRST_COMPLETED,
                )
            )

            for task in completadas:

                datos = metadata.pop(
                    task,
                    None,
                )

                if datos is None:
                    continue

                entry, protocolo = (
                    datos
                )

                try:

                    resultado = (
                        task.result()
                    )

                except Exception as error:

                    detalle = type(error).__name__

                    mensaje = str(error).strip()

                    if mensaje:
                        detalle = (
                            f"{detalle}: "
                            f"{mensaje[:180]}"
                        )

                    resultado = (
                        resultado_dead(
                            entry,
                            protocolo,
                            detalle,
                        )
                    )

                if isinstance(resultado, list):
                    await procesar_resultados_auto(
                        resultado, archivos, archivos_protocolo, carpeta_resume
                    )
                else:
                    await procesar_resultado(
                        resultado, archivos, archivos_protocolo, carpeta_resume
                    )

                async with stats_lock:

                    procesados = (
                        stats["tested"]
                    )

                if (

                    procesados
                    % 25 == 0

                    or

                    procesados == total

                ):

                    await mostrar_progreso(
                        total
                    )

    finally:
        # Cierre cooperativo: no dejamos workers vivos cuando termina el scan
        # o cuando asyncio cancela main_async (por ejemplo, Ctrl+C).
        tareas_vivas = [task for task in pendientes if not task.done()]
        for task in tareas_vivas:
            task.cancel()

        if tareas_vivas:
            await asyncio.gather(*tareas_vivas, return_exceptions=True)

        # Consumir también cualquier excepción de tareas ya finalizadas que
        # todavía permanezcan en el conjunto local.
        terminadas = [task for task in pendientes if task.done()]
        if terminadas:
            await asyncio.gather(*terminadas, return_exceptions=True)

        await geo_client.aclose()
        # Cede un ciclo al backend async para completar callbacks de cierre
        # antes de que asyncio.run destruya el event loop.
        await asyncio.sleep(0)

    print()


# CONFIG JSON

def cargar_config(
    ruta
):
    config = Config()

    if not os.path.isfile(ruta):
        return config

    try:
        with open(ruta, "r", encoding="utf-8") as archivo:
            data = json.load(archivo)

        if not isinstance(data, dict):
            raise ValueError("config.json debe contener un objeto JSON")

        def entero(nombre, actual, minimo, maximo):
            valor = data.get(nombre, actual)
            if isinstance(valor, bool):
                raise ValueError(f"{nombre} debe ser un entero")
            valor = int(valor)
            return max(minimo, min(maximo, valor))

        def numero(nombre, actual, minimo, maximo):
            valor = data.get(nombre, actual)
            if isinstance(valor, bool):
                raise ValueError(f"{nombre} debe ser numérico")
            valor = float(valor)
            return max(minimo, min(maximo, valor))

        config.workers = entero("workers", config.workers, 1, 500)
        config.timeout = numero("timeout", config.timeout, 0.5, 120.0)
        config.connect_timeout = numero(
            "connect_timeout", config.connect_timeout, 0.1, config.timeout
        )
        config.retries = entero("retries", config.retries, 0, 10)
        config.max_latency = numero("max_latency", config.max_latency, 0.1, 120.0)
        config.rate = numero("rate", config.rate, 0.1, 1000.0)
        config.jitter_min = numero("jitter_min", config.jitter_min, 0.0, 10.0)
        config.jitter_max = numero("jitter_max", config.jitter_max, 0.0, 10.0)
        if config.jitter_max < config.jitter_min:
            config.jitter_min, config.jitter_max = config.jitter_max, config.jitter_min
        config.stability_tests = entero(
            "stability_tests", config.stability_tests, 1, 20
        )
        config.min_ip_confirmations = entero(
            "min_ip_confirmations", config.min_ip_confirmations, 1, 3
        )

        valor_third = data.get("third_ip_check", config.third_ip_check)
        if isinstance(valor_third, bool):
            config.third_ip_check = valor_third
        elif isinstance(valor_third, (int, float)) and valor_third in (0, 1):
            config.third_ip_check = bool(valor_third)
        else:
            raise ValueError("third_ip_check debe ser true/false")

    except Exception as error:
        print(
            color(
                (
                    f"[!] Config inválida; se usarán valores seguros: {error}"
                    if LANGUAGE == "es"
                    else f"[!] Invalid config; safe values will be used: {error}"
                ),
                YELLOW,
            )
        )
        config = Config()

    return config

def guardar_config(
    ruta,
    config,
):

    with open(
        ruta,
        "w",
        encoding="utf-8",
    ) as archivo:

        json.dump(
            asdict(config),
            archivo,
            indent=4,
            ensure_ascii=False,
        )


# PERFILES

def aplicar_perfil(
    config,
    perfil,
):

    if perfil == "fast":

        config.workers = 75
        config.rate = 35
        config.timeout = 6
        config.connect_timeout = 3
        config.retries = 1
        config.stability_tests = 2

    elif perfil == "conservative":

        config.workers = 25
        config.rate = 10
        config.timeout = 10
        config.connect_timeout = 5
        config.retries = 3
        config.stability_tests = 3

    elif perfil == "normal":

        config.workers = 50
        config.rate = 20
        config.timeout = 8
        config.connect_timeout = 4
        config.retries = 2
        config.stability_tests = 3

    config.workers = max(
        1,
        min(
            500,
            int(config.workers),
        ),
    )

    config.rate = max(
        0.1,
        float(config.rate),
    )

    config.timeout = max(
        1,
        float(config.timeout),
    )

    config.connect_timeout = max(
        1,
        float(
            config.connect_timeout
        ),
    )

    config.retries = max(
        0,
        int(config.retries),
    )

    return config


# ARCHIVO

ARCHIVOS_RESULTADO = {
    "validos.txt",
    "lentos.txt",
    "muertos.txt",
    "indeterminados.txt",
}


def formatear_tamano(
    tamano
):

    unidades = (
        "B",
        "KB",
        "MB",
        "GB",
        "TB",
    )

    valor = float(
        tamano
    )

    for unidad in unidades:

        if valor < 1024:

            return (
                f"{valor:.2f} "
                f"{unidad}"
            )

        valor /= 1024

    return (
        f"{valor:.2f} TB"
    )


def obtener_contenido_carpeta(
    carpeta
):

    carpetas = []
    archivos = []

    try:

        for nombre in os.listdir(
            carpeta
        ):

            ruta = os.path.join(
                carpeta,
                nombre,
            )

            if os.path.isdir(
                ruta
            ):

                carpetas.append(
                    ruta
                )

                continue

            if not os.path.isfile(
                ruta
            ):
                continue

            if not nombre.lower().endswith(
                ".txt"
            ):
                continue

            if nombre.lower() in (
                ARCHIVOS_RESULTADO
            ):
                continue

            archivos.append(
                ruta
            )

    except OSError:

        return [], []

    carpetas.sort(
        key=lambda ruta:
            os.path.basename(
                ruta
            ).lower()
    )

    archivos.sort(
        key=lambda ruta:
            os.path.basename(
                ruta
            ).lower()
    )

    return (
        carpetas,
        archivos,
    )


def buscar_y_seleccionar_txt():

    carpeta = os.path.join(
        os.path.expanduser("~"),
        "Desktop",
    )

    if not os.path.isdir(
        carpeta
    ):

        carpeta = os.getcwd()

    while True:

        carpetas, archivos = (
            obtener_contenido_carpeta(
                carpeta
            )
        )

        print()

        print(
            color(
                "╔════════════════════════════════════════════════════════════╗",
                BLUE,
            )
        )

        print(
            color(
                "║                 📁 EXPLORADOR V7                         ║",
                BLUE,
            )
        )

        print(
            color(
                "╠════════════════════════════════════════════════════════════╣",
                BLUE,
            )
        )

        print(
            f"║ 📂 {carpeta}"
        )

        print(
            color(
                "╠════════════════════════════════════════════════════════════╣",
                BLUE,
            )
        )

        posiciones = {}

        indice = 1

        for ruta in carpetas:

            nombre = os.path.basename(
                ruta
            )

            print(
                f"║ [{indice:2}] 📁 {nombre}"
            )

            posiciones[
                indice
            ] = (
                "carpeta",
                ruta,
            )

            indice += 1

        for ruta in archivos:

            nombre = os.path.basename(
                ruta
            )

            try:

                tamano = (
                    formatear_tamano(
                        os.path.getsize(
                            ruta
                        )
                    )
                )

            except OSError:

                tamano = "?"

            print(
                f"║ [{indice:2}] 📄 "
                f"{nombre:<38} "
                f"{tamano:>10}"
            )

            posiciones[
                indice
            ] = (
                "archivo",
                ruta,
            )

            indice += 1

        if not posiciones:

            print(
                color(
                    "║ No hay elementos compatibles.                           ║",
                    YELLOW,
                )
            )

        print(
            color(
                "╠════════════════════════════════════════════════════════════╣",
                BLUE,
            )
        )

        print(
            "║ [..] Volver                                             ║"
        )

        print(
            "║ [0]  Cancelar                                           ║"
        )

        print(
            color(
                "╚════════════════════════════════════════════════════════════╝",
                BLUE,
            )
        )

        opcion = input(
            "\nSelecciona: "
        ).strip()

        if opcion == "0":
            return None

        if opcion == "..":

            padre = os.path.dirname(
                carpeta
            )

            if padre != carpeta:

                carpeta = padre

            continue

        try:

            indice = int(
                opcion
            )

        except ValueError:

            print(
                color(
                    "[!] Opción inválida.",
                    RED,
                )
            )

            continue

        seleccion = posiciones.get(
            indice
        )

        if not seleccion:

            print(
                color(
                    "[!] Selección inválida.",
                    RED,
                )
            )

            continue

        tipo, ruta = (
            seleccion
        )

        if tipo == "carpeta":

            carpeta = ruta

            continue

        print(
            color(
                "\n[✓] Archivo seleccionado:",
                GREEN,
            )
        )

        print(
            ruta
        )

        return ruta


def seleccionar_proxy_local():
    """Selecciona un TXT de la carpeta 'proxies' ubicada junto al .py."""
    base = os.path.dirname(os.path.abspath(__file__))
    carpeta = os.path.join(base, "proxies")

    if not os.path.isdir(carpeta):
        mensaje = (
            "[!] No existe la carpeta 'proxies' junto al programa."
            if LANGUAGE == "es"
            else "[!] The 'proxies' folder does not exist next to the program."
        )
        print(color(mensaje, YELLOW))
        print(
            f"    {'Esperada en' if LANGUAGE == 'es' else 'Expected at'}: "
            f"{carpeta}"
        )
        return None

    try:
        archivos = sorted(
            (
                nombre for nombre in os.listdir(carpeta)
                if nombre.lower().endswith(".txt")
                and os.path.isfile(os.path.join(carpeta, nombre))
            ),
            key=str.lower,
        )
    except OSError as error:
        mensaje = (
            f"[!] No se pudo abrir la carpeta proxies: {error}"
            if LANGUAGE == "es"
            else f"[!] Could not open the proxies folder: {error}"
        )
        print(color(mensaje, RED))
        return None

    if not archivos:
        mensaje = (
            "[!] La carpeta 'proxies' no contiene archivos .txt."
            if LANGUAGE == "es"
            else "[!] The 'proxies' folder contains no .txt files."
        )
        print(color(mensaje, YELLOW))
        return None

    while True:
        titulo = "PROXIES LOCALES" if LANGUAGE == "es" else "LOCAL PROXIES"
        volver = "Volver" if LANGUAGE == "es" else "Back"
        prompt = "Selecciona el TXT:" if LANGUAGE == "es" else "Select the TXT file:"

        print()
        print(color("╔════════════════════════════════════════════════════════════╗", CYAN))
        print(color(f"║ {titulo:^58} ║", CYAN))
        print(color("╠════════════════════════════════════════════════════════════╣", CYAN))
        print(f"║ 📂 {carpeta}")
        print(color("╠════════════════════════════════════════════════════════════╣", CYAN))

        for indice, nombre in enumerate(archivos, 1):
            print(f"║ [{indice:2}] 📄 {nombre}")

        print(color("╠════════════════════════════════════════════════════════════╣", CYAN))
        print(f"  [0] {volver}")
        print(color("╚════════════════════════════════════════════════════════════╝", CYAN))

        opcion = input(f"\n{prompt}\n> ").strip()
        if opcion == "0":
            return None

        try:
            indice = int(opcion)
        except ValueError:
            print(color(
                "[!] Opción inválida." if LANGUAGE == "es" else "[!] Invalid option.",
                RED,
            ))
            continue

        if 1 <= indice <= len(archivos):
            return os.path.join(carpeta, archivos[indice - 1])

        print(color(
            "[!] Selección inválida." if LANGUAGE == "es" else "[!] Invalid selection.",
            RED,
        ))

def seleccionar_archivo(*_args, **_kwargs):
    while True:
        if LANGUAGE == "es":
            formatos = (
                "FORMATOS ACEPTADOS:\n"
                "  hostname:port | ip:port\n"
                "  hostname:port:user:pass | ip:port:user:pass\n"
                "  user:pass:hostname:port | user:pass:ip:port\n"
                "PROTOCOLOS COMPATIBLES:\n"
                "  HTTP | HTTPS | SOCKS4 | SOCKS5"
            )
            titulo = "SELECCIONAR PROXIES"
            opcion1 = 'Carpeta local "proxies"'
            opcion2 = "Ruta manual"
            opcion3 = "Explorador / Mini-CD"
            cancelar = "Cancelar"
        else:
            formatos = (
                "SUPPORTED FORMATS:\n"
                "  hostname:port | ip:port\n"
                "  hostname:port:user:pass | ip:port:user:pass\n"
                "  user:pass:hostname:port | user:pass:ip:port\n"
                "SUPPORTED PROTOCOLS:\n"
                "  HTTP | HTTPS | SOCKS4 | SOCKS5"
            )
            titulo = "SELECT PROXIES"
            opcion1 = 'Local "proxies" folder'
            opcion2 = "Manual path"
            opcion3 = "Explorer / Mini-CD"
            cancelar = "Cancel"

        print()
        print(color("╔════════════════════════════════════════════════════════════╗", CYAN))
        print(color(f"║ {titulo:^58} ║", CYAN))
        print(color("╠════════════════════════════════════════════════════════════╣", CYAN))
        print(f"  {formatos}")
        print(color("╠════════════════════════════════════════════════════════════╣", CYAN))
        print(f"  {color('[1]', GREEN)} {opcion1}")
        print(f"  {color('[2]', GREEN)} {opcion2}")
        print(f"  {color('[3]', GREEN)} {opcion3}")
        print(f"  {color('[0]', YELLOW)} {cancelar}")
        print(color("╚════════════════════════════════════════════════════════════╝", CYAN))

        opcion = input(color("> ", CYAN)).strip()

        if opcion == "1":
            ruta = seleccionar_proxy_local()
            if ruta:
                return ruta
            continue

        if opcion == "2":
            ruta = input("Ruta: " if LANGUAGE == "es" else "Path: ").strip().strip('"')
            if os.path.isfile(ruta):
                return ruta
            print(color("[!] Archivo no encontrado." if LANGUAGE == "es" else "[!] File not found.", RED))
            continue

        if opcion == "3":
            ruta = buscar_y_seleccionar_txt()
            if ruta:
                return ruta
            continue

        if opcion == "0":
            return None

        print(color("[!] Opción inválida." if LANGUAGE == "es" else "[!] Invalid option.", RED))


CARPETAS_INTERNAS_RESULTADOS = {"protocolos", "protocols", "logs"}

def normalizar_raiz_resultados(ruta):
    if not ruta:
        return ruta
    ruta = os.path.abspath(os.path.expanduser(str(ruta)))
    while os.path.basename(os.path.normpath(ruta)).lower() in CARPETAS_INTERNAS_RESULTADOS:
        padre = os.path.dirname(ruta)
        if padre == ruta:
            break
        ruta = padre
    return ruta

def es_carpeta_interna_resultados(ruta):
    return os.path.basename(os.path.normpath(ruta)).lower() in CARPETAS_INTERNAS_RESULTADOS

def seleccionar_carpeta_guardado(carpeta_inicial=None):
    """Mini explorador para elegir la carpeta de resultados."""
    carpeta = normalizar_raiz_resultados(carpeta_inicial or os.getcwd())

    while True:
        try:
            carpetas = [
                os.path.join(carpeta, nombre)
                for nombre in os.listdir(carpeta)
                if os.path.isdir(os.path.join(carpeta, nombre))
                and nombre.lower() not in CARPETAS_INTERNAS_RESULTADOS
            ]
            carpetas.sort(key=lambda ruta: os.path.basename(ruta).lower())
        except OSError as error:
            mensaje = (
                f"[!] No se puede abrir la carpeta: {error}"
                if LANGUAGE == "es"
                else f"[!] Cannot open folder: {error}"
            )
            print(color(mensaje, RED))
            carpeta = os.path.dirname(carpeta)
            continue

        if LANGUAGE == "es":
            titulo = "📁 CARPETA DE RESULTADOS"
            vacio = "No hay subcarpetas."
            seleccionar = "Seleccionar esta carpeta"
            crear = "Crear una nueva carpeta aquí"
            volver = "Volver"
            cancelar = "Cancelar"
            prompt = "Selecciona"
            nuevo_nombre = "Nombre de la nueva carpeta:"
            nombre_invalido = "[!] Nombre de carpeta inválido."
            opcion_invalida = "[!] Opción inválida."
            seleccion_invalida = "[!] Selección inválida."
        else:
            titulo = "📁 RESULTS FOLDER"
            vacio = "No subfolders."
            seleccionar = "Select this folder"
            crear = "Create a new folder here"
            volver = "Back"
            cancelar = "Cancel"
            prompt = "Select"
            nuevo_nombre = "New folder name:"
            nombre_invalido = "[!] Invalid folder name."
            opcion_invalida = "[!] Invalid option."
            seleccion_invalida = "[!] Invalid selection."

        print()
        print(color("╔════════════════════════════════════════════════════════════╗", CYAN))
        print(color(f"║ {titulo:^58} ║", CYAN))
        print(color("╠════════════════════════════════════════════════════════════╣", CYAN))
        print(f"║ 📂 {carpeta}")
        print(color("╠════════════════════════════════════════════════════════════╣", CYAN))

        posiciones = {}
        for indice, ruta in enumerate(carpetas, 1):
            print(f"║ [{indice:2}] 📁 {os.path.basename(ruta)}")
            posiciones[indice] = ruta

        if not posiciones:
            print(color(f"  {vacio}", YELLOW))

        print(color("╠════════════════════════════════════════════════════════════╣", CYAN))
        print(f"  [S]  {seleccionar}")
        print(f"  [N]  {crear}")
        print(f"  [..] {volver}")
        print(f"  [0]  {cancelar}")
        print(color("╚════════════════════════════════════════════════════════════╝", CYAN))

        opcion = input(f"\n{prompt}: ").strip()

        if opcion == "0":
            return None

        if opcion.lower() == "s":
            if es_carpeta_interna_resultados(carpeta):
                carpeta = normalizar_raiz_resultados(carpeta)
                print(color(
                    "[!] Esa carpeta es interna. Usa la carpeta raíz de resultados."
                    if LANGUAGE == "es"
                    else "[!] That is an internal folder. Use the results root folder.",
                    YELLOW,
                ))
                continue
            return normalizar_raiz_resultados(carpeta)

        if opcion.lower() == "n":
            nombre = input(f"\n{nuevo_nombre}\n> ").strip()
            if not nombre:
                continue

            if (
                nombre in (".", "..")
                or os.path.basename(nombre) != nombre
                or nombre.lower() in CARPETAS_INTERNAS_RESULTADOS
            ):
                print(color(
                    "[!] Ese nombre está reservado para carpetas internas."
                    if LANGUAGE == "es"
                    else "[!] That name is reserved for internal folders.",
                    RED,
                ))
                continue

            nueva = os.path.join(carpeta, nombre)
            try:
                os.makedirs(nueva, exist_ok=True)
                carpeta = nueva
            except OSError as error:
                mensaje = (
                    f"[!] No se pudo crear: {error}"
                    if LANGUAGE == "es"
                    else f"[!] Could not create folder: {error}"
                )
                print(color(mensaje, RED))
            continue

        if opcion == "..":
            padre = os.path.dirname(carpeta)
            if padre != carpeta:
                carpeta = padre
            continue

        try:
            indice = int(opcion)
        except ValueError:
            print(color(opcion_invalida, RED))
            continue

        seleccion = posiciones.get(indice)
        if seleccion:
            carpeta = seleccion
        else:
            print(color(seleccion_invalida, RED))

def configurar_guardado(estado=None):
    """
    Devuelve (True, carpeta).

    Los resultados siempre se guardan. La carpeta se elige una sola vez
    y queda persistida en el estado local. En ejecuciones posteriores se
    reutiliza automáticamente. Solo vuelve a solicitarse si la ruta
    guardada dejó de existir.
    """
    estado = (
        estado
        if isinstance(estado, dict)
        else cargar_estado_local()
    )

    carpeta_guardada = str(
        estado.get("results_directory", "")
    ).strip()

    if carpeta_guardada:
        carpeta_original = os.path.abspath(os.path.expanduser(carpeta_guardada))
        carpeta_guardada = normalizar_raiz_resultados(carpeta_original)

        if carpeta_guardada != carpeta_original:
            estado["results_directory"] = carpeta_guardada
            guardar_estado_local(estado)

        if os.path.isdir(carpeta_guardada):
            print(
                color(
                    (
                        f"[+] Carpeta de resultados: {carpeta_guardada}"
                        if LANGUAGE == "es"
                        else f"[+] Results folder: {carpeta_guardada}"
                    ),
                    CYAN,
                )
            )
            return True, carpeta_guardada

        estado.pop("results_directory", None)
        guardar_estado_local(estado)

        print(
            color(
                (
                    "[!] La carpeta guardada ya no existe. "
                    "Selecciona una nueva."
                    if LANGUAGE == "es"
                    else
                    "[!] The saved results folder no longer exists. "
                    "Select a new one."
                ),
                YELLOW,
            )
        )

    print(
        color(
            (
                "[i] Elige la carpeta de resultados. "
                "Se recordará para las próximas ejecuciones."
                if LANGUAGE == "es"
                else
                "[i] Choose the results folder. "
                "It will be remembered for future runs."
            ),
            CYAN,
        )
    )

    carpeta = seleccionar_carpeta_guardado()

    if carpeta is None:
        return None, None

    carpeta = normalizar_raiz_resultados(carpeta)

    estado["results_directory"] = carpeta

    if not guardar_estado_local(estado):
        print(
            color(
                (
                    "[!] No se pudo guardar la preferencia de carpeta."
                    if LANGUAGE == "es"
                    else
                    "[!] The folder preference could not be saved."
                ),
                YELLOW,
            )
        )

    return True, carpeta

def seleccionar_modo_procesamiento():
    """Decide si se hace un Re-scan nuevo o se continúa con Resume."""
    while True:
        if LANGUAGE == "es":
            titulo = "MODO DE PROCESAMIENTO"
            rescan = "Re-scan completo"
            rescan_desc = "Nuevo escaneo; permite elegir otra carpeta."
            continuar = "Continuar scan"
            continuar_desc = "Usa Resume y la carpeta del scan anterior."
            volver = "Volver"
            invalida = "[!] Opción inválida."
        else:
            titulo = "PROCESSING MODE"
            rescan = "Full re-scan"
            rescan_desc = "New scan; lets you choose another folder."
            continuar = "Continue scan"
            continuar_desc = "Uses Resume and the previous scan folder."
            volver = "Back"
            invalida = "[!] Invalid option."

        print()
        print(color("╔════════════════════════════════════════════════════════════╗", CYAN))
        print(color(f"║ {titulo:^58} ║", CYAN))
        print(color("╠════════════════════════════════════════════════════════════╣", CYAN))
        print(f"  {color('[1]', MAGENTA)} {rescan}")
        print(f"      {rescan_desc}")
        print()
        print(f"  {color('[2]', GREEN)} {continuar}")
        print(f"      {continuar_desc}")
        print()
        print(f"  {color('[0]', YELLOW)} {volver}")
        print(color("╚════════════════════════════════════════════════════════════╝", CYAN))

        opcion = input(color("> ", CYAN)).strip()
        if opcion == "1":
            return True
        if opcion == "2":
            return False
        if opcion == "0":
            return None
        print(color(invalida, RED))


class ArchivoNulo:
    """Objeto compatible con write/flush/close para modo sin guardado."""
    def write(self, *_args, **_kwargs):
        return 0

    def flush(self):
        pass

    def close(self):
        pass


def abrir_archivos_nulos():
    archivos = {
        "valid": ArchivoNulo(),
        "slow": ArchivoNulo(),
        "dead": ArchivoNulo(),
        "indeterminate": ArchivoNulo(),
    }
    return archivos, {}


# MENÚ

def menu_configuracion():
    while True:
        if LANGUAGE == "es":
            titulo = "CONFIGURACIÓN"
            idioma = "Cambiar idioma"
            volver = "Volver"
            invalida = "[!] Opción inválida."
        else:
            titulo = "SETTINGS"
            idioma = "Change language"
            volver = "Back"
            invalida = "[!] Invalid option."

        print()
        print(color("╔════════════════════════════════════════════════════════════╗", CYAN))
        print(color(f"║ {titulo:^58} ║", CYAN))
        print(color("╠════════════════════════════════════════════════════════════╣", CYAN))
        print(f"  {color('[1]', GREEN)} {idioma}")
        print()
        if LANGUAGE == "es":
            print(color("  [i] Workers, timeouts, reintentos, rate y otros ajustes", CYAN))
            print(color("      avanzados se modifican desde config.json.", CYAN))
        else:
            print(color("  [i] Workers, timeouts, retries, rate and other advanced", CYAN))
            print(color("      settings are changed in config.json.", CYAN))
        print()
        print(f"  {color('[0]', YELLOW)} {volver}")
        print(color("╚════════════════════════════════════════════════════════════╝", CYAN))

        opcion = input(color("> ", CYAN)).strip()

        if opcion == "1":
            cambiar_idioma()
            continue
        if opcion == "0":
            return

        print(color(invalida, RED))


def seleccionar_modo():
    opciones = {
        "1": "http", "2": "https", "3": "socks4", "4": "socks5",
        "5": "auto", "6": "auto_full",
    }
    while True:
        titulo = "SELECCIONAR PROTOCOLO" if LANGUAGE == "es" else "SELECT PROTOCOL"
        config_txt = "Configuración" if LANGUAGE == "es" else "Settings"
        salir = "Salir" if LANGUAGE == "es" else "Exit"
        auto_desc = "detección optimizada por etapas" if LANGUAGE == "es" else "optimized staged detection"
        full_desc = "Exhaustivo: máxima precisión" if LANGUAGE == "es" else "Exhaustive: maximum precision"
        print()
        print(color("╔════════════════════════════════════════════════════════════╗", CYAN))
        print(color(f"║ {('PROXY CHECKER ' + VERSION):^58} ║", CYAN))
        print(color(f"║ {titulo:^58} ║", CYAN))
        print(color("╠════════════════════════════════════════════════════════════╣", CYAN))
        print(f"  {color('[1]', GREEN)} HTTP")
        print(f"  {color('[2]', GREEN)} HTTPS")
        print(f"  {color('[3]', GREEN)} SOCKS4")
        print(f"  {color('[4]', GREEN)} SOCKS5")
        print(f"  {color('[5]', MAGENTA)} AUTO      — {auto_desc}")
        print(f"  {color('[6]', MAGENTA)} AUTO FULL — {full_desc}")
        print(f"  {color('[7]', YELLOW)} {config_txt}")
        print(f"  {color('[0]', YELLOW)} {salir}")
        print(color("╚════════════════════════════════════════════════════════════╝", CYAN))
        opcion = input(color("> ", CYAN)).strip()
        if opcion in opciones:
            return opciones[opcion]
        if opcion == "7":
            menu_configuracion(); continue
        if opcion == "0":
            return None
        print(color("[!] Opción inválida." if LANGUAGE == "es" else "[!] Invalid option.", RED))


# ARGUMENTOS

def obtener_argumentos():

    parser = argparse.ArgumentParser(
        description=
            "Proxy Checker V7"
    )

    parser.add_argument(
        "-f",
        "--file",
        dest="archivo",
        help="TXT con proxies",
    )

    parser.add_argument(
        "-p",
        "--protocol",
        dest="protocolo",
        choices=[
            "http",
            "https",
            "socks4",
            "socks5",
            "auto",
            "auto_full",
        ],
    )

    parser.add_argument(
        "--profile",
        choices=[
            "fast",
            "normal",
            "conservative",
        ],
        default="normal",
    )

    parser.add_argument(
        "-w",
        "--workers",
        type=int,
    )

    parser.add_argument(
        "--rate",
        type=float,
    )

    parser.add_argument(
        "--timeout",
        type=float,
    )

    parser.add_argument(
        "--retries",
        type=int,
    )

    parser.add_argument(
        "--config",
        default="config.json",
    )

    return parser.parse_args()


# BIENVENIDA / DEPENDENCIAS

def comando_instalacion_dependencias():
    # Para el usuario mostramos el comando simple. La instalación automática
    # usa sys.executable internamente para instalar en el mismo Python.
    return 'pip install "httpx[socks]" "httpx-socks[asyncio]"'


def instalar_dependencias_automaticamente():
    comando = [sys.executable, "-m", "pip", "install", "httpx[socks]", "httpx-socks[asyncio]"]
    print(color(f"[+] {t('installing')}", CYAN))
    try:
        resultado = subprocess.run(comando, check=False)
    except OSError:
        return False
    importlib.invalidate_caches()
    return resultado.returncode == 0


def verificar_dependencias():
    global httpx, AsyncProxyTransport
    python_ok = sys.version_info >= (3, 10)
    if not python_ok:
        print(color(f"[×] {t('python_old')}", RED))
        return False

    httpx_ok = importlib.util.find_spec("httpx") is not None
    socks_ok = importlib.util.find_spec("socksio") is not None
    socks4_ok = importlib.util.find_spec("httpx_socks") is not None
    print()
    print(color(f"=== {t('deps')} ===", CYAN))
    print(f"{color('[✓]', GREEN)} Python {platform.python_version()}")
    print(f"{color('[✓]', GREEN) if httpx_ok else color('[×]', RED)} httpx")
    print(f"{color('[✓]', GREEN) if socks_ok else color('[×]', RED)} SOCKS5")
    print(f"{color('[✓]', GREEN) if socks4_ok else color('[×]', RED)} SOCKS4")

    if not httpx_ok or not socks_ok or not socks4_ok:
        print(color(f"\n[!] {t('missing_deps')}", YELLOW))
        respuesta = input(t("install_auto")).strip().lower()
        aceptar = respuesta in {"", "s", "si", "sí", "y", "yes"}
        if not aceptar:
            print(f"\n{comando_instalacion_dependencias()}")
            return False
        if not instalar_dependencias_automaticamente():
            print(color(f"[×] {t('install_failed')}", RED))
            print(comando_instalacion_dependencias())
            return False
        httpx_ok = importlib.util.find_spec("httpx") is not None
        socks_ok = importlib.util.find_spec("socksio") is not None
        socks4_ok = importlib.util.find_spec("httpx_socks") is not None
        if not httpx_ok or not socks_ok or not socks4_ok:
            print(color(f"[×] {t('install_failed')}", RED))
            return False
        print(color(f"[✓] {t('installed')}", GREEN))

    try:
        import httpx as modulo_httpx
        from httpx_socks import AsyncProxyTransport as modulo_async_proxy_transport
        httpx = modulo_httpx
        AsyncProxyTransport = modulo_async_proxy_transport
    except Exception as error:
        print(color(f"[×] httpx: {type(error).__name__}", RED))
        return False

    print(color(f"[✓] {t('ready')}", GREEN))
    return True


# GUÍA INTEGRADA

def mostrar_guia():
    if LANGUAGE == "es":
        titulo = f"GUÍA RÁPIDA {VERSION}"
        lineas = [
            "VALID=funciona | SLOW=lento | DEAD=no funciona | INDET=sin confirmar",
            "PING/LAT=latencia medida | SCORE=0-100 | mayor = mejor resultado",
            "HTTP | HTTPS | SOCKS4 | SOCKS5: comprueban un protocolo específico",
            "AUTO: 1 unidad por proxy; valida internamente HTTP/HTTPS/SOCKS4/SOCKS5",
            "AUTO conserva detección multiprotocolo y cuenta el mejor estado por proxy",
            "AUTO mantiene las pruebas necesarias para VALID/SLOW en cada protocolo",
            "AUTO FULL: exhaustivo, prioriza la máxima precisión cuando el tiempo no es prioridad",
            "INDETERMINATE se reserva para resultados realmente ambiguos; fallos repetidos y concluyentes terminan en DEAD",
            "AUTO/AUTO FULL pueden detectar más de un protocolo en el mismo proxy",
            "VALID/SLOW exige navegación HTTPS real + contenido web válido",
            "Errores locales de transporte no se usan como prueba de proxy DEAD",
            "Continue: usa Resume y conserva la carpeta del scan anterior",
            "Re-scan: prueba todo otra vez y permite elegir una nueva carpeta",
            "VALID/SLOW se guardan también en protocolos/http|https|socks4|socks5",
        ]
        continuar = "Presiona ENTER para continuar..."
    else:
        titulo = f"QUICK GUIDE {VERSION}"
        lineas = [
            "VALID=works | SLOW=slow | DEAD=failed | INDET=unconfirmed",
            "PING/LAT=measured latency | SCORE=0-100 | higher = better result",
            "HTTP | HTTPS | SOCKS4 | SOCKS5: check one specific protocol",
            "AUTO: 1 unit per proxy; internally validates HTTP/HTTPS/SOCKS4/SOCKS5",
            "AUTO keeps multi-protocol detection and counts the best state per proxy",
            "AUTO keeps the checks required for VALID/SLOW on every protocol",
            "AUTO FULL: exhaustive, prioritizes maximum precision when time is not the priority",
            "INDETERMINATE is reserved for truly ambiguous results; repeated conclusive failures become DEAD",
            "AUTO/AUTO FULL can detect multiple protocols on the same proxy",
            "VALID/SLOW requires real HTTPS navigation + valid web content",
            "Local transport errors are not used as proof that a proxy is DEAD",
            "Continue: uses Resume and keeps the previous scan folder",
            "Re-scan: tests everything again and lets you choose a new folder",
            "VALID/SLOW are also saved under protocolos/http|https|socks4|socks5",
        ]
        continuar = "Press ENTER to continue..."
    ancho = 82
    borde = "═" * ancho
    print(); print(color(f"╔{borde}╗", CYAN)); print(color(f"║{titulo:^{ancho}}║", CYAN)); print(color(f"╠{borde}╣", CYAN))
    for linea in lineas:
        print(f"║ {linea:<{ancho - 2}} ║")
    print(color(f"╚{borde}╝", CYAN)); input(color(continuar, GREEN))


# MAIN ASYNC

async def main_async(
    args
):
    # Evita el ruido de AnyIO/httpx durante un Ctrl+C ya gestionado. Solo se
    # silencia un contexto cuyo árbol contiene KeyboardInterrupt; el resto se
    # delega al manejador normal del loop.
    loop = asyncio.get_running_loop()
    manejador_anterior = loop.get_exception_handler()

    def contiene_keyboard_interrupt(exc):
        if isinstance(exc, KeyboardInterrupt):
            return True
        sub = getattr(exc, "exceptions", None)
        if sub:
            return any(contiene_keyboard_interrupt(item) for item in sub)
        return False

    def manejador_loop(loop_actual, context):
        exc = context.get("exception")
        if exc is not None and contiene_keyboard_interrupt(exc):
            return
        if manejador_anterior is not None:
            manejador_anterior(loop_actual, context)
        else:
            loop_actual.default_exception_handler(context)

    loop.set_exception_handler(manejador_loop)

    mostrar_banner()

    print(
        color(
            f"[!] {t('authorized')}",
            YELLOW,
        )
    )

    print()

    mostrar_guia()

    # CONFIG

    config = cargar_config(
        args.config
    )

    aplicar_perfil(
        config,
        args.profile,
    )

    if args.workers is not None:

        config.workers = max(
            1,
            min(
                500,
                args.workers,
            ),
        )

    if args.rate is not None:

        config.rate = max(
            0.1,
            args.rate,
        )

    if args.timeout is not None:

        config.timeout = max(
            1,
            args.timeout,
        )

    if args.retries is not None:

        config.retries = max(
            0,
            args.retries,
        )

    guardar_config(
        args.config,
        config,
    )

    # ARCHIVO

    ruta = seleccionar_archivo(
        args.archivo
    )

    if ruta is None:

        print(
            color(
                "[✓] Saliendo...",
                GREEN,
            )
        )

        return

    # RE-SCAN / RESUME

    re_scan = seleccionar_modo_procesamiento()

    if re_scan is None:
        print(color("[✓] Saliendo...", GREEN))
        return

    # MODO

    modo = args.protocolo

    if not modo:

        modo = seleccionar_modo()

    if modo is None:

        return

    # CARGAR

    entradas = cargar_proxies(
        ruta
    )

    if not entradas:

        print(
            color(
                "[!] No hay proxies válidos.",
                RED,
            )
        )

        return

    # GUARDADO / RESULTADOS / RESUME

    if re_scan:
        print(
            color(
                "[i] Re-scan: elige la carpeta para este nuevo escaneo."
                if LANGUAGE == "es"
                else "[i] Re-scan: choose the folder for this new scan.",
                CYAN,
            )
        )
        carpeta = seleccionar_carpeta_guardado()
        if carpeta is None:
            print(color("[✓] Saliendo..." if LANGUAGE == "es" else "[✓] Exiting...", GREEN))
            return
        carpeta = normalizar_raiz_resultados(carpeta)
        guardar = True
        procesados = set()
    else:
        guardar, carpeta = configurar_guardado()
        if guardar is None:
            print(color("[✓] Saliendo..." if LANGUAGE == "es" else "[✓] Exiting...", GREEN))
            return
        procesados = cargar_procesados(carpeta)

    tareas = construir_tareas(
        entradas,
        modo,
        procesados,
    )

    if re_scan:
        print(color("[+] Re-scan completo: se comprobarán todas las entradas.", CYAN))
    elif guardar and not tareas:
        print(color("[✓] Resume: no quedan pruebas pendientes.", GREEN))
        return

    # INFO DE TAREAS
    # AUTO cuenta proxies como unidades lógicas; AUTO FULL conserva el
    # conteo exhaustivo por combinación proxy/protocolo.
    protocolos_por_proxy = (
        len(PROTOCOLOS) if modo == "auto_full" else 1
    )
    tests_totales = len(entradas) * protocolos_por_proxy

    if LANGUAGE == "es":
        print(color(f"[+] Entradas             : {len(entradas):,}", CYAN))
        print(color(f"[+] Protocolos por proxy : {protocolos_por_proxy}", CYAN))
        print(color(f"[+] Tests totales        : {tests_totales:,}", CYAN))
        print(color(
            f"[i] {len(entradas):,} proxies × "
            f"{protocolos_por_proxy} protocolo"
            f"{'s' if protocolos_por_proxy != 1 else ''} "
            f"= {tests_totales:,} tests",
            CYAN,
        ))
    else:
        print(color(f"[+] Entries              : {len(entradas):,}", CYAN))
        print(color(f"[+] Protocols per proxy  : {protocolos_por_proxy}", CYAN))
        print(color(f"[+] Total tests          : {tests_totales:,}", CYAN))
        print(color(
            f"[i] {len(entradas):,} proxies × "
            f"{protocolos_por_proxy} protocol"
            f"{'s' if protocolos_por_proxy != 1 else ''} "
            f"= {tests_totales:,} tests",
            CYAN,
        ))

    # INFO

    procesados_actuales = max(0, tests_totales - len(tareas))

    if LANGUAGE == "es":
        etiquetas = {
            "title": "CONFIGURACIÓN", "entries": "Entradas", "total": "Tests totales",
            "processed": "Procesados", "pending": "Pendientes", "mode": "Modo",
            "retries": "Reintentos", "max_latency": "Max latencia",
            "ip_confirm": "Confirmaciones IP", "third": "Tercer servicio",
            "geo": "Geolocalización", "ranking": "Ranking", "anon": "Anonimato",
            "save": "Guardar",
        }
    else:
        etiquetas = {
            "title": "CONFIGURATION", "entries": "Entries", "total": "Total tests",
            "processed": "Processed", "pending": "Pending", "mode": "Mode",
            "retries": "Retries", "max_latency": "Max latency",
            "ip_confirm": "IP confirmations", "third": "Third service",
            "geo": "Geolocation", "ranking": "Ranking", "anon": "Anonymity",
            "save": "Save",
        }

    lineas_config = [
        f"{etiquetas['entries']:<20} : {len(entradas):,}",
        f"{etiquetas['total']:<20} : {tests_totales:,}",
        f"{etiquetas['processed']:<20} : {procesados_actuales:,}",
        f"{etiquetas['pending']:<20} : {len(tareas):,}",
        f"{etiquetas['mode']:<20} : {modo.upper()}",
        f"{'Workers':<20} : {config.workers}",
        f"{'Rate':<20} : {config.rate:.2f}/s",
        f"{'Timeout':<20} : {config.timeout:.1f}s",
        f"{'Connect timeout':<20} : {config.connect_timeout:.1f}s",
        f"{etiquetas['retries']:<20} : {config.retries}",
        f"{etiquetas['max_latency']:<20} : {config.max_latency:.1f}s",
        f"{etiquetas['ip_confirm']:<20} : {config.min_ip_confirmations}",
        f"{etiquetas['third']:<20} : {'ON' if config.third_ip_check else 'OFF'}",
        f"{'Stability tests':<20} : {config.stability_tests}",
        f"{etiquetas['geo']:<20} : ON",
        f"{'ISP / ASN':<20} : ON",
        f"{'Score':<20} : ON",
        f"{etiquetas['ranking']:<20} : ON",
        f"{etiquetas['anon']:<20} : ON",
        f"{'Resume':<20} : {'ON' if guardar else 'OFF'}",
        f"{etiquetas['save']:<20} : {'ON' if guardar else 'OFF'}",
        f"{'Async':<20} : ON",
    ]

    print()
    print(color("╔════════════════════════════════════════════════════════════╗", CYAN))
    print(color(f"║ {(VERSION + ' ' + etiquetas['title']):^58} ║", CYAN))
    print(color("╠════════════════════════════════════════════════════════════╣", CYAN))
    for linea in lineas_config:
        print(f"║ {linea:<58} ║")
    print(color("╚════════════════════════════════════════════════════════════╝", CYAN))


    if not tareas:

        print(
            color(
                "[✓] No quedan pruebas pendientes.",
                GREEN,
            )
        )

        return

    # ARCHIVOS

    if guardar:
        archivos, paths = abrir_archivos(carpeta)
        archivos_protocolo, paths_protocolo = abrir_archivos_protocolos(carpeta)
    else:
        archivos, paths = abrir_archivos_nulos()
        archivos_protocolo, paths_protocolo = {}, {}

    # STATS

    async with stats_lock:

        stats.update({

            "tested": 0,
            "valid": 0,
            "slow": 0,
            "dead": 0,
            "indeterminate": 0,

            "excellent": 0,
            "good": 0,
            "fair": 0,
            "poor": 0,

            "start_time":
                time.perf_counter(),

            "protocols": {
                protocolo: {
                    "tested": 0,
                    "valid": 0,
                    "slow": 0,
                    "dead": 0,
                    "indeterminate": 0,
                }
                for protocolo in PROTOCOLOS
            },
            "failure_reasons": {},
            "speed_samples": [],
        })

    inicio = time.perf_counter()

    interrumpido = False
    try:
        await procesar_tareas(
            tareas,
            archivos,
            config,
            archivos_protocolo,
            carpeta if guardar else None,
            auto_full=(modo == "auto_full"),
        )
    except asyncio.CancelledError:
        interrumpido = True
        print()
        print(color("[!] Interrupción recibida. Cerrando de forma segura..." if LANGUAGE == "es" else "[!] Interrupt received. Shutting down safely...", YELLOW))
        # procesar_tareas ya drenó/canceló sus workers en su bloque finally.
    finally:

        for archivo in archivos.values():
            archivo.close()

        for archivo in archivos_protocolo.values():
            archivo.close()


    tiempo_total = (
        time.perf_counter()
        - inicio
    )

    # RESUMEN TXT

    if guardar:
        guardar_resumen_txt(
            carpeta,
            tareas,
            tiempo_total,
        )

    velocidad = (

        stats["tested"]
        / tiempo_total

        if tiempo_total > 0
        else 0
    )

    # RESULTADO / CIERRE PROFESIONAL
    titulo_cierre = (
        "SCAN INTERRUMPIDO — PROGRESO GUARDADO"
        if interrumpido and LANGUAGE == "es"
        else "SCAN INTERRUPTED — PROGRESS SAVED"
        if interrumpido
        else "SCAN COMPLETADO"
        if LANGUAGE == "es"
        else "SCAN COMPLETED"
    )
    ancho = 62
    print()
    print(color("╔" + "═" * ancho + "╗", CYAN))
    print(color("║", CYAN) + color(f"{titulo_cierre:^{ancho}}", BOLD) + color("║", CYAN))
    print(color("╠" + "═" * ancho + "╣", CYAN))
    valid_text = color(format(stats["valid"], ","), GREEN)
    slow_text = color(format(stats["slow"], ","), YELLOW)
    dead_text = color(format(stats["dead"], ","), RED)
    indeterminate_text = color(format(stats["indeterminate"], ","), MAGENTA)

    print(f"  {color('✓ VALID', GREEN):24} {valid_text}")
    print(f"  {color('~ SLOW', YELLOW):24} {slow_text}")
    print(f"  {color('× DEAD', RED):24} {dead_text}")
    print(f"  {color('? INDETERMINATE', MAGENTA):24} {indeterminate_text}")
    print()
    print(f"  {color('TESTS', CYAN):18} {stats['tested']:,}/{len(tareas):,}")
    print(f"  {color('VELOCIDAD' if LANGUAGE == 'es' else 'SPEED', CYAN):18} {velocidad:.2f}/s")
    print(f"  {color('TIEMPO' if LANGUAGE == 'es' else 'TIME', CYAN):18} {formato_tiempo(tiempo_total)}")
    print(color("╚" + "═" * ancho + "╝", CYAN))

    print()
    print(f"{color('◆', MAGENTA)} {color('PROTOCOLOS' if LANGUAGE == 'es' else 'PROTOCOLS', BOLD)}")
    for protocolo in PROTOCOLOS:
        datos = stats["protocols"].get(protocolo, {})
        print(
            f"  {color(protocolo.upper(), CYAN):18} "
            f"{color('OK ' + format(datos.get('valid', 0), ','), GREEN)} | "
            f"{color('SLOW ' + format(datos.get('slow', 0), ','), YELLOW)} | "
            f"{color('DEAD ' + format(datos.get('dead', 0), ','), RED)} | "
            f"{color('INDET ' + format(datos.get('indeterminate', 0), ','), MAGENTA)}"
        )

    if stats["failure_reasons"]:
        print()
        titulo_diag = "DIAGNÓSTICO DE FALLOS" if LANGUAGE == "es" else "FAILURE DIAGNOSTICS"
        print(f"{color('◆', MAGENTA)} {color(titulo_diag, BOLD)}")
        orden = ("CONNECT", "TIMEOUT", "TLS", "PROTOCOL", "HTTP", "CONTENT", "AUTH", "SERVICE", "OTHER")
        partes_diag = []
        for categoria in orden:
            cantidad = stats["failure_reasons"].get(categoria, 0)
            if cantidad:
                partes_diag.append(f"{categoria}={cantidad:,}")
        print("  " + " | ".join(partes_diag))

    if guardar:
        print()
        print(f"{color('◆', MAGENTA)} {color('RESULTADOS' if LANGUAGE == 'es' else 'RESULTS', BOLD)}")
        colores_estado = {"valid": GREEN, "slow": YELLOW, "dead": RED, "indeterminate": MAGENTA}
        for estado, ruta_estado in paths.items():
            print(f"  {color(estado.upper(), colores_estado.get(estado, WHITE)):18} {ruta_estado}")
        print(f"  {color('PROTOCOLOS', CYAN):18} {os.path.join(carpeta, 'protocolos')}")
        print(f"  {color('TXT RESUMEN', CYAN):18} {os.path.join(carpeta, 'resumen.txt')}")
    else:
        print(color("[!] Resultados no guardados (modo temporal)." if LANGUAGE == "es" else "[!] Results were not saved (temporary mode).", YELLOW))

    print()
    if interrumpido:
        print(color("[✓] Tareas pendientes canceladas y conexiones cerradas." if LANGUAGE == "es" else "[✓] Pending tasks cancelled and connections closed.", GREEN))
        if guardar:
            print(color("[✓] El progreso queda listo para Continue." if LANGUAGE == "es" else "[✓] Progress is ready for Continue.", GREEN))
    else:
        print(color("[✓] Resultados guardados y conexiones cerradas correctamente." if LANGUAGE == "es" else "[✓] Results saved and connections closed successfully.", GREEN))

    print(color("─" * 64, CYAN))
    print(color(f"  Proxy Checker {VERSION}", WHITE) + color("  •  by Flippy2x", MAGENTA))
    print(color("  Gracias por usar Proxy Checker. Hasta la próxima." if LANGUAGE == "es" else "  Thanks for using Proxy Checker. See you next time.", GREEN))
    print(color("─" * 64, CYAN))


# MAIN

def main():
    seleccionar_idioma_inicio()


    estado = cargar_estado_local()
    advertir_version_antigua(estado)

    if not verificar_dependencias():
        return

    args = obtener_argumentos()
    diagnostico_local(args.config)
    mostrar_novedades_si_corresponde(estado)

    try:

        asyncio.run(
            main_async(
                args
            )
        )

    except KeyboardInterrupt:

        print()

        print(
            color(
                "[✓] Cierre seguro completado." if LANGUAGE == "es" else "[✓] Safe shutdown completed.",
                GREEN,
            )
        )


if __name__ == "__main__":
    main()
