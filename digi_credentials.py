#!/usr/bin/env python3
"""Read credentials from your own TP-Link XGB430v Pro ESDIGI.

Run: python digi_credentials.py   (no arguments; password uses getpass)
Requires Python 3.9+ and an already installed cryptography or pycryptodomex
or pycryptodome package. Never downloads packages or executes router JavaScript.

Only the IP entered at the prompt is contacted. No proxies, DNS, browser,
telemetry, log files, saved cookies, backups or XML files. All sensitive data
stays in process memory, except the requested terminal output. Python cannot
guarantee erasure of copies in RAM, prevent OS paging, or control terminal
recording. TLS accepts the router's self-signed certificate on the entered IP.

Protocol verified by reading the user's router's public login HTML,
tpEncrypt.js, encrypt.js, gdprProxy.js and oid_str.js on 2026-10-20:
getGDPRParm -> AES-CBC / RSA-no-padding -> POST /cgi_gdpr?9, CGI /cgi/login.
Unknown login protocols fail before credentials are sent.

Backup format reference:
https://github.com/sta-c0000/tpconf_bin_xml (Alain Ducharme, GPL-3.0-or-later)
Key derivation reference:
https://github.com/jqssun/tplink-firmware-tools
This file is licensed GPL-3.0-or-later. The bounded LZSS decoder is adapted
from tpconf_bin_xml's algorithm, Copyright 2018 Alain Ducharme.
License text: https://www.gnu.org/licenses/gpl-3.0.html
"""

import sys

sys.dont_write_bytecode = True

if sys.version_info < (3, 9):
    print("Se necesita Python 3.9 o posterior. Actualiza Python y vuelve a ejecutar el programa.",
          file=sys.stderr)
    sys.exit(1)

import base64
import getpass
import hashlib
import hmac
import html
import http.client
import http.cookies
import ipaddress
import json
import re
import secrets
import socket
import ssl
import warnings
import xml.etree.ElementTree as ET
from html.parser import HTMLParser
from urllib.parse import quote, urljoin, urlsplit


MAX_RESPONSE = 4 * 1024 * 1024
MAX_XML = 4 * 1024 * 1024
PRODUCT_ID = 1083710977
BASE_KEY = bytes.fromhex("748da50bf93e2dcf")
TIMEOUT = 12


class RouterError(Exception):
    """A deliberately secret-free diagnostic."""


def md5(data):
    return hashlib.md5(data, usedforsecurity=False).digest()


class Crypto:
    """No installation, networking, file access or persistent state."""

    def __init__(self):
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            try:
                from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
            except ImportError:
                from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES
            self.backend = "cryptography"
            self.package = "cryptography"
            self.Cipher, self.AES, self.DES, self.modes = Cipher, algorithms.AES, TripleDES, modes
        except ImportError:
            try:
                from Cryptodome.Cipher import AES, DES
                self.package = "pycryptodomex"
            except ImportError:
                try:
                    from Crypto.Cipher import AES, DES
                    self.package = "pycryptodome"
                except ImportError:
                    raise RouterError(
                        "Falta una biblioteca criptográfica local: cryptography, "
                        "pycryptodomex o pycryptodome.\n"
                        "Instala una ejecutando con el mismo Python:\n"
                        "  python -m pip install cryptography\n"
                        "Después vuelve a ejecutar: python digi_credentials.py\n"
                        "Si usas python3, sustituye python por python3 en ambos comandos.\n"
                        "No se han solicitado datos ni realizado conexiones."
                    ) from None
            self.backend = "pycrypto"
            self.AES, self.DES = AES, DES

    def des_decrypt(self, key, data):
        if self.backend == "cryptography":
            # EDE with the same key in all three positions is exactly DES.
            ctx = self.Cipher(self.DES(key * 3), self.modes.ECB()).decryptor()
            return ctx.update(data) + ctx.finalize()
        return self.DES.new(key, self.DES.MODE_ECB).decrypt(data)

    def aes(self, key, iv, data, decrypt=False):
        if self.backend == "cryptography":
            cipher = self.Cipher(self.AES(key), self.modes.CBC(iv))
            ctx = cipher.decryptor() if decrypt else cipher.encryptor()
            return ctx.update(data) + ctx.finalize()
        ctx = self.AES.new(key, self.AES.MODE_CBC, iv=iv)
        return ctx.decrypt(data) if decrypt else ctx.encrypt(data)


def check_requirements():
    """Check the selected local backend before prompts or network activity."""
    try:
        crypto = Crypto()
    except RouterError:
        raise
    except Exception:
        raise RouterError(
            "No se pudo cargar la biblioteca criptográfica local.\n"
            "Prueba a reparar la dependencia predeterminada con el mismo Python:\n"
            "  python -m pip install --upgrade --force-reinstall cryptography\n"
            "Si usas python3, sustituye python por python3.\n"
            "Después vuelve a ejecutar el programa. No se han realizado conexiones."
        ) from None
    try:
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        plain = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
        encrypted = bytes.fromhex("7649abac8119b246cee98e9b12e9197d")
        des_plain = crypto.des_decrypt(
            bytes.fromhex("133457799bbcdff1"), bytes.fromhex("85e813540f0ab405"))
        if (crypto.aes(key, iv, plain) != encrypted
                or crypto.aes(key, iv, encrypted, decrypt=True) != plain
                or des_plain != bytes.fromhex("0123456789abcdef")):
            raise ValueError
    except Exception:
        raise RouterError(
            f"La biblioteca {crypto.package} no supera la comprobación AES/DES.\n"
            "Repárala ejecutando con el mismo Python:\n"
            f"  python -m pip install --upgrade --force-reinstall {crypto.package}\n"
            "Si usas python3, sustituye python por python3.\n"
            "Después vuelve a ejecutar el programa. No se han realizado conexiones."
        ) from None
    try:
        if md5(b"").hex() != "d41d8cd98f00b204e9800998ecf8427e":
            raise ValueError
    except Exception:
        raise RouterError(
            "Este Python no permite MD5, necesario para el formato del router. "
            "Usa una instalación de Python 3.9 o posterior que admita "
            "hashlib.md5(..., usedforsecurity=False). No se han realizado conexiones."
        ) from None
    return crypto


def derive_key(product_id=PRODUCT_ID):
    if not isinstance(product_id, int) or not 0 <= product_id <= 0xFFFFFFFF:
        raise RouterError("ProductID fuera del rango de 32 bits.")
    ascii_hex = f"{product_id:08x}".encode("ascii")
    return bytes(a ^ b for a, b in zip(BASE_KEY, ascii_hex))


def decompress_lzss(src):
    """TP-Link's bitstream: size endian varies; 16-bit flag words are LE."""
    if len(src) < 5:
        raise RouterError("Backup comprimido truncado.")
    sizes = [int.from_bytes(src[:4], order) for order in ("big", "little")]
    sizes = list(dict.fromkeys(n for n in sizes if 1 <= n <= MAX_XML))
    if not sizes:
        raise RouterError("Tamaño LZSS inválido o superior al límite de 4 MiB.")
    successes = []
    for size in sizes:
        pos, flags, bits_left = 5, 0, 0
        out = bytearray(src[4:5])

        def take():
            nonlocal pos
            if pos >= len(src):
                raise ValueError
            value = src[pos]
            pos += 1
            return value

        def bit():
            nonlocal flags, bits_left
            if not bits_left:
                flags = take() | (take() << 8)
                bits_left = 16
            bits_left -= 1
            return (flags >> bits_left) & 1

        def variable():
            value = 1
            for _ in range(24):
                value = (value << 1) | bit()
                if not bit():
                    return value
            raise ValueError

        try:
            while len(out) < size:
                if bit():
                    count = variable() + 2
                    high = (variable() - 2) << 8
                    distance = high + take() + 1
                    if distance > len(out) or count > size - len(out):
                        raise ValueError
                    for _ in range(count):
                        out.append(out[-distance])
                else:
                    out.append(take())
            # Only zero alignment padding may remain.
            if len(src) - pos > 7 or any(src[pos:]):
                raise ValueError
            if not out.lstrip().startswith(b"<?xml") and not out.lstrip().startswith(b"<DslCpeConfig"):
                raise ValueError
            successes.append(bytes(out))
        except (ValueError, IndexError):
            continue
    if len(successes) != 1:
        raise RouterError("LZSS truncado, corrupto o de un formato de firmware no compatible.")
    return successes[0]


def decrypt_backup(data, crypto):
    if len(data) < 24 or len(data) > MAX_RESPONSE or len(data) % 8:
        raise RouterError("La descarga no es un backup DES válido (longitud incorrecta).")
    plain = crypto.des_decrypt(derive_key(), data)
    # Authenticate the payload before decompressing or printing any values.
    payload = None
    for padding in range(8):
        if padding and plain[-padding:] != b"\0" * padding:
            continue
        candidate = plain[16:len(plain) - padding if padding else len(plain)]
        if hmac.compare_digest(plain[:16], md5(candidate)):
            payload = candidate
            break
    if payload is None:
        raise RouterError(
            "MD5 incorrecto: backup dañado o firmware/ProductID no compatible. "
            "No se mostrarán credenciales."
        )
    if payload.lstrip().startswith((b"<?xml", b"<DslCpeConfig")):
        return payload.rstrip(b"\0")
    return decompress_lzss(payload).rstrip(b"\0")


def parse_config(data):
    """Accept XML and the actual TP-Link val=bare dialect, without eval/DTD."""
    if len(data) > MAX_XML:
        raise RouterError("Configuración demasiado grande.")
    try:
        text = data.rstrip(b"\0").decode("utf-8-sig")
    except UnicodeError:
        raise RouterError("Codificación de configuración no compatible.") from None
    if re.search(r"<!\s*(?:DOCTYPE|ENTITY)", text, re.I):
        raise RouterError("Configuración con DTD/entidades no admitida.")
    try:
        return ET.fromstring(text)
    except ET.ParseError:
        pass

    def leaf(match):
        # The TP-Link dialect mixes raw characters and XML entities.
        # Decode entities once, like ElementTree does for well-formed XML.
        value = match[2] if match[2] is not None else match[3].rstrip()
        value = re.sub(
            r"&(?:#[0-9]+|#x[0-9a-fA-F]+|amp|lt|gt|quot|apos);",
            lambda entity: html.unescape(entity[0]), value,
        )
        value = html.escape(value, quote=True)
        value = value.replace("\r", "&#13;").replace("\n", "&#10;").replace("\t", "&#9;")
        return f'<{match[1]} val="{value}" />'

    text = re.sub(
        r'<([A-Za-z_][\w:.-]*)\s+val=(?:"([\s\S]*?)"|([^<>]*?))\s*/>',
        leaf, text,
    )

    def structural(match):
        tag = match[0]
        if " val=" in tag:
            return tag
        return re.sub(r'(\s[\w:.-]+)=(?!["\'])([^\s<>/]+)', r'\1="\2"', tag)

    text = re.sub(r"<[^>]+>", structural, text)
    try:
        return ET.fromstring(text)
    except ET.ParseError:
        raise RouterError("Estructura de configuración no compatible; no se imprimirá XML.") from None


def credential_groups(root):
    """Keep fields in their actual account/PPP/voice context; never guess SIP."""
    groups = {"Cuentas admin/user": [], "PPPoE": [], "VoIP / SIP": []}
    user_fields = {"username", "user", "name", "password", "role", "enable"}
    sip_fields = {
        "authusername", "authpassword", "authuserid", "username", "password",
        "uri", "directorynumber", "proxyserver", "registrarserver",
        "outboundproxy", "useragentdomain", "multiauthusername",
        "multiauthpassword", "multivoipnum", "multiproxyserver",
        "multioutboundproxy", "multiuseragentdomain", "multienable",
        "enable", "status", "multistatus",
    }

    def walk(node, path, ancestors):
        tag = node.tag.rsplit("}", 1)[-1]
        index = node.attrib.get("instance", node.attrib.get("Instance", ""))
        path = path + "/" + tag + (f"[{index}]" if index else "")
        values = {
            child.tag.rsplit("}", 1)[-1]: child.attrib.get("val", child.text or "")
            for child in node if "val" in child.attrib or (len(child) == 0 and child.text)
        }
        lower = {k.lower(): (k, v) for k, v in values.items()}
        ancestry = "/".join(ancestors + [tag]).lower()
        if tag.lower() == "x_tp_usercfg":
            picked = {k: v for k, v in values.items() if k.lower() in {
                "adminname", "adminusername", "adminpwd", "adminpwdbackup",
                "username", "userpwd", "userpwdbackup",
            }}
            if picked:
                groups["Cuentas admin/user"].append((path, picked))
        elif tag.lower() == "user" and "users" in [a.lower() for a in ancestors]:
            picked = {k: v for k, v in values.items() if k.lower() in user_fields}
            if "password" in lower or "username" in lower:
                groups["Cuentas admin/user"].append((path, picked))
        elif any(a.lower() in ("ppp", "wanpppconnection") for a in ancestors + [tag]):
            if "username" in lower or "password" in lower:
                groups["PPPoE"].append((path, {k: v for k, v in values.items()
                    if k.lower() in {"username", "password", "enable", "name",
                                     "connectiontype", "x_tp_connname"}}))
        elif any("voice" in a.lower() for a in ancestors) or tag.lower() == "sip":
            auth_fields = set(lower) & {
                "authusername", "authpassword", "authuserid", "username", "password",
                "multiauthusername", "multiauthpassword",
            }
            if auth_fields:
                groups["VoIP / SIP"].append((path, {
                    k: v for k, v in values.items() if k.lower() in sip_fields
                }))
        if len(ancestors) > 128:
            raise RouterError("Configuración excesivamente anidada.")
        for child in node:
            if len(child):
                walk(child, path, ancestors + [tag])

    walk(root, "", [])
    return groups


def display_value(value):
    if value is None or value.strip().lower() in {"", "(null)", "null", "none", "n/a"}:
        return "(no disponible)"
    if re.fullmatch(r"[*•]+", value):
        return "(oculto)"
    # Escape terminal controls (including newlines) without hiding credentials.
    return "".join(c if c.isprintable() else f"\\u{ord(c):04x}" for c in value)


def credential_summary(groups):
    """Return one account pair per service, without mixing different records."""
    def first(fields, *keys):
        return next((fields[k] for k in keys if k in fields), None)

    def choose(candidates):
        # Prefer explicitly enabled records, then complete pairs. Never silently
        # choose between distinct accounts with equal priority.
        candidates = [(pair, enabled) for pair, enabled in candidates if any(
            value is not None and value.strip().lower() not in {"", "(null)", "null", "none", "n/a"}
            for value in pair)]
        if not candidates:
            return None, None
        def rank(candidate):
            pair, enabled = candidate
            return (enabled == "1", all(
                v is not None and v.strip().lower() not in {"", "(null)", "null", "none", "n/a"}
                for v in pair))
        best = max(map(rank, candidates))
        pairs = {pair for pair, enabled in candidates if rank((pair, enabled)) == best}
        return pairs.pop() if len(pairs) == 1 else ("(varios)", "(varios)")

    admins, admin_config, ppp, sip = [], [], [], []
    for path, values in groups.get("Cuentas admin/user", []):
        fields = {k.lower(): v for k, v in values.items()}
        if path.endswith("/X_TP_UserCfg"):
            admin_config.append((
                (first(fields, "adminusername", "adminname"), fields.get("adminpwd")), None))
        else:
            username = first(fields, "username", "user", "name")
            if username and username.casefold() == "admin":
                admins.append(((username, fields.get("password")), fields.get("enable")))
    for _, values in groups.get("PPPoE", []):
        fields = {k.lower(): v for k, v in values.items()}
        ppp.append(((fields.get("username"), fields.get("password")), fields.get("enable")))
    for _, values in groups.get("VoIP / SIP", []):
        fields = {k.lower(): v for k, v in values.items()}
        for user_key, password_key in (
            ("authusername", "authpassword"), ("authuserid", "authpassword"),
            ("multiauthusername", "multiauthpassword"), ("username", "password"),
        ):
            if user_key in fields or (password_key in fields and user_key != "authuserid"):
                sip.append(((fields.get(user_key), fields.get(password_key)),
                            first(fields, "multienable", "enable")))
    return (
        choose(admins or admin_config),
        choose(ppp),
        choose(sip),
    )


def print_credentials(groups):
    for index, (label, (username, password)) in enumerate(
            zip(("Admin", "PPPoE", "SIP"), credential_summary(groups))):
        if index:
            print()
        print(f"{label} user: {display_value(username)}")
        print(f"{label} password: {display_value(password)}")


class RouterHTTP:
    """One numeric IP, direct sockets, no proxies/DNS, redirects or TLS key log."""

    def __init__(self, address):
        try:
            self.ip = ipaddress.ip_address(address)
        except ValueError:
            raise RouterError("Introduce solo una IP numérica, sin URL, nombre DNS ni puerto.") from None
        if self.ip.is_unspecified or self.ip.is_multicast or "%" in address:
            raise RouterError("La IP debe identificar un único equipo, sin zona IPv6.")
        self.address = str(self.ip)
        self.host = f"[{self.address}]" if self.ip.version == 6 else self.address
        self.scheme = "https"
        self.cookies = {}
        self.token = None

    @property
    def origin(self):
        return f"{self.scheme}://{self.host}"

    def path(self, reference, base="/"):
        if "\\" in reference or any(ord(c) < 32 or ord(c) == 127 for c in reference):
            raise RouterError("Referencia de red no válida.")
        target = urlsplit(urljoin(self.origin + base, html.unescape(reference)))
        try:
            same = ipaddress.ip_address(target.hostname or "") == self.ip
            port = target.port
        except ValueError:
            same, port = False, None
        if (not same or target.scheme != self.scheme or target.username is not None
                or target.password is not None or port not in (None, 443 if self.scheme == "https" else 80)):
            raise RouterError("Bloqueada una referencia fuera de la IP/origen introducido.")
        path = target.path or "/"
        if not path.startswith("/") or path.startswith("//"):
            raise RouterError("Ruta de red no válida.")
        return path + (("?" + target.query) if target.query else "")

    def request(self, path, method="GET", body=None, limit=MAX_RESPONSE):
        path = self.path(path)
        if method not in ("GET", "POST"):
            raise RouterError("Método HTTP no permitido.")
        port = 443 if self.scheme == "https" else 80
        sock = socket.socket(socket.AF_INET6 if self.ip.version == 6 else socket.AF_INET, socket.SOCK_STREAM)
        conn = None
        try:
            sock.settimeout(TIMEOUT)
            sock.connect((self.address, port))
            if self.scheme == "https":
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                # Deliberately do not use create_default_context (SSLKEYLOGFILE).
                sock = context.wrap_socket(sock, server_hostname=self.address)
            conn = http.client.HTTPConnection(self.address, port, timeout=TIMEOUT)
            conn.sock = sock
            headers = {
                "Host": self.host, "Referer": self.origin + "/", "Origin": self.origin,
                "User-Agent": "Mozilla/5.0", "Accept": "*/*",
                "Accept-Encoding": "identity", "Connection": "close",
                "Content-Type": "text/plain; charset=UTF-8",
            }
            if self.cookies:
                headers["Cookie"] = "; ".join(k + "=" + v for k, v in self.cookies.items())
            if self.token:
                headers["TokenID"] = self.token
            conn.request(method, path, body=body, headers=headers)
            response = conn.getresponse()
            status = response.status
            data = response.read(limit + 1)
            if len(data) > limit:
                raise RouterError("Respuesta del router superior al límite de seguridad.")
            if 300 <= status < 400:
                # No redirects, even to the same host: no accidental credential replay.
                raise RouterError("El router redirige la petición; firmware/origen no compatible.")
            if response.getheader("Content-Encoding", "identity").lower() != "identity":
                raise RouterError("Codificación HTTP no compatible.")
            for key, value in response.getheaders():
                if key.lower() == "set-cookie":
                    jar = http.cookies.SimpleCookie()
                    try:
                        jar.load(value)
                    except http.cookies.CookieError:
                        raise RouterError("Cookie de sesión no válida.") from None
                    for name, morsel in jar.items():
                        # Never use cookie domains to select a network destination.
                        self.cookies[name] = morsel.coded_value
            return status, data
        finally:
            if conn:
                conn.close()
            sock.close()

    def text(self, path, method="GET"):
        status, data = self.request(path, method)
        if status != 200:
            raise RouterError(f"El router devuelve HTTP {status}.")
        return data.decode("utf-8", "replace")

    def connect(self):
        # Only fall back before credentials exist in this object.
        try:
            return self.text("/")
        except (OSError, ssl.SSLError):
            self.scheme = "http"
            self.cookies.clear()
            return self.text("/")


class ScriptLinks(HTMLParser):
    def __init__(self, text):
        super().__init__(convert_charrefs=True)
        self.links = []
        self.feed(text)

    def handle_starttag(self, tag, attrs):
        if tag == "script":
            src = dict(attrs).get("src")
            if src:
                self.links.append(src)


def js_variable(text, name):
    match = re.search(
        r"(?<![\w$])" + re.escape(name) + r"""\s*=\s*(?:"([^"]*)"|'([^']*)'|(\d+))[ \t]*(?:;|\r|\n|$)""",
        text,
    )
    return next((v for v in match.groups() if v is not None), None) if match else None


def validate_login_sources(page, sources):
    merged = page + "\n" + "\n".join(sources.values())
    encryption = next((v for k, v in sources.items() if k.endswith("/tpEncrypt.js")), "")
    rsa_source = next((v for k, v in sources.items() if k.endswith("/encrypt.js")), "")
    proxy = next((v for k, v in sources.items() if k.endswith("/gdprProxy.js")), "")
    required = (
        "/cgi/getGDPRParm" in page, "/cgi/login" in page,
        "/cgi_gdpr?9" in proxy, "tmpcount.Passwd=$.Base64Encoding(auth)" in re.sub(r"\s+", "", page),
        "CryptoJS.mode.CBC" in encryption, "CryptoJS.pad.Pkcs7" in encryption,
        bool(re.search(r"MD5\s*\(\s*name\s*\+\s*pwd\s*\)", encryption)),
        bool(re.search(r"rsaEncrypt\([^;]*512\s*,\s*0\s*\)", encryption)),
        "$.rsa.encrypt" in rsa_source,
        js_variable(merged, "INCLUDE_LOGIN_GDPR_ENCRYPT") == "1",
    )
    if not all(required) or re.search(r"encryptOAEP|CryptoJS\.mode\.GCM", encryption):
        raise RouterError(
            "Firmware de login no compatible: no coincide con el protocolo "
            "AES-CBC/RSA verificado. No se han enviado credenciales."
        )


class SessionCipher:
    def __init__(self, crypto, modulus, exponent, seq, username, password):
        if (not re.fullmatch(r"[0-9a-fA-F]{128}", modulus)
                or not re.fullmatch(r"[0-9a-fA-F]{1,8}", exponent)
                or not re.fullmatch(r"\d{1,12}", seq)):
            raise RouterError("Parámetros RSA/secuencia no compatibles.")
        self.n, self.e, self.seq = int(modulus, 16), int(exponent, 16), int(seq)
        if self.n.bit_length() != 512 or self.e < 3 or self.e % 2 == 0:
            raise RouterError("Clave RSA no compatible.")
        self.crypto = crypto
        # Same ASCII representation as the UI, generated with a secure RNG.
        self.key = "".join(secrets.choice("0123456789") for _ in range(16)).encode("ascii")
        self.iv = "".join(secrets.choice("0123456789") for _ in range(16)).encode("ascii")
        self.hash = md5((username + password).encode("utf-8")).hex()

    def encrypt(self, data, login=False):
        raw = data.encode("utf-8")
        pad = 16 - len(raw) % 16
        encoded = base64.b64encode(self.crypto.aes(self.key, self.iv, raw + bytes([pad]) * pad)).decode("ascii")
        message = f"h={self.hash}&s={self.seq + len(encoded)}"
        if login:
            message = f"key={self.key.decode()}&iv={self.iv.decode()}&" + message
        raw = message.encode("ascii")
        signature = ""
        for offset in range(0, len(raw), 64):
            block = raw[offset:offset + 64].ljust(64, b"\0")
            number = int.from_bytes(block, "big")
            if number >= self.n:
                raise RouterError("Bloque de firma RSA inválido.")
            signature += pow(number, self.e, self.n).to_bytes(64, "big").hex()
        return f"sign={signature}\r\ndata={encoded}\r\n".encode("ascii")

    def decrypt(self, data):
        try:
            raw = base64.b64decode(data.strip(), validate=True)
            if not raw or len(raw) % 16:
                raise ValueError
            plain = self.crypto.aes(self.key, self.iv, raw, decrypt=True)
            pad = plain[-1]
            if not 1 <= pad <= 16 or plain[-pad:] != bytes([pad]) * pad:
                raise ValueError
            return plain[:-pad].decode("utf-8")
        except (ValueError, UnicodeError):
            raise RouterError("Respuesta cifrada no válida; firmware no compatible.") from None


class RouterClient:
    def __init__(self, transport, crypto):
        self.http, self.crypto = transport, crypto
        self.sources = {}
        self.cipher = None
        self.page = ""

    def collect_scripts(self, page, base="/"):
        for reference in ScriptLinks(page).links:
            path = self.http.path(reference, base)
            if path in self.sources:
                continue
            if len(self.sources) >= 64:
                raise RouterError("Demasiados recursos web; firmware no compatible.")
            # Public/authenticated JS is data, never executed.
            status, data = self.http.request(path)
            if status == 200:
                self.sources[path] = data.decode("utf-8", "replace")

    def prepare(self):
        self.page = self.http.connect()
        self.collect_scripts(self.page)
        validate_login_sources(self.page, self.sources)

    def login(self, username, password):
        if not username or not password or "\n" in username or "\r" in username:
            raise RouterError("Usuario/contraseña vacíos o usuario no válido.")
        if len(username.encode("utf-8")) > 128 or len(password.encode("utf-8")) > 128:
            raise RouterError("Credenciales demasiado largas para este protocolo.")
        params = self.http.text("/cgi/getGDPRParm", "POST")
        values = [js_variable(params, key) for key in ("nn", "ee", "seq")]
        if any(v is None for v in values):
            raise RouterError("No se recibieron los parámetros de cifrado esperados.")
        if "/cgi/getBusy" in self.page:
            busy = self.http.text("/cgi/getBusy", "POST")
            if js_variable(busy, "isLogined") == "1" or js_variable(busy, "isBusy") == "1":
                raise RouterError("Hay otra sesión abierta u ocupada. Ciérrala en el navegador y vuelve a ejecutar.")
        self.cipher = SessionCipher(self.crypto, *values, username, password)
        fields = {
            "UserName": base64.b64encode(username.encode("utf-8")).decode("ascii"),
            "Passwd": base64.b64encode(password.encode("utf-8")).decode("ascii"),
            "Action": "1", "stack": "0,0,0,0,0,0", "pstack": "0,0,0,0,0,0",
        }
        request = json.dumps({"data": fields, "operation": "cgi", "oid": "/cgi/login"}, separators=(",", ":"))
        status, response = self.http.request("/cgi_gdpr?9", "POST", self.cipher.encrypt(request, True))
        if status != 200:
            raise RouterError(f"Login rechazado (HTTP {status}); no se reintentará.")
        result = self.cipher.decrypt(response)
        ret = re.search(r"\$\.ret\s*=\s*(\d+)\s*;", result)
        if not ret:
            raise RouterError("Respuesta de login desconocida; no se reintentará.")
        code = int(ret[1])
        if code == 71233:
            raise RouterError("Usuario o contraseña incorrectos; no se reintentará.")
        if code:
            raise RouterError(f"Login rechazado por el router (código {code}); no se reintentará.")
        self.page = self.http.text("/")
        token = js_variable(self.page, "token") or js_variable(self.page, "$.tokenid")
        if not token or not re.fullmatch(r"[A-Za-z0-9_-]{8,128}", token):
            raise RouterError("No se recibió un TokenID válido tras el login.")
        self.http.token = token
        self.collect_scripts(self.page)

    def dm_get(self, oid, names):
        # These read-only objects are named in the real backup page.
        allowed = {
            "DEV2_DEV_INFO": {"modelName", "X_TP_DevModelVersion", "X_TP_BuildDate", "X_TP_BuildTime"},
            "DEV2_SYS_CFG": {"signStatus"},
        }
        if oid not in allowed or not set(names) <= allowed[oid]:
            raise RouterError("Consulta de metadatos no permitida.")
        fields = {"stack": "0,0,0,0,0,0", "pstack": "0,0,0,0,0,0"}
        fields.update({name: "" for name in names})
        request = json.dumps({"data": fields, "operation": "go", "oid": oid}, separators=(",", ":"))
        status, raw = self.http.request("/cgi_gdpr?9", "POST", self.cipher.encrypt(request))
        if status != 200:
            raise RouterError(f"No se pudieron leer los metadatos del backup (HTTP {status}).")
        try:
            result = json.loads(self.cipher.decrypt(raw))
        except ValueError:
            raise RouterError("Metadatos de backup no compatibles.") from None
        if not isinstance(result, dict) or result.get("errorcode", 0) not in (0, "0"):
            raise RouterError("El router rechazó la lectura de los metadatos del backup.")
        data = result.get("data")
        if not isinstance(data, dict) or any(not isinstance(data.get(k), (str, int)) for k in names):
            raise RouterError("Faltan metadatos necesarios para calcular el nombre del backup.")
        return {k: str(data[k]) for k in names}

    def dynamic_backup_path(self, text, docs):
        """Reproduce the formula READ from this device's backup page.

        No JavaScript execution, guessed build number, or filename probing.
        Only the DES _backupcfg variant requested by this tool is supported.
        """
        compact = re.sub(r"\s+", "", text)
        evidence = (
            'devInfo.modelName.replace(/\\s/g,"")',
            "devInfo.X_TP_DevModelVersion.slice(0,devInfo.X_TP_DevModelVersion.indexOf('.'))",
            '"/cgi/"+modelName+"V"+modelVersion+devInfo.X_TP_BuildDate+devInfo.X_TP_BuildTime+sign',
            'action=action+"_"+INCLUDE_BOOT_AGINETCONFIG_PLATFORM+"_"+INCLUDE_BOOT_AGINETCONFIG_CONFIGKEY',
            'action=action+"_backupcfg"',
        )
        if not all(item in compact for item in evidence):
            return None
        merged = "\n".join(docs.values())
        if js_variable(merged, "INCLUDE_OPTION66") != "1":
            return None
        signature_flag = js_variable(merged, "INCLUDE_DIGITAL_SIGNATURE")
        aginet_flag = js_variable(merged, "INCLUDE_BOOT_AGINETCONFIG")
        if signature_flag not in ("0", "1") or aginet_flag not in ("0", "1"):
            raise RouterError("Faltan las opciones de firmware para construir la ruta de backup.")
        if js_variable(merged, "userType") == "Admin":
            raise RouterError("Este firmware exporta otro formato para Admin. Ejecuta con la cuenta user.")
        info = self.dm_get("DEV2_DEV_INFO",
                           ("modelName", "X_TP_DevModelVersion", "X_TP_BuildDate", "X_TP_BuildTime"))
        model = re.sub(r"\s", "", info["modelName"])
        version = info["X_TP_DevModelVersion"]
        if "." not in version or not re.fullmatch(r"[A-Za-z0-9_.()-]{1,80}", model):
            raise RouterError("Modelo/versión no compatibles con la fórmula de backup.")
        major = version.split(".", 1)[0]
        date, time = info["X_TP_BuildDate"], info["X_TP_BuildTime"]
        if not all(re.fullmatch(r"\d{1,12}", v) for v in (major, date, time)):
            raise RouterError("Versión/fecha de compilación no compatibles.")
        sign = "n"
        if signature_flag == "1":
            sign = "s" if self.dm_get("DEV2_SYS_CFG", ("signStatus",))["signStatus"] != "0" else "n"
        filename = model + "V" + major + date + time + sign
        if aginet_flag == "1":
            platform = js_variable(merged, "INCLUDE_BOOT_AGINETCONFIG_PLATFORM")
            key_id = js_variable(merged, "INCLUDE_BOOT_AGINETCONFIG_CONFIGKEY")
            if not all(v and re.fullmatch(r"[A-Za-z0-9_-]{1,64}", v) for v in (platform, key_id)):
                raise RouterError("Faltan sufijos Aginet en los scripts de este firmware.")
            filename += "_" + platform + "_" + key_id
        return "/cgi/" + quote(filename + "_backupcfg.bin", safe="._-()")

    def backup_path(self):
        """Find the path in served source; never guess a model/build filename."""
        docs = {"/": self.page, **self.sources}
        seen = set(docs)
        for _ in range(4):
            paths = set()
            for base, text in docs.items():
                if "backupConf" in text and "X_TP_BuildDate" in text:
                    dynamic = self.dynamic_backup_path(text, docs)
                    if dynamic:
                        paths.add(dynamic)
                for match in re.finditer(r"""["']([^"'<>\r\n]*?/cgi/[^"'<>\r\n]*?_backupcfg\.bin)["']""", text):
                    paths.add(self.http.path(match[1], base))
                for match in re.finditer(r"""["'](/cgi/[^"'<>\r\n]*?_backupcfg\.bin)["']""", text):
                    paths.add(self.http.path(match[1], base))
            if len(paths) == 1:
                return paths.pop()
            if len(paths) > 1:
                raise RouterError("El firmware publica varias rutas de backup; no se elegirá una al azar.")
            candidates = set()
            if "/main/backNRestore.htm" not in seen:
                # Actual page read and verified on the user's XGB430v Pro.
                candidates.add("/main/backNRestore.htm")
            main_prefix = any(re.search(r"""["']\./main/["']\s*\+""", t) for t in docs.values())
            for base, text in docs.items():
                # Only follow literal JS/HTML references relevant to menus or backups.
                for match in re.finditer(r"""["']([^"'<> \r\n]+\.(?:js|htm|html))["']""", text):
                    ref = match[1]
                    if not re.search(r"menu|backup|backnrestore|restore|frame", ref, re.I):
                        continue
                    if "/" not in ref and ref.endswith((".htm", ".html")) and main_prefix:
                        ref = "/main/" + ref
                    path = self.http.path(ref, base)
                    if path not in seen:
                        candidates.add(path)
            if not candidates:
                break
            for path in sorted(candidates):
                if len(seen) >= 96:
                    raise RouterError("Demasiadas referencias al buscar la página de backup.")
                seen.add(path)
                status, data = self.http.request(path)
                if status == 200:
                    docs[path] = data.decode("utf-8", "replace")
        raise RouterError("No se reconoce la ruta/fórmula de backup de este firmware. No se probarán nombres inventados.")

    def download_backup(self):
        path = self.backup_path()
        status, data = self.http.request(path)
        if status in (401, 403):
            raise RouterError("La cuenta no tiene permiso para descargar el backup.")
        if status != 200:
            raise RouterError(f"No se pudo descargar el backup (HTTP {status}).")
        if data.lstrip().lower().startswith((b"<!doctype", b"<html", b"<script")):
            raise RouterError("El router devolvió una página web en lugar del backup; sesión o permisos insuficientes.")
        return data

    def logout(self):
        if not self.http.token or not self.cipher:
            return
        try:
            request = json.dumps({
                "data": {"stack": "0,0,0,0,0,0", "pstack": "0,0,0,0,0,0"},
                "operation": "cgi", "oid": "/cgi/logout",
            }, separators=(",", ":"))
            status, _ = self.http.request("/cgi_gdpr?9", "POST", self.cipher.encrypt(request))
            if status != 200:
                print("No se ha podido confirmar el cierre de sesión.")
        except (RouterError, OSError, http.client.HTTPException):
            print("No se ha podido confirmar el cierre de sesión.")
        finally:
            self.http.cookies.clear()
            self.http.token = None
            self.cipher = None


def main():
    if len(sys.argv) != 1:
        raise RouterError("Este programa no acepta parámetros. Ejecútalo sin flags.")
    crypto = check_requirements()
    print("TP-Link XGB430v Pro ESDIGI — lectura local, sin guardar archivos.")
    address = input("IP del router: ").strip()
    transport = RouterHTTP(address)
    client = RouterClient(transport, crypto)
    print("Comprobando el protocolo de acceso del router...")
    client.prepare()
    username = input("Usuario: ").strip()
    # getpass must never silently fall back to an echoed password.
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        try:
            password = getpass.getpass("Contraseña: ")
        except getpass.GetPassWarning:
            raise RouterError("No hay terminal seguro para getpass. Abre una consola interactiva.") from None
    print("Iniciando sesión...")
    try:
        client.login(username, password)
        del password
        print("Descargando y verificando el backup en memoria...")
        backup = client.download_backup()
        xml = decrypt_backup(backup, crypto)
        root = parse_config(xml)
        groups = credential_groups(root)
        del backup, xml, root
        print_credentials(groups)
    finally:
        client.logout()


def run():
    try:
        main()
        return 0
    except (KeyboardInterrupt, EOFError):
        print("\nCancelado.")
        return 130
    except RouterError as error:
        print(f"\nError: {error}", file=sys.stderr)
        return 1
    except (OSError, ssl.SSLError, http.client.HTTPException):
        print("\nError de conexión con la IP introducida. Comprueba la red y el acceso web.", file=sys.stderr)
        return 1
    except Exception:
        # No tracebacks that could expose secrets from a third-party exception.
        print("\nError inesperado; operación cancelada sin guardar datos.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(run())
