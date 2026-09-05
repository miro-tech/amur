#!/usr/bin/env python3

import os
import re
import json
import base64
import urllib.parse
import requests

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad


# ============================================================
# SETTINGS
# ============================================================

API_URL = "https://amur-managev1-xyz.translate.goog/api/protocols"

OUTPUT_DIR = "plusvpn"

ASHO_FILE = os.path.join(
    OUTPUT_DIR,
    "asho.txt"
)

JSON_DIR = os.path.join(
    OUTPUT_DIR,
    "json"
)

FAILED_DIR = os.path.join(
    OUTPUT_DIR,
    "failed"
)

FAILED_FILE = os.path.join(
    OUTPUT_DIR,
    "failed.txt"
)


# ============================================================
# DIRECTORIES
# ============================================================

os.makedirs(
    OUTPUT_DIR,
    exist_ok=True
)

os.makedirs(
    JSON_DIR,
    exist_ok=True
)

os.makedirs(
    FAILED_DIR,
    exist_ok=True
)


# ============================================================
# AES KEY
# ============================================================

def get_key(key_string):

    key = key_string.encode(
        "utf-8"
    )

    if len(key) < 16:

        key = key.ljust(
            16,
            b"\0"
        )

    elif len(key) > 16:

        key = key[:16]

    return key


# ============================================================
# BASE64 DECODER
# ============================================================

def decode_base64_flexible(value):

    if value is None:

        raise ValueError(
            "Base64 value is None"
        )

    value = str(value).strip()

    value = value.lstrip(
        "\ufeff"
    )

    # Remove whitespace
    value = re.sub(
        r"\s+",
        "",
        value
    )

    # Unicode look-alikes
    value = (
        value
        .replace("＋", "+")
        .replace("／", "/")
        .replace("＿", "_")
        .replace("－", "-")
        .replace("＝", "=")
    )

    # --------------------------------------------------------
    # URL percent decoding
    # --------------------------------------------------------

    try:

        decoded_url = urllib.parse.unquote(
            value
        )

        if decoded_url:

            value = decoded_url

    except Exception:

        pass

    # --------------------------------------------------------
    # ASCII Base64
    # --------------------------------------------------------

    try:

        ascii_value = value.encode(
            "ascii"
        ).decode(
            "ascii"
        )

    except UnicodeEncodeError:

        # Try to remove non-ASCII characters
        # ONLY from Base64 noise.
        ascii_value = "".join(
            c for c in value
            if ord(c) < 128
        )

    # --------------------------------------------------------
    # Candidate #1: URL-safe
    # --------------------------------------------------------

    normalized = (
        ascii_value
        .replace("-", "+")
        .replace("_", "/")
    )

    normalized += "=" * (
        -len(normalized) % 4
    )

    try:

        return base64.b64decode(
            normalized,
            validate=True
        )

    except Exception:

        pass

    # --------------------------------------------------------
    # Candidate #2: standard Base64
    # --------------------------------------------------------

    cleaned = re.sub(
        r"[^A-Za-z0-9+/=]",
        "",
        ascii_value
    )

    cleaned += "=" * (
        -len(cleaned) % 4
    )

    try:

        return base64.b64decode(
            cleaned,
            validate=False
        )

    except Exception:

        pass

    # --------------------------------------------------------
    # Candidate #3: urlsafe
    # --------------------------------------------------------

    try:

        return base64.urlsafe_b64decode(
            ascii_value
            + "=" * (
                -len(ascii_value) % 4
            )
        )

    except Exception as e:

        raise ValueError(
            "Unable to decode Base64: "
            + str(e)
        )


# ============================================================
# AES DECRYPT
# ============================================================

def decrypt_value(
    value,
    record_id
):

    key = get_key(
        f"key_{record_id}"
    )

    encrypted = decode_base64_flexible(
        value
    )

    if not encrypted:

        raise ValueError(
            "Decoded ciphertext is empty"
        )

    if len(encrypted) % 16 != 0:

        raise ValueError(
            "AES ciphertext length "
            f"{len(encrypted)} is not multiple of 16"
        )

    cipher = AES.new(
        key,
        AES.MODE_CBC,
        iv=key
    )

    decrypted = cipher.decrypt(
        encrypted
    )

    try:

        decrypted = unpad(
            decrypted,
            AES.block_size
        )

    except ValueError:

        pass

    return decrypted.decode(
        "utf-8",
        errors="ignore"
    ).strip().lstrip(
        "\ufeff"
    )


# ============================================================
# DEFAULT CONFIG
# ============================================================

def base_config():

    return {

        "remarks": "@shenvpn",

        "log": {
            "loglevel": "warning"
        },

        "dns": {

            "hosts": {},

            "servers": [
                {
                    "address": "1.1.1.1",
                    "domains": [
                        "geosite:geolocation-!cn"
                    ]
                },
                "8.8.8.8"
            ]
        },

        "fakedns": [
            {
                "ipPool": "198.18.0.0/15",
                "poolSize": 65535
            }
        ],

        "inbounds": [

            {
                "listen": "127.0.0.1",
                "port": 10808,
                "protocol": "socks",
                "settings": {
                    "auth": "noauth",
                    "udp": True
                },
                "sniffing": {
                    "destOverride": [
                        "http",
                        "tls",
                        "quic"
                    ],
                    "enabled": True,
                    "routeOnly": False
                }
            },

            {
                "listen": "127.0.0.1",
                "port": 10809,
                "protocol": "http",
                "settings": {}
            }
        ],

        "outbounds": [],

        "policy": {

            "levels": {

                "8": {

                    "connIdle": 300,
                    "downlinkOnly": 1,
                    "handshake": 4,
                    "uplinkOnly": 1
                }
            },

            "system": {

                "statsInboundDownlink": True,
                "statsInboundUplink": True
            }
        },

        "routing": {

            "domainStrategy": "AsIs",

            "rules": [

                {
                    "ip": [
                        "geoip:private"
                    ],
                    "outboundTag": "direct"
                },

                {
                    "domain": [
                        "geosite:category-ads-all"
                    ],
                    "outboundTag": "block"
                }
            ]
        }
    }


# ============================================================
# FINISH CONFIG
# ============================================================

def finish_config(
    config,
    proxy
):

    config.setdefault(
        "outbounds",
        []
    )

    config["outbounds"].append(
        proxy
    )

    config["outbounds"].append(
        {
            "protocol": "freedom",
            "tag": "direct"
        }
    )

    config["outbounds"].append(
        {
            "protocol": "dns",
            "tag": "dns-out"
        }
    )

    config["outbounds"].append(
        {
            "protocol": "blackhole",
            "tag": "block"
        }
    )

    return config


# ============================================================
# VLESS
# ============================================================

def vless_to_json(uri):

    parsed = urllib.parse.urlsplit(
        uri
    )

    if not parsed.hostname:

        raise ValueError(
            "VLESS hostname missing"
        )

    if not parsed.port:

        raise ValueError(
            "VLESS port missing"
        )

    uuid = urllib.parse.unquote(
        parsed.username or ""
    )

    if not uuid:

        raise ValueError(
            "VLESS UUID missing"
        )

    q = urllib.parse.parse_qs(
        parsed.query,
        keep_blank_values=True
    )

    def get(
        name,
        default=""
    ):

        value = q.get(
            name
        )

        if not value:

            return default

        return value[0]

    network = get(
        "type",
        "tcp"
    )

    security = get(
        "security",
        ""
    )

    stream = {
        "network": network
    }

    # TLS
    if security == "tls":

        stream["security"] = "tls"

        tls = {}

        sni = get(
            "sni"
        )

        if sni:

            tls["serverName"] = sni

        fp = get(
            "fp"
        )

        if fp:

            tls["fingerprint"] = fp

        alpn = get(
            "alpn"
        )

        if alpn:

            tls["alpn"] = [
                x.strip()
                for x in alpn.split(",")
                if x.strip()
            ]

        stream[
            "tlsSettings"
        ] = tls

    # Reality
    elif security == "reality":

        stream["security"] = "reality"

        reality = {}

        sni = get(
            "sni"
        )

        if sni:

            reality[
                "serverName"
            ] = sni

        fp = get(
            "fp"
        )

        if fp:

            reality[
                "fingerprint"
            ] = fp

        pbk = get(
            "pbk"
        )

        if pbk:

            reality[
                "publicKey"
            ] = pbk

        sid = get(
            "sid"
        )

        if sid:

            reality[
                "shortId"
            ] = sid

        spx = get(
            "spx"
        )

        if spx:

            reality[
                "spiderX"
            ] = spx

        stream[
            "realitySettings"
        ] = reality

    # WS
    if network == "ws":

        ws = {}

        path = get(
            "path"
        )

        if path:

            ws["path"] = path

        host = get(
            "host"
        )

        if host:

            ws["headers"] = {
                "Host": host
            }

        stream[
            "wsSettings"
        ] = ws

    # gRPC
    elif network == "grpc":

        grpc = {}

        service = get(
            "serviceName"
        )

        if service:

            grpc[
                "serviceName"
            ] = service

        mode = get(
            "mode"
        )

        if mode:

            grpc[
                "multiMode"
            ] = (
                mode.lower() == "multi"
            )

        stream[
            "grpcSettings"
        ] = grpc

    # HTTP
    elif network == "http":

        stream[
            "httpSettings"
        ] = {

            "path": get(
                "path",
                "/"
            ),

            "host": (
                [get("host")]
                if get("host")
                else []
            )
        }

    # TCP
    elif network == "tcp":

        header_type = get(
            "headerType"
        )

        if header_type:

            stream[
                "tcpSettings"
            ] = {

                "header": {

                    "type": header_type
                }
            }

    user = {

        "id": uuid,

        "encryption": get(
            "encryption",
            "none"
        )
    }

    flow = get(
        "flow"
    )

    if flow:

        user["flow"] = flow

    proxy = {

        "protocol": "vless",

        "settings": {

            "vnext": [

                {

                    "address":
                        parsed.hostname,

                    "port":
                        parsed.port,

                    "users": [
                        user
                    ]
                }
            ]
        },

        "streamSettings": stream,

        "tag": "proxy"
    }

    return finish_config(
        base_config(),
        proxy
    )


# ============================================================
# VMESS
# ============================================================

def vmess_decode_payload(
    payload
):

    payload = payload.strip()

    payload = urllib.parse.unquote(
        payload
    )

    payload += "=" * (
        -len(payload) % 4
    )

    try:

        raw = base64.b64decode(
            payload
        )

    except Exception:

        raw = base64.urlsafe_b64decode(
            payload
        )

    return json.loads(
        raw.decode(
            "utf-8-sig"
        )
    )


def vmess_to_json(uri):

    payload = uri[
        len("vmess://"):
    ].strip()

    data = vmess_decode_payload(
        payload
    )

    address = (
        data.get("add")
        or data.get("address")
        or data.get("host")
    )

    if not address:

        raise ValueError(
            "VMess address missing"
        )

    port = int(
        data.get(
            "port",
            443
        )
    )

    uuid = (
        data.get("id")
        or data.get("uuid")
    )

    if not uuid:

        raise ValueError(
            "VMess UUID missing"
        )

    network = data.get(
        "net",
        "tcp"
    )

    stream = {
        "network": network
    }

    tls = str(
        data.get(
            "tls",
            ""
        )
    ).lower()

    sni = (
        data.get("sni")
        or data.get("host")
        or ""
    )

    if tls in (
        "tls",
        "true",
        "1"
    ):

        stream["security"] = "tls"

        tls_settings = {}

        if sni:

            tls_settings[
                "serverName"
            ] = sni

        alpn = data.get(
            "alpn"
        )

        if alpn:

            if isinstance(
                alpn,
                str
            ):

                alpn = [
                    x.strip()
                    for x in alpn.split(",")
                    if x.strip()
                ]

            tls_settings[
                "alpn"
            ] = alpn

        stream[
            "tlsSettings"
        ] = tls_settings

    if network == "ws":

        ws = {

            "path": data.get(
                "path",
                "/"
            )
        }

        host = (
            data.get("host")
            or data.get("Host")
            or ""
        )

        if host:

            ws[
                "headers"
            ] = {
                "Host": host
            }

        stream[
            "wsSettings"
        ] = ws

    elif network == "grpc":

        stream[
            "grpcSettings"
        ] = {

            "serviceName":
                data.get(
                    "path",
                    data.get(
                        "serviceName",
                        ""
                    )
                )
        }

    proxy = {

        "protocol": "vmess",

        "settings": {

            "vnext": [

                {

                    "address": address,

                    "port": port,

                    "users": [

                        {

                            "id": uuid,

                            "alterId": int(
                                data.get(
                                    "aid",
                                    0
                                )
                            ),

                            "security": data.get(
                                "scy",
                                "auto"
                            )
                        }
                    ]
                }
            ]
        },

        "streamSettings": stream,

        "tag": "proxy"
    }

    return finish_config(
        base_config(),
        proxy
    )


# ============================================================
# TROJAN
# ============================================================

def trojan_to_json(uri):

    parsed = urllib.parse.urlsplit(
        uri
    )

    if not parsed.hostname:

        raise ValueError(
            "Trojan hostname missing"
        )

    if not parsed.port:

        raise ValueError(
            "Trojan port missing"
        )

    password = urllib.parse.unquote(
        parsed.username or ""
    )

    if not password:

        raise ValueError(
            "Trojan password missing"
        )

    q = urllib.parse.parse_qs(
        parsed.query,
        keep_blank_values=True
    )

    def get(
        name,
        default=""
    ):

        values = q.get(
            name
        )

        if not values:

            return default

        return values[0]

    network = get(
        "type",
        "tcp"
    )

    security = get(
        "security",
        "tls"
    )

    stream = {
        "network": network
    }

    if security == "tls":

        stream[
            "security"
        ] = "tls"

        tls = {}

        sni = get(
            "sni"
        )

        if sni:

            tls[
                "serverName"
            ] = sni

        fp = get(
            "fp"
        )

        if fp:

            tls[
                "fingerprint"
            ] = fp

        stream[
            "tlsSettings"
        ] = tls

    elif security == "reality":

        stream[
            "security"
        ] = "reality"

        reality = {}

        sni = get(
            "sni"
        )

        if sni:

            reality[
                "serverName"
            ] = sni

        fp = get(
            "fp"
        )

        if fp:

            reality[
                "fingerprint"
            ] = fp

        pbk = get(
            "pbk"
        )

        if pbk:

            reality[
                "publicKey"
            ] = pbk

        sid = get(
            "sid"
        )

        if sid:

            reality[
                "shortId"
            ] = sid

        stream[
            "realitySettings"
        ] = reality

    if network == "ws":

        ws = {

            "path": get(
                "path",
                "/"
            )
        }

        host = get(
            "host"
        )

        if host:

            ws[
                "headers"
            ] = {
                "Host": host
            }

        stream[
            "wsSettings"
        ] = ws

    elif network == "grpc":

        stream[
            "grpcSettings"
        ] = {

            "serviceName":
                get(
                    "serviceName"
                )
        }

    proxy = {

        "protocol": "trojan",

        "settings": {

            "servers": [

                {

                    "address":
                        parsed.hostname,

                    "port":
                        parsed.port,

                    "password":
                        password
                }
            ]
        },

        "streamSettings": stream,

        "tag": "proxy"
    }

    return finish_config(
        base_config(),
        proxy
    )


# ============================================================
# SHADOWSOCKS
# ============================================================

def decode_ss_credentials(credentials):

    credentials = urllib.parse.unquote(
        credentials
    ).strip()

    # Remove possible surrounding whitespace
    credentials = credentials.strip()

    # --------------------------------------------------------
    # Case 1:
    # raw method:password
    # --------------------------------------------------------

    if ":" in credentials:

        left, right = credentials.split(
            ":",
            1
        )

        # Method names normally contain ASCII
        # characters. Password may contain Unicode.
        if re.match(
            r"^[A-Za-z0-9._-]+$",
            left
        ):

            if right:

                return (
                    left,
                    right
                )

    # --------------------------------------------------------
    # Case 2:
    # Base64(method:password)
    # --------------------------------------------------------

    candidates = []

    candidates.append(
        credentials
    )

    # URL decode again in case of double encoding
    try:

        candidates.append(
            urllib.parse.unquote(
                credentials
            )
        )

    except Exception:

        pass

    for candidate in candidates:

        # Base64 must be ASCII
        try:

            ascii_candidate = candidate.encode(
                "ascii"
            ).decode(
                "ascii"
            )

        except UnicodeEncodeError:

            continue

        for decoder in (
            base64.b64decode,
            base64.urlsafe_b64decode
        ):

            try:

                padded = ascii_candidate + "=" * (
                    -len(ascii_candidate) % 4
                )

                raw = decoder(
                    padded
                )

                text = raw.decode(
                    "utf-8"
                )

                if ":" in text:

                    method, password = text.split(
                        ":",
                        1
                    )

                    if method and password:

                        return (
                            method,
                            password
                        )

            except Exception:

                continue

    raise ValueError(
        "Unable to decode Shadowsocks credentials"
    )


def ss_to_json(uri):

    parsed = urllib.parse.urlsplit(
        uri
    )

    if not parsed.hostname:

        raise ValueError(
            "SS hostname missing"
        )

    if not parsed.port:

        raise ValueError(
            "SS port missing"
        )

    # --------------------------------------------------------
    # Get raw userinfo safely
    # --------------------------------------------------------

    raw_before_at = uri.split(
        "://",
        1
    )[1]

    raw_before_at = raw_before_at.split(
        "@",
        1
    )[0]

    credentials = raw_before_at

    if not credentials:

        raise ValueError(
            "SS credentials missing"
        )

    method, password = decode_ss_credentials(
        credentials
    )

    proxy = {

        "protocol": "shadowsocks",

        "settings": {

            "servers": [

                {

                    "address":
                        parsed.hostname,

                    "port":
                        parsed.port,

                    "method":
                        method,

                    "password":
                        password
                }
            ]
        },

        "tag": "proxy"
    }

    return finish_config(
        base_config(),
        proxy
    )


# ============================================================
# JSON
# ============================================================

def parse_json_config(text):

    text = text.strip().lstrip(
        "\ufeff"
    )

    obj = json.loads(
        text
    )

    if isinstance(
        obj,
        dict
    ):

        return obj

    if isinstance(
        obj,
        list
    ):

        return obj

    raise ValueError(
        "JSON root is not object/array"
    )


# ============================================================
# URI DETECTION
# ============================================================

URI_PATTERN = re.compile(
    r"(vless|vmess|trojan|ss)://[^\s]+",
    re.IGNORECASE
)


def extract_uri(text):

    text = text.strip().lstrip(
        "\ufeff"
    )

    if re.match(
        r"^(vless|vmess|trojan|ss)://",
        text,
        re.IGNORECASE
    ):

        return text

    match = URI_PATTERN.search(
        text
    )

    if match:

        return match.group(
            0
        ).strip()

    return None


# ============================================================
# CONVERT RECORD
# ============================================================

def convert_record(record):

    record_id = record.get(
        "id"
    )

    value = record.get(
        "value"
    )

    if value is None:

        raise ValueError(
            "Record has no value"
        )

    decrypted = decrypt_value(
        value,
        record_id
    )

    if not decrypted:

        raise ValueError(
            "Decrypted value is empty"
        )

    stripped = decrypted.strip()

    # JSON
    if stripped.startswith(
        "{"
    ) or stripped.startswith(
        "["
    ):

        return (
            parse_json_config(
                stripped
            ),
            "JSON",
            decrypted
        )

    # URI
    uri = extract_uri(
        stripped
    )

    if not uri:

        raise ValueError(
            "Unknown decrypted format: "
            + repr(
                stripped[:300]
            )
        )

    scheme = uri.split(
        ":",
        1
    )[0].lower()

    if scheme == "vless":

        return (
            vless_to_json(uri),
            "VLESS",
            decrypted
        )

    if scheme == "vmess":

        return (
            vmess_to_json(uri),
            "VMess",
            decrypted
        )

    if scheme == "trojan":

        return (
            trojan_to_json(uri),
            "Trojan",
            decrypted
        )

    if scheme == "ss":

        return (
            ss_to_json(uri),
            "SS",
            decrypted
        )

    raise ValueError(
        "Unsupported URI: "
        + scheme
    )


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 60)
    print("MELIV2ME → NekoBox JSON")
    print("=" * 60)

    print()
    print(
        "GET:",
        API_URL
    )

    response = requests.get(
        API_URL,
        timeout=30
    )

    response.raise_for_status()

    data = response.json()

    if isinstance(
        data,
        list
    ):

        records = data

    elif isinstance(
        data,
        dict
    ):

        records = (
            data.get("data")
            or data.get("protocols")
            or data.get("results")
            or []
        )

    else:

        raise ValueError(
            "Unexpected API response"
        )

    print(
        "Total API records:",
        len(records)
    )

    print()

    profiles = []

    stats = {

        "JSON": 0,
        "VLESS": 0,
        "VMess": 0,
        "Trojan": 0,
        "SS": 0,
        "FAILED": 0
    }

    failed_records = []

    # --------------------------------------------------------
    # PROCESS
    # --------------------------------------------------------

    for index, record in enumerate(
        records,
        1
    ):

        record_id = record.get(
            "id",
            "unknown"
        )

        decrypted = ""

        try:

            config, kind, decrypted = convert_record(
                record
            )

            profiles.append(
                config
            )

            stats[kind] += 1

            individual_file = os.path.join(
                JSON_DIR,
                f"config_{index:03d}.json"
            )

            with open(
                individual_file,
                "w",
                encoding="utf-8"
            ) as f:

                json.dump(
                    config,
                    f,
                    ensure_ascii=False,
                    indent=2
                )

            print(
                f"[OK {index:03d}] "
                f"id={record_id} "
                f"{kind}"
            )

        except Exception as e:

            stats["FAILED"] += 1

            error = str(e)

            failed_records.append(
                {
                    "index": index,
                    "id": record_id,
                    "error": error
                }
            )

            print()
            print(
                f"[FAILED {index:03d}] "
                f"id={record_id}: "
                f"{error}"
            )

            # ------------------------------------------------
            # Save raw record
            # ------------------------------------------------

            failed_json = os.path.join(
                FAILED_DIR,
                f"record_{index:03d}.json"
            )

            try:

                with open(
                    failed_json,
                    "w",
                    encoding="utf-8"
                ) as f:

                    json.dump(
                        record,
                        f,
                        ensure_ascii=False,
                        indent=2
                    )

            except Exception:
                pass

            # ------------------------------------------------
            # Try AES decrypt for diagnostics
            # ------------------------------------------------

            try:

                decrypted = decrypt_value(
                    record.get(
                        "value"
                    ),
                    record_id
                )

            except Exception as decrypt_error:

                decrypted = (
                    "[DECRYPT ERROR] "
                    + str(decrypt_error)
                )

            failed_txt = os.path.join(
                FAILED_DIR,
                f"record_{index:03d}.txt"
            )

            try:

                with open(
                    failed_txt,
                    "w",
                    encoding="utf-8"
                ) as f:

                    f.write(
                        "INDEX:\n"
                    )

                    f.write(
                        str(index)
                    )

                    f.write(
                        "\n\nID:\n"
                    )

                    f.write(
                        str(record_id)
                    )

                    f.write(
                        "\n\nERROR:\n"
                    )

                    f.write(
                        error
                    )

                    f.write(
                        "\n\nRAW VALUE:\n"
                    )

                    f.write(
                        str(
                            record.get(
                                "value",
                                ""
                            )
                        )
                    )

                    f.write(
                        "\n\nDECRYPTED:\n"
                    )

                    f.write(
                        decrypted
                    )

            except Exception:
                pass

    # ========================================================
    # ASHO
    # ========================================================

    print()
    print("=" * 60)
    print("WRITING ASHO")
    print("=" * 60)

    with open(
        ASHO_FILE,
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            profiles,
            f,
            ensure_ascii=False,
            indent=2
        )

        f.write(
            "\n"
        )

    # ========================================================
    # FAILED LOG
    # ========================================================

    with open(
        FAILED_FILE,
        "w",
        encoding="utf-8"
    ) as f:

        for item in failed_records:

            f.write(
                f"Record {item['index']}: "
                f"{item['error']}\n"
            )

    # ========================================================
    # VALIDATE
    # ========================================================

    valid = False

    try:

        with open(
            ASHO_FILE,
            "r",
            encoding="utf-8"
        ) as f:

            loaded = json.load(
                f
            )

        valid = isinstance(
            loaded,
            list
        )

    except Exception as e:

        print(
            "ASHO VALIDATION ERROR:",
            e
        )

    # ========================================================
    # SUMMARY
    # ========================================================

    print()
    print("=" * 60)
    print("SUMMARY")
    print("=" * 60)

    print(
        "API records:",
        len(records)
    )

    print(
        "Original JSON:",
        stats["JSON"]
    )

    print(
        "VLESS → JSON:",
        stats["VLESS"]
    )

    print(
        "VMess → JSON:",
        stats["VMess"]
    )

    print(
        "Trojan → JSON:",
        stats["Trojan"]
    )

    print(
        "SS → JSON:",
        stats["SS"]
    )

    print(
        "Failed:",
        stats["FAILED"]
    )

    print(
        "Profiles in ASHO:",
        len(profiles)
    )

    print(
        "ASHO JSON array:",
        "YES" if valid else "NO"
    )

    print()

    print(
        "Output:",
        ASHO_FILE
    )

    print(
        "Individual JSON:",
        JSON_DIR
    )

    print(
        "Failed records:",
        FAILED_DIR
    )

    print(
        "Failed log:",
        FAILED_FILE
    )

    print()

    if len(profiles) == len(records):

        print(
            "SUCCESS: "
            "ALL API RECORDS CONVERTED."
        )

    else:

        print(
            "WARNING: "
            f"{len(records) - len(profiles)} "
            "records were not converted."
        )

    print("=" * 60)


# ============================================================
# RUN
# ============================================================

if __name__ == "__main__":

    main()
