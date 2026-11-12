import re
from base64 import b64decode
from base64 import b64encode
from secrets import token_bytes
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup
from requests import Session
from requests.exceptions import RequestException

from .SSO_error import BackendError

RSA_PADDING_OVERHEAD = 11
SSO_ORIGIN = "https://pass.neu.edu.cn"
KEY_SCRIPT_LIMIT = 8
PUBLIC_KEY_PATTERN = re.compile(r'publicKeyStr\s*=\s*["\']([^"\']+)["\']')


def _is_cas_url(url: str) -> bool:
    parsed = urlparse(url)
    try:
        port = parsed.port
    except ValueError:
        return False
    return parsed.scheme == "https" and parsed.hostname == "pass.neu.edu.cn" and port in (None, 443)


def _script_name(src: str) -> str:
    path = src.split("?", 1)[0]
    return path.rsplit("/", 1)[-1] or src


def _script_priority(src: str) -> int:
    lowered = src.lower()
    if "login_neu" in lowered:
        return 0
    if "login" in lowered:
        return 1
    if "rsa" in lowered:
        return 2
    return 3


def _usable_public_key(text: str):
    match = PUBLIC_KEY_PATTERN.search(text)
    if not match:
        return None
    key = match.group(1)
    try:
        _decode_rsa_public_key(key)
    except Exception:
        return None
    return key


def extract_login_page_rsa_public_key(session: Session, page_soup: BeautifulSoup) -> str:
    # The key may be inline, or it may move between versioned scripts.
    for script_tag in page_soup.find_all("script"):
        if script_tag.get("src"):
            continue
        key = _usable_public_key(script_tag.get_text() or "")
        if key:
            return key

    scripts = []
    seen = set()
    for script_tag in page_soup.find_all("script", src=True):
        src = (script_tag.get("src") or "").strip()
        if not src or src in seen:
            continue
        seen.add(src)
        scripts.append(src)
    scripts.sort(key=_script_priority)

    attempts = []
    for src in scripts[:KEY_SCRIPT_LIMIT]:
        name = _script_name(src)
        script_url = urljoin(SSO_ORIGIN + "/", src)
        if not _is_cas_url(script_url):
            if "login" in src.lower():
                raise BackendError("SSO login script points to an untrusted origin: " + src)
            attempts.append(name + ": cross-origin")
            continue
        try:
            response = session.get(script_url)
        except RequestException as error:
            attempts.append(name + ": " + str(error))
            continue
        status = getattr(response, "status_code", 200)
        if status >= 400:
            attempts.append(name + ": HTTP " + str(status))
            continue
        key = _usable_public_key(response.text)
        if key:
            return key
        attempts.append(name + ": no usable publicKeyStr")

    title_tag = page_soup.find("title")
    title = title_tag.get_text(strip=True) if title_tag else ""
    context = " (page title: " + title + ")" if title else ""
    if attempts:
        raise BackendError(
            "cannot find a usable RSA public key from SSO login page: "
            + "; ".join(attempts)
            + context
        )
    raise BackendError("cannot find SSO login script or RSA public key" + context)


def _read_der_tlv(der_bytes: bytes, offset: int):
    if offset >= len(der_bytes):
        raise ValueError("invalid DER: unexpected end of data")
    tag = der_bytes[offset]
    offset += 1
    if offset >= len(der_bytes):
        raise ValueError("invalid DER: missing length")
    first_length = der_bytes[offset]
    offset += 1
    if first_length & 0x80:
        length_bytes_count = first_length & 0x7F
        if length_bytes_count == 0 or offset + length_bytes_count > len(der_bytes):
            raise ValueError("invalid DER: bad long-form length")
        length = int.from_bytes(der_bytes[offset:offset + length_bytes_count], "big")
        offset += length_bytes_count
    else:
        length = first_length
    if offset + length > len(der_bytes):
        raise ValueError("invalid DER: value out of bounds")
    value = der_bytes[offset:offset + length]
    return tag, value, offset + length


def _decode_rsa_public_key(public_key_b64: str):
    spki_der = b64decode(public_key_b64)
    seq_tag, spki_seq, seq_end = _read_der_tlv(spki_der, 0)
    if seq_tag != 0x30 or seq_end != len(spki_der):
        raise ValueError("invalid SubjectPublicKeyInfo structure")

    _, _, cursor = _read_der_tlv(spki_seq, 0)
    bit_string_tag, bit_string_value, cursor = _read_der_tlv(spki_seq, cursor)
    if bit_string_tag != 0x03 or not bit_string_value or bit_string_value[0] != 0:
        raise ValueError("invalid SubjectPublicKeyInfo BIT STRING")
    if cursor != len(spki_seq):
        raise ValueError("invalid SubjectPublicKeyInfo trailing bytes")

    rsa_der = bit_string_value[1:]
    rsa_seq_tag, rsa_seq, rsa_end = _read_der_tlv(rsa_der, 0)
    if rsa_seq_tag != 0x30 or rsa_end != len(rsa_der):
        raise ValueError("invalid RSAPublicKey structure")
    modulus_tag, modulus_bytes, cursor = _read_der_tlv(rsa_seq, 0)
    exponent_tag, exponent_bytes, cursor = _read_der_tlv(rsa_seq, cursor)
    if modulus_tag != 0x02 or exponent_tag != 0x02 or cursor != len(rsa_seq):
        raise ValueError("invalid RSAPublicKey fields")

    modulus = int.from_bytes(modulus_bytes, "big")
    exponent = int.from_bytes(exponent_bytes, "big")
    key_bytes = len(modulus_bytes) - 1 if modulus_bytes.startswith(b"\x00") else len(modulus_bytes)
    return modulus, exponent, key_bytes


def rsa_encrypt_username_password(username: str, password: str, public_key_b64: str) -> str:
    modulus, exponent, key_bytes = _decode_rsa_public_key(public_key_b64)
    plaintext = (username + password).encode("utf-8")
    max_plaintext_len = key_bytes - RSA_PADDING_OVERHEAD
    if len(plaintext) > max_plaintext_len:
        raise ValueError("username+password is too long for RSA key size")

    padding_len = key_bytes - len(plaintext) - 3
    padding = b""
    while len(padding) < padding_len:
        block = token_bytes(padding_len - len(padding))
        padding += block.replace(b"\x00", b"")
    encoded_message = b"\x00\x02" + padding[:padding_len] + b"\x00" + plaintext
    cipher_int = pow(int.from_bytes(encoded_message, "big"), exponent, modulus)
    return b64encode(cipher_int.to_bytes(key_bytes, "big")).decode("ascii")
