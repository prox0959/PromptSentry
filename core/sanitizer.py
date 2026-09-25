"""
PromptSentry - Sanitizer & Obfuscation Neutralizer
Detects Base64 smuggling, homoglyph character spoofing, and zero-width spaces.
Author: Çınar (prox0959)
"""

import re
import base64
import unicodedata

# Zero-width spaces & invisible characters often used for stealth injection
INVISIBLE_CHARS = [
    '\u200B', '\u200C', '\u200D', '\uFEFF', '\u200E', '\u200F',
    '\u202A', '\u202B', '\u202C', '\u202D', '\u202E'
]

def strip_invisible_characters(text: str) -> tuple[str, int]:
    """
    TR: Metindeki gizli sıfır genişlikli karakterleri (Zero-width spaces) temizler.
    Strips zero-width characters and counts detected occurrences.
    """
    count = 0
    cleaned = []
    for char in text:
        if char in INVISIBLE_CHARS:
            count += 1
        else:
            cleaned.append(char)
    return "".join(cleaned), count

def normalize_unicode_homoglyphs(text: str) -> str:
    """
    TR: Kiril veya sahte benzer karakterleri (Cyrillic homoglyphs) standart Latin alfabesine dönüştürür.
    Normalizes Cyrillic or mathematical homoglyph spoofing (NFKC normalization).
    """
    return unicodedata.normalize('NFKC', text)

def decode_embedded_base64_blobs(text: str) -> list[dict]:
    """
    TR: Metin içerisine gizlenmiş Base64 kodlu blokları yakalar ve çözer.
    Identifies and decodes potential Base64 payload strings.
    """
    # Match potential Base64 strings of length 16+
    pattern = r'(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?'
    matches = re.finditer(pattern, text)
    
    decoded_blobs = []
    for match in matches:
        raw_b64 = match.group(0)
        try:
            decoded_bytes = base64.b64decode(raw_b64, validate=True)
            # Only consider if decoded into printable ASCII/UTF-8
            decoded_text = decoded_bytes.decode('utf-8', errors='strict')
            if len(decoded_text.strip()) > 8 and all(c.isprintable() or c.isspace() for c in decoded_text):
                decoded_blobs.append({
                    "encoded": raw_b64,
                    "decoded": decoded_text
                })
        except Exception:
            continue

    return decoded_blobs

def sanitize_prompt(raw_text: str) -> dict:
    """
    TR: Ham prompt metnini sıfır genişlikli karakterlerden ve gizli payloadlardan arındırır.
    Preprocesses and neutralizes stealth obfuscation.
    """
    stripped_text, invisible_count = strip_invisible_characters(raw_text)
    normalized_text = normalize_unicode_homoglyphs(stripped_text)
    decoded_blobs = decode_embedded_base64_blobs(raw_text)

    return {
        "original_text": raw_text,
        "clean_text": normalized_text,
        "invisible_chars_detected": invisible_count,
        "embedded_base64_payloads": decoded_blobs
    }
