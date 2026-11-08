"""Enclave - Dil desteği. Metinler kaynakta Türkçedir; İngilizce karşılıklar en.py dosyasındadır."""

from typing import Any

_language = "tr"

def set_language(language: str) -> None:
    global _language
    _language = "en" if language == "en" else "tr"

def language() -> str:
    return _language

def tr(text: str, *args: Any) -> str:
    if _language == "en":
        from .en import EN
        text = EN.get(text, text)
    return text.format(*args) if args else text
