"""Tests de normalisation d'URLs et assainissement HTML."""
import pytest
from collector.normalize import canonicalize_url, strip_html, sanitize_url, normalize_text


def test_canonicalize_removes_utm():
    url = "https://example.com/article?utm_source=twitter&utm_medium=social&title=test"
    result = canonicalize_url(url)
    assert "utm_source" not in result
    assert "title=test" in result

def test_canonicalize_removes_fbclid():
    url = "https://example.com/page?fbclid=abc123"
    assert "fbclid" not in canonicalize_url(url)

def test_canonicalize_removes_trailing_slash():
    url = "https://example.com/article/"
    assert canonicalize_url(url) == "https://example.com/article"

def test_canonicalize_removes_fragment():
    url = "https://example.com/article#section-2"
    assert "#" not in canonicalize_url(url)

def test_canonicalize_removes_amp():
    url = "https://example.com/article/amp"
    assert canonicalize_url(url) == "https://example.com/article"

def test_canonicalize_forces_https():
    url = "http://example.com/article"
    result = canonicalize_url(url)
    assert result.startswith("https://")

def test_sanitize_javascript_url():
    """Un lien javascript: doit être neutralisé."""
    assert sanitize_url("javascript:alert(1)") is None

def test_sanitize_data_url():
    assert sanitize_url("data:text/html,<script>evil</script>") is None

def test_sanitize_valid_url():
    assert sanitize_url("https://example.com") == "https://example.com"

def test_strip_html_basic():
    html = "<p>Hello <b>world</b></p>"
    assert strip_html(html) == "Hello world"

def test_strip_html_entities():
    html = "Caf&eacute; &amp; th&eacute;"
    result = strip_html(html)
    assert "&" not in result or "amp" not in result

def test_strip_html_script():
    """Le HTML incluant des scripts doit être nettoyé."""
    html = '<p>Safe text</p><script>alert("xss")</script>'
    result = strip_html(html)
    assert "<script>" not in result
    assert "alert" not in result

def test_normalize_text_removes_accents():
    result = normalize_text("Réseau électrique France")
    assert "e" in result
    assert "é" not in result

def test_normalize_text_removes_stopwords():
    result = normalize_text("le réseau de France est en panne")
    words = result.split()
    assert "le" not in words
    assert "est" not in words
    assert "en" not in words


def test_security_script_injection_end_to_end():
    """Un titre avec <script> doit être neutralisé par strip_html."""
    malicious_title = '<script>alert("xss")</script>Power outage'
    clean = strip_html(malicious_title)
    assert "<script>" not in clean
    assert "alert" not in clean

def test_security_javascript_link_neutralized():
    """Un lien javascript: retourne None via sanitize_url."""
    assert sanitize_url("javascript:alert('xss')") is None
