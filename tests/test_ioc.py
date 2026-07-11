from modules.ioc.extractor import extract_iocs


def test_extract_ipv4_excludes_private_by_default():
    text = "connect to 8.8.8.8 and 192.168.1.1"
    result = extract_iocs(text)
    assert "8.8.8.8" in result.ipv4
    assert "192.168.1.1" not in result.ipv4


def test_extract_domain_and_url():
    text = "visit http://malicious-example.xyz/payload.exe for evil.com details"
    result = extract_iocs(text)
    assert "http://malicious-example.xyz/payload.exe" in result.urls
    assert "evil.com" in result.domains


def test_extract_hashes():
    import hashlib

    md5 = hashlib.md5(b"hello world").hexdigest()
    sha256 = hashlib.sha256(b"hello world").hexdigest()
    result = extract_iocs(f"seen hashes {md5} and {sha256}")
    assert md5 in result.md5
    assert sha256 in result.sha256


def test_extract_cve_and_email():
    result = extract_iocs("Reported CVE-2024-12345 by soc@example.com")
    assert "CVE-2024-12345" in result.cves
    assert "soc@example.com" in result.emails
