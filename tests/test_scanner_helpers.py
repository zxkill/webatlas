from src.scanner import Finding, _score_findings, _extract_meta_generator


def test_score_findings_weights() -> None:
    findings = [
        Finding(category="headers", key="missing", severity="low", description="", evidence={}),
        Finding(category="tls", key="expiring", severity="medium", description="", evidence={}),
        Finding(category="ports", key="open", severity="high", description="", evidence={}),
    ]
    assert _score_findings(findings) == 16


def test_extract_meta_generator() -> None:
    html = '<html><head><meta name="generator" content="WordPress 6.4"></head></html>'
    assert _extract_meta_generator(html) == "WordPress 6.4"
