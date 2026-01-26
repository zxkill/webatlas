from src.domain_utils import normalize_domain


def test_normalize_domain_handles_urls_and_comments() -> None:
    # Проверяем, что URL корректно преобразуется в домен.
    assert normalize_domain("https://Example.com/path") == "example.com"
    # Проверяем, что адрес с портом и логином корректно очищается.
    assert normalize_domain("user:pass@sub.example.com:8080") == "sub.example.com"
    # Проверяем, что комментарии игнорируются.
    assert normalize_domain("# just a comment") is None
    # Проверяем, что пустые строки игнорируются.
    assert normalize_domain("   ") is None


def test_normalize_domain_rejects_invalid_domains() -> None:
    # Некорректные домены должны возвращать None.
    assert normalize_domain("not a domain") is None
    assert normalize_domain("http://localhost") is None
