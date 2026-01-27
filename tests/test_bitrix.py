from src.bitrix import classify, decode_html, score_bitrix


def test_decode_html_fallback_on_unknown_charset() -> None:
    # Проверяем, что при неизвестной кодировке используется запасной UTF-8.
    raw = "тест".encode("utf-8")
    decoded = decode_html(raw, charset="unknown-charset")
    assert "тест" in decoded


def test_score_bitrix_collects_signals_and_caps_score() -> None:
    # Проверяем, что сигнатуры Bitrix корректно учитываются и score ограничен 100.
    headers = {"X-Powered-By": "Bitrix"}
    set_cookie_raw = "BITRIX_SM_UID=123"
    html = "<html><script>BX.message({});</script>/bitrix/admin/</html>"
    score, evidence = score_bitrix(headers, set_cookie_raw, html)

    assert score == 100
    assert len(evidence["signals"]) >= 3


def test_classify_respects_thresholds() -> None:
    # Проверяем пороги классификации Bitrix.
    assert classify(70) == "yes"
    assert classify(35) == "maybe"
    assert classify(34) == "no"
