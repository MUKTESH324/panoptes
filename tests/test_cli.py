from argus.cli import main


def test_plugins_command_lists(capsys):
    assert main(["plugins"]) == 0
    out = capsys.readouterr().out
    assert "security-headers" in out
    assert "reflected-xss" in out


def test_providers_command_lists(capsys):
    assert main(["providers"]) == 0
    out = capsys.readouterr().out
    assert "openai" in out
    assert "ollama" in out


def test_scan_without_authorization_refuses(capsys):
    # No --i-am-authorized => exit code 3, no network touched.
    rc = main(["scan", "https://example.com"])
    assert rc == 3
    err = capsys.readouterr().err
    assert "authorization" in err.lower()


def test_scan_requires_target(capsys):
    rc = main(["scan"])
    assert rc == 2
