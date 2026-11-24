from panoptes.cli import main


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


def test_payloads_command_lists(capsys):
    assert main(["payloads"]) == 0
    out = capsys.readouterr().out
    assert "xss" in out and "ssrf" in out


def test_hunt_without_authorization_refuses(capsys):
    rc = main(["hunt", "https://example.com", "--no-brain"])
    assert rc == 3
    assert "authorization" in capsys.readouterr().err.lower()


def test_brain_stats_empty(tmp_path, capsys):
    db = str(tmp_path / "b.db")
    rc = main(["brain", "stats", "https://example.com", "--brain", db])
    assert rc == 0
    out = capsys.readouterr().out
    assert "runs: 0" in out


def test_portscan_without_authorization_refuses(capsys):
    rc = main(["portscan", "127.0.0.1", "--allow-private"])
    assert rc == 3
    assert "authoriz" in capsys.readouterr().err.lower()


def test_portscan_runs_and_outputs_json(capsys):
    # Port 1 is (almost certainly) closed; just assert it runs and emits JSON.
    rc = main(["portscan", "127.0.0.1", "--i-am-authorized", "--allow-private",
               "--no-nmap", "--ports", "1", "--format", "json"])
    assert rc == 0
    import json
    data = json.loads(capsys.readouterr().out)
    assert data["host"] == "127.0.0.1"
    assert data["method"] == "connect"
