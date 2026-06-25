from __future__ import annotations

from typer.testing import CliRunner

from wizintel.cli import app

runner = CliRunner()


def test_cli_help() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "Passive OSINT" in result.output


def test_cli_init_creates_config_and_data(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["init"])
    assert result.exit_code == 0
    assert "Config created" in result.output


def test_tools_check_smoke(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["tools", "check"])
    assert result.exit_code == 0
    assert "subfinder" in result.output
