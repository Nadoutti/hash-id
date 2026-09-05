"""
Camada de CLI: argparse, códigos de saída e renderização da tabela rich.
"""

import sys

import pytest

from conftest import BCRYPT, MD5
from logic.main import _build_argument_parser, main


@pytest.fixture(autouse=True)
def _wide_terminal(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Fixa a largura do terminal.

    A rich quebra as células conforme a largura detectada; sem isso os asserts
    de substring falhariam em janelas estreitas ou no CI.
    """
    monkeypatch.setenv("COLUMNS", "200")
    monkeypatch.setenv("TERM", "dumb")


def run_cli(monkeypatch: pytest.MonkeyPatch, *args: str) -> int:
    monkeypatch.setattr(sys, "argv", ["hashid", *args])
    return main()


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


def test_top_padrao_e_cinco() -> None:
    args = _build_argument_parser().parse_args([MD5])
    assert args.hash == MD5
    assert args.top == 5


@pytest.mark.parametrize("flag", ["--top", "-n"])
def test_top_aceita_ambas_as_flags(flag: str) -> None:
    args = _build_argument_parser().parse_args([MD5, flag, "2"])
    assert args.top == 2


def test_hash_e_obrigatorio() -> None:
    with pytest.raises(SystemExit) as exc:
        _build_argument_parser().parse_args([])
    assert exc.value.code == 2


# ---------------------------------------------------------------------------
# Códigos de saída
# ---------------------------------------------------------------------------


def test_sai_zero_quando_identifica(monkeypatch: pytest.MonkeyPatch) -> None:
    assert run_cli(monkeypatch, MD5) == 0


def test_sai_um_quando_nao_identifica(monkeypatch: pytest.MonkeyPatch) -> None:
    assert run_cli(monkeypatch, "senha123") == 1


def test_mensagem_de_falha(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    run_cli(monkeypatch, "senha123")
    assert "Nenhuma identificação possível" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# Saída
# ---------------------------------------------------------------------------


def test_tabela_lista_os_candidatos(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    run_cli(monkeypatch, MD5)
    out = capsys.readouterr().out
    assert "MD5" in out
    assert "NTLM" in out
    assert "medium" in out


def test_top_limita_as_linhas(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """MD5 tem 4 candidatos; `--top 1` deve cortar os outros três."""
    run_cli(monkeypatch, MD5, "--top", "1")
    out = capsys.readouterr().out
    assert "MD5" in out
    assert "NTLM" not in out


def test_hash_aparece_no_titulo(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    run_cli(monkeypatch, BCRYPT)
    assert "Bcrypt" in capsys.readouterr().out


def test_sem_saida_de_depuracao(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """
    A CLI não deve imprimir o comprimento cru da entrada antes da tabela.
    """
    run_cli(monkeypatch, MD5)
    first_line = capsys.readouterr().out.splitlines()[0]
    assert first_line.strip() != str(len(MD5))
