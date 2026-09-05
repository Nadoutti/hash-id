import argparse
import re
import sys
from dataclasses import dataclass
from typing import Literal

from rich.console import Console
from rich.table import Table


Confidence = Literal["high", "medium", "low"]

@dataclass(frozen=True, slots=True)
class HashCandidate:
    algorithm: str
    confidence: Confidence

# Regras para hashes prefixados

# para hashes de tamanho fixo

"""
    Note: essas 3 primeiras funções identificam hashes de tamanho fixo, cujo só muda
    a configuração dos seus campos obrigatórios
"""

def _is_bcrypt(input: str) -> bool:
    return bool(re.match(r"^\$2[abxy]\$\d{2}\$[./A-Za-z0-9]{53}$", input))


def _is_phpass(input: str) -> bool:
    return bool(re.match(r"^\$[PH]\$[./A-Za-z0-9]{31}$", input))


def _is_drupal7(input: str) -> bool:
    return bool(re.match(r"^\$S\$[./A-Za-z0-9]{52}$", input))

# Para hashes com tamanho fixo, mas salt variavel

CRYPT_RULES = [
    (r"^\$1\$[./0-9A-Za-z]{1,16}\$[./0-9A-Za-z]{22}$", "MD5 crypt"),
    (r"^\$apr1\$[./0-9A-Za-z]{1,8}\$[./0-9A-Za-z]{22}$", "Apache MD5-crypt"),
    (r"^\$5\$[./0-9A-Za-z]{1,16}\$[./0-9A-Za-z]{43}$", "SHA-256 crypt"),
    (r"^\$6\$[./0-9A-Za-z]{1,16}\$[./0-9A-Za-z]{86}$", "SHA-512 crypt"),
]

# Para PHC com tamanhos variaveis, temos que verificar as estruturas dos campos pra validar

def _is_argon2(input: str) -> bool:
    """
        Identifica argon2

        características:
            - muitos campos necessários
            - número de caracteres máximo indefinido
    """
    pattern: str = r"^\$argon2(id|i|d)\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+$"
    return bool(re.match(pattern, input))

def _is_yescrypt(text: str) -> bool:
    pattern = r"^\$y\$[./A-Za-z0-9]+\$[./A-Za-z0-9]+\$[./A-Za-z0-9]+$"
    return bool(re.match(pattern, text))


# Para hashes de framework (e.g django que usa o nome do algoritmos antes do $)

def _is_django_pbkdf2(text: str, alg: str = "sha256") -> bool:
    pattern = rf"^pbkdf2_{alg}\$\d+\$[^$]+\$[A-Za-z0-9+/]+=*$"
    return bool(re.match(pattern, text))

def _is_django_bcrypt_sha256(text: str) -> bool:
    if not text.startswith("bcrypt_sha256$"):
        return False
    inner = text.split("$", 1)[1]
    return _is_bcrypt(inner)

def _is_django_argon2(text: str) -> bool:
    if not text.startswith("argon2$"):
        return False
    inner = text.split("$", 1)[1]
    inner = "$" + inner
    return _is_argon2(inner)

HEX_CHARSET: frozenset[str] = frozenset("0123456789abcdefABCDEF")
_HEX_UPPER_CHARSET: frozenset[str] = frozenset("0123456789ABCDEF")

HEX_LENGTH_RULES: dict[int, list[str]] = {
    # 16 caracteres hex = 8 bytes = 64 bits. Saída do OLD_PASSWORD() do MySQL.
    16: ["MySQL323", "CRC-64"],
    # 32 caracteres hex = 16 bytes = 128 bits
    32: ["MD5", "NTLM", "MD4", "RIPEMD-128"],
    # 40 caracteres hex = 20 bytes = 160 bits
    40: ["SHA-1", "RIPEMD-160"],
    # 48 caracteres hex = 24 bytes = 192 bits
    48: ["Tiger-192"],
    # 56 caracteres hex = 28 bytes = 224 bits
    56: ["SHA-224", "SHA3-224"],
    # 64 caracteres hex = 32 bytes = 256 bits
    64: ["SHA-256", "SHA3-256", "BLAKE2s-256", "RIPEMD-256"],
    # 80 caracteres hex = 40 bytes = 320 bits (incomum)
    80: ["RIPEMD-320"],
    # 96 caracteres hex = 48 bytes = 384 bits
    96: ["SHA-384", "SHA3-384"],
    # 128 caracteres hex = 64 bytes = 512 bits
    128: ["SHA-512", "SHA3-512", "BLAKE2b-512", "Whirlpool"],
}

def _is_hex(text: str) -> bool:
    """Return True if every character in text is a hex digit and text is non-empty"""
    return bool(text) and all(c in HEX_CHARSET for c in text)

_MYSQL5_HEX_BODY_LENGTH = 40
_MYSQL5_TOTAL_LENGTH = _MYSQL5_HEX_BODY_LENGTH + 1


def _is_mysql5(text: str) -> bool:
    """
    Retorna True para o formato de senha MySQL5: `*` e 40 caracteres hex MAIÚSCULOS.

    O MySQL5 armazena SHA-1(SHA-1(senha)) impresso em hex maiúsculo com um `*` inicial.
    Rejeitamos minúsculas aqui para não retornar um veredito de ALTA confiança
    em uma string editada manualmente ou digitada incorretamente.
    """
    if len(text) != _MYSQL5_TOTAL_LENGTH or not text.startswith("*"):
        return False
    body = text[1:]
    return all(c in _HEX_UPPER_CHARSET for c in body)

_DESCRYPT_CHARSET: frozenset[str] = frozenset(
    "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)
_DESCRYPT_TOTAL_LENGTH = 13


def _is_descrypt(text: str) -> bool:
    """
    Retorna True para o DES crypt tradicional de 13 caracteres (legado /etc/passwd).

    Sem prefixo — apenas 13 caracteres extraídos de `./0-9A-Za-z`.
    Relatamos confiança MÉDIA (não ALTA) porque uma string de 13 caracteres
    nesse charset PODE ser outras coisas (IDs de sessão, valores codificados).
    """
    return len(text) == _DESCRYPT_TOTAL_LENGTH and all(
        c in _DESCRYPT_CHARSET for c in text
    )

def identify(input: str) -> list[HashCandidate]:

    text = input.strip()

    if not text:
        return []

    # Idenficando os prefixados

    if _is_bcrypt(text):
        return [
            HashCandidate(
                algorithm="Bcrypt",
                confidence="high",

            )
        ]

    if _is_phpass(text):
        return [
            HashCandidate(
                algorithm="PhPass",
                confidence="high",

            )
        ]

    if _is_drupal7(text):
        return [
            HashCandidate(
                algorithm="Drupal7",
                confidence="high",

            )
        ]

    for rule, alg in CRYPT_RULES:
        if bool(re.match(rule, text)):
            return [
                HashCandidate(
                    algorithm=alg,
                    confidence="high",

                )
            ]

    # Tamanhos variados

    if _is_argon2(text):
        return [
            HashCandidate(
                algorithm="Argon2",
                confidence="high",

            )
        ]

    if _is_yescrypt(text):
        return [
            HashCandidate(
                algorithm="YesCrypt",
                confidence="high",

            )
        ]

    # Hashes de frameworks

    if _is_django_pbkdf2(text):
        return [
            HashCandidate(
                algorithm="Django pbkdf2",
                confidence="high",

            )
        ]

    if _is_django_bcrypt_sha256(text):
        return [
            HashCandidate(
                algorithm="Django Bcrypt Sha256",
                confidence="high",

            )
        ]

    if _is_django_argon2(text):
        return [
            HashCandidate(
                algorithm="Django Argon2",
                confidence="high",

            )
        ]

    # MySQL5 — literal `*` + 40 caracteres hex maiúsculos
    if _is_mysql5(text):
        return [
            HashCandidate(
                algorithm="MySQL5",
                confidence="high",
            )
        ]

    if _is_descrypt(text):
        return [
            HashCandidate(
                algorithm="DES crypt",
                confidence="medium",
            )
        ]


    if _is_hex(text):
        algorithms = HEX_LENGTH_RULES.get(len(text), [])
        candidates: list[HashCandidate] = []
        for index, algorithm in enumerate(algorithms):
            # O primeiro algoritmo listado para cada comprimento é o padrão moderno
            # e recebe confiança MÉDIA. O restante é BAIXA.
            confidence: Confidence = "medium" if index == 0 else "low"
            candidates.append(
                HashCandidate(
                    algorithm=algorithm,
                    confidence=confidence,
                )
            )
        return candidates

    if text.startswith("$"):
        rest = text[1:]
        if "$" in rest:
            algo_name = rest.split("$", 1)[0]
            # A especificação PHC restringe IDs de algoritmo a alfanuméricos
            # mais `-` e `_`.
            if algo_name and all(c.isalnum() or c in "-_" for c in algo_name):
                return [
                    HashCandidate(
                        algorithm=f"String PHC ({algo_name})",
                        confidence="low",
                    )
                ]

    if text.startswith("eyJ"):
        # JWTs sempre começam com `eyJ` porque seu cabeçalho JSON `{"alg":...}`
        # em base64 começa com esses três caracteres.
        return [
            HashCandidate(
                algorithm="JWT (não é um hash)",
                confidence="low",
            )
        ]

    if any(c in text for c in "+/=") and len(text) > 8:
        # Hashes hex NUNCA contêm `+`, `/`, ou `=`.
        return [
            HashCandidate(
                algorithm="Blob Base64 (não é um hash)",
                confidence="low",
            )
        ]

    return []


def _build_argument_parser() -> argparse.ArgumentParser:
    """
    Constrói o analisador argparse usado pelo main().
    """
    parser = argparse.ArgumentParser(
        prog="hashid",
        description=(
            "Identifica uma string de hash por prefixo, comprimento e charset. "
            "Retorna candidatos classificados com confiança e raciocínio."
        ),
    )
    parser.add_argument(
        "hash",
        help="A string de hash a identificar (envolva em aspas simples se contiver $).",
    )
    parser.add_argument(
        "--top",
        "-n",
        type=int,
        default=5,
        help="Mostra no máximo este número de candidatos (padrão: 5).",
    )
    return parser


def _render_table(
    raw_input: str,
    candidates: list[HashCandidate],
    console: Console,
) -> None:
    """
    Imprime uma Tabela rich mostrando os candidatos identificados.
    """
    table = Table(
        title=f"Hash string: {raw_input.strip()}",
        title_style="bold cyan",
        show_lines=False,
    )
    table.add_column("algoritmo", style="bold white", no_wrap=True)
    table.add_column("confiança", no_wrap=True)

    # Cores para os níveis de confiança.
    confidence_colors: dict[Confidence, str] = {
        "high": "green",
        "medium": "yellow",
        "low": "cyan",
    }
    for candidate in candidates:
        color = confidence_colors[candidate.confidence]
        table.add_row(
            candidate.algorithm,
            f"[{color}]{candidate.confidence}[/{color}]"
        )
    console.print(table)

def main() -> int:
    """
    Ponto de entrada da CLI — retorna um código de saída (0 = ok, 1 = nada encontrado).
    """
    parser = _build_argument_parser()
    args = parser.parse_args()
    console = Console()

    candidates = identify(args.hash)

    if not candidates:
        console.print(
            "[red]Nenhuma identificação possível.[/red] "
            "A entrada não correspondeu a nenhum prefixo conhecido, formato especial "
            "ou comprimento hexadecimal."
        )
        return 1

    # Limita aos top-N solicitados
    trimmed = candidates[: args.top]
    _render_table(args.hash, trimmed, console)


    return 0

if __name__ == "__main__":
    sys.exit(main())
