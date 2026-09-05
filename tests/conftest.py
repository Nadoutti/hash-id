"""
Fixtures e amostras compartilhadas pela suíte.

As amostras vivem aqui (e não espalhadas nos testes) porque a mesma string
costuma ser usada como caso positivo em um arquivo e como caso negativo em
outro — por exemplo, um bcrypt válido é entrada positiva em `test_prefixed`
e prova de "não é hex" em `test_hex`.
"""

import pytest

from logic.main import HashCandidate, identify

# Corpo de 53 caracteres do charset bcrypt (`./A-Za-z0-9`), sem o prefixo.
BCRYPT_BODY = "LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj/RCJa4rlHu"

BCRYPT = f"$2b$12${BCRYPT_BODY}"
PHPASS = "$P$B7ynMPqDdgQXHVYRbNFmMBIL0YLNz1/"
MD5_CRYPT = "$1$abcdefgh$" + "a" * 22
APR1 = "$apr1$abcdefgh$" + "b" * 22
SHA256_CRYPT = "$5$abcdefgh$" + "c" * 43
SHA512_CRYPT = "$6$abcdefgh$" + "d" * 86
ARGON2 = "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG"
YESCRYPT = "$y$j9T$F5Jx5fExrKuPp53xLKQ.Z/$Ml9ZaqPnDPqBmKhOZ0jyKNz"

DJANGO_PBKDF2 = "pbkdf2_sha256$260000$abcdefgh$Kq3z1YQ2yQm0zXo9nBw5s6f7g8h9i0jK1lM2nO3pQ4="
DJANGO_BCRYPT_SHA256 = f"bcrypt_sha256$$2b$12${BCRYPT_BODY}"
DJANGO_ARGON2 = f"argon2${ARGON2.lstrip('$')}"

# Drupal 7: `$S$` + 52 caracteres de `./A-Za-z0-9`, sem separador interno.
# O primeiro caractere do corpo é o marcador de rounds; os 8 seguintes são o
# salt e o resto é o digest — mas a regex só valida charset e comprimento.
DRUPAL7 = "$S$DkIkdWSVZ2FSTG9uY0hpUFpqZFlkVEE4L2ZuUlZ0Nk9wcS5YWTEy"

MYSQL5 = "*6BB4837EB74329105EE4568DDA7DC67ED2CA2AD9"
DESCRYPT = "kR2Cv2FqZlnnA"

MD5 = "5f4dcc3b5aa765d61d8327deb882cf99"
SHA1 = "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk"
BASE64_BLOB = "SGVsbG8gV29ybGQgdGhpcyBpcyBiYXNlNjQ="


def algorithms(text: str) -> list[str]:
    """Nomes dos algoritmos retornados por `identify`, na ordem de confiança."""
    return [candidate.algorithm for candidate in identify(text)]


def top(text: str) -> HashCandidate:
    """Primeiro candidato de `identify` — falha o teste se não houver nenhum."""
    candidates = identify(text)
    assert candidates, f"nenhum candidato para {text!r}"
    return candidates[0]


@pytest.fixture
def sample_hashes() -> dict[str, str]:
    """Mapa nome → hash, para testes que varrem todas as amostras válidas."""
    return {
        "bcrypt": BCRYPT,
        "phpass": PHPASS,
        "md5_crypt": MD5_CRYPT,
        "apr1": APR1,
        "sha256_crypt": SHA256_CRYPT,
        "sha512_crypt": SHA512_CRYPT,
        "argon2": ARGON2,
        "drupal7": DRUPAL7,
        "yescrypt": YESCRYPT,
        "django_pbkdf2": DJANGO_PBKDF2,
        "django_bcrypt_sha256": DJANGO_BCRYPT_SHA256,
        "django_argon2": DJANGO_ARGON2,
        "mysql5": MYSQL5,
        "descrypt": DESCRYPT,
        "md5": MD5,
        "sha1": SHA1,
        "sha256": SHA256,
    }
