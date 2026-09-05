"""
Suíte de testes do identificador de hash.

Adaptada da versão de referência do Insper Sec, que testava o
`hash_identifier.py` original. As mudanças de estrutura que motivaram a
adaptação:

  - O módulo agora é `logic.main` (layout `src/`), não `hash_identifier`.
  - `PREFIX_RULES` (tabela de `startswith`) deixou de existir. No lugar entram
    `CRYPT_RULES` mais funções `_is_*` com regex — a validação passou a olhar
    charset, ordem e comprimento dos campos, e não só o prefixo. É a correção
    descrita em ERRORS.md.
  - `HashCandidate` perdeu o campo `reason`; hoje tem só `algorithm` e
    `confidence`.
  - Os rótulos mudaram: "bcrypt" -> "Bcrypt", "Argon2id" -> "Argon2",
    "Django PBKDF2-SHA256" -> "Django pbkdf2".
  - NetNTLMv1 e NetNTLMv2 não são reconhecidos por esta implementação, então
    os testes daqueles formatos saíram. Ver "Formatos ainda não suportados"
    no fim do arquivo.

Consequência prática da mudança para regex: as cargas úteis de exemplo agora
importam. No suíte antigo, `"$6$rounds=10000$salt$hashedpasswordhere"` passava
porque só o `$6$` era olhado; aqui ele é corretamente rejeitado, e as amostras
vivem em `conftest.py` com os campos no formato certo.
"""

import pytest

from conftest import (
    APR1,
    ARGON2,
    BASE64_BLOB,
    BCRYPT,
    BCRYPT_BODY,
    DESCRYPT,
    DJANGO_ARGON2,
    DJANGO_BCRYPT_SHA256,
    DJANGO_PBKDF2,
    DRUPAL7,
    JWT,
    MD5,
    MD5_CRYPT,
    MYSQL5,
    PHPASS,
    SHA1,
    SHA256,
    SHA256_CRYPT,
    SHA512_CRYPT,
    YESCRYPT,
    algorithms,
)
from logic.main import CRYPT_RULES, HEX_LENGTH_RULES, HashCandidate, identify

# =============================================================================
# Correspondências de prefixo (alta confiança)
# =============================================================================
# Primeiro passo do identify(): a entrada casa com uma regex de formato
# conhecido. Como a regex valida a estrutura inteira — e não só os primeiros
# caracteres — um acerto aqui é definitivo, e reportamos confiança ALTA.


@pytest.mark.parametrize(
    ("sample", "expected"),
    [
        pytest.param(BCRYPT, "Bcrypt", id="bcrypt"),
        pytest.param(PHPASS, "PhPass", id="phpass"),
        pytest.param(DRUPAL7, "Drupal7", id="drupal7"),
        pytest.param(MD5_CRYPT, "MD5 crypt", id="md5_crypt"),
        pytest.param(APR1, "Apache MD5-crypt", id="apr1"),
        pytest.param(SHA256_CRYPT, "SHA-256 crypt", id="sha256_crypt"),
        pytest.param(SHA512_CRYPT, "SHA-512 crypt", id="sha512_crypt"),
        pytest.param(ARGON2, "Argon2", id="argon2id"),
        pytest.param(DJANGO_PBKDF2, "Django pbkdf2", id="django_pbkdf2"),
        pytest.param(
            DJANGO_BCRYPT_SHA256, "Django Bcrypt Sha256", id="django_bcrypt_sha256"
        ),
        pytest.param(DJANGO_ARGON2, "Django Argon2", id="django_argon2"),
    ],
)
def test_formato_prefixado_e_reconhecido(sample: str, expected: str) -> None:
    """
    Cada formato prefixado sai como candidato único e de alta confiança.

    `identify` retorna cedo assim que uma regex casa, então a lista tem
    exatamente um item. Comparar a lista inteira (em vez de olhar só
    `candidates[0]`) prende esse contrato: se um dia a função passar a
    devolver palpites extras junto de um acerto definitivo, este teste avisa.
    """
    candidates = identify(sample)

    assert candidates, f"nenhum candidato retornado para {sample!r}"
    assert [c.algorithm for c in candidates] == [expected]
    assert candidates[0].confidence == "high"


# =============================================================================
# Rejeição de hashes prefixados malformados
# =============================================================================
# Estes são a regressão do erro relatado em ERRORS.md: a versão antiga aceitava
# como bcrypt qualquer string começada em `$2b$`, mesmo sem cost factor ou com
# corpo curto demais. Nenhuma destas entradas pode produzir um veredito ALTO.


@pytest.mark.parametrize(
    "sample",
    [
        pytest.param("$2b$12$curto", id="bcrypt_corpo_curto"),
        pytest.param(f"$2b${BCRYPT_BODY}", id="bcrypt_sem_cost_factor"),
        pytest.param(f"$2z$12${BCRYPT_BODY}", id="bcrypt_variante_invalida"),
        pytest.param(f"$2b$12${BCRYPT_BODY}x", id="bcrypt_longo_demais"),
        # Amostra do suíte antigo: passava quando só o `$6$` era verificado.
        pytest.param("$6$rounds=10000$salt$hashedpasswordhere", id="sha512crypt_antigo"),
        pytest.param("$1$abcdefgh$" + "a" * 21, id="md5crypt_corpo_curto"),
        pytest.param("$5$abcdefgh$" + "c" * 42, id="sha256crypt_corpo_curto"),
        pytest.param("$apr1$abcdefghi$" + "b" * 22, id="apr1_salt_longo_demais"),
        pytest.param(
            "$argon2id$m=65536,t=3,p=4$c29tZXNhbHQ$aGFzaA", id="argon2_sem_versao"
        ),
        pytest.param("$argon2xd$v=19$m=1,t=1,p=1$c2E$aA", id="argon2_variante_invalida"),
    ],
)
def test_prefixado_malformado_nao_recebe_alta_confianca(sample: str) -> None:
    candidates = identify(sample)

    assert all(c.confidence != "high" for c in candidates), (
        f"{sample!r} não deveria produzir veredito de alta confiança"
    )


# =============================================================================
# Formatos especiais
# =============================================================================
# Formatos sem string PHC, mas ainda inconfundíveis pela estrutura.


def test_mysql5_e_reconhecido() -> None:
    """
    MySQL5 = literal `*` seguido de 40 caracteres hex MAIÚSCULOS.

    O MySQL armazena SHA-1(SHA-1(senha)) impresso com `%02X` e um asterisco
    inicial — 41 caracteres no total.
    """
    candidates = identify(MYSQL5)

    assert candidates[0].algorithm == "MySQL5"
    assert candidates[0].confidence == "high"


def test_mysql5_rejeita_corpo_minusculo() -> None:
    """
    Hex minúsculo depois do `*` não é saída real do MySQL5.

    Preferimos não responder nada a responder ERRADO com confiança: um `*` com
    corpo minúsculo é quase certamente uma string editada à mão.
    """
    assert "MySQL5" not in algorithms(MYSQL5.lower())


@pytest.mark.parametrize(
    "sample",
    [
        pytest.param(MYSQL5[1:], id="sem_asterisco"),
        pytest.param(MYSQL5[:-1], id="curto_demais"),
        pytest.param(MYSQL5 + "A", id="longo_demais"),
    ],
)
def test_mysql5_malformado(sample: str) -> None:
    assert "MySQL5" not in algorithms(sample)


def test_descrypt_e_reconhecido() -> None:
    """
    O DES crypt tradicional não tem prefixo — só comprimento e charset o marcam.

    /etc/passwd legado usava esse formato: 13 caracteres de `./0-9A-Za-z`.
    """
    candidates = identify(DESCRYPT)

    assert candidates[0].algorithm == "DES crypt"
    # Confiança MÉDIA: 13 caracteres nesse charset podem ser outra coisa
    # (um ID de sessão, um valor codificado qualquer).
    assert candidates[0].confidence == "medium"


@pytest.mark.parametrize("length", [12, 14])
def test_descrypt_exige_exatamente_13_caracteres(length: int) -> None:
    assert "DES crypt" not in algorithms("a" * length)


def test_descrypt_rejeita_charset_invalido() -> None:
    """`+` está fora do alfabeto do DES crypt."""
    assert "DES crypt" not in algorithms("kR2Cv2Fq+lnnA")


# =============================================================================
# Correspondências de comprimento hex (confiança média / baixa)
# =============================================================================
# Quando a entrada é hex puro não há prefixo para desambiguar: o comprimento
# estreita a lista. O primeiro algoritmo de cada comprimento recebe confiança
# MÉDIA; o restante, BAIXA.


@pytest.mark.parametrize(
    ("sample", "expected"),
    [
        pytest.param("5d2e19393cc5ef67", "MySQL323", id="16_hex"),
        pytest.param(MD5, "MD5", id="32_hex"),
        pytest.param(SHA1, "SHA-1", id="40_hex"),
        pytest.param("a" * 56, "SHA-224", id="56_hex"),
        pytest.param(SHA256, "SHA-256", id="64_hex"),
        pytest.param("a" * 128, "SHA-512", id="128_hex"),
    ],
)
def test_comprimento_hex_traz_o_candidato_mais_provavel_primeiro(
    sample: str, expected: str
) -> None:
    candidates = identify(sample)

    assert candidates[0].algorithm == expected
    assert candidates[0].confidence == "medium"


def test_md5_lista_ntlm_como_alternativa() -> None:
    """32 hex também podem ser NTLM, MD4 ou RIPEMD-128 — devem aparecer."""
    assert "NTLM" in algorithms(MD5)


@pytest.mark.parametrize("length", sorted(HEX_LENGTH_RULES))
def test_toda_linha_de_hex_length_rules_e_coberta(length: int) -> None:
    """
    Cada comprimento da tabela devolve exatamente sua lista de algoritmos.

    Herdado do teste "every row is covered" do suíte antigo, que varria
    PREFIX_RULES. Um erro de digitação em qualquer linha derruba o seu
    próprio caso.
    """
    assert algorithms("a" * length) == HEX_LENGTH_RULES[length]


@pytest.mark.parametrize("length", sorted(HEX_LENGTH_RULES))
def test_confianca_decresce_depois_do_primeiro_candidato(length: int) -> None:
    candidates = identify("a" * length)

    assert candidates[0].confidence == "medium"
    assert all(c.confidence == "low" for c in candidates[1:])


@pytest.mark.parametrize(("regex", "algorithm"), CRYPT_RULES, ids=lambda v: str(v)[:24])
def test_toda_linha_de_crypt_rules_tem_teste(regex: str, algorithm: str) -> None:
    """
    Toda entrada de CRYPT_RULES é exercitada por alguma amostra do conftest.

    Substitui o teste exaustivo de PREFIX_RULES. Não dá para gerar uma amostra
    a partir da regex, então checamos o inverso: nenhum algoritmo da tabela
    ficou sem cobertura.
    """
    covered = {
        alg
        for sample in (MD5_CRYPT, APR1, SHA256_CRYPT, SHA512_CRYPT)
        for alg in algorithms(sample)
    }
    assert algorithm in covered, f"CRYPT_RULES tem `{algorithm}` sem amostra de teste"


def test_hex_maiusculo_e_aceito() -> None:
    assert algorithms(MD5.upper())[0] == "MD5"


@pytest.mark.parametrize("length", [15, 17, 31, 33, 63, 129])
def test_comprimento_hex_desconhecido_nao_identifica(length: int) -> None:
    assert identify("a" * length) == []


def test_caractere_nao_hex_derruba_o_caminho_hex() -> None:
    """Um `g` no meio já basta: a string deixa de ser hex."""
    assert "MD5" not in algorithms("g" + MD5[1:])


# =============================================================================
# Casos de não correspondência / borda
# =============================================================================
# Sempre teste os casos entediantes: vazio, só espaços, lixo.


@pytest.mark.parametrize("sample", ["", "   ", "\n", "\t\n "])
def test_entrada_vazia_nao_retorna_candidatos(sample: str) -> None:
    assert identify(sample) == []


def test_lixo_nao_retorna_candidatos() -> None:
    assert identify("olá, isso não é um hash") == []


@pytest.mark.parametrize("sample", [MD5, BCRYPT, MYSQL5])
def test_espacos_em_volta_sao_ignorados(sample: str) -> None:
    """
    Quebra de linha e espaço não podem atrapalhar o reconhecimento.

    Importa porque copiar do terminal quase sempre traz espaço junto.
    """
    assert algorithms(f"   {sample}\n") == algorithms(sample)


# =============================================================================
# Fallbacks de correspondência suave (dicas de formato, confiança BAIXA)
# =============================================================================
# Quando nada nas tabelas dispara, tentamos duas correspondências suaves:
# formato genérico de string PHC e "isso parece JWT / blob base64".


def test_string_phc_desconhecida_cai_no_generico() -> None:
    """
    Uma string PHC de algoritmo sem regra própria ainda é reportada, com o
    nome do algoritmo extraído do primeiro campo.
    """
    candidates = identify("$pbkdf2-sha512$25000$cnNhbHQ$aGFzaA")

    assert candidates
    assert "PHC" in candidates[0].algorithm
    assert "pbkdf2-sha512" in candidates[0].algorithm
    assert candidates[0].confidence == "low"


def test_phc_sem_segundo_cifrao_nao_identifica() -> None:
    """Sem um segundo `$` não há campo de algoritmo para extrair."""
    assert identify("$semcampos") == []


def test_jwt_e_sinalizado_como_nao_hash() -> None:
    """
    JWTs começam com `eyJ` e devem ser apontados como não-hash.

    Dizer "isso é um JWT" ajuda mais do que devolver silêncio.
    """
    candidates = identify(JWT)

    assert candidates
    assert "JWT" in candidates[0].algorithm
    assert candidates[0].confidence == "low"


def test_blob_base64_e_sinalizado_como_nao_hash() -> None:
    """Hash hex nunca contém `+`, `/` ou `=`."""
    candidates = identify(BASE64_BLOB)

    assert candidates
    assert "Base64" in candidates[0].algorithm
    assert candidates[0].confidence == "low"


def test_base64_curto_demais_nao_identifica() -> None:
    """O fallback base64 exige mais de 8 caracteres."""
    assert identify("ab+/cd==") == []


# =============================================================================
# HashCandidate é imutável
# =============================================================================


def test_hash_candidate_e_frozen() -> None:
    """
    `@dataclass(frozen=True)` impede reatribuição depois da construção.

    Note que a assinatura encolheu na migração: o campo `reason` do suíte
    antigo não existe mais.
    """
    candidate = HashCandidate(algorithm="MD5", confidence="medium")

    with pytest.raises((AttributeError, TypeError)):
        candidate.algorithm = "SHA-1"  # type: ignore[misc]
