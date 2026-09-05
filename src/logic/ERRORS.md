# Relatório de erros.

> Esse arquivo corresponde ao relato de erros encontrados no arquivo hash-identifier.py (https://github.com/gitinspersec/Projetos/blob/main/projects/Individual/a-Hash_ID/hash_identifier.py) que está disponível para aprendizado no repositório do Insper Sec

---

## Erros encontrados

### 1. Verificação de hashes prefixados 

**Erro:** Muitos hashes prefixados estavam sendo verificados de forma errada, não verificando todas as suas condições necessárias para validação, permitindo que fossem aceitos hashes inválidos, exemplo: Estava sendo aceito como b2 hashes com menos de 60 caracteres e sem o cost factor, que são fatores essênciais para que o hash seja válido

**Solução aplicada:** Decidi dividir os hashes prefixados em 5 clusteres diferentes, baseado nas suas características em comum necessárias para a validação, além disso, ao invéz de verificações simples com .startwith() decidi usar regex para validações mais completas de conjunto de caracteres, ordem e tamanho.
