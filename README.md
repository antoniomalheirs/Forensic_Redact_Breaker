# RedactBreaker v1.0 — C++ PDF Redaction Forensic Analyzer

> **FERRAMENTA EDUCACIONAL** — O uso não autorizado em dados de terceiros é proibido.

## Sobre

O RedactBreaker é uma ferramenta forense de linha de comando para análise de falhas de redação (redaction) em documentos PDF. Escrita em C++ nativo, segue a mesma arquitetura do sistema **Brute Force Methods**.

## Funcionalidades

| Módulo | Descrição |
|--------|-----------|
| **Ingestão Forense** | SHA-256 hashing, cadeia de custódia, validação de integridade |
| **Parser PDF Raw** | Parser binário nativo (xref, objetos, streams, FlateDecode) |
| **Finder Vetorial** | Detecção de retângulos preenchidos (preto/branco) no content stream |
| **Finder Raster** | Detecção de tarjas em imagens escaneadas via GDI+ (substitui OpenCV) |
| **Breaker** | Intersecção BBox para recuperação de texto oculto sob tarjas |
| **Deep Forensics** | Texto invisível (white-on-white, micro), conteúdo fora do CropBox |
| **Reporter** | Relatório JSON forense estruturado |

## Como Compilar

### Pré-requisitos
- **Visual Studio 2022** (Community ou superior)
- **Windows SDK** (incluído com VS)

### Compilação
```batch
# Abrir "Developer Command Prompt for VS 2022"
cd C:\Users\Zeca\Desktop\RestoreFiles\RedactBreaker_Academic
build.bat
```

Ou manualmente:
```batch
cl /EHsc /O2 /std:c++17 RedactBreaker.cpp /link gdiplus.lib shlwapi.lib ole32.lib
```

### Executar
```batch
RedactBreaker.exe
```

## Menu Interativo

```
=== SISTEMA DE ANALISE FORENSE DE REDACTIONS ===
1. Analisar PDF (Pipeline Forense Completo)
2. Analise Rapida (Metadados + Texto)
3. Verificar Integridade (SHA-256 + Estrutura)
4. Executar Auto-Teste (Validacao de Modulos)
5. Sobre / Ajuda
0. Sair
```

## Dependências

| Biblioteca | Tipo | Descrição |
|-----------|------|-----------|
| `picosha2.h` | Header-only | SHA-256 (mesma do Brute Force) |
| `gdiplus.lib` | Windows SDK | Decodificação de imagens (JPEG/PNG) |
| `shlwapi.lib` | Windows SDK | Utilidades de path |
| `ole32.lib` | Windows SDK | COM/IStream para GDI+ |

**Zero dependências externas** — tudo é header-only ou Windows SDK nativo.

## Arquitetura

```
RedactBreaker.cpp (~1300 linhas)
├── Inflate (RFC 1951 DEFLATE) — decompressão FlateDecode
├── PDFParser — parser binário PDF raw
├── RasterAnalysis — detecção de tarjas via GDI+
├── Forensic Modules — finder, breaker, deep forensics
├── Reporter — JSON forense
├── Self-Test — validação automática
└── Main Menu — interface interativa ANSI
```

## Desenvolvido por
**Zeca** — Para uso didático e acadêmico.
