# ModelGuard

Open-source, local-first model supply-chain inspection. **Evidence, not a safety certificate.**

MVP 0.1: a static browser app and dependency-free Python CLI. No ModelGuard backend, hosted GPU, uploads, accounts or telemetry. Users pay only for their own compute/network and any hosting they choose. Public Hugging Face metadata queries contact Hugging Face directly.

## Run

```bash
python -m pip install -e .
modelguard scan /path/to/model --output report.json
modelguard scan /path/to/model --hash --output report.json
modelguard hub owner/model --revision main --output report.json
modelguard verify /path/to/model owner/model --revision main --partial
python -m http.server 8000 --directory web --bind 127.0.0.1
```

Open http://127.0.0.1:8000. Import the CLI report or inspect selected filenames. `--hash` streams bytes in 1 MiB blocks; a 500 GB model still takes considerable disk I/O and time. No model weights are fetched by `hub`. A file's extension is a review signal, not proof of its actual format or an exploit.

## Implemented vs planned

| Capability | MVP |
|---|---|
| Public Hub inventory pinned to returned commit SHA | Implemented, metadata only |
| Local file inventory, extension risk signals | Implemented |
| SHA-256 streaming | CLI, explicit `--hash` |
| `config.json` / `auto_map` review signal | Local CLI, bounded 2 MiB |
| `verify`: local SHA-256 vs Hub LFS hashes, format detection by signature | Implemented (LFS files only) |
| JSON export and browser history | Implemented, one report up to 1 MiB in localStorage |
| Pickle opcode scanning (raw and PyTorch zip), GGUF/safetensors header validation | Local CLI, static, bounded; allowlist heuristic |
| Python AST, dependency review, signature (not just extension) confirmation | Planned |
| Behavioral trigger tests, tool-call evaluation, weight analysis | Research roadmap; not implemented |
| "Clean" / "100% safe" badge | Deliberately unsupported |

`coverage.content=false` means comprehensive content inspection was not performed, even where `config.json` was checked. All current reports use `insufficient_evidence` for the overall backdoor conclusion. CLI exit 0 means the inspection completed, not that the model is safe; exit 2 means incomplete/error. Reports contain local paths/names: review before sharing. Private Hub models are not supported.

## Documentation

- [Analysis methodology](docs/METHODOLOGY.md)
- [Architecture and cost boundaries](docs/ARCHITECTURE.md)
- [Research roadmap](docs/ROADMAP.md)
- [Report contract](docs/REPORT_SPEC.md)
- [Threat model](docs/THREAT_MODEL.md)
- [Development and architecture decisions](docs/DEVELOPMENT.md)
- [Contribution guide](CONTRIBUTING.md)
- [Security policy](SECURITY.md)

```bash
python -m unittest discover -s tests -v
node --check web/app.js
```

Host `web/` on any static host, including GitHub Pages, without an API server. Do not connect private tokens to a public browser app. CLI package is not published on PyPI; install from the checked-out source.
