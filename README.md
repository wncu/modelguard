# ModelGuard

Open-source, local-first model supply-chain inspection. **Evidence, not a safety certificate.**

Version 0.2: a static browser app and a dependency-free Python CLI (standard library only, Python 3.10+). No ModelGuard backend, hosted GPU, uploads, accounts or telemetry. Users pay only for their own compute/network and any hosting they choose. Public Hugging Face metadata queries contact Hugging Face directly.

## Three ways to use it

All three share the same rules (MG001-MG016) and never execute, import or unpickle model content.

**1. CLI** (Python 3.10+, standard library only)

```bash
python -m pip install git+https://github.com/wncu/modelguard   # or: pip install -e . from a checkout
modelguard scan /path/to/model --format text            # human summary
modelguard scan /path/to/model --hash --output report.json
modelguard scan ~/.cache/huggingface/hub/models--org--name --hash   # HF cache: blobs verified by name
modelguard hub owner/model --revision main --output report.json
modelguard verify /path/to/model owner/model --revision main --partial
modelguard scan ./model --fail-on high                    # CI: exit 1 on high findings
```

Without `--hash` only headers and pickle opcodes are read, so a scan takes milliseconds to seconds regardless of model size. `--hash` reads every byte (about 500 MB/s per core on CPUs without SHA extensions); `--jobs N` hashes N files in parallel.

**2. MCP server** for Claude Code, Claude Desktop and IDEs (stdio, no extra dependencies)

```bash
claude mcp add modelguard -- modelguard mcp          # or: modelguard-mcp
```

Read-only tools: `modelguard_scan(path, hash?, follow_symlinks?, include_files?)`, `modelguard_hub(repo, revision?)` and `modelguard_verify(path, repo, revision?, partial?)`. Results are compact (findings first, at most 200) with both text and `structuredContent`. For Claude Desktop, add `{"command": "modelguard", "args": ["mcp"]}` under `mcpServers`.

**3. Web app** (static, works offline once loaded)

```bash
python scripts/serve.py        # http://127.0.0.1:8000, or host web/ on any static host (GitHub Pages)
```

Pick files or a whole folder: the browser engine (`web/engine.mjs`, a port of the CLI checks) reads them locally in slices, so multi-GB models never load into memory and nothing is uploaded. It can also hash and compare a folder with a Hub revision. Python AST review (MG013) and symlink handling are CLI-only. Its results are kept identical to the CLI by a parity test.

## Implemented vs planned

| Capability | Status |
|---|---|
| Public Hub inventory pinned to returned commit SHA | Implemented, metadata only |
| Local inventory; extension signals; format detection by content signature | Implemented |
| Pickle analysis: opcode walk with a symbolic stack (raw, legacy and zip PyTorch, npy/npz object arrays, pickles hidden under other names) | Implemented, never unpickles; allowlist heuristic |
| safetensors / GGUF structure: offsets, sizes per dtype and quantization type, overlaps, trailing data | Implemented |
| Chat templates (GGUF metadata, `tokenizer_config.json`, `chat_template.jinja`): Jinja SSTI patterns | Implemented, pattern-based |
| `auto_map` / `custom_pipelines` in config files; Python AST of shipped `.py` files | Implemented, static |
| SHA-256: local streaming, HF cache blob names, `verify` against Hub LFS hashes | Implemented |
| JSON/text output, `--fail-on` for CI, browser history | Implemented |
| MCP server (stdio) and in-browser content analysis with CLI parity | Implemented |
| Keras/HDF5 Lambda layers, ONNX, archives other than zip | Planned (archives flagged MG016) |
| Behavioral trigger tests, tool-call evaluation, weight analysis | Research roadmap; not implemented |
| "Clean" / "100% safe" badge | Deliberately unsupported |

Validation: every malicious sample of the public picklescan test corpus that can be inspected is reported `high`, with no `high` on its benign samples; 19 real GGUF files across 18 quantization formats match byte for byte; differential tests against `pickle.Unpickler` and fuzzing of real models. See [docs/VALIDATION.md](docs/VALIDATION.md).

`coverage.content=false` means comprehensive content inspection was not performed, even where `config.json` was checked. All reports use `insufficient_evidence` for the overall backdoor conclusion. CLI exit 0 means the inspection completed, not that the model is safe; exit 1 only with `--fail-on`; exit 2 means incomplete/error. Reports contain local paths/names: review before sharing. Private Hub models are not supported.

## Documentation

- [Analysis methodology](docs/METHODOLOGY.md)
- [Architecture and cost boundaries](docs/ARCHITECTURE.md)
- [Research roadmap](docs/ROADMAP.md)
- [Report contract and rules](docs/REPORT_SPEC.md)
- [Validation and resource measurements](docs/VALIDATION.md)
- [Threat model](docs/THREAT_MODEL.md)
- [Development and architecture decisions](docs/DEVELOPMENT.md)
- [Contribution guide](CONTRIBUTING.md)
- [Security policy](SECURITY.md)

```bash
python scripts/check.py      # unit tests, CLI/web parity (needs Node 20+), JS syntax
python scripts/bench.py      # synthetic worst cases: time and peak memory
```

The CLI package is not published on PyPI; install from GitHub or a checkout. Publishing notes: [docs/PUBLISHING.md](docs/PUBLISHING.md).
