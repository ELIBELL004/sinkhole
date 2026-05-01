# sinkhole

Static analysis tool that maps trust boundary crossings in Python ML/AI projects. Traces where untrusted data reaches dangerous execution sinks without sanitization.

## What it detects

| Category | Examples |
|---|---|
| `CODE_EXEC` | `eval()`, `exec()`, `compile()`, `importlib.import_module()` |
| `DESERIALIZATION` | `pickle.loads`, `torch.load` (no `weights_only`), `joblib.load`, `yaml.load` (no SafeLoader), `numpy.load(allow_pickle=True)` |
| `FILESYSTEM` | `shutil.rmtree`, `os.remove`, `open()` write with user path |
| `PATH_TRAVERSAL` | `os.path.join` with user-controlled component, `pathlib /` operator |
| `COMMAND_EXEC` | `subprocess.*`, `os.system`, `os.popen` |
| `SSRF` | `requests.get/post`, `httpx.*`, `urllib.request.urlopen` with user URL |
| `PROMPT_INJECTION` | RAG retrieval / external text in LLM system prompt f-strings |
| `SAFE_MODE_BYPASS` | `safe_mode = False`, safety flags settable via env/config/args |

## Install

```bash
cd ~/tools/sinkhole
pip install colorama   # optional, for colored output
```

## Usage

```bash
# Scan a repo
python -m sinkhole /path/to/target/repo

# Filter to critical and high only
python -m sinkhole /path/to/repo --severity CRITICAL,HIGH

# Filter to specific categories
python -m sinkhole /path/to/repo --category CODE_EXEC,DESERIALIZATION,PROMPT_INJECTION

# Custom JSON output path + verbose (shows fixes + chain steps)
python -m sinkhole /path/to/repo --output results.json --verbose

# No JSON output
python -m sinkhole /path/to/repo --no-json

# Exit code: 1 if CRITICAL or HIGH findings found (useful in CI)
python -m sinkhole /path/to/repo && echo "clean"
```

## Scan the test fixtures

```bash
python -m sinkhole ~/tools/sinkhole/test --verbose
```

Expected output includes:
- `eval()` with user input (CRITICAL, CODE_EXEC)
- `pickle.loads` with HTTP body (CRITICAL, DESERIALIZATION)
- `torch.load` without `weights_only=True` (CRITICAL, DESERIALIZATION)
- `os.system` with user-controlled host (CRITICAL, COMMAND_EXEC)
- `requests.get` with user URL (HIGH, SSRF)
- `shutil.rmtree` on user path (CRITICAL, FILESYSTEM)
- RAG context in system prompt (HIGH, PROMPT_INJECTION)
- `safe_mode = False` (HIGH, SAFE_MODE_BYPASS)
- Path traversal via `os.path.join` (HIGH, PATH_TRAVERSAL)

## JSON report format

```json
{
  "tool": "sinkhole",
  "total": 12,
  "findings": [
    {
      "finding_id": "SINK-0001",
      "severity": "CRITICAL",
      "category": "CODE_EXEC",
      "source": { "file": "app.py", "line": 14, "type": "HTTP_INPUT", "variable": "code" },
      "sink":   { "file": "app.py", "line": 15, "type": "eval", "function": "eval" },
      "chain":  [{ "file": "app.py", "line": 14, "code": "code = request.form.get('code')" }],
      "description": "eval() executes arbitrary Python code from a string",
      "suggested_fix": "Never pass external data to eval()"
    }
  ]
}
```

## Untrusted sources tracked

- **HTTP_INPUT**: Flask/FastAPI/Django request params, body, headers, files, cookies
- **FILE_INPUT**: `open()` reads, uploaded file content
- **CONFIG_INPUT**: `os.environ`, `sys.argv`, `argparse`, dotenv, yaml/json config reads
- **RAG_RETRIEVAL**: `similarity_search()`, `.query()`, `.retrieve()`, `get_relevant_documents()`
- **AGENT_MEMORY**: chat history, message history, conversation context variables
- **EXTERNAL_API**: HTTP response bodies, webhook payloads
- **USER_CONTENT**: function parameters in route handlers

## Sanitizers recognized (data is safe after these)

`os.path.normpath`, `os.path.abspath`, `os.path.realpath`, `pathlib.resolve()`,
`html.escape`, `shlex.quote`, `werkzeug.secure_filename`, `bleach.clean`,
`markupsafe.escape`, any function with `sanitize`/`validate`/`clean`/`escape`/`safe` in its name.

## Architecture

```
sinkhole/
├── __main__.py          CLI entry point
├── core/
│   ├── ast_walker.py    Recursive .py file parser, import alias resolver
│   ├── sinks.py         Sink registry (30+ sinks across 8 categories)
│   ├── sources.py       Source registry + tainted variable heuristics
│   └── flow_tracker.py  Intra-file taint propagation + sink matching
├── rules/
│   ├── ml_specific.py   ML rules: RAG→prompt, safe_mode, model_load_rce, unauth_destructive
│   └── general.py       General rules: shell=True, yaml without SafeLoader, path join
└── output/
    └── reporter.py      Terminal (colored) + JSON output
```
