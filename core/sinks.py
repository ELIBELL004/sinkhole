from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class Category(str, Enum):
    CODE_EXEC = "CODE_EXEC"
    DESERIALIZATION = "DESERIALIZATION"
    FILESYSTEM = "FILESYSTEM"
    PATH_TRAVERSAL = "PATH_TRAVERSAL"
    COMMAND_EXEC = "COMMAND_EXEC"
    SSRF = "SSRF"
    PROMPT_INJECTION = "PROMPT_INJECTION"
    SAFE_MODE_BYPASS = "SAFE_MODE_BYPASS"


@dataclass
class Sink:
    name: str
    category: Category
    severity: Severity
    description: str
    # (module, func) or (None, func) for builtins
    module: str | None
    func: str
    # optional: keyword arg that makes it dangerous
    danger_kwarg: str | None = None
    # optional: keyword arg value that makes it dangerous
    danger_kwarg_value: object = None
    suggested_fix: str = ""


SINKS: list[Sink] = [
    # CODE_EXEC
    Sink("eval", Category.CODE_EXEC, Severity.CRITICAL,
         "eval() executes arbitrary Python code from a string",
         None, "eval", suggested_fix="Never pass external data to eval()"),
    Sink("exec", Category.CODE_EXEC, Severity.CRITICAL,
         "exec() executes arbitrary Python code from a string",
         None, "exec", suggested_fix="Never pass external data to exec()"),
    Sink("compile", Category.CODE_EXEC, Severity.HIGH,
         "compile() + exec() can execute arbitrary code",
         None, "compile", suggested_fix="Do not compile untrusted input"),
    Sink("__import__", Category.CODE_EXEC, Severity.HIGH,
         "__import__() loads an arbitrary module by name",
         None, "__import__", suggested_fix="Allowlist permitted module names"),
    Sink("importlib.import_module", Category.CODE_EXEC, Severity.HIGH,
         "importlib.import_module() loads an arbitrary module by name",
         "importlib", "import_module", suggested_fix="Allowlist permitted module names"),

    # DESERIALIZATION
    Sink("pickle.loads", Category.DESERIALIZATION, Severity.CRITICAL,
         "pickle.loads() executes arbitrary code during deserialization",
         "pickle", "loads", suggested_fix="Use JSON or a schema-validated format instead"),
    Sink("pickle.load", Category.DESERIALIZATION, Severity.CRITICAL,
         "pickle.load() executes arbitrary code during deserialization",
         "pickle", "load", suggested_fix="Use JSON or a schema-validated format instead"),
    Sink("pickle.Unpickler", Category.DESERIALIZATION, Severity.CRITICAL,
         "pickle.Unpickler executes arbitrary code during deserialization",
         "pickle", "Unpickler", suggested_fix="Use JSON or a schema-validated format instead"),
    Sink("joblib.load", Category.DESERIALIZATION, Severity.CRITICAL,
         "joblib.load() is pickle under the hood — executes arbitrary code",
         "joblib", "load", suggested_fix="Only load models from trusted sources; use weights_only=True where possible"),
    Sink("torch.load", Category.DESERIALIZATION, Severity.CRITICAL,
         "torch.load() without weights_only=True executes arbitrary code via pickle",
         "torch", "load", suggested_fix="Use torch.load(..., weights_only=True)"),
    Sink("dill.load", Category.DESERIALIZATION, Severity.CRITICAL,
         "dill.load() executes arbitrary code during deserialization",
         "dill", "load", suggested_fix="Use a safe serialization format"),
    Sink("dill.loads", Category.DESERIALIZATION, Severity.CRITICAL,
         "dill.loads() executes arbitrary code during deserialization",
         "dill", "loads", suggested_fix="Use a safe serialization format"),
    Sink("yaml.load", Category.DESERIALIZATION, Severity.HIGH,
         "yaml.load() without SafeLoader executes arbitrary Python objects",
         "yaml", "load", suggested_fix="Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader)"),
    Sink("jsonpickle.decode", Category.DESERIALIZATION, Severity.CRITICAL,
         "jsonpickle.decode() executes arbitrary code during deserialization",
         "jsonpickle", "decode", suggested_fix="Use standard json.loads() instead"),
    Sink("shelve.open", Category.DESERIALIZATION, Severity.HIGH,
         "shelve.open() uses pickle internally — untrusted files can RCE",
         "shelve", "open", suggested_fix="Only open shelve files from trusted sources"),
    Sink("marshal.loads", Category.DESERIALIZATION, Severity.HIGH,
         "marshal.loads() can execute code if given crafted bytecode",
         "marshal", "loads", suggested_fix="Never unmarshal untrusted data"),
    Sink("numpy.load_pickle", Category.DESERIALIZATION, Severity.CRITICAL,
         "numpy.load() with allow_pickle=True executes arbitrary pickle code",
         "numpy", "load", danger_kwarg="allow_pickle", danger_kwarg_value=True,
         suggested_fix="Use numpy.load(..., allow_pickle=False)"),

    # FILESYSTEM
    Sink("shutil.rmtree", Category.FILESYSTEM, Severity.CRITICAL,
         "shutil.rmtree() recursively deletes a directory tree",
         "shutil", "rmtree", suggested_fix="Validate and normalize path before deletion; require explicit confirmation"),
    Sink("shutil.move", Category.FILESYSTEM, Severity.HIGH,
         "shutil.move() moves files/directories to an attacker-controlled path",
         "shutil", "move", suggested_fix="Validate source and destination paths"),
    Sink("os.remove", Category.FILESYSTEM, Severity.HIGH,
         "os.remove() deletes a file at an attacker-controlled path",
         "os", "remove", suggested_fix="Validate and normalize path"),
    Sink("os.unlink", Category.FILESYSTEM, Severity.HIGH,
         "os.unlink() deletes a file at an attacker-controlled path",
         "os", "unlink", suggested_fix="Validate and normalize path"),
    Sink("os.rename", Category.FILESYSTEM, Severity.MEDIUM,
         "os.rename() moves a file to an attacker-controlled path",
         "os", "rename", suggested_fix="Validate source and destination paths"),
    Sink("os.makedirs", Category.FILESYSTEM, Severity.MEDIUM,
         "os.makedirs() creates directories at an attacker-controlled path",
         "os", "makedirs", suggested_fix="Validate and normalize path"),
    Sink("open_write", Category.FILESYSTEM, Severity.HIGH,
         "open() in write mode at an attacker-controlled path can overwrite arbitrary files",
         None, "open", suggested_fix="Validate and normalize path; restrict to allowed directories"),

    # PATH_TRAVERSAL
    Sink("os.path.join_traversal", Category.PATH_TRAVERSAL, Severity.HIGH,
         "os.path.join() with user-controlled component enables path traversal",
         "os.path", "join", suggested_fix="Use os.path.normpath + validate result starts with allowed base"),
    Sink("pathlib_div_traversal", Category.PATH_TRAVERSAL, Severity.HIGH,
         "pathlib / operator with user-controlled component enables path traversal",
         "pathlib", "__truediv__", suggested_fix="Call .resolve() and validate result is within allowed base"),

    # COMMAND_EXEC
    Sink("subprocess.run", Category.COMMAND_EXEC, Severity.CRITICAL,
         "subprocess.run() executes a system command",
         "subprocess", "run", suggested_fix="Use subprocess with a list of args, never shell=True with user input"),
    Sink("subprocess.call", Category.COMMAND_EXEC, Severity.CRITICAL,
         "subprocess.call() executes a system command",
         "subprocess", "call", suggested_fix="Avoid shell=True; validate all args"),
    Sink("subprocess.Popen", Category.COMMAND_EXEC, Severity.CRITICAL,
         "subprocess.Popen() executes a system command",
         "subprocess", "Popen", suggested_fix="Avoid shell=True; validate all args"),
    Sink("subprocess.check_output", Category.COMMAND_EXEC, Severity.CRITICAL,
         "subprocess.check_output() executes a system command",
         "subprocess", "check_output", suggested_fix="Avoid shell=True; validate all args"),
    Sink("subprocess.check_call", Category.COMMAND_EXEC, Severity.CRITICAL,
         "subprocess.check_call() executes a system command",
         "subprocess", "check_call", suggested_fix="Avoid shell=True; validate all args"),
    Sink("os.system", Category.COMMAND_EXEC, Severity.CRITICAL,
         "os.system() executes a shell command string",
         "os", "system", suggested_fix="Use subprocess with a list of args instead"),
    Sink("os.popen", Category.COMMAND_EXEC, Severity.CRITICAL,
         "os.popen() executes a shell command string",
         "os", "popen", suggested_fix="Use subprocess with a list of args instead"),

    # SSRF
    Sink("requests.get", Category.SSRF, Severity.HIGH,
         "requests.get() with user-controlled URL enables SSRF",
         "requests", "get", suggested_fix="Validate URL against an allowlist; block internal/private IP ranges"),
    Sink("requests.post", Category.SSRF, Severity.HIGH,
         "requests.post() with user-controlled URL enables SSRF",
         "requests", "post", suggested_fix="Validate URL against an allowlist"),
    Sink("requests.put", Category.SSRF, Severity.HIGH,
         "requests.put() with user-controlled URL enables SSRF",
         "requests", "put", suggested_fix="Validate URL against an allowlist"),
    Sink("requests.delete", Category.SSRF, Severity.HIGH,
         "requests.delete() with user-controlled URL enables SSRF",
         "requests", "delete", suggested_fix="Validate URL against an allowlist"),
    Sink("requests.head", Category.SSRF, Severity.MEDIUM,
         "requests.head() with user-controlled URL enables SSRF",
         "requests", "head", suggested_fix="Validate URL against an allowlist"),
    Sink("urllib.request.urlopen", Category.SSRF, Severity.HIGH,
         "urllib.request.urlopen() with user-controlled URL enables SSRF",
         "urllib.request", "urlopen", suggested_fix="Validate URL against an allowlist"),
    Sink("httpx.get", Category.SSRF, Severity.HIGH,
         "httpx.get() with user-controlled URL enables SSRF",
         "httpx", "get", suggested_fix="Validate URL against an allowlist"),
    Sink("httpx.post", Category.SSRF, Severity.HIGH,
         "httpx.post() with user-controlled URL enables SSRF",
         "httpx", "post", suggested_fix="Validate URL against an allowlist"),
    Sink("aiohttp.ClientSession.get", Category.SSRF, Severity.HIGH,
         "aiohttp ClientSession.get() with user-controlled URL enables SSRF",
         "aiohttp", "get", suggested_fix="Validate URL against an allowlist"),

    # PROMPT_INJECTION (detected by flow_tracker special logic)
    Sink("prompt_template_injection", Category.PROMPT_INJECTION, Severity.HIGH,
         "External/retrieved text inserted into LLM system prompt — prompt injection risk",
         None, "_prompt_template_", suggested_fix="Treat retrieved content as data, not instructions; use XML delimiters to isolate user content"),

    # SAFE_MODE_BYPASS (detected by ml_specific rules)
    Sink("safe_mode_false", Category.SAFE_MODE_BYPASS, Severity.HIGH,
         "Safety mode boolean hardcoded or overridable to False",
         None, "_safe_mode_bypass_", suggested_fix="Do not allow safety flags to be disabled via user config or arguments"),
]

# Build lookup indexes
_by_func: dict[str, list[Sink]] = {}
_by_module_func: dict[tuple[str, str], list[Sink]] = {}

for _s in SINKS:
    _by_func.setdefault(_s.func, []).append(_s)
    if _s.module:
        _by_module_func.setdefault((_s.module, _s.func), []).append(_s)


def get_sinks_for_func(func_name: str) -> list[Sink]:
    return _by_func.get(func_name, [])


def get_sinks_for_module_func(module: str, func_name: str) -> list[Sink]:
    results = _by_module_func.get((module, func_name), [])
    # Also check partial module match (e.g. "os" matches "os.path")
    for (mod, fn), sinks in _by_module_func.items():
        if fn == func_name and (module.startswith(mod) or mod.startswith(module)):
            for s in sinks:
                if s not in results:
                    results.append(s)
    return results
