from dataclasses import dataclass
from enum import Enum


class SourceType(str, Enum):
    HTTP_INPUT = "HTTP_INPUT"
    FILE_INPUT = "FILE_INPUT"
    CONFIG_INPUT = "CONFIG_INPUT"
    RAG_RETRIEVAL = "RAG_RETRIEVAL"
    AGENT_MEMORY = "AGENT_MEMORY"
    EXTERNAL_API = "EXTERNAL_API"
    USER_CONTENT = "USER_CONTENT"


@dataclass
class SourcePattern:
    name: str
    source_type: SourceType
    description: str
    # (module, attr_chain) patterns — None module = builtin/any
    module: str | None
    # dot-separated attribute chain, last part is the call/attribute that yields tainted data
    attr: str


SOURCE_PATTERNS: list[SourcePattern] = [
    # HTTP_INPUT — Flask
    SourcePattern("flask.request.args", SourceType.HTTP_INPUT, "Flask query string parameters", "flask", "request.args"),
    SourcePattern("flask.request.form", SourceType.HTTP_INPUT, "Flask form data", "flask", "request.form"),
    SourcePattern("flask.request.json", SourceType.HTTP_INPUT, "Flask JSON body", "flask", "request.json"),
    SourcePattern("flask.request.data", SourceType.HTTP_INPUT, "Flask raw request body", "flask", "request.data"),
    SourcePattern("flask.request.headers", SourceType.HTTP_INPUT, "Flask request headers", "flask", "request.headers"),
    SourcePattern("flask.request.files", SourceType.HTTP_INPUT, "Flask uploaded files", "flask", "request.files"),
    SourcePattern("flask.request.values", SourceType.HTTP_INPUT, "Flask combined form/query params", "flask", "request.values"),
    SourcePattern("flask.request.cookies", SourceType.HTTP_INPUT, "Flask cookies", "flask", "request.cookies"),
    SourcePattern("flask.request.get_json", SourceType.HTTP_INPUT, "Flask JSON body via get_json()", "flask", "request.get_json"),

    # HTTP_INPUT — FastAPI / Starlette
    SourcePattern("fastapi.Request.body", SourceType.HTTP_INPUT, "FastAPI raw request body", "fastapi", "Request.body"),
    SourcePattern("fastapi.Request.json", SourceType.HTTP_INPUT, "FastAPI JSON body", "fastapi", "Request.json"),
    SourcePattern("fastapi.Request.query_params", SourceType.HTTP_INPUT, "FastAPI query params", "fastapi", "Request.query_params"),
    SourcePattern("fastapi.Request.headers", SourceType.HTTP_INPUT, "FastAPI headers", "fastapi", "Request.headers"),
    SourcePattern("starlette.Request.body", SourceType.HTTP_INPUT, "Starlette raw request body", "starlette", "Request.body"),

    # HTTP_INPUT — Django
    SourcePattern("django.request.GET", SourceType.HTTP_INPUT, "Django GET query params", "django", "request.GET"),
    SourcePattern("django.request.POST", SourceType.HTTP_INPUT, "Django POST body", "django", "request.POST"),
    SourcePattern("django.request.body", SourceType.HTTP_INPUT, "Django raw body", "django", "request.body"),
    SourcePattern("django.request.FILES", SourceType.HTTP_INPUT, "Django uploaded files", "django", "request.FILES"),
    SourcePattern("django.request.META", SourceType.HTTP_INPUT, "Django request META (headers, env)", "django", "request.META"),
    SourcePattern("django.request.COOKIES", SourceType.HTTP_INPUT, "Django cookies", "django", "request.COOKIES"),

    # FILE_INPUT
    SourcePattern("open_read", SourceType.FILE_INPUT, "File content read with open()", None, "open"),
    SourcePattern("pathlib.read_text", SourceType.FILE_INPUT, "File content via pathlib.read_text()", "pathlib", "read_text"),
    SourcePattern("pathlib.read_bytes", SourceType.FILE_INPUT, "File content via pathlib.read_bytes()", "pathlib", "read_bytes"),

    # CONFIG_INPUT
    SourcePattern("os.environ", SourceType.CONFIG_INPUT, "Environment variable", "os", "environ"),
    SourcePattern("os.getenv", SourceType.CONFIG_INPUT, "Environment variable via getenv()", "os", "getenv"),
    SourcePattern("sys.argv", SourceType.CONFIG_INPUT, "Command-line argument", "sys", "argv"),
    SourcePattern("argparse.parse_args", SourceType.CONFIG_INPUT, "Parsed CLI argument", "argparse", "parse_args"),
    SourcePattern("dotenv.values", SourceType.CONFIG_INPUT, "dotenv config value", "dotenv", "values"),
    SourcePattern("yaml_config_read", SourceType.CONFIG_INPUT, "YAML config file read", "yaml", "safe_load"),
    SourcePattern("json_config_read", SourceType.CONFIG_INPUT, "JSON config file read", "json", "load"),
    SourcePattern("toml_config_read", SourceType.CONFIG_INPUT, "TOML config file read", "toml", "load"),

    # RAG_RETRIEVAL
    SourcePattern("similarity_search", SourceType.RAG_RETRIEVAL, "Vector DB similarity search result", None, "similarity_search"),
    SourcePattern("vectorstore.query", SourceType.RAG_RETRIEVAL, "Vector store query result", None, "query"),
    SourcePattern("retriever.retrieve", SourceType.RAG_RETRIEVAL, "Retriever result", None, "retrieve"),
    SourcePattern("retriever.get_relevant_documents", SourceType.RAG_RETRIEVAL, "LangChain retriever result", None, "get_relevant_documents"),
    SourcePattern("retriever.invoke", SourceType.RAG_RETRIEVAL, "LangChain retriever invoke result", None, "invoke"),
    SourcePattern("index.query", SourceType.RAG_RETRIEVAL, "Index query result (LlamaIndex/Pinecone/etc.)", None, "index.query"),
    SourcePattern("chroma.query", SourceType.RAG_RETRIEVAL, "ChromaDB query result", "chromadb", "query"),
    SourcePattern("weaviate.query", SourceType.RAG_RETRIEVAL, "Weaviate query result", "weaviate", "query"),

    # AGENT_MEMORY
    SourcePattern("memory.load_memory_variables", SourceType.AGENT_MEMORY, "LangChain memory load", None, "load_memory_variables"),
    SourcePattern("chat_history", SourceType.AGENT_MEMORY, "Chat/conversation history variable", None, "chat_history"),
    SourcePattern("message_history", SourceType.AGENT_MEMORY, "Message history variable", None, "message_history"),
    SourcePattern("conversation_history", SourceType.AGENT_MEMORY, "Conversation history variable", None, "conversation_history"),

    # EXTERNAL_API
    SourcePattern("requests.get.response", SourceType.EXTERNAL_API, "HTTP GET response body", "requests", "get"),
    SourcePattern("requests.post.response", SourceType.EXTERNAL_API, "HTTP POST response body", "requests", "post"),
    SourcePattern("httpx.get.response", SourceType.EXTERNAL_API, "httpx GET response body", "httpx", "get"),
    SourcePattern("openai.response", SourceType.EXTERNAL_API, "OpenAI API response", "openai", "ChatCompletion.create"),
    SourcePattern("anthropic.response", SourceType.EXTERNAL_API, "Anthropic API response", "anthropic", "messages.create"),
    SourcePattern("webhook_payload", SourceType.EXTERNAL_API, "Webhook payload from external service", None, "webhook"),
]

# Names that strongly suggest tainted data regardless of origin
TAINTED_VARNAMES: frozenset[str] = frozenset({
    "user_input", "user_query", "user_message", "user_data", "user_content",
    "query", "prompt", "input_text", "raw_input",
    "context", "context_texts", "contextTexts", "retrieved_docs", "retrieved_chunks",
    "search_results", "chunks", "documents", "doc_content",
    "chat_history", "message_history", "conversation_history", "messages",
    "webhook_data", "payload", "request_data", "body", "form_data",
    "env_val", "config_val", "arg_val",
})

# Attribute names on request objects that yield tainted data
REQUEST_TAINT_ATTRS: frozenset[str] = frozenset({
    "args", "form", "json", "data", "body", "headers", "files",
    "values", "cookies", "GET", "POST", "FILES", "META", "COOKIES",
    "query_params", "path_params",
})

# Function call names that yield tainted data
TAINTED_CALL_NAMES: frozenset[str] = frozenset({
    "get_json", "parse_args", "getenv", "similarity_search", "query",
    "retrieve", "get_relevant_documents", "load_memory_variables",
    "read_text", "read_bytes", "readline", "readlines", "read",
    "invoke", "fetch", "search",
})
