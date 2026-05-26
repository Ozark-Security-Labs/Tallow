ANALYZER_ID = "builtin.rules"
ANALYZER_VERSION = "0.1.0"
RULESET_VERSION = "2026.05.26"
FINDING_SCHEMA_VERSION = "v1"
CONTRACT_VERSION = "v1"

SEVERITY_RANK = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}

LIFECYCLE_SCRIPT_KEYS = (
    "preinstall",
    "install",
    "postinstall",
    "prepublish",
    "prepare",
)

NETWORK_COMMAND_PATTERNS = (
    r"\bcurl\b",
    r"\bwget\b",
    r"\bnc\b",
    r"\bnetcat\b",
    r"\bpowershell\b",
    r"\bInvoke-WebRequest\b",
    r"\biwr\b",
    r"fetch\s*\(",
)

WEBHOOK_URL_PATTERNS = (
    r"discord(?:app)?\.com/api/webhooks/",
    r"api\.telegram\.org/bot",
    r"hooks\.slack\.com/services/",
    r"webhook\.site/",
    r"pastebin\.com/raw/",
    r"gist\.githubusercontent\.com/",
)

EXECUTABLE_EXTENSIONS = {".js", ".mjs", ".cjs", ".ts", ".py", ".sh", ".bash", ".zsh"}
DOC_EXTENSIONS = {".md", ".txt", ".rst", ".adoc"}

BINARY_MAGICS = {
    "elf": bytes.fromhex("7f454c46"),
    "pe": bytes.fromhex("4d5a"),
    "macho_be": bytes.fromhex("feedface"),
    "macho_be64": bytes.fromhex("feedfacf"),
    "macho_le": bytes.fromhex("cffaedfe"),
    "macho_fat": bytes.fromhex("cafebabe"),
}
