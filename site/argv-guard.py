#!/usr/bin/env python3
"""PreToolUse guard for Bash on the employer-managed Mac.

Microsoft Defender for Endpoint records the full command line (argv) of every process
and sends it to the employer, where a reverse-shell-shaped command or a token in argv
becomes a security alert (or a leaked secret).

Denies, before the command runs:
  1. reverse-shell-shaped constructs (/dev/tcp, nc -e, bash -i >&, socat exec, ...)
  2. secrets that would land in argv: $SECRET_VAR or $(op read ...) as an argument to an
     external program, literal tokens, passwords in URLs / -u user:pass / --password=,
     expect scripts that type passwords, sshpass

Reads the hook JSON on stdin; prints a deny decision as JSON, or nothing to allow.
The shell expands variables before exec, so `curl -H "Authorization: Bearer $TOKEN"`
puts the token itself in curl's argv. Builtins (printf, echo, export, test, ...) don't
exec, so a secret passed to them never reaches the EDR.
"""

import json
import re
import sys

FIX = (
    "Put the secret in a mode-600 file and pass the file (curl -H @file, curl --config -, "
    "--password-stdin), or have a script read it from the environment/1Password itself. "
    "A builtin like printf can write it: printf 'Authorization: Bearer %s\\n' \"$(op read ...)\" > hdr"
)

REVERSE_SHELL = [
    (r"/dev/(tcp|udp)/", "bash /dev/tcp is the classic reverse-shell construct, and Defender alerts on it. Probe ports with `nc -z host port`."),
    (r"\b(nc|ncat|netcat)\b[^;|&\n]*\s-[a-zA-Z]*[ec]\b", "nc -e/-c spawns a shell over the network."),
    (r"\b(ba|z|k)?sh\s+-i\b[^\n]*[<>]&", "interactive shell wired to a socket/fd is a reverse shell."),
    (r"\bmkfifo\b[^\n]*\b(nc|ncat|netcat|openssl)\b", "fifo + nc/openssl is a reverse-shell pattern."),
    (r"\bsocat\b[^\n]*\b(exec|system):", "socat exec: spawns a shell over the network."),
    (r"\bpty\.spawn\b|socket\.socket\([^\n]*(subprocess|os\.dup2)|os\.dup2\([^\n]*socket", "scripted socket-to-shell is a reverse shell."),
    (r"\bssh\b[^;|&\n]*\s-[a-zA-Z]*R\b", "reverse SSH tunnels from this Mac are off-limits; reach home hosts over Tailscale."),
]

SECRET_LITERALS = [
    (r"\bgh[pousr]_[A-Za-z0-9]{30,}", "GitHub token"),
    (r"\bgithub_pat_[A-Za-z0-9_]{20,}", "GitHub fine-grained token"),
    (r"\bsk-ant-[A-Za-z0-9_-]{20,}", "Anthropic API key"),
    (r"\bsk-(proj-)?[A-Za-z0-9_-]{32,}", "API secret key"),
    (r"\bxox[abprs]-[A-Za-z0-9-]{10,}", "Slack token"),
    (r"\bAKIA[0-9A-Z]{16}\b", "AWS access key"),
    (r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", "JWT"),
    (r"-----BEGIN [A-Z ]*PRIVATE KEY", "private key"),
    (r"(?i)\bbearer\s+[A-Za-z0-9._~+/-]{20,}", "literal bearer token"),
    (r"(?i)\b(x-api-key|api-key|x-auth-token|private-token)\s*:\s*[A-Za-z0-9._-]{16,}", "literal API key header"),
    (r"https?://[^/\s:@'\"]+:[^@\s/'\"]+@", "credentials embedded in a URL"),
]

SECRET_FLAGS = [
    (r"\bsshpass\b", "sshpass puts the password in argv. Use SSH keys."),
    (r"\bexpect\b[^\n]*\bsend\b", "expect scripts that type passwords put them in argv. Use SSH keys."),
    (r"--(password|passwd|token|api-key|apikey|secret|client-secret)(=|\s+)(?!-|\s)\S", "secret passed as a command-line flag."),
    (r"\bcurl\b[^\n]*\s(-u|--user)\s+['\"]?[^\s:'\"]+:[^\s'\"]+", "curl -u user:password puts the password in argv."),
]

SECRET_NAME = re.compile(
    r"(TOKEN|SECRET|PASSWORD|PASSWD|PASS|API_?KEY|APIKEY|PRIVATE_KEY|CREDENTIALS?|AUTH|PAT|DKEY|KEY)$",
    re.IGNORECASE,
)
VAR_EXPANSION = re.compile(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)")
SECRET_SOURCE = re.compile(
    r"(\$\(|`)\s*(op\s+(read|item\s+get)|security\s+find-(generic|internet)-password|gh\s+auth\s+token|"
    r"cat\s+[^)`]*(token|secret|password|\.key|credentials|\.env))",
    re.IGNORECASE,
)

# Programs that never exec: what they receive stays inside the shell.
BUILTINS = {
    "printf", "echo", "export", "local", "readonly", "declare", "typeset", "test", "[", "[[",
    "read", "unset", ":", "true", "false", "builtin", "set", "return", "exit", "eval",
}
KEYWORDS = {"if", "then", "elif", "else", "do", "while", "until", "!", "{", "time", "case", "in"}
SEPARATOR = re.compile(r"(\|\||&&|[;&|\n(`])")
ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")


def segment_before(command: str, pos: int) -> str:
    """The simple command that contains `pos`, from its start up to `pos`."""
    start = 0
    for match in SEPARATOR.finditer(command, 0, pos):
        start = match.end()
    return command[start:pos]


def reaches_argv(command: str, pos: int) -> bool:
    """Would text expanded at `pos` become an argument of an external program?"""
    words = segment_before(command, pos).split()
    while words and words[0] in KEYWORDS:
        words.pop(0)
    while words and ASSIGNMENT.match(words[0]):
        if len(words) == 1:
            return False  # NAME=$SECRET (assignment or env prefix): environment, not argv
        words.pop(0)
    if not words:
        return False
    if words[0] == "sudo" or words[0] == "env":
        return True
    return words[0].lstrip("\\") not in BUILTINS


def strip_heredocs(command: str) -> str:
    """Heredoc bodies go to stdin, not argv; drop them before scanning for secrets."""
    out, lines, i = [], command.split("\n"), 0
    while i < len(lines):
        line = lines[i]
        out.append(line)
        m = re.search(r"<<-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1", line)
        i += 1
        if m:
            end = m.group(2)
            while i < len(lines) and lines[i].strip() != end:
                i += 1
            if i < len(lines):
                out.append(lines[i])
                i += 1
    return "\n".join(out)


def check(command: str) -> str | None:
    for pattern, why in REVERSE_SHELL:
        if re.search(pattern, command):
            return f"Reverse-shell-shaped command: {why}"

    argv_text = strip_heredocs(command)
    for pattern, what in SECRET_LITERALS:
        if re.search(pattern, argv_text):
            return f"Secret in argv ({what}). {FIX}"
    for pattern, why in SECRET_FLAGS:
        if re.search(pattern, argv_text):
            return f"Secret in argv: {why} {FIX}"

    for m in SECRET_SOURCE.finditer(argv_text):
        if reaches_argv(argv_text, m.start()):
            return f"Secret in argv: `{m.group(0).strip()}...` is substituted into an external program's arguments. {FIX}"
    for m in VAR_EXPANSION.finditer(argv_text):
        if SECRET_NAME.search(m.group(1)) and reaches_argv(argv_text, m.start()):
            return f"Secret in argv: ${m.group(1)} is expanded into an external program's arguments, which Defender logs. {FIX}"
    return None


def main() -> None:
    try:
        payload = json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError):
        return
    if payload.get("tool_name") != "Bash":
        return
    command = (payload.get("tool_input") or {}).get("command") or ""
    reason = check(command)
    if reason:
        print(json.dumps({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": f"[argv-guard] {reason} (Managed Mac: Defender logs every command line; see AGENTS.md.)",
            }
        }))


if __name__ == "__main__":
    main()
