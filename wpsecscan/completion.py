"""O47 Shell completion generation.

Reads the argparse parser and emits a bash / zsh / PowerShell completion
script. Invoke via `wpsecscan --completion bash > /etc/bash_completion.d/wpsecscan`.

Uses the parser introspection in `__main__.main()` — we re-build a minimal
duplicate flag list rather than coupling the two modules.
"""
from __future__ import annotations

# All long flags exposed by __main__.py. Source of truth: grep -E
# 'add_argument\(\s*"-' wpsecscan/__main__.py | sed ... | sort -u
# Keep alphabetical so a sync diff is easy to spot.
FLAGS = [
    "--abuseipdb-token",
    "--aggressive",
    "--api-server",
    "--api-token",
    "--attestation",
    "--attestation-customer",
    "--attestation-vendor",
    "--auth-pass",
    "--auth-user",
    "--auto-pr",
    "--auto-pr-repo",
    "--burp-export",
    "--checkpoint",
    "--completion",
    "--concurrency",
    "--config",
    "--csv",
    "--daemon",
    "--dashboard",
    "--debug",
    "--deep-throttle",
    "--deep-throttle-attempts",
    "--deep-throttle-pacing",
    "--diff",
    "--diff-against",
    "--exec-pdf",
    "--fail-on",
    "--file",
    "--format",
    "--github-search-token",
    "--har",
    "--hibp-token",
    "--html-only",
    "--insecure",
    "--json-only",
    "--md",
    "--no-color",
    "--no-console",
    "--no-update-check",
    "--out",
    "--parallel-groups",
    "--password-audit",
    "--patchstack-token",
    "--profile",
    "--prove",
    "--query",
    "--region",
    "--replay-har",
    "--resume",          # v2.8.2 L3 — added in v2.8.1, missing from completions
    "--sarif",
    "--sbom",
    "--self-update",     # v2.8.2 L3 — added in v2.8.1, missing from completions
    "--shell",
    "--since",
    "--ssh-audit",
    "--timeout",
    "--update-db",
    "--user-agent",
    "--version",
    "--vt-token",
    "--wpscan-token",
    "--xlsx",
]


def bash() -> str:
    flag_list = " ".join(FLAGS)
    return f"""# WPSecScan bash completion
_wpsecscan_completions() {{
    local cur prev opts
    COMPREPLY=()
    cur="${{COMP_WORDS[COMP_CWORD]}}"
    prev="${{COMP_WORDS[COMP_CWORD-1]}}"
    opts="{flag_list}"
    if [[ ${{cur}} == -* ]] ; then
        COMPREPLY=( $(compgen -W "${{opts}}" -- ${{cur}}) )
        return 0
    fi
    # File-completion for known flags
    case "${{prev:-}}" in
        --file|--out|--har|--diff-against|--baseline|--daemon|--replay-har|--sbom|--attestation|--auto-pr|--config|--report-template)
            COMPREPLY=( $(compgen -f -- ${{cur}}) )
            return 0
            ;;
        # #39 — value-completion for enum-style flags so <TAB> suggests valid choices.
        --fail-on)
            COMPREPLY=( $(compgen -W "info low medium high critical" -- ${{cur}}) )
            return 0
            ;;
        --ai-explain-for)
            COMPREPLY=( $(compgen -W "client dev exec" -- ${{cur}}) )
            return 0
            ;;
        --completion)
            COMPREPLY=( $(compgen -W "bash zsh powershell" -- ${{cur}}) )
            return 0
            ;;
        --format)
            COMPREPLY=( $(compgen -W "json html csv md xlsx sarif burp docx exec-pdf" -- ${{cur}}) )
            return 0
            ;;
    esac
}}
complete -F _wpsecscan_completions wpsecscan
complete -F _wpsecscan_completions wpsecscan-gui
"""


def zsh() -> str:
    flag_list = " ".join(f"'{f}'" for f in FLAGS)
    return f"""#compdef wpsecscan wpsecscan-gui
# WPSecScan zsh completion
_wpsecscan() {{
    local -a flags
    flags=({flag_list})
    _arguments -s "*::flag:->flags"
    case $state in
        flags) _describe -t flags 'wpsecscan flags' flags ;;
    esac
}}
_wpsecscan
"""


def fish() -> str:
    """v2.8.1 U4 — Fish shell completion.

    Install via: `wpsecscan --completion fish > ~/.config/fish/completions/wpsecscan.fish`
    """
    lines = ["# WPSecScan fish completion"]
    for f in FLAGS:
        # fish completions take `-l <long>` (strip the leading `--`).
        if f.startswith("--"):
            # v2.8.2 M7 — emit empty -d descriptions so a future doc
            # generator can populate them without changing the line shape.
            lines.append(f"complete -c wpsecscan -l {f[2:]} -d ''")
            lines.append(f"complete -c wpsecscan-gui -l {f[2:]} -d ''")
    return "\n".join(lines) + "\n"


def powershell() -> str:
    flag_list = ",\n        ".join(f"'{f}'" for f in FLAGS)
    return f"""# WPSecScan PowerShell completion
Register-ArgumentCompleter -Native -CommandName wpsecscan,wpsecscan-gui -ScriptBlock {{
    param($wordToComplete, $commandAst, $cursorPosition)
    @(
        {flag_list}
    ) | Where-Object {{ $_ -like "$wordToComplete*" }} |
        ForEach-Object {{ [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterName', $_) }}
}}
"""


def generate(shell: str) -> str:
    shell = (shell or "bash").lower()
    if shell == "bash":
        return bash()
    if shell == "zsh":
        return zsh()
    if shell in ("powershell", "pwsh"):
        return powershell()
    if shell == "fish":
        return fish()
    raise ValueError(f"unsupported shell {shell!r}; use bash/zsh/powershell/fish")
