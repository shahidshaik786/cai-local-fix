from __future__ import annotations

import asyncio
import copy
import os
import logging
import platform
import shutil
import sys
from dataclasses import dataclass, field
from typing import Any, cast

from openai.types.responses import ResponseCompletedEvent

logger = logging.getLogger(__name__)

_AUTO_PENTEST_TOOL_CANDIDATES = [
    "amass",
    "anew",
    "aquatone",
    "alterx",
    "arjun",
    "assetfinder",
    "aws",
    "bhedak",
    "bypass-403",
    "cewl",
    "chaos",
    "commix",
    "corsy",
    "crlfuzz",
    "curl",
    "dalfox",
    "dig",
    "dnsgen",
    "dnsrecon",
    "dnsvalidator",
    "dnsx",
    "docker",
    "dirb",
    "dirsearch",
    "dnsenum",
    "feroxbuster",
    "ffuf",
    "gau",
    "gf",
    "git-dumper",
    "github-subdomains",
    "gitleaks",
    "gobuster",
    "gospider",
    "gotator",
    "gowitness",
    "graphql-cop",
    "graphqlmap",
    "grype",
    "hakrawler",
    "hakrevdns",
    "helm",
    "h2csmuggler",
    "host",
    "http",
    "httprobe",
    "httpie",
    "httpx",
    "interactsh-client",
    "jaeles",
    "jq",
    "jwt_tool",
    "katana",
    "kiterunner",
    "kubectl",
    "kube-hunter",
    "kxss",
    "linkfinder",
    "mapcidr",
    "masscan",
    "meg",
    "metabigor",
    "naabu",
    "nikto",
    "nmap",
    "notify",
    "nuclei",
    "openssl",
    "paramspider",
    "playwright",
    "prowler",
    "puredns",
    "python",
    "qsreplace",
    "retire",
    "rush",
    "rustscan",
    "s3scanner",
    "secretfinder",
    "semgrep",
    "shuffledns",
    "smuggler",
    "slowhttptest",
    "slowloris",
    "sqlmap",
    "steampipe",
    "subfinder",
    "subjack",
    "subzy",
    "syft",
    "terrascan",
    "testssl",
    "theHarvester",
    "tlsx",
    "tplmap",
    "trufflehog",
    "trivy",
    "unfurl",
    "uncover",
    "uro",
    "wafw00f",
    "wapiti",
    "waybackurls",
    "waymore",
    "websocat",
    "wfuzz",
    "whatweb",
    "whois",
    "wpscan",
    "x8",
    "xnLinkFinder",
    "xsstrike",
    "zgrab2",
    "zap-baseline.py",
    "zaproxy",
]
_AUTO_PENTEST_ENUMERATION_TOOLS = (
    "curl",
    "httpx",
    "http",
    "httpie",
    "jq",
    "python",
    "openssl",
    "dig",
    "host",
    "whois",
    "nmap",
    "naabu",
    "dnsx",
    "tlsx",
    "subfinder",
    "amass",
    "assetfinder",
    "github-subdomains",
    "gau",
    "waybackurls",
    "katana",
    "hakrawler",
    "gospider",
    "gobuster",
    "ffuf",
    "dirsearch",
    "feroxbuster",
    "dirb",
    "whatweb",
    "arjun",
    "paramspider",
    "linkfinder",
    "xnLinkFinder",
    "theHarvester",
    "aws",
    "kubectl",
    "helm",
)
_AUTO_PENTEST_ATTACK_TOOLS = tuple(
    tool for tool in _AUTO_PENTEST_TOOL_CANDIDATES if tool not in _AUTO_PENTEST_ENUMERATION_TOOLS
)
_AUTO_PENTEST_WSL_SUPPORTED_TOOLS = (
    "curl",
    "httpx",
    "http",
    "httpie",
    "jq",
    "python",
    "openssl",
    "dig",
    "host",
    "whois",
    "nmap",
    "naabu",
    "dnsx",
    "tlsx",
    "subfinder",
    "amass",
    "assetfinder",
    "github-subdomains",
    "gau",
    "waybackurls",
    "katana",
    "hakrawler",
    "gospider",
    "gobuster",
    "ffuf",
    "dirsearch",
    "feroxbuster",
    "dirb",
    "whatweb",
    "arjun",
    "paramspider",
    "linkfinder",
    "xnLinkFinder",
    "theHarvester",
    "aws",
    "kubectl",
    "helm",
    "anew",
    "cewl",
    "sqlmap",
    "commix",
    "wafw00f",
    "wapiti",
    "nikto",
    "nuclei",
    "dalfox",
    "xsstrike",
    "crlfuzz",
    "h2csmuggler",
    "testssl",
    "wfuzz",
    "slowhttptest",
    "slowloris",
    "masscan",
    "rustscan",
    "trivy",
    "syft",
    "grype",
    "wpscan",
    "git-dumper",
    "uro",
    "waymore",
    "retire",
    "semgrep",
    "gitleaks",
    "jaeles",
    "trufflehog",
    "zgrab2",
    "chaos",
    "alterx",
    "puredns",
    "shuffledns",
    "interactsh-client",
    "asnmap",
    "mapcidr",
    "uncover",
    "notify",
    "subjack",
    "subzy",
    "gotator",
    "httprobe",
    "meg",
    "qsreplace",
    "unfurl",
    "gf",
)
_AUTO_PENTEST_WINDOWS_SUPPORTED_TOOLS = (
    "curl",
    "httpx",
    "http",
    "httpie",
    "jq",
    "python",
    "openssl",
    "nmap",
    "subfinder",
    "httpx",
    "katana",
    "nuclei",
    "naabu",
    "dnsx",
    "tlsx",
    "gau",
    "waybackurls",
    "gobuster",
    "ffuf",
    "sqlmap",
    "arjun",
    "wafw00f",
    "dirsearch",
)
_AUTO_PENTEST_TOOL_ALIASES = {
    "aws": ("aws", "aws2"),
    "h2csmuggler": ("h2csmuggler", "h2csmuggler.py"),
    "http": ("http", "httpie"),
    "httpie": ("httpie", "http"),
    "jwt_tool": ("jwt_tool", "jwt_tool.py", "jwt-tool", "jwt_tool_cli.py"),
    "linkfinder": ("linkfinder", "LinkFinder", "LinkFinder.py", "linkfinder.py"),
    "kxss": ("kxss", "kxss.py"),
    "paramspider": ("paramspider", "ParamSpider", "paramspider.py"),
    "graphql-cop": ("graphql-cop", "graphql-cop.py", "ppfuzz"),
    "secretfinder": ("secretfinder", "SecretFinder", "SecretFinder.py"),
    "testssl": ("testssl", "testssl.sh"),
    "theHarvester": ("theHarvester", "theharvester", "theHarvester.py"),
    "tplmap": ("tplmap", "tplmap.py"),
    "wapiti": ("wapiti", "wapiti3"),
    "xnLinkFinder": ("xnLinkFinder", "xnlinkfinder"),
    "zap-baseline.py": ("zap-baseline.py", "zap-baseline"),
    "zaproxy": ("zaproxy", "zap.sh"),
}


def _auto_pentest_system_prompt_budget() -> int:
    try:
        return max(1, int(os.getenv("CAI_AUTO_PENTEST_SAFE_CHECK_BUDGET", "200")))
    except ValueError:
        return 200


def auto_pentest_min_required_tools() -> int:
    required = os.getenv("CAI_AUTO_PENTEST_MIN_TOOLS", "").strip()
    if not required:
        return len(_AUTO_PENTEST_ENUMERATION_TOOLS)
    try:
        return max(0, int(required))
    except ValueError:
        return len(_AUTO_PENTEST_ENUMERATION_TOOLS)


def _auto_pentest_required_startup_tools() -> tuple[str, ...]:
    mode = os.getenv("CAI_AUTO_PENTEST_REQUIRED_TOOL_MODE", "enumeration").strip().lower()
    if mode in {"all", "all-candidates", "everything"}:
        return _auto_pentest_supported_tools(_auto_pentest_os_label())
    if mode in {"none", "off"}:
        return ()
    supported = set(_auto_pentest_supported_tools(_auto_pentest_os_label()))
    return tuple(tool for tool in _AUTO_PENTEST_ENUMERATION_TOOLS if tool in supported)


def _auto_pentest_supported_tools(os_label: str) -> tuple[str, ...]:
    if os_label in {"WSL/Linux", "Linux"}:
        return _AUTO_PENTEST_WSL_SUPPORTED_TOOLS
    if os_label == "Windows":
        return _AUTO_PENTEST_WINDOWS_SUPPORTED_TOOLS
    return tuple(
        tool
        for tool in _AUTO_PENTEST_ENUMERATION_TOOLS
        if tool in {"curl", "httpx", "jq", "python", "nmap", "sqlmap", "arjun"}
    )


def _auto_pentest_os_label() -> str:
    system = platform.system()
    if system == "Linux":
        try:
            with open("/proc/version", encoding="utf-8", errors="ignore") as version_file:
                version = version_file.read().lower()
            if "microsoft" in version or "wsl" in version:
                return "WSL/Linux"
        except OSError:
            pass
    return system or "unknown"


def _auto_pentest_package_manager_candidates(os_label: str) -> list[str]:
    if os_label == "Windows":
        return ["winget", "choco", "scoop", "go", "pipx", "npm"]
    if os_label == "WSL/Linux":
        return ["apt", "apt-get", "snap", "go", "pipx", "npm", "cargo"]
    if os_label == "Linux":
        return ["apt", "apt-get", "dnf", "yum", "pacman", "snap", "go", "pipx", "npm", "cargo"]
    return ["go", "pipx", "npm", "cargo"]


def _auto_pentest_search_path() -> str:
    paths = [os.environ.get("PATH", "")]
    cwd = os.getcwd()
    home = os.path.expanduser("~")
    candidate_dirs = [
        os.path.dirname(sys.executable),
        os.path.join(home, "go", "bin"),
        os.path.join(home, ".local", "bin"),
        os.path.join(home, ".npm-global", "bin"),
        os.path.join(home, ".cargo", "bin"),
        os.path.join(home, "tools", "h2csmuggler"),
        os.path.join(home, "tools", "jwt_tool"),
        os.path.join(home, "tools", "LinkFinder"),
        os.path.join(home, "tools", "SecretFinder"),
        os.path.join(home, "tools", "tplmap"),
        os.path.join(home, "tools", "kxss"),
        os.path.join(home, "tools", "theHarvester"),
        os.path.join(home, "tools", "ParamSpider"),
        os.path.join(home, "tools", "graphql-cop"),
    ]
    if os.name == "nt":
        candidate_dirs.extend(
            [
                os.path.join(cwd, "cai_env", "Scripts"),
                os.path.join(cwd, ".venv", "Scripts"),
                os.path.join(cwd, "venv", "Scripts"),
            ]
        )
    else:
        candidate_dirs.extend(
            [
                os.path.join(cwd, "cai_env_wsl", "bin"),
                os.path.join(cwd, "cai_env", "bin"),
                os.path.join(cwd, ".venv", "bin"),
                os.path.join(cwd, "venv", "bin"),
            ]
        )
    paths.extend(path for path in candidate_dirs if path and os.path.isdir(path))
    unique_paths: list[str] = []
    seen: set[str] = set()
    for path_group in paths:
        for path in path_group.split(os.pathsep):
            normalized = os.path.normcase(os.path.abspath(path)) if path else ""
            if not normalized or normalized in seen:
                continue
            seen.add(normalized)
            unique_paths.append(path)
    return os.pathsep.join(unique_paths)


def _auto_pentest_notable_search_dirs(search_path: str) -> list[str]:
    cwd = os.path.normcase(os.path.abspath(os.getcwd()))
    home = os.path.normcase(os.path.abspath(os.path.expanduser("~")))
    notable: list[str] = []
    for path in search_path.split(os.pathsep):
        if not path:
            continue
        absolute = os.path.abspath(path)
        normalized = os.path.normcase(absolute)
        if normalized.startswith(cwd) or normalized == os.path.normcase(
            os.path.abspath(os.path.dirname(sys.executable))
        ) or normalized.startswith(os.path.join(home, "go")) or normalized.startswith(
            os.path.join(home, ".local")
        ) or normalized.startswith(os.path.join(home, ".npm-global")) or normalized.startswith(
            os.path.join(home, ".cargo")
        ) or normalized.startswith(os.path.join(home, "tools")):
            notable.append(absolute)
    return notable


def _auto_pentest_find_tool(tool_name: str, search_path: str) -> str | None:
    aliases = _AUTO_PENTEST_TOOL_ALIASES.get(tool_name, (tool_name,))
    for alias in aliases:
        direct = shutil.which(alias, path=search_path)
        if direct:
            return direct
        for path in search_path.split(os.pathsep):
            if not path:
                continue
            candidate = os.path.join(path, alias)
            if os.path.isfile(candidate):
                return candidate
        if os.name == "nt":
            for suffix in (".exe", ".bat", ".cmd", ".ps1", ".py"):
                direct = shutil.which(f"{alias}{suffix}", path=search_path)
                if direct:
                    return direct
                for path in search_path.split(os.pathsep):
                    if not path:
                        continue
                    candidate = os.path.join(path, f"{alias}{suffix}")
                    if os.path.isfile(candidate):
                        return candidate
        elif not alias.endswith(".py"):
            direct = shutil.which(f"{alias}.py", path=search_path)
            if direct:
                return direct
            for path in search_path.split(os.pathsep):
                if not path:
                    continue
                candidate = os.path.join(path, f"{alias}.py")
                if os.path.isfile(candidate):
                    return candidate
    return None


def get_auto_pentest_tool_inventory_data() -> dict[str, Any]:
    os_label = _auto_pentest_os_label()
    search_path = _auto_pentest_search_path()
    available = []
    missing = []
    available_by_name: dict[str, str] = {}
    for tool_name in _AUTO_PENTEST_TOOL_CANDIDATES:
        path = _auto_pentest_find_tool(tool_name, search_path)
        if path:
            available.append({"name": tool_name, "path": path})
            available_by_name[tool_name] = path
        else:
            missing.append(tool_name)

    candidates = _auto_pentest_package_manager_candidates(os_label)
    available_package_managers = [
        name for name in candidates if _auto_pentest_find_tool(name, search_path)
    ]
    missing_package_managers = [
        name for name in candidates if not _auto_pentest_find_tool(name, search_path)
    ]
    supported_tools = _auto_pentest_supported_tools(os_label)
    supported_set = set(supported_tools)
    unsupported_tools = [
        name for name in _AUTO_PENTEST_TOOL_CANDIDATES if name not in supported_set
    ]
    startup_required_tools = _auto_pentest_required_startup_tools()
    missing_startup_required_tools = [
        name for name in startup_required_tools if name not in available_by_name
    ]
    enumeration_available = [
        {"name": name, "path": available_by_name[name]}
        for name in _AUTO_PENTEST_ENUMERATION_TOOLS
        if name in available_by_name and name in supported_set
    ]
    enumeration_missing = [
        name
        for name in _AUTO_PENTEST_ENUMERATION_TOOLS
        if name in supported_set and name not in available_by_name
    ]
    attack_available = [
        {"name": name, "path": available_by_name[name]}
        for name in _AUTO_PENTEST_ATTACK_TOOLS
        if name in available_by_name and name in supported_set
    ]
    attack_missing = [
        name
        for name in _AUTO_PENTEST_ATTACK_TOOLS
        if name in supported_set and name not in available_by_name
    ]
    minimum_required = len(startup_required_tools)
    return {
        "os": os_label,
        "tool_count": len(_AUTO_PENTEST_TOOL_CANDIDATES),
        "supported_tool_count": len(supported_tools),
        "unsupported_tools": unsupported_tools,
        "enumeration_tool_count": len(
            [tool for tool in _AUTO_PENTEST_ENUMERATION_TOOLS if tool in supported_set]
        ),
        "attack_tool_count": len(
            [tool for tool in _AUTO_PENTEST_ATTACK_TOOLS if tool in supported_set]
        ),
        "available_tools": available,
        "missing_tools": missing,
        "minimum_required": minimum_required,
        "required_tool_mode": os.getenv("CAI_AUTO_PENTEST_REQUIRED_TOOL_MODE", "enumeration"),
        "required_tools": list(startup_required_tools),
        "missing_required_tools": missing_startup_required_tools,
        "minimum_ready": not missing_startup_required_tools,
        "enumeration_tools": enumeration_available,
        "missing_enumeration_tools": enumeration_missing,
        "attack_tools": attack_available,
        "missing_attack_tools": attack_missing,
        "available_package_managers": available_package_managers,
        "missing_package_managers": missing_package_managers,
        "search_paths": search_path.split(os.pathsep),
        "notable_search_dirs": _auto_pentest_notable_search_dirs(search_path),
        "search_path_extra": [
            path
            for path in search_path.split(os.pathsep)
            if path and path not in os.environ.get("PATH", "").split(os.pathsep)
        ],
        "install_hint": _auto_pentest_install_plan_hint(os_label),
        "install_commands": auto_pentest_install_commands(os_label),
    }


def _auto_pentest_package_manager_inventory(os_label: str) -> str:
    candidates = _auto_pentest_package_manager_candidates(os_label)
    search_path = _auto_pentest_search_path()
    available = [name for name in candidates if _auto_pentest_find_tool(name, search_path)]
    missing = [name for name in candidates if not _auto_pentest_find_tool(name, search_path)]
    return (
        f"package managers available: {', '.join(available) if available else 'none'}; "
        f"package managers missing: {', '.join(missing) if missing else 'none'}"
    )


def _auto_pentest_install_plan_hint(os_label: str) -> str:
    if os_label == "Windows":
        return (
            "On native Windows, prefer installing a smaller native toolkit with winget, "
            "Chocolatey, Scoop, Go, or Python/pipx after user approval. For the full "
            "toolkit, recommend WSL Ubuntu."
        )
    if os_label in {"WSL/Linux", "Linux"}:
        return (
            "On Ubuntu/WSL, CAI installs in stages: first the Web/API/cloud "
            "enumeration toolkit, then the attack and validation toolkit. The "
            "auto-pentest startup gate requires enumeration readiness by default; "
            "attack tools are installed and used after discovery data exists."
        )
    return "Install missing tools only after user approval using the platform package manager."


def _auto_pentest_clone_command(repo_url: str, directory_name: str) -> str:
    return (
        "mkdir -p ~/tools && cd ~/tools && "
        f"if [ ! -d {directory_name}/.git ]; then "
        f"GIT_TERMINAL_PROMPT=0 git clone --depth 1 {repo_url} {directory_name}; "
        "fi"
    )


def _auto_pentest_requirements_command(directory_name: str) -> str:
    return (
        f"test ! -f ~/tools/{directory_name}/requirements.txt || "
        f"python3 -m pip install --user -r ~/tools/{directory_name}/requirements.txt"
    )


def auto_pentest_install_commands(os_label: str | None = None) -> list[str]:
    os_label = os_label or _auto_pentest_os_label()
    if os_label in {"WSL/Linux", "Linux"}:
        return [
            "sudo apt update",
            "sudo apt install -y nmap masscan dirb nikto jq curl git unzip make gcc golang-go pipx npm dnsutils whois whatweb wafw00f wapiti slowhttptest testssl.sh dnsrecon dnsenum libcurl4-openssl-dev python3-dev libssl-dev pkg-config httpie cewl wfuzz ruby ruby-dev awscli websocat cargo",
            "if command -v snap >/dev/null 2>&1; then sudo snap install feroxbuster || true; sudo snap install rustscan || true; sudo snap install trivy || true; sudo snap install syft --classic || true; sudo snap install grype --classic || true; sudo snap install helm --classic || true; fi",
            "sudo gem install wpscan || true",
            "pipx ensurepath",
            "pipx install sqlmap",
            "pipx install arjun",
            "pipx install wafw00f",
            "pipx install dirsearch",
            "pipx install xsstrike",
            "pipx install commix",
            "pipx install wapiti3",
            "pipx install git-dumper",
            "pipx install uro",
            "pipx install waymore",
            "pipx install slowloris",
            "pipx install xnLinkFinder",
            "pipx install playwright",
            "pipx install semgrep",
            "mkdir -p ~/.npm-global && npm config set prefix ~/.npm-global && npm install -g retire",
            _auto_pentest_clone_command("https://github.com/BishopFox/h2csmuggler.git", "h2csmuggler"),
            _auto_pentest_clone_command("https://github.com/GerbenJavado/LinkFinder.git", "LinkFinder"),
            _auto_pentest_clone_command("https://github.com/devanshbatham/ParamSpider.git", "ParamSpider"),
            _auto_pentest_clone_command("https://github.com/laramies/theHarvester.git", "theHarvester"),
            "chmod +x ~/tools/h2csmuggler/*.py ~/tools/LinkFinder/*.py ~/tools/theHarvester/*.py ~/tools/ParamSpider/*.py 2>/dev/null || true",
            _auto_pentest_requirements_command("LinkFinder"),
            _auto_pentest_requirements_command("ParamSpider"),
            _auto_pentest_requirements_command("theHarvester"),
            "go install github.com/OJ/gobuster/v3@latest",
            "go install github.com/ffuf/ffuf/v2@latest",
            "go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
            "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
            "go install github.com/projectdiscovery/katana/cmd/katana@latest",
            "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
            "go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
            "go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
            "go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest",
            "go install github.com/projectdiscovery/notify/cmd/notify@latest",
            "go install github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest",
            "go install github.com/projectdiscovery/uncover/cmd/uncover@latest",
            "go install github.com/lc/gau/v2/cmd/gau@latest",
            "go install github.com/tomnomnom/waybackurls@latest",
            "go install github.com/hahwul/dalfox/v2@latest",
            "go install github.com/tomnomnom/assetfinder@latest",
            "go install github.com/tomnomnom/anew@latest",
            "go install github.com/tomnomnom/unfurl@latest",
            "go install github.com/tomnomnom/gf@latest",
            "go install github.com/tomnomnom/httprobe@latest",
            "go install github.com/tomnomnom/meg@latest",
            "go install github.com/tomnomnom/qsreplace@latest",
            "go install github.com/jaeles-project/gospider@latest",
            "go install github.com/hakluke/hakrawler@latest",
            "go install github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest",
            "go install github.com/jaeles-project/jaeles@latest",
            "go install github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest",
            "go install github.com/d3mondev/puredns/v2@latest",
            "go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest",
            "go install github.com/projectdiscovery/asnmap/cmd/asnmap@latest",
            "go install github.com/projectdiscovery/alterx/cmd/alterx@latest",
            "go install github.com/projectdiscovery/chaos-client/cmd/chaos@latest",
            "go install github.com/owasp-amass/amass/v4/...@master",
            "go install github.com/gwen001/github-subdomains@latest",
            "go install github.com/hahwul/dalfox/v2@latest",
            "go install github.com/gitleaks/gitleaks/v8@latest",
            "go install github.com/trufflesecurity/trufflehog/v3@latest",
            "go install github.com/zmap/zgrab2@latest",
            "go install github.com/haccer/subjack@latest",
            "go install github.com/LukaSikic/subzy@latest",
            "go install github.com/Josue87/gotator@latest",
            'export PATH="$PATH:$HOME/go/bin:$HOME/.local/bin"',
        ]
    if os_label == "Windows":
        return [
            "winget install -e --id GoLang.Go",
            "winget install -e --id Python.Python.3.12",
            "python -m pip install --user pipx",
            "python -m pipx ensurepath",
            "pipx install sqlmap",
            "pipx install arjun",
            "pipx install wafw00f",
            "pipx install dirsearch",
            "go install github.com/OJ/gobuster/v3@latest",
            "go install github.com/ffuf/ffuf/v2@latest",
            "go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
            "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        ]
    return []


def _auto_pentest_tool_inventory() -> str:
    inventory = get_auto_pentest_tool_inventory_data()
    available = [
        f"{item['name']}={item['path']}" for item in inventory["available_tools"]
    ]
    missing = inventory["missing_tools"]

    return (
        f" Tool inventory for this {inventory['os']} environment: available tools: "
        f"{', '.join(available) if available else 'none'}; missing tools: "
        f"{', '.join(missing) if missing else 'none'}. "
        f"Enumeration toolkit readiness: {len(inventory['enumeration_tools'])}/"
        f"{inventory['enumeration_tool_count']} installed; missing enumeration tools: "
        f"{', '.join(inventory['missing_enumeration_tools']) if inventory['missing_enumeration_tools'] else 'none'}. "
        f"Attack toolkit readiness: {len(inventory['attack_tools'])}/"
        f"{inventory['attack_tool_count']} installed; missing attack tools: "
        f"{', '.join(inventory['missing_attack_tools']) if inventory['missing_attack_tools'] else 'none'}. "
        f"{_auto_pentest_package_manager_inventory(inventory['os'])}. "
        f"Startup requirement mode: {inventory['required_tool_mode']}; required tools "
        f"before auto-pentest starts: {inventory['minimum_required']}. "
        f"{inventory['install_hint']} Use the most specific installed tool first: "
        "httpx for header/probe sweeps, gobuster/ffuf/dirsearch for bounded content "
        "discovery when installed, sqlmap only for discovered in-scope parameters "
        "with non-destructive low-intensity options, and curl for direct proof/evidence "
        "requests. "
        "If a missing tool is required for the next step, ask the user to install it "
        "instead of pretending it is available."
    )


def _apply_auto_pentest_system_prompt(system_prompt: str | None) -> str | None:
    if os.getenv("CAI_AUTO_PENTEST_MODE", "false").lower() != "true":
        return system_prompt
    if os.getenv("CAI_AGENT_TYPE", "") != "bug_bounter_agent":
        return system_prompt
    if system_prompt and "CAI_AUTO_PENTEST_MODE is enabled." in system_prompt:
        return system_prompt

    budget = _auto_pentest_system_prompt_budget()
    tool_inventory = _auto_pentest_tool_inventory()
    relaxed_instruction = ""
    if os.getenv("CAI_AUTO_PENTEST_RELAXED", "false").lower() == "true":
        relaxed_instruction = (
            " CAI_AUTO_PENTEST_RELAXED is enabled for this non-production target: "
            "auto-approve in-scope app-layer actions such as state-changing "
            "test-account requests, while still blocking out-of-scope and host-destructive "
            "commands."
        )
    parallel_count = int(os.getenv("CAI_PARALLEL", "1") or "1")
    try:
        auto_parallelism = max(1, int(os.getenv("CAI_AUTO_PENTEST_PARALLELISM", "1")))
    except ValueError:
        auto_parallelism = 1
    parallel_instruction = ""
    if parallel_count >= 3:
        parallel_instruction = (
            f" CAI_PARALLEL={parallel_count} is enabled: divide coverage by role. "
            "If your agent name ends with #1, focus on discovery and configuration. "
            "If it ends with #2, focus on API authentication and authorization. "
            "If it ends with #3, focus on client-side, business logic, and validation "
            "checks. Avoid duplicating another agent's obvious next check."
        )
    if auto_parallelism > 1:
        parallel_instruction += (
            f" CAI_AUTO_PENTEST_PARALLELISM={auto_parallelism} is enabled at the "
            "tool execution layer: independent in-scope checks may run concurrently, but "
            "dependent, brute force, DoS/load, aggressive fuzzing, and destructive "
            "tests must remain serialized or guarded."
        )
    auto_prompt = (
        "\n\nCAI_AUTO_PENTEST_MODE is enabled. The authorized scope is only "
        "http://localhost:8888 and http://127.0.0.1:8888. Continue the authorized "
        "pentest workflow by using registered tools for in-scope HTTP/API "
        f"checks until at least {budget} checklist items have actual tool results, then summarize. "
        "This budget represents an expanded top-200 web/API vulnerability checklist "
        "based on Interview_Prep: address items "
        "one by one by executing applicable in-scope checks across vulnerability "
        "categories. A category such as SQL injection is not itself 200 test cases: "
        "run a bounded set of detection subchecks for discovered parameters, record "
        "the evidence, then move to XSS, auth, IDOR/BOLA, upload, SSRF, headers, "
        "CORS, methods, disclosure, workflow, and API-specific categories. "
        "Do not loop on the same endpoint, parameter, or vulnerability class. "
        "If a command returns a quoting/format error, correct it once; if it still "
        "fails, move to the next vulnerability category. Do not mark checklist items "
        "not applicable, guarded, skipped, or complete in assistant prose; only the "
        "runner can classify an executed tool request. "
        "Use the built-in structured Web/API test-case registry instead of random "
        "payload selection. Registry categories include recon and endpoint discovery, "
        "security headers, HTTP methods, CORS, cookies and session attributes, "
        "authentication, authorization/IDOR/BOLA, input validation, bounded SQL injection "
        "signals, non-executing XSS reflection checks, SSRF parameter discovery, file upload "
        "validation, error/debug exposure, sensitive data exposure, low-count rate "
        "limit signals, business logic checks, and OWASP API Top 10 coverage. "
        f"{tool_inventory} "
        "Do not blindly send vulnerability payloads first. Complete and report an "
        "enumeration baseline before vulnerability payload testing. CAI persists "
        "enumeration artifacts from completed tool results to "
        "logs/auto_pentest/enumeration.sqlite and mirrors them in "
        "logs/auto_pentest/report.md; later attack checks must be selected from "
        "those discovered URLs, routes, APIs, parameters, auth surfaces, object IDs, "
        "and workflows instead of guessed targets. Follow this exact "
        "order: 1) fetch the application entry HTML and response headers, 2) extract "
        "real script/link/manifest URLs from that HTML, 3) fetch discovered static "
        "assets only, 4) extract real routes, APIs, forms, JavaScript endpoints, and "
        "object IDs from those assets and responses, "
        "4) identify registration/login/logout/profile/workflow functionality, "
        "5) create and login with a harmless test account when registration exists, "
        "6) understand normal app behavior with that account, then 7) query or rely "
        "on the stored enumeration dataset and run targeted vulnerability checks "
        "based on discovered functionality. "
        "Print a concise enumeration summary in normal assistant text after this baseline: "
        "discovered assets, routes/APIs, forms/auth flows, parameters, and items not found. "
        "Do not guess paths such as /static/app.js or /static/api.json unless the HTML or "
        "a discovered asset references them. "
        "First verify required local tools are available, such as curl and PowerShell; "
        "do not install anything unless a required tool is missing and the user approves. "
        "Scoped URL discovery tools such as gobuster, ffuf, dirsearch, and crawling commands "
        "may be used with small wordlists, low threads, and reasonable limits against the "
        "authorized localhost target only. "
        "If a registration endpoint exists, create a unique harmless test account using "
        "an email like cai-test-<timestamp>@example.com and a non-secret test password, "
        "then login with the same credentials, save cookies to a local cookie jar, and "
        "use that authenticated session for auth, authorization, CSRF, and cookie "
        "attribute checks. Cookie jar inspection is allowed when it uses the test session. "
        "For this non-production target, validate password policy with a small set of "
        "registration attempts using weak, boundary, and acceptable test passwords. "
        "Validate rate limiting with very low-count request bursts only, enough to observe "
        "whether throttling exists, not enough to load test. In-scope state-changing API "
        "requests such as PUT, PATCH, and DELETE may be tested when they use disposable "
        "test data or the created test account; the runner asks once per session before "
        "non-destructive in-scope tests and still guards destructive state-changing "
        "requests. "
        "Emit exactly one registered tool call JSON per assistant turn. For HTTP checks "
        "use generic_linux_command with a command argument, not pseudo-tools named curl "
        "or httpx. Do not invent pseudo-tools such as extract_real_js_asset_urls or "
        "check_robots_sitemap_security_metadata; use generic_linux_command for those "
        "checks. Select the best installed tool for each step: use httpx for structured "
        "header/status probing, gobuster/ffuf/dirsearch for bounded directory/content "
        "enumeration if installed, sqlmap only after real parameters are discovered "
        "with --batch and low-intensity non-destructive options, and curl for direct "
        "request/response evidence. Cover, without repeating "
        "successful checks unnecessarily: security headers, cookie attributes, CORS, "
        "OPTIONS/methods, robots.txt, sitemap.xml, security.txt, well-known metadata, "
        "manifest/static assets, JavaScript route extraction, API discovery, Swagger/"
        "OpenAPI, GraphQL discovery, harmless reflected proof strings, non-destructive "
        "SQLi bounded detection probes, REST parameter pollution, path traversal only on discovered file "
        "parameters, source maps, backup/source disclosure names with reasonable limits, "
        "cache headers, cache deception, host header behavior with in-scope hosts, "
        "CSRF signals on discovered state-changing forms, JWT inspection only when "
        "tokens are discovered, auth/authz only with provided or discovered test "
        "accounts/IDs, IDOR/BOLA only when object IDs exist, mass assignment only on "
        "discovered JSON APIs, upload validation only on discovered upload endpoints, "
        "very low-count rate-limit signals, and business logic checks only on discovered "
        "workflows. Do not use browser-executing XSS payloads, real user credentials, "
        "credential stuffing, brute force, load tests, deletion, writes outside intended app "
        "requests, or out-of-scope URLs. Do not stop after basic header checks. Do not "
        "call CTF flag-discriminator or handoff-style tools unless you have an actual "
        "non-empty flag candidate. If a tool is needed, emit the "
        f"registered tool call JSON and continue from the tool result.{relaxed_instruction}"
        f"{parallel_instruction}"
    )
    return f"{system_prompt or ''}{auto_prompt}"


from ._run_impl import (
    AgentToolUseTracker,
    NextStepFinalOutput,
    NextStepHandoff,
    NextStepRunAgain,
    QueueCompleteSentinel,
    RunImpl,
    SingleStepResult,
    TraceCtxManager,
    get_model_tracing_impl,
)
from .agent import Agent
from .agent_output import AgentOutputSchema
from .exceptions import (
    AgentsException,
    InputGuardrailTripwireTriggered,
    MaxTurnsExceeded,
    ModelBehaviorError,
    OutputGuardrailTripwireTriggered,
)
from .guardrail import InputGuardrail, InputGuardrailResult, OutputGuardrail, OutputGuardrailResult
from .handoffs import Handoff, HandoffInputFilter, handoff
from .items import ItemHelpers, ModelResponse, RunItem, TResponseInputItem
from .lifecycle import RunHooks
from .logger import logger
from .model_settings import ModelSettings
from .models.interface import Model, ModelProvider
from .models.openai_provider import OpenAIProvider
from .result import RunResult, RunResultStreaming
from .run_context import RunContextWrapper, TContext
from .stream_events import AgentUpdatedStreamEvent, RawResponsesStreamEvent
from .tool import Tool
from .tracing import Span, SpanError, agent_span, get_current_trace, trace
from .tracing.span_data import AgentSpanData
from .usage import Usage
from .util import _coro, _error_tracing

# CAI_MAX_TURNS must be converted to an int to avoid type mismatch error when comparing.
max_turns_env = os.getenv("CAI_MAX_TURNS")
if max_turns_env is not None:
    try:
        DEFAULT_MAX_TURNS = int(max_turns_env)
    except ValueError:
        try:
            DEFAULT_MAX_TURNS = float(max_turns_env)
        except ValueError:
            DEFAULT_MAX_TURNS = float("inf")
else:
    DEFAULT_MAX_TURNS = float("inf")

price_limit_env = os.getenv("CAI_PRICE_LIMIT")
if price_limit_env is not None:
    try:
        DEFAULT_PRICE_LIMIT = float(price_limit_env)
    except ValueError:
        DEFAULT_PRICE_LIMIT = float("inf")
else:
    DEFAULT_PRICE_LIMIT = float("inf")


@dataclass
class RunConfig:
    """Configures settings for the entire agent run."""

    model: str | Model | None = None
    """The model to use for the entire agent run. If set, will override the model set on every
    agent. The model_provider passed in below must be able to resolve this model name.
    """

    model_provider: ModelProvider = field(default_factory=OpenAIProvider)
    """The model provider to use when looking up string model names. Defaults to OpenAI."""

    model_settings: ModelSettings | None = None
    """Configure global model settings. Any non-null values will override the agent-specific model
    settings.
    """

    handoff_input_filter: HandoffInputFilter | None = None
    """A global input filter to apply to all handoffs. If `Handoff.input_filter` is set, then that
    will take precedence. The input filter allows you to edit the inputs that are sent to the new
    agent. See the documentation in `Handoff.input_filter` for more details.
    """

    input_guardrails: list[InputGuardrail[Any]] | None = None
    """A list of input guardrails to run on the initial run input."""

    output_guardrails: list[OutputGuardrail[Any]] | None = None
    """A list of output guardrails to run on the final output of the run."""

    tracing_disabled: bool = False
    """Whether tracing is disabled for the agent run. If disabled, we will not trace the agent run.
    """

    trace_include_sensitive_data: bool = True
    """Whether we include potentially sensitive data (for example: inputs/outputs of tool calls or
    LLM generations) in traces. If False, we'll still create spans for these events, but the
    sensitive data will not be included.
    """

    workflow_name: str = "Agent workflow"
    """The name of the run, used for tracing. Should be a logical name for the run, like
    "Code generation workflow" or "Customer support agent".
    """

    trace_id: str | None = None
    """A custom trace ID to use for tracing. If not provided, we will generate a new trace ID."""

    group_id: str | None = None
    """
    A grouping identifier to use for tracing, to link multiple traces from the same conversation
    or process. For example, you might use a chat thread ID.
    """

    trace_metadata: dict[str, Any] | None = None
    """
    An optional dictionary of additional metadata to include with the trace.
    """


class Runner:
    @classmethod
    async def run(
        cls,
        starting_agent: Agent[TContext],
        input: str | list[TResponseInputItem],
        *,
        context: TContext | None = None,
        max_turns: int = DEFAULT_MAX_TURNS,
        hooks: RunHooks[TContext] | None = None,
        run_config: RunConfig | None = None,
    ) -> RunResult:
        """Run a workflow starting at the given agent. The agent will run in a loop until a final
        output is generated. The loop runs like so:
        1. The agent is invoked with the given input.
        2. If there is a final output (i.e. the agent produces something of type
            `agent.output_type`, the loop terminates.
        3. If there's a handoff, we run the loop again, with the new agent.
        4. Else, we run tool calls (if any), and re-run the loop.

        In two cases, the agent may raise an exception:
        1. If the max_turns is exceeded, a MaxTurnsExceeded exception is raised.
        2. If a guardrail tripwire is triggered, a GuardrailTripwireTriggered exception is raised.

        Note that only the first agent's input guardrails are run.

        Args:
            starting_agent: The starting agent to run.
            input: The initial input to the agent. You can pass a single string for a user message,
                or a list of input items.
            context: The context to run the agent with.
            max_turns: The maximum number of turns to run the agent for. A turn is defined as one
                AI invocation (including any tool calls that might occur).
            hooks: An object that receives callbacks on various lifecycle events.
            run_config: Global settings for the entire agent run.

        Returns:
            A run result containing all the inputs, guardrail results and the output of the last
            agent. Agents may perform handoffs, so we don't know the specific type of the output.
        """
        if hooks is None:
            hooks = RunHooks[Any]()
        if run_config is None:
            run_config = RunConfig()

        tool_use_tracker = AgentToolUseTracker()

        with TraceCtxManager(
            workflow_name=run_config.workflow_name,
            trace_id=run_config.trace_id,
            group_id=run_config.group_id,
            metadata=run_config.trace_metadata,
            disabled=run_config.tracing_disabled,
        ):
            current_turn = 0
            original_input: str | list[TResponseInputItem] = copy.deepcopy(input)
            generated_items: list[RunItem] = []
            model_responses: list[ModelResponse] = []

            context_wrapper: RunContextWrapper[TContext] = RunContextWrapper(
                context=context,  # type: ignore
            )

            input_guardrail_results: list[InputGuardrailResult] = []

            current_span: Span[AgentSpanData] | None = None
            current_agent = starting_agent
            should_run_agent_start_hooks = True

            try:
                while True:
                    # Start an agent span if we don't have one. This span is ended if the current
                    # agent changes, or if the agent loop ends.
                    if current_span is None:
                        handoff_names = [h.agent_name for h in cls._get_handoffs(current_agent)]
                        if output_schema := cls._get_output_schema(current_agent):
                            output_type_name = output_schema.output_type_name()
                        else:
                            output_type_name = "str"

                        current_span = agent_span(
                            name=current_agent.name,
                            handoffs=handoff_names,
                            output_type=output_type_name,
                        )
                        current_span.start(mark_as_current=True)

                        all_tools = await cls._get_all_tools(current_agent)
                        current_span.span_data.tools = [t.name for t in all_tools]

                    current_turn += 1
                    if current_turn > max_turns:
                        _error_tracing.attach_error_to_span(
                            current_span,
                            SpanError(
                                message="Max turns exceeded",
                                data={"max_turns": max_turns},
                            ),
                        )
                        raise MaxTurnsExceeded(f"Max turns ({max_turns}) exceeded")

                    logger.debug(
                        f"Running agent {current_agent.name} (turn {current_turn})",
                    )

                    if current_turn == 1:
                        input_guardrail_results, turn_result = await asyncio.gather(
                            cls._run_input_guardrails(
                                starting_agent,
                                starting_agent.input_guardrails
                                + (run_config.input_guardrails or []),
                                copy.deepcopy(input),
                                context_wrapper,
                            ),
                            cls._run_single_turn(
                                agent=current_agent,
                                all_tools=all_tools,
                                original_input=original_input,
                                generated_items=generated_items,
                                hooks=hooks,
                                context_wrapper=context_wrapper,
                                run_config=run_config,
                                should_run_agent_start_hooks=should_run_agent_start_hooks,
                                tool_use_tracker=tool_use_tracker,
                            ),
                        )
                    else:
                        turn_result = await cls._run_single_turn(
                            agent=current_agent,
                            all_tools=all_tools,
                            original_input=original_input,
                            generated_items=generated_items,
                            hooks=hooks,
                            context_wrapper=context_wrapper,
                            run_config=run_config,
                            should_run_agent_start_hooks=should_run_agent_start_hooks,
                            tool_use_tracker=tool_use_tracker,
                        )
                    should_run_agent_start_hooks = False

                    model_responses.append(turn_result.model_response)
                    original_input = turn_result.original_input
                    generated_items = turn_result.generated_items

                    if isinstance(turn_result.next_step, NextStepFinalOutput):
                        output_guardrail_results = await cls._run_output_guardrails(
                            current_agent.output_guardrails + (run_config.output_guardrails or []),
                            current_agent,
                            turn_result.next_step.output,
                            context_wrapper,
                        )
                        return RunResult(
                            input=original_input,
                            new_items=generated_items,
                            raw_responses=model_responses,
                            final_output=turn_result.next_step.output,
                            _last_agent=current_agent,
                            input_guardrail_results=input_guardrail_results,
                            output_guardrail_results=output_guardrail_results,
                        )
                    elif isinstance(turn_result.next_step, NextStepHandoff):
                        # Get the previous agent before switching
                        previous_agent = current_agent
                        current_agent = cast(Agent[TContext], turn_result.next_step.new_agent)
                        
                        # Transfer message history for swarm patterns
                        # Check if both agents have models with message_history
                        if (hasattr(previous_agent, 'model') and hasattr(previous_agent.model, 'message_history') and
                            hasattr(current_agent, 'model') and hasattr(current_agent.model, 'message_history')):
                            # Import the is_swarm_pattern function from patterns utils
                            try:
                                from cai.agents.patterns.utils import is_swarm_pattern
                                # Check if either agent is part of a swarm pattern
                                if is_swarm_pattern(previous_agent) or is_swarm_pattern(current_agent):
                                    # Transfer the message history to the new agent
                                    current_agent.model.message_history = previous_agent.model.message_history
                                    # Also share history in AGENT_MANAGER
                                    if hasattr(previous_agent, 'name') and hasattr(current_agent, 'name'):
                                        from cai.sdk.agents.simple_agent_manager import AGENT_MANAGER
                                        AGENT_MANAGER.share_swarm_history(previous_agent.name, current_agent.name)
                            except ImportError:
                                # If we can't import, check if agents have bidirectional handoffs
                                # by looking if the new agent can handoff back to the previous agent
                                if hasattr(current_agent, 'handoffs'):
                                    for handoff_item in current_agent.handoffs:
                                        if hasattr(handoff_item, 'agent_name') and handoff_item.agent_name == previous_agent.name:
                                            # Bidirectional handoff detected, share history
                                            current_agent.model.message_history = previous_agent.model.message_history
                                            break
                        
                        # Register the handoff agent with AGENT_MANAGER for tracking
                        # This ensures patterns/swarms work with commands like /history and /graph
                        from cai.sdk.agents.simple_agent_manager import AGENT_MANAGER
                        if hasattr(current_agent, 'name'):
                            # For non-parallel patterns, use set_active_agent which will handle it as single agent
                            # This maintains compatibility with single agent commands
                            AGENT_MANAGER.set_active_agent(current_agent, current_agent.name)
                        
                        current_span.finish(reset_current=True)
                        current_span = None
                        should_run_agent_start_hooks = True
                    elif isinstance(turn_result.next_step, NextStepRunAgain):
                        pass
                    else:
                        raise AgentsException(
                            f"Unknown next step type: {type(turn_result.next_step)}"
                        )
            finally:
                if current_span:
                    current_span.finish(reset_current=True)

    @classmethod
    def run_sync(
        cls,
        starting_agent: Agent[TContext],
        input: str | list[TResponseInputItem],
        *,
        context: TContext | None = None,
        max_turns: int = DEFAULT_MAX_TURNS,
        hooks: RunHooks[TContext] | None = None,
        run_config: RunConfig | None = None,
    ) -> RunResult:
        """Run a workflow synchronously, starting at the given agent. Note that this just wraps the
        `run` method, so it will not work if there's already an event loop (e.g. inside an async
        function, or in a Jupyter notebook or async context like FastAPI). For those cases, use
        the `run` method instead.

        The agent will run in a loop until a final output is generated. The loop runs like so:
        1. The agent is invoked with the given input.
        2. If there is a final output (i.e. the agent produces something of type
            `agent.output_type`, the loop terminates.
        3. If there's a handoff, we run the loop again, with the new agent.
        4. Else, we run tool calls (if any), and re-run the loop.

        In two cases, the agent may raise an exception:
        1. If the max_turns is exceeded, a MaxTurnsExceeded exception is raised.
        2. If a guardrail tripwire is triggered, a GuardrailTripwireTriggered exception is raised.

        Note that only the first agent's input guardrails are run.

        Args:
            starting_agent: The starting agent to run.
            input: The initial input to the agent. You can pass a single string for a user message,
                or a list of input items.
            context: The context to run the agent with.
            max_turns: The maximum number of turns to run the agent for. A turn is defined as one
                AI invocation (including any tool calls that might occur).
            hooks: An object that receives callbacks on various lifecycle events.
            run_config: Global settings for the entire agent run.

        Returns:
            A run result containing all the inputs, guardrail results and the output of the last
            agent. Agents may perform handoffs, so we don't know the specific type of the output.
        """
        return asyncio.get_event_loop().run_until_complete(
            cls.run(
                starting_agent,
                input,
                context=context,
                max_turns=max_turns,
                hooks=hooks,
                run_config=run_config,
            )
        )

    @classmethod
    def run_streamed(
        cls,
        starting_agent: Agent[TContext],
        input: str | list[TResponseInputItem],
        context: TContext | None = None,
        max_turns: int = DEFAULT_MAX_TURNS,
        hooks: RunHooks[TContext] | None = None,
        run_config: RunConfig | None = None,
    ) -> RunResultStreaming:
        """Run a workflow starting at the given agent in streaming mode. The returned result object
        contains a method you can use to stream semantic events as they are generated.

        The agent will run in a loop until a final output is generated. The loop runs like so:
        1. The agent is invoked with the given input.
        2. If there is a final output (i.e. the agent produces something of type
            `agent.output_type`, the loop terminates.
        3. If there's a handoff, we run the loop again, with the new agent.
        4. Else, we run tool calls (if any), and re-run the loop.

        In two cases, the agent may raise an exception:
        1. If the max_turns is exceeded, a MaxTurnsExceeded exception is raised.
        2. If a guardrail tripwire is triggered, a GuardrailTripwireTriggered exception is raised.

        Note that only the first agent's input guardrails are run.

        Args:
            starting_agent: The starting agent to run.
            input: The initial input to the agent. You can pass a single string for a user message,
                or a list of input items.
            context: The context to run the agent with.
            max_turns: The maximum number of turns to run the agent for. A turn is defined as one
                AI invocation (including any tool calls that might occur).
            hooks: An object that receives callbacks on various lifecycle events.
            run_config: Global settings for the entire agent run.

        Returns:
            A result object that contains data about the run, as well as a method to stream events.
        """
        if hooks is None:
            hooks = RunHooks[Any]()
        if run_config is None:
            run_config = RunConfig()

        # If there's already a trace, we don't create a new one. In addition, we can't end the
        # trace here, because the actual work is done in `stream_events` and this method ends
        # before that.
        new_trace = (
            None
            if get_current_trace()
            else trace(
                workflow_name=run_config.workflow_name,
                trace_id=run_config.trace_id,
                group_id=run_config.group_id,
                metadata=run_config.trace_metadata,
                disabled=run_config.tracing_disabled,
            )
        )
        # Need to start the trace here, because the current trace contextvar is captured at
        # asyncio.create_task time
        if new_trace:
            new_trace.start(mark_as_current=True)

        output_schema = cls._get_output_schema(starting_agent)
        context_wrapper: RunContextWrapper[TContext] = RunContextWrapper(
            context=context  # type: ignore
        )

        streamed_result = RunResultStreaming(
            input=copy.deepcopy(input),
            new_items=[],
            current_agent=starting_agent,
            raw_responses=[],
            final_output=None,
            is_complete=False,
            current_turn=0,
            max_turns=max_turns,
            input_guardrail_results=[],
            output_guardrail_results=[],
            _current_agent_output_schema=output_schema,
            _trace=new_trace,
        )

        # Kick off the actual agent loop in the background and return the streamed result object.
        streamed_result._run_impl_task = asyncio.create_task(
            cls._run_streamed_impl(
                starting_input=input,
                streamed_result=streamed_result,
                starting_agent=starting_agent,
                max_turns=max_turns,
                hooks=hooks,
                context_wrapper=context_wrapper,
                run_config=run_config,
            )
        )
        return streamed_result

    @classmethod
    async def _run_input_guardrails_with_queue(
        cls,
        agent: Agent[Any],
        guardrails: list[InputGuardrail[TContext]],
        input: str | list[TResponseInputItem],
        context: RunContextWrapper[TContext],
        streamed_result: RunResultStreaming,
        parent_span: Span[Any],
    ):
        queue = streamed_result._input_guardrail_queue

        # We'll run the guardrails and push them onto the queue as they complete
        guardrail_tasks = [
            asyncio.create_task(
                RunImpl.run_single_input_guardrail(agent, guardrail, input, context)
            )
            for guardrail in guardrails
        ]
        guardrail_results = []
        try:
            for done in asyncio.as_completed(guardrail_tasks):
                result = await done
                if result.output.tripwire_triggered:
                    _error_tracing.attach_error_to_span(
                        parent_span,
                        SpanError(
                            message="Guardrail tripwire triggered",
                            data={
                                "guardrail": result.guardrail.get_name(),
                                "type": "input_guardrail",
                            },
                        ),
                    )
                queue.put_nowait(result)
                guardrail_results.append(result)
        except Exception:
            for t in guardrail_tasks:
                t.cancel()
            raise

        streamed_result.input_guardrail_results = guardrail_results

    @classmethod
    async def _run_streamed_impl(
        cls,
        starting_input: str | list[TResponseInputItem],
        streamed_result: RunResultStreaming,
        starting_agent: Agent[TContext],
        max_turns: int,
        hooks: RunHooks[TContext],
        context_wrapper: RunContextWrapper[TContext],
        run_config: RunConfig,
    ):
        current_span: Span[AgentSpanData] | None = None
        current_agent = starting_agent
        current_turn = 0
        should_run_agent_start_hooks = True
        tool_use_tracker = AgentToolUseTracker()

        streamed_result._event_queue.put_nowait(AgentUpdatedStreamEvent(new_agent=current_agent))

        try:
            while True:
                if streamed_result.is_complete:
                    break

                # Start an agent span if we don't have one. This span is ended if the current
                # agent changes, or if the agent loop ends.
                if current_span is None:
                    handoff_names = [h.agent_name for h in cls._get_handoffs(current_agent)]
                    if output_schema := cls._get_output_schema(current_agent):
                        output_type_name = output_schema.output_type_name()
                    else:
                        output_type_name = "str"

                    current_span = agent_span(
                        name=current_agent.name,
                        handoffs=handoff_names,
                        output_type=output_type_name,
                    )
                    current_span.start(mark_as_current=True)

                    all_tools = await cls._get_all_tools(current_agent)
                    tool_names = [t.name for t in all_tools]
                    current_span.span_data.tools = tool_names
                current_turn += 1
                streamed_result.current_turn = current_turn

                if current_turn > max_turns:
                    _error_tracing.attach_error_to_span(
                        current_span,
                        SpanError(
                            message="Max turns exceeded",
                            data={"max_turns": max_turns},
                        ),
                    )
                    streamed_result._event_queue.put_nowait(QueueCompleteSentinel())
                    break

                if current_turn == 1:
                    # Run the input guardrails in the background and put the results on the queue
                    streamed_result._input_guardrails_task = asyncio.create_task(
                        cls._run_input_guardrails_with_queue(
                            starting_agent,
                            starting_agent.input_guardrails + (run_config.input_guardrails or []),
                            copy.deepcopy(ItemHelpers.input_to_new_input_list(starting_input)),
                            context_wrapper,
                            streamed_result,
                            current_span,
                        )
                    )
                try:
                    turn_result = await cls._run_single_turn_streamed(
                        streamed_result,
                        current_agent,
                        hooks,
                        context_wrapper,
                        run_config,
                        should_run_agent_start_hooks,
                        tool_use_tracker,
                        all_tools,
                    )
                    should_run_agent_start_hooks = False
                    
                    # Process the turn result
                    streamed_result.raw_responses = streamed_result.raw_responses + [
                        turn_result.model_response
                    ]
                    streamed_result.input = turn_result.original_input
                    streamed_result.new_items = turn_result.generated_items

                    if isinstance(turn_result.next_step, NextStepHandoff):
                        # Get the previous agent before switching
                        previous_agent = current_agent
                        current_agent = turn_result.next_step.new_agent
                        
                        # Transfer message history for swarm patterns
                        # Check if both agents have models with message_history
                        if (hasattr(previous_agent, 'model') and hasattr(previous_agent.model, 'message_history') and
                            hasattr(current_agent, 'model') and hasattr(current_agent.model, 'message_history')):
                            # Import the is_swarm_pattern function from patterns utils
                            try:
                                from cai.agents.patterns.utils import is_swarm_pattern
                                # Check if either agent is part of a swarm pattern
                                if is_swarm_pattern(previous_agent) or is_swarm_pattern(current_agent):
                                    # Transfer the message history to the new agent
                                    current_agent.model.message_history = previous_agent.model.message_history
                                    # Also share history in AGENT_MANAGER
                                    if hasattr(previous_agent, 'name') and hasattr(current_agent, 'name'):
                                        from cai.sdk.agents.simple_agent_manager import AGENT_MANAGER
                                        AGENT_MANAGER.share_swarm_history(previous_agent.name, current_agent.name)
                            except ImportError:
                                # If we can't import, check if agents have bidirectional handoffs
                                # by looking if the new agent can handoff back to the previous agent
                                if hasattr(current_agent, 'handoffs'):
                                    for handoff_item in current_agent.handoffs:
                                        if hasattr(handoff_item, 'agent_name') and handoff_item.agent_name == previous_agent.name:
                                            # Bidirectional handoff detected, share history
                                            current_agent.model.message_history = previous_agent.model.message_history
                                            break
                        
                        current_span.finish(reset_current=True)
                        current_span = None
                        should_run_agent_start_hooks = True
                        streamed_result._event_queue.put_nowait(
                            AgentUpdatedStreamEvent(new_agent=current_agent)
                        )
                    elif isinstance(turn_result.next_step, NextStepFinalOutput):
                        streamed_result._output_guardrails_task = asyncio.create_task(
                            cls._run_output_guardrails(
                                current_agent.output_guardrails
                                + (run_config.output_guardrails or []),
                                current_agent,
                                turn_result.next_step.output,
                                context_wrapper,
                            )
                        )

                        try:
                            output_guardrail_results = await streamed_result._output_guardrails_task
                        except Exception:
                            # Exceptions will be checked in the stream_events loop
                            output_guardrail_results = []

                        streamed_result.output_guardrail_results = output_guardrail_results
                        streamed_result.final_output = turn_result.next_step.output
                        streamed_result.is_complete = True
                        streamed_result._event_queue.put_nowait(QueueCompleteSentinel())
                    elif isinstance(turn_result.next_step, NextStepRunAgain):
                        pass
                except (KeyboardInterrupt, asyncio.CancelledError) as e:
                    # Re-raise to propagate the interruption
                    raise e
                except Exception as e:
                    if current_span:
                        _error_tracing.attach_error_to_span(
                            current_span,
                            SpanError(
                                message="Error in agent run",
                                data={"error": str(e)},
                            ),
                        )
                    streamed_result.is_complete = True
                    streamed_result._event_queue.put_nowait(QueueCompleteSentinel())
                    raise

            streamed_result.is_complete = True
        finally:
            if current_span:
                current_span.finish(reset_current=True)

    @classmethod
    async def _run_single_turn_streamed(
        cls,
        streamed_result: RunResultStreaming,
        agent: Agent[TContext],
        hooks: RunHooks[TContext],
        context_wrapper: RunContextWrapper[TContext],
        run_config: RunConfig,
        should_run_agent_start_hooks: bool,
        tool_use_tracker: AgentToolUseTracker,
        all_tools: list[Tool],
    ) -> SingleStepResult:
        if should_run_agent_start_hooks:
            await asyncio.gather(
                hooks.on_agent_start(context_wrapper, agent),
                (
                    agent.hooks.on_start(context_wrapper, agent)
                    if agent.hooks
                    else _coro.noop_coroutine()
                ),
            )

        output_schema = cls._get_output_schema(agent)

        streamed_result.current_agent = agent
        streamed_result._current_agent_output_schema = output_schema

        system_prompt = _apply_auto_pentest_system_prompt(
            await agent.get_system_prompt(context_wrapper)
        )

        handoffs = cls._get_handoffs(agent)
        model = cls._get_model(agent, run_config)
        model_settings = agent.model_settings.resolve(run_config.model_settings)
        model_settings = RunImpl.maybe_reset_tool_choice(agent, tool_use_tracker, model_settings)

        # Ensure agent model is set in model_settings for streaming mode
        if not hasattr(model_settings, "agent_model") or not model_settings.agent_model:
            if isinstance(agent.model, str):
                model_settings.agent_model = agent.model
            elif isinstance(run_config.model, str):
                model_settings.agent_model = run_config.model

        final_response: ModelResponse | None = None

        input = ItemHelpers.input_to_new_input_list(streamed_result.input)
        input.extend([item.to_input_item() for item in streamed_result.new_items])

        # 1. Stream the output events
        async for event in model.stream_response(
            system_prompt,
            input,
            model_settings,
            all_tools,
            output_schema,
            handoffs,
            get_model_tracing_impl(
                run_config.tracing_disabled, run_config.trace_include_sensitive_data
            ),
        ):
            if isinstance(event, ResponseCompletedEvent):
                usage = (
                    Usage(
                        requests=1,
                        input_tokens=event.response.usage.input_tokens,
                        output_tokens=event.response.usage.output_tokens,
                        total_tokens=event.response.usage.total_tokens,
                    )
                    if event.response.usage
                    else Usage()
                )
                final_response = ModelResponse(
                    output=event.response.output,
                    usage=usage,
                    referenceable_id=event.response.id,
                )

            streamed_result._event_queue.put_nowait(RawResponsesStreamEvent(data=event))

        # 2. At this point, the streaming is complete for this turn of the agent loop.
        if not final_response:
            raise ModelBehaviorError("Model did not produce a final response!")

        # 3. Now, we can process the turn as we do in the non-streaming case
        single_step_result = None
        try:
            single_step_result = await cls._get_single_step_result_from_response(
                agent=agent,
                original_input=streamed_result.input,
                pre_step_items=streamed_result.new_items,
                new_response=final_response,
                output_schema=output_schema,
                all_tools=all_tools,
                handoffs=handoffs,
                hooks=hooks,
                context_wrapper=context_wrapper,
                run_config=run_config,
                tool_use_tracker=tool_use_tracker,
            )

            RunImpl.stream_step_result_to_queue(single_step_result, streamed_result._event_queue)
            return single_step_result
        except (KeyboardInterrupt, asyncio.CancelledError) as e:
            # When interrupted, we need to ensure the message history is consistent
            # The tool calls were already added during streaming, but results were not
            # If we have a partial result, stream it before re-raising
            if single_step_result:
                RunImpl.stream_step_result_to_queue(single_step_result, streamed_result._event_queue)
            raise e

    @classmethod
    async def _run_single_turn(
        cls,
        *,
        agent: Agent[TContext],
        all_tools: list[Tool],
        original_input: str | list[TResponseInputItem],
        generated_items: list[RunItem],
        hooks: RunHooks[TContext],
        context_wrapper: RunContextWrapper[TContext],
        run_config: RunConfig,
        should_run_agent_start_hooks: bool,
        tool_use_tracker: AgentToolUseTracker,
    ) -> SingleStepResult:
        # Ensure we run the hooks before anything else
        if should_run_agent_start_hooks:
            await asyncio.gather(
                hooks.on_agent_start(context_wrapper, agent),
                (
                    agent.hooks.on_start(context_wrapper, agent)
                    if agent.hooks
                    else _coro.noop_coroutine()
                ),
            )

        system_prompt = _apply_auto_pentest_system_prompt(
            await agent.get_system_prompt(context_wrapper)
        )

        output_schema = cls._get_output_schema(agent)
        handoffs = cls._get_handoffs(agent)
        input = ItemHelpers.input_to_new_input_list(original_input)
        input.extend([generated_item.to_input_item() for generated_item in generated_items])

        new_response = await cls._get_new_response(
            agent,
            system_prompt,
            input,
            output_schema,
            all_tools,
            handoffs,
            context_wrapper,
            run_config,
            tool_use_tracker,
        )

        return await cls._get_single_step_result_from_response(
            agent=agent,
            original_input=original_input,
            pre_step_items=generated_items,
            new_response=new_response,
            output_schema=output_schema,
            all_tools=all_tools,
            handoffs=handoffs,
            hooks=hooks,
            context_wrapper=context_wrapper,
            run_config=run_config,
            tool_use_tracker=tool_use_tracker,
        )

    @classmethod
    async def _get_single_step_result_from_response(
        cls,
        *,
        agent: Agent[TContext],
        all_tools: list[Tool],
        original_input: str | list[TResponseInputItem],
        pre_step_items: list[RunItem],
        new_response: ModelResponse,
        output_schema: AgentOutputSchema | None,
        handoffs: list[Handoff],
        hooks: RunHooks[TContext],
        context_wrapper: RunContextWrapper[TContext],
        run_config: RunConfig,
        tool_use_tracker: AgentToolUseTracker,
    ) -> SingleStepResult:
        processed_response = RunImpl.process_model_response(
            agent=agent,
            all_tools=all_tools,
            response=new_response,
            output_schema=output_schema,
            handoffs=handoffs,
        )

        # Log tools used with robust type checking
        if hasattr(processed_response, "tools_used") and processed_response.tools_used:
            for i, tool_call in enumerate(processed_response.tools_used):
                try:
                    # Safely extract tool name with multiple fallbacks
                    tool_name = "Unknown"
                    try:
                        if hasattr(tool_call, "tool"):
                            if isinstance(tool_call.tool, str):
                                tool_name = tool_call.tool
                            elif hasattr(tool_call.tool, "name"):
                                tool_name = tool_call.tool.name
                            else:
                                tool_name = str(tool_call.tool)
                    except Exception:
                        pass

                    # Safely extract call_id
                    call_id = "Unknown"
                    try:
                        if hasattr(tool_call, "call_id"):
                            call_id = str(tool_call.call_id)
                    except Exception:
                        pass

                    # Safely extract parsed_args
                    parsed_args = "Unknown"
                    try:
                        if hasattr(tool_call, "parsed_args"):
                            parsed_args = str(tool_call.parsed_args)
                    except Exception:
                        pass
                except Exception:
                    pass

        tool_use_tracker.add_tool_use(agent, processed_response.tools_used)

        return await RunImpl.execute_tools_and_side_effects(
            agent=agent,
            original_input=original_input,
            pre_step_items=pre_step_items,
            new_response=new_response,
            processed_response=processed_response,
            output_schema=output_schema,
            hooks=hooks,
            context_wrapper=context_wrapper,
            run_config=run_config,
        )

    @classmethod
    async def _run_input_guardrails(
        cls,
        agent: Agent[Any],
        guardrails: list[InputGuardrail[TContext]],
        input: str | list[TResponseInputItem],
        context: RunContextWrapper[TContext],
    ) -> list[InputGuardrailResult]:
        if not guardrails:
            return []

        guardrail_tasks = [
            asyncio.create_task(
                RunImpl.run_single_input_guardrail(agent, guardrail, input, context)
            )
            for guardrail in guardrails
        ]

        guardrail_results = []

        for done in asyncio.as_completed(guardrail_tasks):
            result = await done
            if result.output.tripwire_triggered:
                # Cancel all guardrail tasks if a tripwire is triggered.
                for t in guardrail_tasks:
                    t.cancel()
                _error_tracing.attach_error_to_current_span(
                    SpanError(
                        message="Guardrail tripwire triggered",
                        data={"guardrail": result.guardrail.get_name()},
                    )
                )
                raise InputGuardrailTripwireTriggered(result)
            else:
                guardrail_results.append(result)

        return guardrail_results

    @classmethod
    async def _run_output_guardrails(
        cls,
        guardrails: list[OutputGuardrail[TContext]],
        agent: Agent[TContext],
        agent_output: Any,
        context: RunContextWrapper[TContext],
    ) -> list[OutputGuardrailResult]:
        if not guardrails:
            return []

        guardrail_tasks = [
            asyncio.create_task(
                RunImpl.run_single_output_guardrail(guardrail, agent, agent_output, context)
            )
            for guardrail in guardrails
        ]

        guardrail_results = []

        for done in asyncio.as_completed(guardrail_tasks):
            result = await done
            if result.output.tripwire_triggered:
                # Cancel all guardrail tasks if a tripwire is triggered.
                for t in guardrail_tasks:
                    t.cancel()
                _error_tracing.attach_error_to_current_span(
                    SpanError(
                        message="Guardrail tripwire triggered",
                        data={"guardrail": result.guardrail.get_name()},
                    )
                )
                raise OutputGuardrailTripwireTriggered(result)
            else:
                guardrail_results.append(result)

        return guardrail_results

    @classmethod
    async def _get_new_response(
        cls,
        agent: Agent[TContext],
        system_prompt: str | None,
        input: list[TResponseInputItem],
        output_schema: AgentOutputSchema | None,
        all_tools: list[Tool],
        handoffs: list[Handoff],
        context_wrapper: RunContextWrapper[TContext],
        run_config: RunConfig,
        tool_use_tracker: AgentToolUseTracker,
    ) -> ModelResponse:
        model = cls._get_model(agent, run_config)
        model_settings = agent.model_settings.resolve(run_config.model_settings)
        model_settings = RunImpl.maybe_reset_tool_choice(agent, tool_use_tracker, model_settings)

        # Ensure agent model is set in model_settings
        if not hasattr(model_settings, "agent_model") or not model_settings.agent_model:
            if isinstance(agent.model, str):
                model_settings.agent_model = agent.model
            elif isinstance(run_config.model, str):
                model_settings.agent_model = run_config.model

        new_response = await model.get_response(
            system_instructions=_apply_auto_pentest_system_prompt(system_prompt),
            input=input,
            model_settings=model_settings,
            tools=all_tools,
            output_schema=output_schema,
            handoffs=handoffs,
            tracing=get_model_tracing_impl(
                run_config.tracing_disabled, run_config.trace_include_sensitive_data
            ),
        )

        context_wrapper.usage.add(new_response.usage)

        return new_response

    @classmethod
    def _get_output_schema(cls, agent: Agent[Any]) -> AgentOutputSchema | None:
        if agent.output_type is None or agent.output_type is str:
            return None

        return AgentOutputSchema(agent.output_type)

    @classmethod
    def _get_handoffs(cls, agent: Agent[Any]) -> list[Handoff]:
        handoffs = []
        for handoff_item in agent.handoffs:
            if isinstance(handoff_item, Handoff):
                handoffs.append(handoff_item)
            elif isinstance(handoff_item, Agent):
                handoffs.append(handoff(handoff_item))
        return handoffs

    @classmethod
    async def _get_all_tools(cls, agent: Agent[Any]) -> list[Tool]:
        return await agent.get_all_tools()

    @classmethod
    def _get_model(cls, agent: Agent[Any], run_config: RunConfig) -> Model:
        model = None
        agent_model = None
        if isinstance(run_config.model, Model):
            model = run_config.model
        elif isinstance(run_config.model, str):
            model = run_config.model_provider.get_model(run_config.model)
            agent_model = run_config.model
        elif isinstance(agent.model, Model):
            model = agent.model
        else:
            model = run_config.model_provider.get_model(agent.model)
            agent_model = agent.model

        # Store the original agent model in model_settings for later use
        if agent_model and hasattr(agent, "model_settings"):
            agent.model_settings.agent_model = agent_model

        # Set agent name if the model supports it (for CLI display)
        if hasattr(model, "set_agent_name"):
            model.set_agent_name(agent.name)

        return model
