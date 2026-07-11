#!/usr/bin/env python3
"""Interactive installer for Forgex.

Run this from the repo root:

    python install.py        (Windows / macOS / Linux)
    python3 install.py       (macOS / Linux, if `python` isn't aliased)

It walks you through:

    1) Your OS (Windows / Linux / macOS)
    2) If Linux, which distro family you're on (so it knows which
       package manager to use for native libraries)
    3) Whether you want a full development setup or a standard
       install with the extra forensic-format extras

...then installs Forgex accordingly. No third-party packages are
required to *run* this script — it's stdlib-only on purpose, since it
has to work before Forgex's own dependencies are installed.
"""
from __future__ import annotations

import platform
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent


# ---------------------------------------------------------------------
# small menu helper
# ---------------------------------------------------------------------
def ask(question: str, options: list[str]) -> int:
    """Print a numbered menu and return the 1-based index the user picked."""
    print(f"\n{question}")
    for i, opt in enumerate(options, start=1):
        print(f"  {i}) {opt}")
    while True:
        choice = input(f"Enter 1-{len(options)}: ").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(options):
            return int(choice)
        print(f"Please enter a number between 1 and {len(options)}.")


def confirm(question: str, default_yes: bool = True) -> bool:
    suffix = "[Y/n]" if default_yes else "[y/N]"
    answer = input(f"{question} {suffix}: ").strip().lower()
    if not answer:
        return default_yes
    return answer in ("y", "yes")


def run(cmd: list[str], *, sudo: bool = False) -> bool:
    """Run a command, showing it first. Returns True on success."""
    if sudo and platform.system() != "Windows":
        cmd = ["sudo", *cmd]
    print(f"  $ {' '.join(cmd)}")
    try:
        subprocess.run(cmd, check=True)
        return True
    except FileNotFoundError:
        print(f"  ! '{cmd[0]}' not found on this system, skipping.")
        return False
    except subprocess.CalledProcessError as exc:
        print(f"  ! Command failed (exit code {exc.returncode}).")
        return False


# ---------------------------------------------------------------------
# step 1: OS
# ---------------------------------------------------------------------
OS_WINDOWS, OS_LINUX, OS_MACOS = "windows", "linux", "macos"


def ask_os() -> str:
    choice = ask(
        "Which OS are you installing Forgex on?",
        ["Windows", "Linux", "macOS"],
    )
    return {1: OS_WINDOWS, 2: OS_LINUX, 3: OS_MACOS}[choice]


# ---------------------------------------------------------------------
# step 2 (Linux only): distro family
# ---------------------------------------------------------------------
# Each family maps to the package manager used by it *and* the other
# distros commonly based on it, so picking "Ubuntu / Debian" also
# covers Mint, Pop!_OS, Kali, Zorin, elementary OS, etc.
LINUX_FAMILIES = {
    "debian": {
        "label": "Ubuntu / Debian (and derivatives: Mint, Pop!_OS, Kali, Zorin, elementary, Raspberry Pi OS...)",
        "pm": "apt",
        "update_cmd": ["apt-get", "update"],
        "install_cmd": ["apt-get", "install", "-y"],
        "packages": ["libmagic1", "libpango-1.0-0", "libpangocairo-1.0-0",
                     "libgdk-pixbuf2.0-0", "libffi-dev", "shared-mime-info"],
    },
    "fedora": {
        "label": "Fedora / RHEL / CentOS (and derivatives: Rocky Linux, AlmaLinux, Nobara...)",
        "pm": "dnf",
        "update_cmd": None,
        "install_cmd": ["dnf", "install", "-y"],
        "packages": ["file-libs", "pango", "gdk-pixbuf2", "libffi-devel"],
    },
    "arch": {
        "label": "Arch (and derivatives: Manjaro, EndeavourOS, Garuda...)",
        "pm": "pacman",
        "update_cmd": None,
        "install_cmd": ["pacman", "-S", "--noconfirm"],
        "packages": ["file", "pango", "gdk-pixbuf2", "libffi"],
    },
    "opensuse": {
        "label": "openSUSE (Leap / Tumbleweed)",
        "pm": "zypper",
        "update_cmd": None,
        "install_cmd": ["zypper", "install", "-y"],
        "packages": ["file-magic", "pango", "gdk-pixbuf-devel", "libffi-devel"],
    },
    "alpine": {
        "label": "Alpine",
        "pm": "apk",
        "update_cmd": None,
        "install_cmd": ["apk", "add"],
        "packages": ["file-dev", "pango", "gdk-pixbuf", "libffi-dev"],
    },
    "other": {
        "label": "Other / not sure (skip automatic native-library install)",
        "pm": None,
        "update_cmd": None,
        "install_cmd": None,
        "packages": [],
    },
}


def detect_linux_family() -> str | None:
    """Best-effort guess from /etc/os-release, used only as a hint."""
    os_release = Path("/etc/os-release")
    if not os_release.exists():
        return None
    text = os_release.read_text(encoding="utf-8", errors="ignore").lower()
    if "id_like" in text:
        for line in text.splitlines():
            if line.startswith("id_like="):
                like = line.split("=", 1)[1].strip('"')
                for family in ("debian", "fedora", "arch", "opensuse", "alpine"):
                    if family in like:
                        return family
    for line in text.splitlines():
        if line.startswith("id="):
            distro_id = line.split("=", 1)[1].strip('"')
            if distro_id in ("ubuntu", "debian", "linuxmint", "pop", "kali", "zorin", "raspbian"):
                return "debian"
            if distro_id in ("fedora", "rhel", "centos", "rocky", "almalinux", "nobara"):
                return "fedora"
            if distro_id in ("arch", "manjaro", "endeavouros", "garuda"):
                return "arch"
            if distro_id in ("opensuse", "opensuse-leap", "opensuse-tumbleweed"):
                return "opensuse"
            if distro_id == "alpine":
                return "alpine"
    return None


def ask_linux_family() -> str:
    guess = detect_linux_family()
    keys = list(LINUX_FAMILIES.keys())
    labels = [LINUX_FAMILIES[k]["label"] for k in keys]
    if guess:
        print(f"\nDetected distro family: {LINUX_FAMILIES[guess]['label']}")
        if confirm("Use this?"):
            return guess
    choice = ask("Which distro family are you on?", labels)
    return keys[choice - 1]


# ---------------------------------------------------------------------
# step 3: install type
# ---------------------------------------------------------------------
INSTALL_DEV, INSTALL_FULL = "dev", "full"


def ask_install_type() -> str:
    choice = ask(
        "What kind of install do you want?",
        [
            "Full development setup — editable install, includes dev tools "
            "(pytest, ruff) and all optional forensic-format extras. Pick this "
            "if you're going to edit Forgex's code.",
            "Standard install with the extra stuff — regular (non-editable) "
            "install with all optional forensic-format extras (yara, scapy, "
            "registry/EVTX parsing, PDF/report rendering, etc.), for everyday use.",
        ],
    )
    return INSTALL_DEV if choice == 1 else INSTALL_FULL


# ---------------------------------------------------------------------
# native/system dependencies for the "full" extras
# ---------------------------------------------------------------------
def install_system_deps(os_choice: str, linux_family: str | None) -> None:
    print("\nSome of the optional extras (python-magic, weasyprint) rely on "
          "native system libraries, not just Python packages.")

    if os_choice == OS_LINUX:
        family = LINUX_FAMILIES.get(linux_family or "other")
        if not family["install_cmd"]:
            print("Skipping automatic native-library install — install libmagic, "
                  "pango, gdk-pixbuf and libffi yourself if you hit import errors.")
            return
        if not confirm(f"Install native libraries via {family['pm']} now? (uses sudo)"):
            return
        if family["update_cmd"]:
            run(family["update_cmd"], sudo=True)
        run([*family["install_cmd"], *family["packages"]], sudo=True)

    elif os_choice == OS_MACOS:
        if not shutil.which("brew"):
            print("Homebrew not found — install it from https://brew.sh first, "
                  "then re-run this script, or install libmagic/pango/gdk-pixbuf/libffi manually.")
            return
        if confirm("Install native libraries via Homebrew now?"):
            run(["brew", "install", "libmagic", "pango", "gdk-pixbuf", "libffi"])

    elif os_choice == OS_WINDOWS:
        print("On Windows:")
        print("  - python-magic needs a DLL bundle; we'll install 'python-magic-bin' "
              "instead of 'python-magic' below to cover that.")
        print("  - weasyprint (PDF report rendering) needs the GTK3 runtime installed "
              "separately: https://weasyprint.readthedocs.io/en/stable/install.html#windows")


# ---------------------------------------------------------------------
# pip install
# ---------------------------------------------------------------------
def pip_install(install_type: str, os_choice: str) -> bool:
    pip_cmd = [sys.executable, "-m", "pip", "install"]

    if install_type == INSTALL_DEV:
        pip_cmd.append("-e")
        target = f"{REPO_ROOT}[full,dev]"
    else:
        target = f"{REPO_ROOT}[full]"
    pip_cmd.append(target)

    print(f"\nInstalling Forgex ({'editable, full + dev extras' if install_type == INSTALL_DEV else 'full extras'})...")
    ok = run(pip_cmd)

    if not ok:
        # Common on newer distro Python installs (PEP 668 "externally
        # managed environment"). Offer the standard escape hatches.
        print("\nThat install failed — if the error mentions an "
              "'externally-managed-environment', try one of:")
        print(f"  {sys.executable} -m pip install {'-e ' if install_type == INSTALL_DEV else ''}"
              f"{target} --break-system-packages")
        print(f"  python3 -m venv .venv && . .venv/bin/activate && "
              f"pip install {'-e ' if install_type == INSTALL_DEV else ''}{target}")
        return False

    if os_choice == OS_WINDOWS:
        run([sys.executable, "-m", "pip", "install", "python-magic-bin"])

    return True


# ---------------------------------------------------------------------
# main
# ---------------------------------------------------------------------
def main() -> None:
    print("=" * 60)
    print("  Forgex installer")
    print("=" * 60)

    os_choice = ask_os()
    linux_family = ask_linux_family() if os_choice == OS_LINUX else None
    install_type = ask_install_type()

    if confirm("\nInstall native system libraries needed by the extras?"):
        install_system_deps(os_choice, linux_family)

    success = pip_install(install_type, os_choice)

    print("\n" + "=" * 60)
    if success:
        print("Done. Try it out with:")
        print("  forgex --help")
        print("  forgex plugin list")
        print("from any directory — it doesn't need to be the repo root.")
    else:
        print("Install did not complete. See the suggestions above and re-run.")
    print("=" * 60)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nCancelled.")
        sys.exit(1)
