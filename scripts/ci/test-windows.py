#!/usr/bin/env python3
"""Run the static Qt suite and the shipped executable on a disposable Windows runner."""
import ctypes
from ctypes import wintypes
import hashlib
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import zipfile


ROOT = Path(__file__).resolve().parents[2]
RESULTS = ROOT / ".build/results"


def sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def main_window(pid, title):
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    callback_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    user32.EnumWindows.argtypes = [callback_type, wintypes.LPARAM]
    user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
    user32.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
    user32.IsWindowVisible.argtypes = [wintypes.HWND]
    found = []

    @callback_type
    def visit(hwnd, _):
        owner = wintypes.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(owner))
        text = ctypes.create_unicode_buffer(512)
        user32.GetWindowTextW(hwnd, text, len(text))
        if owner.value == pid and user32.IsWindowVisible(hwnd) and text.value == title:
            found.append(hwnd)
        return True

    user32.EnumWindows(visit, 0)
    return found[0] if found else None


def smoke(executable, database, version, label):
    # Only Windows system directories are on PATH: no developer Qt/MinGW DLLs.
    environment = os.environ.copy()
    environment["PATH"] = str(Path(os.environ["SystemRoot"]) / "System32")
    environment["QT_QPA_PLATFORM"] = "windows"
    process = subprocess.Popen([str(executable)], cwd=executable.parent, env=environment)
    try:
        deadline = time.monotonic() + 90
        window = None
        ready = False
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError(f"{label}: exited during startup ({process.returncode})")
            window = main_window(process.pid, f"STIGQter {version}")
            if database.exists():
                try:
                    with sqlite3.connect(database, timeout=1) as db:
                        ready = db.execute("SELECT COUNT(*) FROM CCI").fetchone()[0] > 0
                except sqlite3.Error:
                    pass
            if window and ready:
                break
            time.sleep(0.5)
        if not window or not ready:
            raise RuntimeError(f"{label}: main window or initialized SQLite database missing")
        # Give the startup version worker time to finish, then request a normal close.
        time.sleep(10)
        user32 = ctypes.WinDLL("user32", use_last_error=True)
        user32.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
        if not user32.PostMessageW(window, 0x0010, 0, 0):  # WM_CLOSE
            raise ctypes.WinError(ctypes.get_last_error())
        if process.wait(timeout=60) != 0:
            raise RuntimeError(f"{label}: nonzero shutdown status ({process.returncode})")
        with sqlite3.connect(database) as db:
            if db.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise RuntimeError(f"{label}: SQLite integrity check failed")
            errors = db.execute("SELECT message FROM Log WHERE message LIKE 'Version check unavailable:%'").fetchall()
            if errors:
                raise RuntimeError(f"{label}: startup version check failed: {errors}")
        print(f"PASS: {label}: visible GUI, SQLite, startup version check, clean shutdown", flush=True)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()


def main():
    if sys.platform != "win32" or os.environ.get("GITHUB_ACTIONS") != "true":
        raise RuntimeError("Run only in a disposable GitHub-hosted Windows job")
    RESULTS.mkdir(parents=True, exist_ok=True)
    version = (ROOT / "VERSION").read_text().strip()
    dist = ROOT / ".build/dist"
    for line in (dist / "SHA256SUMS-windows.txt").read_text().splitlines():
        expected, name = line.split(maxsplit=1)
        if sha256(dist / name.removeprefix("*")) != expected:
            raise RuntimeError(f"Package checksum mismatch: {name}")

    with tempfile.TemporaryDirectory(prefix="STIGQter-release-") as temporary:
        runtime = Path(temporary)
        fixtures = runtime / "tests"
        fixtures.mkdir()
        for name in ("U_ASD_V5R1_STIG.zip", "U_ASD_V5R2_STIG.zip", "emassTRImport.xlsx", "xccdf_lol.xml"):
            shutil.copy2(ROOT / "tests" / name, fixtures)
        test = runtime / "tst_stigqter.exe"
        shutil.copy2(ROOT / ".build/windows/tests/release/tst_stigqter.exe", test)
        environment = os.environ.copy()
        environment["QT_QPA_PLATFORM"] = "windows"
        environment["STIGQTER_LIVE_RELEASE_CHECK"] = "1"
        subprocess.run([str(test), "-o", f"{RESULTS / 'windows-tests.txt'},txt", "-o",
                        f"{RESULTS / 'windows-tests.xml'},junitxml"], cwd=runtime,
                       env=environment, timeout=900, check=True)
        print((RESULTS / "windows-tests.txt").read_text(), flush=True)

        package = runtime / "portable"
        with zipfile.ZipFile(dist / f"STIGQter-{version}-win64.zip") as archive:
            archive.extractall(package)
        executable = package / "STIGQter.exe"
        if sha256(executable) != sha256(dist / f"STIGQter-{version}-win64.exe"):
            raise RuntimeError("ZIP executable differs from the standalone release asset")
        database = package / "STIGQter.db"
        database.touch()
        smoke(executable, database, version, "portable database")

        normal = runtime / "normal"
        normal.mkdir()
        shutil.copy2(executable, normal)
        appdata = Path(os.environ["APPDATA"]) / "STIGQter"
        if appdata.exists():
            raise RuntimeError("Refusing to touch a pre-existing STIGQter application-data directory")
        try:
            smoke(normal / "STIGQter.exe", appdata / "STIGQter.db", version, "normal user database")
        finally:
            if appdata.exists():
                shutil.rmtree(appdata)
    (RESULTS / "windows-smoke.txt").write_text(
        f"STIGQter {version}: package hashes and ZIP/EXE identity verified; native Qt suite passed; "
        "portable and normal SQLite startup, live Pages TLS, and clean shutdown passed.\n")


if __name__ == "__main__":
    main()
