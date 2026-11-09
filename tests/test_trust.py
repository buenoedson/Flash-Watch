"""Testes para o verificador de confiabilidade de processos (trust.py)."""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from flashwatch import trust


def _fake_inspector(signed: bool = True, valid: bool = True, source: str = "pe", signer: str = "Microsoft Corporation"):
    def _fn(path):
        return {
            "path": path or "",
            "exists": bool(path),
            "signed": signed,
            "signature_valid": valid,
            "signature_source": source,
            "signer": signer,
            "status_hex": "0x00000000" if valid else "0x800B0100",
            "sha256": "deadbeef" * 8 if path else "",
        }
    return _fn


def test_trusted_microsoft_binary():
    res = trust.evaluate_trust(
        r"C:\Windows\System32\notepad.exe",
        image="notepad.exe",
        cmdline="notepad.exe",
        file_inspector=_fake_inspector(source="catalog", signer="Microsoft Windows"),
    )
    assert res["verdict"] == trust.VERDICT_TRUSTED_MS
    assert res["signed"] is True


def test_trusted_third_party_signed():
    res = trust.evaluate_trust(
        r"C:\Program Files (x86)\AnyDesk\AnyDesk.exe",
        image="AnyDesk.exe",
        cmdline=r'"C:\Program Files (x86)\AnyDesk\AnyDesk.exe" --backend',
        file_inspector=_fake_inspector(source="pe", signer="philandro Software GmbH"),
    )
    assert res["verdict"] == trust.VERDICT_TRUSTED_SIGNED


def test_lolbin_executing_script():
    res = trust.evaluate_trust(
        r"C:\Windows\System32\cmd.exe",
        image="cmd.exe",
        cmdline=r'cmd.exe /c "C:\jobs\backup.bat"',
        file_inspector=_fake_inspector(source="catalog", signer="Microsoft Windows"),
    )
    assert res["verdict"] == trust.VERDICT_LOLBIN_CAUTION
    assert any("script" in r.lower() for r in res["reasons"])


def test_suspicious_encoded_powershell():
    res = trust.evaluate_trust(
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        image="powershell.exe",
        cmdline="powershell.exe -NoP -W Hidden -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA",
        file_inspector=_fake_inspector(source="catalog", signer="Microsoft Windows"),
    )
    assert res["verdict"] == trust.VERDICT_SUSPICIOUS
    assert any("Base64" in r for r in res["reasons"])


def test_suspicious_masquerading_system_process():
    res = trust.evaluate_trust(
        r"C:\Users\Public\svchost.exe",
        image="svchost.exe",
        cmdline=r"C:\Users\Public\svchost.exe",
        file_inspector=_fake_inspector(source="pe", signer="Microsoft Corporation"),
    )
    assert res["verdict"] == trust.VERDICT_SUSPICIOUS
    assert any("masquerading" in r.lower() for r in res["reasons"])


def test_unsigned_in_temp_vs_program_files():
    untrusted_insp = _fake_inspector(signed=False, valid=False, source="none", signer="")
    r_temp = trust.evaluate_trust(
        r"C:\Users\user\AppData\Local\Temp\updater.exe",
        image="updater.exe",
        cmdline="updater.exe",
        file_inspector=untrusted_insp,
    )
    assert r_temp["verdict"] == trust.VERDICT_SUSPICIOUS

    r_prog = trust.evaluate_trust(
        r"C:\Tools\mytool.exe",
        image="mytool.exe",
        cmdline="mytool.exe",
        file_inspector=untrusted_insp,
    )
    assert r_prog["verdict"] == trust.VERDICT_UNSIGNED


@pytest.mark.skipif(sys.platform != "win32", reason="Requer WinVerifyTrust / CatRoot do Windows")
def test_real_windows_catalog_and_pe_verification(tmp_path: Path):
    cmd_path = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "cmd.exe")
    info = trust.inspect_executable(cmd_path)
    assert info["exists"] is True
    assert info["signature_valid"] is True
    assert info["signature_source"] in ("catalog", "pe")
    assert len(info["sha256"]) == 64

    # Arquivo não assinado criado em tmp_path
    dummy = tmp_path / "unsigned_tool.exe"
    dummy.write_bytes(b"MZ" + b"\x00" * 128)
    u_info = trust.inspect_executable(str(dummy))
    assert u_info["exists"] is True
    assert u_info["signature_valid"] is False
    assert len(u_info["sha256"]) == 64

