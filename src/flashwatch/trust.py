"""Verificação de confiabilidade de processos e linhas de comando no Windows 11.

Camadas implementadas (100% offline, sem dependências externas, RNF-03):
1. Assinatura digital Authenticode embutida (PE) + Catálogo do Windows (WinVerifyTrust / CryptCATAdmin)
   com extração do nome do signatário (CryptQueryObject + CertGetNameStringW).
2. Reputação de diretório (System32/Program Files/WindowsApps vs. %TEMP%/%APPDATA%/Downloads/Public)
   e detecção de masquerading de binários críticos do Windows.
3. Análise heurística de LOLBins (cmd/powershell/wscript/mshta/rundll32/regsvr32/certutil/bitsadmin)
   e de linhas de comando (ofuscação -EncodedCommand, -WindowStyle Hidden, scripts em pastas temporárias).
4. Cálculo de hash SHA-256 com cache por (caminho_normalizado, mtime_ns, tamanho).
"""
from __future__ import annotations

import ctypes
import hashlib
import ntpath
import os
import re
import sys
import threading
from ctypes import wintypes
from pathlib import Path

IS_WINDOWS = sys.platform == "win32"

VERDICT_TRUSTED_MS = "confiavel_microsoft"
VERDICT_TRUSTED_SIGNED = "confiavel_assinado"
VERDICT_LOLBIN_CAUTION = "atencao_lolbin"
VERDICT_UNSIGNED = "nao_assinado"
VERDICT_SUSPICIOUS = "suspeito"
VERDICT_UNKNOWN = "desconhecido"

VERDICT_LABELS = {
    VERDICT_TRUSTED_MS: "CONFIÁVEL (Microsoft)",
    VERDICT_TRUSTED_SIGNED: "CONFIÁVEL (Assinado)",
    VERDICT_LOLBIN_CAUTION: "ATENÇÃO (LOLBin/Script)",
    VERDICT_UNSIGNED: "NÃO ASSINADO",
    VERDICT_SUSPICIOUS: "SUSPEITO / ALTO RISCO",
    VERDICT_UNKNOWN: "DESCONHECIDO",
}

SYSTEM_CRITICAL_NAMES = frozenset({
    "svchost.exe", "csrss.exe", "smss.exe", "wininit.exe", "winlogon.exe",
    "services.exe", "lsass.exe", "conhost.exe", "explorer.exe", "sihost.exe",
    "taskhostw.exe", "dwm.exe", "runtimebroker.exe", "dllhost.exe",
})

LOLBIN_INTERPRETERS = frozenset({
    "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe",
    "msiexec.exe", "forfiles.exe", "pcalua.exe", "installutil.exe", "msbuild.exe",
})

HIGH_RISK_CMD_PATTERNS: tuple[tuple[re.Pattern, str], ...] = (
    (re.compile(r"(?i)(?:^|\s)-(?:e|en|enc|enco|encodedcommand)\s+[A-Za-z0-9+/=]{16,}"),
     "PowerShell com comando codificado em Base64 (-EncodedCommand)"),
    (re.compile(r"(?i)frombase64string\s*\("),
     "Decodificação dinâmica de payload Base64"),
    (re.compile(r"(?i)\b(?:iex|invoke-expression)\b"),
     "Execução dinâmica via Invoke-Expression (IEX)"),
    (re.compile(r"(?i)\b(?:downloadstring|downloadfile|downloaddata|invoke-webrequest|invoke-restmethod|start-bitstransfer)\b"),
     "Download de conteúdo remoto na linha de comando"),
    (re.compile(r"(?i)\bcertutil(?:\.exe)?\b[^\n]*-urlcache"),
     "Uso de certutil para download remoto (-urlcache)"),
    (re.compile(r"(?i)\bbitsadmin(?:\.exe)?\b[^\n]*/transfer"),
     "Uso de bitsadmin para transferência de arquivo"),
    (re.compile(r"(?i)\bmshta(?:\.exe)?\b[^\n]*(?:http://|https://|javascript:|vbscript:)"),
     "Execução de script remoto/inline via mshta.exe"),
    (re.compile(r"(?i)\bregsvr32(?:\.exe)?\b[^\n]*/i:https?:"),
     "Execução remota de scriptlet via regsvr32 (/i:http)"),
)

CAUTION_CMD_PATTERNS: tuple[tuple[re.Pattern, str], ...] = (
    (re.compile(r"(?i)(?:^|\s)-(?:w|windowstyle)\s+hidden\b"),
     "Janela oculta explicitamente (-WindowStyle Hidden)"),
    (re.compile(r"(?i)(?:^|\s)-(?:ep|executionpolicy)\s+(?:bypass|unrestricted)\b"),
     "Bypass de política de execução do PowerShell (-ExecutionPolicy Bypass)"),
    (re.compile(r"(?i)\.(?:bat|cmd|ps1|vbs|js|wsf|hta)\b"),
     "Execução de arquivo de script (.bat/.ps1/.vbs/.js/.hta)"),
)

_TEMP_PATH_FRAGMENTS = (
    "\\appdata\\local\\temp\\",
    "\\appdata\\roaming\\",
    "\\users\\public\\",
    "\\programdata\\temp\\",
    "\\windows\\temp\\",
    "\\downloads\\",
)

# --------------------------------------------------------------------------------------
# Estruturas e Bindings Win32 (wintrust.dll / crypt32.dll) — RNF-03
# --------------------------------------------------------------------------------------
TRUST_E_NOSIGNATURE = 0x800B0100
TRUST_E_BAD_DIGEST = 0x80096010
TRUST_E_EXPLICIT_DISTRUST = 0x800B0111
TRUST_E_SUBJECT_NOT_TRUSTED = 0x800B0004
CERT_E_EXPIRED = 0x800B0101
CERT_E_UNTRUSTEDROOT = 0x800B0109
CERT_E_REVOKED = 0x800B010C

WTD_UI_NONE = 2
WTD_REVOKE_NONE = 0
WTD_CHOICE_FILE = 1
WTD_CHOICE_CATALOG = 2
WTD_STATEACTION_VERIFY = 1
WTD_STATEACTION_CLOSE = 2
WTD_CACHE_ONLY_URL_RETRIEVAL = 0x00001000

CERT_QUERY_OBJECT_FILE = 1
CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED = 1 << 10
CERT_QUERY_FORMAT_FLAG_BINARY = 2
CERT_NAME_SIMPLE_DISPLAY_TYPE = 4

GENERIC_READ = 0x80000000
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
FILE_SHARE_DELETE = 0x00000004
OPEN_EXISTING = 3
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", wintypes.DWORD),
        ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD),
        ("Data4", wintypes.BYTE * 8),
    ]


# {00AAC56B-CD44-11d0-8CC2-00C04FC295EE} — WINTRUST_ACTION_GENERIC_VERIFY_V2
WINTRUST_ACTION_GENERIC_VERIFY_V2 = GUID(
    0x00AAC56B, 0xCD44, 0x11D0,
    (wintypes.BYTE * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE),
)


class WINTRUST_FILE_INFO(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD),
        ("pcwszFilePath", wintypes.LPCWSTR),
        ("hFile", wintypes.HANDLE),
        ("pgKnownSubject", ctypes.POINTER(GUID)),
    ]


class WINTRUST_CATALOG_INFO(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD),
        ("dwCatalogVersion", wintypes.DWORD),
        ("pcwszCatalogFilePath", wintypes.LPCWSTR),
        ("pcwszMemberTag", wintypes.LPCWSTR),
        ("pcwszMemberFilePath", wintypes.LPCWSTR),
        ("hMemberFile", wintypes.HANDLE),
        ("pbCalculatedFileHash", ctypes.POINTER(wintypes.BYTE)),
        ("cbCalculatedFileHash", wintypes.DWORD),
        ("pcCatalogContext", ctypes.c_void_p),
        ("hCatAdmin", wintypes.HANDLE),
    ]


class _WT_UNION(ctypes.Union):
    _fields_ = [
        ("pFile", ctypes.POINTER(WINTRUST_FILE_INFO)),
        ("pCatalog", ctypes.POINTER(WINTRUST_CATALOG_INFO)),
    ]


class WINTRUST_DATA(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD),
        ("pPolicyCallbackData", wintypes.LPVOID),
        ("pSIPClientData", wintypes.LPVOID),
        ("dwUIChoice", wintypes.DWORD),
        ("fdwRevocationChecks", wintypes.DWORD),
        ("dwUnionChoice", wintypes.DWORD),
        ("u", _WT_UNION),
        ("dwStateAction", wintypes.DWORD),
        ("hWVTStateData", wintypes.HANDLE),
        ("pwszURLReference", wintypes.LPCWSTR),
        ("dwProvFlags", wintypes.DWORD),
        ("dwUIContext", wintypes.DWORD),
        ("pSignatureSettings", wintypes.LPVOID),
    ]


class CATALOG_INFO(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD),
        ("wszCatalogFile", wintypes.WCHAR * 260),
    ]


if IS_WINDOWS:
    wintrust = ctypes.WinDLL("wintrust", use_last_error=True)
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    WinVerifyTrust = wintrust.WinVerifyTrust
    WinVerifyTrust.argtypes = [wintypes.HWND, ctypes.POINTER(GUID), ctypes.POINTER(WINTRUST_DATA)]
    WinVerifyTrust.restype = wintypes.LONG

    CryptCATAdminAcquireContext2 = wintrust.CryptCATAdminAcquireContext2
    CryptCATAdminAcquireContext2.argtypes = [
        ctypes.POINTER(wintypes.HANDLE), ctypes.POINTER(GUID), wintypes.LPCWSTR, wintypes.LPVOID, wintypes.DWORD,
    ]
    CryptCATAdminAcquireContext2.restype = wintypes.BOOL

    CryptCATAdminReleaseContext = wintrust.CryptCATAdminReleaseContext
    CryptCATAdminReleaseContext.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    CryptCATAdminReleaseContext.restype = wintypes.BOOL

    CryptCATAdminCalcHashFromFileHandle2 = wintrust.CryptCATAdminCalcHashFromFileHandle2
    CryptCATAdminCalcHashFromFileHandle2.argtypes = [
        wintypes.HANDLE, wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.BYTE), wintypes.DWORD,
    ]
    CryptCATAdminCalcHashFromFileHandle2.restype = wintypes.BOOL

    CryptCATAdminEnumCatalogFromHash = wintrust.CryptCATAdminEnumCatalogFromHash
    CryptCATAdminEnumCatalogFromHash.argtypes = [
        wintypes.HANDLE, ctypes.POINTER(wintypes.BYTE), wintypes.DWORD, wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    CryptCATAdminEnumCatalogFromHash.restype = wintypes.HANDLE

    CryptCATAdminReleaseCatalogContext = wintrust.CryptCATAdminReleaseCatalogContext
    CryptCATAdminReleaseCatalogContext.argtypes = [wintypes.HANDLE, wintypes.HANDLE, wintypes.DWORD]
    CryptCATAdminReleaseCatalogContext.restype = wintypes.BOOL

    CryptCATCatalogInfoFromContext = wintrust.CryptCATCatalogInfoFromContext
    CryptCATCatalogInfoFromContext.argtypes = [wintypes.HANDLE, ctypes.POINTER(CATALOG_INFO), wintypes.DWORD]
    CryptCATCatalogInfoFromContext.restype = wintypes.BOOL

    CryptQueryObject = crypt32.CryptQueryObject
    CryptQueryObject.argtypes = [
        wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.HANDLE), ctypes.POINTER(wintypes.HANDLE), ctypes.POINTER(ctypes.c_void_p),
    ]
    CryptQueryObject.restype = wintypes.BOOL

    CertEnumCertificatesInStore = crypt32.CertEnumCertificatesInStore
    CertEnumCertificatesInStore.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
    CertEnumCertificatesInStore.restype = ctypes.c_void_p

    CertFreeCertificateContext = crypt32.CertFreeCertificateContext
    CertFreeCertificateContext.argtypes = [ctypes.c_void_p]
    CertFreeCertificateContext.restype = wintypes.BOOL

    CertGetNameStringW = crypt32.CertGetNameStringW
    CertGetNameStringW.argtypes = [
        ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID, wintypes.LPWSTR, wintypes.DWORD,
    ]
    CertGetNameStringW.restype = wintypes.DWORD

    CertCloseStore = crypt32.CertCloseStore
    CertCloseStore.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    CertCloseStore.restype = wintypes.BOOL

    CryptMsgClose = crypt32.CryptMsgClose
    CryptMsgClose.argtypes = [wintypes.HANDLE]
    CryptMsgClose.restype = wintypes.BOOL

    CreateFileW = kernel32.CreateFileW
    CreateFileW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
        wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
    ]
    CreateFileW.restype = wintypes.HANDLE

    CloseHandle = kernel32.CloseHandle
    CloseHandle.argtypes = [wintypes.HANDLE]
    CloseHandle.restype = wintypes.BOOL


# --------------------------------------------------------------------------------------
# Extração de signatário e verificação PE / Catálogo
# --------------------------------------------------------------------------------------
def _extract_signer_from_file(path: str) -> str:
    """Extrai o Simple Display Name do certificado embutido em um PE ou arquivo .cat."""
    if not IS_WINDOWS:
        return ""
    hstore = wintypes.HANDLE()
    hmsg = wintypes.HANDLE()
    ok = CryptQueryObject(
        CERT_QUERY_OBJECT_FILE,
        ctypes.c_wchar_p(path),
        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
        CERT_QUERY_FORMAT_FLAG_BINARY,
        0,
        None,
        None,
        None,
        ctypes.byref(hstore),
        ctypes.byref(hmsg),
        None,
    )
    if not ok:
        return ""
    signer = ""
    try:
        ctx = CertEnumCertificatesInStore(hstore, None)
        if ctx:
            try:
                buf = ctypes.create_unicode_buffer(256)
                n = CertGetNameStringW(ctx, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, None, buf, 256)
                if n > 1:
                    signer = buf.value
            finally:
                CertFreeCertificateContext(ctx)
    finally:
        if hmsg:
            CryptMsgClose(hmsg)
        if hstore:
            CertCloseStore(hstore, 0)
    return signer


def _verify_embedded(path: str) -> int:
    fi = WINTRUST_FILE_INFO()
    fi.cbStruct = ctypes.sizeof(WINTRUST_FILE_INFO)
    fi.pcwszFilePath = path
    fi.hFile = None
    fi.pgKnownSubject = None

    wd = WINTRUST_DATA()
    wd.cbStruct = ctypes.sizeof(WINTRUST_DATA)
    wd.dwUIChoice = WTD_UI_NONE
    wd.fdwRevocationChecks = WTD_REVOKE_NONE
    wd.dwUnionChoice = WTD_CHOICE_FILE
    wd.u.pFile = ctypes.pointer(fi)
    wd.dwStateAction = WTD_STATEACTION_VERIFY
    wd.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL

    status = WinVerifyTrust(None, ctypes.byref(WINTRUST_ACTION_GENERIC_VERIFY_V2), ctypes.byref(wd)) & 0xFFFFFFFF
    wd.dwStateAction = WTD_STATEACTION_CLOSE
    WinVerifyTrust(None, ctypes.byref(WINTRUST_ACTION_GENERIC_VERIFY_V2), ctypes.byref(wd))
    return status


def _verify_catalog(path: str) -> tuple[int, str]:
    """Verifica assinatura via Catálogo do Sistema (CatRoot) para binários nativos do Windows."""
    hfile = CreateFileW(
        path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        None, OPEN_EXISTING, 0, None,
    )
    if not hfile or hfile == INVALID_HANDLE_VALUE:
        return TRUST_E_NOSIGNATURE, ""
    hcat_admin = wintypes.HANDLE()
    try:
        if not CryptCATAdminAcquireContext2(ctypes.byref(hcat_admin), None, None, None, 0):
            return TRUST_E_NOSIGNATURE, ""
        try:
            hash_len = wintypes.DWORD(0)
            CryptCATAdminCalcHashFromFileHandle2(hcat_admin, hfile, ctypes.byref(hash_len), None, 0)
            if hash_len.value == 0:
                return TRUST_E_NOSIGNATURE, ""
            hash_buf = (wintypes.BYTE * hash_len.value)()
            if not CryptCATAdminCalcHashFromFileHandle2(hcat_admin, hfile, ctypes.byref(hash_len), hash_buf, 0):
                return TRUST_E_NOSIGNATURE, ""
            member_tag = "".join(f"{b:02X}" for b in hash_buf[: hash_len.value])
            hcat_info = CryptCATAdminEnumCatalogFromHash(hcat_admin, hash_buf, hash_len.value, 0, None)
            if not hcat_info:
                return TRUST_E_NOSIGNATURE, ""
            try:
                ci = CATALOG_INFO()
                ci.cbStruct = ctypes.sizeof(CATALOG_INFO)
                if not CryptCATCatalogInfoFromContext(hcat_info, ctypes.byref(ci), 0):
                    return TRUST_E_NOSIGNATURE, ""
                cat_path = ci.wszCatalogFile
                wci = WINTRUST_CATALOG_INFO()
                wci.cbStruct = ctypes.sizeof(WINTRUST_CATALOG_INFO)
                wci.pcwszCatalogFilePath = cat_path
                wci.pcwszMemberTag = member_tag
                wci.pcwszMemberFilePath = path
                wci.hMemberFile = hfile
                wci.pbCalculatedFileHash = hash_buf
                wci.cbCalculatedFileHash = hash_len.value
                wci.hCatAdmin = hcat_admin

                wd = WINTRUST_DATA()
                wd.cbStruct = ctypes.sizeof(WINTRUST_DATA)
                wd.dwUIChoice = WTD_UI_NONE
                wd.fdwRevocationChecks = WTD_REVOKE_NONE
                wd.dwUnionChoice = WTD_CHOICE_CATALOG
                wd.u.pCatalog = ctypes.pointer(wci)
                wd.dwStateAction = WTD_STATEACTION_VERIFY
                wd.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL
                status = WinVerifyTrust(
                    None, ctypes.byref(WINTRUST_ACTION_GENERIC_VERIFY_V2), ctypes.byref(wd)
                ) & 0xFFFFFFFF
                wd.dwStateAction = WTD_STATEACTION_CLOSE
                WinVerifyTrust(None, ctypes.byref(WINTRUST_ACTION_GENERIC_VERIFY_V2), ctypes.byref(wd))
                signer = _extract_signer_from_file(cat_path) if status == 0 else ""
                return status, signer or ("Microsoft Windows" if status == 0 else "")
            finally:
                CryptCATAdminReleaseCatalogContext(hcat_admin, hcat_info, 0)
        finally:
            CryptCATAdminReleaseContext(hcat_admin, 0)
    finally:
        CloseHandle(hfile)


def _compute_sha256(path: str, max_bytes: int = 64 * 1024 * 1024) -> str:
    try:
        st = os.stat(path)
        if st.st_size > max_bytes:
            return ""
        with open(path, "rb") as fh:
            return hashlib.file_digest(fh, "sha256").hexdigest()
    except OSError:
        return ""


_FILE_CACHE: dict[tuple[str, int, int], dict] = {}
_CACHE_LOCK = threading.Lock()


def inspect_executable(path: str | None) -> dict:
    """Inspeciona assinatura Authenticode/Catálogo e SHA-256 de um executável com cache."""
    base = {
        "path": path or "",
        "exists": False,
        "signed": False,
        "signature_valid": False,
        "signature_source": "none",  # pe | catalog | none
        "signer": "",
        "status_hex": "",
        "sha256": "",
    }
    if not path:
        return base
    cleaned = path.strip().strip('"')
    if cleaned.startswith("\\??\\"):
        cleaned = cleaned[4:]
    p = Path(cleaned)
    try:
        st = p.stat()
    except OSError:
        return base
    norm = os.path.normcase(os.path.abspath(cleaned))
    cache_key = (norm, st.st_mtime_ns, st.st_size)
    with _CACHE_LOCK:
        cached = _FILE_CACHE.get(cache_key)
        if cached is not None:
            return dict(cached)

    info = dict(base, path=cleaned, exists=True)
    info["sha256"] = _compute_sha256(cleaned)

    if IS_WINDOWS:
        status = _verify_embedded(cleaned)
        if status == 0:
            info["signed"] = True
            info["signature_valid"] = True
            info["signature_source"] = "pe"
            info["signer"] = _extract_signer_from_file(cleaned) or "Assinado (PE)"
            info["status_hex"] = "0x00000000"
        elif status == TRUST_E_NOSIGNATURE:
            cat_status, cat_signer = _verify_catalog(cleaned)
            if cat_status == 0:
                info["signed"] = True
                info["signature_valid"] = True
                info["signature_source"] = "catalog"
                info["signer"] = cat_signer or "Microsoft Windows"
                info["status_hex"] = "0x00000000"
            else:
                info["status_hex"] = f"0x{cat_status:08X}"
        else:
            info["signed"] = True
            info["signature_valid"] = False
            info["signature_source"] = "pe"
            info["signer"] = _extract_signer_from_file(cleaned)
            info["status_hex"] = f"0x{status:08X}"

    with _CACHE_LOCK:
        if len(_FILE_CACHE) > 2048:
            _FILE_CACHE.clear()
        _FILE_CACHE[cache_key] = dict(info)
    return info


# --------------------------------------------------------------------------------------
# Regras de Diretório, Masquerading e LOLBins
# --------------------------------------------------------------------------------------
def classify_path_location(path: str | None) -> tuple[str, list[str]]:
    """Retorna (categoria, motivos). Categorias: system | program_files | user_temp | user | unknown."""
    if not path:
        return "unknown", []
    norm = path.strip().strip('"').lower().replace("/", "\\")
    if norm.startswith("\\??\\"):
        norm = norm[4:]
    base = ntpath.basename(norm)
    reasons: list[str] = []

    windir = (os.environ.get("SystemRoot") or r"C:\Windows").lower().rstrip("\\")
    sys32 = f"{windir}\\system32\\"
    syswow = f"{windir}\\syswow64\\"
    winapps = "\\program files\\windowsapps\\"

    is_sys_dir = norm.startswith(sys32) or norm.startswith(syswow) or norm == f"{windir}\\explorer.exe"
    if base in SYSTEM_CRITICAL_NAMES and not is_sys_dir and winapps not in norm:
        reasons.append(f"Possível masquerading: '{base}' executando fora de System32/SysWOW64 ({path})")
        return "suspicious_masquerade", reasons

    if any(frag in norm for frag in _TEMP_PATH_FRAGMENTS):
        reasons.append(f"Executável rodando em diretório temporário/gravável pelo usuário ({path})")
        return "user_temp", reasons
    if norm.startswith("\\\\"):
        reasons.append(f"Executável rodando a partir de compartilhamento de rede UNC ({path})")
        return "network_share", reasons
    if is_sys_dir or norm.startswith(f"{windir}\\") or winapps in norm:
        return "system", reasons
    if "\\program files\\" in norm or "\\program files (x86)\\" in norm:
        return "program_files", reasons
    return "user", reasons


def analyze_command_line(image: str | None, cmdline: str | None, real_command: str | None = None) -> tuple[str, list[str]]:
    """Analisa se há uso de LOLBin, script externo ou flags de ofuscação/evasão.

    Retorna (nível: 'none' | 'caution' | 'high_risk', lista_de_motivos).
    """
    combined = " ".join(x for x in (cmdline, real_command) if x and x != "[Pendente ETW...]").strip()
    if not combined:
        return "none", []
    reasons: list[str] = []
    level = "none"

    for rx, msg in HIGH_RISK_CMD_PATTERNS:
        if rx.search(combined):
            reasons.append(msg)
            level = "high_risk"

    for rx, msg in CAUTION_CMD_PATTERNS:
        if rx.search(combined):
            reasons.append(msg)
            if level == "none":
                level = "caution"

    low_cmd = combined.lower().replace("/", "\\")
    if any(frag in low_cmd for frag in _TEMP_PATH_FRAGMENTS):
        reasons.append("Linha de comando referencia arquivo em pasta temporária/AppData/Downloads")
        if level == "none":
            level = "caution"
        if any(ext in low_cmd for ext in (".ps1", ".vbs", ".js", ".hta", ".bat", ".cmd", ".exe")):
            level = "high_risk"

    img_base = ntpath.basename(image or "").lower()
    if img_base in LOLBIN_INTERPRETERS and level == "none":
        # Se for cmd/powershell com argumentos reais além do próprio nome
        tokens = combined.split()
        if len(tokens) > 1:
            reasons.append(f"Interpretador/LOLBin ({img_base}) executando comando com argumentos")
            level = "caution"

    return level, reasons


def evaluate_trust(
    exe_path: str | None,
    image: str | None = None,
    cmdline: str | None = None,
    real_command: str | None = None,
    file_inspector=inspect_executable,
) -> dict:
    """Combina assinatura digital, diretório e análise de linha de comando em um veredito único."""
    sig = file_inspector(exe_path) if exe_path else inspect_executable("")
    loc_cat, loc_reasons = classify_path_location(exe_path)
    eff_image = image or ntpath.basename(exe_path or "")
    cmd_level, cmd_reasons = analyze_command_line(eff_image, cmdline, real_command)

    reasons: list[str] = []
    reasons.extend(loc_reasons)
    reasons.extend(cmd_reasons)

    signer_low = (sig.get("signer") or "").lower()
    is_ms = sig.get("signature_valid") and ("microsoft" in signer_low or sig.get("signature_source") == "catalog")

    if loc_cat in ("suspicious_masquerade", "network_share"):
        verdict = VERDICT_SUSPICIOUS
    elif sig.get("signed") and not sig.get("signature_valid"):
        reasons.append(f"Assinatura digital inválida ou revogada ({sig.get('status_hex')})")
        verdict = VERDICT_SUSPICIOUS
    elif cmd_level == "high_risk":
        verdict = VERDICT_SUSPICIOUS
    elif not sig.get("signature_valid"):
        if not sig.get("exists"):
            verdict = VERDICT_UNKNOWN
            if exe_path:
                reasons.append("Caminho do executável não pôde ser verificado em disco")
        elif loc_cat == "user_temp":
            reasons.append("Executável não assinado em diretório temporário")
            verdict = VERDICT_SUSPICIOUS
        else:
            reasons.append("Executável sem assinatura Authenticode válida")
            verdict = VERDICT_UNSIGNED
    elif cmd_level == "caution":
        verdict = VERDICT_LOLBIN_CAUTION
    elif loc_cat == "user_temp":
        reasons.append("Binário assinado executando a partir de pasta temporária")
        verdict = VERDICT_LOLBIN_CAUTION
    elif is_ms:
        verdict = VERDICT_TRUSTED_MS
    else:
        verdict = VERDICT_TRUSTED_SIGNED

    if not reasons:
        if verdict == VERDICT_TRUSTED_MS:
            reasons.append(f"Assinado pela Microsoft ({sig.get('signature_source')}) em diretório padrão")
        elif verdict == VERDICT_TRUSTED_SIGNED:
            reasons.append(f"Assinatura Authenticode válida ({sig.get('signer')})")

    return {
        "verdict": verdict,
        "label": VERDICT_LABELS.get(verdict, verdict),
        "signed": bool(sig.get("signature_valid")),
        "signature_source": sig.get("signature_source", "none"),
        "signer": sig.get("signer", ""),
        "status_hex": sig.get("status_hex", ""),
        "sha256": sig.get("sha256", ""),
        "location": loc_cat,
        "reasons": reasons,
    }

