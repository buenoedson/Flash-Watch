# Script de empacotamento PyInstaller (T-12)
param(
    [ValidateSet("spec", "onedir", "onefile")]
    [string]$Mode = "spec"
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

$Py = Join-Path $Root ".venv\Scripts\python.exe"
if (-not (Test-Path $Py)) {
    $Py = "python"
}

if ($Mode -eq "spec") {
    & $Py -m PyInstaller --noconfirm --clean "build\flashwatch.spec"
} elseif ($Mode -eq "onedir") {
    & $Py -m PyInstaller --noconfirm --clean --onedir --windowed --uac-admin --name FlashWatch --paths src "src\flashwatch\__main__.py"
} elseif ($Mode -eq "onefile") {
    & $Py -m PyInstaller --noconfirm --clean --onefile --windowed --uac-admin --name FlashWatch --paths src "src\flashwatch\__main__.py"
}
