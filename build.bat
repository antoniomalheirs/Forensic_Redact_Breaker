@echo off
REM ========================================================================
REM RedactBreaker v1.0 - Build Script (MSVC)
REM ========================================================================
REM Requires: Visual Studio Developer Command Prompt (cl.exe available)
REM Usage: Open "Developer Command Prompt for VS" then run this script.
REM ========================================================================

echo.
echo [*] RedactBreaker v1.0 - Build System
echo ========================================

REM Check if cl.exe is available
where cl >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo [!] ERRO: cl.exe nao encontrado!
    echo [!] Execute este script no "Developer Command Prompt for VS 2022"
    echo [!] Ou execute: "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
    pause
    exit /b 1
)

echo [+] Compilador MSVC detectado
echo [*] Compilando RedactBreaker.cpp...
echo.

cl /EHsc /O2 /std:c++17 /W3 /Fe:RedactBreaker.exe RedactBreaker.cpp /link gdiplus.lib shlwapi.lib ole32.lib

if %ERRORLEVEL% equ 0 (
    echo.
    echo ========================================
    echo [+] BUILD SUCCESSFUL!
    echo [+] Executavel: RedactBreaker.exe
    echo ========================================
    echo.
    echo Para executar: RedactBreaker.exe
) else (
    echo.
    echo ========================================
    echo [X] BUILD FAILED!
    echo [X] Verifique os erros acima.
    echo ========================================
)

pause
