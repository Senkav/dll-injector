@echo off
echo ============================================
echo  DLL Injector - Build Script
echo  Requires: Visual Studio 2022 (any edition)
echo ============================================
echo.

:: Check if cl.exe is available
where cl.exe >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: cl.exe not found!
    echo Please run this script from:
    echo   "Developer Command Prompt for VS 2022"
    echo   OR
    echo   "x64 Native Tools Command Prompt for VS 2022"
    echo.
    echo You can find it in Start Menu ^> Visual Studio 2022
    pause
    exit /b 1
)

echo [*] Compiler found: OK
echo [*] Building...
echo.

cl.exe ^
    /std:c++20 ^
    /O2 /W3 /WX- ^
    /EHsc ^
    /DUNICODE /D_UNICODE /DWIN32 /D_WINDOWS ^
    /MT ^
    injector_gui.cpp ^
    /Fe:DllInjector.exe ^
    /link ^
    /SUBSYSTEM:WINDOWS ^
    /ENTRY:wWinMainCRTStartup ^
    user32.lib kernel32.lib comctl32.lib shell32.lib psapi.lib advapi32.lib

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ============================================
    echo  SUCCESS: DllInjector.exe created!
    echo  Run as Administrator for best results.
    echo ============================================
    del /q *.obj 2>nul
) else (
    echo.
    echo ============================================
    echo  BUILD FAILED - see errors above
    echo ============================================
)

pause
