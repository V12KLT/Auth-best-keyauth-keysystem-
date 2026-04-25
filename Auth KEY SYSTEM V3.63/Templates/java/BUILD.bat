@echo off
echo ============================================
echo  KeyAuth Java Builder
echo ============================================
echo.

where javac >nul 2>nul
if %ERRORLEVEL% == 0 (
    echo [*] Compiling...
    javac KeyAuth.java
    if %ERRORLEVEL% == 0 (
        echo [+] Build successful. Running...
        echo.
        java KeyAuth
    ) else (
        echo [-] Compilation failed.
    )
    goto :done
)

echo [-] Java JDK not found.
echo.
echo     Install it from: https://adoptium.net/
echo     Make sure 'javac' is in your PATH.

:done
echo.
pause
