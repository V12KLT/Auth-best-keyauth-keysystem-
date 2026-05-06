@echo off
echo ============================================
echo  KeyAuth C# Builder
echo ============================================
echo.

where dotnet >nul 2>nul
if %ERRORLEVEL% == 0 (
    echo [*] Found .NET SDK, building...
    dotnet run
    goto :done
)

echo [-] .NET SDK not found.
echo.
echo     Install it from: https://dotnet.microsoft.com/download
echo     Then run this script again.

:done
echo.
pause
