@echo off
echo ============================================
echo  KeyAuth C++ Builder
echo ============================================
echo.

where cl >nul 2>nul
if %ERRORLEVEL% == 0 (
    echo [*] Found MSVC compiler, building...
    cl /EHsc /std:c++17 /O2 keyauth.cpp /Fe:keyauth.exe ws2_32.lib secur32.lib bcrypt.lib crypt32.lib advapi32.lib
    if %ERRORLEVEL% == 0 (
        echo.
        echo [+] Build successful: keyauth.exe
    ) else (
        echo.
        echo [-] Build failed. Make sure you are running this from a Developer Command Prompt.
    )
    goto :done
)

where cmake >nul 2>nul
if %ERRORLEVEL% == 0 (
    echo [*] Found CMake, building...
    if not exist build mkdir build
    cd build
    cmake .. -G "Visual Studio 17 2022"
    cmake --build . --config Release
    if %ERRORLEVEL% == 0 (
        echo.
        echo [+] Build successful: build\Release\keyauth.exe
    ) else (
        echo.
        echo [-] CMake build failed.
    )
    cd ..
    goto :done
)

echo [-] No compiler found.
echo.
echo     Option 1: Install Visual Studio with "Desktop development with C++"
echo               Then open "Developer Command Prompt" and run this script again.
echo.
echo     Option 2: Install CMake (cmake.org) and run this script again.

:done
echo.
pause
