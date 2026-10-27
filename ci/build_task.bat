@echo off
rem Runs inside the PHP SDK shell (phpsdk-<crt>-x64.bat -s <toolset> -t ci\build_task.bat),
rem from the PHP source directory. Needs THREAD_SAFE (1/0), OBJ_DIR and LOG_DIR.

echo Compiler:
cl 2>&1 | findstr /i "version"
echo Linker:
link 2>&1 | findstr /i "version"
echo bison:
bison --version 2>&1 | findstr /i "bison"
echo re2c:
re2c --version 2>&1

cmd /c buildconf.bat --force
if %errorlevel% neq 0 exit /b 3

rem only the core, the CLI and CGI SAPIs and the session extension: no third-party libraries
set CONF=--disable-all --enable-cli --enable-cgi --enable-session --enable-object-out-dir=%OBJ_DIR%
if "%THREAD_SAFE%"=="0" set CONF=%CONF% --disable-zts
echo configure.bat %CONF%
cmd /c configure.bat %CONF%
if %errorlevel% neq 0 exit /b 3

nmake /NOLOGO > "%LOG_DIR%\nmake.log" 2>&1
set RC=%errorlevel%
type "%LOG_DIR%\nmake.log"
if %RC% neq 0 exit /b 3
exit /b 0
