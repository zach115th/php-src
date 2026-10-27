@echo off
rem Runs inside the PHP SDK shell (phpsdk-<crt>-x64.bat -s <toolset> -t ci\build_task.bat, or
rem vcvarsall plus bin\phpsdk_setvars.bat), from the PHP source directory.
rem Needs THREAD_SAFE (1/0), OBJ_DIR and LOG_DIR.

echo Windows SDK: %WindowsSDKVersion%
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
rem configure.bat does not always report its errors in the exit code
if not exist Makefile (
	echo configure did not produce a Makefile
	exit /b 3
)

rem Bison 3 declares zendparse() in the generated header without ZEND_API, which VS2015 rejects
rem (C2375). 7.0.13 added the fix to the Makefile (62bed405da9); do the same for older releases.
findstr /c:"ZEND_API int zendparse" win32\build\Makefile >nul
if not errorlevel 1 goto parser_ok
echo Applying the zendparse export fix of 62bed405da9 to the generated parser
nmake /NOLOGO Zend\zend_language_parser.c
if %errorlevel% neq 0 exit /b 3
sed -i "s,^int zendparse\(.*\),ZEND_API int zendparse\1,g" Zend/zend_language_parser.c
sed -i "s,^int zendparse\(.*\),ZEND_API int zendparse\1,g" Zend/zend_language_parser.h
sed -i "s,^#ifndef YYTOKENTYPE,#include \"zend.h\"\n#ifndef YYTOKENTYPE,g" Zend/zend_language_parser.h
findstr /n /c:"ZEND_API int zendparse" Zend\zend_language_parser.h || exit /b 3
:parser_ok

nmake /NOLOGO > "%LOG_DIR%\nmake.log" 2>&1
set RC=%errorlevel%
type "%LOG_DIR%\nmake.log"
if %RC% neq 0 exit /b 3
exit /b 0
