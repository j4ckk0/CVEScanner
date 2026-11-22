@echo off
rem Starts CVEScanner's window with its runtime, without a console. Arguments are passed to the program, after the
rem folder of the database zips (database\, loaded at the start) and of the reports (reports\), both beside it.
rem It runs javaw.exe, signed by the Eclipse Foundation: no executable of ours, unsigned, that a security policy
rem might refuse (CVEScanner.exe does the same, and is not signed). For the command line: cvescanner-cli.bat.
rem -XX:-UsePerfData: the JVM's performance counters stay in memory, not in a file of %TEMP%;
rem -XX:+UseCompactObjectHeaders: smaller objects, less memory for a large database.
rem cvescanner.aot, Java's AOT cache of the program (pom.xml makes it), for a faster start; read only, and
rem silently passed over should it not match the runtime. No ( ) block: a path's ")" would close it.
rem --help, -h, /?: the window has no console to print in, so the options are printed by cvescanner-cli.bat.
if /i "%~1"=="--help" goto help
if /i "%~1"=="-h" goto help
if "%~1"=="/?" goto help
if not exist "%~dp0cvescanner.aot" goto without
start "" "%~dp0jre\bin\javaw.exe" -XX:-UsePerfData -XX:+UseCompactObjectHeaders "-XX:AOTCache=%~dp0cvescanner.aot" ^
  -Xlog:aot=off -Xlog:cds=off -jar "%~dp0cvescanner.jar" --db-dir "%~dp0database" -o "%~dp0reports" %*
exit /b 0
:without
start "" "%~dp0jre\bin\javaw.exe" -XX:-UsePerfData -XX:+UseCompactObjectHeaders -jar "%~dp0cvescanner.jar" ^
  --db-dir "%~dp0database" -o "%~dp0reports" %*
exit /b 0
:help
call "%~dp0cvescanner-cli.bat" --help
exit /b 0
