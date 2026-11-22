@echo off
rem CVEScanner on the command line, in this console, with its runtime: cvescanner-cli.bat --no-gui -d C:\src\my-app
rem The database zips of database\ are loaded and the reports written in reports\, both beside the program, unless
rem the arguments say otherwise. Its exit code is the program's: 0, 1 on an error, 2 past --fail-on (for a CI).
if "%~1"=="/?" goto help
"%~dp0jre\bin\java.exe" -XX:-UsePerfData -XX:+UseCompactObjectHeaders -jar "%~dp0cvescanner.jar" ^
  --db-dir "%~dp0database" -o "%~dp0reports" %*
exit /b %errorlevel%
:help
rem /?, as Windows' own commands take it: the options (--help)
"%~dp0jre\bin\java.exe" -XX:-UsePerfData -jar "%~dp0cvescanner.jar" --help
exit /b %errorlevel%
