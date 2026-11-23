@echo off
rem
rem The databases downloaded into the project's database\, which scripts\run.bat loads: the distribution's
rem download-databases.bat (cvescanner-app\src\dist), with --dir database; its arguments go to it.
rem
rem   scripts\download-databases.bat                asks, then the GitHub Advisory Database and NVD's CVE feeds
rem   scripts\download-databases.bat all --accept   every database, no question asked
rem
call "%~dp0..\cvescanner-app\src\dist\download-databases.bat" --dir "%~dp0..\database" %*
exit /b %errorlevel%
