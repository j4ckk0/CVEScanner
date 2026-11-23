@echo off
rem
rem Download the vulnerability databases CVEScanner reads, on a computer with internet access, into database\ (the
rem project's, which scripts\run.bat loads) or the folder --dir names: then copy them beside the program, into its
rem database folder, on the computer that scans. The program itself never reaches the network; this script does.
rem
rem   scripts\download-databases.bat                     the GitHub Advisory Database and NVD's CVE feeds
rem   scripts\download-databases.bat all                 every database below
rem   scripts\download-databases.bat osv cvelist         only these
rem   scripts\download-databases.bat --dir E:\database ghsa
rem
rem   ghsa      advisory-database-main.zip, the GitHub Advisory Database (recommended; about 500 MB)
rem   osv       Maven-all.zip, npm-all.zip, PyPI-all.zip: OSV.dev's exports (about 270 MB together)
rem   nvd       nvdcve-2.0-YYYY.json.zip from 2002 to this year, and nvdcve-2.0-modified.json.zip: NVD's CVE
rem             feeds, for the components off-the-shelf (about 220 MB together)
rem   cvelist   YYYY-MM-DD_all_CVEs_at_midnight.zip.zip, the CVE List's newest release (about 650 MB)
rem
rem Run it again to update: a file the server has not changed since is not downloaded again, and a newer CVE List
rem replaces the older one. Each file is written beside its final name first, so that an interrupted download
rem leaves the previous file whole. Uses curl.exe, which Windows 10 and later ship.
rem
setlocal EnableDelayedExpansion
cd /d "%~dp0.."
rem (the project root)

set "DIR=database"
set "SETS="
:args
if "%~1"=="" goto argsDone
if /i "%~1"=="--dir" (
  if "%~2"=="" (echo --dir needs a folder 1>&2 & exit /b 2)
  set "DIR=%~2"
  shift & shift & goto args
)
if /i "%~1"=="all" (set "SETS=!SETS! ghsa osv nvd cvelist" & shift & goto args)
for %%s in (ghsa osv nvd cvelist) do if /i "%~1"=="%%s" (set "SETS=!SETS! %%s" & shift & goto args)
echo unknown argument %~1 (ghsa, osv, nvd, cvelist, all, --dir DIR) 1>&2
exit /b 2
:argsDone
if "%SETS%"=="" set "SETS=ghsa nvd"
where curl.exe >nul 2>nul || (echo curl.exe not found in PATH 1>&2 & exit /b 1)
if not exist "%DIR%" mkdir "%DIR%"
set "FAILED=0"

for %%s in (%SETS%) do (
  if /i "%%s"=="ghsa" call :get advisory-database-main.zip https://github.com/github/advisory-database/archive/refs/heads/main.zip
  if /i "%%s"=="osv" for %%e in (Maven npm PyPI) do call :get %%e-all.zip https://osv-vulnerabilities.storage.googleapis.com/%%e/all.zip
  if /i "%%s"=="nvd" call :nvd
  if /i "%%s"=="cvelist" call :cvelist
)

echo.
echo In %DIR%:
dir /b "%DIR%\*.zip"
if not "%FAILED%"=="0" (echo %FAILED% download^(s^) failed: run the script again 1>&2 & exit /b 1)
exit /b 0

:nvd
for /f %%y in ('powershell -NoProfile -Command "(Get-Date).Year"') do set "YEAR=%%y"
for /l %%y in (2002,1,%YEAR%) do call :get nvdcve-2.0-%%y.json.zip https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-%%y.json.zip
call :get nvdcve-2.0-modified.json.zip https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-modified.json.zip
exit /b 0

:cvelist
rem the newest release's asset of the whole list (not its _delta_ files), named by its day
set "URL="
set "NAME="
for /f "usebackq tokens=1,2" %%a in (`powershell -NoProfile -Command "(Invoke-RestMethod https://api.github.com/repos/CVEProject/cvelistV5/releases/latest).assets | Where-Object name -like '*_all_CVEs_at_midnight.zip.zip' | Select-Object -First 1 | ForEach-Object { $_.name + ' ' + $_.browser_download_url }"`) do (set "NAME=%%a" & set "URL=%%b")
if "%URL%"=="" (
  echo    the CVE List's newest release not found ^(https://github.com/CVEProject/cvelistV5/releases^) 1>&2
  set /a FAILED+=1
  exit /b 1
)
call :get %NAME% %URL% || exit /b 1
rem the older days' lists: the new one replaces them
for %%o in ("%DIR%\*_all_CVEs_at_midnight.zip.zip") do if /i not "%%~nxo"=="%NAME%" (del "%%o" & echo    removed the older %%~nxo)
exit /b 0

rem get NAME URL: DIR\NAME downloaded, unless the server has not changed it since the copy there
:get
set "FILE=%DIR%\%~1"
set "PART=%DIR%\%~1.part"
set "SINCE="
if exist "%FILE%" set SINCE=-z "%FILE%"
echo == %~1
if exist "%PART%" del "%PART%"
curl.exe -fL --retry 3 --remote-time --progress-bar %SINCE% -o "%PART%" "%~2"
if errorlevel 1 (
  echo    failed: %~2 1>&2
  if exist "%PART%" del "%PART%"
  set /a FAILED+=1
  exit /b 1
)
set "SIZE=0"
if exist "%PART%" for %%A in ("%PART%") do set "SIZE=%%~zA"
if "%SIZE%"=="0" (
  if exist "%PART%" del "%PART%"
  echo    unchanged
) else (
  move /y "%PART%" "%FILE%" >nul
)
exit /b 0
