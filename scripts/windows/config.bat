@echo off
rem Loads user_preferences.cfg (see user_preferences.example.cfg in the repository folder)
rem into environment variables for the other .bat files. GHIDRA_MATCHING_CONFIG can point
rem to a preferences file elsewhere. Also sets REPO, EXPORT_PATH and OUT_PATH.
for %%I in ("%~dp0..\..") do set "REPO=%%~fI"
set "CFG=%GHIDRA_MATCHING_CONFIG%"
if "%CFG%"=="" set "CFG=%REPO%\user_preferences.cfg"
if not exist "%CFG%" (
  echo Preferences file not found: %CFG%
  echo Copy user_preferences.example.cfg to user_preferences.cfg and fill in your paths.
  exit /b 1
)
for /f "usebackq eol=# tokens=1,* delims==" %%A in ("%CFG%") do set "%%A=%%B"
if "%EXPORT_DIR%"=="" set "EXPORT_DIR=exports"
if "%OUT_DIR%"=="" set "OUT_DIR=out"
rem relative paths are relative to the repository folder
if "%EXPORT_DIR:~1,1%"==":" (set "EXPORT_PATH=%EXPORT_DIR%") else (set "EXPORT_PATH=%REPO%\%EXPORT_DIR%")
if "%OUT_DIR:~1,1%"==":" (set "OUT_PATH=%OUT_DIR%") else (set "OUT_PATH=%REPO%\%OUT_DIR%")
rem GHIDRA_PROJECT_NAME and PROGRAM_NAME are optional (builds can be given as Project/folder/program)
if not defined GHIDRA_INSTALL_DIR (
  echo GHIDRA_INSTALL_DIR is not set in %CFG%
  exit /b 1
)
if not defined GHIDRA_PROJECT_DIR (
  echo GHIDRA_PROJECT_DIR is not set in %CFG%
  exit /b 1
)
exit /b 0
