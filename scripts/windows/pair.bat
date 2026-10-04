@echo off
rem Pair two exported builds and write the pairing table (no Ghidra needed).
rem
rem   pair.bat <source GhidraProjectPath> <target GhidraProjectPath>
rem   pair.bat v1.0 v1.1
rem
rem The source is the build that has your markup; builds are given as for export.bat. Writes
rem   <OUT_DIR>\pairs_<source>_to_<target>.csv      items with your markup and their new address
rem   <OUT_DIR>\unmatched_<source>_to_<target>.csv  items with your markup that found no partner
setlocal
call "%~dp0config.bat"
if errorlevel 1 exit /b 1

set "SRC=%~1"
if "%SRC%"=="" set /p "SRC=Source build (the one with your markup): "
set "TGT=%~2"
if "%TGT%"=="" set /p "TGT=Target build (the new one): "
call "%~dp0resolve.bat" "%SRC%" S
if errorlevel 1 exit /b 1
call "%~dp0resolve.bat" "%TGT%" T
if errorlevel 1 exit /b 1

set "PY=%REPO%\.venv\Scripts\python.exe"
if not exist "%PY%" set "PY=python"
if not exist "%OUT_PATH%" mkdir "%OUT_PATH%"

"%PY%" -m ghidra_matching pair "%EXPORT_PATH%\%S_LABEL%" "%EXPORT_PATH%\%T_LABEL%" -o "%OUT_PATH%\pairs_%S_LABEL%_to_%T_LABEL%.csv" --unmatched "%OUT_PATH%\unmatched_%S_LABEL%_to_%T_LABEL%.csv"
