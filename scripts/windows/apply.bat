@echo off
rem Apply your markup from the source build to the target build (headless). The GUI alternative
rem is running ApplyMatchTable.java from the Script Manager on the target program.
rem
rem   apply.bat <source GhidraProjectPath> <target GhidraProjectPath> [dry|apply] ["option=value" ...]
rem
rem   apply.bat v1.0 v1.1                 dry run: only writes the report
rem   apply.bat v1.0 v1.1 apply           changes the target and saves it
rem   apply.bat v1.0 v1.1 dry "min_confidence=0.5" "replace_signatures=false"
rem   apply.bat v1.0 v1.1 apply "min_confidence=0.5" "replace_signatures=false"
rem
rem Builds are given as for export.bat and must be in the same Ghidra project. Each option
rem needs its own quotes, because cmd splits unquoted arguments at "=". Options in
rem APPLY_OPTIONS (user_preferences.cfg) are always passed first, so options given here win.
rem Reads <OUT_DIR>\pairs_<source>_to_<target>.csv (from pair.bat or update.bat) and writes
rem <OUT_DIR>\apply_report_<source>_to_<target>.csv. Back up the project before the first real run.
setlocal
call "%~dp0config.bat"
if errorlevel 1 exit /b 1

set "SRC=%~1"
if "%SRC%"=="" set /p "SRC=Source build (the one with your markup): "
set "TGT=%~2"
if "%TGT%"=="" set /p "TGT=Target build (receives the markup): "
call "%~dp0resolve.bat" "%SRC%" S
if errorlevel 1 exit /b 1
call "%~dp0resolve.bat" "%TGT%" T
if errorlevel 1 exit /b 1
if /i not "%S_PROJECT%"=="%T_PROJECT%" (
  echo Source and target must be in the same Ghidra project ^(%S_PROJECT% vs %T_PROJECT%^).
  exit /b 1
)
set "MODE=%~3"
if "%MODE%"=="" set "MODE=dry"

set "PAIRS=%OUT_PATH%\pairs_%S_LABEL%_to_%T_LABEL%.csv"
set "REPORT=%OUT_PATH%\apply_report_%S_LABEL%_to_%T_LABEL%.csv"
if not exist "%PAIRS%" (
  echo %PAIRS% not found. Run pair.bat %SRC% %TGT% first.
  exit /b 1
)

set OPTS="report=%REPORT%" %APPLY_OPTIONS%
if /i "%MODE%"=="dry" (
  set OPTS=%OPTS% dry_run=true
) else if /i not "%MODE%"=="apply" (
  echo Third argument must be dry or apply.
  exit /b 2
)
shift & shift & shift
:collect
if "%~1"=="" goto run
set OPTS=%OPTS% "%~1"
shift
goto collect

:run
echo Applying %S_PROJECT%:/%S_FOLDER%/%S_PROGRAM% -^> /%T_FOLDER%/%T_PROGRAM% (%MODE%)
echo Options: %OPTS%
call "%GHIDRA_INSTALL_DIR%\support\analyzeHeadless.bat" "%GHIDRA_PROJECT_DIR%" "%T_PROJECT%/%T_FOLDER%" -process "%T_PROGRAM%" -noanalysis -scriptPath "%REPO%\ghidra_scripts" -postScript ApplyMatchTable.java "%PAIRS%" "/%S_FOLDER%/%S_PROGRAM%" %OPTS%
echo.
if exist "%REPORT%" (echo Report: %REPORT%) else (echo No report written - see the log above.)
