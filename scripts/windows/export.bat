@echo off
rem Export one build for matching (headless). The GUI alternative is running
rem ExportMatchData.java from the Script Manager.
rem
rem   export.bat <GhidraProjectPath>
rem   export.bat v1.1                          project + program from user_preferences.cfg
rem   export.bat MyProject/v1.1/program.exe    full path inside the Ghidra project
rem
rem Writes <EXPORT_DIR>\<label>.functions.csv/.data.csv/.meta.json, where the label is the
rem build's folder name (v1.1). Missing arguments are asked for.
setlocal
call "%~dp0config.bat"
if errorlevel 1 exit /b 1

set "BUILD=%~1"
if "%BUILD%"=="" set /p "BUILD=Build (project folder, or Project/folder/program): "
call "%~dp0resolve.bat" "%BUILD%" B
if errorlevel 1 exit /b 1
if not exist "%EXPORT_PATH%" mkdir "%EXPORT_PATH%"

echo Exporting %B_PROJECT%:/%B_FOLDER%/%B_PROGRAM% to %EXPORT_PATH%\%B_LABEL%.*
call "%GHIDRA_INSTALL_DIR%\support\analyzeHeadless.bat" "%GHIDRA_PROJECT_DIR%" "%B_PROJECT%/%B_FOLDER%" -process "%B_PROGRAM%" -readOnly -noanalysis -scriptPath "%REPO%\ghidra_scripts" -postScript ExportMatchData.java "%EXPORT_PATH%" "%B_LABEL%"

if not exist "%EXPORT_PATH%\%B_LABEL%.functions.csv" (
  echo.
  echo Export failed. If the log says "Unable to lock project", close the project in Ghidra.
  exit /b 1
)
echo.
echo Done: %EXPORT_PATH%\%B_LABEL%.functions.csv, .data.csv, .meta.json
