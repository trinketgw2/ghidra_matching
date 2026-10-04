@echo off
rem Export the build with your markup, import + analyse a new build (or reuse an existing
rem one), export it and write the pairing table - in one go. Progress is shown while a new
rem build is analysed. Close the project in the Ghidra GUI first.
rem
rem   update.bat                                               asks for everything
rem   update.bat <source GhidraProjectPath> --new [exe] [--name <folder>]
rem   update.bat <source GhidraProjectPath> --existing <target GhidraProjectPath>
rem
rem   update.bat v1.0 --new                     exe from the source build's import path,
rem                                                  folder named by BUILD_NAME_FORMAT (today)
rem   update.bat v1.0 --new "D:\app\program.exe" --name v1.2
rem   update.bat v1.0 --existing v1.1
rem   update.bat MyProject/v1.0/program.exe --existing MyProject/v1.1/program.exe
rem
rem Builds are a project folder (project and program from user_preferences.cfg) or a full
rem path inside the Ghidra project, as for export.bat.
rem Then review <OUT_DIR>\pairs_<source>_to_<target>.csv and run apply.bat.
setlocal
call "%~dp0config.bat"
if errorlevel 1 exit /b 1
set "PY=%REPO%\.venv\Scripts\python.exe"
if not exist "%PY%" set "PY=python"
"%PY%" -m ghidra_matching update %*
set "RC=%ERRORLEVEL%"
rem keep the window open when started by double-click
echo %CMDCMDLINE% | find /i "/c" >nul && pause
exit /b %RC%
