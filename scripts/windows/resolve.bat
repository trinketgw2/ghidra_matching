@echo off
rem Internal helper: resolve.bat <GhidraProjectPath> <PREFIX>
rem Splits a build argument into <PREFIX>_PROJECT, <PREFIX>_FOLDER, <PREFIX>_PROGRAM and
rem <PREFIX>_LABEL (last folder name, used to name exports and pairing tables).
rem   v1.1                      folder; project and program from user_preferences.cfg
rem   v1.1/program.exe          folder/program; project from user_preferences.cfg
rem   MyProject/v1.1/program.exe  full project path (also MyProject/builds/v1.1/program.exe)
setlocal EnableDelayedExpansion
set "ARG=%~1"
if "!ARG!"=="" (
  echo No build given.
  exit /b 1
)
set "ARG=!ARG:\=/!"
if "!ARG:~0,1!"=="/" set "ARG=!ARG:~1!"
set /a N=0
set "FOLDER="
set "PREV="
rem percent expansion on purpose: the replacement must happen before FOR splits the list.
rem FOLDER collects the parts between the first and the last one.
for %%x in ("%ARG:/=" "%") do (
  if not "%%~x"=="" (
    set /a N+=1
    if !N! geq 3 set "FOLDER=!FOLDER!/!PREV!"
    set "PREV=%%~x"
    if !N! equ 1 set "FIRST=%%~x"
  )
)
set "PROJ=%GHIDRA_PROJECT_NAME%"
set "PROG=%PROGRAM_NAME%"
if %N% equ 1 (
  set "FOLDER=%FIRST%"
) else if %N% equ 2 (
  set "FOLDER=%FIRST%"
  set "PROG=%PREV%"
) else (
  set "PROJ=%FIRST%"
  set "PROG=%PREV%"
  set "FOLDER=%FOLDER:~1%"
)
for %%f in ("%FOLDER:/=" "%") do set "LBL=%%~f"
if "!PROJ!"=="" (
  echo No project for "%~1": set GHIDRA_PROJECT_NAME in user_preferences.cfg or pass Project/folder/program.
  exit /b 1
)
if "!PROG!"=="" (
  echo No program for "%~1": set PROGRAM_NAME in user_preferences.cfg or pass folder/program.
  exit /b 1
)
endlocal & set "%~2_PROJECT=%PROJ%" & set "%~2_FOLDER=%FOLDER%" & set "%~2_PROGRAM=%PROG%" & set "%~2_LABEL=%LBL%"
exit /b 0
