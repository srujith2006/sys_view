@echo off
title Build QE-NIDS Android APK
echo ======================================================================
echo   BUILDING FLUTTER ANDROID APK (QE-NIDS THREATGUARD)
echo ======================================================================
echo.
echo [1/3] Getting Flutter packages...
call flutter pub get
if %errorlevel% neq 0 (
    echo [ERROR] Flutter is not installed or failed to fetch packages.
    pause
    exit /b %errorlevel%
)

echo.
echo [2/3] Building Release APK...
call flutter build apk --release
if %errorlevel% neq 0 (
    echo [ERROR] APK build failed. Check Android SDK and Java setup.
    pause
    exit /b %errorlevel%
)

echo.
echo [3/3] Build Complete!
echo APK location:
echo %CD%\build\app\outputs\flutter-apk\app-release.apk
echo.
pause
