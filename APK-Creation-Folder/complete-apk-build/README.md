# Samsung Root Tool - Complete APK Build Structure 
 
This is a complete Android project structure for building the Samsung Root Tool APK. 
 
## Features 
- 9 different rooting methods 
- OpenSSL AES-256-GCM encrypted native engine 
- Device-specific Samsung Tab S10+ 5G support 
- Real system calls (no simulations) 
 
## Building the APK 
 
### Option 1: Using build script (Recommended) 
1. Run `build-apk.bat` as Administrator 
2. Wait for build to complete 
3. Find APK at: `app\build\outputs\apk\debug\app-debug.apk` 
 
### Option 2: Using Gradle directly 
1. Set JAVA_HOME to Java 17 
2. Run: `gradlew.bat assembleDebug` 
3. Find APK at: `app\build\outputs\apk\debug\app-debug.apk` 
 
### Option 3: Using Android Studio 
1. Open this folder in Android Studio 
2. Wait for Gradle sync 
3. Build → Build Bundle(s) / APK(s) → Build APK(s) 
 
## Requirements 
- Java 17 or higher 
- Android SDK (will be downloaded automatically) 
- Windows 10/11 
 
## Installation 
1. Enable "Unknown Sources" on your Samsung tablet 
2. Transfer APK to tablet 
3. Install APK 
4. Open "Samsung Root Tool" 
5. Tap "START ROOT ATTEMPT" 
 
Good luck with your rooting attempt! 
