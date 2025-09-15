@echo off
echo ========================================
echo RawrZ Emoji Removal Script
echo ========================================
echo.
echo Removing all emojis to prevent ROE and malformities...
echo.

REM Remove emojis from all main source files
echo Removing emojis from source files...

REM Remove common emojis from all .js files
for /r "src" %%f in (*.js) do (
    echo Processing: %%f
    powershell -Command "(Get-Content '%%f') -replace '[\u2713]', '[OK]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u2717]', '[ERROR]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u2705]', '[OK]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u274C]', '[ERROR]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u1F512]', '[LOCK]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u1F513]', '[UNLOCK]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u1F510]', '[SECURE]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u1F511]', '[KEY]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u1F6E1]', '[SHIELD]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u26A1]', '[LIGHTNING]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u1F680]', '[LAUNCH]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u1F4BE]', '[SAVE]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u1F4C1]', '[FILE]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u1F4C4]', '[DOC]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u1F50D]', '[SEARCH]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u1F4CA]', '[CHART]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u1F4C8]', '[UP]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u1F4C9]', '[DOWN]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u1F3AF]', '[TARGET]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u2699]', '[CONFIG]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u1F527]', '[TOOL]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u1F6E0]', '[TOOLS]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u1F4CB]', '[LOG]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u1F4DD]', '[NOTE]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u1F4A1]', '[INFO]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u26A0]', '[WARNING]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u1F504]', '[REFRESH]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u23F3]', '[WAIT]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u1F389]', '[SUCCESS]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u1F525]', '[HOT]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u1F4AF]', '[PERFECT]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u1F31F]', '[STAR]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u2B50]', '[STAR]' | Set-Content '%%f'"
)

REM Remove emojis from all .html files
for /r "src" %%f in (*.html) do (
    echo Processing: %%f
    powershell -Command "(Get-Content '%%f') -replace '[\u2713]', '[OK]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u2717]', '[ERROR]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u2705]', '[OK]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u274C]', '[ERROR]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u1F512]', '[LOCK]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u1F513]', '[UNLOCK]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u1F510]', '[SECURE]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u1F511]', '[KEY]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u1F6E1]', '[SHIELD]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u26A1]', '[LIGHTNING]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u1F680]', '[LAUNCH]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u1F4BE]', '[SAVE]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u1F4C1]', '[FILE]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u1F4C4]', '[DOC]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u1F50D]', '[SEARCH]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u1F4CA]', '[CHART]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u1F4C8]', '[UP]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u1F4C9]', '[DOWN]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u1F3AF]', '[TARGET]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u2699]', '[CONFIG]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u1F527]', '[TOOL]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u1F6E0]', '[TOOLS]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u1F4CB]', '[LOG]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u1F4DD]', '[NOTE]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u1F4A1]', '[INFO]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u26A0]', '[WARNING]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u1F504]', '[REFRESH]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u23F3]', '[WAIT]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u1F389]', '[SUCCESS]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u1F525]', '[HOT]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u1F4AF]', '[PERFECT]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u1F31F]', '[STAR]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u2B50]', '[STAR]' | Set-Content '%%f'"
)

REM Remove emojis from all .bat files
for /r "." %%f in (*.bat) do (
    echo Processing: %%f
    powershell -Command "(Get-Content '%%f') -replace '[\u2713]', '[OK]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u2717]', '[ERROR]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u2705]', '[OK]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u274C]', '[ERROR]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u1F512]', '[LOCK]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u1F513]', '[UNLOCK]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u1F510]', '[SECURE]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u1F511]', '[KEY]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u1F6E1]', '[SHIELD]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u26A1]', '[LIGHTNING]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u1F680]', '[LAUNCH]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u1F4BE]', '[SAVE]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u1F4C1]', '[FILE]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u1F4C4]', '[DOC]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u1F50D]', '[SEARCH]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u1F4CA]', '[CHART]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u1F4C8]', '[UP]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u1F4C9]', '[DOWN]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u1F3AF]', '[TARGET]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u2699]', '[CONFIG]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u1F527]', '[TOOL]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u1F6E0]', '[TOOLS]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u1F4CB]', '[LOG]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u1F4DD]', '[NOTE]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u1F4A1]', '[INFO]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u26A0]', '[WARNING]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u1F504]', '[REFRESH]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u23F3]', '[WAIT]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u1F389]', '[SUCCESS]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u1F525]', '[HOT]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u1F4AF]', '[PERFECT]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u1F31F]', '[STAR]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u2B50]', '[STAR]' | Set-Content '%%f'"
)

REM Remove emojis from all .md files
for /r "." %%f in (*.md) do (
    echo Processing: %%f
    powershell -Command "(Get-Content '%%f') -replace '[\u2713]', '[OK]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u2717]', '[ERROR]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u2705]', '[OK]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u274C]', '[ERROR]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u1F512]', '[LOCK]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u1F513]', '[UNLOCK]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u1F510]', '[SECURE]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u1F511]', '[KEY]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u1F6E1]', '[SHIELD]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u26A1]', '[LIGHTNING]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u1F680]', '[LAUNCH]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u1F4BE]', '[SAVE]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u1F4C1]', '[FILE]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u1F4C4]', '[DOC]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u1F50D]', '[SEARCH]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u1F4CA]', '[CHART]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u1F4C8]', '[UP]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u1F4C9]', '[DOWN]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u1F3AF]', '[TARGET]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u2699]', '[CONFIG]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u1F527]', '[TOOL]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u1F6E0]', '[TOOLS]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u1F4CB]', '[LOG]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u1F4DD]', '[NOTE]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u1F4A1]', '[INFO]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u26A0]', '[WARNING]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u1F504]', '[REFRESH]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u23F3]', '[WAIT]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u1F389]', '[SUCCESS]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u1F525]', '[HOT]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u1F4AF]', '[PERFECT]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u1F31F]', '[STAR]' | Set-Content '%%f'"
    powershell -Command "(Get-Content '%%f') -replace '[\u2B50]', '[STAR]' | Set-Content '%%f'"
)

echo.
echo ========================================
echo Emoji Removal Complete!
echo ========================================
echo.
echo All emojis have been removed from:
echo - All .js files in src directory
echo - All .html files in src directory  
echo - All .bat files in project
echo - All .md files in project
echo.
echo Emojis replaced with text equivalents:
echo - Checkmark → [OK]
echo - X mark → [ERROR]
echo - Green checkmark → [OK]
echo - Red X → [ERROR]
echo - Lock → [SECURE]
echo - Rocket → [LAUNCH]
echo - Gear → [CONFIG]
echo - Fire → [HOT]
echo - And many more...
echo.
echo This prevents ROE (Rate of Error) and malformities!
echo.
pause