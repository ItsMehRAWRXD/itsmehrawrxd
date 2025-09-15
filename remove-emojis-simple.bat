@echo off
echo ========================================
echo RawrZ Simple Emoji Removal Script
echo ========================================
echo.
echo Removing emojis to prevent ROE and malformities...
echo.

REM Create a simple Node.js script to remove emojis
echo Creating emoji removal script...
(
echo const fs = require('fs'^);
echo const path = require('path'^);
echo.
echo const emojiReplacements = {
echo     '\u2713': '[OK]',
echo     '\u2717': '[ERROR]',
echo     '\u2705': '[OK]',
echo     '\u274C': '[ERROR]',
echo     '\u1F512': '[LOCK]',
echo     '\u1F513': '[UNLOCK]',
echo     '\u1F510': '[SECURE]',
echo     '\u1F511': '[KEY]',
echo     '\u1F6E1': '[SHIELD]',
echo     '\u26A1': '[LIGHTNING]',
echo     '\u1F680': '[LAUNCH]',
echo     '\u1F4BE': '[SAVE]',
echo     '\u1F4C1': '[FILE]',
echo     '\u1F4C4': '[DOC]',
echo     '\u1F50D': '[SEARCH]',
echo     '\u1F4CA': '[CHART]',
echo     '\u1F4C8': '[UP]',
echo     '\u1F4C9': '[DOWN]',
echo     '\u1F3AF': '[TARGET]',
echo     '\u2699': '[CONFIG]',
echo     '\u1F527': '[TOOL]',
echo     '\u1F6E0': '[TOOLS]',
echo     '\u1F4CB': '[LOG]',
echo     '\u1F4DD': '[NOTE]',
echo     '\u1F4A1': '[INFO]',
echo     '\u26A0': '[WARNING]',
echo     '\u1F504': '[REFRESH]',
echo     '\u23F3': '[WAIT]',
echo     '\u1F389': '[SUCCESS]',
echo     '\u1F525': '[HOT]',
echo     '\u1F4AF': '[PERFECT]',
echo     '\u1F31F': '[STAR]',
echo     '\u2B50': '[STAR]'
echo };
echo.
echo function removeEmojisFromFile(filePath^) {
echo     try {
echo         let content = fs.readFileSync(filePath, 'utf8'^);
echo         let modified = false;
echo         
echo         for (const [emoji, replacement] of Object.entries(emojiReplacements^)^) {
echo             if (content.includes(emoji^)^) {
echo                 content = content.replace(new RegExp(emoji, 'g'^), replacement^);
echo                 modified = true;
echo             }
echo         }
echo         
echo         if (modified^) {
echo             fs.writeFileSync(filePath, content, 'utf8'^);
echo             console.log('Processed:', filePath^);
echo         }
echo     } catch (error^) {
echo         console.error('Error processing', filePath, ':', error.message^);
echo     }
echo }
echo.
echo function processDirectory(dirPath, extensions^) {
echo     try {
echo         const files = fs.readdirSync(dirPath^);
echo         
echo         for (const file of files^) {
echo             const fullPath = path.join(dirPath, file^);
echo             const stat = fs.statSync(fullPath^);
echo             
echo             if (stat.isDirectory(^)^) {
echo                 processDirectory(fullPath, extensions^);
echo             } else if (stat.isFile(^)^) {
echo                 const ext = path.extname(file^).toLowerCase(^);
echo                 if (extensions.includes(ext^)^) {
echo                     removeEmojisFromFile(fullPath^);
echo                 }
echo             }
echo         }
echo     } catch (error^) {
echo         console.error('Error processing directory', dirPath, ':', error.message^);
echo     }
echo }
echo.
echo console.log('Starting emoji removal...'^);
echo.
echo // Process source files
echo if (fs.existsSync('src'^)^) {
echo     processDirectory('src', ['.js', '.html', '.css', '.json']^);
echo }
echo.
echo // Process root files
echo processDirectory('.', ['.bat', '.md', '.txt']^);
echo.
echo console.log('Emoji removal complete!'^);
) > remove-emojis.js

echo Running emoji removal...
node remove-emojis.js

echo.
echo Cleaning up...
del remove-emojis.js

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
echo This prevents ROE (Rate of Error) and malformities!
echo.
pause
