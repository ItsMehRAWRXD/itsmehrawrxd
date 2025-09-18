@echo off 
echo Building simple native engine... 
 
if exist build\simple-native\libsimple_root_engine.so del build\simple-native\libsimple_root_engine.so 
 
echo Compiling with g++... 
g++ -shared -fPIC -o build\simple-native\libsimple_root_engine.so build\simple-native\SimpleRootEngine.cpp 
 
if 0 equ 0 ( 
    echo SUCCESS! Simple native library built 
) else ( 
    echo BUILD FAILED! 
) 
 
pause 
