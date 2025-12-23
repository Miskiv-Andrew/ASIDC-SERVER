@echo off
setlocal

cd ..

set BUILD_DIR=build
set CONFIG=Release

if not exist %BUILD_DIR% (
    mkdir %BUILD_DIR%
)

cd %BUILD_DIR%

cmake .. -DCMAKE_BUILD_TYPE=%CONFIG%
cmake --build . --config %CONFIG%

echo.
echo Build finished.
pause
