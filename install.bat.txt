@echo off
echo Checking for Python...
where python >nul 2>&1
if %errorlevel% neq 0 (
    echo Python is not installed or not in PATH. Please install Python from https://www.python.org/downloads/
    pause
    exit /b 1
)

echo Installing/Updating dependencies...
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

echo Running your script...
python your_script_name.py

echo Script finished.
pause