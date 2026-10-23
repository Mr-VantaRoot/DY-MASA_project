$ProjectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $ProjectRoot
$env:PYTHONPATH = ".;backend"
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
