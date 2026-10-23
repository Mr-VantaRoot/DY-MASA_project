$FrontendDir = Join-Path (Split-Path -Parent $PSScriptRoot) "frontend"
Set-Location $FrontendDir
New-Item -ItemType Directory -Force -Path "node_modules\.vite-temp" | Out-Null
npm run dev
