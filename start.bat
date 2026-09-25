@echo off
title MANKKDEV Control Panel
cd /d "%~dp0"
if not exist node_modules (
  echo Menginstal dependensi, mohon tunggu...
  call npm install
)
start "" http://localhost:3000
node server.js
pause
