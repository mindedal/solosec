@echo off
:: This wrapper allows Windows users to just type "solosec"
:: without needing to type ".ps1"
powershell -ExecutionPolicy Bypass -File "%~dp0solosec.ps1" %*
