@echo off
jarsigner -verbose -keystore "%~dp0\debug.keystore" -storepass android -keypass android %1 androiddebugkey