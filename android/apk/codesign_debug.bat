@echo off
jarsigner -verbose -keystore "%~dp0\debug2.keystore" -storepass android -keypass android %1 debug