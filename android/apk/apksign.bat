"%~dp0..\zipalign.exe" -v 4 %1 %1.out.apk
java -jar "%~dp0..\apksigner.jar" sign --ks "%~dp0debug.keystore" --ks-key-alias test --ks-pass pass:test123456 --key-pass pass:test123456 --v1-signing-enabled true --v2-signing-enabled true %1.out.apk
move %1.out.apk %1