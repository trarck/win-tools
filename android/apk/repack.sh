#!/bin/bash
# Takashi Soda Jan 2012 
# Copyright DeNA Co., Ltd.

# Syntax 
# Argument 1: app name
# Argument 2: game_apk
# Argument 3: package name
# Argument 4: path for game directory
# Argument 5: version_name in AndroidManifest.xml
# Argument 6: version_code in AndroidManifest.xml
#
# Optional configuration by environment values
# Env GAME_SERVER: game server (e.g. spapp-a.mobage-platform.kr)
# Env C2DM_SENDER_ID: c2dm sender (e.g. mobagekrc2dm@gmail.com)

echo $0 $*

CMDNAME=`basename $0`
if [ $# -ne 6 ]; then
  echo "Usage: $CMDNAME app_name game_apk package_name game_path version_name version_code" 1>&2
  exit 1
fi

app_name=$1
game_apk=$2
package_name=$3
game_path=$4
version_name=$5
version_code=$6

# Temporary directory
temp_directory='Temporary_'$package_name

# clean up any existing directories
echo "removing $temp_directory"
rm -fr $temp_directory

# first step is to unpack the apk
echo "unpacking the apk"
java -jar ../apktool.jar d $game_apk -o $temp_directory

# replace the AndroidManifest.xml
manifest=$temp_directory'/AndroidManifest.xml'

# parse the AndroidManifest.xml
old_package_name="com.xuebaogames.demongame"

# change package names everywhere
echo "defining package names: $package_name"

cp -rf "./AndroidManifest.xml" $manifest
#sed -i '' 's|package=".*"|package="'$package_name'"|g' $manifest
#sed -i '' 's|android:versionCode=".*"|android:versionCode="'$version_code'"|g' $manifest
#sed -i '' 's|android:versionName=".*"|android:versionName="'$version_name'"|g' $manifest
if [ ! -z "`grep RUN ${manifest}`" ] ; then
  sed -i '' 's|android:name=".*\.RUN"|android:name="'$package_name'.RUN"|g' $manifest
fi

string=$temp_directory'/res/values/strings.xml'

# change app_name in strings.xml
#echo "changing app_name in strings.xml: ${app_name}"
#sed -i '' 's|<string name="gamejs_name">.*<\/string>|<string name="gamejs_name">'"$app_name"'</string>|g' $string
#sed -i '' 's|<string name="notification_title">.*<\/string>|<string name="notification_title">'"$app_name"'</string>|g' $string


# package
echo "repackaging apk"
java -jar ../apktool.jar b $temp_directory -o output-unsigned-unaligned.apk

# for internal use
echo "signing..."
KEYSTORE=demongame.keystore

jarsigner --verbose -keystore ${KEYSTORE} -storepass Xuebao2014 output-unsigned-unaligned.apk demongame
mv output-unsigned-unaligned.apk output-unaligned.apk
zipalign -v 4 output-unaligned.apk output.apk && mv output.apk $package_name.apk && rm -f output-unaligned.apk
