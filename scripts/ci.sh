#!/bin/bash

if [[ $TRAVIS_OS_NAME == 'windows' ]]; then
  find / -name "MsBuild.exe"
  find / -name "cl.exe"
  msbuild /target:Build /p:Configuration=Debug   /p:Platform=Win32
  msbuild /target:Build /p:Configuration=Release /p:Platform=Win32
  msbuild /target:Build /p:Configuration=Debug   /p:Platform=x64
  msbuild /target:Build /p:Configuration=Release /p:Platform=x64
else
  # Linux or mac
  make
  make test
fi
