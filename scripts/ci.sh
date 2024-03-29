#!/bin/bash

if [[ $RUNNER_OS == 'Windows' ]]; then
  df
  #find / -name "MsBuild.exe"
  #find / -name "cl.exe"
  msbuild /target:Build /p:Configuration=Debug   /p:Platform=Win32
  msbuild /target:Build /p:Configuration=Release /p:Platform=Win32
  msbuild /target:Build /p:Configuration=Debug   /p:Platform=x64
  msbuild /target:Build /p:Configuration=Release /p:Platform=x64
  find .
  uname -s
else
  # Linux or mac
  make
  make test
  out=vsencrypt.$(uname -s)
  mv vsencrypt $out
  find .
fi
