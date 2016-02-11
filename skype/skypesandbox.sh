#!/bin/bash
mkdir -p containment
grep -q '<Installed>2</Installed>' containment/.Skype/shared.xml || (
  echo "Bypassing blocking terms of service dialogue (only needs to happen once)"
  env HOME="$(pwd)/containment" skype &
  sleep 5
  kill %1
  sleep 2
  kill -9 %1
  sed -i '/<UI>/a    <Installed>2</Installed>' containment/.Skype/shared.xml
)
#xvfb-run -s '-screen 0 10x10x8' \
#dbus-run-session \
env HOME="$(pwd)/containment" skype --pipelogin
