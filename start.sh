#!/bin/bash

python ./http-bridge/setup.py 
if [ $? -eq 0 ]
then
  echo "Setup successful, starting http-bridge"
  python ./http-bridge/processes.py
else
  echo "Setup failed with error " >&2
fi