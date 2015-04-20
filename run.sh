#!/bin/sh

cd ./netsetup
sh ./newNetup.sh
cd ../
sleep 2
./practiGateway.exe ./config

