#!/bin/bash
cp ../../build/bin/Release/ecli ./ecli
alias lmp="sudo EUNOMIA_REPOSITORY=https://linuxkerneltravel.github.io/lmp/ EUNOMIA_HOME=/home/ubuntu/.lmp/ ./ecli"
