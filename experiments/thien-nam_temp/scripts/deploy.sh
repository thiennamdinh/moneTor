#!/bin/bash

# - obtain folder name and description from args
# - record description
# - record commits (shadow/shadow-tor/tor)
#
# - make new folder
# - copy generate_command.sh in
# - call generate_command.sh
#
# - run shadow (in background)
#
# - copy analyze_command.sh in
# - call analyze_command.sh

EXPERIMENT=$1
DESCRIPTION=$2

if [ -d "$EXPERIMENT" ]; then
    echo "directory already exists; exiting"
    exit 1
fi

# create and navigate to inputed directory
cd "$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd ../
mkdir $EXPERIMENT
cd $EXPERIMENT

# set up in the info describing the run

VSHADOW="$( cd ~/Code/shadow && git rev-parse HEAD )"
VPLUGIN="$( cd ~/Code/shadow-plugin-tor && git rev-parse HEAD )"
VTOR="$( cd ~/Code/shadow-plugin-tor/build/tor && git rev-parse HEAD )"

printf "${DESCRIPTION}\n\n" > info.txt
printf "shadow commit: ${VSHADOW}\n" >> info.txt
printf "plugin commit: ${VPLUGIN}\n" >> info.txt
printf "tor commit: ${VTOR}\n" >> info.txt

cp ../scripts/generate_command.sh ./
cp ../scripts/analyze_command.sh ./

# generate the simulation and run it
{ ./generate_command.sh > generate.log; } &>generate.err &&
    echo "generation complete" &&
    { shadow --cpu-threshold=-1 shadow.config.xml > shadow.log; } >&shadow.err &&
    echo "simulation complete" &&
    { ./analyze_command.sh > analyze.log; } &>analyze.err &&
    echo "analysis complete"
