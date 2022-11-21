#!/bin/bash 

if [ $# -le 1 ]
  then
    echo "Usage: prepare_json <subs> <.json>"
    exit 1
fi

awk '{for(i=NF;i>=1;i--) printf "%s ", $i;print""}' $1| awk '$1=$1' > converted

sed -e 's/^/s|/' -e $'s/ /|/' -e 's/$/|g/' converted > commands.sed
sed -f commands.sed $2 > correct.json
sed -e 's/^/s|/' -e $'s/ /  /' -e $'s/ /"/'   -e $'s/ /|/' -e 's/$/" /' -e 's/ /|g/' $1 > commands2.sed
sed -f commands2.sed correct.json > ready_for_repl.json 

rm -rf commands.sed
rm -rf commands2.sed
rm -rf converted
rm -rf correct.json

exit 0
