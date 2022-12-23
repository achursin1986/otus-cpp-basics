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
sed -f commands2.sed correct.json > correct2.json
awk '{for(x=1;x<=NF;x++)if($x~/"ext-reachability-tlv/){sub(/ext-reachability-tlv/,"ext-reachability-tlv"i++)}}1' correct2.json > correct3.json
awk '{for(x=1;x<=NF;x++)if($x~/"reachability-tlv/){sub(/reachability-tlv/,"reachability-tlv"i++)}}1' correct3.json > ready_for_repl.json


rm -rf commands.sed
rm -rf commands2.sed
rm -rf converted
rm -rf correct.json
rm -rf correct2.json
rm -rf correct3.json


exit 0
