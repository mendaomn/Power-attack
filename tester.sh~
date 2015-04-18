#!/bin/bash
 
if [ $# -eq 0 ]
  then
    echo "No arguments supplied"
    echo "Usage:"
    echo "$0 <input file> <n> <start_value>"
    exit 1
fi
 
file=$1
n=$2
i=$3
count=0
nope=0
 
while [ $count -lt 100 ]
do
   ./ta $file $i | grep -e "[0-9a-f]" > /dev/null
   if [ $? -eq 0 ]
   then
      ((count++))
   else
      count=0
   fi
   echo $i $count
   ((i++))
done
 
echo exp=$((i-1))
