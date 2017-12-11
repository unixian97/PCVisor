# /bin/bash

for file in ../test/rules/*; do
    echo ${file##*/}
    ./rule2prefix.py $file ../test/p_rules/${file##*/}
done
