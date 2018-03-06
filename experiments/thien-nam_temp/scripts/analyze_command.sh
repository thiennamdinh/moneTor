#!/bin/bash

# generate data
python ~/Code/shadow/src/tools/parse-shadow.py shadow.log --prefix results_shadow/
python ~/Code/shadow/src/tools/parse-tgen.py shadow.data/hosts --prefix results_tgen/
python ~/Code/shadow/src/tools/parse-tgen.py shadow.data/hosts --prefix results_tgen_web_np/ --filter "web|np"
python ~/Code/shadow/src/tools/parse-tgen.py shadow.data/hosts --prefix results_tgen_web_pr --filter "web|pr"
python ~/Code/shadow/src/tools/parse-tgen.py shadow.data/hosts --prefix results_tgen_bulk_np/ --filter "bulk|np"
python ~/Code/shadow/src/tools/parse-tgen.py shadow.data/hosts --prefix results_tgen_bulk_pr/ --filter "bulk|pr"

# create plots
python ~/Code/shadow/src/tools/plot-shadow.py --prefix shadow --data results_shadow/ "all"
python ~/Code/shadow/src/tools/plot-shadow.py --prefix split --data results_tgen_web_np "nonprem web" --data results_tgen_web_pr "premium web" --data results_tgen_bulk_np "nonprem bulk" --data results_tgen_bulk_pr "premium bulk"
