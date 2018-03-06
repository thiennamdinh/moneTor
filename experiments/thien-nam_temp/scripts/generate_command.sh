#!/bin/bash

DIR="~/Code/moneTor/experiments/"

python ~/Code/shadow-plugin-tor/tools/generate.py --nauths 3 --nrelays 20 --nclients 200 --nintermediaries 4 --nservers 5 --fwebnonprem 0.80 --fwebpremium 0.05 --fbulknonprem 0.1 --fbulkpremium 0.05 ${DIR}/net_data/alexa-top-1000-ips.csv ${DIR}/net_data/consensuses-2018-02/03/2018-02-03-00-00-00-consensus ${DIR}/net_data/server-descriptors-2018-02/ ${DIR}/net_data/extra-infos-2018-02/ ${DIR}/net_data/clients.csv

cd conf/
echo "MoneTorSingleCore 1" >> tor.common.torrc
