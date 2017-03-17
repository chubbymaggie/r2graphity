# r2graphity

Usage
=====

graphity.py [-h] [-p] [-i] [-l] [-b] [-n] [-c CSVDUMP] input


positional arguments:

  input           Tool requires an input file or directory; directory, i.e. batch processing, only possible and feasible for csvdump option and Neo4j dump


optional arguments:

  -h, --help      show this help message and exit

  -d, --deactivatecache   Deactivate caching of graphs, for debugging of graph generation

  -p, --printing  Print the graph as text, as in, nodes with respective content

  -i, --info      Print info and stats of the graph

  -l, --plotting  Plotting the graph via pyplot

  -b, --behavior  Scan for behaviors listed in graphityFunc.py

  -n, --neodump   Dump graph to Neo4j (configured to flush previous data from Neo, might wanna change that)

  -c CSVDUMP, --csvdump CSVDUMP Dump info data to a given csv file, appends a line per sample



R2Graphity is built to construct a graph structure based on the function call graph of a Windows executable. Details on how the graph is built and processing options can be found in the attached slide deck, presented at H2HC 2016 in Sao Paulo, Brasil.


Dependencies
============


Watch out to get the Python3 packages, or install directly with pip3.

radare2		https://github.com/radare/radare2

r2pipe		https://github.com/radare/radare2/wiki/R2PipeAPI

NetworkX		https://github.com/networkx/

Neo4j			https://neo4j.com/download/

py2neo		http://py2neo.org/v3/

numpy			https://github.com/numpy/numpy

pefile		https://github.com/erocarrera/pefile

pydeep		https://github.com/kbandla/pydeep


Watch out to install radare2 from the git repository, do not use the Debian package. Tested to run best with radare2 1.3.0-git 13968 @ linux-x86-64, commit: 17355cbe3cd21ed1b3a91f1ee85680f9cc28fd8f build: 2017-03-05__20:31:24

Installation
============

```
    (sudo) pip3 install -r requirements.txt
```

