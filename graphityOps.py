import networkx as nx
import graphityFunc

# TODO restructure this to graphityOps.py, for scanning, graph transformation, info extraction

### SCANNING ###

# searching nodes and nearby nodes a pattern defined by graphityFunc.py
def patternScan(graphity, pattern):

	# search is performed by defining "anchor" node, where initial pattern is found
	# search then moved from there 1 level up to search surrounding nodes (number of levels could be increased)
	# pattern lists for now are kept rather small
	# TODO determine distance between found patterns to see which functionalities lie close to each other
	patternNum = len(pattern)
	anchorList = []

	allCalls = nx.get_node_attributes(graphity, 'calls')

	for function in allCalls:
	
		# TODO make this prettier!
		# apis = [el[1] for el in allCalls[function]]
		# if 'CreateThread' in apis:
		# 	print (function)
			
		for call in allCalls[function]:

			api = call[1]
			anchorpat = pattern[0]

			if anchorpat in api:
				if not list(filter(lambda daAnchor: daAnchor['address'] == function, anchorList)):
					
					# maintain a dict of patterns per anchor to keep track of found patterns
					patternCheck = {}
					for item in pattern:
						patternCheck[item] = False
					patternCheck[anchorpat] = function

					anchorList.append({'address':function, 'patterns':patternCheck})

	# anchor nodes found and more than one pattern searched for
	if patternNum > 1 and len(anchorList) > 0:
		for anchor in anchorList:

			functionalityScanForApi(graphity, anchor, anchor['address'], patternNum)
			if False in anchor['patterns'].values():

				anchorNeighbors = nx.all_neighbors(graphity, anchor['address'])
				for neighbor in anchorNeighbors:
					functionalityScanForApi(graphity, anchor, neighbor, patternNum)

	return anchorList


# Search for a specific pattern within a node, orient by anchor pattern
def functionalityScanForApi(graphity, anchor, seNode, patternNum):

	for patt in anchor['patterns']:

		# anchor has a dict that saves which patterns were found already
		for call in graphity.node[seNode]['calls']:
			api = call[1]

			# found a pattern in an api call, that hasnt been found before
			if patt in api and anchor['patterns'][patt] == False:
				anchor['patterns'][patt] = seNode

				if not False in anchor['patterns'].values():
					# all patterns found - done
					break
					
					
### TRANSFORMATION ###

# Create a copy of the graphity structure, with APIs and strings as separate nodes
# Returns extended graph
def fetchExtendedGraph(graphity, allAtts):
	
	# copy NetworkX graph structure
	analysisGraph = graphity.copy()
	
	# per node, add string/api nodes and respective edges, networkx cares about possible duplicates automatically
	for aNode in analysisGraph.nodes(data=True):
	
		stringList = aNode[1]['strings']
		for stringData in stringList:
			analysisGraph.add_node(stringData[1], type='String')
			analysisGraph.add_edge(aNode[0], stringData[1])
				
		apiList = aNode[1]['calls']
		for apiData in apiList:
			analysisGraph.add_node(apiData[1], type='Api')
			analysisGraph.add_edge(aNode[0], apiData[1])
		
		# delete lists from nodes
		del analysisGraph.node[aNode[0]]['calls']
		del analysisGraph.node[aNode[0]]['strings']
	
	# add super node as SHA1
	analysisGraph.add_node(allAtts['sha1'], fileSize=allAtts['filesize'], binType=allAtts['filetype'], imphash=allAtts['imphash'], compilation=allAtts['compilationts'], addressEp=allAtts['addressep'], sectionEp=allAtts['sectionep'], sectionCount=allAtts['sectioncount'], originalFilename=allAtts['originalfilename'])
		
	# add edges to super node
	indegrees = graphity.in_degree()
	for val in indegrees:
		if indegrees[val] == 0:
			analysisGraph.add_edge(allAtts['sha1'], val)
		
	return analysisGraph						
		

# Returns the subgraph following [address] extended with APIs/Strings as separate nodes
def fetchExtendedSubgraph(graphity, address):

	theSub = nx.DiGraph()
	theSub.add_node(address, type='function', size=graphity.node[address]['size'], apicallcount=graphity.node[address]['apicallcount'])
	subGraphity(graphity, theSub, address)
	return theSub

def subGraphity(graphity, theSub, address):
	
	for acall in graphity.node[address]['calls']:
		label = acall[0] + '|' + acall[1]
		theSub.add_node(label, type='api', apiname=acall[1])
		theSub.add_edge(address, label)
	
	for astring in graphity.node[address]['strings']:
		label = astring[0] + '|' + astring[1]
		theSub.add_node(label, type='string', string=astring[1])
		theSub.add_edge(address, label)
	
	neighbors = graphity.successors(address)
	
	for neigh in neighbors:
		theSub.add_node(neigh, type='function', size=graphity.node[neigh]['size'], apicallcount=graphity.node[neigh]['apicallcount']) # add attributes
		theSub.add_edge(address, neigh)
		subGraphity(graphity, theSub, neigh)
		
	return
	

# returns the graph, nodes containing each their detected patterns, and a list of all detected patterns
# but no more string and api lists
def fetchBehaviorgadgetGraph(graphity):
	
	behaviorGraph = graphity.copy()
		
	allThePatterns = graphityFunc.funcDict
	allTheFindings = []
	for patty in allThePatterns:
		findings = patternScan(graphity, allThePatterns[patty])
		for hit in findings:
			if not False in hit['patterns'].values():
				for node in hit['patterns']:
					theNode = hit['patterns'][node]
					behaviorGraph.node[theNode][patty] = patty
	
	for node in behaviorGraph:
		del behaviorGraph.node[node]['calls']
		del behaviorGraph.node[node]['strings']
		behaviorGraph.node[node]['behaviors'] = ''
		for patty in allThePatterns:
			if behaviorGraph.node[node].get(patty):
				behaviorGraph.node[node]['behaviors'] += '|' + patty
		if behaviorGraph.node[node]['behaviors'] != '':
			behaviorGraph.node[node]['behaviors'] += '|'
	
	return behaviorGraph
	
# fetch a graph with particular patterns in APIs/Strings highlighted, e.g. allocs
def fetchSpecialGraph(graphity, specials):
	
	# TODO extend for strings
	specialGraph = graphity.copy()
	for node in specialGraph.nodes():
		for spec in specials:
			specialGraph.node[node][spec] = 0
	
	allCalls = nx.get_node_attributes(specialGraph, 'calls')
	for function in allCalls:
		for call in allCalls[function]:
			for spec in specials:
				if spec in call[1].lower():
					specialGraph.node[function][spec] += 1
	
	# TODO add one partition feature for all specs
	
	for node in specialGraph:
		del specialGraph.node[node]['calls']
		del specialGraph.node[node]['strings']
	
	return specialGraph