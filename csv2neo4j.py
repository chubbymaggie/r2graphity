#!/usr/bin/env python
# -*- coding: utf-8 -*-

import csv
from py2neo import authenticate, Graph, Relationship
from py2neo.ogm import GraphObject, Property


match_method = {
    #'filename': True,
    #'filetype': True,
    #'filesize': 1000,
    #'md5': True,
    #'imphash': True,
    #'compilationtime': True,
    #'addressep': True,
    #'sectionep': True,
    #'tlssections': True,
    #'originalfilename': True,
    #'sectioncount': 1,
    #'secname1': True,
    #'secname2': True,
    #'secname3': True,
    #'secname4': True,
    #'secname5': True,
    #'secname6': True,
    #'secsize1': 1000,
    #'secsize2': 1000,
    #'secsize3': 1000,
    #'secsize4': 1000,
    #'secsize5': 1000,
    #'secsize6': 1000,
    #'secent1': 0.1,
    #'secent2': 0.1,
    #'secent3': 0.1,
    #'secent4': 0.1,
    #'secent5': 0.1,
    #'secent6': 0.1,
    'functionstotal': 1,
    'refslocal': 1,
    #'refsglobalvar': 1,
    'refsunknown': 1,
    'apitotal': 1,
    #'apimisses': 1,
    'stringsreferenced': 1,
    #'stringsdangling': 1,
    'stringsnoref': 1
}


class Sample(GraphObject):
    __primarykey__ = "md5"

    md5 = Property()
    filename = Property()
    filetype = Property()
    filesize = Property()
    imphash = Property()
    compilationtime = Property()
    addressep = Property()
    sectionep = Property()
    tlssections = Property()
    originalfilename = Property()
    sectioncount = Property()
    secname1 = Property()
    secname2 = Property()
    secname3 = Property()
    secname4 = Property()
    secname5 = Property()
    secname6 = Property()
    secsize1 = Property()
    secsize2 = Property()
    secsize3 = Property()
    secsize4 = Property()
    secsize5 = Property()
    secsize6 = Property()
    secent1 = Property()
    secent2 = Property()
    secent3 = Property()
    secent4 = Property()
    secent5 = Property()
    secent6 = Property()
    functionstotal = Property()
    refslocal = Property()
    refsglobalvar = Property()
    refsunknown = Property()
    apitotal = Property()
    apimisses = Property()
    stringsreferenced = Property()
    stringsdangling = Property()
    stringsnoref = Property()

host = 'localhost:7474'
username = 'neo4j'
password = 'neo4j'

authenticate(host, username, password)

graph = Graph("http://{}/db/data/".format(host))
graph.delete_all()

with open('test.csv') as csvfile:
    reader = csv.DictReader(csvfile)
    tx = graph.begin()
    for row in reader:
        sample = Sample()
        for k, v in row.items():
            if v is not None and v != '0':
                setattr(sample, k, v)
        graph.push(sample)
    tx.commit()
    for s in Sample.select(graph):
        for k, v in match_method.items():
            tx = graph.begin()
            if k == 'md5' or 'sec' in k or not getattr(s, k):
                continue
            elif isinstance(v, bool):
                for rel in Sample.select(graph).where("_.{val} = '{data}'".format(val=k, data=getattr(s, k))):
                    if s == rel:
                        continue
                    if len(list(graph.match(start_node=rel.__ogm__.node, end_node=s.__ogm__.node, rel_type=k))) > 0:
                        continue
                    r = Relationship(s.__ogm__.node, k, rel.__ogm__.node, bidirectional=True)
                    tx.create(r)
            else:
                for rel in Sample.select(graph).where("_.{val} >= '{min}' AND _.{val} <= '{max}'".format(val=k, min=float(getattr(s, k)) - v, max=float(getattr(s, k)) + v)):
                    if s == rel:
                        continue
                    if len(list(graph.match(start_node=rel.__ogm__.node, end_node=s.__ogm__.node, rel_type=k))) > 0:
                        continue
                    r = Relationship(s.__ogm__.node, k, rel.__ogm__.node, bidirectional=True)
                    tx.create(r)
            tx.commit()
