import os
import sys
from re import search
import requests
from bs4 import BeautifulSoup
import config
import progressbar

baseurl = sys.argv[1]
'''
str1 = "./vulscan -u '%s'>output.txt" % (baseurl)
os.system(str1)
'''

#reading the contents from the web crawler file

flag = 0
endpoints = []

with open("output.txt", "r") as f:
	   grades = [x.strip() for x in f.readlines()]


for i in grades:
	if search(baseurl,str(i)):
		currenturl = str(i)
	if str(i) == "LINKS:":
		flag = 1
	if flag == 1:
		endpoints.append(str(currenturl)[1:-1]+"/"+str(i)[1:-1])
	
	
	if str(i) == "]":
		flag = 0   

def GetHTML(url):
	r = requests.get(url)
	return(r.text)

#remove this:
GetHTML(endpoints[6])

def GetHref(html):
	soup = BeautifulSoup(html,"lxml")
	hreflist = []
	for link in soup.findAll('a'):
		href = link.get('href')
		if href and '#'  not in href:
			hreflist.append(href)
	return set(hreflist)

def GetContentofPages(urllist):
	links = {None:None}

	for url in urllist:
		html = GetHTML(url)
		links.update({url:html})

	links.pop(None)

	return links

def CheckforVulns(contents):
	global bar
    global currenttested
    result = []

    bar = progressbar.progressbar("bar", "Search vulns")
    bar.totalcount = len(config.vulncheck)
    bar.count = 0

    for vulnlist in config.vulncheck:
        bar.total = len(vulnlist[0])
        bar.value = 0
        bar.count += 1
        currenttested = vulnlist[1]
        for vuln in vulnlist[0]:
            bar.progress(1)
            if payload:
                result.append(payload)
                break
    
    bar.delbar()
    return result




