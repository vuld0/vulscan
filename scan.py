import os
import sys
from re import search
import requests
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin
from pprint import pprint

#Initializing an HTTP session & setting the browser

s = requests.Session()
s.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36"

#Extracting all forms from the HTML Content

def get_all_forms(url):
	"""Given a `url`, it returns forms from the HTML content"""
	soup = bs(s.get(url).content,"html.parser")
	return soup.find_all("form")

def get_form_details(form):
	"""Extracting info about an HTML `form`"""	

	details = {}

	#get the form action(target url)

	try:
		action = form.attrs.get("action").lower()

	except:
		action = None

	#getting the form methods

	method = form.attrs.get("method","get").lower()

	inputs = []

	#getting all the input details
	for tag in form.find_all("input"):
		type = tag.attrs.get("type","text")
		name = tag.attrs.get("name")
		value = tag.attrs.get("value","")
		inputs.append({"type":type,"name":name,"value":value})

	details["action"] = action
	details["method"] = method
	details["inputs"] = inputs

	return details

def is_vulnerable(response):
    errors = {
        # MySQL
        "you have an error in your sql syntax;",
        "warning: mysql",
        # SQL Server
        "unclosed quotation mark after the character string",
        # Oracle
        "quoted string not properly terminated",
    }
    for error in errors:
        # if you find one of these errors, return True
        if error in response.content.decode().lower():
            return True
    # no error detected
    return False
	
def scanSQLi(url):
	for c in "\"'":
		#adding quotes to the url
		newurl = f"{url}{c}"
		print("Trying",newurl)
		res = s.get(newurl)
		if is_vulnerable(res):
			# SQL Injection detected on the URL
			# Add the Caution below 
			print("SQL Injection Detected",newurl)
			return

	forms = get_all_forms(url)
	print(f"Detected {len} forms on {url}.")
	for form in forms:
		form_details = get_form_details(form)
		for c in "\"'":
			data = {}
			for input_tag in form_details["inputs"]:
				if input_tag in form_details["inputs"]:
					try:
						data[input_tag["name"]] = input_tag["value"] + c
					except:
						pass
				elif input_tag["type"] != "submit":
					data[input["name"]] = f"test{c}"
			url = urljoin(url, form_details["action"])
			if form_details["method"] == "post":
				res = s.post(url,data = data)
			elif form_details["method"] == "get":
				res = s.get(url,params=data)

			if is_vulnerable(res):
				print("SQL Injection vulnerability detected, link:", url)
				pprint(form_details)
				break


def submit_form(form_details, url, value):
    # construct the full URL (if the url provided in action is relative)
    target_url = urljoin(url, form_details["action"])
    # get the inputs
    inputs = form_details["inputs"]
    data = {}
    for input in inputs:
        # replace all text and search values with `value`
        if input["type"] == "text" or input["type"] == "search":
            input["value"] = value
        input_name = input.get("name")
        input_value = input.get("value")
        if input_name and input_value:
            data[input_name] = input_value

    if form_details["method"] == "post":
        return requests.post(target_url, data=data)
    else:
        return requests.get(target_url, params=data)


def scanXSS(url):
	forms = get_all_forms(url)
	print(f"[+] Detected {len(forms)} forms on {url}.")
	xsspayload = "<Script>alert('check')</scripT>"

	for form in forms:
		form_details = get_form_details(form)
		content = submit_form(form_details, url, xsspayload).content.decode()
		if xsspayload in content:
			print(f"[+] XSS Detected on {url}")
			print(f"[*] Form details:")
			pprint(form_details)

if __name__ == "__main__":
	baseurl = sys.argv[1]

	# str1 = "./vulscan -u '%s'>output.txt" % (baseurl)
	# os.system(str1)


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


	for link in endpoints:
		scanSQLi(link)
		scanXSS(link)

	


