import argparse
import json
import requests
import codecs
import locale
import os
import sys
import ast
import csv
import time
import re
   
class Censys:
 
	def __init__(self, ip):
 
		self.API_URL = "https://www.censys.io/api/v1"
		self.UID = "<UID>"
		self.SECRET = "<secret key>"
		self.set=["IP Address","Services","Web Title","Server","Server Powered By","Server Description","Name","Alternative DNS names from ceritificate","Browser Trusted Certificate","Vulnerable to Heartbleed","Certificate Expires on","FTP Banner","SSH Banner","Telnet Banner","SMTP Banner","IMAP Banner","POP3 Banner","IMAPS Banner","POP3S Banner","Open DNS resolver","Description","OS","Device Type","Manfacturer","product","Country","Continent","Updated at"];
		self.out=open("new_data.csv","w",encoding='utf-8')
		self.output=csv.writer(self.out)
		self.output.writerow(self.set)

	def search(self):
 
		pages = float('inf')
		page = 1
		count= 1
		while page <= pages:  
			params = {'query' : '"<org name>"', 'page' : page}
			try:
				res = requests.post(self.API_URL + "/search/ipv4", json = params, auth = (self.UID, self.SECRET))
				payload = res.json()
				pages=payload['metadata']['pages']
				for r in payload['results']:
					self.set=[];
					try:
						if r["ip"]:
							ip = r["ip"]
						else:
							ip = "N/A"
					except:
						ip = "N/A"
					try:
						if r["protocols"]:
							proto = r["protocols"]
							#proto = [p.split("/")[0] for p in proto]
							#proto.sort(key=float)
							protoList = ','.join(map(str, proto))
						else:
							protoList="N/A"
					except:
						protoList="N/A"
					print ('IP: [%s] - Protocols: [%s]' %  (ip, protoList))
					print (' Pages: [%f]' % pages)
					print (page)
					print (count)
					#print (pages)
					self.set.append(ip)
					self.set.append(protoList)
					#if '80' in protoList:
					self.view(ip)
					count +=1
				page += 1
				time.sleep(150)
			except Exception as error:
				print ("first")
				print (error)
		self.out.close()

	def view(self, server):
 
		try:
			res = requests.get(self.API_URL + ("/view/ipv4/%s" % server), auth = (self.UID, self.SECRET))
			payload = res.json()
			combined = json.dumps(payload)
			combined_l = combined.lower()
			total_count = combined_l.count("<org name>")
			body = "None"
			try:
				body1 = payload['80']['http']['get']['body']
				body = body1.lower()
			except:
				body = "None"
			body_count = body.count("<org name>")
			print ("count %d : %d" % (total_count,body_count))
			if (total_count>body_count):
				try:
					if payload['80']['http']['get']['title']:
						title = payload['80']['http']['get']['title']
						result = re.search('(.+?)</title>',title)
						if result:
							title = result.group(1)
						self.set.append(title)
					else:
						self.set.append("N/A")
				except:
					self.set.append("N/A")
				try:
					if payload['80']['http']['get']['headers']['server']:
						self.set.append(payload['80']['http']['get']['headers']['server'])
						print("if")
					else:
						self.set.append("N/A")
						print("else")
				except:
					self.set.append("N/A")
				try:
					if payload['80']['http']['get']['headers']['x_powered_by']:
						self.set.append(payload['80']['http']['get']['headers']['x_powered_by'])
					else:
						self.set.append("N/A")
				except:
					self.set.append("N/A")
				try:
					if payload['80']['http']['get']['metadata']['description']:
						self.set.append(payload['80']['http']['get']['metadata']['description'])
					else:
						self.set.append("N/A")
				except:
					self.set.append("N/A")
				try:
					if payload['443']['https']['tls']['certificate']['parsed']['subject']['common_name']:
						self.set.append(payload['443']['https']['tls']['certificate']['parsed']['subject']['common_name'])
					else:
						self.set.append("N/A")
				except:
					self.set.append("N/A")
				try:
					if payload['443']['https']['tls']['certificate']['parsed']['extensions']['subject_alt_name']['dns_names']:
						self.set.append(payload['443']['https']['tls']['certificate']['parsed']['extensions']['subject_alt_name']['dns_names'])
					else:
						self.set.append("N/A")
				except:
					self.set.append("N/A")
				try:
					if (str(payload['443']['https']['tls']['validation']['browser_trusted']) == "True"):
						self.set.append(payload['443']['https']['tls']['validation']['browser_trusted'])
					elif (str(payload['443']['https']['tls']['validation']['browser_trusted']) == "False"):
						self.set.append(payload['443']['https']['tls']['validation']['browser_trusted'])
					else:
						self.set.append("N/A")
				except:
					self.set.append("N/A")
				try:
					if (str(payload['443']['https']['heartbleed']['heartbleed_vulnerable']) == "True"):
						self.set.append(payload['443']['https']['heartbleed']['heartbleed_vulnerable'])
					elif (str(payload['443']['https']['heartbleed']['heartbleed_vulnerable']) == "False"):
						self.set.append(payload['443']['https']['heartbleed']['heartbleed_vulnerable'])
					else:
						print("else")
						self.set.append("N/A")
				except:
					self.set.append("N/A")
				try:
					if payload['443']['https']['tls']['certificate']['parsed']['validity']['end']:
						self.set.append(payload['443']['https']['tls']['certificate']['parsed']['validity']['end'])
					else:
						self.set.append("N/A")
				except:
					self.set.append("N/A")
				try:
					if payload['21']['ftp']['banner']['banner']:
						self.set.append(payload['21']['ftp']['banner']['banner'])
					else:
						self.set.append("N/A")
				except:
					self.set.append("N/A")
				try:
					if payload['22']['ssh']['banner']['raw_banner']:
						self.set.append(payload['22']['ssh']['banner']['raw_banner'])
					else:
						self.set.append("N/A")
				except:
					self.set.append("N/A")
				try:
					if payload['23']['telnet']['banner']['banner']:
						self.set.append(payload['23']['telnet']['banner']['banner'])
					else:
						self.set.append("N/A")
				except:
					self.set.append("N/A")
				try:
					if payload['25']['smtp']['starttls']['banner']:
						self.set.append(payload['25']['smtp']['starttls']['banner'])
					else:
						self.set.append("N/A")
				except:
					self.set.append("N/A")
				try:
					if payload['143']['imap']['starttls']['banner']:
						self.set.append(payload['143']['imap']['starttls']['banner'])
					else:
						self.set.append("N/A")
				except:
					self.set.append("N/A")
				try:
					if payload['110']['pop3']['starttls']['banner']:
						self.set.append(payload['110']['pop3']['starttls']['banner'])
					else:
						self.set.append("N/A")
				except:
					self.set.append("N/A")
				try:
					if payload['993']['imaps']['tls']['banner']:
						self.set.append(payload['993']['imaps']['tls']['banner'])
					else:
						self.set.append("N/A")
				except:
					self.set.append("N/A")
				try:
					if payload['995']['pop3s']['tls']['banner']:
						self.set.append(payload['995']['pop3s']['tls']['banner'])
					else:
						self.set.append("N/A")
				except:
					self.set.append("N/A")
				try:
					#print (payload['53']['dns']['lookup']['open_resolver'])
					if (str(payload['53']['dns']['lookup']['open_resolver']) == "False"):
						self.set.append(payload['53']['dns']['lookup']['open_resolver'])
					elif (str(payload['53']['dns']['lookup']['open_resolver']) == "True"):
						self.set.append(payload['53']['dns']['lookup']['open_resolver'])
					else:
						self.set.append("N/A")
				except:
					self.set.append("N/A")
				try:
					if payload['metadata']['description']:
						self.set.append(payload['metadata']['description'])
					else:
						self.set.append("N/A")
				except:
					self.set.append("N/A")
				try:
					if payload['metadata']['os_description']:
						self.set.append(payload['metadata']['os_description'])
					else:
						self.set.append("N/A")
				except:
					self.set.append("N/A")
				try:
					if payload['metadata']['device_type']:
						self.set.append(payload['metadata']['device_type'])
					else:
						self.set.append("N/A")
				except:
					self.set.append("N/A")
				try:
					if payload['metadata']['manufacturer']:
						self.set.append(payload['metadata']['manufacturer'])
					else:
						self.set.append("N/A")
				except:
					self.set.append("N/A")
				try:
					if payload['metadata']['product']:
						self.set.append(payload['metadata']['product'])
					else:
						self.set.append("N/A")
				except:
					self.set.append("N/A")
				try:
					if payload['location']['country']:
						self.set.append(payload['location']['country'])
					else:
						self.set.append("N/A")
				except:
					self.set.append("N/A")
				try:
					if payload['location']['continent']:
						self.set.append(payload['location']['continent'])
					else:
						self.set.append("N/A")
				except:
					self.set.append("N/A")
				try:
					if payload['updated_at']:
						self.set.append(payload['updated_at'])
					else:
						self.set.append("N/A")
				except:
					self.set.append("N/A")
				self.output.writerow(self.set)
		except Exception as error:
			print ("second")
			print (error)
parser = argparse.ArgumentParser(description = 'CENSYS.IO Web Server Search')
parser.add_argument('-f', '--find', help='CENSYS Search', required = True)
args = parser.parse_args()
ip = args.find
censys = Censys(ip)
censys.search()
