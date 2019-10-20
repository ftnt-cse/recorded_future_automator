#!/usr/bin/env python2
# Fetches recorded future IoCs and convert them into CSVs FortiSIEM can ingest via it's local http server
# Authors: FortiSIEM CSE Team

import csv
import getpass
import json
import re
import os
import sys
from datetime import datetime
import time
import requests
from rfapi import ConnectApiClient
import dateutil.parser as date_parser
import argparse

#document_root_folder='/var/www/html/ioc'
document_root_folder='/var/www/html/ioc/'

# Configuration
# Replace the api key below with the one you purchased from Recorded Future
api_key=''
# Considered criticality : return IoC has various criticality level depending on its rating source, the variable considered_criticality is used to select either the least or the worst
considered_criticality='WORST' # select 'WORST' to pick the worst one

def to_epoch(mytime):
	# Convert time to epoch
	tz_str = '''-12 Y
	-11 X NUT SST
	-10 W CKT HAST HST TAHT TKT
	-9 V AKST GAMT GIT HADT HNY
	-8 U AKDT CIST HAY HNP PST PT
	-7 T HAP HNR MST PDT
	-6 S CST EAST GALT HAR HNC MDT
	-5 R CDT COT EASST ECT EST ET HAC HNE PET
	-4 Q AST BOT CLT COST EDT FKT GYT HAE HNA PYT
	-3 P ADT ART BRT CLST FKST GFT HAA PMST PYST SRT UYT WGT
	-2 O BRST FNT PMDT UYST WGST
	-1 N AZOT CVT EGT
	0 Z EGST GMT UTC WET WT
	1 A CET DFT WAT WEDT WEST
	2 B CAT CEDT CEST EET SAST WAST
	3 C EAT EEDT EEST IDT MSK
	4 D AMT AZT GET GST KUYT MSD MUT RET SAMT SCT
	5 E AMST AQTT AZST HMT MAWT MVT PKT TFT TJT TMT UZT YEKT
	6 F ALMT BIOT BTT IOT KGT NOVT OMST YEKST
	7 G CXT DAVT HOVT ICT KRAT NOVST OMSST THA WIB
	8 H ACT AWST BDT BNT CAST HKT IRKT KRAST MYT PHT SGT ULAT WITA WST
	9 I AWDT IRKST JST KST PWT TLT WDT WIT YAKT
	10 K AEST ChST PGT VLAT YAKST YAPT
	11 L AEDT LHDT MAGT NCT PONT SBT VLAST VUT
	12 M ANAST ANAT FJT GILT MAGST MHT NZST PETST PETT TVT WFT
	13 FJST NZDT
	11.5 NFT
	10.5 ACDT LHST
	9.5 ACST
	6.5 CCT MMT
	5.75 NPT
	5.5 SLT
	4.5 AFT IRDT
	3.5 IRST
	-2.5 HAT NDT
	-3.5 HNT NST NT
	-4.5 HLV VET
	-9.5 MART MIT'''

	tzd = {}
	for tz_descr in map(str.split, tz_str.split('\n')):
		tz_offset = int(float(tz_descr[0]) * 3600)
		for tz_code in tz_descr[1:]:
			tzd[tz_code] = tz_offset

	parsed_time = date_parser.parse(mytime,tzinfos=tzd)
	return int(parsed_time.strftime('%s'))


def to_time(mytime):
	#return a converted epoch as time and date
	timestamp=time.strftime('%H:%M:%S', time.localtime(mytime)),time.strftime('%m/%d/%Y', time.localtime(mytime))
	return ' '.join(timestamp)



def ip_to_country_lookup(lookup_ip):
	# Lookup ip to country
	# Args:
	#     lookup_ip			: ip to resolve
	# Returns:
	#	  Country
	try:
		session = requests.Session()
		response = session.get('https://freegeoip.app/json/' + lookup_ip)

		country=json.loads(response.content)									# if the http req succeeds
		if country['country_name']:									# if the lookup response contains a country
			return country['country_name']							# ip to country lookup
		else:
			return 'Unknown'										#ip to country lookup

	except requests.ConnectionError:
		print("Connection error, Make sure the device is listening in 443")
		return 'Unknown'
	except requests.ConnectTimeout:
		print("Connection timeout")
		return 'Unknown'
	except requests.exceptions.RequestException as e:
		print("An error occured: %s" % e)	
		return 'Unknown'

		
def csv_formatter(csv_file,ioc_type,country_lookup='no'):
	# Parses and formats the fetched IoCs to be used by FortiSIEM
	# Args: 
	#		csv_file			: downloaded ioc file from recorded future
	#		ioc_type			: type of ioc to process (ip, domain, hash)
	#		country_lookup 		: lookup (or not) the IP or domain to country, default value is 'no'	
	open(document_root_folder + ioc_type + '_rf.csv', 'w').close()										# Empty previous content

	with open(csv_file, 'rb') as f:
		next(f)																	#skip first line
		details_dict={}
		csv_line=[]
		reader = csv.reader(f, delimiter=',')									# Load csv and convert to list
		ioc_list = list(reader)

		if ioc_type == 'domain':
			print 'Saving columns: Domain | Confidence | Country (if -c yes) | IoC Name | Severity | Time-stamp | Comment | Last Seen (Tentative) to ' + document_root_folder + ioc_type + '_rf.csv'
		elif ioc_type == 'ip':
			print 'Saving columns: IP | Confidence | Country (if -c yes) | IoC Name | Severity | Timestamp | Comment | Last Seen (Tentative) to ' + document_root_folder + ioc_type + '_rf.csv'
		elif ioc_type == 'hash':
			print 'Saving columns: Hash | Confidence | Hash Algorythm | IoC Name | Severity | Timestamp | Comment | Last Seen (Tentative) to ' + document_root_folder + ioc_type + '_rf.csv'
			
		for item in ioc_list:

			csv_line.append(item[0])											# IP address, domain or hash
			csv_line.append(item[2]) 											# Risk string

			if ioc_type == 'ip' or ioc_type == 'domain':
				try:
					details_dict=json.loads(item[3])
					if country_lookup == 'yes':								#Convert EvidenceDetails into json
						csv_line.append(ip_to_country_lookup(item[0]))					# lookup country
					else:
						csv_line.append('Unresolved')
				except ValueError as e:
					continue
			elif ioc_type == 'hash':
				try:
					details_dict=json.loads(item[4])								#Convert EvidenceDetails into json
					csv_line.append(item[1])										#Read hash algorythm
				except ValueError as e:
					continue

			details_list=details_dict['EvidenceDetails']							# Collect evidence details list
			if considered_criticality == 'LEAST':
				evidence_details = details_list[0]
			elif considered_criticality == 'WORST':
				evidence_details = details_list[len(details_list)-1]


			csv_line.append(evidence_details['Name'])								#IoC Type
			csv_line.append(str(evidence_details['Criticality']))					#Severity

			csv_line.append(to_time(to_epoch(evidence_details['Timestamp'])))		#timestamp 
			csv_line.append(evidence_details['EvidenceString'])

			# attempt to parse last seen date
			last_seen = re.findall(r'(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)(\s+\d+,\s+\d{4})',evidence_details['EvidenceString'])

			if len(last_seen) > 0:
				date=''
				for item in last_seen[0]:
					date = date + item
				last_seen = datetime.strptime(date.replace(', ','/').replace(' ','/'), '%b/%d/%Y')
				csv_line.append(last_seen.strftime('%m/%d/%Y'))

			line="|".join(csv_line).encode('UTF-8')
			with open(document_root_folder + ioc_type + '_rf.csv', 'a') as f:
				f.write(line + '\n')

			del csv_line[:]


def main():
	parser = argparse.ArgumentParser()
	parser.add_argument('-t', '--type',type=str, required=True,choices={"ip", "hash", "domain"}, help="Type of IoC to process : ip, hash, domain. exp for IP use : --type ip")
	parser.add_argument('-c', '--clookup',type=str, required=False,choices={"yes", "no"}, default='no', help="Chose whether to lookup the IP or domain country or not")
	args = parser.parse_args()

	if not os.path.exists(document_root_folder):
		print document_root_folder + ' folder is missing.'
		sys.exit(1)
	if not os.access(document_root_folder, os.W_OK):
		print 'User '+ getpass.getuser() +' has no write permission on  '+document_root_folder
		sys.exit(1)

	
	print 'Downloading IoC...'
	api = ConnectApiClient(auth=api_key)

	#Name	Risk	RiskString	EvidenceDetails
	with open(document_root_folder + args.type + '.csv', 'wb') as f:
		api.save_risklist(f, args.type, None, 'csv')

	
	csv_formatter(document_root_folder + args.type + '.csv', args.type, args.clookup)


if __name__ == '__main__':
	main()
