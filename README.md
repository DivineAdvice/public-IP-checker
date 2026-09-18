# public-IP-checker
It's a simple IP-address checker that checks public information and writes it in json-file.
This script is NOT created for DDoS or other non-fair usage.
In order to start using script you need to get IpInfo and AbuseIPDB api-key's, after that change variables in .env file.
IpInfo: https://ipinfo.io/
AbuseIPDB: https://www.abuseipdb.com/

USAGE:
Should be use through console (windows or programming environment).
Example:

	python main.py -ip 8.8.8.8

if you want script to check additional ports, add argument -p, example:

	python main.py -ip 8.8.8.8 -p port1,port2,port3

	
