import socket
import ipinfo
import json
import requests
import os
import ipaddress
from dotenv import load_dotenv
from bs4 import BeautifulSoup
import dns.resolver
from portscan import PortScan
import logging
import argparse



def port_add_checker(port_range, ports_add):
    ports = port_range
    portsBefore = port_range.split(",")
    portsToAdd = ports_add.split(",")
    for i in range(len(portsToAdd)):
        if portsToAdd[i] not in portsBefore:
            ports += "," + portsToAdd[i]
    return ports


def port_scan(address, port_range, ports_add):
    ports = port_add_checker(port_range, ports_add)
    scanner = PortScan(address, ports, thread_num=500, show_refused=False, wait_time=1, stop_after_count=True)

    open_port_discovered = scanner.run() 

    openPorts = []
    for i in range(len(open_port_discovered)):
        openPorts.append(open_port_discovered[i][1]) 
    data = {
        "ports": openPorts
    }
    if len(openPorts) == 0: 
        logging.warning("Open ports not found")
    return data 


def get_dns_records(domain):
    
    records = {}
    try:
        records['A'] = [r.to_text() for r in dns.resolver.resolve(domain, 'A')]
    except Exception as e:
        logging.warning(f"records 'A' not found")
    try:
        records['MX'] = [r.to_text() for r in dns.resolver.resolve(domain, 'MX')]
    except Exception as e:
        logging.warning(f"records 'MX' not found: {e}")
    try:
        records['NS'] = [r.to_text() for r in dns.resolver.resolve(domain, 'NS')]
    except Exception as e:
        logging.warning(f"records 'NS' not found: {e}")
    try:
        records['TXT'] = [r.to_text() for r in dns.resolver.resolve(domain, 'TXT')]
    except Exception as e:
        logging.warning(f"records 'TXT' not found: {e}")

    return records

def abuseIPDB_func(address, key):
    url = 'https://api.abuseipdb.com/api/v2/check'

    querystring = {
        'ipAddress': f'{address}',
        'maxAgeInDays': '90'
    }
    

    headers = {
        'Accept': 'application/json',
        'Key': f'{key}'
    }
    
    response = requests.request(method='GET', url=url, headers=headers, params=querystring)

    try:
        decodedResponse = json.loads(response.text)
        data = decodedResponse.get('data')
        domain = data.get("domain")
        return data, domain
    except:
        logging.error("Can't load info from AbuseIPDB")
        return other_domain_search(address)

def json_dock_reader(address):
    url = f"https://{address}"

    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status() 

        soup = BeautifulSoup(response.text, "html.parser")

        data = {
            "url": url,
            "status_code": response.status_code,
            "title": soup.title.string if soup.title else "no title",
            "meta_description": "",
            "headers": dict(response.headers)
        }

        meta_desc = soup.find("meta", attrs={"name": "description"})
        if meta_desc:
            data["meta_description"] = meta_desc.get("content")
        return data
    except requests.exceptions.RequestException as e:
        logging.error(f"error while connecting to a site: {e}")


def ip_desc(ip,key):
    access_token = f"{key}"
    handler = ipinfo.getHandler(access_token)
    data = handler.getDetails(ip)
    return data.details

def other_domain_search(address):
    try:
        domain = socket.gethostbyaddr(address)
        domain = domain[0]
        return domain
    except:
        logging.error("domain search failed")
        return None

def json_create(dict, address):
    with open(f"ip/{address}.json", "w", encoding="utf-8") as json_file:
        json.dump(dict, json_file, ensure_ascii=False, indent=4)
        logging.info('json-file is successfully created')

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    load_dotenv()
    abuse_api_key = os.getenv("ABUSE_API_KEY")
    geo_api_key = os.getenv("GEO_API_KEY")
    port_range = os.getenv("PORT_RANGE")

    parser = argparse.ArgumentParser(description="type IP-address")
    parser.add_argument("-ip",  type=str, help="type IP-address in this format: X.X.X.X")
    parser.add_argument("-p", "--ports",  type=str, help="type additional ports like in example: 'port,port,port'")

    args = parser.parse_args()
    ip = f"{args.ip}"
    ports_add = f"{args.ports}"
    try:
        result = ipaddress.ip_address(ip)
        try:
            ports = port_scan(ip, port_range, ports_add)
        except:
            None
        try:
            records = get_dns_records(ip)
        except:
            None
        try:
            abuseIPDB, domain = abuseIPDB_func(ip, abuse_api_key)
        except:
            None
        try:
            geo = ip_desc(ip, geo_api_key)
        except:
            None
        try:
            jsonReader = json_dock_reader(domain)
        except:
            None

        dict = {"AbuseIPDB": abuseIPDB, "jsonReader": jsonReader, "ipGeoInfo": geo, "DNS records": records,
                "OpenPorts": ports}
        json_create(dict, ip)
    except:
        logging.error("Invalid IP-address, please type in this format: 'X.X.X.X'")