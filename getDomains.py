import requests
import pandas as pd
import os
from io import StringIO
import io
import tarfile
import zipfile
import gzip
from dotenv import load_dotenv
import os
import re
import psycopg2
import socket
from concurrent.futures import ThreadPoolExecutor
from threading import Lock
import gc

load_dotenv()

# color for printing warnings
WARNING_COLOR = "\033[93m"
# regex for domain detecion in text
DOMAIN_REGEX = r'\b(?:(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:[A-Z|a-z]{2,})\.?)\b'
# regex for IP detecion in text
IP_REGEX = r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b|\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b"

# file for storing functional blacklist sources (HTTP 200 status)
URL_FILE = "sources.txt"
# ips to ignore from host files
IGNORED_IPS = ["0.0.0.0", "localhost", "127.0.0.1", "255.255.255.255"]
WHITELIST = {"255.255.255.255", "localhost.localdomain"} # prevents the script from inserting nonsense, feel free to add more
# HTTP header for request
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"
}
MAX_WORKERS = 200

# list for working blacklist sources
working_urls = []

#lists for storing lines from csv, other files
CSV = []
TXT = []

domainsForLookup = set()
ipsForLookup = set()

"""
    check_url checks whether a connection to an url is available

    @param url: url to be checked
    @returns True if page is available, False otherwise
"""
def check_url(url):
    try:
        response = requests.get(url, timeout=5, headers=HEADERS)
        response.raise_for_status()
        return True
    except (
        requests.HTTPError,
        requests.ConnectionError,
        requests.Timeout,
        requests.exceptions.InvalidURL,
        requests.exceptions.InvalidSchema,
        requests.exceptions.MissingSchema,
    ):
        print(f"{WARNING_COLOR}[ERROR] could not connect to {url}")
        return False

"""
    download_csv downloads and extracts lines from a CSV file

    @param url: url of the file
    @returns lines of the file

"""
def download_csv(url):
    try:
        response = requests.get(url, headers=HEADERS)
        data = StringIO(response.text)
        df = pd.read_csv(data)
        return df
    except pd.errors.ParserError:
        print(f"{WARNING_COLOR}[ERROR] failed to parse csv from {url}")


"""
    download_txt downloads and extracts lines from a TXT file

    @param url: url of the file
    @returns lines of the file

"""
def download_txt(url):
    try:
        lines = []
        response = requests.get(url, headers=HEADERS)
        response.raise_for_status()

        content_type = response.headers.get("Content-Type")
        content_disposition = response.headers.get("Content-Disposition")
        if content_disposition and "filename=" in content_disposition:
            filename = content_disposition.split("filename=")[-1].strip('\"')
        else:
            filename = "my_file"
        
        if "text/html" in content_type or "text/plain" in content_type:
            stream = io.StringIO(response.text)
            for line in stream:
                lines.append(line.strip())
        else:
            if filename.endswith(".zip"):
                with zipfile.ZipFile(io.BytesIO(response.content)) as zip_ref:
                    for name in zip_ref.namelist():
                        with zip_ref.open(name) as f:
                            for line in io.TextIOWrapper(f):
                                lines.append(line.strip())

            elif filename.endswith("tar.gz"):
                with tarfile.open(fileobj=io.BytesIO(response.content), mode="r:gz") as tar_ref:
                    for member in tar_ref.getmembers():
                        if member.isfile():
                            f = tar_ref.extractfile(member)
                            if f:
                                for line in io.TextIOWrapper(f):
                                    lines.append(line.strip())
                
        lines = response.text.splitlines()
        return lines
    except (requests.HTTPError, requests.ConnectionError, requests.Timeout):
        print(f"{WARNING_COLOR}[ERROR] failed to parse text from {url}")

"""
    download_gz downloads and extracts lines from a .gz file

    @param url: url of the file
    @returns lines of the file

"""
def download_gz(url):
    response = requests.get(url, headers=HEADERS)
    gzfile = io.BytesIO(response.content)
    with gzip.GzipFile(fileobj=gzfile) as f:
        decompressed_bytes = f.read()
        tar = tarfile.open(fileobj=io.BytesIO(decompressed_bytes), mode="r:")
        files_lines = []
        for name in tar.getnames():
            file = tar.extractfile(name)
            if file is not None:
                lines = file.read().decode().splitlines()
                files_lines.extend(lines)  # extend instead of append
        return files_lines

"""
    download_csv downloads and extracts lines from a .zip file

    @param url: url of the file
    @returns lines of the file

"""
def download_zip(url):
    lines = []
    response = requests.get(url, headers=HEADERS)
    with zipfile.ZipFile(io.BytesIO(response.content)) as zip_ref:
        for name in zip_ref.namelist():
            with zip_ref.open(name) as f:
                for line in io.TextIOWrapper(f):
                    lines.append(line.strip())
    return lines


"""
   findInformationTxt searches for domains and ips in lines from the downloaded .txt and other files

    @param TXT lines from .txt and other non csv sources
    @param cur database cursor
    @param con database connection

"""
def findInformationTxt(lines, source):
    for line in lines:
        if not line.startswith("#") and not line.startswith(";") and not line.startswith("//"): 
            domain_matches = re.findall(DOMAIN_REGEX, line, re.IGNORECASE)
            ip_matches = re.findall(IP_REGEX, line)
            insertIntoDB(domain_matches, ip_matches, source)

"""
   findInformationCsv searches for domains and ips in lines from the downloaded .csv files

    @param CSV lines from csv sources
    @param cur database cursor
    @param con database connection

"""
def findInformationCsv(df, source):
        for _, row in df.iterrows():
            for col in df.columns:
                line = str(row[col])
                if not line.startswith("#") and not line.startswith(";") and not line.startswith("//"): 
                    domain_matches = re.findall(DOMAIN_REGEX, line, re.IGNORECASE)
                    ip_matches = re.findall(IP_REGEX, line)
                    insertIntoDB(domain_matches, ip_matches, source)

"""
    resolveIp tries to retrieve a domain from an ip address

    @param ip ip address 

"""
def getHostnameFromIp(ip):
    ipsDomains = {}
    try:
        retrieved_domains = socket.gethostbyaddr(ip)[0]
        ipsDomains[ip] = retrieved_domains
        if not retrieved_domains:
            ipsDomains[ip] = []
    except Exception as e:
        ipsDomains[ip] = []
    return ipsDomains

def updateIpsDomains():
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        results = list(pool.map(getHostnameFromIp, ipsForLookup))

    ipsDomains = {}
    for dic in results:
        ipsDomains.update(dic)

    for ip, domain in ipsDomains.items():
        print(f"[INFO] inserting resolved {ip} with domain {domain}")
        sql = "INSERT INTO domains_new VALUES(%s, %s, (SELECT source_id FROM domains_new WHERE domain=%s)) ON CONFLICT DO NOTHING"
        cur.execute(sql, (domain, [ip], domain))
        conn.commit()


"""
    resolveDomain tries to retrieve an ip from a domain

    @param domain domain 

"""
# TODO: once in a while insert it into database, this is not memory efficient
def getIpFromHostname(domain):
    domainIps = {}

    try:
       info = socket.getaddrinfo(domain, None)
       retrieved_ips = [item[4][0] for item in info]
       domainIps[domain] = retrieved_ips
    except Exception as e:
        domainIps[domain] = []

    return domainIps


def updateDomainsIps():
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        results = list(pool.map(getIpFromHostname, domainsForLookup))

    domainIps = {}
    for dic in results:
        domainIps.update(dic)

    for domain, ip in domainIps.items():
        print(f"[INFO] updating {domain} with {ip}")
        sql = ("UPDATE domains_new SET ip = %s WHERE domain = %s")
        cur.execute(sql, (ip, domain))
        conn.commit()

"""
    insertIntoDb inserts domains and ips without using DNS resolve to the database

    @param domain_matches domains matched on a line from source using a domain regex
    @param ip_matches ips matched on a line from source using an ip regex
    @param cur database cursor
    @param conn database connection

"""
#TODO: check if flow
def insertIntoDB(domain_matches, ip_matches, source):
    domain = domain_matches[0] if domain_matches else None
    ip = ip_matches[0] if ip_matches else None

    if ip in IGNORED_IPS:
        ip = None

    if domain is not None:
        if domain.startswith("www."):
            domain = domain[4:]

    if domain is not None and ip is not None:
        try:
            cur.execute(f"INSERT INTO domains_new VALUES ('{domain}', ARRAY['{ip}'], (SELECT source_id FROM sources_new WHERE source='{source}' LIMIT 1)) ON CONFLICT DO NOTHING")
            conn.commit()
        except Exception as e:
            print(f"{WARNING_COLOR}[Error] {e}")
    
    elif domain is not None and ip is None:
        domainsForLookup.add(domain)
        try:
            cur.execute(f"INSERT INTO domains_new VALUES ('{domain}', ARRAY['{ip}'], (SELECT source_id FROM sources_new WHERE source='{source}' LIMIT 1)) ON CONFLICT DO NOTHING")
            conn.commit()
        except Exception as e:
            print(f"{WARNING_COLOR}[Error] {e}")
    elif domain is None and ip is not None:
        ipsForLookup.add(ip)
        try:
            cur.execute(f"INSERT INTO ip_new VALUES (ARRAY['{ip}'], (SELECT source_id FROM sources_new WHERE source='{source}' LIMIT 1)) ON CONFLICT DO NOTHING")
            conn.commit()
        except Exception as e:
            print(f"{WARNING_COLOR}[Error] {e}")
"""
    load_google_sheet loads urls from provided google spreadsheet

    @param sheet_id id of the sheet 
    @param sheet_name name of the sheet

"""
def load_google_sheet(sheet_id = os.environ["SHEET_ID"], sheet_name = "Blacklists"):
    url = f"https://docs.google.com/spreadsheets/d/{sheet_id}/gviz/tq?tqx=out:csv&sheet={sheet_name}"
    print(url)
    df = pd.read_csv(url, encoding="utf-8")
    urls = df["link"]
    return urls

def yieldCurrentLines():
    for url in working_urls:
            _, ext = os.path.splitext(url)
            if ext == ".csv":
                print(f"[INFO] downloading csv from {url}")
                df = download_csv(url)
                if df is not None:
                    yield df, url, "CSV"
            elif ext == ".gz":
                print(f"[INFO] downloading .gz from {url}")
                lines = download_gz(url)
                if lines is not None:
                    yield lines, url, "TXT"
            elif ext == ".zip":
                print(f"[INFO] downloading .zip from {url}")
                lines = download_zip(url)
                if lines is not None:
                        yield lines, url, "TXT"
            else:
                print(f"[INFO] downloading from {url}")
                lines = download_txt(url)
                if lines is not None:
                        yield lines, url, "TXT"

def main():
    global cur
    global conn
    
    print("[INFO] loading google sheet")

    sheet_urls = load_google_sheet()
    
    print("[INFO] checking sources for availability")
    for url in sheet_urls:
        #TODO: 
        if url == "em_th":
            pass
        if url == "mal_doms":
            pass
        if check_url(url):
           working_urls.append(url)

    print(f"[INFO] writing available sources into the {URL_FILE}")
    with open(URL_FILE, "w") as f:
        for url in working_urls:
            f.write(f"{url}\n")

    print("[INFO] conneting to the database")
    conn = psycopg2.connect(
            host= os.environ["HOST"],
            user = os.environ["USER"],
            database = os.environ["DATABASE"],
            password = os.environ["PASSWORD"]
            )
    cur = conn.cursor()

    print("[INFO] accessing database tables")
    cur.execute("CREATE TABLE IF NOT EXISTS sources_new (source_id INT GENERATED ALWAYS AS IDENTITY, source VARCHAR(1024), PRIMARY KEY(source_id))")
    cur.execute("CREATE TABLE IF NOT EXISTS domains_new (domain VARCHAR(255) UNIQUE, ip VARCHAR(1024)[], source_id INT, CONSTRAINT fk_source FOREIGN KEY(source_id) REFERENCES sources_new(source_id))")
    cur.execute("CREATE TABLE IF NOT EXISTS ip_new (ip VARCHAR(1024) UNIQUE, source_id INT, CONSTRAINT fk_source FOREIGN KEY(source_id) REFERENCES sources_new(source_id))")
    conn.commit()

    for lines, source_url, source_type in yieldCurrentLines():
        cur.execute(f"INSERT INTO sources_new(source) VALUES('{source_url}') ON CONFLICT DO NOTHING")
        conn.commit()
        if source_type == "CSV":
            findInformationCsv(lines, source_url)
        elif source_type == "TXT":
            findInformationTxt(lines, source_url)

    updateDomainsIps()
    updateIpsDomains()

    cur.close()
    conn.close()

if __name__ == "__main__":
    main()
