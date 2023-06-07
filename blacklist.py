import urllib
import tarfile
import shutil
import io
import psycopg2
import re
import csv
import pickle
import os.path
import logging
import logging.config
import concurrent.futures
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from functools import reduce
import dns
from dns import resolver, reversename

import subprocess

def dump_database():
    command = "pg_dump blacklist"

    with open("/home/blacklist/export.sql", "w") as outfile:
        subprocess.run(command, stdout=outfile, check=True)


def GetDataFromTable(col, table):
    """
    Returns certain column from table in the blacklist DB.

    Paramaters:
        col(str): Identifies the column in table.
        table(str): Identifies what table to select from.

    Returns:
        set: All the records sql query fetches.
    """

    sql = "SELECT {0} FROM {1}".format(col,table)
    blcursor.execute(sql)
    _records = blcursor.fetchall()
    _records = [i[0] for i in _records]
    _records = set(_records)
    return _records


def GetSrc():
    """
    Returns the sourceid of certain blacklist source.

    Returns:
        int: Primary key of the source.
    """

    sql = "(SELECT sourceid FROM sources WHERE link = %s)"
    blcursor.execute(sql, (source,)) # source being the current row in the sheet
    src = blcursor.fetchone()
    src = src[0]
    return src


def InsertDataToTable(table, col, vals):
    """
    Simplifies the insert query and executes it.

    Parameters:
        table(str): Identifies the table to insert to.
        col(str): Identifies the column of the table.
        vals(): The value(s) to insert. Data type depends on the the DB.
    """

    sql = "INSERT INTO {0} ({1}) VALUES (%s)".format(table, col)
    blcursor.execute(sql, (vals,))
    bldb.commit()


def InsertDataFromSnake(query):
    """
    Inserts the data from tidbsnake DB to blacklist DB.

    Parameters:
        query(str): The query for snake to execute.
    """

    global ip, line

    sncursor.execute(query)
    snakeData = sncursor.fetchall()
    snakeData = [i[0] for i in snakeData]
    for line in snakeData:
        if len(line) != 0 and  \
                not line.startswith("#") and \
                not line.startswith(";") and \
                not line.startswith("//"):
            x = re.search(ipRegEx, line)
            if x:
                ip = x.group()
                if ip not in forbiddenIps:
                    InsertIPs()
                else:
                    InsertDoms()
            else:
                InsertDoms()


def InsertDoms():
    """
    Uses RegEx to find the domain on the current line and inserts it to the DB.
    """

    global newDoms, updatedDoms, domsForLookup

    x = re.search(domRegEx, line)
    if x:
        dom = x.group()
        if dom.startswith("www."):
            dom = dom[4:]

        if not dom in whitelist:
            # print(dom)

            sql = """
                WITH row AS (
                    INSERT INTO domains (domain, sourceid, first_occ)
                    VALUES (%s, %s, now())
                    ON CONFLICT (domain, sourceid)
                    DO UPDATE SET update_occ = now()
                    RETURNING ip, date_part('days',now() - first_occ)
                ) SELECT * from row;
                """

            blcursor.execute(sql, (dom, src))
            bldb.commit()
            returned = blcursor.fetchall()
            returnedIPs = returned[0][0]
            returnedDays = returned[0][1]
            
            if returnedDays % 30 == 0 or returnedIPs is None:
                domsForLookup.add(dom)

            if returnedIPs is None:
                newDoms += 1
            else:
                updatedDoms += 1


def InsertIPs():
    """
    Inserts found IP to blacklist DB.
    """

    global newIPs, updatedIPs, domsForLookup
    
    # print(ip)

    sql = """
            WITH row AS (
                INSERT INTO ips (ip, sourceid, first_occ)
                VALUES (%s, %s, now())
                ON CONFLICT (ip, sourceid)
                DO UPDATE SET update_occ = now()
                RETURNING domain, date_part('days',now() - first_occ)
            ) SELECT * from row;
        """
    blcursor.execute(sql, (ip, src))
    bldb.commit()
    returned = blcursor.fetchall()
    returnedDoms = returned[0][0]
    returnedDays = returned[0][1]

    if returnedDays % 30 == 0 or returnedDoms is None:
        IpsForLookup.add(ip)  

    if returnedDoms is None:
        newIPs += 1
    else:
        updatedIPs += 1


def GetDataFromSheet():
    """
    Uses the Google Sheets API to get the data from blacklist sheet.

    Returns:
        list: Values from the B column. Starts at B13.
    """
    # If modifying these scopes, delete the file token.pickle.
    SCOPES = ['https://www.googleapis.com/auth/spreadsheets.readonly']

    # The ID and range of a sample spreadsheet.
    SAMPLE_SPREADSHEET_ID = '1LN0lnHZqwmiXftJK47G1FXaHCZJ-opzSNMcBRc0GwQE'
    SAMPLE_RANGE_NAME = 'Blacklists!B13:B'

    # Shows basic usage of the Sheets API.
    # Prints values from a sample spreadsheet.

    creds = None
    # The file token.pickle stores the user's access and refresh tokens, and is
    # created automatically when the authorization flow completes for the first
    # time.
    if os.path.exists('token.pickle'):
        with open('token.pickle', 'rb') as token:
            creds = pickle.load(token)
    # If there are no (valid) credentials available, let the user log in.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                'credentials.json', SCOPES)
            creds = flow.run_local_server()
        # Save the credentials for the next run
        with open('token.pickle', 'wb') as token:
            pickle.dump(creds, token)

    service = build('sheets', 'v4', credentials=creds)

    # Call the Sheets API
    _sheet = service.spreadsheets()
    result = _sheet.values().get(spreadsheetId=SAMPLE_SPREADSHEET_ID,
                                range=SAMPLE_RANGE_NAME).execute()
    _sheet = result.get("values")

    if not _sheet:
        print("No data found in sheet")
        log.warning("No data found in sheet")
    else:
        _sheet = reduce(lambda x, y: x+y, _sheet)
        return _sheet


def GetHostnameFromIP(ip):
    """
    Nslookup
    
    Parameters:
        ip(str)
    
    Returns:
        dict: ip and founds hosts
    """
    doms = []
    ipsDomains = {}

    try:
        reverse_name = reversename.from_address(ip)
        answer = dnsResolver.query(reverse_name, "PTR")

        for item in answer:
            doms.append(item.to_text()[:-1])

        ipsDomains[ip] = doms
        return ipsDomains
    except dns.resolver.NXDOMAIN as e:
        print(str(e))
        ipsDomains[ip] = []
        return ipsDomains
    except resolver.NoNameservers as e:
        print(str(e))
        ipsDomains[ip] = []
        return ipsDomains
    except dns.exception.Timeout as e:
        print(str(e))
        ipsDomains[ip] = []
        return ipsDomains
    except resolver.NoAnswer as e:
        print(str(e))
        ipsDomains[ip] = []
        return ipsDomains


def GetIPFromHostname(hostname):

    ips = []
    domainsIps = {}

    try:
        answer = dnsResolver.query(hostname)

        for item in answer:
            if item not in forbiddenIps:
                ips.append(item.to_text())

        domainsIps[hostname] = ips
        return domainsIps
    except dns.exception.Timeout as e:
        print(str(e))
        domainsIps[hostname] = []
        return domainsIps
    except resolver.NXDOMAIN as e:
        print(str(e))
        domainsIps[hostname] = []
        return domainsIps
    except resolver.NoNameservers as e:
        print(str(e))
        domainsIps[hostname] = []
        return domainsIps
    except resolver.NoAnswer as e:
        print(str(e))
        domainsIps[hostname] = []
        return domainsIps


def UpdateDomainsIps():
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(GetIPFromHostname, domsForLookup))

    domainsIps = {}
    for dic in results:
        domainsIps.update(dic)
    print(domainsIps)

    for domain,ip in domainsIps.items():
        sql = "UPDATE domains SET ip = %s WHERE domain = %s"
        blcursor.execute(sql, (ip, domain))
        bldb.commit() 


def UpdateIpsDomains():
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(GetHostnameFromIP, IpsForLookup))
        print(results)

        ipsDomains = {}
        for dic in results:
            ipsDomains.update(dic) 
        print(ipsDomains)

        for ip,domain in ipsDomains.items():
            sql = "UPDATE ips SET domain = %s WHERE ip = %s"
            blcursor.execute(sql, (domain, ip))
            bldb.commit()
        
def GetDataFromCSV():
    links = []
    with open("bl.csv") as csvf:
        reader = csv.reader(csvf)
        print(reader)
        for row in reader:
            links.append(row[1])
        links = links[12:]
        links = [x for x in links if x!='']
        return links



# log setup
log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)
formatter = logging.Formatter(fmt="%(asctime)s %(levelname)s: %(message)s", datefmt="%Y-%m-%d - %H:%M:%S")
fh = logging.FileHandler("bl.log")
fh.setLevel(logging.DEBUG)
fh.setFormatter(formatter)
log.addHandler(fh)

log.info("Starting script")


try:
    # blacklist BD connection
    bldb = psycopg2.connect(
        host="localhost",
        user="postgres",
        database="blacklist",
        password="postgres"
	# was Bl4ckl1stDB123
    )
    blcursor = bldb.cursor()

    # tidbsnake DB connection
    snakedb = psycopg2.connect(
        host="update2",
        user="ti_readonly",
        database="tidbsnakev2",
        password="reAdOnLy123ti"
    )
    sncursor = snakedb.cursor()
except Exception as e:
    print(str(e))
    log.error(str(e))

dnsResolver = resolver.Resolver()
# GCX: "172.28.32.2", "8.8.4.4" ... NIC.cz> 193.17.47.1 a 185.43.135.1
dnsResolver.nameservers = ["185.43.135.1", "193.17.47.1"]
dnsResolver.timeout = 90
dnsResolver.lifetime = 90
IpsForLookup = set() # when the script has collected all ips it does the nslookup from this set
domsForLookup = set() # when the script has collected all domains it does the nslookup from this set
workers = 2000 # max workers for asynchronous nslookup

nonvalidTypes = {"csv"}  # file types the script doesn't support
validTxtTypes = {"plain", "octet-stream", "html"} # valid text types the script supports
validArchTypes = {"x-gzip"}  # valid archive types the script supports

whitelist = {"255.255.255.255", "localhost.localdomain"} # prevents the script from inserting nonsense, feel free to add more
forbiddenIps = {"0.0.0.0", "127.0.0.1", "255.255.255.255"} # nonsense IPs, feel free to add more

newDoms = 0 # var for script to log at the end
newIPs = 0 # var for script to log at the end
updatedDoms = 0 # var for script to log at the ends
updatedIPs = 0 # var for script to log at the end

domRegEx = r"(?:[a-z0-9](?:[a-z0-9-_]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-_]{0,61}[a-z0-9]"
ipRegEx = r"^((?:(?:(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):){6})(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):(?:(?:[0-9a-fA-F]{1,4})))|(?:(?:(?:(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9]))\.){3}(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9])))))))|(?:(?:::(?:(?:(?:[0-9a-fA-F]{1,4})):){5})(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):(?:(?:[0-9a-fA-F]{1,4})))|(?:(?:(?:(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9]))\.){3}(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9])))))))|(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})))?::(?:(?:(?:[0-9a-fA-F]{1,4})):){4})(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):(?:(?:[0-9a-fA-F]{1,4})))|(?:(?:(?:(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9]))\.){3}(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9])))))))|(?:(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):){0,1}(?:(?:[0-9a-fA-F]{1,4})))?::(?:(?:(?:[0-9a-fA-F]{1,4})):){3})(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):(?:(?:[0-9a-fA-F]{1,4})))|(?:(?:(?:(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9]))\.){3}(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9])))))))|(?:(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):){0,2}(?:(?:[0-9a-fA-F]{1,4})))?::(?:(?:(?:[0-9a-fA-F]{1,4})):){2})(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):(?:(?:[0-9a-fA-F]{1,4})))|(?:(?:(?:(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9]))\.){3}(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9])))))))|(?:(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):){0,3}(?:(?:[0-9a-fA-F]{1,4})))?::(?:(?:[0-9a-fA-F]{1,4})):)(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):(?:(?:[0-9a-fA-F]{1,4})))|(?:(?:(?:(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9]))\.){3}(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9])))))))|(?:(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):){0,4}(?:(?:[0-9a-fA-F]{1,4})))?::)(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):(?:(?:[0-9a-fA-F]{1,4})))|(?:(?:(?:(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9]))\.){3}(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9])))))))|(?:(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):){0,5}(?:(?:[0-9a-fA-F]{1,4})))?::)(?:(?:[0-9a-fA-F]{1,4})))|(?:(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):){0,6}(?:(?:[0-9a-fA-F]{1,4})))?::)))))|((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"

sources = GetDataFromTable("link", "sources") # sources that currently are in the blacklist BD
#sheet = GetDataFromSheet()
sheet = GetDataFromCSV()
sourcesList = []

for source in sheet:
    sourcesList.append(source)
    if not source in sources:
        InsertDataToTable("sources", "link", source)


with open("sourcesFile.txt", "w") as f:
    for source in sourcesList:
        f.write(f"{source}\n")


# Iterration through all the rows in the sheet
for source in sheet:
    # Clause for urls
    if source.startswith("http"):
        try:
            retrieved = urllib.request.urlretrieve(source, filename=None)
        except urllib.error.HTTPError as e:
            print(str(e) + " " + source)
            log.error(str(e) + " " + source)
            continue
        except urllib.error.URLError as e:
            print(str(e) + " " + source)
            log.error(str(e) + " " + source)
            continue
        # retrieved file
        file_tmp = retrieved[0]

        # file type of retrieved file
        file_info = retrieved[1]
        ctype = file_info.get_content_subtype()
        if ctype in nonvalidTypes:
            continue
        print("Reading " + source + " " + ctype)
        src = GetSrc()

        # Clause for txt files
        if ctype in validTxtTypes:
            with io.open(file_tmp, "r", encoding="utf-8") as f:
                for line in f:
                    # All kinds of comments are being used in the sources, they could contain non-malicious domains
                    if len(line) != 0 and  \
                            not line.startswith("#") and \
                            not line.startswith(";") and \
                            not line.startswith("//"):
                        x = re.search(ipRegEx, line)
                        if x:
                            ip = x.group()
                            if ip not in forbiddenIps:
                                InsertIPs()
                            # if there is a nonsense ip the script still needs to ask if 
                            # there is a domain because some of the sources look like this: 0.0.0.0 adservice.google.com.vn
                            else:
                                InsertDoms()
                        else:
                            InsertDoms()
            os.remove(file_tmp)

        # Clause for archives
        if ctype in validArchTypes:

            # Extract archive
            base_name = os.path.basename(source)
            file_name, file_extension = os.path.splitext(base_name)
            tar = tarfile.open(file_tmp)
            tar.extractall(file_name)

            # Iterration through the extracted archive
            for subdir, dirs, files in os.walk(file_name, topdown="true"):
                for file in files:
                    if file == "domains":
                        path = subdir + os.sep + file
                        with io.open(path, "r", encoding="utf-8") as f:
                            for line in f:
                                if len(line) != 0 and  \
                                        not line.startswith("#") and \
                                        not line.startswith(";") and \
                                        not line.startswith("//"):
                                    x = re.search(ipRegEx, line)
                                    if x:
                                        ip = x.group()
                                        if ip not in forbiddenIps and not ip.startswith("0.0.0.0"):
                                            InsertIPs()
                                        else:
                                            InsertDoms()
                                    else:
                                        InsertDoms()
            shutil.rmtree(file_name)

    # Clause for tidbsnake
    else:
        src = GetSrc()

        if source == "em_th":
            sql = "SELECT ip_addr FROM ti.reputations WHERE abbrev ilike '_f%'"

        elif source == "mal_doms":
            sql = "SELECT domain from esetti.domains"

        InsertDataFromSnake(sql)

    UpdateDomainsIps()

# Do the nslookup for ips/domains 
# Do the nslookup only if It's the 30th day from the first occurence of the dom/ip OR if It's firstly found
UpdateDomainsIps()
UpdateIpsDomains()

dump_database()

# log some statistics

print("{0} new domains ".format(newDoms))
log.info("%s new domains ", newDoms)

print("{0} domains updated ".format(updatedDoms))
log.info("%s domains updated ", updatedDoms)

print("{0} new IPs ".format(newIPs))
log.info("%s new IPs ", newIPs)

print("{0} IPs updated".format(updatedIPs))
log.info("%s IPs updated ", updatedIPs)
