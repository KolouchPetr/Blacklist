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

load_dotenv()

WARNING_COLOR = "\033[93m"
DOMAIN_REGEX = r'\b(?:(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:[A-Z|a-z]{2,})\.?)\b'
IP_REGEX = r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b|\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b"

URL_FILE = "sources.txt"


working_urls = []
CSV = []
TXT = []
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"
}


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


def download_csv(url):
    try:
        response = requests.get(url, headers=HEADERS)
        data = StringIO(response.text)
        df = pd.read_csv(data)
        return df
    except pd.errors.ParserError:
        print(f"{WARNING_COLOR}[ERROR] failed to parse csv from {url}")


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

def download_zip(url):
    lines = []
    response = requests.get(url, headers=HEADERS)
    with zipfile.ZipFile(io.BytesIO(response.content)) as zip_ref:
        for name in zip_ref.namelist():
            with zip_ref.open(name) as f:
                for line in io.TextIOWrapper(f):
                    lines.append(line.strip())
    return lines


def insertTXT(TXT, cur, conn):
    try:
        for line in TXT:
            domain_matches = re.findall(DOMAIN_REGEX, line, re.IGNORECASE)
            # ip_matches = re.findall(IP_REGEX, line)

            domain = domain_matches[0] if domain_matches else None
            # ip = ip_matches[0] if ip_matches else None

            if domain is None:
                continue

            domain = re.sub(r"www\.", "", domain)

            cur.execute(f"INSERT INTO domain_ip_pairs VALUES ('{domain}') ON CONFLICT DO NOTHING")
            conn.commit()
    except Exception as e:
        print(f"{WARNING_COLOR}[ERROR] error inserting domain {domain}")
        print(f"{WARNING_COLOR}[Error] in insertTXT: {e}")


def insertCSV(CSV, cur, conn):
    try:
        for df in CSV:
            for _, row in df.iterrows():
                for col in df.columns:
                    line = str(row[col])
                    domain_matches = re.findall(DOMAIN_REGEX, line, re.IGNORECASE)
                    # ip_matches = re.findall(IP_REGEX, line)

                    domain = domain_matches[0] if domain_matches else None
                    # ip = ip_matches[0] if ip_matches else None

                    if domain is None:
                        continue

                    domain = re.sub(r"www\.", "", domain)
                
                    cur.execute(f"INSERT INTO domain_ip_pairs VALUES ('{domain}') ON CONFLICT DO NOTHING")
                    conn.commit()
    except Exception as e:
        print(f"{WARNING_COLOR}[ERROR] error inserting domain {domain}")
        print(f"{WARNING_COLOR}[ERROR] in insertCSV :{e}")


def load_google_sheet(sheet_id = os.environ["SHEET_ID"], sheet_name = "Blacklists"):
    url = f"https://docs.google.com/spreadsheets/d/{sheet_id}/gviz/tq?tqx=out:csv&sheet={sheet_name}"
    df = pd.read_csv(url, encoding="utf-8")
    urls = df["link"]
    return urls
def main():

    load_google_sheet()

    sheet_urls = load_google_sheet()
    for url in sheet_urls:
        if check_url(url):
           working_urls.append(url)

    with open(URL_FILE, "w") as f:
        for url in working_urls:
            f.write(f"{url}\n")

    for url in working_urls:
        _, ext = os.path.splitext(url)
        if ext == ".csv":
            print(f"[INFO] downloading csv from {url}")
            df = download_csv(url)
            if df is not None:
                CSV.append(df)
        elif ext == ".gz":
            print(f"[INFO] downloading .gz from {url}")
            lines = download_gz(url)
            if lines is not None:
                for line in lines:
                    TXT.append(line)
        elif ext == ".zip":
            print(f"[INFO] downloading .zip from {url}")
            lines = download_zip(url)
            if lines is not None:
                for line in lines:
                    TXT.append(line)
        else:
            print(f"[INFO] downloading from {url}")
            lines = download_txt(url)
            if lines is not None:
                for line in lines:
                    TXT.append(line)

    try:
        conn = psycopg2.connect(
                host= os.environ["HOST"],
                user = os.environ["USER"],
                database = os.environ["DATABASE"],
                password = os.environ["PASSWORD"]
                )
        cur = conn.cursor()

        cur.execute("CREATE TABLE IF NOT EXISTS domain_ip_pairs (domain VARCHAR(255) UNIQUE)")
        conn.commit()

        insertTXT(TXT, cur, conn)
        insertCSV(CSV, cur, conn)
    except Exception as e:
        print(f"{WARNING_COLOR}[ERROR] an error occured while connecting to the database: {e}")
        exit(1)

    cur.close()
    conn.close()

if __name__ == "__main__":
    main()
