import requests
import time
import re
import logging
from typing import Tuple, Optional

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def load_payloads(risk: int) -> list:
    """
    Load payloads based on the risk level.
    """
    payload_file = f"payloads{risk}.txt"
    payloads = []
    try:
        with open(payload_file, "r") as f:
            for line in f:
                payloads.append(line.strip())
    except FileNotFoundError:
        logging.warning(f"Payload file '{payload_file}' not found. Using empty payload list.")
    return payloads

def perform_request(url: str, cookie: Optional[str]) -> Tuple[bool, str, float, str]:
    """
    Perform an HTTP request with the given cookie.
    Returns a tuple containing:
        - success: a boolean indicating whether the request was successful
        - url: the URL
        - response_time: the time it took for the request to complete
        - error_message: an error message if the request failed
    """
    start_time = time.time()

    headers = {}
    if cookie:
        headers["Cookie"] = cookie

    try:
        response = requests.get(url, headers=headers)
    except requests.RequestException as e:
        return False, url, 0, str(e)

    response_time = time.time() - start_time
    if 200 <= response.status_code < 300:
        return True, url, response_time, ""
    return False, url, response_time, f"HTTP status code: {response.status_code}"

def analyze_response_content(response: requests.Response) -> bool:
    """
    Analyze the response content to detect potential SQL injection vulnerabilities.
    Returns a boolean indicating whether a vulnerability was detected.
    """
    # Check for common SQL error messages
    if re.search(r"SQL syntax error|Error executing query", response.text):
        return True

    # Check for differences in response content between successful and failed queries
    if re.search(r"SELECT|INSERT|UPDATE|DELETE", response.text):
        return True

    return False

def process_payloads(url: str, cookie: Optional[str], output_file: Optional[str], dbms: str, level: int, risk: int) -> None:
    """
    Process the payloads and detect potential SQL injection vulnerabilities.
    """
    payloads = load_payloads(risk)

    if not payloads:
        logging.warning("No payloads loaded. Exiting.")
        return

    for payload in payloads:
        url_with_payload = url.replace("*", payload)
        success, url_with_payload, response_time, error_message = perform_request(url_with_payload, cookie)

        # Analyze the response content for potential vulnerabilities
        if analyze_response_content(error_message):
            result_line = f"✓ SQLi Found! URL: {url_with_payload} - Response Time: {response_time:.2f} seconds"
            logging.info(result_line)
            print(f"\033[92m{result_line}\033[0m")
        else:
            result_line = f"✗ Not Vulnerable. URL: {url_with_payload} - Response Time: {response_time:.2f} seconds"
            logging.info(result_line)
            print(f"\033[91m{result_line}\033[0m")

        if output_file:
            try:
                with open(output_file, "a") as f:
                    f.write(result_line + "\n")
            except IOError as e:
                logging.error(f"Error writing to output file: {e}")

        if success and level >= 2:
            db_name = get_db_name(url_with_payload, cookie, dbms)
            if db_name:
                logging.info(f"Database name: {db_name}")
                if level >= 3:
                    tables = get_tables(url_with_payload, cookie, dbms, db_name)
                    if tables:
                        logging.info(f"Tables: {', '.join(tables)}")
                        if level >= 4:
                            columns = get_columns(url_with_payload, cookie, dbms, db_name, tables[0])
                            if columns:
                                logging.info(f"Columns: {', '.join(columns)}")
                                if level >= 5:
                                    dump_data(url_with_payload, cookie, dbms, db_name, tables[0], columns[0])

def main():
    parser = argparse.ArgumentParser()
    parser.add_argumentHere's the continuation:

```python
    parser.add_argument("url", help="The URL to test for SQL injection")
    parser.add_argument("-c", "--cookie", help="The cookie to use for the request")
    parser.add_argument("-o", "--output", help="The file to output the results to")
    parser.add_argument("-d", "--dbms", help="The database management system to use")
    parser.add_argument("-l", "--level", type=int, help="The level of testing to perform")
    parser.add_argument("-r", "--risk", type=int, default=1, help="The risk level of the testing (default: 1)")
    args = parser.parse_args()

    process_payloads(args.url, args.cookie, args.output, args.dbms, args.level, args.risk)

if __name__ == "__main__":
    main()
