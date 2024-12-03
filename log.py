import re
import csv
from collections import Counter

LOG_FILE = "sample.log"
THRESHOLD = 10
CSV_FILE = "log_analysis_results.csv"

def parse_log(file_path):
    with open(file_path, "r") as file:
        return file.readlines()

def count_requests(logs):
    ip_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    ip_addresses = [re.match(ip_pattern, log).group() for log in logs if re.match(ip_pattern, log)]
    return Counter(ip_addresses)

def most_accessed_endpoint(logs):
    endpoint_pattern = r'"[A-Z]+\s(/[\w/]+)'
    endpoints = [re.search(endpoint_pattern, log).group(1) for log in logs if re.search(endpoint_pattern, log)]
    endpoint_counts = Counter(endpoints)
    return endpoint_counts.most_common(1)[0]

def detect_suspicious_activity(logs):
    failed_login_pattern = r"401"
    ip_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    failed_ips = [re.match(ip_pattern, log).group() for log in logs if re.search(failed_login_pattern, log) and re.match(ip_pattern, log)]
    failed_counts = Counter(failed_ips)
    return {ip: count for ip, count in failed_counts.items() if count > THRESHOLD}

def save_to_csv(ip_counts, top_endpoint, suspicious_ips):
    with open(CSV_FILE, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_counts.items():
            writer.writerow([ip, count])
        writer.writerow([])
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerow([top_endpoint[0], top_endpoint[1]])
        writer.writerow([])
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in suspicious_ips.items():
            writer.writerow([ip, count])

def main():
    logs = parse_log(LOG_FILE)
    ip_counts = count_requests(logs)
    top_endpoint = most_accessed_endpoint(logs)
    suspicious_ips = detect_suspicious_activity(logs)
    print("Requests per IP:")
    for ip, count in ip_counts.items():
        print(f"{ip}: {count}")
    print("\nMost Frequently Accessed Endpoint:")
    print(f"{top_endpoint[0]} (Accessed {top_endpoint[1]} times)")
    print("\nSuspicious Activity Detected:")
    for ip, count in suspicious_ips.items():
        print(f"{ip}: {count}")
    save_to_csv(ip_counts, top_endpoint, suspicious_ips)

if __name__ == "__main__":
    main()
