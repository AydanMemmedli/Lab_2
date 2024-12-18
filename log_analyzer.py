import re
import csv
import json

# 1. Access log faylının oxunması və URL-lərin çıxarılması
access_log_file = "access_log.txt"
threat_feed_file = "threat_feed.html"

# URL-lər və status kodları üçün siyahılar
url_status_list = []
url_404_counts = {}

# Regex: IP, tarix, URL və status kodu
log_pattern = re.compile(r'"\w+\s(http[s]?://[^\s]+)\sHTTP/\d\.\d"\s(\d{3})')

# 1a. Access log faylını oxumaq və URL-ləri çıxarmaq
with open(access_log_file, "r") as log_file:
    for line in log_file:
        match = log_pattern.search(line)
        if match:
            url, status_code = match.groups()
            url_status_list.append((url, status_code))
            # 404 status kodlarını saymaq
            if status_code == "404":
                if url in url_404_counts:
                    url_404_counts[url] += 1
                else:
                    url_404_counts[url] = 1

# 2. Bütün URL-ləri və status kodlarını saxla: url_status_report.txt
with open("url_status_report.txt", "w") as report_file:
    for url, status in url_status_list:
        report_file.write(f"{url} {status}\n")

# 3. 404 xətalarını CSV formatında yazmaq: malware_candidates.csv
with open("malware_candidates.csv", "w", newline="") as csv_file:
    writer = csv.writer(csv_file)
    writer.writerow(["URL", "404 Count"])
    for url, count in url_404_counts.items():
        writer.writerow([url, count])

# 4. Veb Scraping: Qara siyahıdakı domenləri çıxarmaq
blacklisted_domains = []

# Qara siyahıdakı domenləri HTML faylından çıxarırıq
with open(threat_feed_file, "r") as html_file:
    for line in html_file:
        domain_match = re.search(r'>([\w\.-]+\.com)<', line)
        if domain_match:
            blacklisted_domains.append(domain_match.group(1))

# 5. Qara siyahı ilə müqayisə və uyğun URL-ləri tapmaq
alert_urls = {}
for url, status in url_status_list:
    for domain in blacklisted_domains:
        if domain in url:
            if url in alert_urls:
                alert_urls[url]["count"] += 1
            else:
                alert_urls[url] = {"status": status, "count": 1}

# 6. Uyğun qara siyahıdakı URL-ləri JSON formatında saxla: alert.json
with open("alert.json", "w") as json_file:
    json.dump(alert_urls, json_file, indent=4)

# 7. Xülasə hesabatı yaratmaq: summary_report.json
summary = {
    "total_urls": len(url_status_list),
    "total_404_errors": len(url_404_counts),
    "blacklisted_matches": len(alert_urls)
}

with open("summary_report.json", "w") as summary_file:
    json.dump(summary, summary_file, indent=4)

print("Tapşırıq yerinə yetirildi! Fayllar yaradıldı:")
print(" - url_status_report.txt")
print(" - malware_candidates.csv")
print(" - alert.json")
print(" - summary_report.json")
