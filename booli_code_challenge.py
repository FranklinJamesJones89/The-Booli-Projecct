#! python3



# A Python app that pulls the CVE Collection Endpoint for the published
# vulunerablities in the last 120 days then maps the CVE_items to the ECS
# fields and outputs the data to a list of JSON arrays on to the console.

# Import relevant libraries/modules
import requests, json, time
from datetime import date, timedelta, datetime


# Dynamically set date values to query API requests spanning 120 days from present
end_date = date.today()
days = timedelta(120)
start_date = end_date - days

# Convert datetime object to str
end_date_str = str(end_date)
start_date_str = str(start_date)


# Define API search parameters
start_index = 0
max_results_per_page = 2000
total_result = 7367

# Append CVE_Items to new lists
request_data = []
cve_items_list = []

# ESC Fields
esc_fields = ['vulnerability.id', 'vulnerability.reference', 'vulnerability.description', 'vulnerability.score.base', 'vulnerability.severity']

# Request URL
url = f'https://services.nvd.nist.gov/rest/json/cves/1.0/?pubStartDate={start_date_str}T00:00:00:000%20UTC-06:00&pubEndDate={end_date_str}T00:00:00:000%20UTC-06:00&resultsPerPage={max_results_per_page}'

# Mapped fields output
output = [esc_fields]

# Request pages
while start_index < total_result:
    new_url = f'{url}&startIndex={start_index}'
    res  = requests.get(new_url)
    start_index += max_results_per_page
    res_data = res.json()
    cve_items_list += res_data['result']['CVE_Items']
    request_data.append(cve_items_list)


# Create a list of nested lists to output mapped CVE Fields
for item in cve_items_list:
    values_arr = []
    values_arr.append(item['cve']['CVE_data_meta']['ID'])
    values_arr.append(item['cve']['description']['description_data'][0]['value'])
    values_arr.append(item['cve']['references']['reference_data'][0]['url'])
    try: values_arr.append(item['impact']['baseMetricV3']['cvssV3']['baseScore'])
    except: KeyError: values_arr.append(' ')
    try: values_arr.append(item['impact']['baseMetricV3']['cvssV3']['baseSeverity'])
    except: KeyError: values_arr.append(' ')
    output.append(values_arr)


for items in output:
    print(items)
