import requests

def get_cve_details(cve_id):
    url = f"https://services.nvd.nist.gov/rest/json/cve/1.0/{cve_id}"
    
    try:
        response = requests.get(url)
        response.raise_for_status()  
        
        cve_data = response.json()

        cve_item = cve_data.get('result', {}).get('CVE_Items', [])[0]
        cve_description = cve_item.get('cve', {}).get('description', {}).get('description_data', [])[0].get('value', 'No description available')
        published_date = cve_item.get('publishedDate', 'No published date available')
        last_modified_date = cve_item.get('lastModifiedDate', 'No last modified date available')

        impact = cve_item.get('impact', {})
        cvss_v3 = impact.get('baseMetricV3', {}).get('cvssV3', {})
        base_score_v3 = cvss_v3.get('baseScore', 'Not available')
        base_severity_v3 = cvss_v3.get('baseSeverity', 'Not available')

        # Affected products and versions (CPEs)
        configurations = cve_item.get('configurations', {})
        cpe_nodes = configurations.get('nodes', [])
        affected_products = []
        for node in cpe_nodes:
            cpe_match = node.get('cpe_match', [])
            for cpe in cpe_match:
                affected_products.append(cpe.get('cpe23Uri', 'No affected product/version data available'))
        
        print(f"CVE ID: {cve_id}")
        print(f"Description: {cve_description}")
        print(f"Published Date: {published_date}")
        print(f"Last Modified Date: {last_modified_date}")
        print(f"CVSS V3 Base Score: {base_score_v3}")
        print(f"CVSS V3 Base Severity: {base_severity_v3}")
        print("Affected Products and Versions:")
        for product in affected_products:
            print(f"- {product}")
    
    except requests.exceptions.HTTPError as http_err:
        print(f"HTTP error occurred: {http_err}") 
    except Exception as err:
        print(f"An error occurred: {err}")

get_cve_details('CVE-2016-5195')
