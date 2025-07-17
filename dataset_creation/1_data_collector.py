#!/usr/bin/env python3

import os
import json
import logging
import requests
import xml.etree.ElementTree as ET
from bs4 import BeautifulSoup
from datetime import datetime, timedelta
from typing import Dict, List, Union, Optional
from pathlib import Path
import feedparser
import pandas as pd
import yaml
import time
import shutil
import argparse
from github import Github

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class CyberDataCollector:
    def __init__(self, output_dir: str = "raw_data"):
        """Initialize the data collector with output directory configuration.
        
        Required API Keys (set as environment variables):
        - VIRUSTOTAL_API_KEY: Required for VirusTotal API access
        - ALIENVAULT_API_KEY: Required for AlienVault OTX API
        - HTB_API_KEY: Required for HackTheBox API
        
        Rate Limits:
        - CTFtime API: 30 requests per minute
        - NVD API: 5 requests per 30 seconds
        - VirusTotal API: Depends on subscription tier
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize API clients
        self.github_client = Github(os.getenv('GITHUB_TOKEN'))
        self.opencve_auth = (os.getenv('OPENCVE_EMAIL'), os.getenv('OPENCVE_PASSWORD'))
        self.nvd_api_key = os.getenv('NVD_API_KEY')
        
        # Load API keys from environment variables
        self.api_keys = {
            'virustotal': os.getenv('VIRUSTOTAL_API_KEY'),
            'alienvault': os.getenv('ALIENVAULT_API_KEY'),
            'hackthebox': os.getenv('HTB_API_KEY'),
            'malpedia': os.getenv('MALPEDIA_API_KEY'),
            'malshare': os.getenv('MALSHARE_API_KEY'),
            'shodan': os.getenv('SHODAN_API_KEY'),
            'phishtank': os.getenv('PHISHTANK_API_KEY'),
        }
        
        # Initialize rate limiting
        self.rate_limits = {
            'nvd_cve': {'requests': 5, 'period': 30},
            'ctftime': {'requests': 30, 'period': 60},
            'github': {'requests': 60, 'period': 3600},  # GitHub API limit
            'virustotal': {'requests': 4, 'period': 60},
            'shodan': {'requests': 1, 'period': 1},
            'malshare': {'requests': 25, 'period': 60},
        }
        self.last_request_time = {}
        
        # Add request timeout settings
        self.timeouts = {
            'default': 30,
            'download': 180,  # Longer timeout for downloading larger files
            'scraping': 60,   # Longer timeout for web scraping
        }
        
        # Add retry configurations
        self.retry_config = {
            'max_retries': 3,
            'base_delay': 5,
            'max_delay': 60,
            'exponential_backoff': True,
        }
        
        # API endpoints and configurations
        self.endpoints = {
            # NIST and CVE Sources
            'nvd_cve': 'https://services.nvd.nist.gov/rest/json/cves/2.0',
            # 'opencve': 'https://app.opencve.io/api/cve',
            # 'nist_standards': 'https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.json',
            'mitre_attack': 'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json',
            'mitre_capec': 'https://capec.mitre.org/data/xml/views/3000.xml',
            
            # Threat Intelligence Feeds
            # 'alienvault_otx': 'https://otx.alienvault.com/api/v1/pulses/subscribed',
            # 'threatfox_api': 'https://threatfox-api.abuse.ch/api/v1/',
            
            # Security Advisories
            'microsoft_security': 'https://api.msrc.microsoft.com/cvrf/v2.0/updates',
            'ubuntu_usn': 'https://ubuntu.com/security/notices/rss.xml',
            #'redhat_security': 'https://access.redhat.com/labs/securitydataapi/cve.json',
            
            # Research and Reports
            'arxiv_cs_crypto': 'http://export.arxiv.org/api/query?search_query=cat:cs.CR&max_results=100',
            #'exploit_db': 'https://www.exploit-db.com/download/',
            
            # Malware Information
            #'malware_bazaar': 'https://bazaar.abuse.ch/api/v1/',
            #'virustotal': 'https://www.virustotal.com/vtapi/v2/',
            #'malpedia': 'https://malpedia.caad.fkie.fraunhofer.de/api/v1/',
            #'malshare': 'https://malshare.com/api.php',
            #'thezoo': 'https://github.com/ytisf/theZoo/raw/master/malware.yml',
            #'vxug': 'https://vx-underground.org/samples.html',
            
            # CTF Resources
            'ctftime': 'https://ctftime.org/api/v1/events/',
            #'root_me': 'https://api.www.root-me.org/challenges',
            #'hackthebox': 'https://www.hackthebox.com/api/v4/challenge/list',
            
            # Security Testing Resources
            #'metasploit_modules': 'https://raw.githubusercontent.com/rapid7/metasploit-framework/master/modules/',
            #'pentesterlab': 'https://pentesterlab.com/exercises/api/v1/',
            #'vulnhub': 'https://www.vulnhub.com/api/v1/entries/',
           # 'offensive_security': 'https://offsec.tools/api/tools',
            #'securitytube': 'https://www.securitytube.net/api/v1/videos',
            'pentestmonkey': 'https://github.com/pentestmonkey/php-reverse-shell/raw/master/php-reverse-shell.php',
            'payloadsallthethings': 'https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/',
            
            # Social Engineering Resources
            #'phishtank': 'https://phishtank.org/phish_search.php?valid=y&active=all&Search=Search',
            #'openphish': 'https://openphish.com/feed.txt',
            #'social_engineer_toolkit': 'https://github.com/trustedsec/social-engineer-toolkit/raw/master/src/templates/',
            #'gophish': 'https://github.com/gophish/gophish/raw/master/templates/',
            
            # DoS/DDoS Resources
            #'ddosdb': 'https://ddosdb.org/api/v1/',
            #'netscout_atlas': 'https://atlas.netscout.com/api/v2/',
            
            # MITM & Injection Resources
            #'bettercap': 'https://raw.githubusercontent.com/bettercap/bettercap/master/modules/',
            #'sqlmap': 'https://raw.githubusercontent.com/sqlmapproject/sqlmap/master/data/',
            #'nosqlmap': 'https://raw.githubusercontent.com/codingo/NoSQLMap/master/attacks/',
            
            # Zero-Day & Password Resources
            'zerodayinitiative': 'https://www.zerodayinitiative.com/rss/published/',
            'project_zero': 'https://bugs.chromium.org/p/project-zero/issues/list?rss=true',
            'rockyou': 'https://github.com/danielmiessler/SecLists/raw/master/Passwords/Leaked-Databases/',
            'hashcat': 'https://hashcat.net/hashcat/',
            
            # IoT Security Resources
            #'iot_vulndb': 'https://www.exploit-db.com/download/iot/',
            #'iot_sentinel': 'https://iotsentinel.csec.ch/api/v1/',
            #'shodan_iot': 'https://api.shodan.io/shodan/host/search?key={}&query=iot',
        }
        
        # Initialize session for better performance
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'CyberLLMInstruct-DataCollector/1.0'
        })

    def _check_rate_limit(self, endpoint: str) -> None:
        """
        Implement rate limiting for APIs.
        Sleeps if necessary to respect rate limits.
        """
        if endpoint not in self.rate_limits:
            return
            
        current_time = time.time()
        if endpoint in self.last_request_time:
            elapsed = current_time - self.last_request_time[endpoint]
            limit = self.rate_limits[endpoint]
            if elapsed < (limit['period'] / limit['requests']):
                sleep_time = (limit['period'] / limit['requests']) - elapsed
                logger.debug(f"Rate limiting {endpoint}, sleeping for {sleep_time:.2f}s")
                time.sleep(sleep_time)
                
        self.last_request_time[endpoint] = current_time

    def _make_request(self, endpoint: str, url: str, params: Dict = None, headers: Dict = None, 
                     timeout: int = None, method: str = 'get', data: Dict = None, auth = None) -> Optional[requests.Response]:
        """
        Enhanced request method with better error handling and retries.
        """
        self._check_rate_limit(endpoint)
        
        if headers is None:
            headers = {}
        
        # Set auth for OpenCVE
        if endpoint == 'opencve' and not auth:
            auth = self.opencve_auth
            
        # Add API keys to headers based on endpoint
        for key, value in self.api_keys.items():
            if endpoint.startswith(key) and value:
                if key == 'virustotal':
                    headers['x-apikey'] = value
                elif key == 'alienvault':
                    headers['X-OTX-API-KEY'] = value
                # ... add other API key headers as needed
        
        timeout = timeout or self.timeouts['default']
        retry_count = 0
        last_error = None
        
        while retry_count < self.retry_config['max_retries']:
            try:
                if method.lower() == 'get':
                    response = self.session.get(url, params=params, headers=headers, timeout=timeout, auth=auth)
                elif method.lower() == 'post':
                    # Check if we need to send form data or JSON data
                    content_type = headers.get('Content-Type', '')
                    if 'application/x-www-form-urlencoded' in content_type:
                        response = self.session.post(url, params=params, headers=headers, data=data, timeout=timeout, auth=auth)
                    else:
                        response = self.session.post(url, params=params, headers=headers, json=data, timeout=timeout, auth=auth)
                
                response.raise_for_status()
                return response
                
            except requests.exceptions.RequestException as e:
                last_error = e
                retry_count += 1
                
                if retry_count == self.retry_config['max_retries']:
                    break
                    
                # Calculate delay with exponential backoff
                if self.retry_config['exponential_backoff']:
                    delay = min(
                        self.retry_config['base_delay'] * (2 ** (retry_count - 1)),
                        self.retry_config['max_delay']
                    )
                else:
                    delay = self.retry_config['base_delay']
                    
                logger.warning(f"Request failed (attempt {retry_count}/{self.retry_config['max_retries']}): {str(e)}")
                logger.info(f"Retrying in {delay} seconds...")
                time.sleep(delay)
        
        logger.error(f"All retry attempts failed for {url}: {str(last_error)}")
        return None

    def fetch_cve_data(self, start_index: int = 0, results_per_page: int = 2000) -> Optional[Dict]:
        """
        Fetch CVE data from NVD database.
        
        Note: Implements rate limiting of 5 requests per 30 seconds
        """
        try:
            params = {
                'startIndex': start_index,
                'resultsPerPage': results_per_page
            }
            response = self._make_request('nvd_cve', self.endpoints['nvd_cve'], params=params)
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching CVE data: {str(e)}")
            return None

    def fetch_opencve_data(self, limit: int = 100) -> Optional[Dict]:
        """
        Fetch CVE data from the OpenCVE API.
        
        Args:
            limit: Maximum number of CVEs to fetch
            
        Returns:
            Dictionary containing CVE data or None if failed
        
        Note: Uses basic authentication with the provided OpenCVE credentials.
        """
        try:
            all_cves = []
            page = 1
            
            # Fetch pages until we reach the limit or there are no more pages
            while len(all_cves) < limit:
                params = {
                    'page': page
                }
                response = self._make_request('opencve', self.endpoints['opencve'], params=params)
                
                if not response:
                    break
                    
                data = response.json()
                results = data.get('results', [])
                
                if not results:
                    break
                    
                all_cves.extend(results)
                
                # Check if there's a next page
                if not data.get('next'):
                    break
                    
                page += 1
                
                # Limit the number of CVEs
                if len(all_cves) >= limit:
                    all_cves = all_cves[:limit]
                    break
            
            # Get detailed information for each CVE
            detailed_cves = []
            for cve in all_cves[:10]:  # Limit detailed lookups to avoid rate limiting
                cve_id = cve.get('cve_id')
                if cve_id:
                    detailed_url = f"{self.endpoints['opencve']}/{cve_id}"
                    detailed_response = self._make_request('opencve', detailed_url)
                    
                    if detailed_response:
                        detailed_cves.append(detailed_response.json())
            
            return {
                'summary': all_cves,
                'detailed': detailed_cves,
                'count': len(all_cves),
                'timestamp': datetime.now().isoformat()
            }
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching OpenCVE data: {str(e)}")
            return None

    def fetch_nist_standards(self) -> Optional[Dict]:
        """
        Fetch NIST cyber security standards.
        
        Returns:
            Dictionary containing NIST standards or None if failed
        """
        logger.warning("NIST standards fetching is disabled due to URL issues")
        return None

    def fetch_mitre_attack(self) -> Optional[Dict]:
        """Fetch MITRE ATT&CK framework data."""
        try:
            response = self.session.get(self.endpoints['mitre_attack'])
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching MITRE ATT&CK data: {str(e)}")
            return None

    def fetch_capec_data(self) -> Optional[Dict]:
        """Fetch MITRE CAPEC (Common Attack Pattern Enumeration and Classification) data."""
        try:
            response = self.session.get(self.endpoints['mitre_capec'])
            response.raise_for_status()
            return {'xml_data': response.text}
        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching CAPEC data: {str(e)}")
            return None

    def fetch_ubuntu_security_notices(self) -> Optional[Dict]:
        """Fetch Ubuntu Security Notices."""
        try:
            feed = feedparser.parse(self.endpoints['ubuntu_usn'])
            return {'entries': feed.entries}
        except Exception as e:
            logger.error(f"Error fetching Ubuntu Security Notices: {str(e)}")
            return None

    def fetch_arxiv_papers(self) -> Optional[Dict]:
        """Fetch recent cyber security papers from arXiv."""
        try:
            response = self.session.get(self.endpoints['arxiv_cs_crypto'])
            response.raise_for_status()
            feed = feedparser.parse(response.text)
            return {'papers': feed.entries}
        except Exception as e:
            logger.error(f"Error fetching arXiv papers: {str(e)}")
            return None

    def fetch_redhat_security(self) -> Optional[Dict]:
        """Fetch Red Hat Security Data."""
        try:
            response = self.session.get(self.endpoints['redhat_security'])
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching Red Hat Security data: {str(e)}")
            return None

    def fetch_microsoft_security(self) -> Optional[Dict]:
        """Fetch Microsoft Security Updates."""
        try:
            response = self.session.get(self.endpoints['microsoft_security'])
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching Microsoft Security Updates: {str(e)}")
            return None

    def fetch_malware_data(self) -> Optional[Dict]:
        """
        Fetch malware data from MalwareBazaar.
        """
        logger.warning("Malware data fetching is disabled due to API issues")
        return None

    def fetch_social_engineering_data(self) -> Optional[Dict]:
        """
        Fetch social engineering data from PhishTank.
        """
        logger.warning("Social engineering data fetching is disabled due to scraping issues")
        return None

    def scrape_security_articles(self, url: str) -> Optional[Dict]:
        """
        Scrape cyber security articles from provided URL.
        
        Args:
            url: URL to scrape
            
        Returns:
            Dictionary containing scraped data or None if failed
        """
        try:
            response = self.session.get(url)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract relevant information (customize based on website structure)
            data = {
                'title': soup.title.string if soup.title else None,
                'text': soup.get_text(),
                'url': url,
                'timestamp': datetime.now().isoformat()
            }
            return data
        except (requests.exceptions.RequestException, AttributeError) as e:
            logger.error(f"Error scraping article from {url}: {str(e)}")
            return None

    def save_data(self, data: Union[Dict, List], source: str, format: str = 'json') -> bool:
        """
        Enhanced save_data method with better error handling and backup.
        """
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = self.output_dir / f"{source}_{timestamp}.{format}"
            
            # Create backup directory
            backup_dir = self.output_dir / 'backups'
            backup_dir.mkdir(exist_ok=True)
            
            # Save data with proper encoding and error handling
            if format == 'json':
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)
                    f.flush()
                    os.fsync(f.fileno())  # Ensure data is written to disk
                    
            elif format == 'xml':
                # Improved XML handling
                root = ET.Element("data")
                self._dict_to_xml(data, root)
                tree = ET.ElementTree(root)
                tree.write(filename, encoding='utf-8', xml_declaration=True)
                
            elif format == 'yaml':
                with open(filename, 'w', encoding='utf-8') as f:
                    yaml.dump(data, f, allow_unicode=True, default_flow_style=False)
                    f.flush()
                    os.fsync(f.fileno())
                    
            elif format == 'csv':
                df = pd.DataFrame(data)
                df.to_csv(filename, index=False, encoding='utf-8')
            
            # Create backup
            backup_file = backup_dir / f"{source}_{timestamp}_backup.{format}"
            shutil.copy2(filename, backup_file)
            
            logger.info(f"Successfully saved data to {filename} with backup at {backup_file}")
            return True
            
        except Exception as e:
            logger.error(f"Error saving data: {str(e)}")
            return False

    def _dict_to_xml(self, data: Union[Dict, List, str, int, float], parent: ET.Element):
        """Helper method for converting dictionary to XML."""
        if isinstance(data, dict):
            for key, value in data.items():
                child = ET.SubElement(parent, str(key))
                self._dict_to_xml(value, child)
        elif isinstance(data, (list, tuple)):
            for item in data:
                child = ET.SubElement(parent, 'item')
                self._dict_to_xml(item, child)
        else:
            parent.text = str(data)

    def fetch_ctf_data(self) -> Optional[Dict]:
        """
        Fetch CTF event data and challenges from various platforms.
        
        Returns:
            Dictionary containing CTF data or None if failed
        """
        try:
            # Get upcoming and ongoing CTF events from CTFtime
            # CTFtime API requires start and end time parameters
            start_time = datetime.now()
            end_time = start_time + timedelta(days=90)  # Get events for next 90 days
            
            params = {
                'start': int(start_time.timestamp()),
                'finish': int(end_time.timestamp()),
                'limit': 100
            }
            
            response = self.session.get(self.endpoints['ctftime'], params=params)
            response.raise_for_status()
            ctftime_events = response.json()
            
            # Compile CTF data from different sources
            ctf_data = {
                'ctftime_events': ctftime_events,
                'timestamp': datetime.now().isoformat(),
                'metadata': {
                    'source': 'CTFtime API',
                    'event_timeframe': f"{start_time.date()} to {end_time.date()}"
                }
            }
            
            return ctf_data
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching CTF data: {str(e)}")
            return None

    def fetch_security_testing_resources(self) -> Optional[Dict]:
        """
        Fetch security testing scripts and resources from educational sources.
        
        Note: Some endpoints may be blocked by corporate firewalls or security policies.
        GitHub rate limits apply for raw.githubusercontent.com requests.
        """
        logger.warning("Security testing resources fetching is disabled due to URL issues")
        return None

def main():
    """Main function to process command-line arguments and run data collection."""
    description = """
    Collect cybersecurity data from various sources.
    
    Working sources:
    - cve_data: CVE vulnerability data from NVD
    - opencve_data: CVE vulnerability data from OpenCVE API
    - mitre_attack: MITRE ATT&CK framework data
    - capec_data: Common Attack Pattern Enumeration and Classification data
    - ubuntu_security: Ubuntu Security Notices
    - arxiv_papers: Recent cybersecurity papers from arXiv
    - redhat_security: Red Hat Security Data
    - microsoft_security: Microsoft Security Updates
    - ctf_data: CTF event data and challenges
    
    Disabled sources (known issues):
    - nist_standards: NIST cybersecurity standards (URL issues)
    - malware_data: Malware data from MalwareBazaar (API issues)
    - social_engineering: Phishing data from PhishTank (scraping issues)
    - security_testing: Security testing resources (URL issues)
    """
    
    parser = argparse.ArgumentParser(description=description, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--sources", nargs="+", help="List of sources to fetch data from, space-separated")
    parser.add_argument("--output-dir", default="raw_data", help="Directory to save collected data")
    
    args = parser.parse_args()
    
    collector = CyberDataCollector(output_dir=args.output_dir)
    
    # Define all available sources
    all_sources = {
        'cve_data': collector.fetch_cve_data,
        'opencve_data': collector.fetch_opencve_data,
        'mitre_attack': collector.fetch_mitre_attack,
        'capec_data': collector.fetch_capec_data,
        'ubuntu_security': collector.fetch_ubuntu_security_notices,
        'arxiv_papers': collector.fetch_arxiv_papers,
        'redhat_security': collector.fetch_redhat_security,
        'microsoft_security': collector.fetch_microsoft_security,
        'ctf_data': collector.fetch_ctf_data,
    }
    
    # Disabled sources
    disabled_sources = {
        'nist_standards': collector.fetch_nist_standards,
        'malware_data': collector.fetch_malware_data,
        'social_engineering': collector.fetch_social_engineering_data,
        'security_testing': collector.fetch_security_testing_resources,
    }
    
    # If specific sources are provided, use only those
    sources_to_fetch = {}
    if args.sources:
        for source in args.sources:
            if source in all_sources:
                sources_to_fetch[source] = all_sources[source]
            elif source in disabled_sources:
                sources_to_fetch[source] = disabled_sources[source]
                logger.warning(f"Including disabled source: {source}")
            elif source == "all":
                sources_to_fetch = all_sources
                break
            else:
                logger.warning(f"Unknown source: {source}, ignoring")
    else:
        # If no sources specified, use all working ones
        sources_to_fetch = all_sources
    
    logger.info(f"Collecting data from {len(sources_to_fetch)} sources")
    
    for source_name, fetch_function in sources_to_fetch.items():
        logger.info(f"Fetching data from {source_name}...")
        data = fetch_function()
        if data:
            collector.save_data(data, source_name)
        else:
            logger.warning(f"No data retrieved from {source_name}")

if __name__ == "__main__":
    main() 
