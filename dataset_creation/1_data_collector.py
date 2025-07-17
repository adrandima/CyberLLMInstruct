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

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class CyberDataCollector:
    def __init__(self, output_dir: str = "raw_data"):
        """Initialize the data collector with output directory configuration.
        
        Note: API key requirements removed as per refactoring.
        
        Rate Limits:
        - CTFtime API: 30 requests per minute
        - NVD API: 5 requests per 30 seconds
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Note: API key loading and authentication removed as per refactoring requirements
        
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


            'mitre_attack': 'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json',
            'mitre_capec': 'https://capec.mitre.org/data/xml/views/3000.xml',
            
            # Threat Intelligence Feeds

            'threatfox_api': 'https://threatfox-api.abuse.ch/api/v1/',
            
            # Security Advisories
            'microsoft_security': 'https://api.msrc.microsoft.com/cvrf/v2.0/updates',
            'ubuntu_usn': 'https://ubuntu.com/security/notices/rss.xml',

            
            # Research and Reports
            'arxiv_cs_crypto': 'http://export.arxiv.org/api/query?search_query=cat:cs.CR&max_results=100',
            'exploit_db': 'https://www.exploit-db.com/download/',
            

            # CTF Resources
            'ctftime': 'https://ctftime.org/api/v1/events/',
            'root_me': 'https://api.www.root-me.org/challenges',
            
            # DoS/DDoS Resources
            'ddosdb': 'https://ddosdb.org/api/v1/',
            'netscout_atlas': 'https://atlas.netscout.com/api/v2/',
            
            # MITM & Injection Resources
            'bettercap': 'https://raw.githubusercontent.com/bettercap/bettercap/master/modules/',
            'sqlmap': 'https://raw.githubusercontent.com/sqlmapproject/sqlmap/master/data/',
            'nosqlmap': 'https://raw.githubusercontent.com/codingo/NoSQLMap/master/attacks/',
            
            # Zero-Day & Password Resources
            'zerodayinitiative': 'https://www.zerodayinitiative.com/rss/published/',
            'project_zero': 'https://bugs.chromium.org/p/project-zero/issues/list?rss=true',
            'rockyou': 'https://github.com/danielmiessler/SecLists/raw/master/Passwords/Leaked-Databases/',
            'hashcat': 'https://hashcat.net/hashcat/',
            
            # IoT Security Resources
            'iot_vulndb': 'https://www.exploit-db.com/download/iot/',
            'iot_sentinel': 'https://iotsentinel.csec.ch/api/v1/',
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
        
        # Note: API key authentication removed as per refactoring requirements
        
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
            if response:
                return response.json()
            else:
                return None
        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching CVE data: {str(e)}")
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

    # fetch_malware_data, fetch_social_engineering_data, and fetch_security_testing_resources functions removed

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

    # fetch_security_testing_resources function removed

def main():
    """Main function to process command-line arguments and run data collection."""
    description = """
    Collect cybersecurity data from various sources.
    
    Working sources:
    - cve_data: CVE vulnerability data from NVD
    - mitre_attack: MITRE ATT&CK framework data
    - capec_data: Common Attack Pattern Enumeration and Classification data
    - ubuntu_security: Ubuntu Security Notices
    - arxiv_papers: Recent cybersecurity papers from arXiv
    - microsoft_security: Microsoft Security Updates
    - ctf_data: CTF event data and challenges
    
    Note: API key dependent and problematic sources have been removed.
    """
    
    parser = argparse.ArgumentParser(description=description, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--sources", nargs="+", help="List of sources to fetch data from, space-separated")
    parser.add_argument("--output-dir", default="raw_data", help="Directory to save collected data")
    
    args = parser.parse_args()
    
    collector = CyberDataCollector(output_dir=args.output_dir)
    
    # Define all available sources
    all_sources = {
        'cve_data': collector.fetch_cve_data,
        'mitre_attack': collector.fetch_mitre_attack,
        'capec_data': collector.fetch_capec_data,
        'ubuntu_security': collector.fetch_ubuntu_security_notices,
        'arxiv_papers': collector.fetch_arxiv_papers,
        'microsoft_security': collector.fetch_microsoft_security,
        'ctf_data': collector.fetch_ctf_data,
    }
    
    # Note: Disabled sources and functions removed as per refactoring requirements
    
    # If specific sources are provided, use only those
    sources_to_fetch = {}
    if args.sources:
        for source in args.sources:
            if source in all_sources:
                sources_to_fetch[source] = all_sources[source]
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
