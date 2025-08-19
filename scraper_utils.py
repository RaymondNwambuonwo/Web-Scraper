import requests
import time
import json
import csv
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse, urljoin
from urllib.robotparser import RobotFileParser

class SecureScraper:
    def __init__(self, base_url: str, delay: float = 1.0):
        """Initialize scraper with respectful defaults"""
        self.base_url = base_url
        self.delay = delay  # Delay between requests
        self.session = requests.Session()
        
        # Set respectful headers
        self.session.headers.update({
            'User-Agent': 'SecurityResearchBot/1.0 (Educational Purpose)',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        })
        
        # Setup logging
        self.setup_logging()
        
        # Check robots.txt
        self.check_robots_txt()
    
    def setup_logging(self):
        """Configure logging for scraping activities"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('scraper.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def check_robots_txt(self):
        """Check robots.txt for scraping permissions"""
        try:
            robots_url = urljoin(self.base_url, '/robots.txt')
            rp = RobotFileParser()
            rp.set_url(robots_url)
            rp.read()
            
            user_agent = self.session.headers.get('User-Agent', '*')
            can_fetch = rp.can_fetch(user_agent, self.base_url)
            
            if can_fetch:
                self.logger.info(f"✅ Robots.txt allows scraping for {self.base_url}")
            else:
                self.logger.warning(f"⚠️  Robots.txt restricts scraping for {self.base_url}")
                
        except Exception as e:
            self.logger.warning(f"Could not check robots.txt: {e}")
    
    def make_request(self, url: str, max_retries: int = 3) -> Optional[requests.Response]:
        """Make HTTP request with error handling and retries"""
        for attempt in range(max_retries):
            try:
                self.logger.info(f"Fetching: {url} (attempt {attempt + 1})")
                
                response = self.session.get(url, timeout=10)
                response.raise_for_status()
                
                # Rate limiting
                time.sleep(self.delay)
                
                return response
                
            except requests.exceptions.RequestException as e:
                self.logger.error(f"Request failed (attempt {attempt + 1}): {e}")
                if attempt < max_retries - 1:
                    wait_time = (attempt + 1) * 2  # Exponential backoff
                    self.logger.info(f"Retrying in {wait_time} seconds...")
                    time.sleep(wait_time)
                else:
                    self.logger.error(f"Max retries exceeded for {url}")
                    return None
    
    def save_to_json(self, data: List[Dict], filename: str):
        """Save data to JSON file"""
        filepath = f"data/{filename}"
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False, default=str)
            self.logger.info(f"✅ Data saved to {filepath}")
        except Exception as e:
            self.logger.error(f"Failed to save JSON: {e}")
    
    def save_to_csv(self, data: List[Dict], filename: str):
        """Save data to CSV file"""
        if not data:
            self.logger.warning("No data to save")
            return
            
        filepath = f"data/{filename}"
        try:
            with open(filepath, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=data[0].keys())
                writer.writeheader()
                writer.writerows(data)
            self.logger.info(f"✅ Data saved to {filepath}")
        except Exception as e:
            self.logger.error(f"Failed to save CSV: {e}")
    
    def get_page_info(self, url: str) -> Dict:
        """Get basic information about a webpage"""
        response = self.make_request(url)
        if not response:
            return {}
        
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(response.content, 'html.parser')
        
        return {
            'url': url,
            'title': soup.title.string.strip() if soup.title else 'No title',
            'status_code': response.status_code,
            'content_length': len(response.content),
            'scraped_at': datetime.now().isoformat()
        }

def clean_text(text: str) -> str:
    """Clean and normalize text data"""
    if not text:
        return ""
    
    # Remove extra whitespace and newlines
    cleaned = ' '.join(text.split())
    
    # Remove non-printable characters
    cleaned = ''.join(char for char in cleaned if char.isprintable())
    
    return cleaned.strip()

def validate_url(url: str) -> bool:
    """Validate URL format"""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False