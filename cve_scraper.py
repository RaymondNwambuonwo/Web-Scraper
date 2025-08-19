import requests
from bs4 import BeautifulSoup
from datetime import datetime, timedelta
from scraper_utils import SecureScraper, clean_text
from typing import List, Dict

class CVEScraper(SecureScraper):
    def __init__(self):
        super().__init__("https://cve.mitre.org", delay=2.0)
        self.cve_data = []
    
    def scrape_recent_cves(self, days: int = 7) -> List[Dict]:
        """Scrape recent CVEs from MITRE's public feed"""
        self.logger.info(f"Scraping CVEs from last {days} days...")
        
        # Use MITRE's public RSS feed (more respectful than scraping HTML)
        rss_url = "https://cve.mitre.org/data/refs/refmap/source-CONFIRM.rss"
        
        response = self.make_request(rss_url)
        if not response:
            return []
        
        soup = BeautifulSoup(response.content, 'xml')
        items = soup.find_all('item')
        
        cutoff_date = datetime.now() - timedelta(days=days)
        
        for item in items[:20]:  # Limit to first 20 items
            try:
                title = clean_text(item.title.text) if item.title else "No title"
                description = clean_text(item.description.text) if item.description else "No description"
                link = item.link.text if item.link else ""
                pub_date = item.pubDate.text if item.pubDate else ""
                
                # Extract CVE ID from title
                cve_id = self.extract_cve_id(title)
                
                cve_entry = {
                    'cve_id': cve_id,
                    'title': title,
                    'description': description,
                    'link': link,
                    'published_date': pub_date,
                    'scraped_at': datetime.now().isoformat(),
                    'severity': self.estimate_severity(description),
                    'category': self.categorize_vulnerability(description)
                }
                
                self.cve_data.append(cve_entry)
                
            except Exception as e:
                self.logger.error(f"Error parsing CVE item: {e}")
        
        self.logger.info(f"✅ Collected {len(self.cve_data)} CVE entries")
        return self.cve_data
    
    def extract_cve_id(self, text: str) -> str:
        """Extract CVE ID from text"""
        import re
        match = re.search(r'CVE-\d{4}-\d+', text)
        return match.group(0) if match else "Unknown"
    
    def estimate_severity(self, description: str) -> str:
        """Estimate severity based on description keywords"""
        description_lower = description.lower()
        
        critical_keywords = ['remote code execution', 'privilege escalation', 'buffer overflow']
        high_keywords = ['denial of service', 'information disclosure', 'cross-site scripting']
        medium_keywords = ['authentication bypass', 'sql injection']
        
        if any(keyword in description_lower for keyword in critical_keywords):
            return "Critical"
        elif any(keyword in description_lower for keyword in high_keywords):
            return "High"
        elif any(keyword in description_lower for keyword in medium_keywords):
            return "Medium"
        else:
            return "Low"
    
    def categorize_vulnerability(self, description: str) -> str:
        """Categorize vulnerability type"""
        description_lower = description.lower()
        
        if 'sql' in description_lower:
            return "SQL Injection"
        elif 'xss' in description_lower or 'cross-site' in description_lower:
            return "Cross-Site Scripting"
        elif 'buffer overflow' in description_lower:
            return "Buffer Overflow"
        elif 'privilege escalation' in description_lower:
            return "Privilege Escalation"
        elif 'denial of service' in description_lower:
            return "Denial of Service"
        else:
            return "Other"
    
    def generate_threat_intel_report(self) -> Dict:
        """Generate threat intelligence summary"""
        if not self.cve_data:
            return {}
        
        severity_counts = {}
        category_counts = {}
        
        for cve in self.cve_data:
            severity = cve.get('severity', 'Unknown')
            category = cve.get('category', 'Unknown')
            
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            category_counts[category] = category_counts.get(category, 0) + 1
        
        report = {
            'total_cves': len(self.cve_data),
            'severity_distribution': severity_counts,
            'category_distribution': category_counts,
            'high_risk_cves': [cve for cve in self.cve_data if cve.get('severity') in ['Critical', 'High']],
            'generated_at': datetime.now().isoformat()
        }
        
        return report

def main():
    """Main execution function"""
    print("🔍 CVE Threat Intelligence Scraper")
    print("Author: Raymond")
    print("="*50)
    
    scraper = CVEScraper()
    
    try:
        # Scrape recent CVEs
        cves = scraper.scrape_recent_cves(days=7)
        
        if cves:
            # Save data
            scraper.save_to_json(cves, 'recent_cves.json')
            scraper.save_to_csv(cves, 'recent_cves.csv')
            
            # Generate threat intel report
            report = scraper.generate_threat_intel_report()
            scraper.save_to_json([report], 'threat_intel_report.json')
            
            # Print summary
            print(f"\n📊 CVE Summary:")
            print(f"   Total CVEs: {len(cves)}")
            print(f"   High/Critical: {len([c for c in cves if c.get('severity') in ['Critical', 'High']])}")
            print(f"   Data saved to: data/ directory")
            
        else:
            print("❌ No CVE data collected")
            
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    main()