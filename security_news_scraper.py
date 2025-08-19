import feedparser
from datetime import datetime
from scraper_utils import SecureScraper, clean_text
from typing import List, Dict

class SecurityNewsScraper(SecureScraper):
    def __init__(self):
        super().__init__("https://feeds.feedburner.com", delay=1.5)
        self.news_sources = {
            'Krebs on Security': 'https://krebsonsecurity.com/feed/',
            'Threatpost': 'https://threatpost.com/feed/',
            'Dark Reading': 'https://www.darkreading.com/rss.xml',
            'Security Week': 'https://feeds.feedburner.com/Securityweek'
        }
        self.articles = []
    
    def scrape_security_news(self, max_articles: int = 10) -> List[Dict]:
        """Scrape latest security news from multiple sources"""
        self.logger.info("Scraping security news from multiple sources...")
        
        for source_name, feed_url in self.news_sources.items():
            try:
                self.logger.info(f"Fetching from {source_name}...")
                
                # Use feedparser for RSS feeds (more reliable than requests)
                feed = feedparser.parse(feed_url)
                
                if feed.bozo:
                    self.logger.warning(f"Feed parsing issues for {source_name}")
                
                for entry in feed.entries[:max_articles]:
                    article = self.parse_article(entry, source_name)
                    if article:
                        self.articles.append(article)
                
                # Rate limiting
                import time
                time.sleep(self.delay)
                
            except Exception as e:
                self.logger.error(f"Error scraping {source_name}: {e}")
        
        # Sort by publication date (newest first)
        self.articles.sort(key=lambda x: x.get('published_date', ''), reverse=True)
        
        self.logger.info(f"✅ Collected {len(self.articles)} articles")
        return self.articles
    
    def parse_article(self, entry, source_name: str) -> Dict:
        """Parse individual RSS feed entry"""
        try:
            article = {
                'title': clean_text(getattr(entry, 'title', 'No title')),
                'link': getattr(entry, 'link', ''),
                'description': clean_text(getattr(entry, 'summary', 'No description')),
                'published_date': getattr(entry, 'published', ''),
                'source': source_name,
                'scraped_at': datetime.now().isoformat(),
                'tags': self.extract_security_tags(entry),
                'threat_level': self.assess_threat_level(entry)
            }
            
            return article
            
        except Exception as e:
            self.logger.error(f"Error parsing article: {e}")
            return None
    
    def extract_security_tags(self, entry) -> List[str]:
        """Extract security-related tags from article"""
        tags = []
        content = f"{getattr(entry, 'title', '')} {getattr(entry, 'summary', '')}".lower()
        
        security_keywords = [
            'malware', 'ransomware', 'phishing', 'breach', 'vulnerability',
            'exploit', 'zero-day', 'apt', 'threat actor', 'cybersecurity',
            'data breach', 'ddos', 'botnet', 'trojan', 'backdoor'
        ]
        
        for keyword in security_keywords:
            if keyword in content:
                tags.append(keyword.title())
        
        return list(set(tags))  # Remove duplicates
    
    def assess_threat_level(self, entry) -> str:
        """Assess threat level based on article content"""
        content = f"{getattr(entry, 'title', '')} {getattr(entry, 'summary', '')}".lower()
        
        critical_indicators = ['zero-day', 'critical vulnerability', 'active exploitation', 'widespread attack']
        high_indicators = ['new malware', 'data breach', 'ransomware', 'apt group']
        medium_indicators = ['vulnerability', 'security advisory', 'patch available']
        
        if any(indicator in content for indicator in critical_indicators):
            return "Critical"
        elif any(indicator in content for indicator in high_indicators):
            return "High"
        elif any(indicator in content for indicator in medium_indicators):
            return "Medium"
        else:
            return "Low"
    
    def generate_news_summary(self) -> Dict:
        """Generate summary of security news"""
        if not self.articles:
            return {}
        
        threat_levels = {}
        sources = {}
        tags = {}
        
        for article in self.articles:
            # Count threat levels
            level = article.get('threat_level', 'Unknown')
            threat_levels[level] = threat_levels.get(level, 0) + 1
            
            # Count sources
            source = article.get('source', 'Unknown')
            sources[source] = sources.get(source, 0) + 1
            
            # Count tags
            for tag in article.get('tags', []):
                tags[tag] = tags.get(tag, 0) + 1
        
        # Get top threats
        high_threat_articles = [a for a in self.articles if a.get('threat_level') in ['Critical', 'High']]
        
        summary = {
            'total_articles': len(self.articles),
            'threat_level_distribution': threat_levels,
            'source_distribution': sources,
            'top_security_tags': dict(sorted(tags.items(), key=lambda x: x[1], reverse=True)[:10]),
            'high_threat_articles': high_threat_articles[:5],  # Top 5 high-threat articles
            'generated_at': datetime.now().isoformat()
        }
        
        return summary

def main():
    """Main execution function"""
    print("📰 Security News Intelligence Scraper")
    print("Author: Raymond Nwambuonwo")
    print("="*50)
    
    scraper = SecurityNewsScraper()
    
    try:
        # Scrape security news
        articles = scraper.scrape_security_news(max_articles=10)
        
        if articles:
            # Save data
            scraper.save_to_json(articles, 'security_news.json')
            scraper.save_to_csv(articles, 'security_news.csv')
            
            # Generate summary
            summary = scraper.generate_news_summary()
            scraper.save_to_json([summary], 'news_summary.json')
            
            # Print summary
            print(f"\n📊 News Summary:")
            print(f"   Total articles: {len(articles)}")
            print(f"   High/Critical threats: {len([a for a in articles if a.get('threat_level') in ['Critical', 'High']])}")
            print(f"   Sources: {len(set(a.get('source') for a in articles))}")
            print(f"   Data saved to: data/ directory")
            
        else:
            print("❌ No articles collected")
            
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    main()