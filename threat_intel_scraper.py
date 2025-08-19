import os
from datetime import datetime
from typing import List
from cve_scraper import CVEScraper
from security_news_scraper import SecurityNewsScraper
from scraper_utils import SecureScraper

class ThreatIntelSuite:
    def __init__(self):
        self.create_data_directory()
        self.results = {}
    
    def create_data_directory(self):
        """Ensure data directory exists"""
        if not os.path.exists('data'):
            os.makedirs('data')
            print("📁 Created data directory")
    
    def run_full_collection(self):
        """Run complete threat intelligence collection"""
        print("🔍 Starting Comprehensive Threat Intelligence Collection")
        print("Author: Raymond Nwambuonwo")
        print("="*60)
        
        # Collect CVE data
        print("\n1️⃣ Collecting CVE Data...")
        cve_scraper = CVEScraper()
        cves = cve_scraper.scrape_recent_cves(days=7)
        self.results['cves'] = {
            'count': len(cves),
            'high_risk': len([c for c in cves if c.get('severity') in ['Critical', 'High']]),
            'data': cves
        }
        
        # Collect security news
        print("\n2️⃣ Collecting Security News...")
        news_scraper = SecurityNewsScraper()
        articles = news_scraper.scrape_security_news(max_articles=15)
        self.results['news'] = {
            'count': len(articles),
            'high_threat': len([a for a in articles if a.get('threat_level') in ['Critical', 'High']]),
            'data': articles
        }
        
        # Generate comprehensive report
        self.generate_comprehensive_report()
        
        # Print summary
        self.print_collection_summary()
    
    def generate_comprehensive_report(self):
        """Generate comprehensive threat intelligence report"""
        report = {
            'collection_summary': {
                'total_cves': self.results['cves']['count'],
                'high_risk_cves': self.results['cves']['high_risk'],
                'total_articles': self.results['news']['count'],
                'high_threat_articles': self.results['news']['high_threat'],
                'collection_date': datetime.now().isoformat()
            },
            'risk_assessment': self.assess_overall_risk(),
            'recommendations': self.generate_recommendations(),
            'data_sources': [
                'MITRE CVE Database',
                'Krebs on Security',
                'Threatpost',
                'Dark Reading',
                'Security Week'
            ]
        }
        
        # Save comprehensive report
        import json
        with open('data/comprehensive_threat_report.json', 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        print("✅ Comprehensive report generated")
    
    def assess_overall_risk(self) -> str:
        """Assess overall threat landscape risk"""
        high_risk_cves = self.results['cves']['high_risk']
        high_threat_news = self.results['news']['high_threat']
        
        total_high_risk = high_risk_cves + high_threat_news
        
        if total_high_risk >= 10:
            return "High"
        elif total_high_risk >= 5:
            return "Medium"
        else:
            return "Low"
    
    def generate_recommendations(self) -> List[str]:
        """Generate security recommendations based on collected data"""
        recommendations = []
        
        if self.results['cves']['high_risk'] > 0:
            recommendations.append("Review and prioritize patching for high-risk CVEs")
            recommendations.append("Implement vulnerability scanning for affected systems")
        
        if self.results['news']['high_threat'] > 0:
            recommendations.append("Monitor for indicators of compromise related to recent threats")
            recommendations.append("Update security awareness training based on current threat landscape")
        
        recommendations.extend([
            "Continue regular threat intelligence collection",
            "Share findings with security team for action planning",
            "Schedule follow-up collection in 24-48 hours"
        ])
        
        return recommendations
    
    def print_collection_summary(self):
        """Print summary of collection results"""
        print(f"\n📊 THREAT INTELLIGENCE COLLECTION SUMMARY")
        print("="*50)
        print(f"🔍 CVE Data:")
        print(f"   Total CVEs: {self.results['cves']['count']}")
        print(f"   High/Critical: {self.results['cves']['high_risk']}")
        
        print(f"\n📰 Security News:")
        print(f"   Total Articles: {self.results['news']['count']}")
        print(f"   High Threat: {self.results['news']['high_threat']}")
        
        print(f"\n🎯 Overall Risk Level: {self.assess_overall_risk()}")
        
        print(f"\n📁 Data Files Generated:")
        data_files = [
            'recent_cves.json', 'recent_cves.csv',
            'security_news.json', 'security_news.csv',
            'comprehensive_threat_report.json'
        ]
        for file in data_files:
            if os.path.exists(f'data/{file}'):
                print(f"   ✅ {file}")
        
        print(f"\n💡 Next Steps:")
        for rec in self.generate_recommendations()[:3]:
            print(f"   • {rec}")

def main():
    """Main execution function"""
    suite = ThreatIntelSuite()
    
    try:
        suite.run_full_collection()
        print(f"\n🎉 Threat intelligence collection completed successfully!")
        print(f"📂 Check the 'data/' directory for all collected intelligence.")
        
    except KeyboardInterrupt:
        print(f"\n⚠️  Collection interrupted by user")
    except Exception as e:
        print(f"\n❌ Error during collection: {e}")

if __name__ == "__main__":
    main()