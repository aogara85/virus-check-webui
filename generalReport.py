from jinja2 import Environment, FileSystemLoader
import plotly.graph_objects as go
import json
from datetime import datetime
from vt_scanner import ScanResult
import plotly.figure_factory as ff
import os

class ReportGenerator:
    def __init__(self, template_dir=None):
        if template_dir is None:
            template_dir = os.path.dirname(os.path.abspath(__file__))
        self.env = Environment(loader=FileSystemLoader(template_dir))
        
    def create_threat_distribution(self, result_dict):
        """脅威の分布を示すヒートマップを作成"""
        labels = []
        negative_rates = []
        
        for target, details in result_dict.items():
            labels.append(target)
            negative_rate = details[1]  # negative count
            negative_rates.append(negative_rate)

        fig = go.Figure(data=[
            go.Bar(
                x=labels,
                y=negative_rates,
                marker_color='rgb(158,202,225)',
                name='ネガティブ検出数'
            )
        ])
        
        fig.update_layout(
            title='検出分布',
            xaxis_title='スキャン対象',
            yaxis_title='検出数',
            showlegend=True
        )
        return fig.to_html()
    
    def create_category_chart(self, result_dict):
        """全カテゴリーの分布を円グラフで表示"""
        all_categories = {}
        for details in result_dict.values():
            categories = details[7]  # categoriesのインデックス
            if categories:
                for category in categories:
                    all_categories[category] = all_categories.get(category, 0) + 1
        
        if not all_categories:
            return ""
            
        fig = go.Figure(data=[
            go.Pie(
                labels=list(all_categories.keys()),
                values=list(all_categories.values()),
                hole=.3
            )
        ])
        fig.update_layout(title="カテゴリー分布")
        return fig.to_html()
    
    def generate_html_report(self, result_dict):
        """HTMLレポートを生成"""
        template = self.env.get_template("report_template.html")
        
        # 結果の分析
        summary = self._analyze_results(result_dict)
        findings = self._extract_key_findings(result_dict)
        recommendations = self._generate_recommendations(summary)
        
        context = {
            "scan_results": result_dict,
            "summary": summary,
            "threat_distribution": self.create_threat_distribution(result_dict),
            "category_chart": self.create_category_chart(result_dict),
            "generated_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "key_findings": findings,
            "recommendations": recommendations
        }
        
        return template.render(context)
    
    def _analyze_results(self, result_dict):
        """結果の総合分析"""
        total_targets = len(result_dict)
        total_positives = sum(1 for details in result_dict.values() if details[1] > 0)  # negative count > 0
        total_comments = sum(1 for details in result_dict.values() if details[6])  # comment_tf
        
        # 国別の集計
        countries = {}
        for details in result_dict.values():
            country = details[4]  # country
            countries[country] = countries.get(country, 0) + 1
            
        # タグの集計
        all_tags = {}
        for details in result_dict.values():
            tags = details[5]  # tags
            for tag in tags:
                all_tags[tag] = all_tags.get(tag, 0) + 1
                
        return {
            "total_targets": total_targets,
            "total_positives": total_positives,
            "detection_rate": (total_positives / total_targets * 100) if total_targets > 0 else 0,
            "total_comments": total_comments,
            "countries": countries,
            "top_tags": dict(sorted(all_tags.items(), key=lambda x: x[1], reverse=True)[:5])
        }
    
    def _extract_key_findings(self, result_dict):
        """主要な発見事項を抽出"""
        findings = []
        
        # 高リスクのターゲット
        high_risk = [target for target, details in result_dict.items() 
                    if details[1] > 0]  # negative count > 0
        if high_risk:
            findings.append(f"高リスクと判定されたターゲット: {len(high_risk)}件")
            
        # コメントのあるターゲット
        commented = [target for target, details in result_dict.items() 
                    if details[6]]  # comment_tf
        if commented:
            findings.append(f"コミュニティコメントのあるターゲット: {len(commented)}件")
        
        # 最も多い国
        countries = {}
        for details in result_dict.values():
            country = details[4]  # country
            countries[country] = countries.get(country, 0) + 1
        if countries:
            top_country = max(countries.items(), key=lambda x: x[1])
            findings.append(f"最も多い国: {top_country[0]} ({top_country[1]}件)")
            
        return findings
    
    def _generate_recommendations(self, summary):
        """推奨事項を生成"""
        recommendations = []
        
        if summary["total_positives"] > 0:
            recommendations.append(
                f"検出されたターゲットが{summary['total_positives']}件あります。"
                "セキュリティ監査を実施することを推奨します。"
            )
            
        if summary["detection_rate"] > 30:
            recommendations.append(
                f"検出率が{summary['detection_rate']:.1f}%と高いため、"
                "ネットワークセキュリティの見直しを推奨します。"
            )
            
        if summary["total_comments"] > 0:
            recommendations.append(
                f"{summary['total_comments']}件のターゲットにコミュニティコメントがあります。"
                "内容を確認することを推奨します。"
            )
            
        return recommendations

# 使用例
if __name__ == "__main__":
    # サンプルデータ
    sample_data = {
        "example.com": ["malware detected", 5, 10, 20, "US", ["malware"], True, ["malicious"]],
        "192.168.1.1": ["suspicious", 3, 5, 15, "JP", ["suspicious"], False, ["suspicious"]],
        "test.com": ["clean", 0, 0, 30, "DE", [], False, ["benign"]]
    }
    
    # レポート生成
    generator = ReportGenerator()
    html_report = generator.generate_html_report(sample_data)
    
    # HTMLファイルとして保存
    with open("report.html", "w", encoding="utf-8") as f:
        f.write(html_report)