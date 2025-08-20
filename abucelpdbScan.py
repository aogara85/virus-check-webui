import requests
import json
import csv
from datetime import datetime
import sys
import ipaddress
import os

# データフォルダのパス設定
DATA_FOLDER_ROOT_PATH = ".\\data"
ABUSEIPDB_SCAN_DATA_PATH = ".\\data\\abuseipdbscan"

class AbuseIPDBChecker:
    def __init__(self, api_key):
        """
        AbuseIPDBのチェッカークラスを初期化
        
        Args:
            api_key (str): AbuseIPDBのAPIキー
        """
        self.api_key = api_key
        self.base_url = "https://api.abuseipdb.com/api/v2"
        self.headers = {
            'Accept': 'application/json',
            'Key': self.api_key
        }
        
        # アウトプットのディレクトリ作成
        os.makedirs(DATA_FOLDER_ROOT_PATH, exist_ok=True)
        os.makedirs(ABUSEIPDB_SCAN_DATA_PATH, exist_ok=True)

    def get_file_list(self):
        """
        スキャン結果の保存先のファイル名とフルパスのリストを返す
        """
        file_fullpath_list = []
        if os.path.exists(ABUSEIPDB_SCAN_DATA_PATH):
            file_list = os.listdir(ABUSEIPDB_SCAN_DATA_PATH)
            for filename in file_list:
                file_fullpath_list.append(os.path.join(ABUSEIPDB_SCAN_DATA_PATH, filename))
        return file_fullpath_list

    def check_id(self, ip_address):
        """
        スキャン結果のIPアドレスが一致するファイルの存在をチェックする。
        返り値はタプル（存在有無をbool、存在した場合のフルパス）
        """
        for file_path in self.get_file_list():
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    jsondata = json.load(f)
                    if "data" in jsondata and jsondata["data"].get("ipAddress") == ip_address:
                        return (True, file_path)
            except (json.JSONDecodeError, KeyError, FileNotFoundError):
                continue
        return (False, "")

    def check_ip(self, ip_address, days=30, overwrite=False):
        """
        単一のIPアドレスをチェック
        
        Args:
            ip_address (str): チェックするIPアドレス
            days (int): 過去何日分のレポートを確認するか（デフォルト30日）
            overwrite (bool): 既存ファイルを上書きするかどうか
        
        Returns:
            dict: APIレスポンス
        """
        try:
            ipaddress.ip_address(ip_address)
            
            # 既存ファイルのチェック
            report_check = self.check_id(ip_address)
            
            # 上書き設定がONなら既存チェックをオフに
            if overwrite:
                report_check = (False, "")
            
            output_filename = f"{ABUSEIPDB_SCAN_DATA_PATH}/{ip_address}.json"
            
            # 既にスキャン済ファイルであれば、jsonファイルから読み出す
            if report_check[0]:
                with open(report_check[1], 'r', encoding='utf-8') as f:
                    jsondata = json.load(f)
                    return jsondata
            else:
                check_url = f"{self.base_url}/check"
                params = {
                    'ipAddress': ip_address,
                    'maxAgeInDays': days
                }
                
                response = requests.get(check_url, headers=self.headers, params=params)
                response.raise_for_status()
                
                result = response.json()
                
                # レスポンスをファイルに保存
                with open(output_filename, "w", encoding='utf-8') as outfile:
                    json.dump(result, outfile, ensure_ascii=False, indent=2)
                
                return result
            
        except ValueError as e:
            error_response = {"error": f"Invalid IP address: {str(e)}"}
            return error_response
        except requests.exceptions.RequestException as e:
            error_response = {"error": f"API request failed: {str(e)}"}
            # エラーレスポンスもファイルに保存
            try:
                output_filename = f"{ABUSEIPDB_SCAN_DATA_PATH}/{ip_address}_error.json"
                with open(output_filename, "w", encoding='utf-8') as outfile:
                    json.dump(error_response, outfile, ensure_ascii=False, indent=2)
            except:
                pass
            return error_response

    def get_reports(self, ip_address, days=30, limit=100):
        """
        特定のIPアドレスの詳細なレポート履歴を取得
        
        Args:
            ip_address (str): チェックするIPアドレス
            days (int): 過去何日分のレポートを取得するか（デフォルト30日）
            limit (int): 取得するレポートの最大数（デフォルト100件）
        
        Returns:
            dict: レポート詳細情報
        """
        try:
            ipaddress.ip_address(ip_address)
            
            reports_url = f"{self.base_url}/reports"
            params = {
                'ipAddress': ip_address,
                'maxAgeInDays': days,
                'limit': limit
            }
            
            response = requests.get(reports_url, headers=self.headers, params=params)
            response.raise_for_status()
            
            return response.json()
        
        except ValueError as e:
            return {"error": f"Invalid IP address: {str(e)}"}
        except requests.exceptions.RequestException as e:
            return {"error": f"API request failed: {str(e)}"}

    def save_detailed_reports(self, ip_address, output_file, days=30):
        """
        IPアドレスの詳細レポートをCSVファイルに保存
        
        Args:
            ip_address (str): チェックするIPアドレス
            output_file (str): 出力CSVファイル名
            days (int): 過去何日分のレポートを取得するか（デフォルト30日）
        """
        reports = self.get_reports(ip_address, days)
        
        if "data" in reports and "reports" in reports["data"]:
            with open(output_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow([
                    'Report Date',
                    'Reporter',
                    'Country',
                    'Categories',
                    'Comment'
                ])
                
                for report in reports["data"]["reports"]:
                    categories = []
                    if "categories" in report:
                        # カテゴリーコードを人間が読める形式に変換
                        categories = self.convert_categories(report["categories"])
                    
                    writer.writerow([
                        report.get("reportedAt", ""),
                        report.get("reporterID", "Anonymous"),
                        report.get("reporterCountryCode", ""),
                        ", ".join(categories),
                        report.get("comment", "")
                    ])
            
            print(f"Detailed reports have been saved to {output_file}")
        else:
            print(f"No reports found for IP {ip_address}")

    def convert_categories(self, category_numbers):
        """
        カテゴリー番号を説明テキストに変換
        """
        categories = {
            1: "DNS Compromise",
            2: "DNS Poisoning",
            3: "Fraud Orders",
            4: "DDoS Attack",
            5: "FTP Brute-Force",
            6: "Ping of Death",
            7: "Phishing",
            8: "Fraud VoIP",
            9: "Open Proxy",
            10: "Web Spam",
            11: "Email Spam",
            12: "Blog Spam",
            13: "VPN IP",
            14: "Port Scan",
            15: "Hacking",
            16: "SQL Injection",
            17: "Spoofing",
            18: "Brute-Force",
            19: "Bad Web Bot",
            20: "Exploited Host",
            21: "Web App Attack",
            22: "SSH",
            23: "IoT Targeted"
        }
        
        return [categories.get(cat, f"Unknown ({cat})") for cat in category_numbers]

    def bulk_check_file(self, input_file, output_file, days=30):
        """
        ファイルから複数のIPアドレスをチェック
        
        Args:
            input_file (str): IPアドレスリストを含む入力ファイルパス（1行1IP）
            output_file (str): 結果を出力するCSVファイルパス
            days (int): 過去何日分のレポートを確認するか（デフォルト30日）
        """
        results = []
        
        try:
            with open(input_file, 'r') as f:
                ip_list = [line.strip() for line in f if line.strip()]
            
            for ip in ip_list:
                result = self.check_ip(ip, days)
                if "data" in result:
                    data = result["data"]
                    results.append({
                        'IP': ip,
                        'Confidence Score': data.get('abuseConfidenceScore', ''),
                        'Total Reports': data.get('totalReports', ''),
                        'Last Reported': data.get('lastReportedAt', ''),
                        'Domain': data.get('domain', ''),
                        'Country': data.get('countryCode', '')
                    })
                else:
                    results.append({
                        'IP': ip,
                        'Error': result.get('error', 'Unknown error')
                    })
            
            if results:
                fieldnames = ['IP', 'Confidence Score', 'Total Reports', 'Last Reported', 'Domain', 'Country', 'Error']
                with open(output_file, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.DictWriter(f, fieldnames=fieldnames)
                    writer.writeheader()
                    writer.writerows(results)
                
                print(f"Results have been saved to {output_file}")
            
        except FileNotFoundError:
            print(f"Error: Input file '{input_file}' not found")
        except Exception as e:
            print(f"Error processing file: {str(e)}")

def main():
    """
    メイン実行関数
    使用例：
    1. 基本チェック:
       python script.py check <API_KEY> <INPUT_FILE> <OUTPUT_FILE> [DAYS]
    2. 詳細レポート:
       python script.py reports <API_KEY> <IP_ADDRESS> <OUTPUT_FILE> [DAYS]
    """
    if len(sys.argv) < 4:
        print("Usage:")
        print("1. Basic check: python script.py check <API_KEY> <INPUT_FILE> <OUTPUT_FILE> [DAYS]")
        print("2. Detailed reports: python script.py reports <API_KEY> <IP_ADDRESS> <OUTPUT_FILE> [DAYS]")
        sys.exit(1)
    
    command = sys.argv[1]
    api_key = sys.argv[2]
    checker = AbuseIPDBChecker(api_key)
    
    if command == "check":
        input_file = sys.argv[3]
        output_file = sys.argv[4]
        days = int(sys.argv[5]) if len(sys.argv) > 5 else 30
        checker.bulk_check_file(input_file, output_file, days)
    
    elif command == "reports":
        ip_address = sys.argv[3]
        output_file = sys.argv[4]
        days = int(sys.argv[5]) if len(sys.argv) > 5 else 30
        checker.save_detailed_reports(ip_address, output_file, days)
    
    else:
        print("Invalid command. Use 'check' or 'reports'")
        sys.exit(1)

if __name__ == "__main__":
    main()