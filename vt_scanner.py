from __future__ import annotations
import json
import hashlib
import re
import sqlite3
import requests
import os
import time
from datetime import datetime, timedelta
from dataclasses import dataclass


#make name of data folder
DATA_FOLDER_ROOT_PATH = ".\\data"
HASH_SCAN_DATA_PATH = ".\\data\\hashscan"
URL_SCAN_DATA_PATH = ".\\data\\urlscan"
IP_SCAN_DATA_PATH = ".\\data\\ipscan"
DOMAIN_SCAN_DATA_PATH = ".\\data\\domainscan"

@dataclass
class ScanResult:
    '''
    スキャン結果を格納する構造体
    '''
    result_str:str
    detected: bool
    categories: list    #domain,URLのみ
    country:str
    negative:int
    positive: int
    total:int
    negative_votes:int
    positive_votes: int
    tags: list
    scans: dict
    id:str
    type:str
    whois:str           #domain,IPのみ
    recent_comment: list


class VtScanner:
    def __init__(self, is_premium=False):
        self.base_url = "https://www.virustotal.com/api/v3"
        self.last_request_time = None
        
        # プレミアムAPIかどうかでレート制限を設定
        self.is_premium = is_premium
        if is_premium:
            self.request_interval = 1.0  # プレミアム: 1秒間隔
        else:
            self.request_interval = 15.0  # 無料: 15秒間隔（1分間に4リクエスト）
        
        #アウトプットのディレクトリ作成
        os.makedirs(DATA_FOLDER_ROOT_PATH, exist_ok=True)
        os.makedirs(HASH_SCAN_DATA_PATH, exist_ok=True)
        os.makedirs(URL_SCAN_DATA_PATH, exist_ok=True)
        os.makedirs(IP_SCAN_DATA_PATH, exist_ok=True)
        os.makedirs(DOMAIN_SCAN_DATA_PATH, exist_ok=True)

    def _wait_for_rate_limit(self, show_progress=True):
        """
        レート制限に従って適切な間隔を空ける
        
        Args:
            show_progress (bool): 待機時間を表示するかどうか
        """
        if self.last_request_time is not None:
            elapsed = (datetime.now() - self.last_request_time).total_seconds()
            if elapsed < self.request_interval:
                wait_time = self.request_interval - elapsed
                if show_progress:
                    print(f"レート制限のため {wait_time:.1f}秒 待機中...")
                time.sleep(wait_time)
        
        self.last_request_time = datetime.now()

    def _make_api_request(self, url, headers, show_progress=True, timeout=30):
        """
        レート制限を考慮してAPIリクエストを行う
        
        Args:
            url (str): リクエストURL
            headers (dict): リクエストヘッダー
            show_progress (bool): 進捗を表示するかどうか
            timeout (int): タイムアウト時間（秒）
        
        Returns:
            requests.Response: APIレスポンス
        """
        self._wait_for_rate_limit(show_progress)
        
        try:
            response = requests.get(url, headers=headers, timeout=timeout)
            return response
        except requests.exceptions.Timeout:
            print(f"タイムアウトが発生しました: {url}")
            raise
        except requests.exceptions.RequestException as e:
            print(f"APIリクエストエラー: {e}")
            raise

    def get_file_list(self)->tuple[list[str],list[str]]:
        '''
        スキャン結果の保存先のファイル名と相対パスのタプルを返す
        '''
        file_fullpath_list = []
        file_fullpath_list_url = []
        file_fullpath_list_ip = []
        file_fullpath_list_domain = []
        file_list = os.listdir(HASH_SCAN_DATA_PATH)
        file_list_url = os.listdir(URL_SCAN_DATA_PATH)
        file_list_ip = os.listdir(IP_SCAN_DATA_PATH)
        file_list_domain = os.listdir(DOMAIN_SCAN_DATA_PATH)
        for filename in file_list:
            file_fullpath_list.append(os.path.join(HASH_SCAN_DATA_PATH,filename))
        for filename in file_list_url:
            file_fullpath_list_url.append(os.path.join(URL_SCAN_DATA_PATH,filename))
        for filename in file_list_ip:
            file_fullpath_list_ip.append(os.path.join(IP_SCAN_DATA_PATH,filename))
        for filename in file_list_domain:
            file_fullpath_list_domain.append(os.path.join(DOMAIN_SCAN_DATA_PATH,filename))            
        return (file_list,file_fullpath_list,file_fullpath_list_url,file_fullpath_list_ip,file_fullpath_list_domain)

    def check_id(self,id:str,type:int)->tuple[bool,str]:
        '''
        スキャン結果のidが一致するファイルの存在をチェックする。
        ファイルやURLはsha256に、IPならIPになる。
        type:1=file,2=url,3=ip,4=domain
        返り値はタプル、(存在有無をbool、存在した場合のフルパス)
        '''
        for file in self.get_file_list()[type]:
            try:
                with open(file,'r', encoding='utf-8') as f:
                    jsondata = json.load(f)
                    scanresult = self.jsonDataConverter(jsondata)
                if id == scanresult.id:
                    return (True,file)
                else:
                    continue
            except (json.JSONDecodeError, FileNotFoundError, UnicodeDecodeError) as e:
                print(f"ファイル読み込みエラー {file}: {e}")
                continue
        return (False,"")
  
    
    def jsonDataConverter(self,jsondata:dict)->ScanResult:
        '''
        読み込んだjsonファイルをScanResultにパースして返す。
        '''
        if jsondata:
            try:
                negative = jsondata["data"]["attributes"]["last_analysis_stats"]["malicious"]
                + jsondata["data"]["attributes"]["last_analysis_stats"]["suspicious"]
                positive = jsondata["data"]["attributes"]["last_analysis_stats"]["harmless"]
                + jsondata["data"]["attributes"]["last_analysis_stats"]["undetected"]
                
                if jsondata["data"]["type"] == "file":
                    categories = []
                    country = "-"
                    total = jsondata["data"]["attributes"]["last_analysis_stats"]["type-unsupported"] + negative + positive
                    whois = ""
                    recent_comment=[]
                elif jsondata["data"]["type"] == "domain":
                    categories_dict = jsondata["data"]["attributes"]["categories"]
                    categories = [value for value in categories_dict.values() if categories_dict]
                    country = "-"
                    total = jsondata["data"]["attributes"]["last_analysis_stats"]["undetected"] + negative + positive
                    try:
                        whois = jsondata["data"]["attributes"]["whois"]
                    except:
                        whois = "No Data"
                    try:
                        recent_comment= [i["attributes"]["text"] for i in jsondata["comments"]]
                    except:
                        recent_comment=[]
                elif jsondata["data"]["type"] == "url":
                    categories_dict = jsondata["data"]["attributes"]["categories"]
                    categories = [value for value in categories_dict.values() if categories_dict]
                    country = "-"
                    total = jsondata["data"]["attributes"]["last_analysis_stats"]["undetected"] + negative + positive
                    whois = ""
                    try:
                        recent_comment= [i["attributes"]["text"] for i in jsondata["comments"]]
                    except:
                        recent_comment=[]
                else:
                    categories = []
                    country = jsondata["data"]["attributes"]["country"]
                    total = jsondata["data"]["attributes"]["last_analysis_stats"]["undetected"] + negative + positive
                    try:
                        whois = jsondata["data"]["attributes"]["whois"]
                    except:
                        whois = "No Data"
                    try:
                        recent_comment= [i["attributes"]["text"] for i in jsondata["comments"]]
                    except:
                        recent_comment=[]
                        
                positive_votes:int = jsondata["data"]["attributes"]["total_votes"]["harmless"]
                negative_votes:int = jsondata["data"]["attributes"]["total_votes"]["malicious"]
                av_result:dict = jsondata["data"]["attributes"]["last_analysis_results"]
                
                return ScanResult(
                    "Detected" if negative > 0 else "Safe",
                    True if negative > 0 else False,
                    categories,
                    country,
                    negative,
                    positive,
                    total,
                    negative_votes,
                    positive_votes,
                    jsondata["data"]["attributes"]["tags"],
                    av_result,
                    jsondata["data"]["id"],
                    jsondata["data"]["type"],
                    whois,
                    recent_comment
                )
            except KeyError as e:
                print(f"JSONデータの解析エラー: {e}")
                return ScanResult(
                    "Error",
                    False,
                    [],
                    "-",
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    [],
                    {},
                    "",
                    "",
                    "",
                    []
                )
        else:
            return ScanResult(
                "Not found",
                False,
                [],
                "-",
                -1,
                -1,
                -1,
                -1,
                -1,
                [],
                {},
                "",
                "",
                "",
                []
            )

    def hashScanner(self,apikey:str,filename:str,hash:str,overwrite:bool, show_progress=True)->ScanResult:
        '''
        SHA256hashをIDとしたレポートを取得する。endpointはfile/{id}のみ
        
        Args:
            apikey (str): VirusTotalのAPIキー
            filename (str): 保存するファイル名
            hash (str): スキャンするハッシュ値
            overwrite (bool): 既存ファイルを上書きするかどうか
            show_progress (bool): 進捗を表示するかどうか
        '''
        headers = {"x-apikey": apikey}
        #Check Report
        report_check = self.check_id(hash,1)
        
        # 上書き設定がONなら既存チェックをオフに
        if overwrite:
            report_check = (False, "")
        
        output_filename = f"{HASH_SCAN_DATA_PATH}/{filename}.json"
        
        #既にスキャン済ファイルであれば、jsonファイルから読み出す
        if report_check[0]:
            if show_progress:
                print(f"キャッシュから読み込み: {hash}")
            with open(report_check[1],'r', encoding='utf-8') as f:
                jsondata = json.load(f)
                return self.jsonDataConverter(jsondata)
        else:
            if show_progress:
                print(f"APIからスキャン開始: {hash}")
                
            # URL for the VirusTotal API
            url_files = f"{self.base_url}/files/{hash}"
            url_behaviours = f"{self.base_url}/files/{hash}/behaviours"

            try:
                # Send the API request with rate limiting
                response_files = self._make_api_request(url_files, headers, show_progress)
                
                if response_files.status_code == 200:
                    # behavioursエンドポイントも取得（レート制限考慮）
                    response_behaviours = self._make_api_request(url_behaviours, headers, show_progress)
                    
                    result = response_files.json()
                    
                    # behavioursが取得できた場合のみ追加
                    if response_behaviours.status_code == 200:
                        result_behaviours = response_behaviours.json()
                        result["behaviours"] = result_behaviours
                    else:
                        result["behaviours"] = {"data": []}
                        if show_progress:
                            print(f"Behaviours取得失敗 (ステータス: {response_behaviours.status_code})")
                    
                    with open(output_filename, "w", encoding='utf-8') as outfile:
                        json.dump(result, outfile, ensure_ascii=False, indent=2)
                    
                    if show_progress:
                        print(f"スキャン完了: {hash}")
                    return self.jsonDataConverter(result)
                else:
                    if show_progress:
                        print(f"API呼び出し失敗 (ステータス: {response_files.status_code}): {hash}")
                    return self.jsonDataConverter({})
                    
            except requests.exceptions.RequestException as e:
                print(f"ネットワークエラー: {e}")
                return self.jsonDataConverter({})

    def ip_UrlScanner(self,apikey:str,ip_url:str,overwrite:bool=False, show_progress=True)->ScanResult:
        '''
        IP、URL、ドメイン、ハッシュ値をスキャンする統合メソッド
        
        Args:
            apikey (str): VirusTotalのAPIキー
            ip_url (str): スキャンする対象（IP、URL、ドメイン、ハッシュ）
            overwrite (bool): 既存ファイルを上書きするかどうか
            show_progress (bool): 進捗を表示するかどうか
        '''
        headers = {"x-apikey": apikey}
        
        # URLかIPアドレスかを判別する
        ip_pattern = r"^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"
        md5_pattern = r"^[a-fA-F0-9]{32}$"
        sha1_pattern = r"^[a-fA-F0-9]{40}$"
        sha256_pattern = r"^[a-fA-F0-9]{64}$"
        hostname_pattern = r"^(?!:\/\/)(?![0-9]+$)(?!-)[a-zA-Z0-9-]{1,63}(?<!-)(\.[a-zA-Z0-9-]{1,63})*$"
        
        try:
            if ip_url.startswith("http") or ip_url.startswith("https"):
                # URLの場合、URLのSHA-256ハッシュ値を取得する
                url_sha256 = hashlib.sha256(ip_url.encode('utf-8')).hexdigest()
                #既にスキャン済のファイルが存在するかのチェック
                report_exist = self.check_id(url_sha256,2)
                
                # 上書き設定がONなら既存チェックをオフに
                if overwrite:
                    report_exist = (False, "")
                
                if report_exist[0]:
                    if show_progress:
                        print(f"キャッシュから読み込み (URL): {ip_url}")
                    with open(report_exist[1],'r', encoding='utf-8') as f:
                        jsondata = json.load(f)
                        return self.jsonDataConverter(jsondata)
                else:
                    if show_progress:
                        print(f"APIからスキャン開始 (URL): {ip_url}")
                    
                    output_filename = f"{URL_SCAN_DATA_PATH}/{url_sha256}.json"
                    
                    # Virustotal APIを使用して、URLの情報を取得する
                    url_response = self._make_api_request(
                        self.base_url + "/urls/" + url_sha256, 
                        headers, 
                        show_progress
                    )
                    
                    if url_response.status_code == 200:
                        result_url = url_response.json()
                        #コメントを付与
                        result_url["comments"] = self.get_comments(apikey,"url",url_sha256, show_progress)
                        with open(output_filename, "w", encoding='utf-8') as outfile:
                            json.dump(result_url, outfile, ensure_ascii=False, indent=2)
                        
                        if show_progress:
                            print(f"スキャン完了 (URL): {ip_url}")
                        return self.jsonDataConverter(result_url)
                    else:
                        if show_progress:
                            print(f"API呼び出し失敗 (URL, ステータス: {url_response.status_code}): {ip_url}")
                        return self.jsonDataConverter({})
                        
            elif re.match(ip_pattern,ip_url):
                # IPアドレスの場合、IPアドレスの情報を取得する
                #既にスキャン済のファイルが存在するかのチェック
                report_exist = self.check_id(ip_url,3)
                
                # 上書き設定がONなら既存チェックをオフに
                if overwrite:
                    report_exist = (False, "")
                
                if report_exist[0]:
                    if show_progress:
                        print(f"キャッシュから読み込み (IP): {ip_url}")
                    with open(report_exist[1],'r', encoding='utf-8') as f:
                        jsondata = json.load(f)
                        return self.jsonDataConverter(jsondata)
                else:
                    if show_progress:
                        print(f"APIからスキャン開始 (IP): {ip_url}")
                    
                    output_filename = f"{IP_SCAN_DATA_PATH}/{ip_url}.json"
                    ip_response = self._make_api_request(
                        self.base_url + "/ip_addresses/" + ip_url, 
                        headers, 
                        show_progress
                    )
                    
                    if ip_response.status_code == 200:
                        result_ip = ip_response.json()
                        #コメントを付与
                        result_ip["comments"] = self.get_comments(apikey,"ip",ip_url, show_progress)                                 
                        with open(output_filename, "w", encoding='utf-8') as outfile:
                            json.dump(result_ip, outfile, ensure_ascii=False, indent=2)
                        
                        if show_progress:
                            print(f"スキャン完了 (IP): {ip_url}")
                        return self.jsonDataConverter(result_ip)
                    else:
                        if show_progress:
                            print(f"API呼び出し失敗 (IP, ステータス: {ip_response.status_code}): {ip_url}")
                        return self.jsonDataConverter({})
                        
            elif re.match(md5_pattern,ip_url) or re.match(sha1_pattern,ip_url) or re.match(sha256_pattern,ip_url):
                #Hash値の場合
                return self.hashScanner(apikey,ip_url,ip_url,overwrite, show_progress)

            elif re.match(hostname_pattern,ip_url):
                #ドメインの場合
                #既にスキャン済のファイルが存在するかのチェック
                report_exist = self.check_id(ip_url,4)
                
                # 上書き設定がONなら既存チェックをオフに
                if overwrite:
                    report_exist = (False, "")
                
                if report_exist[0]:
                    if show_progress:
                        print(f"キャッシュから読み込み (Domain): {ip_url}")
                    with open(report_exist[1],'r', encoding='utf-8') as f:
                        jsondata = json.load(f)                    
                        return self.jsonDataConverter(jsondata)
                else:
                    if show_progress:
                        print(f"APIからスキャン開始 (Domain): {ip_url}")
                    
                    output_filename = f"{DOMAIN_SCAN_DATA_PATH}/{ip_url}.json"
                    domain_response = self._make_api_request(
                        self.base_url + "/domains/" + ip_url, 
                        headers, 
                        show_progress
                    )
                    
                    if domain_response.status_code == 200:
                        result_domain = domain_response.json()
                        #コメントを付与
                        result_domain["comments"] = self.get_comments(apikey,"domain",ip_url, show_progress)                    
                        with open(output_filename, "w", encoding='utf-8') as outfile:
                            json.dump(result_domain, outfile, ensure_ascii=False, indent=2)
                        
                        if show_progress:
                            print(f"スキャン完了 (Domain): {ip_url}")
                        return self.jsonDataConverter(result_domain)
                    else:
                        if show_progress:
                            print(f"API呼び出し失敗 (Domain, ステータス: {domain_response.status_code}): {ip_url}")
                        return self.jsonDataConverter({})
            
            else:
                #該当しない文字列の場合は、空の辞書を与える
                if show_progress:
                    print(f"不正な形式: {ip_url}")
                return self.jsonDataConverter({})
                
        except requests.exceptions.RequestException as e:
            print(f"ネットワークエラー ({ip_url}): {e}")
            return self.jsonDataConverter({})

    def get_comments(self,api_key:str,type:str,id:str, show_progress=True)->list[dict]:
        '''
        typeを指定し、対応するエンドポイントにてコメントを取得する。
        typeはurl,ip,domain,fileのいずれか
        
        Args:
            api_key (str): VirusTotalのAPIキー
            type (str): オブジェクトタイプ
            id (str): オブジェクトID
            show_progress (bool): 進捗を表示するかどうか
        '''
        url = ""
        if type == "url":
            url = f'{self.base_url}/urls/{id}/comments'
        elif type == "ip":
            url = f'{self.base_url}/ip_addresses/{id}/comments'
        elif type == "domain":
            url = f'{self.base_url}/domains/{id}/comments'
        elif type == "file":
            url = f'{self.base_url}/files/{id}/comments'
        
        if not url:
            return [{}]
        
        headers = {
            'x-apikey': api_key
        }
        
        try:
            response = self._make_api_request(url, headers, show_progress)
            if response.status_code == 200:
                return response.json()["data"]
            else:
                if show_progress:
                    print(f"コメント取得失敗 (ステータス: {response.status_code})")
                return [{}]
        except requests.exceptions.RequestException as e:
            print(f"コメント取得エラー: {e}")
            return [{}]
        
    def chromeHistoryExtractor(self):
        '''
        Chromeの履歴を抽出する（既存のメソッド）
        '''
        # Chromeの履歴データベースのパスを取得
        #r'\\AppData\\Local\\Google\\Chrome\\User Data\\Default'
        data_path_ch = os.path.expanduser('~') + r'\\Desktop'
        history_db_ch = os.path.join(data_path_ch, 'History')
        if not os.path.isfile(history_db_ch):
            raise Exception("Chrome history database not found")
        # 履歴データベースに接続
        with sqlite3.connect(history_db_ch) as c:
            cursor = c.cursor()
        # urlsテーブルから必要な情報を取得
        select_statement = "SELECT urls.url, urls.title, visits.visit_time FROM urls, visits WHERE urls.id = visits.url;"
        sql = 'SELECT url, title FROM urls ORDER BY last_visit_time DESC LIMIT 20'
        #cursor.execute(select_statement)
        cursor.execute(sql)
        # カラム名を取得
        columns = [description[0] for description in cursor.description]

        try:
            # 結果を出力
            results = cursor.fetchall()

            if results is not None:
                # カラム名を出力
                print(columns,'colums')

            # 結果を出力
            n = 0
            for row in results:
                n +=1
                print(n,row)
            else:
                print("No history found in Chrome.")
            
            cursor.close()
        except TypeError:
            print("Error: Failed to fetch history from Chrome database.")

    def get_rate_limit_info(self):
        '''
        現在のレート制限設定を取得する
        
        Returns:
            dict: レート制限情報
        '''
        return {
            "is_premium": self.is_premium,
            "request_interval": self.request_interval,
            "last_request_time": self.last_request_time.isoformat() if self.last_request_time else None
        }

    def estimate_scan_time(self, target_count):
        '''
        スキャン予定時間を推定する
        
        Args:
            target_count (int): スキャン対象数
            
        Returns:
            dict: 推定時間情報
        '''
        total_seconds = target_count * self.request_interval
        minutes = int(total_seconds // 60)
        seconds = int(total_seconds % 60)
        
        return {
            "total_seconds": total_seconds,
            "minutes": minutes,
            "seconds": seconds,
            "formatted": f"{minutes}分{seconds}秒" if minutes > 0 else f"{seconds}秒"
        }