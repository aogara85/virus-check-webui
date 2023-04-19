import json
import re
import sqlite3
import requests
import os
from dataclasses import dataclass


#make name of data folder
DATA_FOLDER_ROOT_PATH = ".\\data"
HASH_SCAN_DATA_PATH = ".\\data\\hashscan"
URL_SCAN_DATA_PATH = ".\\data\\urlscan"
IP_SCAN_DATA_PATH = ".\\data\\ipscan"

@dataclass
class ScanResult:
    '''
    スキャン結果を格納する構造体
    '''
    result_str:str
    detected: bool
    negative:int
    positive: int
    total:int
    negative_votes:int
    positive_votes: int
    tags: list
    scans: dict
    id:str

class VtScanner:
    def __init__(self):
        self.base_url = "https://www.virustotal.com/api/v3"
        #アウトプットのディレクトリ作成
        if not os.path.exists(DATA_FOLDER_ROOT_PATH):
            os.mkdir(DATA_FOLDER_ROOT_PATH)
            os.mkdir(HASH_SCAN_DATA_PATH)
            os.mkdir(URL_SCAN_DATA_PATH)
            os.mkdir(IP_SCAN_DATA_PATH)

    def get_file_list(self)->tuple[list[str],list[str]]:
        '''
        スキャン結果の保存先のファイル名と相対パスのタプルを返す
        '''
        file_fullpath_list = []
        file_list = os.listdir(HASH_SCAN_DATA_PATH)
        for filename in file_list:
            file_fullpath_list.append(os.path.join(HASH_SCAN_DATA_PATH,filename))
        return (file_list,file_fullpath_list)

    def check_file_by_hash(self,hash_value)->tuple[bool,str]:
        '''
        スキャン結果のsha256が一致するファイルの存在をチェックする。
        '''
        for file in self.get_file_list()[1]:
            scanresult = self.jsonDataConverter(file)
            if hash_value == scanresult.id:
                return (True,file)
            else:
                continue
        return (False,"")
  
    
    def jsonDataConverter(self,json_data)->ScanResult:
        '''
        読み込んだjsonファイルをScanResultにパースして返す。
        '''
        with open(json_data, "r") as f:
            jsondata = json.load(f)
            negative = jsondata["data"]["attributes"]["last_analysis_stats"]["malicious"]
            + jsondata["data"]["attributes"]["last_analysis_stats"]["suspicious"]
            positive = jsondata["data"]["attributes"]["last_analysis_stats"]["harmless"]
            + jsondata["data"]["attributes"]["last_analysis_stats"]["undetected"]
            total = jsondata["data"]["attributes"]["last_analysis_stats"]["type-unsupported"] + negative + positive
            positive_votes:int = jsondata["data"]["attributes"]["total_votes"]["harmless"]
            negative_votes:int = jsondata["data"]["attributes"]["total_votes"]["malicious"]
            av_result:dict = jsondata["data"]["attributes"]["last_analysis_results"]
            return ScanResult(
                "Detected" if negative > 0 else "Safe",
                True if negative > 0 else False,
                negative,
                positive,
                total,
                negative_votes,
                positive_votes,
                jsondata["data"]["attributes"]["tags"],
                av_result,
                jsondata["data"]["id"]
            )
        
    def hashScanner(self,apikey:str,filename:str,hash:str,overwrite:bool)->ScanResult:
        '''
        SHA256hashをIDとしたレポートを取得する。endpointはfile/{id}のみ
        '''
        headers = {"x-apikey": apikey}
        #Check Report
        report_check = self.check_file_by_hash(hash)
        #既にスキャン済ファイルがあったとしても上書き設定がONならcheckをオフに。
        if overwrite == True:
            report_check[0] = False
        output_filename = f"{HASH_SCAN_DATA_PATH}/{filename}.json"
        #既にスキャン済ファイルであれば、jsonファイルから読み出す。
        if report_check[0] :
            return self.jsonDataConverter(report_check[1])
        else:
            # URL for the VirusTotal API
            url_files = f"{self.base_url}/files/{hash}"
            url_behaviours = f"{self.base_url}/files/{hash}/behaviours"

            # Send the API request
            response_files = requests.get(url_files, headers=headers)
            response_behaviours = requests.get(url_behaviours, headers=headers)

            #Check the response_files
            if response_files.status_code == 200 and response_behaviours.status_code == 200:
                result = response_files.json()
                #behavioursエンドポイントの処理
                result_behaviours = response_behaviours.json()
                result["behaviours"] = result_behaviours
                with open(output_filename, "w") as outfile:
                    json.dump(result, outfile)
                #filesエンドポイントの処理
                negative = result["data"]["attributes"]["last_analysis_stats"]["malicious"]
                + result["data"]["attributes"]["last_analysis_stats"]["suspicious"]
                positive = result["data"]["attributes"]["last_analysis_stats"]["harmless"]
                + result["data"]["attributes"]["last_analysis_stats"]["undetected"]
                total = result["data"]["attributes"]["last_analysis_stats"]["type-unsupported"] + negative + positive
                positive_votes:int = result["data"]["attributes"]["total_votes"]["harmless"]
                negative_votes:int = result["data"]["attributes"]["total_votes"]["malicious"]
                av_result:dict = result["data"]["attributes"]["last_analysis_results"]

                return ScanResult(
                    "Detected" if negative > 0 else "Safe",
                    True if negative > 0 else False,
                    negative,
                    positive,
                    total,
                    negative_votes,
                    positive_votes,
                    result["data"]["attributes"]["tags"],
                    av_result,
                    result["data"]["id"]                    
                )
            else:
                return ScanResult(
                    "Not found",
                    False,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    [],
                    {},
                    ""
                )

    def ipScanner(self,apikey:str):
        headers = {"x-apikey": apikey}

    def chromeHistoryExtractor(self):
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
        cursor.execute(select_statement)

        # カラム名を取得
        columns = [description[0] for description in cursor.description]

        try:
            # 結果を出力
            results = cursor.fetchall()

            if results is not None:
                # カラム名を出力
                print(columns,'colums')

            # 結果を出力
            for row in results:
                print(row,'row')
            else:
                print("No history found in Chrome.")
        except TypeError:
            print("Error: Failed to fetch history from Chrome database.")