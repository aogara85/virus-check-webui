from __future__ import annotations
import requests
import json
import os
from dataclasses import dataclass, field
from typing import List, Optional

# データフォルダのパス設定
DATA_FOLDER_ROOT_PATH = ".\\data"
MB_SCAN_DATA_PATH = ".\\data\\mbscan"

@dataclass
class MBScanResult:
    """
    Malware Bazaarのスキャン結果を格納する構造体
    """
    query_status: str
    detected: bool = False
    sha256_hash: Optional[str] = None
    sha1_hash: Optional[str] = None
    md5_hash: Optional[str] = None
    signature: Optional[str] = None
    file_type: Optional[str] = None
    file_type_mime: Optional[str] = None
    file_name: Optional[str] = None
    file_size: Optional[int] = None
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    reporter: Optional[str] = None
    anonymous: Optional[int] = None
    imphash: Optional[str] = None
    tlsh: Optional[str] = None
    ssdeep: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    intelligence: dict = field(default_factory=dict)
    error_message: Optional[str] = None

class MBScanner:
    def __init__(self, api_key: str):
        """
        MBScannerを初期化
        
        Args:
            api_key (str): MalwareBazaarのAPIキー
        """
        self.base_url = "https://mb-api.abuse.ch/api/v1/"
        self.api_key = api_key
        self.headers = {
            'Auth-Key': self.api_key
        }
        
        # アウトプットのディレクトリ作成
        if not os.path.exists(DATA_FOLDER_ROOT_PATH):
            os.mkdir(DATA_FOLDER_ROOT_PATH)
        if not os.path.exists(MB_SCAN_DATA_PATH):
            os.mkdir(MB_SCAN_DATA_PATH)

    def get_file_list(self) -> List[str]:
        """
        スキャン結果の保存先のファイル名とフルパスのリストを返す
        """
        file_fullpath_list = []
        if os.path.exists(MB_SCAN_DATA_PATH):
            file_list = os.listdir(MB_SCAN_DATA_PATH)
            for filename in file_list:
                file_fullpath_list.append(os.path.join(MB_SCAN_DATA_PATH, filename))
        return file_fullpath_list

    def check_id(self, hash_value: str) -> tuple[bool, str]:
        """
        スキャン結果のhash値が一致するファイルの存在をチェックする。
        返り値はタプル（存在有無をbool、存在した場合のフルパス）
        """
        for file in self.get_file_list():
            try:
                with open(file, 'r', encoding='utf-8') as f:
                    jsondata = json.load(f)
                    if jsondata.get("query_status") == "ok" and jsondata.get("data"):
                        scan_data = jsondata["data"][0]
                        # SHA256, SHA1, MD5のいずれかが一致するかチェック
                        if (hash_value.lower() == scan_data.get("sha256_hash", "").lower() or
                            hash_value.lower() == scan_data.get("sha1_hash", "").lower() or
                            hash_value.lower() == scan_data.get("md5_hash", "").lower()):
                            return (True, file)
            except (json.JSONDecodeError, KeyError, FileNotFoundError):
                continue
        return (False, "")

    def jsonDataConverter(self, jsondata: dict) -> MBScanResult:
        """
        読み込んだjsonファイルをMBScanResultにパースして返す。
        """
        if jsondata and jsondata.get("query_status") == "ok" and jsondata.get("data"):
            scan_data = jsondata["data"][0]
            return MBScanResult(
                query_status="ok",
                detected=True,
                sha256_hash=scan_data.get("sha256_hash"),
                sha1_hash=scan_data.get("sha1_hash"),
                md5_hash=scan_data.get("md5_hash"),
                signature=scan_data.get("signature"),
                file_type=scan_data.get("file_type"),
                file_type_mime=scan_data.get("file_type_mime"),
                file_name=scan_data.get("file_name"),
                file_size=scan_data.get("file_size"),
                first_seen=scan_data.get("first_seen"),
                last_seen=scan_data.get("last_seen"),
                reporter=scan_data.get("reporter"),
                anonymous=scan_data.get("anonymous"),
                imphash=scan_data.get("imphash"),
                tlsh=scan_data.get("tlsh"),
                ssdeep=scan_data.get("ssdeep"),
                tags=scan_data.get("tags", []),
                intelligence=scan_data.get("intelligence", {})
            )
        elif jsondata and jsondata.get("query_status") == "hash_not_found":
            return MBScanResult(query_status="hash_not_found", detected=False)
        else:
            return MBScanResult(
                query_status="error",
                detected=False,
                error_message=jsondata.get("query_status", "Unknown error") if jsondata else "No data"
            )

    def hash_scanner(self, hash_value: str, overwrite: bool = False) -> MBScanResult:
        """
        ファイルハッシュをMalware Bazaarに照会する
        
        Args:
            hash_value (str): 検索するハッシュ値
            overwrite (bool): 既存ファイルを上書きするかどうか
        """
        # 既存ファイルのチェック
        report_check = self.check_id(hash_value)
        
        # 上書き設定がONなら既存チェックをオフに
        if overwrite:
            report_check = (False, "")
        
        output_filename = f"{MB_SCAN_DATA_PATH}/{hash_value}.json"
        
        # 既にスキャン済ファイルであれば、jsonファイルから読み出す
        if report_check[0]:
            with open(report_check[1], 'r', encoding='utf-8') as f:
                jsondata = json.load(f)
                return self.jsonDataConverter(jsondata)
        else:
            data = {
                'query': 'get_info',
                'hash': hash_value,
            }

            try:
                response = requests.post(self.base_url, data=data, headers=self.headers, timeout=15)
                response.raise_for_status()  # HTTPエラーがあれば例外を発生させる

                json_response = response.json()

                # レスポンスをファイルに保存
                with open(output_filename, "w", encoding='utf-8') as outfile:
                    json.dump(json_response, outfile, ensure_ascii=False, indent=2)

                return self.jsonDataConverter(json_response)

            except requests.exceptions.RequestException as e:
                error_response = {
                    "query_status": "error",
                    "error_message": f"API request failed: {e}"
                }
                # エラーレスポンスもファイルに保存
                with open(output_filename, "w", encoding='utf-8') as outfile:
                    json.dump(error_response, outfile, ensure_ascii=False, indent=2)
                
                return MBScanResult(
                    query_status="error",
                    detected=False,
                    error_message=f"API request failed: {e}"
                )