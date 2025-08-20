import json
import os
import binascii
import time
import hashlib
import streamlit as st
import pandas as pd
from vt_scanner import VtScanner
from vt_scanner import ScanResult
import matplotlib.pyplot as plt
from generalReport import ReportGenerator
from abucelpdbScan import AbuseIPDBChecker
from mb_scanner import MBScanner, MBScanResult
from datetime import datetime
import matplotlib.pyplot as plt

# ページ設定（最初に設定）
st.set_page_config(
    page_title="VT Scanner",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Streamlit設定の最適化
@st.cache_data
def load_file_list():
    """ファイルリストをキャッシュ"""
    scanner = VtScanner()
    return scanner.get_file_list()

@st.cache_data
def load_json_file(file_path):
    """JSONファイルの読み込みをキャッシュ"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        st.error(f"ファイル読み込みエラー: {e}")
        return None

@st.cache_data
def process_all_files(file_list, scan_type):
    """全ファイルの処理をキャッシュ"""
    scanner = VtScanner()
    all_results = []
    detection_stats = {"Detected": 0, "Safe": 0, "Error": 0}
    
    # プログレスバーの表示
    progress_bar = st.progress(0)
    status_text = st.empty()
    
    for i, file_path in enumerate(file_list):
        try:
            status_text.text(f"ファイル読み込み中... {i+1}/{len(file_list)}")
            
            jsondata = load_json_file(file_path)
            if jsondata is None:
                continue
                
            read_result = scanner.jsonDataConverter(jsondata)
            filename = os.path.basename(file_path).replace('.json', '')
            
            # 統計情報の集計
            result_status = read_result.result_str
            if result_status in detection_stats:
                detection_stats[result_status] += 1
            else:
                detection_stats["Error"] += 1
            
            # 結果の構築（スキャンタイプに応じて）
            if scan_type == "file":
                result_data = {
                    'ファイル名': filename,
                    '結果': read_result.result_str,
                    '検出数': read_result.negative,
                    '正常判定': read_result.positive,
                    'ポジティブ投票': read_result.positive_votes,
                    'ネガティブ投票': read_result.negative_votes,
                    'タグ数': len(read_result.tags),
                    'コメント有無': len(read_result.recent_comment) > 0
                }
            elif scan_type == "url":
                result_data = {
                    'URL SHA256': filename,
                    '結果': read_result.result_str,
                    '検出数': read_result.negative,
                    '正常判定': read_result.positive,
                    'ポジティブ投票': read_result.positive_votes,
                    'ネガティブ投票': read_result.negative_votes,
                    'カテゴリ数': len(read_result.categories),
                    'タグ数': len(read_result.tags),
                    'コメント有無': len(read_result.recent_comment) > 0
                }
            elif scan_type == "ip":
                result_data = {
                    'IPアドレス': filename,
                    '結果': read_result.result_str,
                    '検出数': read_result.negative,
                    '正常判定': read_result.positive,
                    'ポジティブ投票': read_result.positive_votes,
                    'ネガティブ投票': read_result.negative_votes,
                    '国': read_result.country,
                    'タグ数': len(read_result.tags),
                    'コメント有無': len(read_result.recent_comment) > 0
                }
            elif scan_type == "domain":
                result_data = {
                    'ドメイン': filename,
                    '結果': read_result.result_str,
                    '検出数': read_result.negative,
                    '正常判定': read_result.positive,
                    'ポジティブ投票': read_result.positive_votes,
                    'ネガティブ投票': read_result.negative_votes,
                    'カテゴリ数': len(read_result.categories),
                    'タグ数': len(read_result.tags),
                    'コメント有無': len(read_result.recent_comment) > 0
                }
            
            all_results.append(result_data)
            
        except Exception as e:
            st.warning(f"ファイル {file_path} の読み込みに失敗しました: {e}")
            detection_stats["Error"] += 1
        
        # プログレスバーの更新（10件ごとに更新して負荷軽減）
        if i % 10 == 0 or i == len(file_list) - 1:
            progress_bar.progress((i + 1) / len(file_list))
    
    status_text.text("完了")
    progress_bar.empty()
    status_text.empty()
    
    return all_results, detection_stats

# pandas バージョン互換性のためのヘルパー関数
def safe_style_map(styler, func, subset=None):
    """pandas バージョンに応じてmapまたはapplymapを使用"""
    try:
        # pandas 2.1.0以降
        if subset:
            return styler.map(func, subset=subset)
        else:
            return styler.map(func)
    except AttributeError:
        # pandas 2.1.0未満
        if subset:
            return styler.applymap(func, subset=subset)
        else:
            return styler.applymap(func)

def vtScannerResultvView(score):
    if type(score) == int and score > 0 :
        change_color = 'color : red'
    elif type(score) == int and score == 0:
        change_color = 'color :green'
    elif type(score) == str and score == 'Detected':
        change_color = 'color : red'
    elif type(score) == str and score == 'Safe':
        change_color = 'color :green'
    else :
        change_color = ''
    return change_color

def highlight_not_none(val):
    if val is None:
        return ""
    elif val == "type-unsupported" or val == "timeout":
        return ""
    elif val == "undetected" or val == "harmless" or val == "clean":
        return "color : green"
    elif val == "malicious":
        return 'color : red'
    elif val =="suspicious" or val == "spam":
        return 'color : orange'
    elif val == "phishing":
        return "background-color: yellow"
    elif val == "malware":
        return "background-color: red"
    else:
        return ""

def create_pie_chart(detection_stats):
    """円グラフ作成の共通関数"""
    non_zero_stats = {k: v for k, v in detection_stats.items() if v > 0}
    
    if non_zero_stats:
        labels = list(non_zero_stats.keys())
        values = list(non_zero_stats.values())
        colors = []
        explode = []
        
        for label in labels:
            if label == "Detected":
                colors.append('#FF0000')
                explode.append(0.1)
            elif label == "Safe":
                colors.append('#228B22')
                explode.append(0)
            else:
                colors.append('#FFA500')
                explode.append(0)
        
        fig, ax = plt.subplots(figsize=(6, 6))
        ax.pie(values, colors=colors, labels=labels, autopct='%1.1f%%', 
              explode=explode, textprops={'color': 'white'})
        ax.axis("equal")
        fig.set_facecolor('none')
        st.pyplot(fig)
        
        # 数値表示
        st.subheader("詳細数値")
        for label, value in non_zero_stats.items():
            percentage = (value / sum(values)) * 100
            st.write(f"**{label}**: {value}件 ({percentage:.1f}%)")

def filehash_scan_page():
    st.title("FileHashscan")
    api_key = st.text_input('set APIKEY','')
    st.write('APYKEY is ',api_key) 
    exist_file_not_scan = st.radio("既にスキャンしたファイルの処理を選んでください", ["結果を再表示", "スキャン結果を上書きする"])
    overwrite =False
    if exist_file_not_scan == "スキャン結果を上書きする":
        overwrite =True
    else:
        overwrite =False
    # フォルダ選択ダイアログを表示
    file_path_list = st.file_uploader("Select a folder", accept_multiple_files=True)
    file_hash_dict = {}
    for file in file_path_list:
        file_contents = file.read()
        hash_func = hashlib.sha256()
        hash_func.update(file_contents)
        hash_value = hash_func.hexdigest()
        file_magic_number = binascii.hexlify(file_contents[:4]).decode('utf-8')
        file_hash_dict[file.name] = [hash_value,file_magic_number]
        file_hash_dict.update()
    
    df = pd.DataFrame.from_dict(file_hash_dict, orient='index', columns=['Hash','Magic Number'])
    df.index.name = 'File Name'
    st.write(df)
    file_scaned_dict = {}
    if st.button('Scan Start'):
        if bool(file_hash_dict):
            # プログレスバー表示
            progress_bar = st.sidebar.progress(0)
            status_text = st.sidebar.empty()
            
            # 推定時間を表示
            estimated_time = len(file_hash_dict) * 15  # 秒
            st.info(f"推定処理時間: 約 {estimated_time // 60}分 {estimated_time % 60}秒")
            
            n = 1
            for k, v in file_hash_dict.items():
                scanner = VtScanner()
                
                # status_textで現在の処理とレート制限情報を表示
                status_text.text(f"処理中: {k} ({n}/{len(file_hash_dict)})")
                
                result: ScanResult = scanner.hashScanner(api_key, k, v[0], overwrite)
                file_scaned_dict[k] = [result.result_str, result.negative, result.positive, result.negative_votes]
                
                progress_bar.progress(n / len(file_hash_dict))
                n += 1
                
                # time.sleep(0.1) を削除（VtScannerクラス内で制御）
            
            status_text.text("完了")
            st.markdown('''
            - Result        :アンチウイルスソフトによる結果
            - Negative Score:アンチウイルスソフトの検知数
            - +votes        :コミュニティのポジティブな投票
            - -votes        :コミュニティのネガティブな投票
            ''')
            df2 = pd.DataFrame.from_dict(file_scaned_dict, orient='index', columns=['Result','Negative Score','+votes','-votes'])
            df2.index.name = 'File Name'
        # データフレームを表示
            styled_df = safe_style_map(df2.style, vtScannerResultvView)
            st.write(styled_df)
        #円グラフを描画
            labels = ["Detected", "Not found", "Safe"]
            label_color = ['#FF0000','#D6C6AF','#228B22']
            values = [(df2 == 'Detected').values.sum(), (df2 == 'Not found').values.sum(), (df2 == 'Safe').values.sum()]
            fig, ax = plt.subplots()
            ax.pie(values,colors=label_color ,labels=labels, autopct='%1.1f%%',explode=[0.2,0,0],textprops={'color': 'white'})
            ax.axis("equal")
            fig.set_facecolor('none')
            st.pyplot(fig)
        else:
            pass

def url_scan_page():
    st.title("DOMAIN / URL / IP Scan")
    api_key = st.text_input('set APIKEY','')
    st.write('APYKEY is ',api_key)
    
    # 既存ファイルの処理オプション
    exist_file_not_scan = st.radio("既にスキャンしたファイルの処理を選んでください", ["結果を再表示", "スキャン結果を上書きする"])
    overwrite = exist_file_not_scan == "スキャン結果を上書きする"
    
    ips_urls = st.text_area("スキャンするDOMAIN、IP、URL、Hash値を入力してください。", "")
    if st.button('Scan Start'):
        ips_urls_list =ips_urls.split("\n")
        scanner = VtScanner()
        result_dict = {}
        #コメント用
        comment_dict = {}
        if ips_urls_list:
            #プログレスバーをサイドバーに表示
            progress_bar = st.sidebar.progress(0)
            status_text = st.sidebar.empty()
            n = 1
            for ip_url in ips_urls_list:
                comment_tf = bool
                result = scanner.ip_UrlScanner(api_key, ip_url.strip(), overwrite)

                if result.recent_comment:
                    comment_dict[ip_url.strip()] = result.recent_comment
                    comment_tf=True
                else:
                    comment_tf=False                
                result_dict[ip_url.strip()] = [result.result_str,result.negative,result.positive_votes,result.negative_votes,result.country,result.tags,comment_tf,result.categories]
                progress_bar.progress(n / len(ips_urls_list))
                status_text.text(f"処理中... {n * 100 // len(ips_urls_list)}%")
                n += 1
                time.sleep(0.1)
            status_text.text("完了")                    
        st.markdown('''
        - Result        :アンチウイルスソフトによる結果
        - Negative Score:アンチウイルスソフトの検知数
        - +votes        :コミュニティのポジティブな投票
        - -votes        :コミュニティのネガティブな投票
        ''')
        # レポート生成
        generator = ReportGenerator()
        html_report = generator.generate_html_report(result_dict)
        
        # HTMLファイルとして保存
        with open("report.html", "w", encoding="utf-8") as f:
            f.write(html_report)        
        df = pd.DataFrame.from_dict(result_dict, orient='index', columns=['Result','Negative Score','+votes','-votes','country','tags','comment','categories'])
        df.index.name = 'Target'
        styled_df = safe_style_map(df.style, vtScannerResultvView)
        st.write(styled_df)
        tab1, tab2 = st.tabs(["Summary", "Comments"])
        #円グラフを描画
        with tab1:
            labels = ["Detected", "Not found", "Safe"]
            label_color = ['#FF0000','#D6C6AF','#228B22']
            values = [(df == 'Detected').values.sum(), (df == 'Not found').values.sum(), (df == 'Safe').values.sum()]
            fig, ax = plt.subplots()
            ax.pie(values,colors=label_color ,labels=labels, autopct='%1.1f%%',textprops={'color': 'white'})
            ax.axis("equal")
            fig.set_facecolor('none')
            st.pyplot(fig)
        with tab2:
            st.write(comment_dict)

def abuseipdb_scan_page():
    st.title("AbuseIPDB Scan")
    api_key = st.text_input('set APIKEY','')
    st.write('APIKEY is ',api_key)
    
    # 既存ファイルの処理オプション
    exist_file_not_scan = st.radio("既にスキャンしたファイルの処理を選んでください", ["結果を再表示", "スキャン結果を上書きする"])
    overwrite = exist_file_not_scan == "スキャン結果を上書きする"
    
    ips = st.text_area("スキャンするIPアドレスを入力してください。", "")
    if st.button('Scan Start'):
        ip_list = ips.split("\n")
        checker = AbuseIPDBChecker(api_key)
        result_list = []
        if ip_list:
            progress_bar = st.sidebar.progress(0)
            status_text = st.sidebar.empty()
            n = 1
            for ip in ip_list:
                if ip.strip():
                    result = checker.check_ip(ip.strip(), overwrite=overwrite)
                    if "data" in result:
                        result_list.append(result["data"])
                progress_bar.progress(n / len(ip_list))
                status_text.text(f"処理中... {n * 100 // len(ip_list)}%")
                n += 1
                time.sleep(0.1)
            status_text.text("完了")
        if result_list:
            df = pd.DataFrame(result_list)
            st.write(df)

            #円グラフを描画
            labels = ["Detected", "Safe"]
            label_color = ['#FF0000','#228B22']
            detected_count = df[df['abuseConfidenceScore'] > 0].shape[0]
            safe_count = df[df['abuseConfidenceScore'] == 0].shape[0]
            values = [detected_count, safe_count]

            fig, ax = plt.subplots()
            ax.pie(values,colors=label_color ,labels=labels, autopct='%1.1f%%',explode=[0.2,0],textprops={'color': 'white'})
            ax.axis("equal")
            fig.set_facecolor('none')
            st.pyplot(fig)

def malware_bazaar_scan_page():
    st.title("Malware Bazaar Scan")
    # APIキー入力フィールドを追加
    api_key = st.text_input('set APIKEY','')
    st.write('APIKEY is ',api_key)
    
    # 既存ファイルの処理オプション
    exist_file_not_scan = st.radio("既にスキャンしたファイルの処理を選んでください", ["結果を再表示", "スキャン結果を上書きする"])
    overwrite = exist_file_not_scan == "スキャン結果を上書きする"
    
    hashes = st.text_area("スキャンするHash値を入力してください。", "")
    if st.button('Scan Start'):
        if not api_key:
            st.error("APIキーを入力してください。")
            return
        
        hash_list = hashes.split("\n")
        scanner = MBScanner(api_key)  # APIキーを渡す
        result_list = []
        if hash_list:
            progress_bar = st.sidebar.progress(0)
            status_text = st.sidebar.empty()
            n = 1
            for h in hash_list:
                if h.strip():
                    result = scanner.hash_scanner(h.strip(), overwrite)
                    result_list.append(result)
                progress_bar.progress(n / len(hash_list))
                status_text.text(f"処理中... {n * 100 // len(hash_list)}%")
                n += 1
                time.sleep(0.1)
            status_text.text("完了")
        
        if result_list:
            st.markdown('''
            - Query Status  : APIクエリの状況
            - Detected      : マルウェアとして検出されたかどうか
            - Signature     : マルウェアファミリー名
            - File Type     : ファイルタイプ
            - First Seen    : 初回発見日時
            - Tags          : 関連タグ
            ''')
            
            # 結果をDataFrameに変換して表示
            df_data = []
            for result in result_list:
                df_data.append({
                    'Query Status': result.query_status,
                    'Detected': result.detected,
                    'SHA256': result.sha256_hash or '-',
                    'Signature': result.signature or '-',
                    'File Type': result.file_type or '-',
                    'First Seen': result.first_seen or '-',
                    'Tags': ', '.join(result.tags) if result.tags else '-',
                    'Error': result.error_message or '-'
                })
            
            df = pd.DataFrame(df_data)
            
            # カラーリング関数
            def mb_result_view(val):
                if val == True:  # Detected
                    return 'color: red'
                elif val == False and df.loc[df['Detected'] == val, 'Query Status'].iloc[0] == 'hash_not_found':
                    return 'color: green'
                elif val == 'ok':
                    return 'color: green'
                elif val == 'error':
                    return 'color: red'
                else:
                    return ''
            
            # スタイル適用
            styled_df = safe_style_map(df.style, mb_result_view, subset=['Detected', 'Query Status'])
            st.dataframe(styled_df)

            # 円グラフを描画
            labels = ["Detected", "Not found", "Error"]
            label_color = ['#FF0000','#228B22', '#FFA500']
            detected_count = df[df['Detected'] == True].shape[0]
            not_found_count = df[df['Query Status'] == 'hash_not_found'].shape[0]
            error_count = df[df['Query Status'] == 'error'].shape[0]
            values = [detected_count, not_found_count, error_count]

            # 0でない値のみ表示
            non_zero_values = [(label, value, color) for label, value, color in zip(labels, values, label_color) if value > 0]
            
            if non_zero_values:
                fig, ax = plt.subplots()
                labels_nz, values_nz, colors_nz = zip(*non_zero_values)
                explode = [0.1 if label == "Detected" else 0 for label in labels_nz]
                ax.pie(values_nz, colors=colors_nz, labels=labels_nz, autopct='%1.1f%%', explode=explode, textprops={'color': 'white'})
                ax.axis("equal")
                fig.set_facecolor('none')
                st.pyplot(fig)

def result_viewer():
    st.title("Result Viewer")
    
    # サイドバーでファイル数制限の設定を追加
    st.sidebar.subheader("表示設定")
    max_files = st.sidebar.slider("最大表示ファイル数", 10, 500, 100, 10)
    show_sample_only = st.sidebar.checkbox("サンプル表示モード（最初の10件のみ）", False)
    
    options = ["FileScan", "URLScan", "IPScan","DOMAINScan", "MBScan", "AbuseIPDBScan"]
    selected_option = st.radio("Choose an option", options)
    st.markdown(
        '''
        既にスキャン済のファイルを閲覧するモードです。
        '''
    )
    
    file_path_list = load_file_list()
    
    if selected_option == "FileScan":
        choice_result_viewer_file = st.selectbox("Select data",sorted(file_path_list[1],key=len)[:max_files])
        if choice_result_viewer_file:
            # 表示モード選択を追加
            view_mode = st.radio("表示モード", ["個別表示", "全件統計"])
            
            if view_mode == "個別表示":
                tab1, tab2 = st.tabs(["AV scans", "raw Data"])
                with tab1:
                    jsondata = load_json_file(choice_result_viewer_file)
                    if jsondata:
                        scanner = VtScanner()
                        read_result = scanner.jsonDataConverter(jsondata)
                        df = pd.DataFrame.from_dict(read_result.scans).T
                        styled_df = safe_style_map(df.style, highlight_not_none, subset=["category","result"])
                        st.dataframe(styled_df)
                with tab2:
                    jsondata = load_json_file(choice_result_viewer_file)
                    if jsondata:
                        st.write(jsondata.get("behaviours", {}))
            
            else:  # 全件統計
                # ファイル数制限の適用
                files_to_process = file_path_list[1][:max_files] if not show_sample_only else file_path_list[1][:10]
                
                st.info(f"処理対象: {len(files_to_process)}件のファイル")
                
                if st.button("統計処理開始"):
                    all_results, detection_stats = process_all_files(files_to_process, "file")
                    
                    tab1, tab2, tab3 = st.tabs(["統計サマリー", "詳細結果", "円グラフ"])
                    
                    with tab1:
                        st.subheader("スキャン結果サマリー")
                        col1, col2, col3, col4 = st.columns(4)
                        with col1:
                            st.metric("総ファイル数", len(all_results))
                        with col2:
                            st.metric("検出数", detection_stats.get("Detected", 0))
                        with col3:
                            st.metric("安全", detection_stats.get("Safe", 0))
                        with col4:
                            detection_rate = (detection_stats.get("Detected", 0) / len(all_results) * 100) if all_results else 0
                            st.metric("検出率", f"{detection_rate:.1f}%")
                    
                    with tab2:
                        if all_results:
                            st.subheader("全ファイル詳細結果")
                            df = pd.DataFrame(all_results)
                            
                            def file_result_view(val):
                                if val == "Detected":
                                    return 'color: red'
                                elif val == "Safe":
                                    return 'color: green'
                                else:
                                    return 'color: orange'
                            
                            styled_df = safe_style_map(df.style, file_result_view, subset=['結果'])
                            st.dataframe(styled_df, use_container_width=True)
                            
                            # CSVダウンロード機能
                            csv = df.to_csv(index=False, encoding='utf-8-sig')
                            st.download_button(
                                label="CSVダウンロード",
                                data=csv,
                                file_name=f"filescan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                                mime="text/csv"
                            )
                    
                    with tab3:
                        create_pie_chart(detection_stats)

    elif selected_option == "URLScan":
        files_to_show = file_path_list[2][:max_files]
        choice_result_viewer_file = st.selectbox("Select data", sorted(files_to_show, key=len))
        if choice_result_viewer_file:
            view_mode = st.radio("表示モード", ["個別表示", "全件統計"])
            
            if view_mode == "個別表示":
                tab1, tab2 = st.tabs(["AV scans", "raw Data"])
                with tab1:
                    jsondata = load_json_file(choice_result_viewer_file)
                    if jsondata:
                        scanner = VtScanner()
                        read_result = scanner.jsonDataConverter(jsondata)
                        df = pd.DataFrame.from_dict(read_result.scans).T
                        styled_df = safe_style_map(df.style, highlight_not_none, subset=["category","result"])
                        st.dataframe(styled_df)
                with tab2:
                    jsondata = load_json_file(choice_result_viewer_file)
                    if jsondata:
                        st.write(jsondata)
            
            else:  # 全件統計
                files_to_process = file_path_list[2][:max_files] if not show_sample_only else file_path_list[2][:10]
                st.info(f"処理対象: {len(files_to_process)}件のファイル")
                
                if st.button("統計処理開始"):
                    all_results, detection_stats = process_all_files(files_to_process, "url")
                    
                    tab1, tab2, tab3 = st.tabs(["統計サマリー", "詳細結果", "円グラフ"])
                    
                    with tab1:
                        st.subheader("URLスキャン結果サマリー")
                        col1, col2, col3, col4 = st.columns(4)
                        with col1:
                            st.metric("総URL数", len(all_results))
                        with col2:
                            st.metric("検出数", detection_stats.get("Detected", 0))
                        with col3:
                            st.metric("安全", detection_stats.get("Safe", 0))
                        with col4:
                            detection_rate = (detection_stats.get("Detected", 0) / len(all_results) * 100) if all_results else 0
                            st.metric("検出率", f"{detection_rate:.1f}%")
                    
                    with tab2:
                        if all_results:
                            st.subheader("全URL詳細結果")
                            df = pd.DataFrame(all_results)
                            
                            def url_result_view(val):
                                if val == "Detected":
                                    return 'color: red'
                                elif val == "Safe":
                                    return 'color: green'
                                else:
                                    return 'color: orange'
                            
                            styled_df = safe_style_map(df.style, url_result_view, subset=['結果'])
                            st.dataframe(styled_df, use_container_width=True)
                            
                            csv = df.to_csv(index=False, encoding='utf-8-sig')
                            st.download_button(
                                label="CSVダウンロード",
                                data=csv,
                                file_name=f"urlscan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                                mime="text/csv"
                            )
                    
                    with tab3:
                        create_pie_chart(detection_stats)

    elif selected_option == "IPScan":
        files_to_show = file_path_list[3][:max_files]
        choice_result_viewer_file = st.selectbox("Select data", sorted(files_to_show, key=len))
        if choice_result_viewer_file:
            view_mode = st.radio("表示モード", ["個別表示", "全件統計"])
            
            if view_mode == "個別表示":
                tab1, tab2 = st.tabs(["AV scans", "raw Data"])
                with tab1:
                    jsondata = load_json_file(choice_result_viewer_file)
                    if jsondata:
                        scanner = VtScanner()
                        read_result = scanner.jsonDataConverter(jsondata)
                        df = pd.DataFrame.from_dict(read_result.scans).T
                        styled_df = safe_style_map(df.style, highlight_not_none, subset=["category","result"])
                        st.dataframe(styled_df)
                with tab2:
                    jsondata = load_json_file(choice_result_viewer_file)
                    if jsondata:
                        st.write(jsondata)
            
            else:  # 全件統計
                files_to_process = file_path_list[3][:max_files] if not show_sample_only else file_path_list[3][:10]
                st.info(f"処理対象: {len(files_to_process)}件のファイル")
                
                if st.button("統計処理開始"):
                    all_results, detection_stats = process_all_files(files_to_process, "ip")
                    
                    tab1, tab2, tab3 = st.tabs(["統計サマリー", "詳細結果", "円グラフ"])
                    
                    with tab1:
                        st.subheader("IPスキャン結果サマリー")
                        col1, col2, col3, col4 = st.columns(4)
                        with col1:
                            st.metric("総IP数", len(all_results))
                        with col2:
                            st.metric("検出数", detection_stats.get("Detected", 0))
                        with col3:
                            st.metric("安全", detection_stats.get("Safe", 0))
                        with col4:
                            detection_rate = (detection_stats.get("Detected", 0) / len(all_results) * 100) if all_results else 0
                            st.metric("検出率", f"{detection_rate:.1f}%")
                    
                    with tab2:
                        if all_results:
                            st.subheader("全IP詳細結果")
                            df = pd.DataFrame(all_results)
                            
                            def ip_result_view(val):
                                if val == "Detected":
                                    return 'color: red'
                                elif val == "Safe":
                                    return 'color: green'
                                else:
                                    return 'color: orange'
                            
                            styled_df = safe_style_map(df.style, ip_result_view, subset=['結果'])
                            st.dataframe(styled_df, use_container_width=True)
                            
                            csv = df.to_csv(index=False, encoding='utf-8-sig')
                            st.download_button(
                                label="CSVダウンロード",
                                data=csv,
                                file_name=f"ipscan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                                mime="text/csv"
                            )
                    
                    with tab3:
                        create_pie_chart(detection_stats)

    elif selected_option == "DOMAINScan":
        files_to_show = file_path_list[4][:max_files]
        choice_result_viewer_file = st.selectbox("Select data", sorted(files_to_show, key=len))
        if choice_result_viewer_file:
            view_mode = st.radio("表示モード", ["個別表示", "全件統計"])
            
            if view_mode == "個別表示":
                tab1, tab2 = st.tabs(["AV scans", "raw Data"])
                with tab1:
                    jsondata = load_json_file(choice_result_viewer_file)
                    if jsondata:
                        scanner = VtScanner()
                        read_result = scanner.jsonDataConverter(jsondata)
                        df = pd.DataFrame.from_dict(read_result.scans).T
                        styled_df = safe_style_map(df.style, highlight_not_none, subset=["category","result"])
                        st.dataframe(styled_df)
                with tab2:
                    jsondata = load_json_file(choice_result_viewer_file)
                    if jsondata:
                        st.write(jsondata)
            
            else:  # 全件統計
                files_to_process = file_path_list[4][:max_files] if not show_sample_only else file_path_list[4][:10]
                st.info(f"処理対象: {len(files_to_process)}件のファイル")
                
                if st.button("統計処理開始"):
                    all_results, detection_stats = process_all_files(files_to_process, "domain")
                    
                    tab1, tab2, tab3 = st.tabs(["統計サマリー", "詳細結果", "円グラフ"])
                    
                    with tab1:
                        st.subheader("ドメインスキャン結果サマリー")
                        col1, col2, col3, col4 = st.columns(4)
                        with col1:
                            st.metric("総ドメイン数", len(all_results))
                        with col2:
                            st.metric("検出数", detection_stats.get("Detected", 0))
                        with col3:
                            st.metric("安全", detection_stats.get("Safe", 0))
                        with col4:
                            detection_rate = (detection_stats.get("Detected", 0) / len(all_results) * 100) if all_results else 0
                            st.metric("検出率", f"{detection_rate:.1f}%")
                    
                    with tab2:
                        if all_results:
                            st.subheader("全ドメイン詳細結果")
                            df = pd.DataFrame(all_results)
                            
                            def domain_result_view(val):
                                if val == "Detected":
                                    return 'color: red'
                                elif val == "Safe":
                                    return 'color: green'
                                else:
                                    return 'color: orange'
                            
                            styled_df = safe_style_map(df.style, domain_result_view, subset=['結果'])
                            st.dataframe(styled_df, use_container_width=True)
                            
                            csv = df.to_csv(index=False, encoding='utf-8-sig')
                            st.download_button(
                                label="CSVダウンロード",
                                data=csv,
                                file_name=f"domainscan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                                mime="text/csv"
                            )
                    
                    with tab3:
                        create_pie_chart(detection_stats)

    elif selected_option == "MBScan":
        try:
            mb_scanner = MBScanner("")  # 結果表示のみなのでAPIキーは空でOK
            mb_file_list = mb_scanner.get_file_list()[:max_files]
            
            if mb_file_list:
                view_mode = st.radio("表示モード", ["全件表示", "個別表示"])
                
                if view_mode == "全件表示":
                    st.info(f"処理対象: {len(mb_file_list)}件のファイル")
                    
                    if st.button("MBScan統計処理開始"):
                        all_results = []
                        progress_bar = st.progress(0)
                        status_text = st.empty()
                        
                        for i, file_path in enumerate(mb_file_list):
                            try:
                                status_text.text(f"ファイル読み込み中... {i+1}/{len(mb_file_list)}")
                                
                                jsondata = load_json_file(file_path)
                                if jsondata:
                                    read_result = mb_scanner.jsonDataConverter(jsondata)
                                    filename = os.path.basename(file_path).replace('.json', '')
                                    
                                    all_results.append({
                                        'Hash': filename,
                                        'Query Status': read_result.query_status,
                                        'Detected': read_result.detected,
                                        'SHA256': read_result.sha256_hash or '-',
                                        'Signature': read_result.signature or '-',
                                        'File Type': read_result.file_type or '-',
                                        'File Name': read_result.file_name or '-',
                                        'First Seen': read_result.first_seen or '-',
                                        'Last Seen': read_result.last_seen or '-',
                                        'Reporter': read_result.reporter or '-',
                                        'Tags': ', '.join(read_result.tags) if read_result.tags else '-',
                                        'Error': read_result.error_message or '-'
                                    })
                            except Exception as e:
                                st.warning(f"ファイル {file_path} の読み込みに失敗しました: {e}")
                            
                            if i % 10 == 0 or i == len(mb_file_list) - 1:
                                progress_bar.progress((i + 1) / len(mb_file_list))
                        
                        status_text.text("完了")
                        progress_bar.empty()
                        status_text.empty()
                        
                        if all_results:
                            df = pd.DataFrame(all_results)
                            
                            def mb_result_view(val):
                                if val == True:  # Detected
                                    return 'color: red'
                                elif val == 'ok':
                                    return 'color: green'
                                elif val == 'error' or val == 'hash_not_found':
                                    return 'color: orange'
                                else:
                                    return ''
                            
                            styled_df = safe_style_map(df.style, mb_result_view, subset=['Detected', 'Query Status'])
                            st.dataframe(styled_df, use_container_width=True)
                            
                            # 統計情報
                            detected_count = df[df['Detected'] == True].shape[0]
                            not_found_count = df[df['Query Status'] == 'hash_not_found'].shape[0]
                            error_count = df[df['Query Status'] == 'error'].shape[0]
                            
                            st.subheader("統計情報")
                            col1, col2, col3, col4 = st.columns(4)
                            with col1:
                                st.metric("総件数", len(all_results))
                            with col2:
                                st.metric("検出数", detected_count)
                            with col3:
                                st.metric("未発見", not_found_count)
                            with col4:
                                st.metric("エラー", error_count)
                        else:
                            st.info("有効な結果がありません")
                
                else:  # 個別表示
                    choice_result_viewer_file = st.selectbox("Select data", sorted(mb_file_list, key=len))
                    if choice_result_viewer_file:
                        tab1, tab2 = st.tabs(["Scan Result", "raw Data"])
                        with tab1:
                            jsondata = load_json_file(choice_result_viewer_file)
                            if jsondata:
                                read_result = mb_scanner.jsonDataConverter(jsondata)
                                
                                result_data = {
                                    'Query Status': [read_result.query_status],
                                    'Detected': [read_result.detected],
                                    'SHA256': [read_result.sha256_hash or '-'],
                                    'Signature': [read_result.signature or '-'],
                                    'File Type': [read_result.file_type or '-'],
                                    'File Name': [read_result.file_name or '-'],
                                    'First Seen': [read_result.first_seen or '-'],
                                    'Last Seen': [read_result.last_seen or '-'],
                                    'Reporter': [read_result.reporter or '-'],
                                    'Tags': [', '.join(read_result.tags) if read_result.tags else '-'],
                                    'Error': [read_result.error_message or '-']
                                }
                                df = pd.DataFrame(result_data)
                                st.dataframe(df)
                                
                                if read_result.intelligence:
                                    st.subheader("Intelligence Information")
                                    st.json(read_result.intelligence)
                        
                        with tab2:
                            jsondata = load_json_file(choice_result_viewer_file)
                            if jsondata:
                                st.json(jsondata)
            else:
                st.info("MBScanの結果ファイルが見つかりません")
        except Exception as e:
            st.error(f"MBScanの結果を読み込み中にエラーが発生しました: {e}")
    
    elif selected_option == "AbuseIPDBScan":
        try:
            abuse_checker = AbuseIPDBChecker("")  # 結果表示のみなのでAPIキーは空でOK
            abuse_file_list = abuse_checker.get_file_list()[:max_files]
            
            if abuse_file_list:
                view_mode = st.radio("表示モード", ["全件表示", "個別表示"])
                
                if view_mode == "全件表示":
                    st.info(f"処理対象: {len(abuse_file_list)}件のファイル")
                    
                    if st.button("AbuseIPDB統計処理開始"):
                        all_results = []
                        progress_bar = st.progress(0)
                        status_text = st.empty()
                        
                        for i, file_path in enumerate(abuse_file_list):
                            try:
                                status_text.text(f"ファイル読み込み中... {i+1}/{len(abuse_file_list)}")
                                
                                jsondata = load_json_file(file_path)
                                if jsondata:
                                    filename = os.path.basename(file_path).replace('.json', '').replace('_error', '')
                                    
                                    if "data" in jsondata:
                                        data = jsondata["data"]
                                        all_results.append({
                                            'IP Address': data.get('ipAddress', filename),
                                            'Abuse Confidence Score': data.get('abuseConfidenceScore', 0),
                                            'Total Reports': data.get('totalReports', 0),
                                            'Last Reported': data.get('lastReportedAt', '-'),
                                            'Country': data.get('countryCode', '-'),
                                            'Usage Type': data.get('usageType', '-'),
                                            'ISP': data.get('isp', '-'),
                                            'Domain': data.get('domain', '-'),
                                            'Is Public': data.get('isPublic', '-'),
                                            'Is Whitelisted': data.get('isWhitelisted', '-')
                                        })
                                    elif "error" in jsondata:
                                        all_results.append({
                                            'IP Address': filename,
                                            'Abuse Confidence Score': 'Error',
                                            'Total Reports': 'Error',
                                            'Last Reported': '-',
                                            'Country': '-',
                                            'Usage Type': '-',
                                            'ISP': '-',
                                            'Domain': '-',
                                            'Is Public': '-',
                                            'Is Whitelisted': '-'
                                        })
                            except Exception as e:
                                st.warning(f"ファイル {file_path} の読み込みに失敗しました: {e}")
                            
                            if i % 10 == 0 or i == len(abuse_file_list) - 1:
                                progress_bar.progress((i + 1) / len(abuse_file_list))
                        
                        status_text.text("完了")
                        progress_bar.empty()
                        status_text.empty()
                        
                        if all_results:
                            df = pd.DataFrame(all_results)
                            
                            def abuse_result_view(val):
                                if val == 'Error':
                                    return 'color: red'
                                elif isinstance(val, (int, float)) and val > 0:
                                    return 'color: red'
                                elif isinstance(val, (int, float)) and val == 0:
                                    return 'color: green'
                                elif val == True:
                                    return 'color: orange'
                                elif val == False:
                                    return 'color: green'
                                else:
                                    return ''
                            
                            styled_df = safe_style_map(df.style, abuse_result_view, subset=['Abuse Confidence Score', 'Is Whitelisted'])
                            st.dataframe(styled_df, use_container_width=True)
                            
                            # 統計情報
                            detected_count = len([r for r in all_results if isinstance(r['Abuse Confidence Score'], (int, float)) and r['Abuse Confidence Score'] > 0])
                            safe_count = len([r for r in all_results if isinstance(r['Abuse Confidence Score'], (int, float)) and r['Abuse Confidence Score'] == 0])
                            error_count = len([r for r in all_results if r['Abuse Confidence Score'] == 'Error'])
                            
                            st.subheader("統計情報")
                            col1, col2, col3, col4 = st.columns(4)
                            with col1:
                                st.metric("総件数", len(all_results))
                            with col2:
                                st.metric("検出数", detected_count)
                            with col3:
                                st.metric("安全", safe_count)
                            with col4:
                                st.metric("エラー", error_count)
                        else:
                            st.info("有効な結果がありません")
                
                else:  # 個別表示
                    choice_result_viewer_file = st.selectbox("Select data", sorted(abuse_file_list, key=len))
                    if choice_result_viewer_file:
                        tab1, tab2 = st.tabs(["Scan Result", "raw Data"])
                        with tab1:
                            jsondata = load_json_file(choice_result_viewer_file)
                            if jsondata and "data" in jsondata:
                                data = jsondata["data"]
                                result_data = {
                                    'IP Address': [data.get('ipAddress', '-')],
                                    'Abuse Confidence Score': [data.get('abuseConfidenceScore', '-')],
                                    'Total Reports': [data.get('totalReports', '-')],
                                    'Last Reported': [data.get('lastReportedAt', '-')],
                                    'Country': [data.get('countryCode', '-')],
                                    'Usage Type': [data.get('usageType', '-')],
                                    'ISP': [data.get('isp', '-')],
                                    'Domain': [data.get('domain', '-')],
                                    'Is Public': [data.get('isPublic', '-')],
                                    'Is Whitelisted': [data.get('isWhitelisted', '-')]
                                }
                                df = pd.DataFrame(result_data)
                                
                                def abuse_result_view(val):
                                    if isinstance(val, (int, float)) and val > 0:
                                        return 'color: red'
                                    elif isinstance(val, (int, float)) and val == 0:
                                        return 'color: green'
                                    elif val == True:
                                        return 'color: orange'
                                    elif val == False:
                                        return 'color: green'
                                    else:
                                        return ''
                                
                                styled_df = safe_style_map(df.style, abuse_result_view)
                                st.dataframe(styled_df)
                            else:
                                st.error("有効なAbuseIPDBデータが見つかりません")
                        
                        with tab2:
                            jsondata = load_json_file(choice_result_viewer_file)
                            if jsondata:
                                st.json(jsondata)
            else:
                st.info("AbuseIPDBのスキャン結果ファイルが見つかりません")
        except Exception as e:
            st.error(f"AbuseIPDBScanの結果を読み込み中にエラーが発生しました: {e}")

def main():
    # サイドバーの設定
    st.sidebar.header("Menu")
    menu = ["File scan", "DOMAIN / URL / IP Scan", "AbuseIPDB Scan", "Malware Bazaar Scan", "result Viewer"]
    default_choice = menu[0]  # デフォルトで選択されるページ
    choice = st.sidebar.selectbox("Select a page", menu, index=menu.index(default_choice))

    # 選択されたページの実行
    if choice == "File scan":
        filehash_scan_page()
    elif choice == "DOMAIN / URL / IP Scan":
        url_scan_page()
    elif choice == "AbuseIPDB Scan":
        abuseipdb_scan_page()
    elif choice == "Malware Bazaar Scan":
        malware_bazaar_scan_page()
    elif choice == "result Viewer":
        result_viewer()

if __name__ == "__main__":
    main()