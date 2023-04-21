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
        return "background-color: red"
    else:
        return ""



def filehash_scan_page():
    st.title("FileHashscan")
    api_key = st.text_input('USE APIKEY','')
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
            #プログレスバーをサイドバーに表示
            progress_bar = st.sidebar.progress(0)
            status_text = st.sidebar.empty()
            n = 1
            for k,v in file_hash_dict.items():
                scanner = VtScanner()
                result:ScanResult = scanner.hashScanner(api_key,k,v[0],overwrite)
                score = result.negative
                detail = result.result_str
                positive = result.positive_votes * -1 if result.positive_votes != -1 else 0
                #[result_str,negative,positive,result.negative_votes]
                file_scaned_dict[k] = [ detail, score, result.positive , result.negative_votes]
                progress_bar.progress(n / len(file_hash_dict))
                status_text.text(f"処理中... {n * 100 // len(file_hash_dict)}%")
                n += 1
                time.sleep(0.1)
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
            st.write(df2.style.applymap(vtScannerResultvView))
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
    st.title("URL scan")
    api_key = st.text_input('USE APIKEY','')
    st.write('APYKEY is ',api_key)
    ips_urls = st.text_area("スキャンするIP、URLを入力してください。", "")
    if st.button('Scan Start'):
        ips_urls_list =ips_urls.split("\n")
        scanner = VtScanner()
        result_dict = {}
        if ips_urls_list:
            for ip_url in ips_urls_list:
                result = scanner.ip_UrlScanner(api_key,ip_url.strip())
                result_dict[ip_url.strip()] = [result.result_str,result.negative,result.positive_votes,result.negative_votes]
        df = pd.DataFrame.from_dict(result_dict, orient='index', columns=['Result','Negative Score','+votes','-votes'])
        df.index.name = 'Target'
        st.write(df.style.applymap(vtScannerResultvView))

def result_viewer():
    st.title("Result Viewer")
    options = ["FileScan", "URLScan", "IPScan"]
    selected_option = st.radio("Choose an option", options)
    st.markdown(
        '''
        既にスキャン済のファイルを閲覧するモードです。
        '''
    )
    scanner = VtScanner()
    file_path_list = scanner.get_file_list()
    if selected_option == "FileScan":
        choice_result_viewer_file = st.selectbox("Select data",sorted(file_path_list[1],key=len))
        if choice_result_viewer_file:
            tab1, tab2 = st.tabs(["AV scans", "raw Data"])
            with tab1:
                read_result:ScanResult = scanner.jsonDataConverter(choice_result_viewer_file)
                df = pd.DataFrame.from_dict(read_result.scans).T
                styled_df = df.style.applymap(highlight_not_none, subset=["category","result"])
                st.dataframe(styled_df)
            with tab2:
                with open(choice_result_viewer_file, "r") as f:
                    json_data = json.load(f)            
                st.write(json_data["behaviours"])
    elif selected_option == "URLScan":
        choice_result_viewer_file = st.selectbox("Select data",sorted(file_path_list[2],key=len))
        if choice_result_viewer_file:
            tab1, tab2 = st.tabs(["AV scans", "raw Data"])
            with tab1:
                read_result:ScanResult = scanner.jsonDataConverter(choice_result_viewer_file)
                df = pd.DataFrame.from_dict(read_result.scans).T
                styled_df = df.style.applymap(highlight_not_none, subset=["category","result"])
                st.dataframe(styled_df)
            with tab2:
                with open(choice_result_viewer_file, "r") as f:
                    json_data = json.load(f)            
                st.write(json_data)
    elif selected_option == "IPScan":
        choice_result_viewer_file = st.selectbox("Select data",sorted(file_path_list[3],key=len))
        if choice_result_viewer_file:
            tab1, tab2 = st.tabs(["AV scans", "raw Data"])
            with tab1:
                read_result:ScanResult = scanner.jsonDataConverter(choice_result_viewer_file)
                df = pd.DataFrame.from_dict(read_result.scans).T
                styled_df = df.style.applymap(highlight_not_none, subset=["category","result"])
                st.dataframe(styled_df)
            with tab2:
                with open(choice_result_viewer_file, "r") as f:
                    json_data = json.load(f)            
                st.write(json_data)     

def main():
    # サイドバーの設定
    st.sidebar.header("Menu")
    menu = ["File scan", "URL scan","result Viewer"]
    default_choice = menu[0]  # デフォルトで選択されるページ
    choice = st.sidebar.selectbox("Select a page", menu, index=menu.index(default_choice))
    if st.sidebar.button('アプリを終了する'):
        st.stop()
    # 選択されたページの実行



    if choice == "File scan":
        filehash_scan_page()
    elif choice == "URL scan":
        url_scan_page()
    elif choice == "result Viewer":
        result_viewer()

if __name__ == "__main__":
    main()