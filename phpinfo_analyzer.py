#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import requests
import sys
from bs4 import BeautifulSoup
from urllib.parse import urlparse

# --- 設定：安全規則 ---
# 格式：'指令': ['建議值', '嚴重性', '說明']
# 特殊值：
#   '<non-empty-path>': 檢查值是否已設定且非空 (用於 open_basedir 等路徑)
#   '<boolean-true>': 檢查值是否為 PHP 認定的 TRUE (On, True, 1)
#   '<boolean-false>': 檢查值是否為 PHP 認定的 FALSE (Off, False, 0, "")
#   '<check-disabled-functions>': 特殊檢查 disable_functions
#   '<check-if-needed>': 資訊性檢查，提示使用者根據需求判斷
#   '<check-reasonable-limit>': 資訊性檢查，提示設定合理限制
SECURITY_RULES = {
    # --- 重要安全設定 ---
    'display_errors': ['<boolean-false>', '嚴重', '生產環境應設為 Off，防止洩漏敏感資訊。'],
    'log_errors': ['<boolean-true>', '建議', '應設為 On，將錯誤記錄在伺服器端。'],
    'error_log': ['<non-empty-path>', '建議', '應設定一個明確的錯誤日誌檔案路徑。'],
    'expose_php': ['<boolean-false>', '中等', '應設為 Off，隱藏 HTTP 標頭中的 PHP 版本。'],
    'allow_url_fopen': ['<boolean-false>', '高', '應設為 Off，降低 SSRF 和遠端檔案包含風險。'],
    'allow_url_include': ['<boolean-false>', '嚴重', '必須設為 Off，防止遠端檔案包含 (RFI) 漏洞。'],
    'open_basedir': ['<non-empty-path>', '高', '應設定以限制 PHP 腳本只能存取指定的目錄。'],
    'disable_functions': ['<check-disabled-functions>', '中等', '應禁用不必要的危險函數，例如 exec, system, shell_exec, passthru 等。'],

    # --- 會話 Session 安全 ---
    'session.cookie_httponly': ['<boolean-true>', '高', '應設為 On，防止客戶端腳本存取 Session Cookie (緩解 XSS)。'],
    'session.cookie_secure': ['<boolean-true>', '高', '若網站全程使用 HTTPS，應設為 On，僅透過 HTTPS 傳輸 Cookie。'],
    'session.use_strict_mode': ['<boolean-true>', '高', '應設為 On，伺服器不接受未初始化的 Session ID (防止會話固定)。'],
    'session.use_only_cookies': ['<boolean-true>', '高', '應設為 On，強制 Session ID 僅透過 Cookie 傳遞 (防止會話固定)。'],
    'session.save_path': ['<non-empty-path>', '建議', '應設定一個網站根目錄以外的安全路徑來儲存 Session 檔案。'],

    # --- 檔案上傳 ---
    'file_uploads': ['<check-if-needed>', '資訊', '僅在應用程式需要檔案上傳功能時才設為 On。'],
    'upload_max_filesize': ['<check-reasonable-limit>', '資訊', '設定合理的檔案大小上限 (例如 2M-10M)，防止 DoS 攻擊。'],
    'upload_tmp_dir': ['<non-empty-path>', '建議', '應設定一個網站根目錄以外的安全暫存目錄。'],

    # --- 資源限制 ---
    'max_execution_time': ['<check-reasonable-limit>', '資訊', '設定合理的腳本執行時間上限 (例如 30-60 秒)，防止腳本失控。'],
    'memory_limit': ['<check-reasonable-limit>', '資訊', '根據應用程式需求設定合理的記憶體上限 (例如 128M-256M)。'],
}

# 被認為有潛在危險的函數列表 (用於 disable_functions 檢查)
DANGEROUS_FUNCTIONS = [
    'exec', 'passthru', 'shell_exec', 'system', 'proc_open', 'popen',
    'show_source', 'parse_ini_file', 'pcntl_exec', 'symlink', 'link', 'dl'
]

# --- 輔助函數 ---

def parse_phpinfo(html_content):
    """解析 phpinfo() 的 HTML 內容，提取設定指令和本地值。"""
    parsed_settings = {}
    try:
        soup = BeautifulSoup(html_content, 'html.parser')
        # 嘗試找到包含設定的表格行
        # 選擇器邏輯：尋找 <tr>，其下有兩個 <td>，且第一個 <td> 內容不為空
        # 這可能需要根據實際 phpinfo() 輸出進行調整
        rows = soup.select('tr')
        for row in rows:
            cells = row.find_all('td')
            if len(cells) >= 2:
                directive_cell = cells[0]
                value_cell = cells[1]

                # 提取文字並去除多餘空白
                directive = directive_cell.get_text(strip=True)
                local_value = value_cell.get_text(strip=True)

                # 簡單的檢查，判斷第一個儲存格是否可能是指令名稱
                if directive and '.' in directive or directive.islower(): # 經驗法則
                    # 處理 phpinfo() 中顯示的 "no value"
                    if local_value.lower() == 'no value':
                        parsed_settings[directive] = '' # 將 'no value' 視為空字串
                    else:
                        parsed_settings[directive] = local_value
    except Exception as e:
        print(f"[錯誤] 解析 HTML 時發生錯誤: {e}", file=sys.stderr)
    return parsed_settings

def check_boolean(value):
    """檢查值是否代表 True (大小寫不敏感的 'on', 'true', '1')"""
    if value is None:
        return False
    return value.lower() in ('on', 'true', '1')

def analyze_settings(settings):
    """根據安全規則分析解析出的設定。"""
    results = []
    for directive, rule in SECURITY_RULES.items():
        recommended, severity, reason = rule
        current_value = settings.get(directive) # 若指令不存在則為 None
        issue_found = False
        actual_recommended_display = recommended
        current_value_display = current_value if current_value is not None else '[未設定]'

        # 處理特殊檢查邏輯
        if recommended == '<boolean-true>':
            if not check_boolean(current_value):
                issue_found = True
            actual_recommended_display = 'On'
        elif recommended == '<boolean-false>':
            # 對於應為 Off 的設定，None 或空字串通常也視為 Off
            if check_boolean(current_value):
                issue_found = True
            actual_recommended_display = 'Off'
        elif recommended == '<non-empty-path>':
            if current_value is None or current_value == '':
                issue_found = True
            actual_recommended_display = '應設定一個有效的路徑'
        elif recommended == '<check-disabled-functions>':
            currently_disabled = []
            if current_value:
                currently_disabled = [f.strip() for f in current_value.split(',')]

            missing_disabled = [
                func for func in DANGEROUS_FUNCTIONS if func not in currently_disabled
            ]
            if missing_disabled:
                issue_found = True
                reason += f" 建議禁用: {', '.join(missing_disabled)}."
            actual_recommended_display = '包含危險函數的列表'
        elif recommended in ('<check-if-needed>', '<check-reasonable-limit>'):
            # 資訊性檢查，總是添加到結果中（如果值存在）
            if current_value is not None:
                 results.append({
                    'directive': directive,
                    'current_value': current_value_display,
                    'recommended': actual_recommended_display,
                    'severity': severity,
                    'reason': reason,
                    'is_issue': False # 標記為資訊性
                })
            continue # 跳過後續的 issue 檢查
        else:
            # 標準值比較
            if current_value != recommended:
                issue_found = True

        if issue_found:
            results.append({
                'directive': directive,
                'current_value': current_value_display,
                'recommended': actual_recommended_display,
                'severity': severity,
                'reason': reason,
                'is_issue': True
            })

    return results

def print_results(results):
    """格式化並印出分析結果。"""
    if not results:
        print("\n[+] 根據定義的規則，未發現明顯問題或建議。")
        return

    print("\n--- PHP 設定安全分析結果 ---")
    print(f"{'指令':<30} {'當前值':<25} {'建議值/檢查':<25} {'嚴重性':<10} {'說明'}")
    print("-" * 110)

    # 先顯示問題，再顯示資訊
    results.sort(key=lambda x: not x['is_issue']) # True (is_issue) 排在前面

    for item in results:
        severity_color_map = {
            '嚴重': '\033[91m', # 紅色
            '高': '\033[93m',   # 黃色
            '中等': '\033[94m', # 藍色
            '建議': '\033[96m', # 青色
            '資訊': '\033[92m', # 綠色
        }
        color_start = severity_color_map.get(item['severity'], '\033[0m') # 預設無顏色
        color_end = '\033[0m' # 重設顏色

        # 為了對齊，需要考慮顏色代碼的長度（雖然它們不顯示）
        # 簡單處理：假設顏色代碼不影響視覺寬度
        print(f"{item['directive']:<30} {item['current_value']:<25} {item['recommended']:<25} "
              f"{color_start}{item['severity']:<10}{color_end} {item['reason']}")

    print("-" * 110)

# --- 主程式邏輯 ---
def main():
    parser = argparse.ArgumentParser(description='分析 phpinfo() 輸出的安全設定。')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-f', '--file', help='包含 phpinfo() HTML 輸出的本地檔案路徑。')
    group.add_argument('-u', '--url', help='phpinfo() 頁面的 URL。警告：請僅用於受信任的 URL！')
    parser.add_argument('-t', '--timeout', type=int, default=10, help='抓取 URL 時的超時秒數 (預設: 10)')

    args = parser.parse_args()

    html_content = ""
    source_description = ""

    if args.file:
        source_description = f"檔案: {args.file}"
        try:
            with open(args.file, 'r', encoding='utf-8', errors='ignore') as f:
                html_content = f.read()
            print(f"[+] 正在從檔案讀取: {args.file}")
        except FileNotFoundError:
            print(f"[錯誤] 檔案未找到: {args.file}", file=sys.stderr)
            sys.exit(1)
        except IOError as e:
            print(f"[錯誤] 無法讀取檔案 {args.file}: {e}", file=sys.stderr)
            sys.exit(1)

    elif args.url:
        source_description = f"URL: {args.url}"
        # 基本的 URL 驗證
        parsed_url = urlparse(args.url)
        if not all([parsed_url.scheme, parsed_url.netloc]):
             print(f"[錯誤] 無效的 URL 格式: {args.url}", file=sys.stderr)
             sys.exit(1)
        if parsed_url.scheme not in ('http', 'https'):
             print(f"[錯誤] 僅支援 http 和 https 協議: {args.url}", file=sys.stderr)
             sys.exit(1)

        print(f"[!] 正在從 URL 抓取: {args.url}")
        print("[!] 警告：從不受信任的 URL 抓取可能存在安全風險 (SSRF)。")
        try:
            headers = {'User-Agent': 'PHPInfo-Analyzer-Script/1.0'} # 設置 User-Agent
            response = requests.get(args.url, timeout=args.timeout, headers=headers, verify=True) # 啟用 SSL 驗證
            response.raise_for_status() # 如果狀態碼不是 2xx，則拋出異常
            # 嘗試解碼，優先使用 headers 中的編碼，若無則嘗試 utf-8
            response.encoding = response.apparent_encoding or 'utf-8'
            html_content = response.text
        except requests.exceptions.Timeout:
            print(f"[錯誤] 連接超時 ({args.timeout} 秒): {args.url}", file=sys.stderr)
            sys.exit(1)
        except requests.exceptions.RequestException as e:
            print(f"[錯誤] 抓取 URL 時發生錯誤 {args.url}: {e}", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
             print(f"[錯誤] 處理 URL 時發生未知錯誤 {args.url}: {e}", file=sys.stderr)
             sys.exit(1)

    if not html_content:
        print("[錯誤] 無法獲取 HTML 內容。", file=sys.stderr)
        sys.exit(1)

    print(f"[+] 正在解析從 {source_description} 獲取的內容...")
    parsed_settings = parse_phpinfo(html_content)

    if not parsed_settings:
        print("[錯誤] 未能從 HTML 中解析出任何 PHP 設定。請確認輸入來源是有效的 phpinfo() 輸出。", file=sys.stderr)
        sys.exit(1)

    print(f"[+] 解析完成，找到 {len(parsed_settings)} 個設定。正在進行分析...")
    analysis_results = analyze_settings(parsed_settings)

    print_results(analysis_results)

    print("\n--- 免責聲明 ---")
    print("* 此工具提供基於常見安全實踐的自動化檢查，結果僅供參考。")
    print("* 解析可能因 phpinfo() HTML 結構差異而不完整或不準確。")
    print("* 某些建議 (如 open_basedir 路徑, disable_functions 列表) 需要根據您的應用程式上下文進行判斷。")
    print("* 請務必手動審查您的 PHP 設定，並參考官方文件。")
    print("* 從 URL 抓取內容存在固有風險，請謹慎使用。")
    print("--- 完成 ---")

if __name__ == '__main__':
    main()
