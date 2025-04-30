# phpinfo_analyzer

- 用於分析 PHP 的 phpinfo() 輸出，根據常見的安全設定檢查相關設定。能夠幫助開發者、系統管理員、滲透測試工程師快速識別潛在的不安全 PHP 組態。

## 功能
- 從本地 HTML 檔案讀取 phpinfo() 輸出。
- 從遠端 URL 抓取 phpinfo() 頁面內容。

## 前置需求 (Pre-request)
```
pip install requests beautifulsoup4
```

## 使用方法

python analyze_phpinfo.py [選項]

### 選項：
`-h`, `--help`: 顯示幫助訊息並退出。

`-f FILE`, `--file FILE`: 指定包含 phpinfo() HTML 輸出的本地檔案路徑。

`-u URL`, `--url URL`: 指定 phpinfo() 頁面的 URL。警告：請僅用於受信任的 URL！

`-t TIMEOUT`, `--timeout TIMEOUT`: 抓取 URL 時的超時秒數 (預設: 10)。

注意： `-f` 和 `-u` 選項必須提供其中一個，且只能提供一個。

### 使用範例
從本地檔案分析：
```
python analyze_phpinfo.py -f /path/to/your/phpinfo_output.html
```

從 URL 分析 (僅限受信任的來源)：
```
python analyze_phpinfo.py -u http://your-trusted-server.com/phpinfo.php
```

從 URL 分析並設定超時為 5 秒：
```
python analyze_phpinfo.py -u http://your-trusted-server.com/phpinfo.php -t 5
```
