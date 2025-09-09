# ngx_http_ja3_module

本模組為 Nginx/OpenResty 的 JA3 指紋擷取模組，能於 TLS 握手階段即時解析 ClientHello，並輸出 JA3 字串，方便進行 TLS 客戶端指紋辨識。

---

## 功能說明

- 於 TLS 握手階段，擷取並輸出 JA3 字串（格式：`version,ciphers,extensions,elliptic_curves,ec_point_formats`）
- 支援 TLS 1.2/1.3
- 可即時於 Nginx error log 觀察 JA3 內容

---

## JA3 組裝流程與註解

本模組組裝 JA3 字串的流程如下：

1. **取得 TLS Version**
   - 先嘗試從 `supported_versions` extension 取得（RFC 8446 §4.2.1），若無則退回 legacy_version。
   - 參考：[apache httpd 實作](https://github.com/apache/httpd/blob/a6dcd191f4f168e06ccaac55edaeca5d02b4a791/modules/ssl/ssl_engine_kernel.c#L2408)

2. **取得 CipherSuites**
   - 兩兩 byte 組成一個數字，轉十進位，用 `-` 連接。
   - 參考：[OpenSSL man page](https://manpages.debian.org/experimental/libssl-doc/SSL_client_hello_get1_extensions_present.3ssl.en.html)

3. **取得 Extensions**
   - 取得 extension type，轉十進位，用 `-` 連接。
   - 參考：[OpenSSL man page](https://manpages.debian.org/experimental/libssl-doc/SSL_client_hello_get1_extensions_present.3ssl.en.html)

4. **取得 EllipticCurves**
   - 解析 `supported_groups` extension（RFC 8446 §4.2.7），前2個byte為長度，後面每2個byte為一個 group id，轉十進位，用 `-` 連接。
   - 參考：[nginx-devel 討論](https://mailman.nginx.org/pipermail/nginx-devel/2020-April/013123.html)

5. **取得 ECPointFormats**
   - 解析 `ec_point_formats` extension，第一個byte為list長度，後面每byte為一個格式，轉十進位，用 `-` 連接。

6. **組合 JA3 字串**
   - 格式：`TLSVersion,CipherSuites,Extensions,EllipticCurves,ECPointFormats`

---

## 編譯與安裝

1. **將本模組原始碼放入 Nginx/OpenResty 原始碼目錄下的 `modules/` 資料夾**
2. **重新編譯 Nginx/OpenResty 並加上本模組**
   ```bash
   ./configure CC=clang CFLAGS="-g -O0" ./configure \
      --with-http_ssl_module \
      --with-http_v2_module \
      --with-http_stub_status_module \
      --add-dynamic-module=modules/ngx_http_ja3_module
   make && make install
   ```
3. **在 nginx.conf 中載入模組**
   ```nginx
   load_module modules/ngx_http_ja3_module.so;
   ```

---

## Nginx 設定範例

```nginx
worker_processes  1;
load_module modules/ngx_http_ja3_module.so;

events {
    worker_connections  1024;
}

http {
    server {
        listen 443 ssl;
        server_name _;

        ssl_certificate     /path/to/your.crt;
        ssl_certificate_key /path/to/your.key;

        location / {
            return 200 "ok";
        }
    }
}
```

---

## 測試方式

### 1. 使用 curl 測試（含 SNI）

```bash
curl -vk --resolve test:443:127.0.0.1 https://test/
```

### 2. 使用 openssl s_client 測試

```bash
openssl s_client -connect 127.0.0.1:443 -servername test -alpn http/1.1 -curves X25519:P-256:P-384 -sigalgs RSA+SHA256
```

### 3. 從第三方服務取得自己電腦 curl 的 ja3

```bash
curl https://tools.scrapfly.io/api/tls | jq .
```

### 4. 觀察 Nginx error log

可於 Nginx error log 看到類似以下輸出：

```
SSL Version: 771
Cipher: 4866-4867-4865-...
Extensions: 0-11-10-...
EllipticCurves: 29-23-...
ECPointFormats: 0-1-2
[JA3] 771,4866-4867-4865-...,0-11-10-...,29-23-...,0-1-2
```

---

### 5. 使用 tlsfuzzer 進行自動化 TLS 行為測試

你可以用 [tlsfuzzer](https://github.com/tlsfuzzer/tlsfuzzer) 驗證 JA3 模組與 Nginx/OpenResty 的 TLS 行為：

#### Nginx 設定範例
---
``` nginx.conf
worker_processes  1;
load_module modules/ngx_http_ja3_module.so;

events {
    worker_connections  1024;
}

http {
    server {
        listen 4433 ssl;
        server_name _;

        ssl_certificate     dummy.crt;
        ssl_certificate_key dummy.key;

        location / {
            return 200 "ok";
        }
    }
}

```
```bash
# 下載並安裝 tlsfuzzer
git clone https://github.com/tlsfuzzer/tlsfuzzer
cd tlsfuzzer
python3 -m venv venv
venv/bin/pip install --pre tlslite-ng

# 執行最大 ClientHello 測試
PYTHONPATH=. venv/bin/python scripts/test-client-hello-max-size.py

# 執行所有測試腳本
for f in scripts/test-*.py; do
    echo "Running $f ..."
    PYTHONPATH=. venv/bin/python "$f" || echo "❌ $f failed"
done
```

> 測試前請確保 Nginx/OpenResty 已啟動並監聽正確的 TLS 連接埠（4433），且 `ssl_certificate` 與 `ssl_certificate_key` 設定正確。

---

## 程式重點

- 使用 OpenSSL 1.1.1+ 的 ClientHello callback API
- 解析 TLS version、cipher suites、extensions、supported_groups、ec_point_formats
- 依 JA3 標準格式組合字串並輸出
- 詳細註解請見原始碼內部說明

---

## 參考資料

- [JA3 指紋原理](https://github.com/salesforce/ja3)
- [OpenSSL ClientHello callback 文件](https://www.openssl.org/docs/man1.1.1/man3/SSL_client_hello_get0_ext.html)
- [RFC 8446 - TLS 1.3](https://datatracker.ietf.org/doc/html/rfc8446)
- [nginx-devel 討論](https://mailman.nginx.org/pipermail/nginx-devel/2020-April/013123.html)

---

## 注意事項

- 若要正確取得 SNI (extension 0)，請務必用 domain name 連線（不要直接用 IP）。
- 若要正確取得 elliptic curves，請確認 client hello 有帶 supported_groups extension。
- 本模組僅於 TLS 握手階段輸出 JA3，無額外 HTTP 功能。
- 詳細流程與 RFC 參考請見原始碼註解