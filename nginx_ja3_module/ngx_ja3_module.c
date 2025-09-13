#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <openssl/ssl.h>

#define JA3_BUF_LEN 8192

static int ngx_ja3_client_hello_cb(SSL *ssl, int *al, void *arg);
static ngx_int_t ngx_ja3_init(ngx_conf_t *cf);

static ngx_http_module_t ngx_ja3_module_ctx = {
    NULL,           /* preconfiguration */
    ngx_ja3_init, /* postconfiguration */
    NULL, NULL, NULL, NULL, NULL, NULL
};

ngx_module_t ngx_ja3_module = {
    NGX_MODULE_V1,
    &ngx_ja3_module_ctx,
    NULL,
    NGX_HTTP_MODULE,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NGX_MODULE_V1_PADDING
};

static int ngx_ja3_client_hello_cb(SSL *ssl, int *al, void *arg)
{
    // 測試 ja3 
    // 從第三方服務取得自己電腦 curl 的 ja3: curl https://tools.scrapfly.io/api/tls | jq .
    // local 測試: curl -vk --resolve test:443:127.0.0.1 https://test/
    /*
    組裝 ja3 流程
    1. 取得 TLSVersion → 整數
    2. 取得 CipherSuites → 轉成十進制，兩兩 byte 組成一個數字，用 "-" 連接
    3. 取得 Extensions → 轉十進制，用 "-" 連接
    4. 取得 EllipticCurves → 轉十進制，用 "-" 連接
    5. 取得 ECPointFormats → 轉十進制，用 "-" 連接
    6. 按格式組合成字串：TLSVersion,CipherSuites,Extensions,EllipticCurves,ECPointFormats
    參考文件: 
        # 取得 TLS version
        https://github.com/apache/httpd/blob/a6dcd191f4f168e06ccaac55edaeca5d02b4a791/modules/ssl/ssl_engine_kernel.c#L2408
        https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.1

        # 取得 CipherSuites
        https://manpages.debian.org/experimental/libssl-doc/SSL_client_hello_get1_extensions_present.3ssl.en.html

        # 取得 Extensions
        https://manpages.debian.org/experimental/libssl-doc/SSL_client_hello_get1_extensions_present.3ssl.en.html
        
        # 用於取得 EllipticCurves, ECPointFormats
        https://mailman.nginx.org/pipermail/nginx-devel/2020-April/013123.html
    */
    // volatile 告訴編譯器不要優化掉這個變數
    char ja3[JA3_BUF_LEN];

    // 用戶端的 cipher suites 清單長度
    size_t cipher_len;
    memset(ja3,0,sizeof(ja3));
    
    // 以下方法出自 apache httpd C 內部實現
    // https://github.com/apache/httpd/blob/a6dcd191f4f168e06ccaac55edaeca5d02b4a791/modules/ssl/ssl_engine_kernel.c#L2408
    // 1. 取得 TLS version
    const unsigned char *sv_data = NULL;
    size_t sv_len = 0;
    int ja3_version = 0;

    if (SSL_client_hello_get0_ext(ssl, TLSEXT_TYPE_supported_versions, &sv_data, &sv_len)) {
        // 根據 RFC8446 文件: https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.1
        //    struct {
        //        select (Handshake.msg_type) {
        //            case client_hello:
        //                ProtocolVersion versions<2..254>;  <- 版本號從第二個 bytes 開始，後面每 2 byte = 一個 TLS version (例如 0x0304 = 772)
        //
        //            case server_hello: /* and HelloRetryRequest */
        //                ProtocolVersion selected_version;
        //        };
        //    } SupportedVersions;
        if (sv_len >= 3) { // 第一個 byte 為總共有幾個版本號，只取第一個出現的版本號，未來這邊可以做排序，如果有多個版本號
            ja3_version = (sv_data[1] << 8) | sv_data[2];
        }
    }

    if (ja3_version == 0) {
        // 如果 client 沒有送 supported_versions (舊 client)，退回 legacy_version
        ja3_version = SSL_client_hello_get0_legacy_version(ssl);
    }

    char version_str[64] = {0};
    snprintf(version_str, sizeof(version_str), "%d", ja3_version); // 轉成十進位字串
    
    // 2. 取得 cipher suites
    // 定義暫存 cipher 資料的結構
    const unsigned char *cipher_data = NULL;
    cipher_len = SSL_client_hello_get0_ciphers(ssl, &cipher_data);
    char cipher_str[512] = {0};
    if (cipher_data && cipher_len > 1) {

        for(int i=0;i<cipher_len;i+=2){
            /*
            cs[i] << 8：把第 i 個 byte 左移 8 位，變成高位元組（high byte）。
            | cs[i+1]：用 bitwise OR，把第 i+1 個 byte 放到低位元組（low byte）。
            假設
                cipher_data[i]   = 0x0012 = 0000 0000 0001 0010 (16-bit)
                cipher_data[i+1] = 0x0034 = 0000 0000 0011 0100 (16-bit)
            則
                (cipher_data[i] << 8) 變成 0x1200 = 0001 0010 0000 0000 (16-bit)
                0x1200 與 0x0034 進行 or 運算變成 0x1234
    
                範例如下: or 運算
                Bitwise OR 是逐位比較兩個數字的每一位，只要其中一個數字的該位是 1，結果的該位就是 1。
                0x1200 = 0001 0010 0000 0000 (16-bit)
                0x0034 = 0000 0000 0011 0100 (16-bit)
                -----------------------------------
                0x1234 = 0001 0010 0011 0100 (16-bit)
            */
            uint16_t cipher = (cipher_data[i] << 8) | cipher_data[i+1];
            char cipher_buf[8];
            snprintf(cipher_buf, sizeof(cipher_buf), "%u", cipher); // 轉成十進位字串
            
            // 當 cipher 字串為第二個時，以 '-' 加在字串前面
            // 這樣 cipher_str 就會是像 4865-4866-4867... 這樣的格式。
            if (i>0){
                // 程式運行邊界檢查，防止緩衝區溢位
                if (strlen(cipher_str) + strlen("-") + 1 < sizeof(cipher_str)) {
                    // 串接 '-' 在輸出字串上
                    strncat(cipher_str, "-", 1);
                }
            }
            // 程式運行邊界檢查，防止緩衝區溢位
            if (strlen(cipher_str) + strlen(cipher_buf) + 1 < sizeof(cipher_str)) {
                strncat(cipher_str, cipher_buf, strlen(cipher_buf));
            }
        }
        fprintf(stderr, "SSL Version: %s\n", version_str);
        fprintf(stderr, "Cipher: %s\n", cipher_str);
    }

    // 3. Extensions
    char ext_str[512] = {0};
    int *ext_types_present = NULL;
    size_t ext_count = 0;
    // doc: https://manpages.debian.org/experimental/libssl-doc/SSL_client_hello_get1_extensions_present.3ssl.en.html
    int got_extensions = SSL_client_hello_get1_extensions_present(ssl, &ext_types_present, &ext_count);
    /* got_extensions 返回值：
        1 成功
        0 或負值失敗
    */
    if (got_extensions && ext_types_present && ext_count > 0) {
        for (size_t i = 0; i < ext_count; i++) {
            if (i > 0) {
                if (strlen(ext_str) + strlen("-") + 1 < sizeof(ext_str)){
                    strncat(ext_str, "-", 1);
                }
            }
            
            char ext_buf[8];
            snprintf(ext_buf, sizeof(ext_buf), "%u", ext_types_present[i]);
            if (strlen(ext_str) + strlen(ext_buf) + 1 < sizeof(ext_str)) {
                strncat(ext_str, ext_buf, strlen(ext_buf));
            }
        }
        
        // 根據 openssl 文件要求: 當使用 SSL_client_hello_get1_extensions_present 後，需釋放 OpenSSL 分配的記憶體
        OPENSSL_free(ext_types_present);
    }
    fprintf(stderr, "Extensions: %s\n", ext_str);

    // 若要輸出 sni 資訊，需用下列 curl
    // curl -vk --resolve test:443:127.0.0.1 https://test/
    const unsigned char *sni_data = NULL;
    size_t sni_len = 0;
    if (SSL_client_hello_get0_ext(ssl, TLSEXT_TYPE_server_name, &sni_data, &sni_len)) {
        fprintf(stderr, "SNI extension present, len=%zu\n", sni_len);
    } else {
        fprintf(stderr, "SNI extension NOT present\n");
    }

    // 4. 取得 EllipticCurves (extension 10)
    /*
    根據 RFC8446 文件
    https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.7
    struct {
          NamedGroup named_group_list<2..2^16-1>;
      } NamedGroupList;
    supported_groups:
        - 前2個byte是list長度 (<2..2^16-1> 意思是資料要從第 3 個 byte 開始看)
        - 後面每2個byte是一個group id
    */
    char curves_str[512] = {0};
    const unsigned char *curves_data = NULL;
    size_t curves_len = 0;

    if (SSL_client_hello_get0_ext(ssl, TLSEXT_TYPE_supported_groups, &curves_data, &curves_len)) {
        if (curves_data && curves_len > 2) {
            // 每個 curve ID 佔 2 byte (network byte order)
            for (size_t i = 2; i + 1 < curves_len; i += 2) {
                uint16_t curve_id = (curves_data[i] << 8) | curves_data[i + 1];
    
                char curve_buf[8];
                snprintf(curve_buf, sizeof(curve_buf), "%u", curve_id);
    
                if (i > 2) {
                    if (strlen(curves_str) + strlen("-") + 1 < sizeof(curves_str)){
                        strncat(curves_str, "-", 1);
                    }
                }
                if (strlen(curves_str) + strlen(curve_buf) + 1 < sizeof(curves_str)) {
                    strncat(curves_str, curve_buf, strlen(curve_buf));
                }
            }
        }
    }
    fprintf(stderr, "EllipticCurves: %s\n", curves_str);

    // 5. 取得 ECPointFormats (extension 11)
    char point_formats_str[512] = {0};
    const unsigned char *pf_data = NULL;
    size_t pf_len = 0;

    if (SSL_client_hello_get0_ext(ssl, TLSEXT_TYPE_ec_point_formats, &pf_data, &pf_len)) {
        // pf_data[0] 是 list length
        if (pf_data && pf_len > 1) {
            for (size_t i = 1; i < pf_len; i++) {
                char pf_buf[8];
                snprintf(pf_buf, sizeof(pf_buf), "%u", pf_data[i]);

                if (i > 1) {
                    if (strlen(point_formats_str) + strlen("-") + 1 < sizeof(point_formats_str)){
                        strncat(point_formats_str, "-", 1);
                    }
                }
                if (strlen(point_formats_str) + strlen(pf_buf) + 1 < sizeof(point_formats_str)) {
                    strncat(point_formats_str, pf_buf, strlen(pf_buf));
                }
            }
        }
    }
    fprintf(stderr, "ECPointFormats: %s\n", point_formats_str);

    // 6. 組合 JA3 字串
    snprintf(ja3, sizeof(ja3), "%s,%s,%s,%s,%s", 
            version_str, cipher_str, ext_str, curves_str, point_formats_str);
    /* log JA3 string only */
    fprintf(stderr,"[JA3] %s\n", ja3);

    return SSL_CLIENT_HELLO_SUCCESS;
}

static ngx_int_t ngx_ja3_init(ngx_conf_t *cf)
{
    // 1. 取得 HTTP 主設定（裡面有所有 server block）
    ngx_http_core_main_conf_t *cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    if (!cmcf) return NGX_ERROR; // 沒有主設定就結束

    // 2. 取得所有 server block 的陣列
    ngx_http_core_srv_conf_t **servers = cmcf->servers.elts;
    ngx_uint_t server_count = cmcf->servers.nelts;

    // 3. 逐一處理每個 server block
    for (ngx_uint_t i = 0; i < server_count; i++) {
        ngx_http_core_srv_conf_t *srv = servers[i];

        // 4. 取得這個 server block 的 SSL 設定
        ngx_http_ssl_srv_conf_t *ssl_conf = ngx_http_conf_get_module_srv_conf(srv, ngx_http_ssl_module);

        // 5. 如果有啟用 SSL，註冊 ClientHello callback
        if (ssl_conf && ssl_conf->ssl.ctx) {
            SSL_CTX_set_client_hello_cb(ssl_conf->ssl.ctx, ngx_ja3_client_hello_cb, NULL);
        }
    }
    return NGX_OK;
}