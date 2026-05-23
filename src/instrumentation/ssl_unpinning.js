// SSL Pinning 绕过脚本
// 此脚本会 Hook 多个层面的 SSL 验证函数，强制应用信任系统证书

console.log("[*] SSL Unpinning script loaded");

// ==================== Java 层 SSL Pinning 绕过 ====================

// 1. Hook javax.net.ssl.TrustManager
if (typeof Java !== 'undefined' && Java.available) {
    Java.perform(function() {
        console.log("[*] Hooking Java SSL TrustManager...");
        
        // 1.1 Hook X509TrustManager
        var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
        X509TrustManager.checkServerTrusted.implementation = function(chain, authType) {
            console.log("[+] Bypassed checkServerTrusted for X509TrustManager");
            // 直接返回，不进行任何验证
        };
        
        // 1.2 Hook TrustManagerFactory
        var TrustManagerFactory = Java.use("javax.net.ssl.TrustManagerFactory");
        TrustManagerFactory.init.implementation = function(ks) {
            console.log("[+] Bypassed TrustManagerFactory.init");
            // 调用原始方法，但忽略异常
            try {
                this.init(ks);
            } catch (e) {
                console.log("[*] Ignored exception in TrustManagerFactory.init: " + e);
            }
        };
        
        // 2. Hook 常见网络库的 SSL Pinning
        
        // 2.1 Hook OkHttp3
        try {
            var OkHttpClient = Java.use("okhttp3.OkHttpClient");
            var Builder = OkHttpClient.Builder;
            if (Builder) {
                console.log("[*] Hooking OkHttp3...");
                // 尝试 Hook 证书验证相关方法
                var CertificatePinner = Java.use("okhttp3.CertificatePinner");
                if (CertificatePinner) {
                    CertificatePinner.check.implementation = function(hostname, peerCertificates) {
                        console.log("[+] Bypassed OkHttp3 CertificatePinner.check for " + hostname);
                        // 直接返回，不进行验证
                    };
                }
            }
        } catch (e) {
            console.log("[*] OkHttp3 not found, skipping...");
        }
        
        // 2.2 Hook Retrofit (通常基于 OkHttp3)
        try {
            var Retrofit = Java.use("retrofit2.Retrofit");
            console.log("[*] Retrofit found, but it usually uses OkHttp3 for SSL");
        } catch (e) {
            console.log("[*] Retrofit not found, skipping...");
        }
        
        // 2.3 Hook Volley
        try {
            var HurlStack = Java.use("com.android.volley.toolbox.HurlStack");
            console.log("[*] Hooking Volley HurlStack...");
            // Volley 使用 HttpURLConnection，通常会受到 TrustManager 钩子的影响
        } catch (e) {
            console.log("[*] Volley not found, skipping...");
        }
        
        // 2.4 Hook TrustKit (常见的 SSL Pinning 库)
        try {
            var TrustKit = Java.use("com.datatheorem.android.trustkit.TrustKit");
            console.log("[*] Hooking TrustKit...");
            var PinningTrustManager = Java.use("com.datatheorem.android.trustkit.pinning.PinningTrustManager");
            PinningTrustManager.checkServerTrusted.implementation = function(chain, authType) {
                console.log("[+] Bypassed TrustKit PinningTrustManager.checkServerTrusted");
                // 直接返回，不进行验证
            };
        } catch (e) {
            console.log("[*] TrustKit not found, skipping...");
        }
        
        // 3. Hook 网络连接相关类
        
        // 3.1 Hook HttpsURLConnection
        try {
            var HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
            console.log("[*] Hooking HttpsURLConnection...");
            HttpsURLConnection.setDefaultHostnameVerifier.implementation = function(verifier) {
                console.log("[+] Bypassed HttpsURLConnection.setDefaultHostnameVerifier");
                // 使用一个始终返回 true 的验证器
                var HostnameVerifier = Java.use("javax.net.ssl.HostnameVerifier");
                var fakeVerifier = Java.registerClass({
                    name: "com.example.FakeHostnameVerifier",
                    implements: [HostnameVerifier],
                    methods: {
                        verify: function(hostname, session) {
                            console.log("[+] Bypassed hostname verification for " + hostname);
                            return true;
                        }
                    }
                });
                this.setDefaultHostnameVerifier(fakeVerifier.$new());
            };
        } catch (e) {
            console.log("[*] Error hooking HttpsURLConnection: " + e);
        }
        
        console.log("[+] Java SSL unpinning hooks applied");
    });
}

// ==================== Native 层 SSL Pinning 绕过 ====================

// 注意：Native 层 Hook 可能需要根据目标应用的具体情况进行调整
if (Process.arch === 'arm' || Process.arch === 'arm64') {
    console.log("[*] Checking for Native SSL libraries...");
    
    // 尝试 Hook OpenSSL 函数
    var opensslModule = Process.findModuleByName("libssl.so");
    if (opensslModule) {
        console.log("[*] Found libssl.so, hooking SSL functions...");
        
        // 尝试找到并 Hook SSL_CTX_set_custom_verify 函数
        var SSL_CTX_set_custom_verify = opensslModule.findExportByName("SSL_CTX_set_custom_verify");
        if (SSL_CTX_set_custom_verify) {
            console.log("[+] Found SSL_CTX_set_custom_verify, hooking...");
            Interceptor.attach(SSL_CTX_set_custom_verify, {
                onEnter: function(args) {
                    console.log("[+] Bypassed SSL_CTX_set_custom_verify");
                    // 可以在这里修改验证回调，但简单起见，我们只是记录
                }
            });
        }
        
        // 尝试找到并 Hook SSL_set_verify 函数
        var SSL_set_verify = opensslModule.findExportByName("SSL_set_verify");
        if (SSL_set_verify) {
            console.log("[+] Found SSL_set_verify, hooking...");
            Interceptor.attach(SSL_set_verify, {
                onEnter: function(args) {
                    console.log("[+] Bypassed SSL_set_verify");
                    // 可以在这里修改验证模式，但简单起见，我们只是记录
                }
            });
        }
    } else {
        console.log("[*] libssl.so not found, skipping native hooks");
    }
}

console.log("[+] SSL Unpinning setup complete");
