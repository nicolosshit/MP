// Frida 插桩脚本 - 增强版 (Pro)
// 包含：设备标识、地理位置、剪贴板、联系人、文件、应用列表、多媒体、传感器及加密拦截

console.log("[*] Frida hooks script loaded (Enhanced Version)");

// ==================== 辅助函数 ====================

function generateCanary(apiName) {
    var timestamp = Date.now();
    var random = Math.floor(Math.random() * 10000);
    return "CANARY-" + apiName.toUpperCase() + "-" + timestamp + "-" + random;
}

function getStackTrace() {
    try {
        throw new Error();
    } catch (e) {
        return e.stack || "No stack trace available";
    }
}

function sendMessage(type, api, payload, stackTrace) {
    send({
        type: type,
        api: api,
        payload: payload,
        stack_trace: stackTrace
    });
}

// ==================== 1. 设备标识符相关 API ====================

function hookDeviceIdentifiers() {
    if (Java.available) {
        Java.perform(function() {
            try {
                var TelephonyManager = Java.use("android.telephony.TelephonyManager");
                
                // getDeviceId (IMEI)
                TelephonyManager.getDeviceId.overload().implementation = function() {
                    var canary = generateCanary("getDeviceId");
                    sendMessage("canary_injected", "getDeviceId", canary, getStackTrace());
                    return canary;
                };
                
                // getImei (Android 6.0+)
                var getImeiOverloads = TelephonyManager.getImei.overloads;
                getImeiOverloads.forEach(function(overload) {
                    overload.implementation = function() {
                        var canary = generateCanary("getImei");
                        sendMessage("canary_injected", "getImei", canary, getStackTrace());
                        return canary;
                    }
                });

                // getSubscriberId (IMSI)
                TelephonyManager.getSubscriberId.overload().implementation = function() {
                    var canary = generateCanary("getSubscriberId");
                    sendMessage("canary_injected", "getSubscriberId", canary, getStackTrace());
                    return canary;
                };

                // getLine1Number (手机号)
                TelephonyManager.getLine1Number.overload().implementation = function() {
                    var canary = generateCanary("getLine1Number");
                    sendMessage("canary_injected", "getLine1Number", canary, getStackTrace());
                    return canary;
                };
            } catch (e) { console.log("[!] Error hooking TelephonyManager: " + e); }

            // MAC Address
            try {
                var WifiInfo = Java.use("android.net.wifi.WifiInfo");
                WifiInfo.getMacAddress.implementation = function() {
                    var canary = generateCanary("getMacAddress");
                    sendMessage("canary_injected", "getMacAddress", canary, getStackTrace());
                    return canary;
                };
            } catch (e) { console.log("[!] Error hooking WifiInfo: " + e); }
            
            // Android ID
            try {
                var Secure = Java.use("android.provider.Settings$Secure");
                Secure.getString.implementation = function(resolver, name) {
                    if (name === "android_id") {
                        var canary = "CANARY-ANDROIDID-" + Date.now();
                        sendMessage("canary_injected", "AndroidID", canary, getStackTrace());
                        return canary;
                    }
                    return this.getString(resolver, name);
                };
            } catch (e) { console.log("[!] Error hooking Settings.Secure: " + e); }
        });
    }
}

// ==================== 2. 地理位置相关 API ====================

function hookLocationAPIs() {
    if (Java.available) {
        Java.perform(function() {
            try {
                var LocationManager = Java.use("android.location.LocationManager");
                
                var getLastKnownLocationOverloads = LocationManager.getLastKnownLocation.overloads;
                getLastKnownLocationOverloads.forEach(function(overload) {
                    overload.implementation = function(provider) {
                        var stackTrace = getStackTrace();
                        sendMessage("hook_event", "getLastKnownLocation", { provider: provider }, stackTrace);
                        
                        try {
                            var Location = Java.use("android.location.Location");
                            var fakeLocation = Location.$new(provider);
                            fakeLocation.setLatitude(39.9042);
                            fakeLocation.setLongitude(116.4074);
                            return fakeLocation;
                        } catch (e) { return this.getLastKnownLocation(provider); }
                    }
                });

                var requestLocationUpdatesOverloads = LocationManager.requestLocationUpdates.overloads;
                requestLocationUpdatesOverloads.forEach(function(overload) {
                     overload.implementation = function() {
                         sendMessage("hook_event", "requestLocationUpdates", {}, getStackTrace());
                         return this.requestLocationUpdates.apply(this, arguments);
                     }
                });
            } catch (e) { console.log("[!] Error hooking LocationManager: " + e); }
        });
    }
}

// ==================== 3. 应用列表 (PackageManager) ====================

function hookPackageManager() {
    if (Java.available) {
        Java.perform(function() {
            try {
                var PackageManager = Java.use("android.app.ApplicationPackageManager");
                
                // getInstalledPackages
                PackageManager.getInstalledPackages.overload('int').implementation = function(flags) {
                    sendMessage("hook_event", "getInstalledPackages", { flags: flags }, getStackTrace());
                    // 策略：可以返回精简列表以防检测，或者直接放行但记录
                    return this.getInstalledPackages(flags);
                };

                // getInstalledApplications
                PackageManager.getInstalledApplications.overload('int').implementation = function(flags) {
                    sendMessage("hook_event", "getInstalledApplications", { flags: flags }, getStackTrace());
                    return this.getInstalledApplications(flags);
                };
            } catch (e) { console.log("[!] Error hooking PackageManager: " + e); }
        });
    }
}

// ==================== 4. 多媒体与传感器 (Camera/Mic/Sensor) ====================

function hookMediaAndSensors() {
    if (Java.available) {
        Java.perform(function() {
            // Camera (Old API)
            try {
                var Camera = Java.use("android.hardware.Camera");
                Camera.open.overload().implementation = function() {
                    sendMessage("hook_event", "Camera.open", {}, getStackTrace());
                    return this.open();
                };
                Camera.open.overload('int').implementation = function(id) {
                    sendMessage("hook_event", "Camera.open", { id: id }, getStackTrace());
                    return this.open(id);
                };
            } catch (e) {}

            // Audio Record
            try {
                var MediaRecorder = Java.use("android.media.MediaRecorder");
                MediaRecorder.start.implementation = function() {
                    sendMessage("hook_event", "MediaRecorder.start", {}, getStackTrace());
                    return this.start();
                };
            } catch (e) {}

            // Sensors (Step Counter, etc.)
            try {
                var SensorManager = Java.use("android.hardware.SensorManager");
                SensorManager.registerListener.overload('android.hardware.SensorEventListener', 'android.hardware.Sensor', 'int').implementation = function(listener, sensor, rate) {
                    if (sensor) {
                        var sensorName = sensor.getName();
                        // 过滤掉常用非敏感传感器，只关注敏感的
                        if (sensorName.includes("Step") || sensorName.includes("Proximity") || sensorName.includes("Accelerometer")) {
                            sendMessage("hook_event", "SensorManager.registerListener", { sensor: sensorName }, getStackTrace());
                        }
                    }
                    return this.registerListener(listener, sensor, rate);
                };
            } catch (e) {}
        });
    }
}

// ==================== 5. 短信与联系人 ====================

function hookSmsAndContacts() {
    if (Java.available) {
        Java.perform(function() {
            // SMS
            try {
                var SmsManager = Java.use("android.telephony.SmsManager");
                SmsManager.getAllMessagesFromIcc.implementation = function() {
                    sendMessage("hook_event", "SmsManager.getAllMessagesFromIcc", {}, getStackTrace());
                    return this.getAllMessagesFromIcc();
                };
            } catch (e) {}

            // Contacts Query (ContentResolver)
            try {
                var ContentResolver = Java.use("android.content.ContentResolver");
                ContentResolver.query.overload("android.net.Uri", "[Ljava.lang.String;", "java.lang.String", "[Ljava.lang.String;", "java.lang.String").implementation = function(uri, projection, selection, selectionArgs, sortOrder) {
                    var uriStr = uri.toString();
                    if (uriStr.includes("contacts") || uriStr.includes("call_log") || uriStr.includes("sms")) {
                        sendMessage("hook_event", "ContentResolver.query", { uri: uriStr }, getStackTrace());
                    }
                    return this.query(uri, projection, selection, selectionArgs, sortOrder);
                };
            } catch (e) {}
        });
    }
}

// ==================== 6. 加密拦截 (对抗应用层加密) ====================

function hookEncryption() {
    if (Java.available) {
        Java.perform(function() {
            try {
                var Cipher = Java.use("javax.crypto.Cipher");
                
                // Hook doFinal 用于捕获加密前的明文 (Encrypt Mode) 或 解密后的明文 (Decrypt Mode)
                Cipher.doFinal.overload('[B').implementation = function(input) {
                    var ret = this.doFinal(input);
                    
                    try {
                        // 检查模式：1=ENCRYPT_MODE, 2=DECRYPT_MODE
                        // 这里我们无法直接获取 mode，但可以通过输入输出判断
                        // 如果是加密操作，input 是明文。如果是解密操作，ret 是明文。
                        
                        // 尝试将 input 转为字符串并检查是否有敏感词
                        var inputStr = "";
                        for (var i = 0; i < input.length; ++i) 
                            inputStr += String.fromCharCode(input[i]);
                            
                        // 简单的启发式检查：如果输入包含 "CANARY-"，说明正在加密我们的金丝雀
                        if (inputStr.includes("CANARY-")) {
                            sendMessage("privacy_leak", "Cipher.doFinal (Encryption)", {
                                risk: "High",
                                evidence: "App is encrypting sensitive data: " + inputStr.substring(0, 50) + "..."
                            }, getStackTrace());
                        }
                        
                    } catch (e) {}
                    
                    return ret;
                };
            } catch (e) { console.log("[!] Error hooking Cipher: " + e); }
        });
    }
}

// ==================== 初始化 ====================



// ==================== [新增] 7. Native 层监控 (对抗 C/C++ 绕过) ====================

function hookNativeIO() {
    console.log("[*] Initializing Native Hooks (libc.so)...");
    
    // 监控文件打开操作 (open/openat)
    // 很多恶意 SDK 会直接读取 /proc/net/arp 或 /sdcard 下的文件
    var openPtr = Module.findExportByName("libc.so", "open");
    var openatPtr = Module.findExportByName("libc.so", "openat");

    if (openPtr) {
        Interceptor.attach(openPtr, {
            onEnter: function(args) {
                this.path = Memory.readUtf8String(args[0]);
            },
            onLeave: function(retval) {
                if (this.path) {
                    // 过滤掉系统杂音，只关注敏感路径
                    if (this.path.indexOf("/proc/") >= 0 || 
                        this.path.indexOf("/sdcard/") >= 0 || 
                        this.path.indexOf("dcim") >= 0) {
                        
                        sendMessage("hook_event", "Native::open", {
                            path: this.path,
                            fd: retval.toInt32()
                        }, getStackTrace()); // 注意：Native 堆栈可能需要 Symbolicate 处理，这里简化
                    }
                }
            }
        });
    }
}

// ==================== [新增] 8. 数据污点/混淆追踪 (Base64/Hash) ====================

function hookObfuscation() {
    if (Java.available) {
        Java.perform(function() {
            
            // 1. 监控 Base64 编码
            try {
                var Base64 = Java.use("android.util.Base64");
                
                // Hook encodeToString(byte[], int)
                Base64.encodeToString.overload('[B', 'int').implementation = function(input, flags) {
                    var ret = this.encodeToString(input, flags);
                    
                    // 检查输入是否包含我们的金丝雀
                    var inputStr = "";
                    try {
                        for (var i = 0; i < input.length; ++i) 
                            inputStr += String.fromCharCode(input[i]);
                    } catch(e) {}

                    if (inputStr.includes("CANARY-")) {
                        console.log("[!] Detected Canary obfuscation (Base64)!");
                        sendMessage("privacy_leak", "Data Obfuscation (Base64)", {
                            risk: "High",
                            original: inputStr.substring(0, 30) + "...",
                            obfuscated: ret.substring(0, 30) + "...",
                            description: "App attempted to hide sensitive data using Base64."
                        }, getStackTrace());
                    }
                    return ret;
                };
            } catch (e) { console.log("[!] Base64 hook failed: " + e); }

            // 2. 监控 MD5/SHA 哈希 (MessageDigest)
            try {
                var MessageDigest = Java.use("java.security.MessageDigest");
                
                MessageDigest.digest.overload('[B').implementation = function(input) {
                    var ret = this.digest(input);
                    
                    // 检查输入
                    var inputStr = "";
                    try {
                        for (var i = 0; i < input.length; ++i) 
                            inputStr += String.fromCharCode(input[i]);
                    } catch(e) {}

                    if (inputStr.includes("CANARY-")) {
                        var algo = this.getAlgorithm();
                        console.log("[!] Detected Canary hashing (" + algo + ")!");
                        
                        // 将二进制哈希转为 Hex 字符串以便展示
                        var hexHash = "";
                        for (var j = 0; j < ret.length; j++) {
                            var b = ret[j] & 0xFF;
                            if (b < 16) hexHash += "0";
                            hexHash += b.toString(16);
                        }

                        sendMessage("privacy_leak", "Data Obfuscation (" + algo + ")", {
                            risk: "Medium", // 哈希是单向的，通常用于指纹而非直接传输隐私，风险略低
                            original: inputStr.substring(0, 30) + "...",
                            obfuscated: hexHash,
                            description: "App generated a hash/fingerprint from sensitive data."
                        }, getStackTrace());
                    }
                    return ret;
                };
            } catch (e) { console.log("[!] MessageDigest hook failed: " + e); }
        });
    }
}

// ==================== 修改初始化函数 ====================

function init() {
    console.log("[*] Initializing Ultimate Frida hooks...");
    
    // 现有的 Hooks
    hookDeviceIdentifiers();
    hookLocationAPIs();
    hookPackageManager();
    hookMediaAndSensors();
    hookSmsAndContacts();
    hookEncryption(); 

    // 新增的 Hooks
    hookNativeIO();      // 开启 Native 监控
    hookObfuscation();   // 开启混淆追踪
    
    console.log("[+] All hooks initialized (Java + Native).");
}

// 安全初始化，避免脚本加载时Java对象不可用的问题
try {
    // 使用安全的方式检查Java对象是否存在
    if (typeof Java !== 'undefined') {
        if (Java.available) {
            Java.perform(init);
        } else {
            console.log("[*] Java not available yet, waiting...");
            // 可以添加一个延迟检查
            setTimeout(function() {
                // 安全检查：先判断 Java 变量是否被定义，再判断是否可用
                if (typeof Java !== 'undefined' && Java.available) {
                    console.log("[*] Java runtime detected. Performing Java hooks...");
                    Java.perform(init);
                } else {
                    console.log("[*] Java runtime NOT detected (Pure Native?). performing Native hooks only...");
                    // 如果没有 Java 环境，只启动 Native 监控
                    if (typeof hookNativeIO === 'function') {
                        hookNativeIO();
                    }
                }
            }, 1000);
        }
    } else {
        console.log("[*] Java object not found, skipping Java hooks.");
    }
} catch (e) {
    console.log("[!] Error during initialization: " + e);
}
