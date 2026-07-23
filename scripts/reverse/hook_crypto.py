import frida, time, json, sys

device = frida.get_device('192.168.1.16:39911')
print(f'device: {device}')

PKG = 'bmv.tnoopkeqceeq.vigqccxfmniyfnjucuns'

# 找到运行中的进程
pid = None
for p in device.enumerate_processes():
    if PKG in p.name:
        pid = p.pid
        print(f'target: {p.name} PID={pid}')
        break

if not pid:
    print('APP not running, starting...')
    import subprocess
    subprocess.run(['adb', '-s', '192.168.1.16:39911', 'shell', 
                     'am', 'start', '-n', f'{PKG}/org.telegram.messenger.DefaultIcon'])
    time.sleep(5)
    for p in device.enumerate_processes():
        if PKG in p.name:
            pid = p.pid
            print(f'started: {p.name} PID={pid}')
            break

if not pid:
    print('ERROR: cannot find process')
    sys.exit(1)

session = device.attach(pid)
print(f'attached to PID {pid}')

# Frida 16.x has Java bridge
script_code = """
Java.perform(function() {
    // Hook crypto/aes.NewCipher (via JNI bridge - Go functions are native)
    // Go 的 crypto/aes.NewCipher 实际上在 native 层
    // 但 Go 通过 gobind/JNI 调用
    
    // 方案1: Hook libgojni.so 中的 AES 相关函数
    // 搜索 AES key 创建时的内存模式
    
    var libgo = Process.findModuleByName('libgojni.so');
    if (libgo) {
        console.log('libgojni.so base: ' + libgo.base + ' size: ' + libgo.size);
        
        // 搜索 AES-GCM 相关函数
        // 从 Ghidra 知道: aes.NewCipher 字符串在 0x5a0998 (相对偏移)
        // cipher.NewGCM 字符串在 0x59f04b
        
        // Hook crypto/tls.Conn.Write (用于抓取明文请求数据)
        // 从 Ghidra: tryForwarderControlEndpoints 调用 crypto_tls___Conn__Write
        
        // 方案2: 直接搜索 Go 堆中的 AES key (32 bytes)
        // AES-256 key 通常在内存中有特定模式
        
        // 方案3: Hook 所有 AES 操作
        // 搜索 AES 轮密钥扩展的指令模式
        // ARM64 AES 指令: aese, aesd, aesmc, aesimc
        
        // 方案4: 在 tryForwarderControlEndpoints 函数入口设置断点
        // 函数地址: 0x541390 (虚拟地址)
        // 文件偏移: 0x541390 - 0x4000 = 0x53D390
    }
    
    // 方案5: 搜索内存中的 AES S-box (固定值)
    // AES S-box 的前 16 bytes: 637c777bf26b6fc53001672bfed7ab76
    // 如果找到 S-box，附近的内存就是 AES 轮密钥
    
    console.log('Searching for AES S-box in libgojni.so memory...');
    
    var ranges = Process.enumerateRanges('rwx');
    var libgoBase = libgo ? libgo.base : null;
    
    if (libgoBase) {
        // 在 libgojni.so 的可执行段中搜索 AES 指令
        // ARM64 AES 指令编码:
        // AESE: 0x4E284800
        // AESD: 0x4E285800
        // AESMC: 0x4E286800
        // AESIMC: 0x4E287800
        
        var aesPatterns = [
            {name: 'AESE', pattern: '4e 28 48 00'},
            {name: 'AESD', pattern: '4e 28 58 00'},
            {name: 'AESMC', pattern: '4e 28 68 00'},
            {name: 'AESIMC', pattern: '4e 28 78 00'},
        ];
        
        // 搜索 libgojni.so 的 .text 段
        var textBase = libgoBase.add(0x17c500);  // .text offset
        var textSize = 0x4addf8 - 0x17c500;  // .text size
        
        console.log('Searching .text at ' + textBase + ' size ' + textSize);
        
        // 搜索 AES 指令
        aesPatterns.forEach(function(ap) {
            var results = Memory.scanSync(textBase, textSize, ap.pattern);
            if (results.length > 0) {
                console.log(ap.name + ': found ' + results.length + ' occurrences');
                results.slice(0, 3).forEach(function(r) {
                    console.log('  at ' + r.address);
                });
            }
        });
    }
    
    // 方案6: 直接在 Go 堆中搜索 32-byte key
    // 搜索包含已知 AES key 模式的内存
    console.log('\\nSearching Go heap for keys...');
    
    // Go 堆段通常以 0x4000000000 开头
    var heapBase = ptr('0x4000000000');
    var heapSize = 0x10000000; // 256MB max
    
    try {
        // 搜索 AES key schedule 的特征
        // 如果 AES-256 key 在内存中，它后面会有扩展的轮密钥
        // 但更简单的方法是 hook 函数调用
        
        // 方案7: 用 Interceptor hook tryForwarderControlEndpoints
        // 但 Go 函数的参数通过寄存器传递，难以直接读取
        
        // 方案8: 直接读 Go 堆内存找 AES key
        // 读取堆的前 4MB
        var heapData = heapBase.readByteArray(0x400000);
        if (heapData) {
            var arr = new Uint8Array(heapData);
            console.log('Go heap read: ' + arr.length + ' bytes');
            
            // 搜索已知的 AES key
            var aesKey = [0x71, 0x74, 0x4f, 0x74, 0x6f, 0x46, 0x31, 0x34, 
                         0x63, 0x4b, 0x78, 0x54, 0x6a, 0x72, 0x54, 0x6f];
            var found = false;
            for (var i = 0; i < arr.length - 16; i++) {
                if (arr[i] === aesKey[0] && arr[i+1] === aesKey[1]) {
                    var match = true;
                    for (var j = 2; j < 16; j++) {
                        if (arr[i+j] !== aesKey[j]) { match = false; break; }
                    }
                    if (match) {
                        console.log('AES_KEY found at heap offset 0x' + i.toString(16));
                        // 读取附近 64 bytes
                        var nearby = '';
                        for (var k = -16; k < 48; k++) {
                            nearby += arr[i+k].toString(16).padStart(2, '0');
                        }
                        console.log('nearby: ' + nearby);
                        found = true;
                    }
                }
            }
            if (!found) console.log('AES_KEY not in first 4MB of heap');
        }
    } catch(e) {
        console.log('Heap read error: ' + e);
    }
    
    send({type: 'done'});
});
"""

script = session.create_script(script_code)
script.on('message', lambda msg, data: print(f'[msg] {msg}'))
script.load()
print('script loaded, waiting...')
time.sleep(30)
session.detach()
print('done')
