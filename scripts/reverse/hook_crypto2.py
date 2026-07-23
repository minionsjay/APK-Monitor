import frida, time, sys

device = frida.get_device('192.168.1.16:39911')
pid = 8004
print(f'attaching to PID {pid}...')
session = device.attach(pid)
print('attached')

script_code = """
Java.perform(function() {
    var libgo = Process.findModuleByName('libgojni.so');
    if (libgo) {
        console.log('libgojni.so base: ' + libgo.base + ' size: 0x' + libgo.size.toString(16));
        
        // 搜索 AES 指令
        var textBase = libgo.base.add(0x17c500);
        var textSize = 0x4addf8 - 0x17c500;
        console.log('.text at ' + textBase + ' size 0x' + textSize.toString(16));
        
        // ARM64 AES 指令
        var patterns = [
            {name: 'AESE', pattern: '4e 28 48 00'},
            {name: 'AESD', pattern: '4e 28 58 00'},
        ];
        
        patterns.forEach(function(ap) {
            try {
                var results = Memory.scanSync(textBase, textSize, ap.pattern);
                if (results.length > 0) {
                    console.log(ap.name + ': ' + results.length + ' hits');
                    results.slice(0,5).forEach(function(r) {
                        console.log('  ' + r.address + ' (offset 0x' + r.address.sub(libgo.base).toString(16) + ')');
                    });
                }
            } catch(e) { console.log(ap.name + ' scan error: ' + e); }
        });
    }
    
    // 读 Go 堆内存搜索密钥
    try {
        var heapBase = ptr('0x4000000000');
        
        // 读取前 4MB
        for (var chunk = 0; chunk < 4; chunk++) {
            var addr = heapBase.add(chunk * 0x100000);
            try {
                var data = addr.readByteArray(0x100000);
                if (data) {
                    var arr = new Uint8Array(data);
                    
                    // 搜索 AES key
                    var key = [0x71,0x74,0x4f,0x74,0x6f,0x46,0x31,0x34];
                    for (var i = 0; i < arr.length - 32; i++) {
                        if (arr[i] === key[0] && arr[i+1] === key[1] && arr[i+2] === key[2]) {
                            var match = true;
                            for (var j = 3; j < 8; j++) {
                                if (arr[i+j] !== key[j]) { match = false; break; }
                            }
                            if (match) {
                                var s = '';
                                for (var k = 0; k < 48; k++) s += String.fromCharCode(arr[i+k]);
                                console.log('AES_KEY at heap+0x' + (chunk*0x100000+i).toString(16) + ': ' + s);
                            }
                        }
                    }
                    
                    // 搜索 PSK
                    var psk = [0x70,0x50,0x56,0x57,0x51];
                    for (var i = 0; i < arr.length - 52; i++) {
                        if (arr[i] === psk[0] && arr[i+1] === psk[1] && arr[i+2] === psk[2] && arr[i+3] === psk[3] && arr[i+4] === psk[4]) {
                            var s = '';
                            for (var k = 0; k < 60; k++) s += String.fromCharCode(arr[i+k]);
                            console.log('PSK at heap+0x' + (chunk*0x100000+i).toString(16) + ': ' + s);
                        }
                    }
                    
                    // 搜索 DEADBEEF
                    var dead = [0xde,0xad,0xbe,0xef];
                    for (var i = 0; i < arr.length - 8; i++) {
                        if (arr[i] === dead[0] && arr[i+1] === dead[1] && arr[i+2] === dead[2] && arr[i+3] === dead[3]) {
                            var hex = '';
                            for (var k = 0; k < 32; k++) hex += ('0' + arr[i+k].toString(16)).slice(-2);
                            console.log('DEADBEEF at heap+0x' + (chunk*0x100000+i).toString(16) + ': ' + hex);
                        }
                    }
                }
            } catch(e) {}
        }
    } catch(e) {
        console.log('Heap error: ' + e);
    }
    
    // 搜索 app_line_ips
    try {
        var heapBase = ptr('0x4000000000');
        for (var chunk = 0; chunk < 4; chunk++) {
            var addr = heapBase.add(chunk * 0x100000);
            try {
                var data = addr.readByteArray(0x100000);
                if (data) {
                    var str = '';
                    var arr = new Uint8Array(data);
                    // 搜索 "app_line_ips"
                    for (var i = 0; i < arr.length - 20; i++) {
                        if (arr[i] === 0x61 && arr[i+1] === 0x70 && arr[i+2] === 0x70 && arr[i+3] === 0x5f) {
                            // "app_"
                            var s = '';
                            for (var k = 0; k < 30 && i+k < arr.length; k++) {
                                if (arr[i+k] >= 32 && arr[i+k] <= 126) s += String.fromCharCode(arr[i+k]);
                                else break;
                            }
                            if (s.indexOf('app_line') >= 0) {
                                console.log('app_line at heap+0x' + (chunk*0x100000+i).toString(16) + ': ' + s);
                            }
                        }
                    }
                }
            } catch(e) {}
        }
    } catch(e) {}
    
    send({type: 'done'});
});
"""

script = session.create_script(script_code)
script.on('message', lambda msg, data: print(f'[msg] {msg}'))
script.load()
print('script loaded, waiting 30s...')
time.sleep(30)
session.detach()
print('done')
