import frida, time, sys

device = frida.get_device('192.168.1.16:39911')
pid = 8004
print(f'attaching to PID {pid}...')
session = device.attach(pid)
print('attached')

script_code = """
Java.perform(function() {
    var libgo = Process.findModuleByName("libgojni.so");
    if (libgo) {
        console.log("libgojni.so: " + libgo.base + " size=0x" + libgo.size.toString(16));
    }
    
    // 读 Go 堆内存
    try {
        var heapBase = ptr("0x4000000000");
        var data = heapBase.readByteArray(0x100000);
        if (data) {
            var arr = new Uint8Array(data);
            console.log("Go heap: " + arr.length + " bytes");
            
            // 搜索 AES key
            var key = [0x71,0x74,0x4f,0x74,0x6f,0x46,0x31,0x34];
            for (var i = 0; i < arr.length - 32; i++) {
                if (arr[i] === key[0] && arr[i+1] === key[1] && arr[i+2] === key[2]) {
                    var match = true;
                    for (var j = 3; j < 8; j++) {
                        if (arr[i+j] !== key[j]) { match = false; break; }
                    }
                    if (match) {
                        var s = "";
                        for (var k = 0; k < 48; k++) s += String.fromCharCode(arr[i+k]);
                        console.log("AES_KEY at heap+0x" + i.toString(16) + ": " + s);
                    }
                }
            }
            
            // 搜索 PSK
            for (var i = 0; i < arr.length - 52; i++) {
                if (arr[i] === 0x70 && arr[i+1] === 0x50 && arr[i+2] === 0x56 && arr[i+3] === 0x57 && arr[i+4] === 0x51) {
                    var s = "";
                    for (var k = 0; k < 60; k++) s += String.fromCharCode(arr[i+k]);
                    console.log("PSK at heap+0x" + i.toString(16) + ": " + s);
                }
            }
            
            // 搜索 app_line
            for (var i = 0; i < arr.length - 20; i++) {
                if (arr[i] === 0x61 && arr[i+1] === 0x70 && arr[i+2] === 0x70 && arr[i+3] === 0x5f) {
                    var s = "";
                    for (var k = 0; k < 30 && i+k < arr.length; k++) {
                        if (arr[i+k] >= 32 && arr[i+k] <= 126) s += String.fromCharCode(arr[i+k]);
                        else break;
                    }
                    if (s.indexOf("app_line") >= 0) {
                        console.log("app_line at heap+0x" + i.toString(16) + ": " + s);
                    }
                }
            }
        }
    } catch(e) { console.log("heap error: " + e); }
    
    send({type: "done"});
});
"""

script = session.create_script(script_code)
script.on('message', lambda msg, data: print(f'[msg] {msg}'))
script.load()
print('waiting 15s...')
time.sleep(15)
session.detach()
print('done')
