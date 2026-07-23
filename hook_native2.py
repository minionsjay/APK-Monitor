import frida, time, json, os

device = frida.get_usb_device()
pid = int(open('/dev/stdin','r').readline().strip()) if not os.isatty(0) else None
if not pid:
    import subprocess
    pid = int(subprocess.check_output(['adb','shell','pidof','guabtlu.pvgi.qcxmvajd']).decode().strip())
print(f'PID={pid}')
session = device.attach(pid)

script_code = """
// Hook connect()
var connect_ptr = Module.findExportByName('libc.so', 'connect');
if (connect_ptr) {
    Interceptor.attach(connect_ptr, {
        onEnter: function(args) {
            try {
                var sa = args[1];
                var family = sa.readU16();
                if (family === 2) {
                    var port = (sa.add(2).readU8() << 8) | sa.add(3).readU8();
                    var ip = sa.add(4).readU8() + '.' + sa.add(5).readU8() + '.' + sa.add(6).readU8() + '.' + sa.add(7).readU8();
                    send({type: 'connect', ip: ip, port: port});
                }
            } catch(e) { send({type: 'error', msg: 'connect: ' + e.toString()}); }
        }
    });
    send({type: 'status', msg: 'connect hooked'});
} else {
    send({type: 'status', msg: 'connect not found'});
}

// Hook getaddrinfo
var gai_ptr = Module.findExportByName('libc.so', 'getaddrinfo');
if (gai_ptr) {
    Interceptor.attach(gai_ptr, {
        onEnter: function(args) {
            try {
                var host = args[0].readCString();
                if (host && host.length > 3) {
                    send({type: 'dns', host: host});
                }
            } catch(e) {}
        }
    });
    send({type: 'status', msg: 'getaddrinfo hooked'});
}

// Hook openat
var openat_ptr = Module.findExportByName('libc.so', 'openat');
if (openat_ptr) {
    Interceptor.attach(openat_ptr, {
        onEnter: function(args) {
            try {
                var path = args[1].readCString();
                if (path) {
                    if (path.indexOf('/proc/') === 0 && path.indexOf('/proc/self/') !== 0) {
                        send({type: 'file', path: path});
                    }
                }
            } catch(e) {}
        }
    });
    send({type: 'status', msg: 'openat hooked'});
}

// Hook android_dlopen_ext
var dlopen_ptr = Module.findExportByName(null, 'android_dlopen_ext');
if (dlopen_ptr) {
    Interceptor.attach(dlopen_ptr, {
        onEnter: function(args) {
            try {
                var lib = args[0].readCString();
                if (lib) send({type: 'dlopen', lib: lib});
            } catch(e) {}
        }
    });
    send({type: 'status', msg: 'dlopen hooked'});
}

send({type: 'ready'});
"""

script = session.create_script(script_code)
events = []

def on_message(message, data):
    if message['type'] == 'send':
        payload = message['payload']
        events.append(payload)
        tp = payload.get('type', '')
        if tp == 'status' or tp == 'ready':
            print(f'[*] {payload.get("msg","ready")}')
        else:
            print(f'[{tp}] {json.dumps({k:v for k,v in payload.items() if k != "type"}, ensure_ascii=False)}')
    elif message['type'] == 'error':
        print(f'[ERR] {message.get("description", "")}')

script.on('message', on_message)
script.load()

print('[*] Monitoring for 90 seconds...')
time.sleep(90)

print(f'\n[*] Total events: {len(events)}')
tc = {}
for e in events:
    t = e.get('type', 'unknown')
    tc[t] = tc.get(t, 0) + 1
for t, c in sorted(tc.items()):
    print(f'  {t}: {c}')

with open('/home/ninini/Agents/APK-Research/dumped_dex/187689_runtime_events.json', 'w') as f:
    json.dump(events, f, indent=2, ensure_ascii=False, default=str)

session.detach()
