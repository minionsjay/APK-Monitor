import frida, time, json, os

device = frida.get_usb_device()

# Find target
pid = 6678
for p in device.enumerate_processes():
    if 'guabtlu' in p.name or 'guabtlu' in str(p):
        pid = p.pid
        print(f'Target: {p.name} (PID={pid})')
        break

if not pid:
    print('Target not running, launching...')
    # Launch
    import subprocess
    subprocess.run(['adb', 'shell', 'monkey', '-p', 'guabtlu.pvgi.qcxmvajd', '-c', 'android.intent.category.LAUNCHER', '1'],
                   capture_output=True)
    time.sleep(5)
    for p in device.enumerate_processes():
        if 'guabtlu' in p.name or 'guabtlu' in str(p):
            pid = p.pid
            print(f'Target: {p.name} (PID={pid})')
            break

if not pid:
    print('ERROR: cannot find target process')
    exit(1)

session = device.attach(pid)
print(f'Attached to PID {pid}')

# Use native hooks (libc level) - works without Java bridge
script_code = """
// Native hooks for network connections (libc level)
var libc = Process.findModuleByName('libc.so');

// Hook connect() to catch all TCP connections
var connect = new NativeFunction(
    Module.findExportByName('libc.so', 'connect'),
    'int', ['int', 'pointer', 'int']
);

Interceptor.attach(Module.findExportByName('libc.so', 'connect'), {
    onEnter: function(args) {
        var sockaddr = args[1];
        var family = sockaddr.readU16();
        if (family === 2) { // AF_INET
            var port = (sockaddr.add(2).readU8() << 8) | sockaddr.add(3).readU8();
            var ip = sockaddr.add(4).readU8() + '.' +
                     sockaddr.add(5).readU8() + '.' +
                     sockaddr.add(6).readU8() + '.' +
                     sockaddr.add(7).readU8();
            send({type: 'connect', ip: ip, port: port});
        } else if (family === 10) { // AF_INET6
            var port = (sockaddr.add(2).readU8() << 8) | sockaddr.add(3).readU8();
            send({type: 'connect6', port: port});
        }
    }
});

// Hook getaddrinfo for DNS resolution
Interceptor.attach(Module.findExportByName('libc.so', 'getaddrinfo'), {
    onEnter: function(args) {
        var host = args[0].readCString();
        if (host) {
            send({type: 'dns_resolve', host: host});
        }
    }
});

// Hook open/openat for file access (interesting files only)
Interceptor.attach(Module.findExportByName('libc.so', 'openat'), {
    onEnter: function(args) {
        var path = args[1].readCString();
        if (path && (path.indexOf('/proc/') === 0 || path.indexOf('/sys/') === 0 ||
            path.indexOf('/data/') === 0 || path.indexOf('/sdcard/') === 0 ||
            path.indexOf('/storage/') === 0)) {
            // Only log interesting paths (not every file)
            if (path.indexOf('/proc/self/') !== 0 && path.indexOf('.so') === -1) {
                send({type: 'file_open', path: path});
            }
        }
    }
});

// Hook sendto/send for outgoing data
var sendto = Module.findExportByName('libc.so', 'sendto');
if (sendto) {
    Interceptor.attach(sendto, {
        onEnter: function(args) {
            var len = args[2].toInt32();
            if (len > 10 && len < 500) {
                try {
                    var data = args[1].readByteArray(Math.min(len, 200));
                    send({type: 'sendto', size: len}, data);
                } catch(e) {}
            }
        }
    });
}

// Hook execve for command execution
var execve = Module.findExportByName('libc.so', 'execve');
if (execve) {
    Interceptor.attach(execve, {
        onEnter: function(args) {
            var cmd = args[0].readCString();
            send({type: 'exec', cmd: cmd});
        }
    });
}

// Hook dlopen for dynamic library loading
Interceptor.attach(Module.findExportByName(null, 'android_dlopen_ext'), {
    onEnter: function(args) {
        var lib = args[0].readCString();
        if (lib) {
            send({type: 'dlopen', lib: lib});
        }
    }
});

// Also hook __system_property_get for device info collection
Interceptor.attach(Module.findExportByName('libc.so', '__system_property_get'), {
    onEnter: function(args) {
        var name = args[0].readCString();
        if (name) {
            this.propName = name;
        }
    },
    onLeave: function(retval) {
        if (this.propName) {
            // Only log interesting properties
            var interesting = ['ro.serialno', 'ro.product.model', 'ro.build.version.release',
                'ro.build.display.id', 'ro.boot.serialno', 'ro.hardware',
                'persist.sys.timezone', 'gsm.sim.operator', 'gsm.operator.numeric',
                'gsm.serial', 'ro.bootmode', 'ro.bootloader'];
            if (interesting.indexOf(this.propName) >= 0) {
                try {
                    var value = this.context.x1 ? args[1].readCString() : '';
                } catch(e) {}
                send({type: 'property', name: this.propName});
            }
        }
    }
});

send({type: 'hooks_installed'});
"""

script = session.create_script(script_code)

events = []
def on_message(message, data):
    if message['type'] == 'send':
        payload = message['payload']
        events.append(payload)
        tp = payload.get('type', '')
        if tp == 'hooks_installed':
            print('[*] Hooks installed, monitoring...')
        else:
            extra = {k:v for k,v in payload.items() if k != 'type'}
            if data:
                try:
                    extra['data_hex'] = data[:50].hex()
                except:
                    pass
            print(f'[{tp}] {json.dumps(extra, ensure_ascii=False)}')
    elif message['type'] == 'error':
        print(f'[ERROR] {message.get("description", "")}')

script.on('message', on_message)
script.load()

# Monitor for 90 seconds
print('[*] Monitoring runtime for 90 seconds...')
print('[*] Try interacting with the app on the device (tap, scroll) to trigger behavior')
time.sleep(90)

# Summary
print(f'\n[*] Total events: {len(events)}')
type_counts = {}
for e in events:
    t = e.get('type', 'unknown')
    type_counts[t] = type_counts.get(t, 0) + 1
for t, c in sorted(type_counts.items()):
    print(f'  {t}: {c}')

# Save events
outpath = '/home/ninini/Agents/APK-Research/dumped_dex/187689_runtime_events.json'
with open(outpath, 'w') as f:
    json.dump(events, f, indent=2, ensure_ascii=False, default=str)
print(f'[*] Events saved to {outpath}')

session.detach()
print('[*] Done')
