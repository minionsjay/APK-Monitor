import frida, sys, os, time

device = frida.get_usb_device()

# Find the running process
pkg = 'guabtlu.pvgi.qcxmvajd'
pid = None
for p in device.enumerate_processes():
    if pkg in p.name:
        pid = p.pid
        print(f'Found process: {p.name} (PID={pid})')
        break

if not pid:
    # Spawn it
    print('Spawning...')
    pid = device.spawn([pkg])
    device.resume(pid)
    time.sleep(5)

print(f'Attaching to PID {pid}...')
session = device.attach(pid)
print('Attached')

script_code = """
var ranges = Process.enumerateRanges({prot: 'r--', coalesce: true, coverage: 'full'});
var dexCount = 0;
var dexFiles = [];

var patterns = [
    '64 65 78 0a 30 33 35 00',
    '64 65 78 0a 30 33 36 00',
    '64 65 78 0a 30 33 37 00',
    '64 65 78 0a 30 33 38 00',
    '64 65 78 0a 30 33 39 00',
];

send({type: 'start', ranges: ranges.length});

for (var i = 0; i < ranges.length; i++) {
    try {
        for (var p = 0; p < patterns.length; p++) {
            var matches = Memory.scanSync(ranges[i].base, ranges[i].size, patterns[p]);
            for (var j = 0; j < matches.length; j++) {
                var addr = matches[j].address;
                var fileSize = addr.add(0x20).readU32();
                if (fileSize > 0x70 && fileSize < 100*1024*1024) {
                    var addrStr = addr.toString();
                    var isDup = false;
                    for (var k = 0; k < dexFiles.length; k++) {
                        if (dexFiles[k].addr === addrStr) { isDup = true; break; }
                    }
                    if (isDup) continue;

                    var data = addr.readByteArray(fileSize);
                    dexCount++;
                    dexFiles.push({addr: addrStr, size: fileSize});
                    send({type: 'dex', index: dexCount, addr: addrStr, size: fileSize}, data);
                }
            }
        }
    } catch(e) {
        send({type: 'error', msg: e.toString(), range: i});
    }
}
send({type: 'done', count: dexCount});
"""

script = session.create_script(script_code)
output_dir = '/home/ninini/Agents/APK-Research/dumped_dex/187689'
os.makedirs(output_dir, exist_ok=True)

def on_message(message, data):
    if message['type'] == 'send':
        payload = message['payload']
        tp = payload.get('type', '')
        if tp == 'dex' and data:
            idx = payload['index']
            path = os.path.join(output_dir, f'classes_{idx:02d}.dex')
            with open(path, 'wb') as f:
                f.write(data)
            sz = payload['size']
            print(f'  Dumped dex {idx}: {sz}B from {payload["addr"]} -> {path}')
        elif tp == 'done':
            print(f'Done! Dumped {payload["count"]} dex files')
        elif tp == 'start':
            print(f'Scanning {payload["ranges"]} memory ranges...')
        elif tp == 'error':
            print(f'  Error on range {payload.get("range","?")}: {payload.get("msg","")}')
    elif message['type'] == 'error':
        desc = message.get('description', '')
        stack = message.get('stack', '')
        print(f'Script error: {desc}')
        if stack:
            print(f'  Stack: {stack[:200]}')

script.on('message', on_message)
script.load()

# Wait for completion
time.sleep(60)

try:
    session.detach()
except:
    pass
print('Session detached')
