import frida, sys, os, time, json

device = frida.get_usb_device()
pid = 4891
print(f'Attaching to PID {pid}...')
session = device.attach(pid)
print('Attached')

# Hook all interesting runtime behaviors
script_code = """
Java.perform(function() {
// ===== DNS lookups =====
var InetAddress = Java.use('java.net.InetAddress');
InetAddress.getAllByName.implementation = function(host) {
    var results = this.getAllByName(host);
    var addrs = [];
    for (var i = 0; i < results.length; i++) {
        addrs.push(results[i].getHostAddress());
    }
    send({type: 'dns', host: host, addrs: addrs});
    return results;
};

// ===== DNS TXT (dnsjava) =====
try {
    var Lookup = Java.use('org.xbill.DNS.Lookup');
    Lookup.run.implementation = function() {
        var name = this.getName().toString();
        var type = this.getType();
        send({type: 'dns_txt_query', name: name, qtype: type});
        var result = this.run();
        if (result) {
            var records = [];
            for (var i = 0; i < result.length; i++) {
                records.push(result[i].rdataToString());
            }
            send({type: 'dns_txt_result', name: name, records: records});
        }
        return result;
    };
} catch(e) {}

// ===== HTTP connections =====
var URL = Java.use('java.net.URL');
URL.openConnection.overload().implementation = function() {
    var url = this.toString();
    send({type: 'http', url: url});
    return this.openConnection();
};

// ===== Socket connections =====
var Socket = Java.use('java.net.Socket');
Socket.$init.overload('java.lang.String', 'int').implementation = function(host, port) {
    send({type: 'socket', host: host, port: port});
    return this.$init(host, port);
};

// ===== SMS sending =====
try {
    var SmsManager = Java.use('android.telephony.SmsManager');
    SmsManager.sendTextMessage.implementation = function(destAddr, scAddr, text, sentIntent, deliveryIntent) {
        send({type: 'sms', dest: destAddr, text: text});
        return this.sendTextMessage(destAddr, scAddr, text, sentIntent, deliveryIntent);
    };
} catch(e) {}

// ===== Device ID / IMEI =====
try {
    var TelephonyManager = Java.use('android.telephony.TelephonyManager');
    TelephonyManager.getDeviceId.implementation = function() {
        var id = this.getDeviceId();
        send({type: 'device_id', id: id});
        return id;
    };
    TelephonyManager.getSubscriberId.implementation = function() {
        var subId = this.getSubscriberId();
        send({type: 'subscriber_id', id: subId});
        return subId;
    };
    TelephonyManager.getLine1Number.implementation = function() {
        var num = this.getLine1Number();
        send({type: 'phone_number', number: num});
        return num;
    };
} catch(e) {}

// ===== Location =====
try {
    var LocationManager = Java.use('android.location.LocationManager');
    LocationManager.getLastKnownLocation.implementation = function(provider) {
        var loc = this.getLastKnownLocation(provider);
        send({type: 'location', provider: provider, lat: loc ? loc.getLatitude() : null, lon: loc ? loc.getLongitude() : null});
        return loc;
    };
} catch(e) {}

// ===== Audio recording =====
try {
    var MediaRecorder = Java.use('android.media.MediaRecorder');
    MediaRecorder.start.implementation = function() {
        send({type: 'audio_record_start'});
        return this.start();
    };
} catch(e) {}

// ===== Camera =====
try {
    var Camera = Java.use('android.hardware.Camera');
    Camera.takePicture.implementation = function(shutter, raw, jpeg) {
        send({type: 'camera_capture'});
        return this.takePicture(shutter, raw, jpeg);
    };
} catch(e) {}

// ===== Class loading (dropper) =====
try {
    var DexClassLoader = Java.use('dalvik.system.DexClassLoader');
    DexClassLoader.$init.implementation = function(dexPath, optimizedDir, librarySearchPath, parent) {
        send({type: 'dex_load', path: dexPath, lib: librarySearchPath});
        return this.$init(dexPath, optimizedDir, librarySearchPath, parent);
    };
} catch(e) {}

// ===== Runtime exec =====
try {
    var Runtime = Java.use('java.lang.Runtime');
    Runtime.exec.overload('java.lang.String').implementation = function(cmd) {
        send({type: 'exec', cmd: cmd});
        return this.exec(cmd);
    };
} catch(e) {}

// ===== SharedPrefs (config storage) =====
try {
    var SharedPreferencesEditor = Java.use('android.app.SharedPreferencesImpl$EditorImpl');
    SharedPreferencesEditor.putString.implementation = function(key, value) {
        if (key && (key.contains('server') || key.contains('ip') || key.contains('port') || key.contains('key') || key.contains('token') || key.contains('url') || key.contains('config') || key.contains('c2'))) {
            send({type: 'pref', key: key, value: value});
        }
        return this.putString(key, value);
    };
} catch(e) {}

// ===== AES encryption (C2 config decryption) =====
try {
    var Cipher = Java.use('javax.crypto.Cipher');
    Cipher.doFinal.overload('[B').implementation = function(input) {
        var mode = this.getOpmode ? this.getOpmode() : -1;
        var result = this.doFinal(input);
        // Only log for decrypt mode (mode=2) and small inputs
        if (mode == 2 && input.length < 500) {
            var inputStr = '';
            try { inputStr = Java.use('java.lang.String').$new(input).toString(); } catch(e) {}
            var resultStr = '';
            try { resultStr = Java.use('java.lang.String').$new(result).toString(); } catch(e) {}
            if (resultStr.length > 10 && resultStr.indexOf('|') >= 0) {
                send({type: 'aes_decrypt', input_preview: inputStr.substring(0, 50), result_preview: resultStr.substring(0, 200)});
            }
        }
        return result;
    };
} catch(e) {}

// ===== ContentResolver queries (contact/SMS theft) =====
try {
    var ContentResolver = Java.use('android.content.ContentResolver');
    ContentResolver.query.implementation = function(uri, projection, selection, selectionArgs, sortOrder) {
        var uriStr = uri.toString();
        if (uriStr.contains('sms') || uriStr.contains('contacts') || uriStr.contains('call_log') || uriStr.contains('calllog')) {
            send({type: 'content_query', uri: uriStr});
        }
        return this.query(uri, projection, selection, selectionArgs, sortOrder);
    };
} catch(e) {}

send({type: 'hooks_installed'});
});
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
            print(f'[{tp}] {json.dumps({k:v for k,v in payload.items() if k != "type"}, ensure_ascii=False)}')
    elif message['type'] == 'error':
        print(f'[ERROR] {message.get("description", "")}')

script.on('message', on_message)
script.load()

# Monitor for 60 seconds
print('[*] Monitoring for 60 seconds...')
time.sleep(60)

# Print summary
print(f'\n[*] Total events: {len(events)}')
type_counts = {}
for e in events:
    t = e.get('type', 'unknown')
    type_counts[t] = type_counts.get(t, 0) + 1
for t, c in sorted(type_counts.items()):
    print(f'  {t}: {c}')

# Save all events to file
with open('/home/ninini/Agents/APK-Research/dumped_dex/187689_runtime_events.json', 'w') as f:
    json.dump(events, f, indent=2, ensure_ascii=False, default=str)

session.detach()
print('[*] Done')
