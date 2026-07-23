import frida, time

device = frida.get_usb_device()
pid = 4891
session = device.attach(pid)

script_code = """
console.log('Java available:', typeof Java !== 'undefined');
console.log('Process id:', Process.id);

// Try Java.perform
if (typeof Java !== 'undefined') {
    Java.perform(function() {
        console.log('Inside Java.perform');
        // Try to use a basic Java class
        var String = Java.use('java.lang.String');
        console.log('String class loaded');
    });
} else {
    console.log('Java is not defined - trying to load it');
    // Frida 17+ might need explicit loading
    try {
        var Java = require('frida-java-bridge');
        console.log('Loaded via require');
    } catch(e) {
        console.log('require failed:', e.toString());
    }
}
"""

script = session.create_script(script_code)
def on_msg(msg, data):
    if msg['type'] == 'send':
        print(msg['payload'])
    elif msg['type'] == 'error':
        print('ERROR:', msg.get('description', ''))
    elif msg['type'] == 'log':
        print('LOG:', msg.get('payload', ''))
    else:
        print(msg)

script.on('message', on_msg)
script.load()
time.sleep(3)
session.detach()
