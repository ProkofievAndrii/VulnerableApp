import frida
import sys
import threading

target_app = sys.argv[1]

js_code = """
const searchTerms = {
    "AIzaSyB-83492_asD9238492n3asD_231908": "[M1] Hardcoded API Key found in memory",
    "1:923481029:ios:9a2c3d4e5f6g7h8i": "[M1] Hardcoded Token found in memory",
    "secret": "[M9] Plaintext password found in memory"
};

function toHex8(str) {
    return str.split('').map(c => c.charCodeAt(0).toString(16).padStart(2, '0')).join(' ');
}
function toHex16(str) {
    return str.split('').map(c => c.charCodeAt(0).toString(16).padStart(2, '0') + ' 00').join(' ');
}

let foundVulnerabilities = new Set();

send({ "vuln": "[M8] No Anti-Debugging / Anti-Reversing protection detected" });

let protections = ['r--', 'rw-'];

protections.forEach(function(prot) {
    Process.enumerateRanges({protection: prot, coalesce: true}).forEach(function(range) {
        if (range.size > 1024 * 1024 * 50) return;

        Object.keys(searchTerms).forEach(function(term) {
            if (foundVulnerabilities.has(searchTerms[term])) return;
            try {
                if (Memory.scanSync(range.base, range.size, toHex8(term)).length > 0 || 
                    Memory.scanSync(range.base, range.size, toHex16(term)).length > 0) {
                    foundVulnerabilities.add(searchTerms[term]);
                    send({ "vuln": searchTerms[term] });
                }
            } catch(e) {}
        });
    });
});

send({ "status": "done" });
"""

done_event = threading.Event()


def on_message(message, data):
    if message['type'] == 'send':
        payload = message['payload']
        if 'vuln' in payload:
            print(f"VULN_FOUND:{payload['vuln']}")
        elif 'status' in payload and payload['status'] == 'done':
            done_event.set()
    elif message['type'] == 'error':
        print(f"ERROR:{message['description']}")
        done_event.set()


try:
    device = frida.get_local_device()
    session = device.attach(target_app)
    script = session.create_script(js_code)
    script.on('message', on_message)
    script.load()

    if not done_event.wait(60):
        print("ERROR:Scanner timed out")
    sys.exit(0)
except Exception as e:
    print(f"ERROR:{e}")
    sys.exit(1)