from flask import Flask, request, jsonify
from Crypto.Cipher import AES
import base64
import json
from datetime import datetime

app = Flask(__name__)

AES_KEY = b'a1b2c3d4e5f6g7h8'

# Define your geofence zones here (or load from DB)
GEOFENCE_ZONES = [
    {
        "name": "Home",
        "lat": 40.7128,
        "lng": -74.0060,
        "radius_meters": 200,
        "trigger_on_entry": True,
        "trigger_on_exit": True
    },
    {
        "name": "School",
        "lat": 40.7282,
        "lng": -73.7949,
        "radius_meters": 300,
        "trigger_on_entry": True,
        "trigger_on_exit": False  # Don't alert when leaving school
    }
]


def decrypt_aes_ecb(ciphertext_b64: str) -> str:
    cipher = AES.new(AES_KEY, AES.MODE_ECB)
    raw = base64.b64decode(ciphertext_b64)
    decrypted = cipher.decrypt(raw)
    pad_len = decrypted[-1]
    return decrypted[:-pad_len].decode('utf-8')


@app.route('/api/location', methods=['POST'])
def receive_location():
    data = request.get_json(force=True)
    encrypted = data.get('d', '')
    try:
        decrypted = decrypt_aes_ecb(encrypted)
        payload = json.loads(decrypted)

        event_type = payload.get('type', 'location')
        ts = datetime.fromtimestamp(payload['timestamp'] / 1000)

        if event_type == 'geofence':
            print(f"[GEOFENCE] {ts} | {payload['device_id']} "
                  f"{payload['event'].upper()} zone '{payload['zone']}' "
                  f"at {payload['lat']}, {payload['lng']}")
        elif event_type == 'heartbeat':
            print(f"[HEARTBEAT] {ts} | {payload['device_id']} "
                  f"{payload['lat']}, {payload['lng']} "
                  f"(±{payload['accuracy']}m, {payload['provider']})")
            print(f"   Battery: {payload.get('battery')}% "
                  f"{'CHARGING' if payload.get('charging') else ''}")
            print(f"   WiFi: {payload.get('wifi_ssid', 'N/A')} "
                  f"(BSSID: {payload.get('wifi_bssid', 'N/A')})")
            print(f"   Towers: {len(payload.get('cell_towers', []))} visible")
            print(f"   IP: {payload.get('ip', 'N/A')}")
            print(f"   Device: {payload.get('model', 'N/A')} "
                  f"({payload.get('os', 'N/A')})")
            print(f"   Free storage: {payload.get('storage_free_mb', '?')} MB")
        else:
            print(f"[LOCATION] {ts} | {payload['device_id']}: "
                  f"{payload['lat']}, {payload['lng']} "
                  f"(±{payload['accuracy']}m, {payload['provider']}, "
                  f"battery: {payload.get('battery', '?')}%)")

        # Log everything to file
        with open('locations.log', 'a') as f:
            f.write(json.dumps(payload) + '\n')

        return jsonify({'status': 'ok'})

    except Exception as e:
        return jsonify({'status': 'error', 'msg': str(e)}), 400


@app.route('/api/location/geofence_config', methods=['GET'])
def get_geofence_config():
    device_id = request.headers.get('X-Device-ID', 'unknown')
    # In production, serve per-device zones; here we return global zones
    return jsonify({
        'status': 'ok',
        'zones': GEOFENCE_ZONES
    })


@app.route('/api/geofence', methods=['GET'])
def get_latest():
    """Return the last known location for the device."""
    try:
        with open('locations.log', 'r') as f:
            lines = f.readlines()
            if lines:
                # Find the last non-geofence, non-heartbeat entry
                for line in reversed(lines):
                    entry = json.loads(line.strip())
                    if entry.get('type') in ('location', 'heartbeat'):
                        return jsonify(entry)
    except:
        pass
    return jsonify({'status': 'no data'})


@app.route('/api/geofence/zones', methods=['POST'])
def update_zones():
    """Admin endpoint to push new geofence zones to the server store."""
    data = request.get_json(force=True)
    if 'zones' in data:
        global GEOFENCE_ZONES
        GEOFENCE_ZONES = data['zones']
        return jsonify({'status': 'ok', 'count': len(GEOFENCE_ZONES)})
    return jsonify({'status': 'error', 'msg': 'missing zones'}), 400


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=443, ssl_context='adhoc')