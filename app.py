from flask import Flask, jsonify, render_template
from scanner import scan_network, get_logs

app = Flask(__name__)

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/scan")
def scan():
    devices = scan_network("192.168.1.0/24")
    return jsonify(devices)

@app.route("/logs")
def logs():
    return jsonify(get_logs())

if __name__ == "__main__":
    app.run(debug=True)
