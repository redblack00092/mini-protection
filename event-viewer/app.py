import collections
import json
import os
import threading

from confluent_kafka import Consumer, KafkaError
from flask import Flask, jsonify, render_template_string

app = Flask(__name__)

BROKERS = os.getenv("KAFKA_BROKERS", "kafka:9092")
TOPIC = os.getenv("KAFKA_TOPIC", "mini-protection-events")
MAX_EVENTS = 200

events: collections.deque = collections.deque(maxlen=MAX_EVENTS)


def consume_loop():
    c = Consumer({
        "bootstrap.servers": BROKERS,
        "group.id": "event-viewer",
        "auto.offset.reset": "earliest",
        "enable.auto.commit": True,
    })
    c.subscribe([TOPIC])
    while True:
        msg = c.poll(1.0)
        if msg is None:
            continue
        if msg.error():
            if msg.error().code() != KafkaError._PARTITION_EOF:
                print(f"Kafka error: {msg.error()}")
            continue
        try:
            events.appendleft(json.loads(msg.value().decode("utf-8")))
        except Exception as e:
            print(f"parse error: {e}")


threading.Thread(target=consume_loop, daemon=True).start()

HTML = """<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>mini-protection events</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Segoe UI', sans-serif; background: #0f1117; color: #e2e8f0; }
    header { padding: 20px 32px; border-bottom: 1px solid #2d3748; display: flex; align-items: center; gap: 12px; }
    header h1 { font-size: 18px; font-weight: 600; }
    #status { font-size: 12px; color: #68d391; margin-left: auto; }
    #count  { font-size: 12px; color: #90cdf4; }
    .wrap { padding: 24px 32px; }
    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    th { text-align: left; padding: 10px 12px; background: #1a202c; color: #90cdf4;
         font-weight: 500; border-bottom: 1px solid #2d3748; position: sticky; top: 0; }
    td { padding: 10px 12px; border-bottom: 1px solid #1a202c; vertical-align: top; }
    tr:hover td { background: #1a202c; }
    .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; }
    .Block     { background: #c53030; color: #fff; }
    .Challenge { background: #b7791f; color: #fff; }
    .Captcha   { background: #6b46c1; color: #fff; }
    .reason { color: #a0aec0; font-size: 12px; }
    .conf   { color: #68d391; }
    #empty  { text-align: center; padding: 60px; color: #4a5568; }
  </style>
</head>
<body>
  <header>
    <h1>mini-protection / events</h1>
    <span id="count"></span>
    <span id="status">● live</span>
  </header>
  <div class="wrap">
    <table>
      <thead>
        <tr>
          <th>Time</th>
          <th>IP</th>
          <th>Action</th>
          <th>URI</th>
          <th>Reason</th>
          <th>Conf</th>
        </tr>
      </thead>
      <tbody id="tbody"></tbody>
    </table>
    <div id="empty" style="display:none">이벤트 없음 — 탐지가 발생하면 여기에 표시됩니다.</div>
  </div>
  <script>
    function ts(unix) {
      return new Date(unix * 1000).toLocaleTimeString('ko-KR', {hour12: false});
    }
    function row(e) {
      return `<tr>
        <td>${ts(e.timestamp)}</td>
        <td>${e.src_ip}</td>
        <td><span class="badge ${e.action}">${e.action}</span></td>
        <td>${e.uri}</td>
        <td class="reason">${e.reason}</td>
        <td class="conf">${(e.confidence * 100).toFixed(0)}%</td>
      </tr>`;
    }
    async function refresh() {
      try {
        const res = await fetch('/api/events');
        const data = await res.json();
        const tbody = document.getElementById('tbody');
        const empty = document.getElementById('empty');
        if (data.length === 0) {
          tbody.innerHTML = '';
          empty.style.display = 'block';
        } else {
          empty.style.display = 'none';
          tbody.innerHTML = data.map(row).join('');
        }
        document.getElementById('count').textContent = `${data.length} events`;
        document.getElementById('status').style.color = '#68d391';
      } catch {
        document.getElementById('status').style.color = '#fc8181';
      }
    }
    refresh();
    setInterval(refresh, 2000);
  </script>
</body>
</html>"""


@app.get("/")
def index():
    return render_template_string(HTML)


@app.get("/api/events")
def api_events():
    return jsonify(list(events))


@app.get("/health")
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8081)
