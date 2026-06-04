import http.server
import socketserver
import json
import sys

# Force UTF-8 encoding for stdout
sys.stdout.reconfigure(encoding='utf-8')

PORT = 8080

class SlackWebhookHandler(http.server.SimpleHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        payload = json.loads(post_data.decode('utf-8'))
        
        print("\n\n" + "="*80)
        print("NEW SLACK WEBHOOK RECEIVED!")
        print("="*80)
        
        blocks = payload.get("blocks", [])
        for block in blocks:
            if block["type"] == "header":
                print(f"\n{block['text']['text']}")
            elif block["type"] == "section":
                if "fields" in block:
                    for field in block["fields"]:
                        text = field["text"].replace("*", "").replace("\n", " ")
                        print(f"  {text}")
                elif "text" in block:
                    text = block["text"]["text"].replace("*", "").replace("\n", " ")
                    print(f"  {text}")
            elif block["type"] == "divider":
                print("-" * 40)
                
        print("="*80 + "\n\n")
        
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        self.wfile.write(b"ok")

with socketserver.TCPServer(("", PORT), SlackWebhookHandler) as httpd:
    print(f"Starting mock Slack Webhook server on port {PORT}")
    httpd.serve_forever()
