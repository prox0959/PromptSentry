"""
PromptSentry - High-Performance AI Gateway Reverse Proxy
Intercepts HTTP requests, evaluates user messages, and blocks malicious prompts before reaching the LLM.
Author: Çınar (prox0959)
"""

import json
import time
import urllib.request
import urllib.error
from http.server import HTTPServer, BaseHTTPRequestHandler
from .analyzer import PromptAnalyzer

class GatewayHandler(BaseHTTPRequestHandler):
    analyzer = PromptAnalyzer(block_threshold=45, alert_threshold=25)
    upstream_url = "http://127.0.0.1:11434/api/generate" # Default local Ollama or mock
    forward_upstream = False

    def log_message(self, format, *args):
        # Clean custom logger
        pass

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length)

        start_time = time.time()
        try:
            body = json.loads(post_data.decode('utf-8'))
        except Exception:
            self.send_response(400)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"error": "Invalid JSON body"}).encode())
            return

        # Extract prompt or messages
        prompt_text = ""
        if "prompt" in body:
            prompt_text = body["prompt"]
        elif "messages" in body and isinstance(body["messages"], list):
            # OpenAI format: [{'role': 'user', 'content': '...'}]
            user_msgs = [m.get("content", "") for m in body["messages"] if m.get("role") == "user"]
            prompt_text = " \n ".join(user_msgs)

        # Analyze prompt
        result = self.analyzer.analyze(prompt_text)
        latency_ms = round((time.time() - start_time) * 1000, 2)

        status_colors = {
            "BLOCK": "\033[91m[BLOCKED]\033[0m",
            "ALERT": "\033[93m[ALERT]  \033[0m",
            "ALLOW": "\033[92m[ALLOWED]\033[0m"
        }
        print(f"{status_colors.get(result['verdict'])} Score: {result['threat_score']:<3} | Latency: {latency_ms}ms | Preview: {prompt_text[:60]!r}")

        if result["is_blocked"]:
            self.send_response(403)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            response_payload = {
                "error": "Prompt Rejected by PromptSentry Firewall",
                "verdict": result["verdict"],
                "threat_score": result["threat_score"],
                "violations": result["violations"],
                "latency_ms": latency_ms
            }
            self.wfile.write(json.dumps(response_payload, indent=2).encode())
            return

        # If allowed and configured to forward
        if self.forward_upstream:
            try:
                req = urllib.request.Request(
                    self.upstream_url,
                    data=post_data,
                    headers={'Content-Type': 'application/json'}
                )
                with urllib.request.urlopen(req) as resp:
                    self.send_response(resp.status)
                    for k, v in resp.headers.items():
                        self.send_header(k, v)
                    self.end_headers()
                    self.wfile.write(resp.read())
                return
            except urllib.error.URLError as e:
                pass

        # Standalone inspection success response
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        response_payload = {
            "status": "PROMPT_ACCEPTED",
            "verdict": result["verdict"],
            "threat_score": result["threat_score"],
            "latency_ms": latency_ms,
            "message": "Prompt passed safety inspection."
        }
        self.wfile.write(json.dumps(response_payload, indent=2).encode())

def run_gateway(port: int = 8080, forward_url: str = None):
    """
    TR: PromptSentry AI Güvenlik Duvarı HTTP sunucusunu başlatır.
    Starts the high-performance local AI reverse proxy gateway.
    """
    GatewayHandler.forward_upstream = bool(forward_url)
    if forward_url:
        GatewayHandler.upstream_url = forward_url

    server = HTTPServer(('127.0.0.1', port), GatewayHandler)
    print(f"[*] PromptSentry AI Gateway running on http://127.0.0.1:{port}")
    if forward_url:
        print(f"[*] Forwarding clean traffic to LLM upstream: {forward_url}")
    else:
        print("[*] Running in Standalone Firewall & Inspection Mode (Mock LLM response)")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Stopping PromptSentry Gateway...")
        server.server_close()
