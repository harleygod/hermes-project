"""Burp MCP SSE client — call BurpSuite tools from Python.

Usage:
    from burp_mcp_call import BurpMCP
    burp = BurpMCP()
    
    # Send an HTTP request
    resp = burp.call("send_http1_request", {
        "content": "GET / HTTP/1.1\\r\\nHost: example.com\\r\\n\\r\\n",
        "targetHostname": "example.com",
        "targetPort": 443,
        "usesHttps": True
    })
    
    # Get proxy history
    history = burp.call("get_proxy_http_history", {"count": 10, "offset": 0})
    
    # Generate collaborator payload
    payload = burp.call("generate_collaborator_payload", {})
    
    # Search proxy history
    results = burp.call("get_proxy_http_history_regex", {
        "count": 20, "offset": 0, "regex": "login|admin|api"
    })
"""
import subprocess
import json
import time
import re
import queue
import threading
import requests

class BurpMCP:
    """SSE-based MCP client for BurpSuite."""
    
    def __init__(self, base_url="http://127.0.0.1:9876", timeout=15):
        self.base_url = base_url
        self.timeout = timeout
        self.session_id = None
        self._sse_proc = None
        self._events = queue.Queue()
        self._call_id = 0
    
    def connect(self):
        """Start SSE connection and get session ID."""
        self._sse_proc = subprocess.Popen(
            ["curl", "-s", "-N", "--connect-timeout", "5", 
             "--max-time", str(self.timeout), self.base_url + "/"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
        )
        
        # Read initial endpoint event
        for _ in range(20):
            line = self._sse_proc.stdout.readline()
            if not line:
                break
            m = re.search(r'sessionId=([a-f0-9-]+)', line)
            if m:
                self.session_id = m.group(1)
                break
        
        if not self.session_id:
            raise RuntimeError("Failed to get Burp MCP session ID")
        
        # Start background reader
        self._reader = threading.Thread(target=self._read_sse, daemon=True)
        self._reader.start()
        time.sleep(0.3)
        return self.session_id
    
    def _read_sse(self):
        """Background SSE reader."""
        try:
            for line in self._sse_proc.stdout:
                self._events.put(line.strip())
        except:
            pass
    
    def call(self, method, params=None):
        """Call a Burp MCP tool and return the result."""
        if not self.session_id:
            self.connect()
        
        self._call_id += 1
        call_id = self._call_id
        
        # Send JSON-RPC via POST
        resp = requests.post(
            f"{self.base_url}/?sessionId={self.session_id}",
            json={"jsonrpc": "2.0", "id": call_id, "method": f"tools/call", 
                  "params": {"name": method, "arguments": params or {}}},
            timeout=10
        )
        
        if resp.status_code != 202:
            raise RuntimeError(f"POST rejected: {resp.status_code} {resp.text}")
        
        # Wait for SSE response
        time.sleep(1)
        lines = []
        deadline = time.time() + 5
        while time.time() < deadline:
            try:
                lines.append(self._events.get(timeout=0.5))
                # Check if we have the response
                for line in lines:
                    if line.startswith("data:"):
                        data = line[5:].strip()
                        try:
                            parsed = json.loads(data)
                            if parsed.get("id") == call_id:
                                if "result" in parsed:
                                    return parsed["result"]
                                elif "error" in parsed:
                                    raise RuntimeError(f"MCP error: {parsed['error']}")
                        except json.JSONDecodeError:
                            continue
            except queue.Empty:
                break
        
        raise TimeoutError(f"No response for call {call_id}")
    
    def close(self):
        """Clean up."""
        if self._sse_proc:
            self._sse_proc.kill()
            self._sse_proc = None
            self.session_id = None


# Simple standalone call interface
def burp_call(method, params=None):
    """One-shot Burp MCP call with auto-connect/cleanup."""
    burp = BurpMCP()
    try:
        burp.connect()
        return burp.call(method, params)
    finally:
        burp.close()


if __name__ == "__main__":
    # Test: list all tools
    import sys
    
    # Raw JSON-RPC tools/list (not tools/call)
    import re, queue, threading, time
    
    sse_proc = subprocess.Popen(
        ["curl", "-s", "-N", "--connect-timeout", "5", "--max-time", "15",
         "http://127.0.0.1:9876/"],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
    )
    
    sid = None
    for _ in range(20):
        line = sse_proc.stdout.readline()
        if not line: break
        m = re.search(r'sessionId=([a-f0-9-]+)', line)
        if m: sid = m.group(1); break
    
    if not sid:
        print("FAIL: no session")
        sys.exit(1)
    
    events = queue.Queue()
    def read_sse():
        try:
            for line in sse_proc.stdout:
                events.put(line.strip())
        except: pass
    threading.Thread(target=read_sse, daemon=True).start()
    time.sleep(0.3)
    
    requests.post(f"http://127.0.0.1:9876/?sessionId={sid}",
                  json={"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}},
                  timeout=10)
    
    time.sleep(2)
    while not events.empty():
        line = events.get_nowait()
        if line.startswith("data:"):
            try:
                data = json.loads(line[5:].strip())
                if "result" in data:
                    tools = data["result"].get("tools", [])
                    print(f"Connected: {len(tools)} tools available")
                    for t in tools:
                        print(f"  - {t['name']}: {t['description'][:80]}")
            except: pass
    
    sse_proc.kill()
