#!/usr/bin/env python3
"""
Récepteur de démonstration pour les Webhooks HITL signés de mod_aim.
Vérifie l'en-tête cryptographique `X-AIM-Signature-256` (HMAC-SHA256) avant de traiter le résultat.

Usage :
  python3 examples/webhook_receiver_verify.py
"""
import hashlib
import hmac
import json
from http.server import BaseHTTPRequestHandler, HTTPServer

WEBHOOK_SECRET = "whsec_demo_secret_2026"
PORT = 9090


def verify_signature(secret: str, raw_body: bytes, signature_header: str) -> bool:
    expected = "sha256=" + hmac.new(
        secret.encode("utf-8"), raw_body, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature_header or "")


class AimWebhookHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        raw_body = self.rfile.read(length)
        sig_header = self.headers.get("X-AIM-Signature-256", "")
        ticket_id = self.headers.get("X-AIM-Ticket-ID", "")

        print("\n" + "=" * 70)
        print(f"[Webhook reçu] Ticket ID : {ticket_id}")
        print(f"[Signature]    Header    : {sig_header}")

        if not verify_signature(WEBHOOK_SECRET, raw_body, sig_header):
            print("[ERREUR] Signature HMAC-SHA256 invalide ! Requête rejetée.")
            self.send_response(401)
            self.end_headers()
            self.wfile.write(b'{"error":"invalid_signature"}')
            return

        print("[SUCCÈS] Signature HMAC-SHA256 authentifiée !")
        payload = json.loads(raw_body.decode("utf-8"))
        print(json.dumps(payload, indent=2, ensure_ascii=False))

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status":"received"}')


if __name__ == "__main__":
    print(f"Écoute des Webhooks HITL mod_aim sur http://127.0.0.1:{PORT}/webhook ...")
    server = HTTPServer(("127.0.0.1", PORT), AimWebhookHandler)
    server.serve_forever()
