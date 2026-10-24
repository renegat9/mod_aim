#!/usr/bin/env bash
# ==============================================================================
# Scénario de démonstration complet pour mod_aim (MCP JSON-RPC 2.0, REST & HITL)
# Prérequis : Lancer `cargo run --release` ou `./aim-daemon` dans un autre terminal
# ==============================================================================
set -euo pipefail

BASE_URL="${AIM_URL:-http://127.0.0.1:8080}"

echo "=================================================================="
echo "1. Initialisation de la session MCP (initialize)"
echo "=================================================================="
curl -sS -X POST "$BASE_URL/mcp" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": "init-1",
    "method": "initialize",
    "params": {}
  }' | python3 -m json.tool

echo ""
echo "=================================================================="
echo "2. Découverte dynamique des outils actifs (tools/list)"
echo "=================================================================="
curl -sS -X POST "$BASE_URL/mcp" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": "list-1",
    "method": "tools/list"
  }' | python3 -m json.tool

echo ""
echo "=================================================================="
echo "3. Appel d'un outil déclaratif SQL pur (search_invoices)"
echo "=================================================================="
curl -sS -X POST "$BASE_URL/mcp" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": "sql-1",
    "method": "tools/call",
    "params": {
      "name": "search_invoices",
      "arguments": {
        "client_id": 1,
        "status": "unpaid"
      }
    }
  }' | python3 -m json.tool

echo ""
echo "=================================================================="
echo "4. Appel d'un outil analytique Rhai (customer_billing_summary)"
echo "=================================================================="
curl -sS -X POST "$BASE_URL/api/v1/customer_billing_summary" \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": 1
  }' | python3 -m json.tool

echo ""
echo "=================================================================="
echo "5. Appel d'un module WebAssembly isolé (compound_interest_wasm)"
echo "   1000.00$ (100000 cents) à 5.00% (500 bps) sur 10 périodes"
echo "=================================================================="
curl -sS -X POST "$BASE_URL/api/v1/compound_interest_wasm" \
  -H "Content-Type: application/json" \
  -d '{
    "principal_cents": 100000,
    "rate_bps": 500,
    "periods": 10
  }' | python3 -m json.tool

echo ""
echo "=================================================================="
echo "6. Démonstration du protocole d'Auto-Guérison (AIM_CONTRACT_VIOLATION)"
echo "   Envoi volontaire d'un motif trop court (< 10 caractères)"
echo "=================================================================="
curl -sS -X POST "$BASE_URL/mcp" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": "err-1",
    "method": "tools/call",
    "params": {
      "name": "apply_credit_note",
      "arguments": {
        "invoice_id": 1042,
        "credit_amount": 50.0,
        "reason": "Court"
      }
    }
  }' | python3 -m json.tool

echo ""
echo "=================================================================="
echo "7. Déclenchement d'une demande de validation humaine (HITL)"
echo "   Avec _wait_sec=1 pour récupérer immédiatement le ticket_id"
echo "=================================================================="
curl -sS -X POST "$BASE_URL/mcp" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": "hitl-1",
    "method": "tools/call",
    "params": {
      "name": "apply_credit_note",
      "arguments": {
        "invoice_id": 1042,
        "credit_amount": 150.0,
        "reason": "Geste commercial suite au retard de livraison confirmé.",
        "_wait_sec": 1,
        "_callback": {
          "url": "http://127.0.0.1:9090/webhook",
          "secret": "whsec_demo_secret_2026",
          "context_id": "conv_demo_42"
        }
      }
    }
  }' | python3 -m json.tool

echo ""
echo "-> Ouvrez maintenant http://127.0.0.1:8080/_admin pour approuver ou modifier ce ticket !"
