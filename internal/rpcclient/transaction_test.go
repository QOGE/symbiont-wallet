package rpcclient

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGetConnectionCount(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req rpcRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
			return
		}
		user, password, ok := r.BasicAuth()
		if !ok || user != "user" || password != "password" {
			t.Errorf("request did not use existing RPC credentials")
		}
		if req.Method != "getconnectioncount" || len(req.Params) != 0 {
			t.Errorf("request = %q %v, want getconnectioncount with no params", req.Method, req.Params)
		}
		if err := json.NewEncoder(w).Encode(map[string]any{"result": 8, "error": nil, "id": 1}); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()

	client := New(strings.TrimPrefix(server.URL, "http://"), "user", "password")
	count, err := client.GetConnectionCount(context.Background())
	if err != nil || count != 8 {
		t.Fatalf("GetConnectionCount = (%d, %v), want (8, nil)", count, err)
	}
}

func TestGetConnectionCountRPCError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewEncoder(w).Encode(map[string]any{
			"result": nil, "error": map[string]any{"code": -32603, "message": "node unavailable"}, "id": 1,
		}); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	client := New(strings.TrimPrefix(server.URL, "http://"), "", "")
	if _, err := client.GetConnectionCount(context.Background()); err == nil {
		t.Fatal("RPC failure was silently treated as a peer count")
	}
}

func TestGetBlockCount(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req rpcRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
			return
		}
		user, password, ok := r.BasicAuth()
		if !ok || user != "user" || password != "password" {
			t.Error("request did not use existing RPC credentials")
		}
		if req.Method != "getblockcount" || len(req.Params) != 0 {
			t.Errorf("request = %q %v, want getblockcount with no params", req.Method, req.Params)
		}
		if err := json.NewEncoder(w).Encode(map[string]any{"result": 2459520, "error": nil, "id": 1}); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()

	client := New(strings.TrimPrefix(server.URL, "http://"), "user", "password")
	height, err := client.GetBlockCount(context.Background())
	if err != nil || height != 2459520 {
		t.Fatalf("GetBlockCount = (%d, %v), want (2459520, nil)", height, err)
	}
}

func TestGetBlockCountRPCError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewEncoder(w).Encode(map[string]any{
			"result": nil, "error": map[string]any{"code": -32603, "message": "node unavailable"}, "id": 1,
		}); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	client := New(strings.TrimPrefix(server.URL, "http://"), "", "")
	if _, err := client.GetBlockCount(context.Background()); err == nil {
		t.Fatal("RPC failure was silently treated as block height zero")
	}
}

func TestSendRawTransaction(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req rpcRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatal(err)
		}
		if req.Method != "sendrawtransaction" {
			t.Fatalf("method = %q, want sendrawtransaction", req.Method)
		}
		if len(req.Params) != 1 || req.Params[0] != "deadbeef" {
			t.Fatalf("params = %v, want [deadbeef]", req.Params)
		}
		json.NewEncoder(w).Encode(map[string]any{"result": "abc123", "error": nil, "id": 1})
	}))
	defer server.Close()

	client := New(strings.TrimPrefix(server.URL, "http://"), "", "")
	txid, err := client.SendRawTransaction(context.Background(), "deadbeef")
	if err != nil {
		t.Fatal(err)
	}
	if txid != "abc123" {
		t.Fatalf("txid = %q, want abc123", txid)
	}
}

func TestTransactionConfirmations(t *testing.T) {
	for _, tc := range []struct {
		name      string
		result    any
		rpcError  any
		wantConfs int
		wantFound bool
		wantErr   error
	}{
		{name: "unconfirmed", result: map[string]any{"txid": "abc", "confirmations": 0}, wantFound: true},
		{name: "confirmed", result: map[string]any{"txid": "abc", "confirmations": 1}, wantConfs: 1, wantFound: true},
		{name: "not found", rpcError: map[string]any{"code": -5, "message": "No such mempool or blockchain transaction"}},
		{name: "txindex required", rpcError: map[string]any{"code": -5, "message": "No such mempool transaction. Use -txindex or provide a block hash"}, wantErr: ErrTxIndexRequired},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var req rpcRequest
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
					t.Fatal(err)
				}
				if req.Method != "getrawtransaction" {
					t.Fatalf("method = %q, want getrawtransaction", req.Method)
				}
				json.NewEncoder(w).Encode(map[string]any{"result": tc.result, "error": tc.rpcError, "id": 1})
			}))
			defer server.Close()
			client := New(strings.TrimPrefix(server.URL, "http://"), "", "")
			confs, found, err := client.TransactionConfirmations(context.Background(), "abc")
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("error = %v, want %v", err, tc.wantErr)
			}
			if confs != tc.wantConfs || found != tc.wantFound {
				t.Fatalf("got (%d, %v), want (%d, %v)", confs, found, tc.wantConfs, tc.wantFound)
			}
		})
	}
}
