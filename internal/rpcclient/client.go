// Package rpcclient provides a minimal JSON-RPC client for qogecoind.
//
// Uses only stdlib (net/http + encoding/json) — no external dependency.
// This package has zero effect on any wallet functionality if unused.
package rpcclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Client is a minimal JSON-RPC 1.1 client for a qogecoind node.
type Client struct {
	url      string
	user     string
	password string
	http     *http.Client
}

// New constructs a Client. endpoint should be "host:port" (e.g. "127.0.0.1:8332").
func New(endpoint, user, password string) *Client {
	return &Client{
		url:      "http://" + endpoint + "/",
		user:     user,
		password: password,
		http: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// rpcRequest is the JSON body sent to the node.
type rpcRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      int    `json:"id"`
	Method  string `json:"method"`
	Params  []any  `json:"params"`
}

// rpcResponse is the envelope returned by the node.
type rpcResponse struct {
	ID     int             `json:"id"`
	Result json.RawMessage `json:"result"`
	Error  *rpcError       `json:"error"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *rpcError) Error() string {
	return fmt.Sprintf("rpc error %d: %s", e.Code, e.Message)
}

// call executes one JSON-RPC method and decodes the result into out.
func (c *Client) call(ctx context.Context, method string, params []any, out any) error {
	body, err := json.Marshal(rpcRequest{
		JSONRPC: "1.1",
		ID:      1,
		Method:  method,
		Params:  params,
	})
	if err != nil {
		return fmt.Errorf("rpcclient: marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("rpcclient: new request: %w", err)
	}
	req.SetBasicAuth(c.user, c.password)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("rpcclient: %s: %w", method, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("rpcclient: %s: authentication failed (wrong user/password?)", method)
	}

	var rr rpcResponse
	if err := json.NewDecoder(resp.Body).Decode(&rr); err != nil {
		return fmt.Errorf("rpcclient: %s: decode response: %w", method, err)
	}
	if rr.Error != nil {
		return rr.Error
	}
	if out != nil {
		if err := json.Unmarshal(rr.Result, out); err != nil {
			return fmt.Errorf("rpcclient: %s: decode result: %w", method, err)
		}
	}
	return nil
}

// ── scantxoutset ─────────────────────────────────────────────────────────────

// ScanUnspent is one entry from scantxoutset's "unspents" array.
type ScanUnspent struct {
	Txid        string  `json:"txid"`
	Vout        uint32  `json:"vout"`
	ScriptPubKey string `json:"scriptPubKey"` // hex-encoded
	Desc        string  `json:"desc"`
	Amount      float64 `json:"amount"` // QOGE (not satoshis)
	Height      int64   `json:"height"`
}

// ScanResult is the full response from scantxoutset action="start".
type ScanResult struct {
	Success     bool          `json:"success"`
	Txouts      int64         `json:"txouts"`
	Height      int64         `json:"height"`
	BestBlock   string        `json:"bestblock"`
	Unspents    []ScanUnspent `json:"unspents"`
	TotalAmount float64       `json:"total_amount"` // QOGE
}

// ScanTxOutSet calls scantxoutset with action "start" and the given descriptors.
// descriptors should be in the form []string{"addr(bq1z...)", "addr(bq1z...)"}.
// Returns the raw result — callers use AggregateBalances to map back to addresses.
func (c *Client) ScanTxOutSet(ctx context.Context, descriptors []string) (ScanResult, error) {
	// params: ["start", ["addr(bq1z...)", ...]]
	scanObjs := make([]any, len(descriptors))
	for i, d := range descriptors {
		scanObjs[i] = d
	}

	var result ScanResult
	if err := c.call(ctx, "scantxoutset", []any{"start", scanObjs}, &result); err != nil {
		return ScanResult{}, err
	}
	return result, nil
}

// Ping calls getblockcount — a lightweight liveness check.
// Returns nil if the node responds, an error otherwise.
func (c *Client) Ping(ctx context.Context) error {
	var count int64
	return c.call(ctx, "getblockcount", nil, &count)
}

// ── testmempoolaccept ─────────────────────────────────────────────────────────

// MempoolAcceptResult is one entry from testmempoolaccept's response array.
type MempoolAcceptResult struct {
	Txid         string  `json:"txid"`
	Allowed      bool    `json:"allowed"`
	VSize        int64   `json:"vsize"`
	RejectReason string  `json:"reject-reason"`
	Fees         struct {
		Base float64 `json:"base"`
	} `json:"fees"`
}

// TestMempoolAccept calls testmempoolaccept with a single raw transaction hex.
// Returns the result, or an error if the RPC call itself failed (network / auth).
// A transaction-level rejection is not an error: check result.Allowed and
// result.RejectReason in the caller.
func (c *Client) TestMempoolAccept(ctx context.Context, rawHex string) (MempoolAcceptResult, error) {
	var results []MempoolAcceptResult
	if err := c.call(ctx, "testmempoolaccept", []any{[]string{rawHex}}, &results); err != nil {
		return MempoolAcceptResult{}, err
	}
	if len(results) == 0 {
		return MempoolAcceptResult{}, fmt.Errorf("rpcclient: testmempoolaccept: empty response")
	}
	return results[0], nil
}
