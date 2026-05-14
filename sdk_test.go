package vsdk

import (
	"context"
	"net/http"
	"testing"
)

func TestCanonicalHashDeterministic(t *testing.T) {
	a := map[string]any{"b": 2, "a": 1}
	b := map[string]any{"a": 1, "b": 2}
	ha, err := CanonicalHashBytes(a)
	if err != nil {
		t.Fatal(err)
	}
	hb, err := CanonicalHashBytes(b)
	if err != nil {
		t.Fatal(err)
	}
	if ha != hb {
		t.Fatalf("hash mismatch: %s != %s", ha, hb)
	}
}

func TestWalletSignAndVerify(t *testing.T) {
	w, err := GenerateWallet("test")
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte(`{"hello":"world"}`)
	sig, err := w.SignCanonical(msg)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := VerifyCanonical(w.PublicKey, msg, sig)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatalf("signature failed verification")
	}
}

func TestClientSubmitUsesTransport(t *testing.T) {
	mt := NewMockTransport()
	mt.SetHandler(http.MethodPost, "/v1/operations", func(ctx context.Context, method, path string, in any) (any, *http.Response, error) {
		return OperationResponse{Accepted: true, RecordID: "r1", CanonicalHash: "abc"}, &http.Response{StatusCode: 200, Status: "200 OK"}, nil
	})

	client, err := NewWithTransport(Config{BaseURL: "http://localhost:8080"}, mt)
	if err != nil {
		t.Fatal(err)
	}
	w, err := GenerateWallet("test")
	if err != nil {
		t.Fatal(err)
	}
	if err := client.BindWallet(w); err != nil {
		t.Fatal(err)
	}

	resp, err := client.Create(context.Background(), CreateParams{SpaceID: "space-1", TypeID: VectorFree})
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil || !resp.Accepted || resp.RecordID != "r1" {
		t.Fatalf("unexpected response: %#v", resp)
	}
}

func TestValidationRejectsMissingFields(t *testing.T) {
	if err := validateRecordParams(RecordParams{}); err == nil {
		t.Fatal("expected validation error")
	}
	if err := validateQueryParams(QueryParams{}); err == nil {
		t.Fatal("expected validation error")
	}
}
