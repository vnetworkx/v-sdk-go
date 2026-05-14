package vsdk

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	ProtocolName         = "vector-network"
	ProtocolVersion      = "1.1"
	SchemaVersion        = "1.1"
	RuleVersion          = "1.1"
	SpaceVersion         = "1.1"
	DefaultClientVersion = "0.1.0"
)

type ErrorCode string

const (
	ErrorInvalidArgument            ErrorCode = "INVALID_ARGUMENT"
	ErrorMissingProof               ErrorCode = "MISSING_PROOF"
	ErrorCertificationFailed        ErrorCode = "CERTIFICATION_FAILED"
	ErrorAuthorizationFailed        ErrorCode = "AUTHORIZATION_FAILED"
	ErrorTypeMismatch               ErrorCode = "TYPE_MISMATCH"
	ErrorZeroVectorInvalid          ErrorCode = "ZERO_VECTOR_INVALID"
	ErrorUnknownPolicy              ErrorCode = "UNKNOWN_POLICY"
	ErrorDrainRuleUndefined         ErrorCode = "DRAIN_RULE_UNDEFINED"
	ErrorProjectionAlreadySettled   ErrorCode = "PROJECTION_ALREADY_SETTLED"
	ErrorRecordConflict             ErrorCode = "RECORD_CONFLICT"
	ErrorProtocolVersionUnsupported ErrorCode = "PROTOCOL_VERSION_UNSUPPORTED"
	ErrorTransport                  ErrorCode = "TRANSPORT_ERROR"
	ErrorSerialization              ErrorCode = "SERIALIZATION_ERROR"
	ErrorNotBound                   ErrorCode = "WALLET_NOT_BOUND"
	ErrorInvalidSignature           ErrorCode = "INVALID_SIGNATURE"
)

type SDKError struct {
	Code        ErrorCode      `json:"error_code"`
	Message     string         `json:"message"`
	Recoverable bool           `json:"recoverable"`
	Operation   Operation      `json:"operation,omitempty"`
	Context     map[string]any `json:"context,omitempty"`
	Cause       error          `json:"-"`
}

func (e *SDKError) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.Operation == "" {
		return fmt.Sprintf("%s: %s", e.Code, e.Message)
	}
	return fmt.Sprintf("%s (%s): %s", e.Code, e.Operation, e.Message)
}

func (e *SDKError) Unwrap() error { return e.Cause }

func NewError(code ErrorCode, message string, recoverable bool) *SDKError {
	return &SDKError{Code: code, Message: message, Recoverable: recoverable}
}

func (e *SDKError) WithOperation(op Operation) *SDKError {
	if e != nil {
		e.Operation = op
	}
	return e
}

func (e *SDKError) WithContext(k string, v any) *SDKError {
	if e == nil {
		return nil
	}
	if e.Context == nil {
		e.Context = map[string]any{}
	}
	e.Context[k] = v
	return e
}

func WrapError(code ErrorCode, message string, recoverable bool, cause error) *SDKError {
	return &SDKError{Code: code, Message: message, Recoverable: recoverable, Cause: cause}
}

type Operation string

const (
	OpCreate      Operation = "CREATE"
	OpCertify     Operation = "CERTIFY"
	OpTransfer    Operation = "TRANSFER"
	OpDrain       Operation = "DRAIN"
	OpProject     Operation = "PROJECT"
	OpReconstruct Operation = "RECONSTRUCT"
	OpQuery       Operation = "QUERY"
	OpRecord      Operation = "RECORD"
	OpMove        Operation = "MOVE"
	OpRotate      Operation = "ROTATE"
	OpScale       Operation = "SCALE"
	OpNormalize   Operation = "NORMALIZE"
	OpConstrain   Operation = "CONSTRAIN"
)

type VectorTypeTag string

const (
	VectorPosition VectorTypeTag = "POSITION"
	VectorFree     VectorTypeTag = "FREE"
	VectorBound    VectorTypeTag = "BOUND"
	VectorUnit     VectorTypeTag = "UNIT"
	VectorZero     VectorTypeTag = "ZERO"
	VectorSpatial  VectorTypeTag = "SPATIAL"
)

type CertificationStatus string

const (
	CertCertified   CertificationStatus = "certified"
	CertUncertified CertificationStatus = "uncertified"
	CertSuspended   CertificationStatus = "suspended"
	CertRevoked     CertificationStatus = "revoked"
	CertPending     CertificationStatus = "pending"
)

type Component struct {
	TokenID string      `json:"token_id"`
	Amount  json.Number `json:"amount"`
}

type Vector struct {
	VectorID           string              `json:"vector_id,omitempty"`
	Components         []Component         `json:"components,omitempty"`
	TypeID             VectorTypeTag       `json:"type_id"`
	SpaceID            string              `json:"space_id"`
	OwnerWalletID      string              `json:"owner_wallet_id,omitempty"`
	CertificationState CertificationStatus  `json:"certification_state,omitempty"`
	CreationOrigin     string              `json:"creation_origin,omitempty"`
	Revision           uint64              `json:"revision,omitempty"`
	Status             string              `json:"status,omitempty"`
	Metadata           map[string]any      `json:"metadata,omitempty"`
}

type Wallet struct {
	WalletID     string         `json:"wallet_id"`
	PublicKey    string         `json:"public_key"`
	Metadata     map[string]any `json:"wallet_metadata,omitempty"`
	BoundVectors []string       `json:"bound_vectors,omitempty"`
	Status       string         `json:"status,omitempty"`
	PrivateKey   []byte         `json:"-"`
}

type Proof struct {
	ProofType string `json:"proof_type,omitempty"`
	Payload   string `json:"payload,omitempty"`
	Ref       string `json:"ref,omitempty"`
}

type OperationRequest struct {
	ProtocolVersion string      `json:"protocol_version"`
	SpaceID         string      `json:"space_id"`
	Operation       Operation   `json:"operation"`
	Params          any         `json:"params"`
	ActorPK         string      `json:"actor_pk"`
	Signature       string      `json:"signature"`
	Proof           *Proof      `json:"proof,omitempty"`
	ClientVersion   string      `json:"client_version"`
	IdempotencyKey  string      `json:"idempotency_key,omitempty"`
}

type OperationResponse struct {
	Accepted      bool      `json:"accepted"`
	RecordID      string    `json:"record_id,omitempty"`
	PrevHash      string    `json:"prev_hash,omitempty"`
	StateBefore   any       `json:"state_before,omitempty"`
	StateAfter    any       `json:"state_after,omitempty"`
	Certified     bool      `json:"certified,omitempty"`
	AuthRatio     float64   `json:"auth_ratio,omitempty"`
	Timestamp     time.Time `json:"timestamp,omitempty"`
	Receipt       any       `json:"receipt,omitempty"`
	CanonicalHash string    `json:"canonical_hash,omitempty"`
}

type OperationError struct {
	Accepted      bool           `json:"accepted"`
	ErrorCode     ErrorCode      `json:"error_code"`
	Message       string         `json:"message"`
	Recoverable   bool           `json:"recoverable"`
	Operation     Operation      `json:"operation,omitempty"`
	Context       map[string]any `json:"context,omitempty"`
	CanonicalHash string         `json:"canonical_hash,omitempty"`
}

func (e *OperationError) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.Operation == "" {
		return string(e.ErrorCode) + ": " + e.Message
	}
	return string(e.ErrorCode) + " (" + string(e.Operation) + "): " + e.Message
}

type Record struct {
	EID          string         `json:"eid"`
	ParentHashes []string       `json:"parent_hashes"`
	RegionID     string         `json:"region_id"`
	EntityID     string         `json:"entity_id"`
	VBefore      any            `json:"v_before"`
	VAfter       any            `json:"v_after"`
	Operation    Operation      `json:"operation"`
	Params       any            `json:"params"`
	AuthRatio    float64        `json:"auth_ratio"`
	Certified    bool           `json:"certified"`
	ActorPK      string         `json:"actor_pk"`
	Proof        *Proof         `json:"proof,omitempty"`
	LogicalClock uint64         `json:"logical_clock"`
	Timestamp    time.Time      `json:"timestamp"`
	Signature    string         `json:"signature"`
	EventHash    string         `json:"event_hash"`
}

type ProtocolMetadata struct {
	ProtocolName    string          `json:"protocol_name"`
	ProtocolVersion string          `json:"protocol_version"`
	SchemaVersion   string          `json:"schema_version"`
	RuleVersion     string          `json:"rule_version"`
	SpaceVersion    string          `json:"space_version"`
	ClientVersion   string          `json:"client_version"`
	Features        map[string]bool `json:"features,omitempty"`
	Capabilities    []string        `json:"capabilities,omitempty"`
	Extra           map[string]any  `json:"extra,omitempty"`
}

type QueryParams struct {
	Expression string         `json:"expression"`
	SpaceID    string         `json:"space_id,omitempty"`
	Variables  map[string]any `json:"variables,omitempty"`
}

type RecordParams struct {
	RecordID string `json:"record_id"`
	SpaceID  string `json:"space_id,omitempty"`
}

type CreateParams struct {
	SpaceID         string         `json:"space_id"`
	VectorID        string         `json:"vector_id,omitempty"`
	Components      []Component    `json:"components,omitempty"`
	TypeID          VectorTypeTag  `json:"type_id"`
	Metadata        map[string]any `json:"metadata,omitempty"`
	OriginChallenge string         `json:"origin_challenge,omitempty"`
	Proof           *Proof         `json:"proof,omitempty"`
	IdempotencyKey  string         `json:"idempotency_key,omitempty"`
}

type CertifyParams struct {
	SpaceID   string         `json:"space_id"`
	VectorID  string         `json:"vector_id"`
	Context   map[string]any `json:"context,omitempty"`
	Threshold float64        `json:"threshold,omitempty"`
	Proof     *Proof         `json:"proof,omitempty"`
}

type AmountSpec struct {
	Magnitude json.Number `json:"magnitude,omitempty"`
	Components []Component `json:"components,omitempty"`
}

type DrainOptions struct {
	UseOffsetCredit bool           `json:"use_offset_credit,omitempty"`
	Credit          json.Number    `json:"credit,omitempty"`
	Destination     string         `json:"destination,omitempty"`
	Rule            string         `json:"rule,omitempty"`
	Policy          map[string]any `json:"policy,omitempty"`
}

type TransferOptions struct {
	Drain            *DrainOptions  `json:"drain,omitempty"`
	RequireCertified bool           `json:"require_certified,omitempty"`
	Policy           map[string]any `json:"policy,omitempty"`
	IdempotencyKey   string         `json:"idempotency_key,omitempty"`
}

type TransferParams struct {
	SpaceID     string           `json:"space_id"`
	Source      string           `json:"source"`
	Destination string           `json:"destination"`
	Amount      AmountSpec       `json:"amount"`
	Options     *TransferOptions `json:"options,omitempty"`
	Proof       *Proof           `json:"proof,omitempty"`
}

type DrainParams struct {
	SpaceID        string       `json:"space_id"`
	VectorID       string       `json:"vector_id"`
	AmountOrRule   any          `json:"amount_or_rule"`
	Options        *DrainOptions `json:"options,omitempty"`
	Proof          *Proof       `json:"proof,omitempty"`
	IdempotencyKey string       `json:"idempotency_key,omitempty"`
}

type ProjectParams struct {
	SpaceID               string         `json:"space_id"`
	VectorID              string         `json:"vector_id"`
	EnvironmentID         string         `json:"environment_id"`
	Amount                AmountSpec     `json:"amount"`
	Policy                map[string]any `json:"policy,omitempty"`
	SettlementRule        string         `json:"settlement_rule,omitempty"`
	SettlementTrigger     string         `json:"settlement_trigger,omitempty"`
	CertificationRequired bool           `json:"certification_required,omitempty"`
	Proof                 *Proof         `json:"proof,omitempty"`
	IdempotencyKey        string         `json:"idempotency_key,omitempty"`
}

type ReconstructParams struct {
	SpaceID      string `json:"space_id"`
	VectorID     string `json:"vector_id"`
	ProjectionID string `json:"projection_id"`
	Proof        *Proof `json:"proof,omitempty"`
}

type MoveParams struct {
	SpaceID      string         `json:"space_id"`
	EntityID     string         `json:"entity_id"`
	Position     []json.Number  `json:"position,omitempty"`
	Velocity     []json.Number  `json:"velocity,omitempty"`
	Acceleration []json.Number  `json:"acceleration,omitempty"`
	RegionID     string         `json:"region_id,omitempty"`
	Metadata     map[string]any `json:"metadata,omitempty"`
	Proof        *Proof         `json:"proof,omitempty"`
}

type RotateParams struct {
	SpaceID     string        `json:"space_id"`
	EntityID    string        `json:"entity_id"`
	Orientation []json.Number `json:"orientation,omitempty"`
	Axis        []json.Number `json:"axis,omitempty"`
	Angle       json.Number   `json:"angle,omitempty"`
	Proof       *Proof        `json:"proof,omitempty"`
}

type ScaleParams struct {
	SpaceID  string      `json:"space_id"`
	EntityID string      `json:"entity_id"`
	Factor   json.Number `json:"factor"`
	Proof    *Proof      `json:"proof,omitempty"`
}

type NormalizeParams struct {
	SpaceID  string `json:"space_id"`
	EntityID string `json:"entity_id"`
	Proof    *Proof `json:"proof,omitempty"`
}

type ConstrainParams struct {
	SpaceID  string         `json:"space_id"`
	EntityID string         `json:"entity_id"`
	Rule     string         `json:"rule"`
	Bounds   map[string]any `json:"bounds,omitempty"`
	Proof    *Proof         `json:"proof,omitempty"`
}

type QueryResponse struct {
	Accepted      bool            `json:"accepted"`
	Result        any             `json:"result,omitempty"`
	CanonicalHash string          `json:"canonical_hash,omitempty"`
	Error         *OperationError `json:"error,omitempty"`
}

type EndpointPaths struct {
	SubmitOperation string
	Query           string
	Record          string
	Protocol        string
	Events          string
}

func DefaultEndpointPaths() EndpointPaths {
	return EndpointPaths{
		SubmitOperation: "/v1/operations",
		Query:           "/v1/query",
		Record:          "/v1/records",
		Protocol:        "/v1/protocol",
		Events:          "/v1/events/stream",
	}
}

type Config struct {
	BaseURL         string
	ProtocolName    string
	ProtocolVersion string
	SchemaVersion   string
	RuleVersion     string
	SpaceVersion    string
	ClientVersion   string
	Timeout         time.Duration
	UserAgent       string
	AllowInsecure   bool
	Endpoints       EndpointPaths
}

func (c Config) Normalize() (Config, error) {
	if c.BaseURL == "" {
		return Config{}, NewError(ErrorInvalidArgument, "base_url is required", false)
	}
	if c.ProtocolName == "" {
		c.ProtocolName = ProtocolName
	}
	if c.ProtocolVersion == "" {
		c.ProtocolVersion = ProtocolVersion
	}
	if c.SchemaVersion == "" {
		c.SchemaVersion = SchemaVersion
	}
	if c.RuleVersion == "" {
		c.RuleVersion = RuleVersion
	}
	if c.SpaceVersion == "" {
		c.SpaceVersion = SpaceVersion
	}
	if c.ClientVersion == "" {
		c.ClientVersion = DefaultClientVersion
	}
	if c.Timeout <= 0 {
		c.Timeout = 15 * time.Second
	}
	if c.UserAgent == "" {
		c.UserAgent = "v-sdk-go/" + c.ClientVersion
	}
	if c.Endpoints.SubmitOperation == "" {
		c.Endpoints = DefaultEndpointPaths()
	}
	return c, nil
}

func (c Config) Compatible(meta ProtocolMetadata) bool {
	if meta.ProtocolName != "" && meta.ProtocolName != c.ProtocolName {
		return false
	}
	if meta.ProtocolVersion != "" && meta.ProtocolVersion != c.ProtocolVersion {
		return false
	}
	if meta.SchemaVersion != "" && meta.SchemaVersion != c.SchemaVersion {
		return false
	}
	if meta.RuleVersion != "" && meta.RuleVersion != c.RuleVersion {
		return false
	}
	if meta.SpaceVersion != "" && meta.SpaceVersion != c.SpaceVersion {
		return false
	}
	return true
}

type Transport interface {
	DoJSON(ctx context.Context, method, path string, in any, out any) (*http.Response, error)
}

type HTTPTransport struct {
	BaseURL       *url.URL
	Client        *http.Client
	UserAgent     string
	AllowInsecure bool
}

func NewHTTPTransport(cfg Config) (*HTTPTransport, error) {
	parsed, err := url.Parse(cfg.BaseURL)
	if err != nil {
		return nil, err
	}
	return &HTTPTransport{
		BaseURL:       parsed,
		Client:        &http.Client{Timeout: cfg.Timeout},
		UserAgent:     cfg.UserAgent,
		AllowInsecure: cfg.AllowInsecure,
	}, nil
}

func (t *HTTPTransport) DoJSON(ctx context.Context, method, path string, in any, out any) (*http.Response, error) {
	if t == nil {
		return nil, fmt.Errorf("transport is nil")
	}
	if t.Client == nil {
		t.Client = &http.Client{Timeout: 15 * time.Second}
	}
	u := *t.BaseURL
	u.Path = strings.TrimRight(u.Path, "/") + path

	var body io.Reader
	if in != nil {
		raw, err := MarshalCanonical(in)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(raw)
	}

	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if t.UserAgent != "" {
		req.Header.Set("User-Agent", t.UserAgent)
	}

	resp, err := t.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if out != nil {
		data, err := io.ReadAll(resp.Body)
		if err != nil {
			return resp, err
		}
		if len(data) > 0 {
			if err := json.Unmarshal(data, out); err != nil {
				return resp, err
			}
		}
		return resp, nil
	}

	_, _ = io.Copy(io.Discard, resp.Body)
	return resp, nil
}

type MockTransport struct {
	mu       sync.Mutex
	Handlers map[string]func(ctx context.Context, method, path string, in any) (any, *http.Response, error)
	Calls    []MockCall
}

type MockCall struct {
	Method string
	Path   string
	Body   any
}

func NewMockTransport() *MockTransport {
	return &MockTransport{
		Handlers: map[string]func(context.Context, string, string, any) (any, *http.Response, error){},
	}
}

func (m *MockTransport) SetHandler(method, path string, fn func(ctx context.Context, method, path string, in any) (any, *http.Response, error)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Handlers == nil {
		m.Handlers = map[string]func(context.Context, string, string, any) (any, *http.Response, error){}
	}
	m.Handlers[strings.ToUpper(method)+" "+path] = fn
}

func (m *MockTransport) DoJSON(ctx context.Context, method, path string, in any, out any) (*http.Response, error) {
	m.mu.Lock()
	m.Calls = append(m.Calls, MockCall{Method: method, Path: path, Body: in})
	handler := m.Handlers[strings.ToUpper(method)+" "+path]
	m.mu.Unlock()

	if handler == nil {
		return nil, fmt.Errorf("mock transport has no handler for %s %s", method, path)
	}
	payload, resp, err := handler(ctx, method, path, in)
	if err != nil {
		return resp, err
	}
	if out != nil && payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			return resp, err
		}
		if err := json.Unmarshal(raw, out); err != nil {
			return resp, err
		}
	}
	if resp == nil {
		resp = &http.Response{StatusCode: http.StatusOK, Status: "200 OK"}
	}
	return resp, nil
}

func MarshalCanonical(v any) ([]byte, error) {
	if v == nil {
		return []byte("null"), nil
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var decoded any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&decoded); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := writeCanonicalJSON(&buf, decoded); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeCanonicalJSON(buf *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if x {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case string:
		b, err := json.Marshal(x)
		if err != nil {
			return err
		}
		buf.Write(b)
	case json.Number:
		if x == "" {
			buf.WriteString("0")
			return nil
		}
		if !looksNumeric(x.String()) {
			return fmt.Errorf("invalid number: %q", x.String())
		}
		buf.WriteString(x.String())
	case float64:
		buf.WriteString(strconv.FormatFloat(x, 'f', -1, 64))
	case int:
		buf.WriteString(strconv.Itoa(x))
	case int64:
		buf.WriteString(strconv.FormatInt(x, 10))
	case uint64:
		buf.WriteString(strconv.FormatUint(x, 10))
	case []any:
		buf.WriteByte('[')
		for i, item := range x {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonicalJSON(buf, item); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			kb, _ := json.Marshal(k)
			buf.Write(kb)
			buf.WriteByte(':')
			if err := writeCanonicalJSON(buf, x[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	case time.Time:
		tb, _ := json.Marshal(x.UTC().Format(time.RFC3339Nano))
		buf.Write(tb)
	default:
		raw, err := json.Marshal(x)
		if err != nil {
			return err
		}
		var decoded any
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		if err := dec.Decode(&decoded); err != nil {
			return err
		}
		return writeCanonicalJSON(buf, decoded)
	}
	return nil
}

func looksNumeric(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !(r >= '0' && r <= '9' || r == '-' || r == '+' || r == '.' || r == 'e' || r == 'E') {
			return false
		}
	}
	return true
}

func CanonicalHashBytes(v any) (string, error) {
	raw, err := MarshalCanonical(v)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func ParseNumberRat(n json.Number) (*big.Rat, error) {
	if n == "" {
		return nil, NewError(ErrorInvalidArgument, "number is empty", false)
	}
	r := new(big.Rat)
	if _, ok := r.SetString(n.String()); !ok {
		return nil, NewError(ErrorInvalidArgument, "invalid decimal number", false).WithContext("value", n.String())
	}
	return r, nil
}

func IsPositiveAmount(n json.Number) bool {
	r, err := ParseNumberRat(n)
	if err != nil {
		return false
	}
	return r.Sign() > 0
}

func MarshalJSONNumber(s string) json.Number { return json.Number(s) }

func NormalizeQueryExpression(expr string) string { return strings.Join(strings.Fields(expr), " ") }

func GenerateWallet(walletID string) (*Wallet, error) {
	if walletID == "" {
		walletID = "wallet-local"
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Wallet{
		WalletID:   walletID,
		PublicKey:  hex.EncodeToString(pub),
		PrivateKey: priv,
		Status:     "active",
	}, nil
}

func BindPublicKey(walletID, publicKey string) *Wallet {
	return &Wallet{WalletID: walletID, PublicKey: publicKey, Status: "bound"}
}

func (w *Wallet) PublicKeyBytes() ([]byte, error) {
	if w == nil {
		return nil, errors.New("wallet is nil")
	}
	if w.PublicKey == "" {
		return nil, errors.New("wallet public key missing")
	}
	return hex.DecodeString(w.PublicKey)
}

func (w *Wallet) HasPrivateKey() bool {
	return w != nil && len(w.PrivateKey) == ed25519.PrivateKeySize
}

func (w *Wallet) SignCanonical(data []byte) (string, error) {
	if w == nil {
		return "", errors.New("wallet is nil")
	}
	if !w.HasPrivateKey() {
		return "", errors.New("wallet does not contain private key material")
	}
	sig := ed25519.Sign(w.PrivateKey, data)
	return base64.StdEncoding.EncodeToString(sig), nil
}

func VerifyCanonical(publicKeyHex string, data []byte, signatureB64 string) (bool, error) {
	pub, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		return false, err
	}
	sig, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return false, err
	}
	return ed25519.Verify(ed25519.PublicKey(pub), data, sig), nil
}

func (w *Wallet) WalletSummary() string {
	if w == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%s/%s", w.WalletID, w.PublicKey)
}

func (w *Wallet) Save(path string) error {
	if w == nil {
		return errors.New("wallet is nil")
	}
	if path == "" {
		return errors.New("path is required")
	}
	raw, err := json.MarshalIndent(w, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0o600)
}

func LoadWallet(path string) (*Wallet, error) {
	if path == "" {
		return nil, errors.New("path is required")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var w Wallet
	if err := json.Unmarshal(raw, &w); err != nil {
		return nil, err
	}
	return &w, nil
}

func validateWalletForSigning(w *Wallet) error {
	if w == nil {
		return NewError(ErrorNotBound, "wallet is nil", false)
	}
	if w.PublicKey == "" {
		return NewError(ErrorNotBound, "wallet is not bound to a public key", false)
	}
	if !w.HasPrivateKey() {
		return NewError(ErrorNotBound, "wallet does not contain local signing material", false)
	}
	return nil
}

func validateOperationRequest(req OperationRequest) error {
	if req.ProtocolVersion == "" {
		return NewError(ErrorInvalidArgument, "protocol_version is required", false)
	}
	if req.SpaceID == "" {
		return NewError(ErrorInvalidArgument, "space_id is required", false)
	}
	if req.Operation == "" {
		return NewError(ErrorInvalidArgument, "operation is required", false)
	}
	if req.ActorPK == "" {
		return NewError(ErrorInvalidArgument, "actor_pk is required", false)
	}
	if req.ClientVersion == "" {
		return NewError(ErrorInvalidArgument, "client_version is required", false)
	}
	switch req.Operation {
	case OpCreate:
		return validateCreateParams(req.Params)
	case OpCertify:
		return validateCertifyParams(req.Params)
	case OpTransfer:
		return validateTransferParams(req.Params)
	case OpDrain:
		return validateDrainParams(req.Params)
	case OpProject:
		return validateProjectParams(req.Params)
	case OpReconstruct:
		return validateReconstructParams(req.Params)
	case OpQuery:
		return validateQueryParams(req.Params)
	case OpRecord:
		return validateRecordParams(req.Params)
	case OpMove:
		return validateMoveParams(req.Params)
	case OpRotate:
		return validateRotateParams(req.Params)
	case OpScale:
		return validateScaleParams(req.Params)
	case OpNormalize:
		return validateNormalizeParams(req.Params)
	case OpConstrain:
		return validateConstrainParams(req.Params)
	default:
		return nil
	}
}

func validateCreateParams(v any) error {
	params, ok := v.(CreateParams)
	if !ok {
		if m, ok := v.(map[string]any); ok {
			return validateCreateParams(mapToCreateParams(m))
		}
		return NewError(ErrorTypeMismatch, "create params have unexpected type", false)
	}
	if params.SpaceID == "" {
		return NewError(ErrorInvalidArgument, "create.space_id is required", false)
	}
	if params.TypeID == "" {
		return NewError(ErrorInvalidArgument, "create.type_id is required", false)
	}
	return nil
}

func validateCertifyParams(v any) error {
	params, ok := v.(CertifyParams)
	if !ok {
		if m, ok := v.(map[string]any); ok {
			return validateCertifyParams(mapToCertifyParams(m))
		}
		return NewError(ErrorTypeMismatch, "certify params have unexpected type", false)
	}
	if params.SpaceID == "" || params.VectorID == "" {
		return NewError(ErrorInvalidArgument, "certify requires space_id and vector_id", false)
	}
	if params.Threshold < 0 || params.Threshold > 1 {
		return NewError(ErrorInvalidArgument, "certify threshold must be in [0,1]", false)
	}
	return nil
}

func validateTransferParams(v any) error {
	params, ok := v.(TransferParams)
	if !ok {
		if m, ok := v.(map[string]any); ok {
			return validateTransferParams(mapToTransferParams(m))
		}
		return NewError(ErrorTypeMismatch, "transfer params have unexpected type", false)
	}
	if params.SpaceID == "" || params.Source == "" || params.Destination == "" {
		return NewError(ErrorInvalidArgument, "transfer requires space_id, source, and destination", false)
	}
	if isZeroAmountSpec(params.Amount) {
		return NewError(ErrorInvalidArgument, "transfer amount must be greater than zero", false).WithContext("field", "amount")
	}
	return nil
}

func validateDrainParams(v any) error {
	params, ok := v.(DrainParams)
	if !ok {
		if m, ok := v.(map[string]any); ok {
			return validateDrainParams(mapToDrainParams(m))
		}
		return NewError(ErrorTypeMismatch, "drain params have unexpected type", false)
	}
	if params.SpaceID == "" || params.VectorID == "" {
		return NewError(ErrorInvalidArgument, "drain requires space_id and vector_id", false)
	}
	if params.Options != nil && params.Options.UseOffsetCredit && strings.TrimSpace(params.Options.Credit.String()) == "" {
		return NewError(ErrorInvalidArgument, "offset credit requested but credit is empty", false)
	}
	return nil
}

func validateProjectParams(v any) error {
	params, ok := v.(ProjectParams)
	if !ok {
		if m, ok := v.(map[string]any); ok {
			return validateProjectParams(mapToProjectParams(m))
		}
		return NewError(ErrorTypeMismatch, "project params have unexpected type", false)
	}
	if params.SpaceID == "" || params.VectorID == "" || params.EnvironmentID == "" {
		return NewError(ErrorInvalidArgument, "project requires space_id, vector_id, and environment_id", false)
	}
	if isZeroAmountSpec(params.Amount) {
		return NewError(ErrorInvalidArgument, "project amount must be greater than zero", false)
	}
	return nil
}

func validateReconstructParams(v any) error {
	params, ok := v.(ReconstructParams)
	if !ok {
		if m, ok := v.(map[string]any); ok {
			return validateReconstructParams(mapToReconstructParams(m))
		}
		return NewError(ErrorTypeMismatch, "reconstruct params have unexpected type", false)
	}
	if params.SpaceID == "" || params.VectorID == "" || params.ProjectionID == "" {
		return NewError(ErrorInvalidArgument, "reconstruct requires space_id, vector_id, and projection_id", false)
	}
	return nil
}

func validateQueryParams(v any) error {
	params, ok := v.(QueryParams)
	if !ok {
		if m, ok := v.(map[string]any); ok {
			return validateQueryParams(mapToQueryParams(m))
		}
		return NewError(ErrorTypeMismatch, "query params have unexpected type", false)
	}
	if strings.TrimSpace(params.Expression) == "" {
		return NewError(ErrorInvalidArgument, "query expression is required", false)
	}
	return nil
}

func validateRecordParams(v any) error {
	params, ok := v.(RecordParams)
	if !ok {
		if m, ok := v.(map[string]any); ok {
			return validateRecordParams(mapToRecordParams(m))
		}
		return NewError(ErrorTypeMismatch, "record params have unexpected type", false)
	}
	if strings.TrimSpace(params.RecordID) == "" {
		return NewError(ErrorInvalidArgument, "record_id is required", false)
	}
	return nil
}

func validateMoveParams(v any) error {
	params, ok := v.(MoveParams)
	if !ok {
		if m, ok := v.(map[string]any); ok {
			return validateMoveParams(mapToMoveParams(m))
		}
		return NewError(ErrorTypeMismatch, "move params have unexpected type", false)
	}
	if params.SpaceID == "" || params.EntityID == "" {
		return NewError(ErrorInvalidArgument, "move requires space_id and entity_id", false)
	}
	return nil
}

func validateRotateParams(v any) error {
	params, ok := v.(RotateParams)
	if !ok {
		if m, ok := v.(map[string]any); ok {
			return validateRotateParams(mapToRotateParams(m))
		}
		return NewError(ErrorTypeMismatch, "rotate params have unexpected type", false)
	}
	if params.SpaceID == "" || params.EntityID == "" {
		return NewError(ErrorInvalidArgument, "rotate requires space_id and entity_id", false)
	}
	return nil
}

func validateScaleParams(v any) error {
	params, ok := v.(ScaleParams)
	if !ok {
		if m, ok := v.(map[string]any); ok {
			return validateScaleParams(mapToScaleParams(m))
		}
		return NewError(ErrorTypeMismatch, "scale params have unexpected type", false)
	}
	if params.SpaceID == "" || params.EntityID == "" {
		return NewError(ErrorInvalidArgument, "scale requires space_id and entity_id", false)
	}
	if params.Factor == "" {
		return NewError(ErrorInvalidArgument, "scale factor is required", false)
	}
	return nil
}

func validateNormalizeParams(v any) error {
	params, ok := v.(NormalizeParams)
	if !ok {
		if m, ok := v.(map[string]any); ok {
			return validateNormalizeParams(mapToNormalizeParams(m))
		}
		return NewError(ErrorTypeMismatch, "normalize params have unexpected type", false)
	}
	if params.SpaceID == "" || params.EntityID == "" {
		return NewError(ErrorInvalidArgument, "normalize requires space_id and entity_id", false)
	}
	return nil
}

func validateConstrainParams(v any) error {
	params, ok := v.(ConstrainParams)
	if !ok {
		if m, ok := v.(map[string]any); ok {
			return validateConstrainParams(mapToConstrainParams(m))
		}
		return NewError(ErrorTypeMismatch, "constrain params have unexpected type", false)
	}
	if params.SpaceID == "" || params.EntityID == "" || strings.TrimSpace(params.Rule) == "" {
		return NewError(ErrorInvalidArgument, "constrain requires space_id, entity_id, and rule", false)
	}
	return nil
}

func isZeroAmountSpec(spec AmountSpec) bool {
	if spec.Magnitude == "" && len(spec.Components) == 0 {
		return true
	}
	if spec.Magnitude != "" {
		r, err := ParseNumberRat(spec.Magnitude)
		if err == nil && r.Sign() != 0 {
			return false
		}
	}
	for _, c := range spec.Components {
		r, err := ParseNumberRat(c.Amount)
		if err == nil && r.Sign() != 0 {
			return false
		}
	}
	return true
}

func mapToCreateParams(m map[string]any) CreateParams { var p CreateParams; b, _ := json.Marshal(m); _ = json.Unmarshal(b, &p); return p }
func mapToCertifyParams(m map[string]any) CertifyParams { var p CertifyParams; b, _ := json.Marshal(m); _ = json.Unmarshal(b, &p); return p }
func mapToTransferParams(m map[string]any) TransferParams { var p TransferParams; b, _ := json.Marshal(m); _ = json.Unmarshal(b, &p); return p }
func mapToDrainParams(m map[string]any) DrainParams { var p DrainParams; b, _ := json.Marshal(m); _ = json.Unmarshal(b, &p); return p }
func mapToProjectParams(m map[string]any) ProjectParams { var p ProjectParams; b, _ := json.Marshal(m); _ = json.Unmarshal(b, &p); return p }
func mapToReconstructParams(m map[string]any) ReconstructParams { var p ReconstructParams; b, _ := json.Marshal(m); _ = json.Unmarshal(b, &p); return p }
func mapToQueryParams(m map[string]any) QueryParams { var p QueryParams; b, _ := json.Marshal(m); _ = json.Unmarshal(b, &p); return p }
func mapToRecordParams(m map[string]any) RecordParams { var p RecordParams; b, _ := json.Marshal(m); _ = json.Unmarshal(b, &p); return p }
func mapToMoveParams(m map[string]any) MoveParams { var p MoveParams; b, _ := json.Marshal(m); _ = json.Unmarshal(b, &p); return p }
func mapToRotateParams(m map[string]any) RotateParams { var p RotateParams; b, _ := json.Marshal(m); _ = json.Unmarshal(b, &p); return p }
func mapToScaleParams(m map[string]any) ScaleParams { var p ScaleParams; b, _ := json.Marshal(m); _ = json.Unmarshal(b, &p); return p }
func mapToNormalizeParams(m map[string]any) NormalizeParams { var p NormalizeParams; b, _ := json.Marshal(m); _ = json.Unmarshal(b, &p); return p }
func mapToConstrainParams(m map[string]any) ConstrainParams { var p ConstrainParams; b, _ := json.Marshal(m); _ = json.Unmarshal(b, &p); return p }

type Client struct {
	cfg       Config
	transport Transport
	wallet    *Wallet
}

func New(cfg Config) (*Client, error) {
	norm, err := cfg.Normalize()
	if err != nil {
		return nil, err
	}
	tp, err := NewHTTPTransport(norm)
	if err != nil {
		return nil, err
	}
	return &Client{cfg: norm, transport: tp}, nil
}

func NewWithTransport(cfg Config, transport Transport) (*Client, error) {
	norm, err := cfg.Normalize()
	if err != nil {
		return nil, err
	}
	if transport == nil {
		return nil, NewError(ErrorInvalidArgument, "transport is required", false)
	}
	return &Client{cfg: norm, transport: transport}, nil
}

func (c *Client) Config() Config {
	if c == nil {
		return Config{}
	}
	return c.cfg
}

func (c *Client) SetWallet(wallet *Wallet) error {
	if c == nil {
		return errors.New("client is nil")
	}
	if wallet == nil {
		return NewError(ErrorNotBound, "wallet is nil", false)
	}
	c.wallet = wallet
	return nil
}

func (c *Client) Wallet() *Wallet {
	if c == nil {
		return nil
	}
	return c.wallet
}

func (c *Client) CreateWallet(walletID ...string) (*Wallet, error) {
	if c == nil {
		return nil, errors.New("client is nil")
	}
	id := "wallet-local"
	if len(walletID) > 0 && walletID[0] != "" {
		id = walletID[0]
	}
	w, err := GenerateWallet(id)
	if err != nil {
		return nil, err
	}
	c.wallet = w
	return w, nil
}

func (c *Client) BindWallet(wallet *Wallet) error { return c.SetWallet(wallet) }

func (c *Client) BindPublicKey(walletID, publicKey string) error {
	if c == nil {
		return errors.New("client is nil")
	}
	c.wallet = BindPublicKey(walletID, publicKey)
	return nil
}

func (c *Client) Protocol(ctx context.Context) (*ProtocolMetadata, error) {
	var meta ProtocolMetadata
	if _, err := c.transport.DoJSON(ctx, http.MethodGet, c.cfg.Endpoints.Protocol, nil, &meta); err != nil {
		return nil, err
	}
	if !c.cfg.Compatible(meta) && meta.ProtocolName != "" {
		return nil, NewError(ErrorProtocolVersionUnsupported, "node protocol is incompatible", false).WithContext("server_protocol", meta)
	}
	if meta.ClientVersion == "" {
		meta.ClientVersion = c.cfg.ClientVersion
	}
	return &meta, nil
}

func (c *Client) SignRequest(req *OperationRequest) error {
	if c == nil {
		return errors.New("client is nil")
	}
	if err := validateWalletForSigning(c.wallet); err != nil {
		return err
	}
	if req == nil {
		return NewError(ErrorInvalidArgument, "request is nil", false)
	}
	signed := *req
	signed.Signature = ""
	raw, err := MarshalCanonical(signed)
	if err != nil {
		return WrapError(ErrorSerialization, "failed to serialize request for signing", false, err)
	}
	sig, err := c.wallet.SignCanonical(raw)
	if err != nil {
		return err
	}
	req.Signature = sig
	req.ActorPK = c.wallet.PublicKey
	return nil
}

func (c *Client) VerifyRequestSignature(req OperationRequest) (bool, error) {
	if req.ActorPK == "" || req.Signature == "" {
		return false, NewError(ErrorInvalidSignature, "request is missing signature material", false)
	}
	unsigned := req
	unsigned.Signature = ""
	raw, err := MarshalCanonical(unsigned)
	if err != nil {
		return false, err
	}
	return VerifyCanonical(req.ActorPK, raw, req.Signature)
}

func (c *Client) Submit(ctx context.Context, req OperationRequest) (*OperationResponse, *OperationError, error) {
	if c == nil {
		return nil, nil, errors.New("client is nil")
	}
	if err := validateOperationRequest(req); err != nil {
		return nil, nil, err
	}
	if req.Signature == "" {
		if err := c.SignRequest(&req); err != nil {
			return nil, nil, err
		}
	}
	var success OperationResponse
	if _, err := c.transport.DoJSON(ctx, http.MethodPost, c.cfg.Endpoints.SubmitOperation, req, &success); err != nil {
		return nil, nil, err
	}
	if success.Accepted {
		return &success, nil, nil
	}
	return &success, &OperationError{
		Accepted:      false,
		ErrorCode:     ErrorRecordConflict,
		Message:       "operation rejected",
		Recoverable:    false,
		Operation:     req.Operation,
		CanonicalHash: success.CanonicalHash,
	}, nil
}

func (c *Client) SubmitOperation(ctx context.Context, req OperationRequest) (*OperationResponse, error) {
	resp, opErr, err := c.Submit(ctx, req)
	if err != nil {
		return nil, err
	}
	if opErr != nil {
		return nil, opErr
	}
	return resp, nil
}

func (c *Client) newRequest(spaceID string, op Operation, params any, proof *Proof, idempotency string) OperationRequest {
	req := OperationRequest{
		ProtocolVersion: c.cfg.ProtocolVersion,
		SpaceID:         spaceID,
		Operation:       op,
		Params:          params,
		Proof:           proof,
		ClientVersion:   c.cfg.ClientVersion,
		IdempotencyKey:  idempotency,
	}
	if c.wallet != nil {
		req.ActorPK = c.wallet.PublicKey
	}
	return req
}

func (c *Client) Create(ctx context.Context, params CreateParams) (*OperationResponse, error) {
	return c.SubmitOperation(ctx, c.newRequest(params.SpaceID, OpCreate, params, params.Proof, params.IdempotencyKey))
}

func (c *Client) Certify(ctx context.Context, params CertifyParams) (*OperationResponse, error) {
	return c.SubmitOperation(ctx, c.newRequest(params.SpaceID, OpCertify, params, params.Proof, ""))
}

func (c *Client) Transfer(ctx context.Context, params TransferParams) (*OperationResponse, error) {
	idempotency := ""
	if params.Options != nil {
		idempotency = params.Options.IdempotencyKey
	}
	return c.SubmitOperation(ctx, c.newRequest(params.SpaceID, OpTransfer, params, params.Proof, idempotency))
}

func (c *Client) Drain(ctx context.Context, params DrainParams) (*OperationResponse, error) {
	return c.SubmitOperation(ctx, c.newRequest(params.SpaceID, OpDrain, params, params.Proof, params.IdempotencyKey))
}

func (c *Client) Project(ctx context.Context, params ProjectParams) (*OperationResponse, error) {
	return c.SubmitOperation(ctx, c.newRequest(params.SpaceID, OpProject, params, params.Proof, params.IdempotencyKey))
}

func (c *Client) Reconstruct(ctx context.Context, params ReconstructParams) (*OperationResponse, error) {
	return c.SubmitOperation(ctx, c.newRequest(params.SpaceID, OpReconstruct, params, params.Proof, ""))
}

func (c *Client) Move(ctx context.Context, params MoveParams) (*OperationResponse, error) {
	return c.SubmitOperation(ctx, c.newRequest(params.SpaceID, OpMove, params, params.Proof, ""))
}

func (c *Client) Rotate(ctx context.Context, params RotateParams) (*OperationResponse, error) {
	return c.SubmitOperation(ctx, c.newRequest(params.SpaceID, OpRotate, params, params.Proof, ""))
}

func (c *Client) Scale(ctx context.Context, params ScaleParams) (*OperationResponse, error) {
	return c.SubmitOperation(ctx, c.newRequest(params.SpaceID, OpScale, params, params.Proof, ""))
}

func (c *Client) Normalize(ctx context.Context, params NormalizeParams) (*OperationResponse, error) {
	return c.SubmitOperation(ctx, c.newRequest(params.SpaceID, OpNormalize, params, params.Proof, ""))
}

func (c *Client) Constrain(ctx context.Context, params ConstrainParams) (*OperationResponse, error) {
	return c.SubmitOperation(ctx, c.newRequest(params.SpaceID, OpConstrain, params, params.Proof, ""))
}

func (c *Client) Query(ctx context.Context, params QueryParams) (*QueryResponse, error) {
	if err := validateQueryParams(params); err != nil {
		return nil, err
	}
	params.Expression = NormalizeQueryExpression(params.Expression)
	var resp QueryResponse
	if _, err := c.transport.DoJSON(ctx, http.MethodPost, c.cfg.Endpoints.Query, params, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) Record(ctx context.Context, params RecordParams) (*Record, error) {
	if err := validateRecordParams(params); err != nil {
		return nil, err
	}
	var rec Record
	if _, err := c.transport.DoJSON(ctx, http.MethodPost, c.cfg.Endpoints.Record, params, &rec); err != nil {
		return nil, err
	}
	return &rec, nil
}

func (c *Client) Health(ctx context.Context) (bool, error) {
	meta, err := c.Protocol(ctx)
	if err != nil {
		return false, err
	}
	return c.cfg.Compatible(*meta), nil
}

func (c *Client) SignBytes(payload []byte) (string, error) {
	if err := validateWalletForSigning(c.wallet); err != nil {
		return "", err
	}
	return c.wallet.SignCanonical(payload)
}

func (c *Client) PublicKeyHex() string {
	if c == nil || c.wallet == nil {
		return ""
	}
	return c.wallet.PublicKey
}

func (c *Client) PublicKeyRaw() ([]byte, error) {
	if c == nil || c.wallet == nil {
		return nil, errors.New("wallet is not bound")
	}
	return hex.DecodeString(c.wallet.PublicKey)
}

func (c *Client) SignOperationData(op Operation, payload any) (string, error) {
	if err := validateWalletForSigning(c.wallet); err != nil {
		return "", err
	}
	body := map[string]any{"operation": op, "payload": payload}
	raw, err := MarshalCanonical(body)
	if err != nil {
		return "", err
	}
	return c.wallet.SignCanonical(raw)
}

func (c *Client) SubmitAndWait(ctx context.Context, req OperationRequest) (*OperationResponse, error) {
	return c.SubmitOperation(ctx, req)
}

func ContextWithTimeout(parent context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	if d <= 0 {
		d = 15 * time.Second
	}
	return context.WithTimeout(parent, d)
}

func WalletFromHex(walletID, publicKeyHex string, privateKeyHex ...string) (*Wallet, error) {
	w := BindPublicKey(walletID, publicKeyHex)
	if len(privateKeyHex) > 0 && privateKeyHex[0] != "" {
		priv, err := hex.DecodeString(privateKeyHex[0])
		if err != nil {
			return nil, err
		}
		if len(priv) != ed25519.PrivateKeySize {
			return nil, errors.New("private key has invalid size")
		}
		w.PrivateKey = priv
	}
	return w, nil
}
