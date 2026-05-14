package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	vsdk "github.com/vnetworkx/v-sdk-go"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "protocol":
		runProtocol(os.Args[2:])
	case "wallet":
		runWallet(os.Args[2:])
	case "query":
		runQuery(os.Args[2:])
	case "record":
		runRecord(os.Args[2:])
	case "create":
		runGenericOperation("create", os.Args[2:])
	case "certify":
		runGenericOperation("certify", os.Args[2:])
	case "transfer":
		runGenericOperation("transfer", os.Args[2:])
	case "drain":
		runGenericOperation("drain", os.Args[2:])
	case "project":
		runGenericOperation("project", os.Args[2:])
	case "reconstruct":
		runGenericOperation("reconstruct", os.Args[2:])
	default:
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "v-sdk-go commands:")
	fmt.Fprintln(os.Stderr, "  protocol")
	fmt.Fprintln(os.Stderr, "  wallet create|save|load")
	fmt.Fprintln(os.Stderr, "  query")
	fmt.Fprintln(os.Stderr, "  record")
	fmt.Fprintln(os.Stderr, "  create")
	fmt.Fprintln(os.Stderr, "  certify")
	fmt.Fprintln(os.Stderr, "  transfer")
	fmt.Fprintln(os.Stderr, "  drain")
	fmt.Fprintln(os.Stderr, "  project")
	fmt.Fprintln(os.Stderr, "  reconstruct")
}

func newClient(baseURL string) *vsdk.Client {
	c, err := vsdk.New(vsdk.Config{BaseURL: baseURL, ClientVersion: vsdk.DefaultClientVersion})
	if err != nil {
		fail(err)
	}
	return c
}

func runProtocol(args []string) {
	fs := flag.NewFlagSet("protocol", flag.ExitOnError)
	baseURL := fs.String("base", "http://localhost:8080", "node base URL")
	_ = fs.Parse(args)

	c := newClient(*baseURL)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	meta, err := c.Protocol(ctx)
	if err != nil {
		fail(err)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(meta)
}

func runWallet(args []string) {
	if len(args) == 0 {
		fail(fmt.Errorf("wallet subcommand required"))
	}
	switch args[0] {
	case "create":
		fs := flag.NewFlagSet("wallet create", flag.ExitOnError)
		path := fs.String("out", "wallet.json", "output wallet file")
		walletID := fs.String("id", "wallet-local", "wallet id")
		_ = fs.Parse(args[1:])
		w, err := vsdk.GenerateWallet(*walletID)
		if err != nil {
			fail(err)
		}
		if err := w.Save(*path); err != nil {
			fail(err)
		}
		fmt.Println(w.WalletSummary())
	case "load":
		fs := flag.NewFlagSet("wallet load", flag.ExitOnError)
		path := fs.String("in", "wallet.json", "input wallet file")
		_ = fs.Parse(args[1:])
		w, err := vsdk.LoadWallet(*path)
		if err != nil {
			fail(err)
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(w)
	case "save":
		fs := flag.NewFlagSet("wallet save", flag.ExitOnError)
		in := fs.String("in", "wallet.json", "input wallet file")
		out := fs.String("out", "wallet-copy.json", "output wallet file")
		_ = fs.Parse(args[1:])
		w, err := vsdk.LoadWallet(*in)
		if err != nil {
			fail(err)
		}
		if err := w.Save(*out); err != nil {
			fail(err)
		}
		fmt.Println("saved", *out)
	default:
		fail(fmt.Errorf("unknown wallet subcommand: %s", args[0]))
	}
}

func runQuery(args []string) {
	fs := flag.NewFlagSet("query", flag.ExitOnError)
	baseURL := fs.String("base", "http://localhost:8080", "node base URL")
	expr := fs.String("expr", "", "query expression")
	spaceID := fs.String("space", "", "space identifier")
	_ = fs.Parse(args)

	c := newClient(*baseURL)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := c.Query(ctx, vsdk.QueryParams{Expression: *expr, SpaceID: *spaceID})
	if err != nil {
		fail(err)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(resp)
}

func runRecord(args []string) {
	fs := flag.NewFlagSet("record", flag.ExitOnError)
	baseURL := fs.String("base", "http://localhost:8080", "node base URL")
	recordID := fs.String("id", "", "record identifier")
	spaceID := fs.String("space", "", "space identifier")
	_ = fs.Parse(args)

	c := newClient(*baseURL)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	rec, err := c.Record(ctx, vsdk.RecordParams{RecordID: *recordID, SpaceID: *spaceID})
	if err != nil {
		fail(err)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(rec)
}

func runGenericOperation(name string, args []string) {
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	baseURL := fs.String("base", "http://localhost:8080", "node base URL")
	spaceID := fs.String("space", "", "space identifier")
	_ = fs.Parse(args)

	c := newClient(*baseURL)
	w, err := vsdk.GenerateWallet("wallet-cli")
	if err != nil {
		fail(err)
	}
	_ = c.BindWallet(w)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	switch name {
	case "create":
		resp, err := c.Create(ctx, vsdk.CreateParams{SpaceID: *spaceID, TypeID: vsdk.VectorFree})
		printResp(resp, err)
	case "certify":
		resp, err := c.Certify(ctx, vsdk.CertifyParams{SpaceID: *spaceID, VectorID: "vector-1", Threshold: 0.5})
		printResp(resp, err)
	case "transfer":
		resp, err := c.Transfer(ctx, vsdk.TransferParams{SpaceID: *spaceID, Source: "src", Destination: "dst", Amount: vsdk.AmountSpec{Magnitude: vsdk.MarshalJSONNumber("1")}})
		printResp(resp, err)
	case "drain":
		resp, err := c.Drain(ctx, vsdk.DrainParams{SpaceID: *spaceID, VectorID: "vector-1", AmountOrRule: "1"})
		printResp(resp, err)
	case "project":
		resp, err := c.Project(ctx, vsdk.ProjectParams{SpaceID: *spaceID, VectorID: "vector-1", EnvironmentID: "env-1", Amount: vsdk.AmountSpec{Magnitude: vsdk.MarshalJSONNumber("1")}})
		printResp(resp, err)
	case "reconstruct":
		resp, err := c.Reconstruct(ctx, vsdk.ReconstructParams{SpaceID: *spaceID, VectorID: "vector-1", ProjectionID: "projection-1"})
		printResp(resp, err)
	}
}

func printResp(resp *vsdk.OperationResponse, err error) {
	if err != nil {
		fail(err)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(resp)
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
