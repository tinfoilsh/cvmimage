package volume

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"time"
)

type Request struct {
	Key     []byte `json:"key,omitempty"`
	Binding []byte `json:"binding,omitempty"`
	Permit  string `json:"permit,omitempty"`
}
type Client struct{ Socket string }

func (c Client) call(ctx context.Context, method, path string, body any, into any) error {
	var data []byte
	if body != nil {
		var err error
		data, err = json.Marshal(body)
		if err != nil {
			return err
		}
		defer clear(data)
	}
	socket := c.Socket
	if socket == "" {
		socket = Socket
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}
	defer transport.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, method, "http://volumes"+path, bytes.NewReader(data))
	if err != nil {
		return err
	}
	response, err := (&http.Client{Transport: transport}).Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusNoContent {
		return fmt.Errorf("volume service returned %s", response.Status)
	}
	if into != nil {
		return json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(into)
	}
	return nil
}
func (c Client) Status(ctx context.Context) (Snapshot, error) {
	var result Snapshot
	err := c.call(ctx, "GET", "/v1/status", nil, &result)
	return result, err
}
func (c Client) Enroll(ctx context.Context, name string, r Request) error {
	return c.call(ctx, "POST", "/v1/enroll/"+name, r, nil)
}
func (c Client) Unlock(ctx context.Context, name string, r Request) error {
	return c.call(ctx, "POST", "/v1/unlock/"+name, r, nil)
}

// ReadyVolume is the mounted source granted to a consumer.
type ReadyVolume struct {
	Path   string
	Access string
}
type ReadyVolumes map[string]ReadyVolume

func (c Client) Wait(ctx context.Context, names []string) (ReadyVolumes, error) {
	names = slices.Clone(names)
	slices.Sort(names)
	names = slices.Compact(names)
	if len(names) == 0 {
		return ReadyVolumes{}, nil
	}
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		state, err := c.Status(ctx)
		if err != nil {
			return nil, err
		}
		ready, complete, err := resolveReady(state, names)
		if err != nil {
			return nil, err
		}
		if complete {
			return ready, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
		}
	}
}

func resolveReady(state Snapshot, names []string) (ReadyVolumes, bool, error) {
	byName := make(map[string]Status, len(state.Volumes))
	for _, s := range state.Volumes {
		if _, exists := byName[s.Name]; exists {
			return nil, false, fmt.Errorf("duplicate volume status %s", s.Name)
		}
		byName[s.Name] = s
	}
	ready := make(ReadyVolumes, len(names))
	for _, name := range names {
		s, ok := byName[name]
		if !ok {
			return nil, false, fmt.Errorf("unknown volume %s", name)
		}
		if s.Phase == "failed" || s.Phase == "closed" {
			return nil, false, fmt.Errorf("volume %s is %s", name, s.Phase)
		}
		if s.Phase != "ready" {
			continue
		}
		if !absolutePath(s.Path) || s.Access != "ro" && s.Access != "rw" {
			return nil, false, fmt.Errorf("volume %s returned invalid mount information", name)
		}
		ready[name] = ReadyVolume{Path: s.Path, Access: s.Access}
	}
	return ready, len(ready) == len(names), nil
}
