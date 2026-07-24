package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

const (
	dockerSocketPath          = "/var/run/docker.sock"
	dockerAPIVersion          = "v1.44"
	maxContainerReferenceSize = 255
	maxInspectResponseSize    = 1 << 20
	dockerDialTimeout         = time.Second
	dockerInspectTimeout      = 3 * time.Second
	containerStateCreated     = "created"
	containerStateDead        = "dead"
	containerStateExited      = "exited"
	containerStateRestarting  = "restarting"
)

var errContainerNotFound = errors.New("container not found")

type dockerInspectClient struct {
	client *http.Client
}

type containerInspect struct {
	Base   *containerInspectBase
	Config *containerConfig
}

type containerInspectBase struct {
	ID           string
	Name         string
	RestartCount int
	State        *containerState
	HostConfig   *containerHostConfig
}

type containerConfig struct {
	Image string `json:"Image"`
}

type containerHostConfig struct {
	RestartPolicy containerRestartPolicy `json:"RestartPolicy"`
}

type containerRestartPolicy struct {
	Name              string `json:"Name"`
	MaximumRetryCount int    `json:"MaximumRetryCount"`
}

type containerState struct {
	Status     string                `json:"Status"`
	OOMKilled  bool                  `json:"OOMKilled"`
	ExitCode   int                   `json:"ExitCode"`
	Error      string                `json:"Error"`
	StartedAt  string                `json:"StartedAt"`
	FinishedAt string                `json:"FinishedAt"`
	Health     *containerHealthState `json:"Health"`
}

type containerHealthState struct {
	Status        string                   `json:"Status"`
	FailingStreak int                      `json:"FailingStreak"`
	Log           []*containerHealthResult `json:"Log"`
}

type containerHealthResult struct {
	Start    time.Time `json:"Start"`
	End      time.Time `json:"End"`
	ExitCode int       `json:"ExitCode"`
}

type dockerInspectResponse struct {
	ID           string               `json:"Id"`
	Name         string               `json:"Name"`
	RestartCount int                  `json:"RestartCount"`
	State        *containerState      `json:"State"`
	HostConfig   *containerHostConfig `json:"HostConfig"`
	Config       *containerConfig     `json:"Config"`
}

func newDockerInspectClient(socketPath string) *dockerInspectClient {
	dialer := &net.Dialer{Timeout: dockerDialTimeout}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return dialer.DialContext(ctx, "unix", socketPath)
		},
		DisableCompression:     true,
		MaxIdleConns:           1,
		MaxIdleConnsPerHost:    1,
		MaxConnsPerHost:        1,
		IdleConnTimeout:        2 * dockerInspectTimeout,
		ResponseHeaderTimeout:  dockerInspectTimeout,
		MaxResponseHeaderBytes: 16 << 10,
	}
	return &dockerInspectClient{client: &http.Client{
		Transport: transport,
		Timeout:   dockerInspectTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}}
}

func (c *dockerInspectClient) CloseIdleConnections() {
	c.client.CloseIdleConnections()
}

func (c *dockerInspectClient) ContainerInspect(ctx context.Context, name string) (containerInspect, error) {
	if name == "" || len(name) > maxContainerReferenceSize {
		return containerInspect{}, fmt.Errorf("invalid container reference length %d", len(name))
	}
	requestURL := "http://docker/" + dockerAPIVersion + "/containers/" + url.PathEscape(name) + "/json"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return containerInspect{}, fmt.Errorf("creating inspect request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return containerInspect{}, fmt.Errorf("requesting inspect: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return containerInspect{}, errContainerNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return containerInspect{}, fmt.Errorf("inspect returned HTTP status %d", resp.StatusCode)
	}
	mediaType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return containerInspect{}, fmt.Errorf("inspect returned non-JSON content type %q", resp.Header.Get("Content-Type"))
	}
	if contentLength := resp.Header.Get("Content-Length"); contentLength != "" {
		length, err := strconv.ParseInt(contentLength, 10, 64)
		if err != nil || length < 0 || length > maxInspectResponseSize {
			return containerInspect{}, fmt.Errorf("inspect response has invalid content length %q", contentLength)
		}
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxInspectResponseSize+1))
	if err != nil {
		return containerInspect{}, fmt.Errorf("reading inspect response: %w", err)
	}
	if len(data) > maxInspectResponseSize {
		return containerInspect{}, fmt.Errorf("inspect response exceeds %d bytes", maxInspectResponseSize)
	}
	var wire dockerInspectResponse
	if err := json.Unmarshal(data, &wire); err != nil {
		return containerInspect{}, fmt.Errorf("decoding inspect response: %w", err)
	}
	return containerInspect{
		Base: &containerInspectBase{
			ID:           wire.ID,
			Name:         wire.Name,
			RestartCount: wire.RestartCount,
			State:        wire.State,
			HostConfig:   wire.HostConfig,
		},
		Config: wire.Config,
	}, nil
}
