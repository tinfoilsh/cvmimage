// Command tinfoil-sandbox is the API served inside a sandbox CVM that
// orchestrator creates. It is the guest half of one contract: orchestrator
// mints a short-lived ES256 permit naming a sandbox's domain and the nonce of
// the boot it is meant for, and that permit buys exactly one thing -- the right
// to name the public key that owns this sandbox for the rest of the boot.
//
// The permit is spent by the call that uses it. After one POST /enroll succeeds
// the orchestrator's key is never read again, so the party that launched the
// sandbox cannot re-enter it.
//
// Both halves of every check are local. The orchestrator's key is compiled into
// the measured image, so a client attesting this enclave is told who may
// introduce an owner; the nonce is minted here at startup, so neither a permit
// nor an enrollment outlives the boot it was made against. Verification
// therefore needs no network and no stored state, and nothing here ever dials
// out.
//
// The enrolled key is the sandbox's SSH credential. Enrollment opens the
// workspace volume, seals the key into the one authorized_keys sshd will ever
// read and starts sshd, which is configured for publickey and nothing else: no
// password, no keyboard-interactive, no host-based, no second key, and no
// listener at all until an owner exists.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"tinfoil/internal/bootstate"
	shimconfig "tinfoil/internal/config"
	"tinfoil/internal/runtimeconfig"
	"tinfoil/sandbox/internal/variant"
)

const (
	workspace = "/workspace"

	// The login account's home, which only an unlocked volume can hold.
	home = workspace + "/home"

	// The pack names its closure without the hash at this path below its mount.
	// The volume gets a link to it so the image can use nix's own path for both.
	packProfile = "nix/var/nix/profiles/default"
	nixRoot     = "/nix"
	profiles    = nixRoot + "/var/nix/profiles"
	profile     = profiles + "/default"

	// The login shell is one of these, so the image's directories stay on PATH.
	imagePath = "/usr/local/bin:/usr/bin:/bin"

	// Who may introduce this sandbox's owner is part of what a client attests,
	// so the issuer and its P-256 verifying key (base64 SPKI DER) are part of
	// the measured image rather than injected at launch. The key spends itself
	// on one enrollment: it names the first owner, and can neither name a
	// second nor act as one.
	permitIssuer = "https://orchestrator.tinfoil.sh"
	permitKey    = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEe7Dz4UoNi9fKoAq9DMgv+moqp+dyZyVSeRlAiVlFqZNAMLaamYJotUmKSR7OAT7AND1fC47oDfzOOX9nOs72ew=="

	volumeKeyBytes = 64

	sshdStartTimeout = 30 * time.Second
	syncInterval     = 5 * time.Second

	// The limit is what keeps an unauthenticated body from being interesting.
	maxEnrollBytes = 1 << 12

	coordinate = 32 // bytes per ECDSA P-256 signature half, as JWS packs them

	// sshd listens on the CVM's loopback, which is reachable only through the
	// shim's CONNECT tunnel and is the only reason a client can dial it at all.
	sshPort = 22

	// sshRun holds everything sshd reads: a host key minted at boot, the config
	// rendered from the constant below, and the one authorized_keys an
	// enrollment seals. privilegeSeparationDir is the empty directory Ubuntu's
	// sshd insists on for its unprivileged half.
	sshRun                 = "/run/tinfoil/sandbox"
	hostKey                = sshRun + "/host_key"
	sshdConfig             = sshRun + "/sshd_config"
	authorized             = sshRun + "/authorized_keys"
	privilegeSeparationDir = "/run/sshd"

	sshd = "/usr/sbin/sshd"

	certificateSuffix = "-cert-v01@openssh.com"

	// The login account. The CVM is the boundary, and inside it the owner is
	// root.
	loginUser = "root"
)

// sshdPolicy is sshd's whole configuration: publickey against one sealed file,
// and every other way in named and refused rather than left to a default. It is
// rendered to sshRun at boot and checked with `sshd -t` there, because after an
// enrollment there is no second chance to get it right.
const sshdPolicy = `Port %d
ListenAddress 127.0.0.1
HostKey %s
AuthorizedKeysFile %s
PidFile none

AuthenticationMethods publickey
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
HostbasedAuthentication no
GSSAPIAuthentication no
UsePAM no
PermitEmptyPasswords no
PermitRootLogin prohibit-password
AllowUsers %s
StrictModes yes

AllowAgentForwarding no
AllowTcpForwarding no
GatewayPorts no
PermitTunnel no
PermitUserEnvironment no
X11Forwarding no

LoginGraceTime 30
MaxAuthTries 3
MaxSessions 8
MaxStartups 4:50:8
ClientAliveInterval 60
ClientAliveCountMax 3
PrintMotd no

# A session carrying a command reads no profile script.
SetEnv PATH=%s

# Every accepted key is logged with its fingerprint, which is the only record
# this boot keeps of who came in and dies with it.
LogLevel VERBOSE

# scp and sftp are how an owner moves files over the door they already have;
# internal-sftp needs no binary on the read-only rootfs.
Subsystem sftp internal-sftp
`

type sandbox struct {
	domain string
	permit *ecdsa.PublicKey
	nonce  string
	volume volume

	// fingerprint identifies the host key sshd will present, minted at boot and
	// reported by /healthz. A client reads it over the attested channel before it
	// ever dials port 22, so the shell needs no trust-on-first-use.
	fingerprint string

	// owner is the key named by the one permit this boot honours, and empty until
	// then. That single field is the whole of the authorization state: with no
	// owner the workspace serves nobody, and with one the orchestrator's key has
	// no further use. listening follows it: sshd is started by the enrollment
	// that seals the key, so before one there is no SSH listener to attack.
	mu        sync.Mutex
	owner     string
	listening bool

	enrolling sync.Mutex
}

func main() {
	log.SetFlags(0)
	if len(os.Args) > 1 && os.Args[1] == formatMode {
		if err := runFormatter(os.Args); err != nil {
			log.Fatalf("tinfoil-sandbox: %v", err)
		}
		return
	}
	if err := run(); err != nil {
		log.Fatalf("tinfoil-sandbox: %v", err)
	}
}

func run() (result error) {
	start := time.Now()
	defer func() {
		if result != nil {
			_ = bootstate.RecordStage(variant.Stage, bootstate.StatusFailed, time.Since(start), result.Error())
		}
	}()
	syscall.Umask(0o077)

	config, err := measuredConfig()
	if err != nil {
		return err
	}
	// The domain is the only value that differs per sandbox, so it arrives
	// through the unmeasured external config tinfoild writes at launch -- the
	// same entry tinfoil-boot reads to get the certificate. A permit's subject
	// is checked against it, so the measurement covers that the check happens
	// and the launch decides which name it happens for.
	domain, err := externalDomain()
	if err != nil {
		return err
	}
	permit, err := publicKey(permitKey)
	if err != nil {
		return fmt.Errorf("permit key: %w", err)
	}
	box := &sandbox{
		domain: domain,
		permit: permit,
		// Every credential this boot honours is bound to this string. Minting
		// it here rather than accepting one from the host is what ties them to
		// a boot: the host can only learn the nonce of the instance actually
		// running, so it cannot carry authority across a restart, and a reboot
		// discards the enrollment along with the workspace it protected.
		nonce:  rand.Text(),
		volume: volume{spec: config.Volumes[0], models: len(config.Models)},
	}

	// Everything sshd needs except a key to accept. Failing here is a refusal to
	// boot, which is the only place a broken SSH policy can still be refused:
	// once an enrollment has been claimed it cannot be handed back.
	if err := box.prepare(); err != nil {
		return fmt.Errorf("ssh: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	listener, err := net.Listen("tcp", variant.APIAddress)
	if err != nil {
		return err
	}
	if err := bootstate.RecordStage(variant.Stage, bootstate.StatusOK, time.Since(start), "API listening"); err != nil {
		listener.Close()
		return err
	}

	server := &http.Server{
		Handler:           box.handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdown); err != nil {
			log.Printf("shutdown failed: %v", err)
		}
	}()

	log.Printf("sandbox %s serving boot %s, awaiting enrollment", box.domain, box.nonce)
	if err := server.Serve(listener); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// measuredConfig reads the config tinfoil-boot verified against the hash on the
// kernel command line. The one volume is the workspace, and its first overlay
// names the toolchain pack the shell runs from.
func measuredConfig() (*runtimeconfig.Config, error) {
	data, err := os.ReadFile(bootstate.ConfigPath)
	if err != nil {
		return nil, err
	}
	config, err := runtimeconfig.Decode(data, false)
	if err != nil {
		return nil, err
	}
	if len(config.Volumes) != 1 || len(config.Volumes[0].Overlays) == 0 {
		return nil, errors.New("config must declare one workspace volume with a toolchain overlay")
	}
	return config, nil
}

func externalDomain() (string, error) {
	data, err := os.ReadFile(bootstate.ExternalConfigPath)
	if err != nil {
		return "", err
	}
	external, err := shimconfig.DecodeExternal(data)
	if err != nil {
		return "", err
	}
	if external.Env["DOMAIN"] == "" {
		return "", errors.New("DOMAIN is not set in the external config")
	}
	return external.Env["DOMAIN"], nil
}

// handler serves the exact paths the shim's allowlist names.
func (s *sandbox) handler() http.Handler {
	mux := http.NewServeMux()
	// Open by necessity: a permit is bound to this nonce, so orchestrator has
	// to read the nonce before a permit can exist. It is an identifier, not a
	// secret -- holding it grants nothing without the orchestrator's key.
	mux.HandleFunc("GET /healthz", s.health)
	// The one call a permit authorizes, and the only one it ever will.
	mux.HandleFunc("POST /enroll", s.enroll)
	return mux
}

// health reports the facts a caller needs before it can hold any credential
// here: the nonce a permit must be bound to, whether this boot's permit has
// already been spent, and the host key the shell will present. None is a secret,
// and an owner who finds a boot it did not enroll knows to stop talking to it.
func (s *sandbox) health(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	enrolled, listening := s.owner != "", s.listening
	s.mu.Unlock()
	reply(w, http.StatusOK, map[string]any{
		"domain":   s.domain,
		"nonce":    s.nonce,
		"enrolled": enrolled,
		"ssh": map[string]any{
			"port":      sshPort,
			"user":      loginUser,
			"host-key":  s.fingerprint,
			"listening": listening,
		},
	})
}

// enroll spends this boot's permit on naming an owner. The permit is verified
// before the body is read, so an unauthenticated caller learns nothing; the
// claim is then what makes it single-use, because it refuses a sandbox that
// already has an owner and no permit is ever read after one does.
func (s *sandbox) enroll(w http.ResponseWriter, r *http.Request) {
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		reply(w, http.StatusUnauthorized, failure{"missing permit"})
		return
	}
	if err := s.check(token); err != nil {
		log.Printf("permit refused: %v", err)
		reply(w, http.StatusForbidden, failure{"permit refused"})
		return
	}
	var body struct {
		Key    string `json:"key"`
		Volume string `json:"volume"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, maxEnrollBytes)).Decode(&body); err != nil {
		reply(w, http.StatusBadRequest, failure{"enrollment is not a JSON object naming a key"})
		return
	}
	volumeKey, err := workspaceKey(body.Volume)
	if err != nil {
		log.Printf("enrollment refused: %v", err)
		reply(w, http.StatusBadRequest, failure{"volume is not base64 for a 64-byte workspace key"})
		return
	}
	defer clear(volumeKey)
	line, err := authorizedKey(body.Key)
	if err != nil {
		log.Printf("enrollment refused: %v", err)
		reply(w, http.StatusBadRequest, failure{"key is not one SSH public key"})
		return
	}
	s.enrolling.Lock()
	defer s.enrolling.Unlock()
	if s.ownerKey() != "" {
		// The permit verified, so this is a valid permit arriving after the one
		// that spent it: a replay, or a second holder of the same permit.
		log.Printf("enrollment refused: an owner is already enrolled for this boot")
		reply(w, http.StatusConflict, failure{"sandbox is already enrolled"})
		return
	}
	if err := s.open(volumeKey, line); err != nil {
		log.Printf("workspace refused the key: %v", err)
		reply(w, http.StatusForbidden, failure{"workspace key refused"})
		return
	}
	if err := os.Mkdir(home, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		log.Printf("workspace provisioning failed: %v", err)
		reply(w, http.StatusInternalServerError, failure{"workspace could not be provisioned"})
		return
	}
	if err := s.claim(line); err != nil {
		log.Printf("enrollment refused: %v", err)
		reply(w, http.StatusConflict, failure{"sandbox is already enrolled"})
		return
	}
	// The workspace is already this owner's, so a door that failed to open is
	// reported rather than refused -- /healthz says whether sshd is listening.
	if err := s.seal(line); err != nil {
		log.Printf("ssh seal failed: %v", err)
	}
	log.Printf("sandbox %s enrolled an owner for boot %s", s.domain, s.nonce)
	w.WriteHeader(http.StatusNoContent)
}

func workspaceKey(encoded string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return nil, err
	}
	if len(key) != volumeKeyBytes {
		clear(key)
		return nil, fmt.Errorf("workspace key is %d bytes, want %d", len(key), volumeKeyBytes)
	}
	return key, nil
}

// open spends the workspace key on the volume and, in the same step, seals the
// boot to the owner's key. Sealing to that key rather than to a constant is
// what lets a later client read the report and see which key the box was
// opened for, instead of only that it was opened. The unlocked volume is then
// the store nix and the shell run from: /workspace is bound at /nix so the
// pack's merged store appears at the one path nix's own scripts hardcode.
func (s *sandbox) open(key []byte, owner string) error {
	seal := sha512.Sum384([]byte(owner))
	if err := s.volume.open(key, seal[:]); err != nil {
		return err
	}
	if err := unix.Mount(workspace, nixRoot, "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
		return fmt.Errorf("binding %s at %s: %w", workspace, nixRoot, err)
	}
	if err := os.MkdirAll(profiles, 0o755); err != nil {
		return err
	}
	pack := filepath.Join(bootstate.PrivateModelsDir, s.volume.spec.Overlays[0].Model, packProfile)
	if err := os.Symlink(pack, profile); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	return nil
}

// prepare mints the host key and renders sshd's configuration. The host key is
// generated here rather than baked into the image so it is as short-lived as the
// boot and as unique as the nonce: a sandbox cannot be impersonated by a party
// holding the image. `sshd -t` then parses what was written, so the policy this
// program depends on is known good before any of it matters.
func (s *sandbox) prepare() error {
	for _, directory := range []string{sshRun, privilegeSeparationDir} {
		if err := os.MkdirAll(directory, 0o755); err != nil {
			return err
		}
	}
	if err := command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "", "-f", hostKey); err != nil {
		return fmt.Errorf("host key: %w", err)
	}
	policy := fmt.Sprintf(sshdPolicy, sshPort, hostKey, authorized, loginUser, profile+"/bin:"+imagePath)
	if err := os.WriteFile(sshdConfig, []byte(policy), 0o444); err != nil {
		return err
	}
	if err := command(sshd, "-t", "-f", sshdConfig); err != nil {
		return fmt.Errorf("policy is not one sshd accepts: %w", err)
	}
	fingerprint, err := digest(hostKey + ".pub")
	if err != nil {
		return err
	}
	s.fingerprint = fingerprint
	log.Printf("ssh host key %s ready on port %d", fingerprint, sshPort)
	return nil
}

// seal writes the one credential sshd will ever accept and starts it. The file
// is created O_EXCL and read-only, so the single call that reaches here cannot
// be joined by a second: an owner's own session cannot add a key, and no later
// enrollment exists to try.
func (s *sandbox) seal(line string) error {
	file, err := os.OpenFile(authorized, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o444)
	if err != nil {
		return err
	}
	if _, err := file.WriteString(line); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	// -e keeps sshd's log in the enclave's console alongside this program's,
	// which is the only place either is readable. The death signal closes the
	// door with the process that opened it.
	daemon := exec.Command(sshd, "-D", "-e", "-f", sshdConfig)
	daemon.Stdout, daemon.Stderr = os.Stderr, os.Stderr
	daemon.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM}
	if err := daemon.Start(); err != nil {
		return err
	}
	s.mu.Lock()
	s.listening = true
	s.mu.Unlock()
	if err := awaitListening(); err != nil {
		return err
	}
	if err := os.Remove(hostKey); err != nil {
		return err
	}
	go flush()
	go func() {
		err := daemon.Wait()
		s.mu.Lock()
		s.listening = false
		s.mu.Unlock()
		// Nothing restarts it: the sealed key is spent.
		log.Printf("sshd exited: %v", err)
	}()
	log.Printf("ssh sealed to the enrolled key, listening on port %d as %s", sshPort, loginUser)
	return nil
}

func flush() {
	for range time.Tick(syncInterval) {
		syscall.Sync()
	}
}

func awaitListening() error {
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(sshPort))
	deadline := time.Now().Add(sshdStartTimeout)
	for {
		connection, err := net.DialTimeout("tcp", address, time.Second)
		if err == nil {
			return connection.Close()
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("sshd did not listen on %d within %s: %w", sshPort, sshdStartTimeout, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func authorizedKey(line string) (string, error) {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return "", errors.New("line is not a type and a key")
	}
	if strings.HasSuffix(fields[0], certificateSuffix) {
		return "", errors.New("line names a certificate, not a key")
	}
	blob, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil {
		return "", err
	}
	if len(blob) < 4 || len(blob) < 4+int(binary.BigEndian.Uint32(blob)) {
		return "", errors.New("key is not an SSH public key blob")
	}
	if named := string(blob[4 : 4+binary.BigEndian.Uint32(blob)]); named != fields[0] {
		return "", fmt.Errorf("key is a %s, not the %s the line names", named, fields[0])
	}
	return fields[0] + " " + fields[1] + "\n", nil
}

// digest is the SHA256 fingerprint of a public key file, in the form ssh-keygen
// prints and a client compares against.
func digest(path string) (string, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	fields := strings.Fields(string(content))
	if len(fields) < 2 {
		return "", fmt.Errorf("%s is not a public key", path)
	}
	blob, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(blob)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:]), nil
}

// command runs one of OpenSSH's own tools and keeps its complaint in the error,
// since a failure here is a boot that should not continue.
func command(name string, args ...string) error {
	output, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w: %s", name, err, strings.TrimSpace(string(output)))
	}
	return nil
}

// claim names the owner, once. Every later caller is refused -- including the
// holder of the permit that won, which is what stops a permit being replayed.
func (s *sandbox) claim(owner string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.owner != "" {
		return errors.New("an owner is already enrolled for this boot")
	}
	s.owner = owner
	return nil
}

func (s *sandbox) ownerKey() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.owner
}

// check verifies one JWS against one key: ES256 over the signing input, then the
// claims that tie it to this boot of this sandbox. The signature is checked
// first, so no claim is ever read from an unsigned token.
func (s *sandbox) check(token string) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return errors.New("token is not a JWS")
	}
	var header struct {
		Algorithm string `json:"alg"`
	}
	if err := decode(parts[0], &header); err != nil {
		return fmt.Errorf("token header: %w", err)
	}
	if header.Algorithm != "ES256" {
		return fmt.Errorf("token algorithm is %q, not ES256", header.Algorithm)
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return fmt.Errorf("token signature: %w", err)
	}
	if len(signature) != 2*coordinate {
		return fmt.Errorf("token signature is %d bytes, want %d", len(signature), 2*coordinate)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(s.permit,
		digest[:],
		new(big.Int).SetBytes(signature[:coordinate]),
		new(big.Int).SetBytes(signature[coordinate:]),
	) {
		return errors.New("signature does not match the key this check trusts")
	}
	var claims struct {
		Issuer   string          `json:"iss"`
		Subject  string          `json:"sub"`
		Audience json.RawMessage `json:"aud"`
		Expires  int64           `json:"exp"`
	}
	if err := decode(parts[1], &claims); err != nil {
		return fmt.Errorf("token claims: %w", err)
	}
	switch {
	case claims.Issuer != permitIssuer:
		return fmt.Errorf("token issuer is %q, not %q", claims.Issuer, permitIssuer)
	case claims.Subject != s.domain:
		return fmt.Errorf("token names %q, not this sandbox", claims.Subject)
	case claims.Expires == 0:
		return errors.New("token does not expire")
	case time.Now().After(time.Unix(claims.Expires, 0)):
		return errors.New("token has expired")
	case !slices.Contains(audiences(claims.Audience), s.nonce):
		return errors.New("token is bound to another boot")
	}
	return nil
}

// publicKey reads a P-256 verifying key as base64 SPKI DER.
func publicKey(encoded string) (*ecdsa.PublicKey, error) {
	der, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, errors.New("key is not P-256")
	}
	return key, nil
}

// audiences reads aud either way a JWT may carry it: one string, or a list.
func audiences(raw json.RawMessage) []string {
	var many []string
	if err := json.Unmarshal(raw, &many); err == nil {
		return many
	}
	var one string
	if err := json.Unmarshal(raw, &one); err == nil {
		return []string{one}
	}
	return nil
}

func decode(segment string, into any) error {
	raw, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, into)
}

type failure struct {
	Error string `json:"error"`
}

func reply(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		log.Printf("response failed: %v", err)
	}
}
