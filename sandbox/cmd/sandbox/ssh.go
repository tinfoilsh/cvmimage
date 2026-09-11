package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	imagePath              = "/usr/local/bin:/usr/bin:/bin"
	sshdStartTimeout       = 30 * time.Second
	syncInterval           = 5 * time.Second
	sshPort                = 22
	sshRun                 = "/run/tinfoil/sandbox"
	hostKey                = sshRun + "/host_key"
	sshdConfig             = sshRun + "/sshd_config"
	authorized             = sshRun + "/authorized_keys"
	privilegeSeparationDir = "/run/sshd"
	sshd                   = "/usr/sbin/sshd"
	certificateSuffix      = "-cert-v01@openssh.com"
	loginUser              = "root"
)

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

// seal installs the enrolled credential once and starts SSH on loopback.
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

func command(name string, args ...string) error {
	output, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w: %s", name, err, strings.TrimSpace(string(output)))
	}
	return nil
}
