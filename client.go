// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package ssh is a helper for working with ssh in go.  The client implementation
// is a modified version of `docker/machine/libmachine/ssh/client.go` and only
// uses golang's native ssh client. It has also been improved to resize the tty
// accordingly.  The key functions are meant to be used by either client or server
// and will generate/store keys if not found.
package ssh

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/docker/docker/pkg/term"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
)

// ExitError is a conveniance wrapper for (crypto/ssh).ExitError type.
type ExitError struct {
	Err      error
	ExitCode int
}

// Error implements error interface.
func (err *ExitError) Error() string {
	return err.Err.Error()
}

// Cause implements errors.Causer interface.
func (err *ExitError) Cause() error {
	return err.Err
}

func wrapError(err error) error {
	switch err := err.(type) {
	case *ssh.ExitError:
		e, s := &ExitError{Err: err, ExitCode: -1}, strings.TrimSpace(err.Error())
		// Best-effort attempt to parse exit code from os/exec error string,
		// like "Process exited with status 127".
		if i := strings.LastIndex(s, " "); i != -1 {
			if n, err := strconv.Atoi(s[i+1:]); err == nil {
				e.ExitCode = n
			}
		}
		return e
	default:
		return err
	}
}

// Client is a relic interface that both native and external client matched
type Client interface {
	// Output returns the output of the command run on the host.
	Output(command string) (string, error)

	// OutputWithTimeout returns the output of the command run on the host.
	// call will timeout within a set timeout
	OutputWithTimeout(command string, Timeout time.Duration) (string, error)

	// Shell requests a shell from the remote. If an arg is passed, it tries to
	// exec them on the server.
	Shell(sin io.Reader, sout, serr io.Writer, args ...string) error

	// Start starts the specified command without waiting for it to finish. You
	// have to call the Wait function for that.
	//
	// The first two io.ReadCloser are the standard output and the standard
	// error of the executing command respectively. The returned error follows
	// the same logic as in the exec.Cmd.Start function.
	Start(command string) (io.ReadCloser, io.ReadCloser, io.WriteCloser, error)

	// Wait waits for the command started by the Start function to exit. The
	// returned error follows the same logic as in the exec.Cmd.Wait function.
	Wait() error
	// AddHop adds a new host to the end of the list and returns a new client.
	// The original client is unchanged.
	AddHop(host string, port int) (Client, error)

	// Connects to host and caches connection details for
	// same connection to be reused
	StartPersistentConn(timeout time.Duration) error

	// Stops cached sessions and close the connection
	StopPersistentConn()
}

type HostDetail struct {
	HostName     string
	Port         int
	ClientConfig *ssh.ClientConfig
}

// HopDetails stores open sessions and connections which need
// to be tracked so they can be properly cleaned up
type HopDetails struct {
}

// SessionInfo contains artifacts from the session that need to be cleaned up
type SessionInfo struct {
	openClients []*ssh.Client // list of clients along the path
	openConns   []net.Conn    // list of clients along the path
	openSession *ssh.Session  // current open session
	mux         sync.Mutex
}

// NativeClient is the structure for native client use
type NativeClient struct {
	HostDetails         []HostDetail // list of Hosts
	ClientVersion       string       // ClientVersion is the version string to send to the server when identifying
	persistentConn      *ssh.Client  // cache client
	persistentConnMux   sync.Mutex
	SessionInfo         *SessionInfo
	DefaultClientConfig *ssh.ClientConfig
}

// Auth contains auth info
type Auth struct {
	Passwords []string // Passwords is a slice of passwords to submit to the server
	Keys      []string // Keys is a slice of filenames of keys to try
	RawKeys   [][]byte // RawKeys is a slice of private keys to try
}

// Config is used to create new client.
type Config struct {
	User    string              // username to connect as, required
	Host    string              // hostname to connect to, required
	Version string              // ssh client version, "SSH-2.0-Go" by default
	Port    int                 // port to connect to, 22 by default
	Auth    *Auth               // authentication methods to use
	Timeout time.Duration       // connect timeout, 30s by default
	HostKey ssh.HostKeyCallback // callback for verifying server keys, ssh.InsecureIgnoreHostKey by default
}

func (cfg *Config) version() string {
	if cfg.Version != "" {
		return cfg.Version
	}
	return "SSH-2.0-Go"
}

func (cfg *Config) port() int {
	if cfg.Port != 0 {
		return cfg.Port
	}
	return 22
}

func (cfg *Config) timeout() time.Duration {
	if cfg.Timeout != 0 {
		return cfg.Timeout
	}
	return 30 * time.Second
}

func (cfg *Config) hostKey() ssh.HostKeyCallback {
	if cfg.HostKey != nil {
		return cfg.HostKey
	}
	return ssh.InsecureIgnoreHostKey()
}

// saves SSH client so it can be closed later
func (s *SessionInfo) saveClient(sshClient *ssh.Client) {
	s.mux.Lock()
	defer s.mux.Unlock()
	s.openClients = append(s.openClients, sshClient)
}

// saves SSH connection so it can be closed later
func (s *SessionInfo) saveConn(conn net.Conn) {
	s.mux.Lock()
	defer s.mux.Unlock()
	s.openConns = append(s.openConns, conn)
}

func (s *SessionInfo) CloseAll() {
	s.mux.Lock()
	defer s.mux.Unlock()
	for _, cl := range s.openClients {
		cl.Close()
	}
	for _, con := range s.openConns {
		con.Close()
	}
	s.openClients = nil
	s.openConns = nil
	if s.openSession != nil {
		s.openSession.Close()
	}
	s.openSession = nil

}

// Copy copies the NativeClient with empty SessionInfo
func (c *NativeClient) Copy() *NativeClient {
	// copy the existing host details
	hds := make([]HostDetail, len(c.HostDetails))
	copy(hds, c.HostDetails)

	var sessionInfo SessionInfo
	var copyClient = NativeClient{
		HostDetails:         hds,
		ClientVersion:       c.ClientVersion,
		DefaultClientConfig: c.DefaultClientConfig,
		SessionInfo:         &sessionInfo,
	}
	return &copyClient
}

// AddHopWithConfig adds a new host to the end of the list and returns a new client using the provided config
// The original client is unchanged
func (c *NativeClient) AddHopWithConfig(host string, port int, config *ssh.ClientConfig) (Client, error) {
	newClient := c.Copy()
	var hostDetail = HostDetail{HostName: host, Port: port, ClientConfig: config}
	newClient.HostDetails = append(newClient.HostDetails, hostDetail)
	return newClient, nil
}

// AddHop adds a new host to the end of the list and returns a new client using the same config
// The original client is unchanged
func (c *NativeClient) AddHop(host string, port int) (Client, error) {
	return c.AddHopWithConfig(host, port, c.DefaultClientConfig)
}

// RemoveLastHop returns a new client which is a copy of the original with the last hop removed
func (c *NativeClient) RemoveLastHop() (interface{}, error) {
	if len(c.HostDetails) < 1 {
		return nil, fmt.Errorf("no hops to remove")
	}
	newClient := c.Copy()
	newClient.HostDetails = newClient.HostDetails[:len(newClient.HostDetails)-1]
	return newClient, nil
}

// NewNativeClient creates a new Client using the golang ssh library
func NewNativeClient(user, clientVersion string, host string, port int, hostAuth *Auth, timeout time.Duration, hostKeyCallback ssh.HostKeyCallback) (Client, error) {
	if clientVersion == "" {
		clientVersion = "SSH-2.0-Go"
	}
	defaultConfig, err := NewNativeConfig(user, clientVersion, hostAuth, timeout, hostKeyCallback)
	if err != nil {
		return nil, fmt.Errorf("Error getting host config for native Go SSH: %s", err)
	}

	var hostDetail = HostDetail{HostName: host, Port: port, ClientConfig: &defaultConfig}
	hd := []HostDetail{hostDetail}
	var sessionInfo SessionInfo
	var nc = NativeClient{
		HostDetails:         hd,
		ClientVersion:       clientVersion,
		DefaultClientConfig: &defaultConfig,
		SessionInfo:         &sessionInfo,
	}
	return &nc, nil
}

// NewNativeConfig returns a golang ssh client config struct for use by the NativeClient
func NewNativeConfig(user, clientVersion string, auth *Auth, timeout time.Duration, hostKeyCallback ssh.HostKeyCallback) (ssh.ClientConfig, error) {
	var (
		authMethods []ssh.AuthMethod
	)

	if auth != nil {
		rawKeys := auth.RawKeys
		for _, k := range auth.Keys {
			key, err := ioutil.ReadFile(k)
			if err != nil {
				return ssh.ClientConfig{}, err
			}

			rawKeys = append(rawKeys, key)
		}

		for _, key := range rawKeys {
			privateKey, err := ssh.ParsePrivateKey(key)
			if err != nil {
				return ssh.ClientConfig{}, err
			}

			authMethods = append(authMethods, ssh.PublicKeys(privateKey))
		}

		for _, p := range auth.Passwords {
			authMethods = append(authMethods, ssh.Password(p))
		}
	}

	if hostKeyCallback == nil {
		hostKeyCallback = ssh.InsecureIgnoreHostKey()
	}

	return ssh.ClientConfig{
		User:            user,
		Auth:            authMethods,
		ClientVersion:   clientVersion,
		HostKeyCallback: hostKeyCallback,
		Timeout:         timeout,
	}, nil
}

func (nclient *NativeClient) Connect(timeout time.Duration) (*ssh.Client, *SessionInfo, error) {

	var sshClient *ssh.Client
	var destAddr string
	var err error
	var conn net.Conn
	var configWithTimeout ssh.ClientConfig

	var sessionInfo SessionInfo
	if len(nclient.HostDetails) == 0 {
		return nil, &sessionInfo, fmt.Errorf("no remote hosts")
	}

	for _, h := range nclient.HostDetails {
		destAddr = fmt.Sprintf("%s:%d", h.HostName, h.Port)
		if sshClient == nil {
			//first host
			// make a copy of a client config to use differetnt timeout
			configWithTimeout = *h.ClientConfig
			configWithTimeout.Timeout = timeout
			sshClient, err = ssh.Dial("tcp", destAddr, &configWithTimeout)
			if err != nil {
				sessionInfo.CloseAll()
				return nil, nil, fmt.Errorf("ssh dial fail to %s - %v", destAddr, err)
			}
			sessionInfo.saveClient(sshClient)
			conn, err = sshClient.Dial("tcp", destAddr)
			if err != nil {
				sessionInfo.CloseAll()
				return nil, nil, fmt.Errorf("ssh client dial fail to %s - %v", destAddr, err)
			}
			sessionInfo.saveConn(conn)
		} else {
			// ssh.Client dial does not use a timeout.  In order to make subsequent hops time out, use a separate timer
			ch := make(chan string, 1)
			go func() {
				conn, err = sshClient.Dial("tcp", destAddr)
				if err != nil {
					ch <- fmt.Sprintf("ssh client dial fail to %s - %v", destAddr, err)
				}
				ch <- ""
			}()
			select {
			case result := <-ch:
				if result != "" {
					if conn != nil {
						conn.Close()
					}
					sessionInfo.CloseAll()
					return nil, nil, fmt.Errorf(result)
				}
			case <-time.After(timeout):
				if conn != nil {
					conn.Close()
				}
				sessionInfo.CloseAll()
				return nil, nil, fmt.Errorf("ssh client timeout to %s", destAddr)
			}
			sshconn, chans, reqs, err := ssh.NewClientConn(conn, h.HostName, h.ClientConfig)
			if err != nil {
				return nil, &sessionInfo, fmt.Errorf("NewClientConn fail  to %s - %v", destAddr, err)
			}
			sshClient = ssh.NewClient(sshconn, chans, reqs)
			sessionInfo.saveClient(sshClient)
			sessionInfo.saveConn(conn)
		}
	} //for

	return sshClient, &sessionInfo, nil
}

func (nc *NativeClient) Session(timeout time.Duration) (*ssh.Session, *SessionInfo, error) {
	if nc.persistentConn != nil {
		session, err := nc.persistentConn.NewSession()
		if err != nil {
			// handle persistent connection loss by trying to reconnect
			err = nc.restartPersistentConnection(timeout)
			if err != nil {
				return nil, nil, err
			}
			session, err = nc.persistentConn.NewSession()
			if err != nil {
				// cleanup
				nc.StopPersistentConn()
				return nil, nil, err
			}
		}
		// for the cached connection we don't want to close the session, so return a dummy one
		return session, &SessionInfo{}, nil
	}
	client, sessionInfo, err := nc.Connect(timeout)
	if err != nil {
		return nil, nil, err
	}
	session, err := client.NewSession()
	if err != nil {
		client.Close()
		sessionInfo.CloseAll()
		return nil, nil, err
	}
	return session, sessionInfo, nil
}

func (nc *NativeClient) restartPersistentConnection(timeout time.Duration) error {
	// Need to hold the lock while trying to reconnect
	nc.persistentConnMux.Lock()
	defer nc.persistentConnMux.Unlock()
	nc.stopPersistentConn()
	return nc.startPersistentConn(timeout)
}

func (nc *NativeClient) saveConnection(client *ssh.Client, sessionInfo *SessionInfo) {
	if client == nil && sessionInfo == nil {
		return
	}
	// clear any existing sessions
	nc.stopPersistentConn()
	nc.persistentConn = client
	nc.SessionInfo = sessionInfo
}

func (nc *NativeClient) startPersistentConn(timeout time.Duration) error {
	client, sessionInfo, err := nc.Connect(timeout)
	if err != nil {
		return err
	}
	nc.saveConnection(client, sessionInfo)
	return nil
}

func (nc *NativeClient) stopPersistentConn() {
	if nc.SessionInfo != nil {
		nc.SessionInfo.CloseAll()
		nc.SessionInfo = nil
	}
	if nc.persistentConn != nil {
		nc.persistentConn.Close()
		nc.persistentConn = nil
	}
}

func (nc *NativeClient) StartPersistentConn(timeout time.Duration) error {
	nc.persistentConnMux.Lock()
	defer nc.persistentConnMux.Unlock()
	return nc.startPersistentConn(timeout)
}

func (nc *NativeClient) StopPersistentConn() {
	nc.persistentConnMux.Lock()
	defer nc.persistentConnMux.Unlock()
	nc.stopPersistentConn()
}

// Output returns the output of the command run on the remote host.
func (client *NativeClient) Output(command string) (string, error) {
	return client.OutputWithTimeout(command, client.DefaultClientConfig.Timeout)
}

// Output returns the output of the command run on the remote host.
func (client *NativeClient) OutputWithTimeout(command string, timeout time.Duration) (string, error) {
	session, sessionInfo, err := client.Session(timeout)
	// even on failure, intermediate hop connections must close
	if err != nil {
		return "", err
	}
	defer sessionInfo.CloseAll()
	defer session.Close()
	output, err := session.CombinedOutput(command)
	return string(bytes.TrimSpace(output)), wrapError(err)
}

// Output returns the output of the command run on the remote host as well as a pty.
func (client *NativeClient) OutputWithPty(command string) (string, error) {
	session, sessionInfo, err := client.Session(client.DefaultClientConfig.Timeout)
	if err != nil {
		return "", nil
	}
	defer sessionInfo.CloseAll()
	defer session.Close()

	fd := int(os.Stdin.Fd())

	termWidth, termHeight, err := terminal.GetSize(fd)
	if err != nil {
		return "", err
	}

	modes := ssh.TerminalModes{
		ssh.ECHO:          0,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}

	// request tty -- fixes error with hosts that use
	// "Defaults requiretty" in /etc/sudoers - I'm looking at you RedHat
	if err := session.RequestPty("xterm", termHeight, termWidth, modes); err != nil {
		return "", err
	}

	output, err := session.CombinedOutput(command)

	return string(bytes.TrimSpace(output)), wrapError(err)
}

// Start starts the specified command without waiting for it to finish. You
// have to call the Wait function for that.
func (client *NativeClient) Start(command string) (sout io.ReadCloser, serr io.ReadCloser, sin io.WriteCloser, reterr error) {
	session, sessionInfo, err := client.Session(client.DefaultClientConfig.Timeout)
	if err != nil {
		return nil, nil, nil, err
	}
	defer func() {
		if reterr != nil {
			sessionInfo.CloseAll()
			session.Close()
		}
	}()

	stdout, err := session.StdoutPipe()
	if err != nil {
		return nil, nil, nil, err
	}
	stderr, err := session.StderrPipe()
	if err != nil {
		return nil, nil, nil, err
	}
	stdin, err := session.StdinPipe()
	if err != nil {
		return nil, nil, nil, err
	}
	if err := session.Start(command); err != nil {
		return nil, nil, nil, err
	}
	sessionInfo.openSession = session
	client.saveConnection(nil, sessionInfo)

	return ioutil.NopCloser(stdout), ioutil.NopCloser(stderr), stdin, nil
}

// Wait waits for the command started by the Start function to exit. The
// returned error follows the same logic as in the exec.Cmd.Wait function.
func (client *NativeClient) Wait() error {
	err := client.SessionInfo.openSession.Wait()
	_ = client.SessionInfo.openSession.Close()
	client.SessionInfo.CloseAll()

	return err
}

// Shell requests a shell from the remote. If an arg is passed, it tries to
// exec them on the server.
func (client *NativeClient) Shell(sin io.Reader, sout, serr io.Writer, args ...string) error {
	var (
		termWidth, termHeight = 80, 24
	)
	session, sessionInfo, err := client.Session(client.DefaultClientConfig.Timeout)
	// even on failure, intermediate hop connections must close
	if err != nil {
		return err
	}
	defer sessionInfo.CloseAll()
	defer session.Close()

	session.Stdout = sout
	session.Stderr = serr
	session.Stdin = sin

	modes := ssh.TerminalModes{
		ssh.ECHO: 1,
	}

	fd := os.Stdin.Fd()

	if term.IsTerminal(fd) {
		oldState, err := term.MakeRaw(fd)
		if err != nil {
			return err
		}

		defer term.RestoreTerminal(fd, oldState)

		winsize, err := term.GetWinsize(fd)
		if err == nil {
			termWidth = int(winsize.Width)
			termHeight = int(winsize.Height)
		}
	}

	if err := session.RequestPty("xterm", termHeight, termWidth, modes); err != nil {
		return err
	}

	if len(args) == 0 {
		if err := session.Shell(); err != nil {
			return err
		}

		// monitor for sigwinch
		go monWinCh(session, os.Stdout.Fd())

		session.Wait()
	} else {
		session.Run(strings.Join(args, " "))
	}

	return nil
}

// termSize gets the current window size and returns it in a window-change friendly
// format.
func termSize(fd uintptr) []byte {
	size := make([]byte, 16)

	winsize, err := term.GetWinsize(fd)
	if err != nil {
		binary.BigEndian.PutUint32(size, uint32(80))
		binary.BigEndian.PutUint32(size[4:], uint32(24))
		return size
	}

	binary.BigEndian.PutUint32(size, uint32(winsize.Width))
	binary.BigEndian.PutUint32(size[4:], uint32(winsize.Height))

	return size
}
