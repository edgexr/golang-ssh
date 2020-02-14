package ssh

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// these servers need to be modified when running to have working SSH servers
var testServers []string
var key string
var timeout time.Duration
var vers string

// this data is subject to change; it needs to be populated with 2 working servers
// that can reach each other via the key provided
func initTestData() {
	testServers = []string{"35.199.188.102", "35.199.188.102", "37.50.200.27"} // twice thru the first svr and then to another
	key = os.Getenv("HOME") + "/.mobiledgex/id_rsa_mex"
	timeout = time.Second * 10
	vers = "SSH-2.0-mobiledgex-ssh-client-1.0"
}

type Result struct {
	expected string
	out      string
	err      error
}

func TestNativeClient(t *testing.T) {
	initTestData()
	auth := Auth{Keys: []string{key}}
	client, err := NewNativeClient("ubuntu", vers, testServers[0], 22, &auth, timeout, nil)
	//client.AddHop(testServers[1])
	require.Nil(t, err, "NewNativeClient")
	// run 3 tests concurrently 4 times
	numThread := 5
	results := make(chan Result, numThread)

	for hopTest := 0; hopTest < len(testServers); hopTest++ {
		if hopTest != 0 {
			err := client.AddHop(testServers[hopTest], 22)
			require.Nil(t, err, "addhop")
		}
		for i := 0; i < numThread; i++ {
			go func() {
				expected := fmt.Sprintf("testing: %d", i)
				out, err := client.Output("echo " + expected)
				results <- Result{expected, out, err}
			}()
		}
		for i := 0; i < numThread; i++ {
			result := <-results
			require.Nil(t, result.err, "result")
			require.Equal(t, result.expected, result.out, result.expected)
		}
	}

	// now add bad hop and check for error
	client.AddHop("10.10.10.10", 22)
	_, err = client.Output("hello")
	require.Contains(t, err.Error(), "ssh client timeout")

}
