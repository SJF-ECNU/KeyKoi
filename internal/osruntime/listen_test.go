package osruntime

import "testing"

func TestListenLoopbackTCP(t *testing.T) {
	for _, addr := range []string{":0", "0.0.0.0:0", "[::]:0"} {
		ln, err := ListenLoopbackTCP(addr)
		if err == nil {
			_ = ln.Close()
			t.Errorf("unexpectedly accepted %q", addr)
		}
	}
	ln, err := ListenLoopbackTCP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_ = ln.Close()
}
