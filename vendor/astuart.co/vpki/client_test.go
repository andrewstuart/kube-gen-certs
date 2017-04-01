package vpki

import "testing"

func TestInterface(t *testing.T) {
	var cli interface{}
	cli = &Client{}
	if _, ok := cli.(Certifier); !ok {
		t.Fatalf("Client does not satisfy Certifier interface")
	}
}

func TestInit(t *testing.T) {
	cli := Client{
		Addr:  "foo.bar.baz",
		Mount: "foo",
		Role:  "bar",
	}
	err := cli.init()
	if err != nil {
		t.Fatalf("Error initializing: %v", err)
	}

	if cli.sw == nil {
		t.Errorf("client secretWriter was not set by init")
	}
}
