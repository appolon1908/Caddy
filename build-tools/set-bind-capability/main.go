package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"syscall"
)

const (
	target = "/usr/bin/caddy"
	self   = "/usr/bin/codestra-set-bind-capability"
)

func main() {
	// Linux vfs_cap_data revision 2, effective flag, with only capability 10
	// (CAP_NET_BIND_SERVICE) in the permitted set.
	value := make([]byte, 20)
	binary.LittleEndian.PutUint32(value[0:4], 0x02000001)
	binary.LittleEndian.PutUint32(value[4:8], 1<<10)
	if err := syscall.Setxattr(target, "security.capability", value, 0); err != nil {
		fmt.Fprintf(os.Stderr, "set capability: %v\n", err)
		os.Exit(1)
	}
	if err := os.Remove(self); err != nil {
		fmt.Fprintf(os.Stderr, "remove capability helper: %v\n", err)
		os.Exit(1)
	}
}
