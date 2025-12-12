package common

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand"
	"os/exec"
	"runtime"
	"strconv"
	"bytes"
)

func RunCommand(command string) string {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("powershell", "-Command", command)
	} else {
		cmd = exec.Command("sh", "-c", command)
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Sprintf("Error: %v, Output: %s", err, string(output))
	}
	return string(output)
}

func Atoi(s string) int {
	i, _ := strconv.Atoi(s)
	return i
}

func RandomInt(min, max int) int {
	if max <= min {
		return min
	}
	return rand.Intn(max-min) + min
}

func DecodeAndExtract(encodedParam string) ([]string, error) {
	decoded, err := base64.StdEncoding.DecodeString(encodedParam)
	if err != nil {
		return nil, fmt.Errorf("error decoding base64 string: %w", err)
	}

	dec := json.NewDecoder(bytes.NewReader(decoded))

	// First token: must be '{' (object) or '[' (array)
	tok, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("error reading JSON: %w", err)
	}

	switch d := tok.(type) {
	case json.Delim:
		switch d {
		case '{':
			// Object: read key/value pairs in source order
			out := make([]string, 0, 8)
			for dec.More() {
				// read key
				k, err := dec.Token()
				if err != nil {
					return nil, fmt.Errorf("error reading object key: %w", err)
				}
				if _, ok := k.(string); !ok {
					return nil, fmt.Errorf("object key is not a string: %v", k)
				}

				// read value as string (strict, like map[string]string)
				var v string
				if err := dec.Decode(&v); err != nil {
					return nil, fmt.Errorf("object value is not a string: %w", err)
				}
				out = append(out, v)
			}
			// consume closing '}'
			if tok, err = dec.Token(); err != nil || tok != json.Delim('}') {
				return nil, fmt.Errorf("malformed JSON object")
			}
			return out, nil

		case '[':
			// Array: decode directly (order preserved naturally)
			var arr []string
			if err := dec.Decode(&arr); err != nil {
				return nil, fmt.Errorf("error parsing JSON array of strings: %w", err)
			}
			return arr, nil
		}
	}

	return nil, fmt.Errorf("unsupported JSON: expected object or array")
}
