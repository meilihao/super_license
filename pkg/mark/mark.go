package mark

import (
	"bytes"
	"os"
)

type Mark struct {
	K string
	V string
	E string // why not get V
}

const (
	MarkCodeMachineid = "machine-id"
)

func WithMachineId() (m *Mark) {
	m = &Mark{
		K: MarkCodeMachineid,
	}

	data, err := os.ReadFile("/etc/machine-id")
	if err != nil {
		m.E = err.Error()

		return
	}

	m.V = string(bytes.TrimSpace(data))

	return
}
