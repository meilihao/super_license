package license

import (
	"encoding/json"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/assert"
)

func TestAuthV1Check(t *testing.T) {
	c := WithModel()

	j, err := json.Marshal(c)
	assert.Nil(t, err)
	spew.Dump(j)
}
