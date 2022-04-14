package internal

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/springswen/go-zero/core/stat"
)

func TestWithMetrics(t *testing.T) {
	metrics := stat.NewMetrics("foo")
	opt := WithMetrics(metrics)
	var options rpcServerOptions
	opt(&options)
	assert.Equal(t, metrics, options.metrics)
}
