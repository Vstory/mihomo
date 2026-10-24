package constant

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtraSafePathFunc(t *testing.T) {
	defer func(f func(string) bool) { ExtraSafePathFunc = f }(ExtraSafePathFunc)

	p := &path{homeDir: "/data/files/mihomo/geodata"}
	sandbox := "/data/files/mihomo/processing/providers/"

	ExtraSafePathFunc = nil
	assert.False(t, p.IsSafePath(sandbox+"abc"))

	ExtraSafePathFunc = func(path string) bool { return strings.HasPrefix(path, sandbox) }
	assert.True(t, p.IsSafePath(sandbox+"abc"))
	assert.True(t, p.IsSafePath("/data/files/mihomo/geodata/GeoIP.dat"))
	assert.False(t, p.IsSafePath("/data/files/mihomo/processing/other"))
	assert.False(t, p.IsSafePath("/etc/passwd"))
}
