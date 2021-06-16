package tracee

import (
	"testing"
)

func Benchmark_processLostEvents(b *testing.B) {
	t := Tracee{}
	for i := 0; i < b.N; i++ {
		t.incrementLost(uint64(i))
	}
}
