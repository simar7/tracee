package tracee

import (
	"testing"

	"github.com/aquasecurity/tracee/tracee-ebpf/tracee/external"
	"github.com/stretchr/testify/assert"

	"github.com/stretchr/testify/require"
)

func Test_prepareEventForPrint(t *testing.T) {
	tr := Tracee{
		eventsToTrace: map[int32]bool{ReadEventID: true},
		config: Config{
			Output: &OutputConfig{Format: "foobar"},
		},
	}

	in := make(chan RawEvent, 1)
	in <- RawEvent{Ctx: context{Pid: 123, EventID: ReadEventID}}
	out, errCh, err := tr.prepareEventForPrint(nil, in)
	require.NoError(t, err)
	require.Empty(t, errCh)
	assert.Equal(t, external.Event{
		EventID:   0,
		EventName: "read",
		ProcessID: 123,
		Args:      []external.Argument{},
	}, <-out)
}
