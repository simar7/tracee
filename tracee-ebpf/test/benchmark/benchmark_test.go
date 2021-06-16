package benchmark

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aquasecurity/tracee/tracee-ebpf/tracee"

	ps "github.com/mitchellh/go-ps"
	"github.com/onsi/gomega/gexec"
	"github.com/stretchr/testify/require"

	"github.com/kelseyhightower/envconfig"
	"github.com/stretchr/testify/assert"
)

const (
	CheckTimeout = time.Second * 2
)

type Config struct {
	TraceeBinaryPath string `required:"true" envconfig:"trc_bin"`
}

func getTraceeBinaryPath(b *testing.B) string {
	var c Config
	err := envconfig.Process("trc", &c)
	require.NoError(b, err)

	if _, err := os.Stat(c.TraceeBinaryPath); os.IsNotExist(err) {
		require.FailNow(b, "failed to find tracee binary", err)
	}
	return c.TraceeBinaryPath
}

// load tracee into memory with args
func loadTracee(b *testing.B, traceeBinPath string, w io.Writer, done chan bool, args ...string) {
	cmd := exec.Command(traceeBinPath, args...)
	//fmt.Println("running: ", cmd.String())

	session, err := gexec.Start(cmd, w, w)
	require.NoError(b, err)
	<-done
	session.Interrupt()
}

// get pid by process name
func getPidByName(b *testing.B, name string) int {
	processes, err := ps.Processes()
	require.NoError(b, err)

	for _, p := range processes {
		if strings.Contains(p.Executable(), name) {
			return p.Pid()
		}
	}
	return -1
}

// wait for tracee buffer to fill or timeout to occur, whichever comes first
func waitForTraceeOutput(gotOutput *bytes.Buffer, now time.Time) {
	for {
		if len(gotOutput.String()) > 0 || (time.Since(now) > CheckTimeout) {
			break
		}
		time.Sleep(time.Millisecond)
	}
}

// small set of actions to trigger a magic write event
func checkMagicwrite(b *testing.B, gotOutput *bytes.Buffer) {
	// create a temp dir for testing
	d, err := ioutil.TempDir("", "Test_MagicWrite-dir-*")
	require.NoError(b, err)

	// cp a file to trigger
	f, err := os.CreateTemp(d, "Test_MagicWrite-file-*")
	require.NoError(b, err)
	defer func() {
		os.Remove(d)
	}()

	f.WriteString(`foo.bar.baz`)
	f.Close()

	cpCmd := exec.Command("cp", f.Name(), filepath.Join(d+filepath.Base(f.Name())+"-new"))
	//fmt.Println("executing: ", cpCmd.String())
	cpCmd.Stdout = os.Stdout
	assert.NoError(b, cpCmd.Run())

	waitForTraceeOutput(gotOutput, time.Now())

	// check tracee output
	assert.Contains(b, gotOutput.String(), `[102 111 111 46 98 97 114 46 98 97 122]`)
}

// execute a ls command
func checkExeccommand(b *testing.B, gotOutput *bytes.Buffer) {
	_, _ = exec.Command("ls").CombinedOutput()

	waitForTraceeOutput(gotOutput, time.Now())

	// check tracee output
	processNames := strings.Split(strings.TrimSpace(gotOutput.String()), "\n")
	for _, pname := range processNames {
		assert.Equal(b, "ls", pname)
	}
}

// only capture new pids after tracee
func checkPidnew(b *testing.B, gotOutput *bytes.Buffer) {
	traceePid := getPidByName(b, "tracee")

	// run a command
	_, _ = exec.Command("ls").CombinedOutput()

	waitForTraceeOutput(gotOutput, time.Now())

	// output should only have events with pids greater (newer) than tracee
	pids := strings.Split(strings.TrimSpace(gotOutput.String()), "\n")
	for _, p := range pids {
		pid, _ := strconv.Atoi(p)
		assert.Greater(b, pid, traceePid)
	}
}

// only capture uids of 0 that are run by comm ls
func checkUidzero(b *testing.B, gotOutput *bytes.Buffer) {
	_, _ = exec.Command("ls").CombinedOutput()

	waitForTraceeOutput(gotOutput, time.Now())

	// check output length
	require.NotEmpty(b, gotOutput.String())

	// output should only have events with uids of 0
	uids := strings.Split(strings.TrimSpace(gotOutput.String()), "\n")
	for _, u := range uids {
		uid, _ := strconv.Atoi(u)
		require.Zero(b, uid)
	}
}

// only capture pids of 1
func checkPidOne(b *testing.B, gotOutput *bytes.Buffer) {
	_, _ = exec.Command("init", "q").CombinedOutput()

	waitForTraceeOutput(gotOutput, time.Now())

	// check output length
	require.NotEmpty(b, gotOutput.String())

	// output should only have events with pids of 1
	pids := strings.Split(strings.TrimSpace(gotOutput.String()), "\n")
	for _, p := range pids {
		pid, _ := strconv.Atoi(p)
		require.Equal(b, 1, pid)
	}
}

// check that execve event is called
func checkExecve(b *testing.B, gotOutput *bytes.Buffer) {
	_, _ = exec.Command("ls").CombinedOutput()

	waitForTraceeOutput(gotOutput, time.Now())

	// check output length
	require.NotEmpty(b, gotOutput.String())

	// output should only have events with event name of execve
	eventNames := strings.Split(strings.TrimSpace(gotOutput.String()), "\n")
	for _, en := range eventNames {
		if len(en) > 0 {
			require.Equal(b, "execve", en)
		}
	}
}

// check for filesystem set when ls is invoked
func checkSetFs(b *testing.B, gotOutput *bytes.Buffer) {
	_, _ = exec.Command("ls").CombinedOutput()

	waitForTraceeOutput(gotOutput, time.Now())

	// check output length
	require.NotEmpty(b, gotOutput.String())

	expectedSyscalls := getAllSyscallsInSet("fs")

	// output should only have events with events in the set of filesystem syscalls
	eventNames := strings.Split(strings.TrimSpace(gotOutput.String()), "\n")
	for _, en := range eventNames {
		require.Contains(b, expectedSyscalls, en)
	}
}

func getAllSyscallsInSet(set string) []string {
	var syscallsInSet []string
	for _, v := range tracee.EventsIDToEvent {
		for _, c := range v.Sets {
			if c == set {
				syscallsInSet = append(syscallsInSet, v.Name)
			}
		}
	}
	return syscallsInSet
}

func removeOldTraceeCruft() {
	_ = os.Remove("/tmp/tracee/out/tracee.pid")
}

func waitUntilTracee(traceeDir string) {
	for {
		if _, err := os.Stat(filepath.Join(traceeDir, "out", "tracee.pid")); !os.IsNotExist(err) {
			break
		}
		time.Sleep(time.Millisecond)
	}
}

func BenchmarkTracee_Events(b *testing.B) {
	var testCases = []struct {
		name       string
		args       []string
		eventFunc  func(*testing.B, *bytes.Buffer)
		goTemplate string
	}{
		{
			name:       "do_a_file_write",
			args:       []string{"--trace", "event=magic_write"},
			eventFunc:  checkMagicwrite,
			goTemplate: "{{ .Args }}\n",
		},
		{
			name:       "execute a command",
			args:       []string{"--trace", "comm=ls"},
			eventFunc:  checkExeccommand,
			goTemplate: "{{ .ProcessName }}\n",
		},
		{
			name:       "trace uid 0 with comm ls",
			args:       []string{"--trace", "uid=0", "--trace", "comm=ls"},
			eventFunc:  checkUidzero,
			goTemplate: "{{ .UserID }}\n",
		},
		{
			name:       "trace pid 1",
			args:       []string{"--trace", "pid=1"},
			eventFunc:  checkPidOne,
			goTemplate: "{{ .ProcessID }}\n",
		},
		{
			name:       "trace only execve events from comm ls",
			args:       []string{"--trace", "event=execve"},
			eventFunc:  checkExecve,
			goTemplate: "{{ .EventName }}\n",
		},
		//{
		//	name:       "trace filesystem events from comm ls",
		//	args:       []string{"--trace", "s=fs", "--trace", "comm=ls"},
		//	eventFunc:  checkSetFs,
		//	goTemplate: "{{ .EventName }}\n",
		//},
		// TODO: Add --capture tests
	}

	bin := getTraceeBinaryPath(b)
	for _, tc := range testCases {
		bc := tc

		b.Run(bc.name, func(b *testing.B) {
			b.ReportAllocs()

			f, _ := ioutil.TempFile("", fmt.Sprintf("%s-*", tc.name))
			_, _ = f.WriteString(tc.goTemplate)
			defer func() {
				_ = os.Remove(f.Name())
			}()

			tc.args = append(tc.args, "--output", fmt.Sprintf("gotemplate=%s", f.Name()))

			var gotOutput bytes.Buffer
			done := make(chan bool, 1)

			b.ResetTimer()
			for n := 0; n < b.N; n++ {
				removeOldTraceeCruft()                              // setup
				go loadTracee(b, bin, &gotOutput, done, tc.args...) // start
				waitUntilTracee("/tmp/tracee")                      // wait
				tc.eventFunc(b, &gotOutput)                         // execute
				done <- true                                        // kill tracee
			}

		})
	}
}
