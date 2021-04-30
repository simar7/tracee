package main

import (
	"bufio"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	tracee "github.com/aquasecurity/tracee/tracee-ebpf/tracee/external"
	"github.com/aquasecurity/tracee/tracee-rules/types"
)

var errHelp = errors.New("user has requested help text")

type inputFormat uint8

const (
	invalidInputFormat inputFormat = iota
	jsonInputFormat
	gobInputFormat
)

type inputOptions struct {
	traceeInputFile     *os.File
	traceeInputFormat   inputFormat
	profilerInputFile   *os.File
	profilerInputFormat inputFormat
}

func setupProfilerInputSource(opts *inputOptions) (chan types.Event, error) {
	if opts.profilerInputFormat == jsonInputFormat {
		return setupTraceeJSONInputSource(opts.profilerInputFile)
	}

	return nil, fmt.Errorf("unsupported profiler file format: %s", opts.profilerInputFormat)
}

func setupTraceeInputSource(opts *inputOptions) (chan types.Event, error) {
	if opts.traceeInputFormat == jsonInputFormat {
		return setupTraceeJSONInputSource(opts.traceeInputFile)
	}

	if opts.traceeInputFormat == gobInputFormat {
		return setupTraceeGobInputSource(opts) // TODO: Update to take io.Reader
	}

	return nil, errors.New("invalid or missing input format. See --input-tracee help for details")
}

func setupTraceeGobInputSource(opts *inputOptions) (chan types.Event, error) {
	dec := gob.NewDecoder(opts.traceeInputFile)
	res := make(chan types.Event)
	go func() {
		for {
			var event tracee.Event
			err := dec.Decode(&event)
			if err != nil {
				if err == io.EOF {
					break
				} else {
					log.Printf("Error while decoding event: %v", err)
				}
			} else {
				res <- event
			}
		}
		opts.traceeInputFile.Close()
		close(res)
	}()
	return res, nil
}

func setupTraceeJSONInputSource(inputFile io.Reader) (chan types.Event, error) {
	res := make(chan types.Event)
	scanner := bufio.NewScanner(inputFile)
	go func() {
		for scanner.Scan() {
			event := scanner.Bytes()
			var e tracee.Event
			err := json.Unmarshal(event, &e)
			if err != nil {
				log.Printf("invalid json in %s: %v", string(event), err)
			}
			res <- e
		}
		close(res)
	}()
	return res, nil
}

func parseTraceeInputOptions(inputOpts []string, fileType string) (*inputOptions, error) {
	var (
		inputSourceOptions inputOptions
		err                error
	)

	if len(inputOpts) == 0 {
		return nil, errors.New("no tracee input options specified")
	}

	for i := range inputOpts {
		if inputOpts[i] == "help" {
			return nil, errHelp
		}

		kv := strings.Split(inputOpts[i], ":")
		if len(kv) != 2 {
			return nil, fmt.Errorf("invalid input-tracee option: %s", inputOpts[i])
		}
		if kv[0] == "" || kv[1] == "" {
			return nil, fmt.Errorf("empty key or value passed: key: >%s< value: >%s<", kv[0], kv[1])
		}
		if kv[0] == "file" {
			err = parseTraceeInputFile(&inputSourceOptions, kv[1], fileType)
			if err != nil {
				return nil, err
			}
		} else if kv[0] == "format" {
			err = parseTraceeInputFormat(&inputSourceOptions, kv[1], fileType)
			if err != nil {
				return nil, err
			}
		} else {
			return nil, fmt.Errorf("invalid input-tracee option key: %s", kv[0])
		}
	}
	return &inputSourceOptions, nil
}

func parseTraceeInputFile(option *inputOptions, fileOpt string, fileType string) error {

	if fileOpt == "stdin" {
		switch fileType {
		case "tracee":
			option.traceeInputFile = os.Stdin
		case "profiler":
			option.profilerInputFile = os.Stdin
		}
		return nil
	}
	_, err := os.Stat(fileOpt)
	if err != nil {
		return fmt.Errorf("invalid %s input file: %s", fileType, fileOpt)
	}
	f, err := os.Open(fileOpt)
	if err != nil {
		return fmt.Errorf("invalid file: %s", fileOpt)
	}
	switch fileType {
	case "tracee":
		option.traceeInputFile = f
	case "profiler":
		option.profilerInputFile = f
	}
	return nil
}

func parseTraceeInputFormat(option *inputOptions, formatString string, fileType string) error {
	formatString = strings.ToUpper(formatString)
	var fileFormat inputFormat

	if formatString == "JSON" {
		fileFormat = jsonInputFormat
	} else if formatString == "GOB" {
		fileFormat = gobInputFormat
	} else {
		fileFormat = invalidInputFormat
		return fmt.Errorf("invalid tracee input format specified: %s", formatString)
	}

	switch fileType {
	case "tracee":
		option.traceeInputFormat = fileFormat
	case "profiler":
		option.profilerInputFormat = fileFormat
	}
	return nil
}

func printHelp() {
	traceeInputHelp := `
tracee-rules --input-tracee <key:value>,<key:value> --input-tracee <key:value>

Specify various key value pairs for input options tracee-ebpf. The following key options are available:

'file'   - Input file source. You can specify a relative or absolute path. You may also specify 'stdin' for standard input.
'format' - Input format. Options currently include 'JSON' and 'GOB'. Both can be specified as output formats from tracee-ebpf.

Examples:

'tracee-rules --input-tracee file:./events.json --input-tracee format:json'
'tracee-rules --input-tracee file:./events.gob --input-tracee format:gob'
'sudo tracee-ebpf -o format:gob | tracee-rules --input-tracee file:stdin --input-tracee format:gob'
`

	fmt.Println(traceeInputHelp)
}
