[private]
default:
	@just --list

[private]
simulate datafile:
	#!/usr/bin/env bash
	while read line; do
		echo "$line"
		sleep 0.$RANDOM
	done < {{datafile}} | go run main.go 'in.time'

# simulate a streaming cat | transform
test-pipe:
	just simulate testdata/temperatures.csv
	just simulate testdata/events.jsonl

# transform examples
test-transform:
	DEBUG=2 go run main.go testdata/events.jsonl 'std.extVar("in").time'
	DEBUG=1 go run main.go testdata/temperatures.csv '$number(in.celsius)'

# rerun transform examples on file changes
watch-test:
	watchexec -w . -r -c -- just test-transform