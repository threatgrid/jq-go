package jq_test

import (
	"."
	"encoding/json"
	"testing"
)

func TestApply(t *testing.T) {
	expectReturn(t, mustApply(t, `.`, 1), 1)
	expectReturn(t, mustApply(t, `.`, 1), 1)
	expectReturn(t, mustApply(t, `.`, 1, 2, 3), 1, 2, 3)
	expectReturn(t, mustApply(t, `. | select(. != 0) | 1 / .`, 0, 1, 2, 3), 1.0/1, 1.0/2, 1.0/3)
}

func expectReturn(t *testing.T, seq []string, expect ...interface{}) {
	if len(seq) != len(expect) {
		t.Fatalf("expected: %v, got: %v", formatJson(expect), formatJson(seq))
	}
	for i, sj := range seq {
		sx := formatJson(expect[i])
		if sj != sx {
			t.Errorf("item %v expected: %v, got: %v", i, sx, sj)
		}
	}
}

func mustApply(t *testing.T, proc string, input ...interface{}) []string {
	seq, err := jq.Apply(proc, input...)
	if err != nil {
		t.Logf("while applying %#v to:", proc)
		for i, inp := range input {
			t.Logf("- %v: %#v", i, inp)
		}
		t.Fatal(err)
	}
	ret := make([]string, len(seq))
	for i, s := range seq {
		ret[i] = string(s)
	}
	return ret
}

func mustCompile(t *testing.T, proc string) {
	vm, err := jq.Compile(proc)
	defer vm.Close()
	if err != nil {
		t.Logf(`while compiling: %#v`, proc)
		t.Fatal(err)
	}
}

func formatJson(v interface{}) string {
	p, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(p)
}
