package jq_test

import (
	"."
	"os"
)

func ExampleDump_Inverse() {
	jq.Dump(os.Stdout, "select(. != 0) | 1 / .", 1, 0, 2, 4)
	// Output:
	// 1
	// 0.5
	// 0.25
}
