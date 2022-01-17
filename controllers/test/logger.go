package controllers_test

import (
	"encoding/json"
	"fmt"

	. "github.com/onsi/ginkgo/v2"
)

func LogManifest(manifestToLog interface{}) {
	if manifestToLog != nil {
		pretty, _ := json.MarshalIndent(manifestToLog, "", "\t")
		fmt.Fprintf(GinkgoWriter, "Manifest:\n%s\n", pretty)
	}
}
