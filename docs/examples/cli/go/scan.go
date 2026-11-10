package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"time"
)

type Verdict struct {
	Valid      bool   `json:"valid"`
	Status     string `json:"status"`
	Violations []struct {
		RuleID  string `json:"rule_id"`
		Message string `json:"message"`
	} `json:"violations"`
}

// QueldaScan scans one file with the quelda CLI. Only exit code 0 means valid.
func QueldaScan(path string) Verdict {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "quelda", "scan", path).Output()
	var v Verdict
	if ctx.Err() != nil {
		v.Status = "TIMEOUT"
	} else if json.Unmarshal(out, &v) != nil {
		v.Status = fmt.Sprintf("NO VERDICT (%v)", err)
	}
	v.Valid = err == nil // a non-zero exit, a timeout or a failed start is an error
	return v
}

func main() {
	v := QueldaScan(os.Args[1])
	fmt.Printf("valid=%t status=%s\n", v.Valid, v.Status)
}
