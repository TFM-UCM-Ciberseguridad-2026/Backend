package main

import (
	"encoding/json"
	"fmt"
	"net/http"
)

type Object struct {
	Type               string `json:"type"`
	Name               string `json:"name"`
	SourceRef          string `json:"source_ref"`
	TargetRef          string `json:"target_ref"`
	ExternalReferences []struct {
		SourceName string `json:"source_name"`
		ExternalID string `json:"external_id"`
	} `json:"external_references"`
}

type Stix struct {
	Objects []Object `json:"objects"`
}

func main() {
	resp, err := http.Get("https://raw.githubusercontent.com/mitre/cti/master/capec/2.1/stix-capec.json")
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	var s Stix
	json.NewDecoder(resp.Body).Decode(&s)

	sources := make(map[string]int)
	for _, o := range s.Objects {
		if o.Type == "attack-pattern" {
			for _, ref := range o.ExternalReferences {
				sources[ref.SourceName]++
			}
		}
	}
	for k, v := range sources {
		fmt.Printf("Source %s: %d\n", k, v)
	}
}
