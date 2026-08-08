
package main

import (
    "context"
    "fmt"
    "log"
    "github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

func main() {
    ctx := context.Background()
    driver, err := neo4j.NewDriverWithContext("bolt://localhost:7687", neo4j.BasicAuth("neo4j", "password", ""))
    if err != nil {
        log.Fatal(err)
    }
    defer driver.Close(ctx)

    session := driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
    defer session.Close(ctx)

    query := "MATCH (p:Project)-[:HAS_ENDPOINT]->(e:Endpoint)-[:HAS_INSTALLATION]->(si:SoftwareInstallation)-[:HAS_FINDING]->(f:Finding)-[:OF_VULNERABILITY]->(v:Vulnerability) MATCH (c:CAPEC)-[:MAPS_TO_CWE]->(w:CWE) WHERE (v)-[:HAS_CWE]->(w) OR w.cwe_id IN v.cwe MATCH (c)-[:MAPS_TO_TTP]->(ttp:TTP) WITH collect(DISTINCT ttp) AS infraTTPs UNWIND infraTTPs AS infraTTP MATCH (ta:ThreatActor)-[:USES]->(infraTTP) WITH ta, infraTTPs, collect(DISTINCT infraTTP) AS matchedTTPs RETURN ta.name, size(matchedTTPs)"

    res, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
        result, err := tx.Run(ctx, query, nil)
        if err != nil {
            return nil, err
        }
        var lines []string
        for result.Next(ctx) {
            lines = append(lines, fmt.Sprintf("%v: %v", result.Record().Values[0], result.Record().Values[1]))
        }
        return lines, nil
    })
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println(res)
}

