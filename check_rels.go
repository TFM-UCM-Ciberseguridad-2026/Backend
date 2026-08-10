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

    res, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
        result, err := tx.Run(ctx, "MATCH (ta:ThreatActor)-[r]->(t:TTP) RETURN type(r) AS relType, COUNT(r) AS count", nil)
        if err != nil {
            return nil, err
        }
        var rels []string
        for result.Next(ctx) {
            rels = append(rels, fmt.Sprintf("%s: %d", result.Record().Values[0].(string), result.Record().Values[1].(int64)))
        }
        return rels, nil
    })
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println(res)
}
