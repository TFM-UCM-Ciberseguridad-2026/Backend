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
        result, err := tx.Run(ctx, "MATCH (v:Vulnerability) WHERE v.cwe IS NOT NULL RETURN v.cwe LIMIT 1", nil)
        if err != nil {
            return nil, err
        }
        if result.Next(ctx) {
            return result.Record().Values[0], nil
        }
        return nil, nil
    })
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println(res)
}
