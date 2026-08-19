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

	query := `
		MATCH (n)
		WHERE NOT (n:ThreatActor OR n:TTP OR n:IPAddress)
		OPTIONAL MATCH (n)-[:MAPS_TO|EXPLOITS_VIA_TTP]->(t1:TTP) WHERE "Vulnerability" IN labels(n)
		WITH n, collect(DISTINCT t1) AS t1List
		OPTIONAL MATCH (n)-[:HAS_WEAKNESS|HAS_CWE]->(:CWE)-[:MAPS_TO]->(t2:TTP) WHERE "Vulnerability" IN labels(n)
		WITH n, t1List, collect(DISTINCT t2) AS t2List
		OPTIONAL MATCH (n)-[:HAS_WEAKNESS|HAS_CWE]->(:CWE)<-[:MAPS_TO_CWE]-(:CAPEC)-[:MAPS_TO_TTP]->(t3:TTP) WHERE "Vulnerability" IN labels(n)
		WITH n, t1List, t2List, collect(DISTINCT t3) AS t3List
		WITH n, t1List + t2List + t3List AS combinedTTPs
		UNWIND case when size(combinedTTPs) > 0 then combinedTTPs else [null] end AS t
		WITH n, collect(DISTINCT case when t is not null and t.ttp_id is not null then {ttp_id: t.ttp_id, name: coalesce(t.name, ''), tactic: coalesce(t.tactic, ''), description: coalesce(t.description, '')} else null end) AS inferredTTPs
		WITH n, [x IN inferredTTPs WHERE x IS NOT NULL] AS cleanTTPs
		WITH collect({
			id: elementId(n), 
			labels: labels(n), 
			properties: n {.*, ttps: cleanTTPs}, 
			hasVuln: COUNT { (n)-[:OF_VULNERABILITY]->(:Vulnerability) } > 0
		}) AS nodes
		OPTIONAL MATCH (s)-[rel]->(targetNode)
		WHERE NOT (startNode(rel):ThreatActor OR startNode(rel):TTP OR startNode(rel):IPAddress OR endNode(rel):ThreatActor OR endNode(rel):TTP OR endNode(rel):IPAddress)
		WITH nodes, collect({
			id: elementId(rel),
			type: type(rel),
			source: elementId(startNode(rel)),
			target: elementId(endNode(rel)),
			properties: properties(rel)
		}) AS cleanRels
		OPTIONAL MATCH (n2)-[:HAS_IP]->(ip:IPAddress) WHERE n2:Endpoint OR n2:Container
		WITH nodes, cleanRels, collect(case when n2 is null or ip is null then null else {node_id: elementId(n2), ip: coalesce(ip.ip, ''), vlan_id: coalesce(ip.vlan_id, 0)} end) AS ipMaps
		RETURN nodes, cleanRels AS relationships, [] AS ttp_mappings, [i in ipMaps WHERE i IS NOT NULL] AS ip_mappings
	`

	res, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
		result, err := tx.Run(ctx, query, nil)
		if err != nil {
			return nil, err
		}
		if result.Next(ctx) {
			return result.Record().AsMap(), nil
		}
		return nil, nil
	})
	if err != nil {
		log.Fatal(err)
	}

	recordMap := res.(map[string]interface{})
	nodesRaw := recordMap["nodes"]
	fmt.Printf("Type of nodesRaw: %T\n", nodesRaw)
	if slice, ok := nodesRaw.([]interface{}); ok {
		fmt.Printf("Parsed as []interface{}, length: %d\n", len(slice))
		if len(slice) > 0 {
			fmt.Printf("Type of first element: %T\n", slice[0])
		}
	} else {
		fmt.Println("Failed to parse as []interface{}")
	}
}
