package neo4j

import (
	"context"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

type relationshipRepo struct {
	driver neo4j.DriverWithContext
}

func (r *relationshipRepo) LinkProjectToEndpoint(ctx context.Context, projectID int64, endpointID int64) error {
	query := `
		MATCH (p:Project {id: $projectID})
		MATCH (e:Endpoint {id: $endpointID})
		MERGE (p)-[:HAS_ENDPOINT]->(e)
	`
	params := map[string]any{
		"projectID":  projectID,
		"endpointID": endpointID,
	}
	return executeWriteHelper(ctx, r.driver, query, params)
}

func (r *relationshipRepo) LinkEndpointToHardware(ctx context.Context, endpointID int64, hardwareID int64) error {
	query := `
		MATCH (e:Endpoint {id: $endpointID})
		MATCH (h:Hardware {id: $hardwareID})
		MERGE (e)-[:HAS_HARDWARE]->(h)
	`
	params := map[string]any{
		"endpointID": endpointID,
		"hardwareID": hardwareID,
	}
	return executeWriteHelper(ctx, r.driver, query, params)
}

func (r *relationshipRepo) LinkEndpointToNetwork(ctx context.Context, endpointID int64, networkID int64) error {
	query := `
		MATCH (e:Endpoint {id: $endpointID})
		MATCH (n:Network {id: $networkID})
		MERGE (e)-[:CONNECTED_TO]->(n)
	`
	params := map[string]any{
		"endpointID": endpointID,
		"networkID":  networkID,
	}
	return executeWriteHelper(ctx, r.driver, query, params)
}

func (r *relationshipRepo) LinkEndpointToInstallation(ctx context.Context, endpointID int64, installationID string) error {
	query := `
		MATCH (e:Endpoint {id: $endpointID})
		MATCH (si:SoftwareInstallation {id: $installationID})
		MERGE (e)-[:HAS_INSTALLATION]->(si)
	`
	params := map[string]any{
		"endpointID":     endpointID,
		"installationID": installationID,
	}
	return executeWriteHelper(ctx, r.driver, query, params)
}

func (r *relationshipRepo) LinkInstallationToSoftware(ctx context.Context, installationID string, softwareID int64) error {
	query := `
		MATCH (si:SoftwareInstallation {id: $installationID})
		MATCH (s:Software {id: $softwareID})
		MERGE (si)-[:INSTANCE_OF]->(s)
	`
	params := map[string]any{
		"installationID": installationID,
		"softwareID":     softwareID,
	}
	return executeWriteHelper(ctx, r.driver, query, params)
}

func (r *relationshipRepo) LinkInstallationToFinding(ctx context.Context, installationID string, findingID int64) error {
	query := `
		MATCH (si:SoftwareInstallation {id: $installationID})
		MATCH (f:Finding {id: $findingID})
		MERGE (si)-[:HAS_FINDING]->(f)
	`
	params := map[string]any{
		"installationID": installationID,
		"findingID":      findingID,
	}
	return executeWriteHelper(ctx, r.driver, query, params)
}

func (r *relationshipRepo) LinkFindingToVulnerability(ctx context.Context, findingID int64, cveID string) error {
	query := `
		MATCH (f:Finding {id: $findingID})
		MATCH (v:Vulnerability {cve_id: $cveID})
		MERGE (f)-[:OF_VULNERABILITY]->(v)
	`
	params := map[string]any{
		"findingID": findingID,
		"cveID":     cveID,
	}
	return executeWriteHelper(ctx, r.driver, query, params)
}

func (r *relationshipRepo) LinkFindingToExploit(ctx context.Context, findingID int64, exploitID int64) error {
	query := `
		MATCH (f:Finding {id: $findingID})
		MATCH (ex:Exploit {id: $exploitID})
		MERGE (f)-[:HAS_EXPLOIT]->(ex)
	`
	params := map[string]any{
		"findingID": findingID,
		"exploitID": exploitID,
	}
	return executeWriteHelper(ctx, r.driver, query, params)
}

func (r *relationshipRepo) LinkFindingToRemediation(ctx context.Context, findingID int64, remediationID int64) error {
	query := `
		MATCH (f:Finding {id: $findingID})
		MATCH (rem:Remediation {id: $remediationID})
		MERGE (f)-[:HAS_REMEDIATION]->(rem)
	`
	params := map[string]any{
		"findingID":     findingID,
		"remediationID": remediationID,
	}
	return executeWriteHelper(ctx, r.driver, query, params)
}

func (r *relationshipRepo) LinkRemediationToPatch(ctx context.Context, remediationID int64, patchID int64) error {
	query := `
		MATCH (rem:Remediation {id: $remediationID})
		MATCH (p:Patch {id: $patchID})
		MERGE (rem)-[:USES_PATCH]->(p)
	`
	params := map[string]any{
		"remediationID": remediationID,
		"patchID":       patchID,
	}
	return executeWriteHelper(ctx, r.driver, query, params)
}

func (r *relationshipRepo) LinkPatchToVulnerability(ctx context.Context, patchID int64, cveID string) error {
	query := `
		MATCH (p:Patch {id: $patchID})
		MATCH (v:Vulnerability {cve_id: $cveID})
		MERGE (p)-[:FIXES]->(v)
	`
	params := map[string]any{
		"patchID": patchID,
		"cveID":   cveID,
	}
	return executeWriteHelper(ctx, r.driver, query, params)
}
