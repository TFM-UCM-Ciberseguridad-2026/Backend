const fs = require('fs');
const data = JSON.parse(fs.readFileSync('graph.json', 'utf8'));
const vulns = data.nodes.filter(n => (n.labels||[]).includes('Vulnerability') || n.primaryLabel === 'Vulnerability');
vulns.forEach(v => console.log(v.properties.cve_id, Object.keys(v.properties)));
