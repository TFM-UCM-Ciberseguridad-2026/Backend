const fs = require('fs');
const data = JSON.parse(fs.readFileSync('graph.json', 'utf8'));
const vulns = data.nodes.filter(n => (n.labels||[]).includes('Vulnerability') || n.primaryLabel === 'Vulnerability');
let ttpsSet = new Set();
vulns.forEach(v => {
    if (v.properties.ttps && Array.isArray(v.properties.ttps)) {
        v.properties.ttps.forEach(t => ttpsSet.add(t));
    }
});
console.log('Unique TTPs count:', ttpsSet.size);
console.log('TTPs:', Array.from(ttpsSet));
