const fs = require('fs');
const data = JSON.parse(fs.readFileSync('graph.json', 'utf8'));

let ttpCount = 0;
data.nodes.forEach(n => {
    if ((n.labels && n.labels.includes('TTP')) || n.primaryLabel === 'TTP') {
        ttpCount++;
    }
});

console.log(`Total TTPs in graph.json: ${ttpCount}`);
console.log(`Total Nodes: ${data.nodes.length}`);

if (ttpCount > 0) {
    const ttp = data.nodes.find(n => n.labels && n.labels.includes('TTP'));
    console.log(JSON.stringify(ttp, null, 2));
}
