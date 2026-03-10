// Debug zone reachability
const ZONE_REACH = {
  'dmz': ['dmz', 'prod-web', 'cloud-prod', 'corp'],
  'internet': ['dmz'],
  'prod-web': ['prod-web', 'prod-app', 'dmz', 'corp', 'cloud-prod'],
  'prod-app': ['prod-app', 'prod-db', 'prod-web', 'restricted', 'corp'],
  'prod-db': ['prod-db', 'prod-app', 'restricted'],
  'dev-web': ['dev-web', 'dev-app', 'corp', 'staging'],
  'dev-app': ['dev-app', 'dev-db', 'dev-web', 'corp'],
  'dev-db': ['dev-db', 'dev-app'],
  'staging': ['staging', 'prod-web', 'dev-web', 'dev-app'],
  'corp': ['corp', 'corp-wifi', 'prod-web', 'prod-app', 'dev-web', 'dev-app', 'mgmt'],
  'corp-wifi': ['corp-wifi', 'corp'],
  'restricted': ['restricted', 'prod-db', 'prod-app', 'pci', 'hipaa', 'mgmt', 'security'],
  'pci': ['pci', 'restricted'],
  'hipaa': ['hipaa', 'restricted'],
  'mgmt': ['mgmt', 'security', 'corp', 'restricted'],
  'security': ['security', 'mgmt', 'restricted'],
  'cloud-prod': ['cloud-prod', 'prod-web', 'prod-app', 'cloud-dev'],
  'cloud-dev': ['cloud-dev', 'dev-web', 'dev-app', 'cloud-prod'],
  'dr': ['dr', 'restricted', 'prod-db'],
  'internal': ['internal', 'restricted', 'dmz', 'prod-web', 'prod-app', 'prod-db', 'corp'],
  'airgap': ['airgap', 'restricted']
};

// Test zones used in the test
const testZones = ['dmz', 'prod-web', 'prod-app', 'prod-db', 'corp', 'restricted', 'mgmt', 'dev-web', 'cloud-prod'];

console.log('Testing zone reachability for path building:\n');

// Can we go from dmz (internet-facing) to restricted (where DC might be)?
console.log('Path from DMZ to restricted:');
console.log('  dmz -> prod-web:', ZONE_REACH['dmz'].includes('prod-web'));
console.log('  prod-web -> prod-app:', ZONE_REACH['prod-web'].includes('prod-app'));
console.log('  prod-app -> restricted:', ZONE_REACH['prod-app'].includes('restricted'));
console.log('');

// Check if corp can reach restricted (via mgmt)
console.log('Path from corp to restricted:');
console.log('  corp -> mgmt:', ZONE_REACH['corp'].includes('mgmt'));
console.log('  mgmt -> restricted:', ZONE_REACH['mgmt'].includes('restricted'));
console.log('');

// Check what zones can reach restricted
console.log('Zones that can directly reach restricted:');
for (const [zone, reachable] of Object.entries(ZONE_REACH)) {
  if (reachable.includes('restricted')) {
    console.log(`  ${zone}`);
  }
}
console.log('');

// Check what zones dmz can reach
console.log('Zones reachable from DMZ:', ZONE_REACH['dmz']);
console.log('');

// Check what zones corp can reach
console.log('Zones reachable from corp:', ZONE_REACH['corp']);
