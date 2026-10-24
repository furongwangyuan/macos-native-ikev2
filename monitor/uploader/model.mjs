// Candidate contract adapter only. Not imported by the running dashboard.
import {normalizeSnapshot as normalizeDaily} from './daily_model_v2.mjs';
export * from './daily_model_v2.mjs';

const bad = () => { throw new TypeError('invalid_fleet_contract'); };
const keys = (value, expected) => {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return bad();
  const got = Object.keys(value).sort();
  if (got.length !== expected.length || got.some((key, i) => key !== [...expected].sort()[i])) return bad();
};
const rootKeys = ['schema_version','registry_revision','observed_at','collector','server','coverage','devices'];
const deviceKeys = ['id','name','state','registration_state','connected_since','rate_window_ms',
  'upload_bps','download_bps','upload_bytes','download_bytes','totals_since','counter_epoch','counter_state'];

export function normalizeSnapshot(input) {
  keys(input, rootKeys);
  keys(input.collector, ['state','started_at']);
  keys(input.server, ['state']);
  keys(input.coverage, ['kind','totals_scope','timezone','day','day_started_at','observed_since','limitation']);
  if (input.schema_version !== 3 || !Array.isArray(input.devices) || input.devices.length > 16) return bad();
  const revision = input.registry_revision;
  if (revision !== null && (!Number.isSafeInteger(revision) || revision < 1)) return bad();
  const states = new Map(), names = new Map();
  const legacy = {...input, schema_version: 2, devices: input.devices.map(row => {
    keys(row, deviceKeys);
    if (!['enabled','disabled','revoked'].includes(row.registration_state)) return bad();
    // Python's 80-character contract counts Unicode code points. The frozen
    // daily v2 model uses UTF-16 length, so validate names here before adapting.
    if (typeof row.name !== 'string' || [...row.name].length < 1 || [...row.name].length > 80 ||
        /[\u0000-\u001f\u007f]/u.test(row.name)) return bad();
    states.set(row.id, row.registration_state);
    names.set(row.id, row.name);
    const {registration_state, ...daily} = row;
    return {...daily, name: 'device'};
  })};
  delete legacy.registry_revision;
  const parsed = normalizeDaily(legacy);
  if (revision === null && (parsed.devices.length || parsed.collector.state !== 'unavailable')) return bad();
  // Keep daily accounting unknown distinct from a measured zero. The backend
  // contract enforces this; independently reject corrupted exported metadata.
  for (const d of parsed.devices) {
    if (d.counter_state === 'unavailable' &&
        [d.upload_bytes,d.download_bytes,d.totals_since,d.counter_epoch].some(v => v !== null)) return bad();
    if (d.counter_state === 'partial') {
      if (!new RegExp(`^daily_[A-Za-z0-9_-]{1,48}_${parsed.coverage.day.replaceAll('-','')}$`).test(d.counter_epoch)) return bad();
      if (Date.parse(d.totals_since) < Date.parse(parsed.coverage.observed_since)) return bad();
    }
  }
  const date = value => value === null ? null : new Date(value).toISOString();
  return {...parsed, schema_version: 3, registry_revision: revision,
    observed_at: date(parsed.observed_at),
    collector: {...parsed.collector, started_at: date(parsed.collector.started_at)},
    coverage: {...parsed.coverage, day_started_at: date(parsed.coverage.day_started_at),
      observed_since: date(parsed.coverage.observed_since)},
    devices: parsed.devices.map(d => ({...d, name: names.get(d.id), registration_state: states.get(d.id),
      connected_since: date(d.connected_since), totals_since: date(d.totals_since)}))};
}
