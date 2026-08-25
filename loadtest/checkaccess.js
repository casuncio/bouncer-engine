// k6 gRPC load test for the bouncer-engine authorization service.
//
// Drives the `authz.v1.AuthorizationService/CheckAccess` RPC with a fixed set
// of fixtures (allow + deny cases) across two sequential scenarios:
//   1. baseline — sustained target RPS (default 1000)
//   2. stress  — sustained high RPS (default 10000)
//
// Run with:   k6 run loadtest/checkaccess.js
// Seed first: go run ./loadtest/seed   (or `make loadtest`)
//
// Tunable env vars:
//   BOUNCER_TARGET        — host:port of the engine (default localhost:50051)
//   BOUNCER_BASELINE_RPS  — target rate for the baseline scenario (default 1000)
//   BOUNCER_STRESS_RPS    — target rate for the stress scenario  (default 10000)
//   BOUNCER_SKIP_BASELINE — 'true' to skip the baseline scenario
//   BOUNCER_SKIP_STRESS   — 'true' to skip the stress scenario
import grpc from 'k6/net/grpc';
import { check } from 'k6';
import { SharedArray } from 'k6/data';
import { Trend, Counter } from 'k6/metrics';

// Engine endpoint and per-scenario target rates, overridable via env vars.
const target = __ENV.BOUNCER_TARGET || 'localhost:50051';
const baselineRps = parseInt(__ENV.BOUNCER_BASELINE_RPS || '1000', 10);
const stressRps = parseInt(__ENV.BOUNCER_STRESS_RPS || '10000', 10);
// Allow individual scenarios to be skipped (useful for quick smoke runs).
const skipBaseline = __ENV.BOUNCER_SKIP_BASELINE === 'true';
const skipStress = __ENV.BOUNCER_SKIP_STRESS === 'true';

// Reusable gRPC client. The proto is loaded once at init time so that the
// generated stubs are available to every VU. Connection is established
// lazily inside setup()/checkAccess() (see below).
const client = new grpc.Client();
client.load(['../api'], 'authz.proto');

// Custom metrics reported alongside k6's built-in ones.
//   engine_eval_time_ns — engine-reported evaluation latency (nanoseconds)
//   rpc_errors           — count of non-OK or malformed responses
const engine_eval_time_ns = new Trend('engine_eval_time_ns');
const rpc_errors = new Counter('rpc_errors');

// Fixtures are built once in the init context and shared across all VUs via
// SharedArray (memory-efficient; avoids re-computing per VU). Each fixture
// pairs a CheckAccess request with the expected `allowed` verdict, covering
// both ALLOW paths and implicit/explicit DENY paths.
const fixtures = new SharedArray('fixtures', function () {
  // ALLOW case for the secops policy: SecurityAdmin role + corp CIDR (10/8)
  // + business hours (hour between 8 and 18).
  const secopsAllow = (id, ip, hour) => ({
    principal_id: id,
    principal_attributes: { roles: { values: ['SecurityAdmin'] } },
    resource_type: 'production-db-backup',
    resource_id: '',
    resource_attributes: {},
    action: 'READ',
    environment_attributes: { ip_address: { values: [ip] }, hour: { values: [String(hour)] } },
  });
  // ALLOW case for the dashboard policy: principal with role=admin.
  const dashboardAllow = (id) => ({
    principal_id: id,
    principal_attributes: { role: { values: ['admin'] } },
    resource_type: 'dashboard',
    resource_id: '',
    resource_attributes: {},
    action: 'READ',
    environment_attributes: {},
  });
  // DENY helper for the secops resource — used to exercise implicit denials
  // (wrong role / outside CIDR / after hours) and explicit denials
  // (Contractor role matched by the deny-contractor policy).
  const secopsDeny = (id, roles, ip, hour) => ({
    principal_id: id,
    principal_attributes: { roles: { values: roles } },
    resource_type: 'production-db-backup',
    resource_id: '',
    resource_attributes: {},
    action: 'READ',
    environment_attributes: { ip_address: { values: [ip] }, hour: { values: [String(hour)] } },
  });

  return [
    // --- ALLOW cases (expect: true) ---
    { name: 'allow-secops-a',           expect: true,  request: secopsAllow('usr-1',  '10.4.4.10',    12) },
    { name: 'allow-secops-b',           expect: true,  request: secopsAllow('usr-2',  '10.5.5.20',    14) },
    { name: 'allow-secops-c',           expect: true,  request: secopsAllow('usr-3',  '10.1.1.1',      9) },
    { name: 'allow-secops-d',           expect: true,  request: secopsAllow('usr-4',  '10.0.0.99',    17) },
    { name: 'allow-secops-e',           expect: true,  request: secopsAllow('usr-5',  '10.250.1.7',   10) },
    { name: 'allow-dashboard-a',        expect: true,  request: dashboardAllow('usr-6') },
    { name: 'allow-dashboard-b',        expect: true,  request: dashboardAllow('usr-7') },
    // --- DENY cases (expect: false) ---
    // Implicit: role not in SecurityAdmin — no allow policy matches.
    { name: 'deny-implicit-wrongrole',  expect: false, request: secopsDeny('usr-8',  ['DevOps'],       '10.4.4.10', 12) },
    // Implicit: correct role but IP outside the 10.0.0.0/8 CIDR.
    { name: 'deny-implicit-outofcidr',  expect: false, request: secopsDeny('usr-9',  ['SecurityAdmin'], '192.168.1.5', 12) },
    // Implicit: correct role + CIDR but hour (22) outside the 8–18 window.
    { name: 'deny-implicit-afterhours', expect: false, request: secopsDeny('usr-10', ['SecurityAdmin'], '10.4.4.10', 22) },
    // Explicit: Contractor role is matched by the deny-contractor policy.
    { name: 'deny-explicit-contractor', expect: false, request: secopsDeny('usr-11', ['Contractor'],  '10.4.4.10', 12) },
  ];
});

// Compute the VU pool for a given target RPS. preAllocatedVUs are warmed up
// ahead of time to avoid allocation stalls during ramp-up; maxVUs is the hard
// ceiling k6 may grow to. Both are sized relative to the requested rate and
// floored to sensible minimums.
function vuBudget(rps) {
  return {
    preAllocatedVUs: Math.max(50, Math.ceil(rps / 100)),
    maxVUs: Math.max(200, Math.ceil(rps / 10)),
  };
}

// Build the scenario config dynamically so individual phases can be skipped
// via env vars. The stress scenario is scheduled to start right after the
// baseline scenario finishes (sequential, not concurrent).
const scenarios = {};
const baselineDurationSec = 30 + 60 + 20; // ramp-up + hold + ramp-down
let nextStart = 0; // tracks when the next scenario should begin (seconds)

if (!skipBaseline) {
  scenarios.baseline = {
    executor: 'ramping-arrival-rate', // drive a target RPS regardless of VU count
    exec: 'checkAccess',
    startRate: 0,
    timeUnit: '1s',
    ...vuBudget(baselineRps),
    stages: [
      { duration: '30s', target: baselineRps }, // ramp up
      { duration: '1m',  target: baselineRps }, // hold
      { duration: '20s', target: 0 },           // ramp down
    ],
    startTime: '0s',
  };
  nextStart = baselineDurationSec;
}

if (!skipStress) {
  scenarios.stress = {
    executor: 'ramping-arrival-rate',
    exec: 'checkAccess',
    startRate: 0,
    timeUnit: '1s',
    ...vuBudget(stressRps),
    stages: [
      { duration: '1m',  target: stressRps },
      { duration: '2m',  target: stressRps },
      { duration: '30s', target: 0 },
    ],
    startTime: `${nextStart}s`, // begins once baseline completes
  };
}

// k6 options: scenarios, percentile stats shown in the summary, and SLO
// thresholds. If any threshold is crossed the run exits non-zero — useful
// for CI gating.
export const options = {
  scenarios,
  summaryTrendStats: ['avg', 'min', 'p(50)', 'p(90)', 'p(95)', 'p(99)', 'max'],
  thresholds: {
    grpc_req_duration: ['p(99)<10'],            // end-to-end RPC p99 < 10ms
    engine_eval_time_ns: ['p(99)<2000000'],    // engine-only eval p99  < 2ms
    checks: ['rate>0.995'],                    // >99.5% of assertions must pass
  },
};

// setup() runs once per k6 run (in the init context) before any VU iter.
// Here it verifies the engine is up and the policies are seeded by issuing
// a single CheckAccess probe against the first (allow) fixture. Failing
// fast here avoids spending a long load run against an unseeded engine.
export function setup() {
  client.connect(target, { plaintext: true });

  const probe = client.invoke('authz.v1.AuthorizationService/CheckAccess', fixtures[0].request);
  const probeOk = probe && probe.status === grpc.StatusOK &&
    probe.message && probe.message.allowed === true;

  client.close();

  if (!probeOk) {
    throw new Error(
      `policy seed verification failed — probe CheckAccess returned ` +
      `${JSON.stringify(probe && probe.message)}; ` +
      `ensure the engine is running at ${target} and policies are seeded ` +
      `(run "go run ./loadtest/seed" or "make loadtest")`
    );
  }

  console.log(`policy seeding verified at ${target} — proceeding to load test`);
  return { seeded: true, target };
}

// Per-VU connection state. k6 VUs are long-lived; we connect once on the
// first iteration and reuse the channel for subsequent calls rather than
// paying the TLS/gRPC handshake cost on every request.
let connected = false;

// Default scenario entry point. Each iteration picks a fixture at random,
// invokes CheckAccess, and asserts both the gRPC status and the engine's
// decision match expectations. Engine-reported evaluation time is recorded
// as a custom trend; any non-OK / malformed response bumps the error counter.
export function checkAccess() {
  if (!connected) {
    client.connect(target, { plaintext: true });
    connected = true;
  }

  // Random fixture selection keeps the mix realistic and exercises both the
  // allow and deny code paths within a single scenario.
  const fx = fixtures[Math.floor(Math.random() * fixtures.length)];

  const resp = client.invoke('authz.v1.AuthorizationService/CheckAccess', fx.request, {
    tags: { access: fx.expect ? 'allow' : 'deny' }, // tag metrics by expected verdict
  });

  // Assert: RPC succeeded AND the engine's decision matches the fixture.
  const ok = check(resp, {
    'status is OK': (r) => r && r.status === grpc.StatusOK,
    'decision matches expected': (r) =>
      r && r.message && r.message.allowed === fx.expect,
  });

  if (resp && resp.status === grpc.StatusOK && resp.message) {
    // Record the engine's self-reported evaluation latency (ns), tagged by
    // the actual verdict so allow/deny latencies can be compared.
    const evalNs = Number(resp.message.evaluationTimeNs);
    engine_eval_time_ns.add(evalNs, {
      access: resp.message.allowed ? 'allow' : 'deny',
    });
  } else {
    // Non-OK status or missing message — count as an RPC error.
    rpc_errors.add(1);
  }
}
