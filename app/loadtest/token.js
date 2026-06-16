// Load test — Token endpoint (client_credentials), the provider's real hot path:
// client authentication + ES256 signing + token persistence per request.
//
// Three workload tiers selected via TIER env (medium | high | realhigh), modelled as a
// fixed arrival rate (req/s) so we measure latency/error behaviour AT a target throughput
// rather than just "as fast as VUs go".
//
//   k6 run -e TIER=medium   loadtest/token.js
//   k6 run -e TIER=high     loadtest/token.js
//   k6 run -e TIER=realhigh loadtest/token.js
import http from 'k6/http';
import { check } from 'k6';

const BASE = __ENV.BASE || 'http://127.0.0.1:8081';
const TIER = __ENV.TIER || 'medium';

// rate = target requests/second; duration excludes a short warmup ramp.
const TIERS = {
  medium:   { rate: 200,  duration: '30s', preAllocatedVUs: 100,  maxVUs: 600  },
  high:     { rate: 1000, duration: '30s', preAllocatedVUs: 500,  maxVUs: 2000 },
  realhigh: { rate: 5000, duration: '30s', preAllocatedVUs: 1500, maxVUs: 6000 },
};
const t = TIERS[TIER];
if (!t) throw new Error(`unknown TIER '${TIER}' (use medium|high|realhigh)`);

export const options = {
  scenarios: {
    token: {
      executor: 'constant-arrival-rate',
      rate: t.rate, timeUnit: '1s', duration: t.duration,
      preAllocatedVUs: t.preAllocatedVUs, maxVUs: t.maxVUs,
      gracefulStop: '10s',
    },
  },
  // Pass/fail gates. p95 budget loosens per tier because realhigh is meant to probe the
  // saturation point, not assert it stays fast.
  thresholds: {
    http_req_failed:   [{ threshold: TIER === 'realhigh' ? 'rate<0.05' : 'rate<0.01', abortOnFail: false }],
    http_req_duration: [`p(95)<${TIER === 'realhigh' ? 2000 : TIER === 'high' ? 800 : 300}`],
    checks:            ['rate>0.95'],
  },
};

const BODY = 'grant_type=client_credentials&scope=api' +
             '&client_id=svc-loadtest&client_secret=svc-secret-dev-only';
const PARAMS = { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } };

export default function () {
  const res = http.post(`${BASE}/token`, BODY, PARAMS);
  check(res, {
    'status 200': (r) => r.status === 200,
    'has access_token': (r) => typeof r.body === 'string' && r.body.includes('access_token'),
  });
}
