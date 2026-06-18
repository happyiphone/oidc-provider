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

// rate = target requests/second. The token endpoint is CPU/DB-bound (client-secret hashing +
// ES256 signing + token persistence), so a SINGLE instance ceilings in the low hundreds of rps and
// queues (not errors) past that. Tiers reflect that: medium is sustainable on one instance; high
// probes the saturation edge; realhigh needs horizontal scaling (latency not asserted).
// `p95: 0` disables the latency gate for that tier; override any tier with `-e P95_MS=<ms>`.
const TIERS = {
  medium:   { rate: 75,   duration: '30s', preAllocatedVUs: 60,   maxVUs: 300,  p95: 300  },
  high:     { rate: 200,  duration: '30s', preAllocatedVUs: 200,  maxVUs: 800,  p95: 3000 },
  realhigh: { rate: 1000, duration: '30s', preAllocatedVUs: 800,  maxVUs: 3000, p95: 0    },
};
const t = TIERS[TIER];
if (!t) throw new Error(`unknown TIER '${TIER}' (use medium|high|realhigh)`);
const P95 = __ENV.P95_MS ? Number(__ENV.P95_MS) : t.p95;

export const options = {
  scenarios: {
    token: {
      executor: 'constant-arrival-rate',
      rate: t.rate, timeUnit: '1s', duration: t.duration,
      preAllocatedVUs: t.preAllocatedVUs, maxVUs: t.maxVUs,
      gracefulStop: '10s',
    },
  },
  // Error rate is the HARD gate (a broken endpoint errors). Latency is asserted only where the
  // instance should keep up (medium/high); P95=0 → not asserted (saturation probe).
  thresholds: Object.assign(
    {
      http_req_failed: [{ threshold: TIER === 'realhigh' ? 'rate<0.05' : 'rate<0.01', abortOnFail: false }],
      checks:          ['rate>0.95'],
    },
    P95 > 0 ? { http_req_duration: [`p(95)<${P95}`] } : {}),
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
