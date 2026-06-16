// Load test — read path (discovery + JWKS). These are cacheable, allocation-light, and
// have no DB write, so they show the server's ceiling for the high-fan-out endpoints that
// every RP and resource server hits constantly. Much higher target rates than token.js.
//
//   k6 run -e TIER=medium   loadtest/discovery.js
//   k6 run -e TIER=high     loadtest/discovery.js
//   k6 run -e TIER=realhigh loadtest/discovery.js
import http from 'k6/http';
import { check } from 'k6';

const BASE = __ENV.BASE || 'http://127.0.0.1:8081';
const TIER = __ENV.TIER || 'medium';

const TIERS = {
  medium:   { rate: 1000,  duration: '20s', preAllocatedVUs: 200,  maxVUs: 800   },
  high:     { rate: 5000,  duration: '20s', preAllocatedVUs: 800,  maxVUs: 3000  },
  realhigh: { rate: 15000, duration: '20s', preAllocatedVUs: 2000, maxVUs: 8000  },
};
const t = TIERS[TIER];
if (!t) throw new Error(`unknown TIER '${TIER}'`);

export const options = {
  scenarios: {
    read: {
      executor: 'constant-arrival-rate',
      rate: t.rate, timeUnit: '1s', duration: t.duration,
      preAllocatedVUs: t.preAllocatedVUs, maxVUs: t.maxVUs,
      gracefulStop: '10s',
    },
  },
  thresholds: {
    http_req_failed:   ['rate<0.01'],
    http_req_duration: [`p(95)<${TIER === 'realhigh' ? 1000 : 300}`],
  },
};

export default function () {
  // 50/50 split between the two read endpoints.
  const url = Math.random() < 0.5
    ? `${BASE}/.well-known/openid-configuration`
    : `${BASE}/.well-known/jwks`;
  const res = http.get(url);
  check(res, { 'status 200': (r) => r.status === 200 });
}
