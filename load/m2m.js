// Execute against an IS deployment sized for load, NEVER the bundled H2 development profile.
// k6 run --out json=generated/k6-results.json load/m2m.js
// K6_TOKEN_URL, K6_CLIENT_ID, K6_CLIENT_SECRET are mandatory. 1,000 arrivals/s x 30m.
import http from 'k6/http';
import encoding from 'k6/encoding';
import { check } from 'k6';
import { Rate, Trend } from 'k6/metrics';

const cfg = {
  url: __ENV.K6_TOKEN_URL,
  clientId: __ENV.K6_CLIENT_ID,
  secret: __ENV.K6_CLIENT_SECRET,
  rate: Number(__ENV.K6_RATE || 1000),
  duration: __ENV.K6_DURATION || '30m',
  preAllocatedVUs: Number(__ENV.K6_PRE_VUS || 400),
  maxVUs: Number(__ENV.K6_MAX_VUS || 3000),
};
if (!cfg.url || !cfg.clientId || !cfg.secret) throw Error('Missing K6_TOKEN_URL / K6_CLIENT_ID / K6_CLIENT_SECRET');
export const tokenErrors = new Rate('token_error_rate');
export const tokenLatency = new Trend('token_latency_ms', true);
export const options = {
  scenarios: { m2m: { executor: 'constant-arrival-rate', rate: cfg.rate,
    timeUnit: '1s', duration: cfg.duration, preAllocatedVUs: cfg.preAllocatedVUs,
    maxVUs: cfg.maxVUs, gracefulStop: '30s' } },
  thresholds: {
    'token_error_rate': [{ threshold: 'rate<=0.001', abortOnFail: false }],
    // p95/p99 capture, acceptance values must be AGREED with Magalu before testing.
    'dropped_iterations': ['count==0'],
  },
  summaryTrendStats: ['avg','min','med','p(90)','p(95)','p(99)','max'],
};
export default function () {
  const auth = encoding.b64encode(`${cfg.clientId}:${cfg.secret}`);
  const resp = http.post(cfg.url, 'grant_type=client_credentials', {
    headers: { 'Authorization': `Basic ${auth}`, 'Content-Type': 'application/x-www-form-urlencoded',
      'Accept': 'application/json' }, timeout: '15s', tags: { grant: 'client_credentials' } });
  let valid = resp.status === 200;
  if (valid) { try { valid = Boolean(resp.json('access_token')); } catch (_) { valid = false; } }
  tokenErrors.add(!valid);
  tokenLatency.add(resp.timings.duration);
  check(resp,{ 'real token issued': () => valid });
}
export function handleSummary(data) {
  const metrics = data.metrics || {};
  const payload = {
    test: 'RFP_7_3_M2M', rate: cfg.rate, duration: cfg.duration,
    threshold_status: Object.fromEntries(Object.entries(metrics).filter(([k,v]) => v.thresholds)
      .map(([k,v])=>[k,Object.fromEntries(Object.entries(v.thresholds).map(([t,x])=>[t,x.ok]))])),
    latency_ms: metrics.token_latency_ms?.values || null,
    error_rate: metrics.token_error_rate?.values?.rate ?? null,
    dropped_iterations: metrics.dropped_iterations?.values?.count ?? 0,
    requests: metrics.http_reqs?.values?.count ?? 0,
    caveat: 'Only client_credentials profile. Add distinct approved JWT bearer and token exchange workloads separately.'
  };
  return { 'generated/m2m-summary.json':JSON.stringify(payload,null,2),stdout:JSON.stringify(payload,null,2)+'\n' };
}
