const OPERATOR_ROUTES = [
  /^api\/v1\/console\/(overview|scans|findings|inventory|reset|settings)(\/[^/?]+)?$/,
  /^api\/v1\/console\/evidence\/[0-9a-f-]+$/,
  /^api\/v1\/console\/remediation\/.+$/,
  /^api\/v1\/discovery\/scans(\/[0-9a-f-]+(\/(events|results|cancel))?)?$/,
  /^api\/v1\/discovery\/killswitch$/,
  /^api\/v1\/validation\/(findings|jobs)\/[0-9a-f-]+(\/events)?$/,
  /^api\/v1\/graph\/(contract|assets|analyze|cytoscape|priority|recompute|snapshots\/latest|snapshots\/[0-9a-f-]+)$/,
  /^api\/v1\/intel\/(url|email|domain|ip|exposure)$/,
];

const ADMIN_MUTATIONS = [
  /^PATCH api\/v1\/graph\/assets\/[^/]+$/,
  /^POST api\/v1\/graph\/(routes|facts)$/,
  /^POST api\/v1\/discovery\/killswitch\/reset$/,
  // Runtime settings writes are admin-gated (ADR-0007 D6).
  /^PATCH api\/v1\/console\/settings$/,
  /^POST api\/v1\/console\/settings\/reset$/,
];

export function backendUrl(path: string, search = ""): URL {
  if (!OPERATOR_ROUTES.some((pattern) => pattern.test(path)) &&
      !ADMIN_MUTATIONS.some((pattern) => pattern.test(`PATCH ${path}`)) &&
      !ADMIN_MUTATIONS.some((pattern) => pattern.test(`POST ${path}`))) {
    throw new Error("route is not available through the console proxy");
  }
  const base = process.env.API_INTERNAL_URL ?? "http://api:8000";
  return new URL(`/${path}${search}`, base);
}

export function backendKey(method: string, path: string): string {
  const admin = ADMIN_MUTATIONS.some((pattern) => pattern.test(`${method} ${path}`));
  const name = admin ? "DISCOVERY_ADMIN_API_KEY" : "DISCOVERY_API_KEY";
  const value = process.env[name];
  if (!value) throw new Error(`${name} is not configured`);
  return value;
}
