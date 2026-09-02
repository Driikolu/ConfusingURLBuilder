// Simulates naive, string-level allowlist checks - the kind a real-world
// validator uses when it does NOT do proper URL parsing. These run live
// against the final rendered payload string.

function naiveAuthority(payload) {
  // Deliberately naive: stops at /, ?, # - but NOT at backslash. That gap is
  // exactly where a lot of real bugs live (see the backslash-* techniques).
  const m = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\/([^/?#]*)/.exec(payload);
  return m ? m[1] : "";
}

export const NAIVE_CHECKS = [
  {
    id: "contains",
    label: "contains(url, allowed)",
    description: "The most naive check: the allowed domain appears anywhere in the string.",
    test: (payload, allowedHost) => payload.toLowerCase().includes(allowedHost.toLowerCase()),
  },
  {
    id: "starts-with",
    label: "url.startsWith(scheme://allowed)",
    description: "Checks that the URL literally starts with 'scheme://allowed'.",
    test: (payload, allowedHost, scheme) =>
      payload.toLowerCase().startsWith(`${scheme}://${allowedHost}`.toLowerCase()),
  },
  {
    id: "naive-regex-exact",
    label: "regex authority === allowed",
    description:
      "Extracts the authority with a naive regex (stops at /, ?, # but not at backslash) then compares for equality.",
    test: (payload, allowedHost) => naiveAuthority(payload).toLowerCase() === allowedHost.toLowerCase(),
  },
  {
    id: "naive-regex-suffix",
    label: "regex authority endsWith allowed (subdomain allowlist)",
    description:
      "Same naive extraction, but also accepts subdomains of allowed (a classic allowlist bug).",
    test: (payload, allowedHost) => {
      const a = naiveAuthority(payload).toLowerCase();
      const h = allowedHost.toLowerCase();
      return a === h || a.endsWith("." + h);
    },
  },
];

export function getCheck(id) {
  return NAIVE_CHECKS.find((c) => c.id === id) || NAIVE_CHECKS[0];
}
