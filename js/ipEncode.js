// Alternate representations of an IPv4 address. These are pure string/number
// tricks, independent of the technique-matrix (which was derived using plain
// domain names) - swapping a host for one of these does not change the
// number of path segments a template produces, so a technique's correction
// level still applies, but host *recognition* by a given parser is not
// re-verified here. Treat as best-effort, verify manually when it matters.

const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

export function isIPv4(str) {
  const m = IPV4_RE.exec((str || "").trim());
  if (!m) return false;
  return m.slice(1, 5).every((o) => Number(o) >= 0 && Number(o) <= 255);
}

function octets(ip) {
  return IPV4_RE.exec(ip.trim()).slice(1, 5).map(Number);
}

function toLong(o) {
  return ((o[0] << 24) | (o[1] << 16) | (o[2] << 8) | o[3]) >>> 0;
}

export function ipv4Variants(ip) {
  if (!isIPv4(ip)) return null;
  const o = octets(ip);
  const long = toLong(o);
  const hex = (n) => "0x" + n.toString(16);
  const oct = (n) => "0" + n.toString(8);

  return [
    { id: "decimal", label: "Décimal (32 bits)", value: String(long) },
    { id: "hex-packed", label: "Hex (32 bits)", value: hex(long) },
    { id: "octal-packed", label: "Octal (32 bits)", value: oct(long) },
    { id: "hex-dotted", label: "Hex par octet", value: o.map(hex).join(".") },
    { id: "octal-dotted", label: "Octal par octet", value: o.map(oct).join(".") },
    {
      id: "leading-zero",
      label: "Zéros de tête (souvent lu comme octal !)",
      value: o.map((n) => String(n).padStart(3, "0")).join("."),
    },
    {
      id: "mixed",
      label: "Mixte (hex/octal/décimal panaché)",
      value: `${hex(o[0])}.${oct(o[1])}.${o[2]}.${o[3]}`,
    },
    { id: "ipv6-mapped", label: "IPv6-mapped", value: `[::ffff:${ip}]` },
    {
      id: "ipv6-mapped-hex",
      label: "IPv6-mapped (hex)",
      value: `[::ffff:${((o[0] << 8) | o[1]).toString(16)}:${((o[2] << 8) | o[3]).toString(16)}]`,
    },
    {
      id: "dotless-partial",
      label: "Notation courte (a.bc en decimal 24 bits)",
      value: `${o[0]}.${(o[1] << 16) | (o[2] << 8) | o[3]}`,
    },
  ];
}
