// Mirrors tools/derive_matrix.py's render() exactly - the correction level
// stored in the matrix was derived using this same substitution scheme, so
// any drift here would silently invalidate the pre-verified data.

export function portSuffix(port) {
  const p = (port || "").trim();
  return p ? `:${p}` : "";
}

// Maps ASCII 0x21-0x7E to the Unicode "Halfwidth and Fullwidth Forms" block
// (fixed +0xFEE0 offset) - covers letters, digits, '.', '-' alike, so it
// works on both domain names and dotted IPv4 literals. Several parsers apply
// Unicode/IDNA host mapping that folds these back to plain ASCII.
export function toFullwidth(str) {
  return (str || "").replace(/[\x21-\x7e]/g, (c) => String.fromCodePoint(c.codePointAt(0) + 0xfee0));
}

export function renderTemplate(template, vars) {
  return template
    .replaceAll("{S}", vars.scheme)
    .replaceAll("{A}", vars.allowedHost)
    .replaceAll("{AP}", portSuffix(vars.allowedPort))
    .replaceAll("{T}", vars.targetHost)
    .replaceAll("{TP}", portSuffix(vars.targetPort))
    .replaceAll("{AFW}", toFullwidth(vars.allowedHost))
    .replaceAll("{TFW}", toFullwidth(vars.targetHost))
    .replaceAll("{P}", (vars.path || "/").replace(/^\/+/, ""))
    .replaceAll("{C}", "../".repeat(vars.correctionLevel || 0))
    .replaceAll("{TAB}", "\t")
    .replaceAll("{CR}", "\r")
    .replaceAll("{LF}", "\n")
    .replaceAll("{VT}", "\v")
    .replaceAll("{FF}", "\f")
    .replaceAll("{FWAT}", "＠");
}

export function buildPayload(technique, correctionLevel, inputs) {
  return renderTemplate(technique.template, { ...inputs, correctionLevel });
}
