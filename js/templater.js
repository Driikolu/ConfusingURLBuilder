// Mirrors tools/derive_matrix.py's render() exactly - the correction level
// stored in the matrix was derived using this same substitution scheme, so
// any drift here would silently invalidate the pre-verified data.

export function portSuffix(port) {
  const p = (port || "").trim();
  return p ? `:${p}` : "";
}

export function renderTemplate(template, vars) {
  return template
    .replaceAll("{S}", vars.scheme)
    .replaceAll("{A}", vars.allowedHost)
    .replaceAll("{AP}", portSuffix(vars.allowedPort))
    .replaceAll("{T}", vars.targetHost)
    .replaceAll("{TP}", portSuffix(vars.targetPort))
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
