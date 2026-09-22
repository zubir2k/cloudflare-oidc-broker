function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

export function renderFormPostHtml(redirectUri: string, code: string, state: string): string {
  return `<!DOCTYPE html>
<html>
<head><title>Submitting...</title></head>
<body onload="document.forms[0].submit()">
  <noscript><p>Please click <button type="submit" form="redir-form">here</button> to continue.</p></noscript>
  <form id="redir-form" method="POST" action="${escapeHtml(redirectUri)}">
    <input type="hidden" name="code" value="${escapeHtml(code)}" />
    <input type="hidden" name="state" value="${escapeHtml(state)}" />
  </form>
  <script>
    setTimeout(() => { document.getElementById('redir-form').submit(); }, 100);
  </script>
</body>
</html>`;
}

export function renderFormPostErrorHtml(redirectUri: string, error: string, errorDescription: string | null, state: string): string {
  return `<!DOCTYPE html>
<html>
<head><title>Submitting...</title></head>
<body onload="document.forms[0].submit()">
  <form method="POST" action="${escapeHtml(redirectUri)}">
    <input type="hidden" name="error" value="${escapeHtml(error)}" />
    <input type="hidden" name="state" value="${escapeHtml(state)}" />
    ${errorDescription ? `<input type="hidden" name="error_description" value="${escapeHtml(errorDescription)}" />` : ''}
  </form>
</body>
</html>`;
}