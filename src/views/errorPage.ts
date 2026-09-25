/**
 * Renders a user-friendly Access Denied page.
 * Uses a single button that intelligently handles both popup and main window contexts.
 */
export function renderAccessDeniedHtml(email: string, redirectUri: string): string {
  // Safely extract the origin
  let appOrigin = '/';
  try {
    const url = new URL(redirectUri);
    if (url.protocol === 'http:' || url.protocol === 'https:') {
      appOrigin = url.origin;
    }
  } catch {
    // Fallback
  }

  return `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Access Denied</title>
      <style>
        body {
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
          display: flex;
          justify-content: center;
          align-items: center;
          min-height: 100vh;
          margin: 0;
          background: #f5f5f5;
          color: #333;
        }
        .error-container {
          background: white;
          padding: 2.5rem;
          border-radius: 12px;
          box-shadow: 0 4px 6px rgba(0,0,0,0.05), 0 1px 3px rgba(0,0,0,0.1);
          max-width: 480px;
          width: 100%;
          text-align: center;
        }
        h1 {
          color: #d32f2f;
          margin-top: 0;
          font-size: 1.5rem;
          margin-bottom: 1rem;
        }
        p {
          color: #555;
          line-height: 1.6;
          margin-bottom: 1.5rem;
        }
        .email {
          font-weight: 600;
          color: #1976d2;
          word-break: break-all;
        }
        .action-btn {
          display: inline-block;
          padding: 0.75rem 1.5rem;
          background: #1976d2;
          color: white;
          text-decoration: none;
          border: none;
          border-radius: 6px;
          font-size: 1rem;
          font-weight: 500;
          cursor: pointer;
          transition: background 0.2s;
        }
        .action-btn:hover {
          background: #1565c0;
        }
        .secondary-text {
          font-size: 0.85rem;
          color: #888;
          margin-top: 1rem;
        }
      </style>
    </head>
    <body>
      <div class="error-container">
        <h1>Access Denied</h1>
        <p>Your account <span class="email">${escapeHtml(email)}</span> is not authorized to access this application.</p>
        <p>If you believe this is an error, please contact your administrator to add your account to the authorized users list.</p>
        
        <button class="action-btn" onclick="handleReturn()">Return to Application</button>
        
        <p class="secondary-text">Please try logging in with an authorized account.</p>
      </div>

      <script>
        function handleReturn() {
          const origin = '${escapeHtml(appOrigin)}';
          
          if (window.opener) {
            // Context: Popup
            try {
              // Attempt to redirect the main window back to the app
              window.opener.location.href = origin;
            } catch (e) {
              // Cross-origin restrictions may block this. 
              // The downstream app's JS will detect the popup closing and reset its UI.
              console.warn('Could not redirect opener window:', e);
            }
            // Always close the popup
            window.close();
          } else {
            // Context: Main Window
            window.location.href = origin;
          }
        }
      </script>
    </body>
    </html>
  `;
}

function escapeHtml(unsafe: string): string {
  return unsafe
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}