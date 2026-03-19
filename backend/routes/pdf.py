from flask import Blueprint, request, jsonify, make_response, render_template_string
from weasyprint import HTML
from database import get_db
from routes.auth import jwt_required
from datetime import datetime

pdf_bp = Blueprint('pdf', __name__)


@pdf_bp.route('/api/pdf/statement', methods=['GET'])
@jwt_required
def generate_pdf():
    user_id = request.current_user['user_id']
    db = get_db()
    user = dict(db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone())
    accounts = [dict(r) for r in db.execute(
        'SELECT * FROM accounts WHERE user_id = ?', (user_id,)).fetchall()]
    transactions = [dict(r) for r in db.execute(
        '''SELECT * FROM transactions
           WHERE from_account IN (SELECT account_number FROM accounts WHERE user_id = ?)
              OR to_account   IN (SELECT account_number FROM accounts WHERE user_id = ?)
           ORDER BY created_at DESC LIMIT 20''',
        (user_id, user_id)).fetchall()]
    db.close()

    today    = datetime.now()
    filename = today.strftime('%d-%m-%Y') + '.pdf'
    date_str = today.strftime('%d-%m-%Y')

    # VULN: SSTI-1 — user['full_name'] embedded into the template string via f-string
    # BEFORE render_template_string is called. Jinja2 expressions in full_name are executed.
    # e.g. full_name = "{{7*7}}"   → PDF shows "49"
    # e.g. full_name = "{{config.items()|list}}"  → PDF shows Flask config (JWT secret etc.)
    # e.g. full_name = "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}"
    html_template = f"""<!DOCTYPE html>
<html>
<head>
<style>
  body {{ font-family: Arial, sans-serif; margin: 40px; color: #1a3a5c; }}
  .header {{ background: #1a3a5c; color: white; padding: 20px; margin-bottom: 30px; }}
  .header h1 {{ margin: 0; font-size: 24px; }}
  .header .gold {{ color: #c9a227; }}
  .section {{ margin-bottom: 25px; border: 1px solid #dde3ea; padding: 15px; border-radius: 8px; }}
  .section h2 {{ color: #1a3a5c; font-size: 16px; border-bottom: 2px solid #c9a227; padding-bottom: 8px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th {{ background: #1a3a5c; color: white; padding: 8px; text-align: left; }}
  td {{ padding: 7px 8px; border-bottom: 1px solid #eee; }}
  .balance {{ font-size: 18px; font-weight: bold; color: #1a3a5c; }}
  .footer {{ margin-top: 40px; text-align: center; font-size: 11px; color: #999; border-top: 1px solid #eee; padding-top: 15px; }}
  .warning {{ background: #7b0000; color: white; padding: 8px 12px; font-size: 11px; margin-bottom: 20px; border-radius: 4px; }}
  .badge {{ display: inline-block; padding: 3px 10px; border-radius: 12px; font-size: 11px; font-weight: bold; text-transform: uppercase; }}
  .badge-gold {{ background: #c9a227; color: white; }}
  .badge-silver {{ background: #aaa; color: white; }}
  .badge-bronze {{ background: #cd7f32; color: white; }}
</style>
</head>
<body>
<div class="warning">&#9888; INTENTIONALLY VULNERABLE APPLICATION — FOR TRAINING ONLY</div>
<div class="header">
  <h1>Vuln<span class="gold">Bank</span> — Account Statement</h1>
  <p style="margin:8px 0 0 0; font-size:13px;">Generated: {date_str} &nbsp;|&nbsp; Statement Period: Last 20 transactions</p>
</div>

<div class="section">
  <h2>Account Holder</h2>
  <table>
    <tr><td width="200"><strong>Name</strong></td><td>{ user['full_name'] }</td></tr>
    <tr><td><strong>Email</strong></td><td>{ user['email'] }</td></tr>
    <tr><td><strong>Phone</strong></td><td>{ user['phone'] or 'N/A' }</td></tr>
    <tr><td><strong>Subscription</strong></td><td>
      <span class="badge badge-{ user['subscription_type'] }">{ user['subscription_type'] }</span>
    </td></tr>
  </table>
</div>

<div class="section">
  <h2>Accounts Summary</h2>
  <table>
    <tr><th>Account Number</th><th>Type</th><th>Currency</th><th>Balance</th></tr>
    {{% for acc in accounts %}}
    <tr>
      <td>{{ acc['account_number'] }}</td>
      <td style="text-transform:capitalize;">{{ acc['account_type'] }}</td>
      <td>{{ acc['currency'] }}</td>
      <td class="balance">${{ "%.2f"|format(acc['balance']) }}</td>
    </tr>
    {{% endfor %}}
    {{% if not accounts %}}
    <tr><td colspan="4" style="text-align:center;color:#999;">No accounts found</td></tr>
    {{% endif %}}
  </table>
</div>

<div class="section">
  <h2>Recent Transactions (Last 20)</h2>
  <table>
    <tr><th>Date</th><th>From</th><th>To</th><th>Amount</th><th>Description</th><th>Status</th></tr>
    {{% for tx in transactions %}}
    <tr>
      <td>{{ tx['created_at'][:10] }}</td>
      <td style="font-size:11px;">{{ tx['from_account'] }}</td>
      <td style="font-size:11px;">{{ tx['to_account'] }}</td>
      <td class="balance">${{ "%.2f"|format(tx['amount']) }}</td>
      <td>{{ tx['description'] or '' }}</td>
      <td>{{ tx['status'] or 'completed' }}</td>
    </tr>
    {{% endfor %}}
    {{% if not transactions %}}
    <tr><td colspan="6" style="text-align:center;color:#999;">No transactions found</td></tr>
    {{% endif %}}
  </table>
</div>

<div class="footer">
  VulnBank &copy; 2025 &nbsp;|&nbsp; This document is generated for security training purposes only<br>
  Account statements are confidential. Unauthorised disclosure is prohibited.
</div>
</body>
</html>"""

    # VULN: SSTI-1 — render_template_string evaluates Jinja2 in the full template,
    # including user['full_name'] which was embedded via f-string above
    ctx = {
        'user':         user,
        'accounts':     accounts,
        'transactions': transactions,
        'date':         date_str,
    }
    try:
        rendered_html = render_template_string(html_template, **ctx)
    except Exception as e:
        # VULN: A05 — SSTI/template error details exposed
        return jsonify({'error': 'Template render error', 'detail': str(e)}), 500

    try:
        pdf_bytes = HTML(string=rendered_html).write_pdf()
    except Exception as e:
        return jsonify({'error': 'PDF generation error', 'detail': str(e)}), 500

    response = make_response(pdf_bytes)
    response.headers['Content-Type']        = 'application/pdf'
    response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
    return response
