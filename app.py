"""
Password Payload Generator — Flask Application
=================================================
A cybersecurity educational web application that generates targeted password-testing
payloads and analyses password strength.

DISCLAIMER:
  This tool is designed EXCLUSIVELY for:
    • Authorized cybersecurity education
    • Password-strength auditing
    • Authorized penetration-testing labs

  Unauthorized use against systems you do not own or have explicit written
  permission to test is ILLEGAL and UNETHICAL.

Routes:
  /             → Dashboard
  /generator    → Targeted Payload Generator page
  /analyzer     → Password Analyzer page
  /about        → About / disclaimer page

API Endpoints:
  POST /api/generate   → Generate targeted password candidates
  POST /api/analyze    → Analyze password strength
  POST /api/download   → Download candidates as TXT
  GET  /api/activity   → Retrieve session activity log

Version: 2.0.0
"""

from flask import Flask, render_template, request, jsonify, Response
from generator import generate_profile_payloads, validate_profile_input, MAX_GENERATION_LIMIT
from analyzer import analyze_password
from datetime import datetime

app = Flask(__name__)

# In-memory activity log — never stores actual passwords or input text.
# Only metadata (timestamps, counts) is recorded.
session_activity: list = []


# ---------------------------------------------------------------------------
# Page routes
# ---------------------------------------------------------------------------

@app.route('/')
def dashboard():
    """Renders the Dashboard page with session statistics."""
    return render_template('dashboard.html', page='dashboard')


@app.route('/generator')
def generator():
    """Renders the Targeted Payload Generator page."""
    return render_template('index.html', page='generator')


@app.route('/analyzer')
def analyzer():
    """Renders the Password Analyzer page."""
    return render_template('index.html', page='analyzer')


@app.route('/about')
def about():
    """Renders the About / disclaimer page."""
    return render_template('about.html', page='about')


# ---------------------------------------------------------------------------
# API endpoints
# ---------------------------------------------------------------------------

@app.route('/api/generate', methods=['POST'])
def api_generate():
    """
    Generates targeted password-testing payloads from user profile attributes.

    Request JSON:
      {
        "first_name": "Yeswanth",           (required)
        "last_name": "Raj",                 (optional)
        "nickname": "Yesh",                 (optional)
        "dob": "29 12 2005",                (optional)
        "birth_year": "2005",               (optional)
        "fav_word": "gaming",               (optional)
        "fav_number": "7",                  (optional)
        "custom_keywords": ["team", ...],   (optional)
        "other_info": "chennai",            (optional)
        "max_limit": 5000                   (optional)
      }
    """
    try:
        data = request.get_json(silent=True)

        if not data:
            return jsonify({
                'success': False,
                'message': 'No input profile data provided.',
            }), 400

        # Validate input (first_name is required, others optional)
        validation = validate_profile_input(data)
        if not validation['valid']:
            return jsonify({
                'success': False,
                'message': validation['message'],
            }), 400

        max_limit = min(
            data.get('max_limit', MAX_GENERATION_LIMIT),
            MAX_GENERATION_LIMIT,
        )

        # Generate targeted payloads
        result = generate_profile_payloads(data, max_limit=max_limit)

        # Record activity — sensitive input fields are NOT stored
        first_name = (data.get('first_name') or '').strip()
        session_activity.append({
            'timestamp':       datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'action':          'generate',
            'first_name_len':  len(first_name),
            'total_generated': result['total'],
            'categories_used': len(result['categories']),
        })

        return jsonify(result)

    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Server error: {str(e)}',
        }), 500


@app.route('/api/analyze', methods=['POST'])
def api_analyze():
    """
    Analyses the strength of a user-supplied password.

    The password is processed IN-MEMORY ONLY and is never logged or stored.
    """
    try:
        data = request.get_json(silent=True)

        if not data or 'password' not in data:
            return jsonify({
                'success': False,
                'message': 'No password provided for analysis.',
            }), 400

        password = data['password']

        if len(password) > 128:
            return jsonify({
                'success': False,
                'message': 'Password exceeds maximum length of 128 characters.',
            }), 400

        result = analyze_password(password)

        # Log only metadata — password itself is NOT recorded
        session_activity.append({
            'timestamp':       datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'action':          'analyze',
            'password_length': len(password),
        })

        return jsonify(result)

    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Server error: {str(e)}',
        }), 500


@app.route('/api/download', methods=['POST'])
def api_download():
    """
    Returns generated candidates as a downloadable plain-text file,
    grouped by category.
    """
    try:
        data = request.get_json(silent=True)

        if not data or 'candidates' not in data:
            return jsonify({
                'success': False,
                'message': 'No candidates provided for download.',
            }), 400

        candidates = data['candidates']

        lines = [
            '=' * 60,
            '  PASSWORD PAYLOAD GENERATOR — Targeted Wordlist',
            '  For authorized cybersecurity education & audit labs only.',
            '=' * 60,
            f'  Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}',
            f'  Total Candidates: {len(candidates)}',
            '=' * 60,
            '',
        ]

        # Group by category
        grouped: dict = {}
        for c in candidates:
            cat = c.get('category', 'General')
            grouped.setdefault(cat, []).append(c['text'])

        for category, items in grouped.items():
            lines.append(f'--- {category} ({len(items)}) ---')
            lines.extend(items)
            lines.append('')

        lines += ['=' * 60, '  END OF FILE', '=' * 60]

        return Response(
            '\n'.join(lines),
            mimetype='text/plain',
            headers={
                'Content-Disposition': 'attachment; filename=targeted_passwords.txt',
            },
        )

    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Server error: {str(e)}',
        }), 500


@app.route('/api/activity')
def api_activity():
    """Returns the last 20 session activity entries for the dashboard."""
    return jsonify({
        'success':  True,
        'activity': session_activity[-20:],
    })


@app.route('/api/clear-activity', methods=['POST'])
def api_clear_activity():
    """
    Clears all session logs, cached history, and generation activity
    from the current session.
    """
    global session_activity
    session_activity.clear()
    return jsonify({
        'success': True,
        'message': 'All session activity and history database cleared successfully.'
    })


if __name__ == '__main__':
    banner = (
        '\n' + '=' * 60 + '\n'
        '  Targeted Password Payload Generator v2.0.0\n'
        '  For authorized cybersecurity education only.\n'
        '=' * 60 + '\n'
        '  Starting server at http://127.0.0.1:5000\n'
        '=' * 60 + '\n'
    )
    print(banner)
    app.run(debug=True, host='127.0.0.1', port=5000)
