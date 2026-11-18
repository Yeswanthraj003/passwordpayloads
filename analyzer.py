"""
Password Security Analyzer Module
===================================
Evaluates password strength and provides actionable improvement suggestions.
Designed for authorized cybersecurity education only.

IMPORTANT — Privacy Guarantee:
  • Passwords are NEVER stored to disk or database.
  • Passwords are NEVER transmitted to external APIs or services.
  • All analysis is performed entirely in-memory and results are
    returned directly to the caller.

Scoring methodology:
  • Length           → up to 30 points
  • Character variety→ up to 25 points
  • Distribution     → up to 15 points
  • Pattern penalties→ up to -20 points
  • Complexity bonus → up to 10 points
  Total possible: 0 – 100
"""

import re
import string
from typing import Dict, List


def analyze_password(password: str) -> Dict:
    """
    Master analysis function — returns a full report for the given password.

    Args:
        password: The password string to evaluate.

    Returns:
        dict with keys:
          success  – bool
          message  – str
          analysis – dict with length, counts, score, strength,
                     suggestions, and weaknesses (or None on error)
    """
    if not password:
        return {
            'success': False,
            'message': 'Password cannot be empty.',
            'analysis': None,
        }

    length = len(password)
    uppercase_count  = sum(1 for c in password if c.isupper())
    lowercase_count  = sum(1 for c in password if c.islower())
    digit_count      = sum(1 for c in password if c.isdigit())
    special_count    = sum(1 for c in password if c in string.punctuation)
    space_count      = sum(1 for c in password if c.isspace())

    # How many of the four character classes are present?
    char_types_used = sum([
        uppercase_count > 0,
        lowercase_count > 0,
        digit_count > 0,
        special_count > 0,
    ])

    score = _calculate_strength_score(
        length, uppercase_count, lowercase_count,
        digit_count, special_count, char_types_used, password,
    )

    strength = estimate_strength(score)

    suggestions = _get_suggestions(
        length, uppercase_count, lowercase_count,
        digit_count, special_count, char_types_used, password,
    )

    weaknesses = _detect_weaknesses(password)

    analysis = {
        'length':               length,
        'uppercase':            uppercase_count,
        'lowercase':            lowercase_count,
        'digits':               digit_count,
        'special_characters':   special_count,
        'spaces':               space_count,
        'character_types_used': char_types_used,
        'score':                score,
        'strength':             strength,
        'suggestions':          suggestions,
        'weaknesses':           weaknesses,
    }

    return {
        'success': True,
        'message': 'Analysis complete.',
        'analysis': analysis,
    }


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

def _calculate_strength_score(length: int, uppercase: int, lowercase: int,
                              digits: int, special: int, char_types: int,
                              password: str) -> int:
    """
    Computes a 0–100 numeric strength score.

    Factors:
      1. Length                   (up to 30 pts)
      2. Character-type variety   (up to 25 pts)
      3. Distribution balance     (up to 15 pts)
      4. Pattern penalties        (up to -20 pts)
      5. Exceptional-complexity   (up to +10 pts bonus)
    """
    score = 0

    # --- 1. Length ---
    if length >= 16:
        score += 30
    elif length >= 12:
        score += 25
    elif length >= 10:
        score += 20
    elif length >= 8:
        score += 15
    elif length >= 6:
        score += 10
    else:
        score += 5

    # --- 2. Character-type variety ---
    score += char_types * 6          # max 24
    if char_types == 4:
        score += 1                   # all-four bonus → 25

    # --- 3. Distribution balance ---
    if length > 0:
        ratios = [
            uppercase / length,
            lowercase / length,
            digits    / length,
            special   / length,
        ]
        non_zero = [r for r in ratios if r > 0]
        if len(non_zero) >= 2:
            balance = min(non_zero) / max(non_zero)
            score += int(balance * 15)

    # --- 4. Penalties ---
    password_lower = password.lower()

    # Sequential characters (abc, 123, …)
    sequential = 0
    for i in range(len(password) - 2):
        if ord(password[i]) + 1 == ord(password[i + 1]) == ord(password[i + 2]) - 1:
            sequential += 1
    score -= sequential * 3

    # Low character uniqueness
    if length > 0:
        uniqueness = len(set(password)) / length
        if uniqueness < 0.5:
            score -= 10
        elif uniqueness < 0.7:
            score -= 5

    # Contains a well-known weak word
    weak_words = [
        'password', 'admin', 'login', 'welcome', 'qwerty',
        'letmein', 'monkey', 'dragon', 'master', 'abc123',
    ]
    for w in weak_words:
        if w in password_lower:
            score -= 15
            break

    # --- 5. Bonuses ---
    if length >= 20 and char_types >= 3:
        score += 5
    if length >= 16 and char_types == 4:
        score += 5

    return max(0, min(100, score))


def estimate_strength(score: int) -> str:
    """
    Maps a numeric score (0–100) to a human-friendly label.

    Thresholds:
      80–100 → Very Strong
      60–79  → Strong
      40–59  → Medium
      20–39  → Weak
       0–19  → Very Weak
    """
    if score >= 80:
        return 'Very Strong'
    elif score >= 60:
        return 'Strong'
    elif score >= 40:
        return 'Medium'
    elif score >= 20:
        return 'Weak'
    else:
        return 'Very Weak'


# ---------------------------------------------------------------------------
# Suggestions & weakness detection
# ---------------------------------------------------------------------------

def _get_suggestions(length: int, uppercase: int, lowercase: int,
                     digits: int, special: int, char_types: int,
                     password: str) -> List[str]:
    """
    Returns a list of actionable tips to improve password strength.
    """
    tips: List[str] = []

    if length < 8:
        tips.append('Increase password length to at least 8 characters.')
    elif length < 12:
        tips.append('Consider using 12 or more characters for better security.')
    elif length < 16:
        tips.append('A 16+ character password provides excellent security.')

    if uppercase == 0:
        tips.append('Add uppercase letters (A–Z) for more complexity.')
    if lowercase == 0:
        tips.append('Add lowercase letters (a–z) for more variety.')
    if digits == 0:
        tips.append('Include numbers (0–9) to strengthen the password.')
    if special == 0:
        tips.append('Add special characters (!@#$%&*) for maximum strength.')

    if char_types < 3:
        tips.append(
            'Use at least 3 different character types '
            '(uppercase, lowercase, numbers, symbols).'
        )

    if length > 0 and len(set(password)) == 1:
        tips.append('Avoid using the same character repeatedly.')

    if not tips:
        tips.append(
            'Your password meets strong security criteria. '
            'Consider using a passphrase for even better security.'
        )

    return tips


def _detect_weaknesses(password: str) -> List[str]:
    """
    Scans for common structural weaknesses in the password.

    Checks include common dictionary words, keyboard walks,
    repeated characters, sequential runs, length, and case monotony.
    """
    weaknesses: List[str] = []
    pw = password.lower()

    # Common dictionary passwords
    common_words = [
        'password', 'admin', 'login', 'welcome', 'qwerty',
        'letmein', 'monkey', 'dragon', 'master', '123456',
        'abc123', 'iloveyou', 'trustno1', 'sunshine',
    ]
    for word in common_words:
        if word in pw:
            weaknesses.append(f'Contains common password pattern: "{word}"')

    # Keyboard walks
    for pat in ['qwerty', 'asdfgh', 'zxcvbn', 'qazwsx', '12345', '67890']:
        if pat in pw:
            weaknesses.append(f'Contains keyboard pattern: "{pat}"')

    # Repeated characters (3+)
    if re.search(r'(.)\1{2,}', password):
        weaknesses.append('Contains 3 or more repeated consecutive characters.')

    # Sequential digits
    if re.search(r'(012|123|234|345|456|567|678|789|890)', password):
        weaknesses.append('Contains sequential numbers.')

    # Sequential letters
    for i in range(len(password) - 2):
        a, b, c = password[i], password[i + 1], password[i + 2]
        if a.isalpha() and b.isalpha() and c.isalpha():
            if ord(a.lower()) + 1 == ord(b.lower()) and ord(b.lower()) + 1 == ord(c.lower()):
                weaknesses.append('Contains sequential alphabetical characters.')
                break

    # Too short
    if len(password) < 6:
        weaknesses.append('Password is too short (less than 6 characters).')

    # Mono-case alphabetic
    if password.isalpha() and (password.isupper() or password.islower()):
        weaknesses.append('Uses only one letter case.')

    return weaknesses
