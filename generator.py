"""
Target-Profile Aware Password Payload Generator
================================================
Generates targeted password candidates modeled around user profile attributes
(First Name, Last Name, Nickname, DOB, Birth Year, Favourite Word,
Favourite Number, Custom Keywords, Other Sample Info).

Designed exclusively for authorized cybersecurity education and credential audit labs.
Never store or crack real credentials.
"""

import itertools
import re
from typing import List, Dict, Optional, Set

LEET_MAP = {
    'a': ['@', '4'],
    'e': ['3'],
    'i': ['1', '!'],
    'o': ['0'],
    's': ['$', '5'],
    't': ['7'],
}

COMMON_SEPARATORS = ['', '_', '.', '@', '#', '-']
COMMON_TAILS = ['123', '!', '@', '#', '123!', '@123', '1!', '007']
MAX_GENERATION_LIMIT = 5000


def validate_profile_input(data: dict) -> dict:
    """
    Validates profile fields.
    'first_name' is required; all other fields are optional.
    """
    if not isinstance(data, dict):
        return {'valid': False, 'message': 'Invalid payload format. Expected JSON object.'}

    first_name = (data.get('first_name') or '').strip()
    if not first_name:
        return {'valid': False, 'message': 'First name is required.'}

    if len(first_name) > 50:
        return {'valid': False, 'message': 'First name cannot exceed 50 characters.'}

    return {'valid': True, 'message': 'Input is valid.'}


def parse_dob(dob_raw: str, birth_year_raw: str = '') -> Dict[str, str]:
    """
    Extracts date components: day, month, year, 2-digit year, full formats (DDMMYYYY, DDMM, etc.)
    Accepts formats like:
      - '29 12 2005'
      - '29/12/2005'
      - '29-12-2005'
      - '2005-12-29'
      - '29122005'
    """
    date_tokens = {}
    dob = (dob_raw or '').strip()
    year = (birth_year_raw or '').strip()

    # Extract digits
    digits = re.findall(r'\d+', dob)
    day = ""
    month = ""
    extracted_year = ""

    if len(digits) == 3:
        # Check if first is 4-digit (YYYY MM DD) or last is 4-digit (DD MM YYYY)
        if len(digits[0]) == 4:
            extracted_year, month, day = digits[0], digits[1].zfill(2), digits[2].zfill(2)
        else:
            day, month, extracted_year = digits[0].zfill(2), digits[1].zfill(2), digits[2]
    elif len(digits) == 1 and len(digits[0]) == 8:
        # e.g., 29122005
        day = digits[0][0:2]
        month = digits[0][2:4]
        extracted_year = digits[0][4:8]

    if not extracted_year and year:
        extracted_year = year

    # Normalise components
    if day:
        date_tokens['dd'] = day
    if month:
        date_tokens['mm'] = month
    if extracted_year:
        date_tokens['yyyy'] = extracted_year
        if len(extracted_year) == 4:
            date_tokens['yy'] = extracted_year[-2:]

    # Combined date strings
    if day and month and extracted_year:
        date_tokens['ddmmyyyy'] = f"{day}{month}{extracted_year}"
        date_tokens['ddmm'] = f"{day}{month}"
        if 'yy' in date_tokens:
            date_tokens['ddmmyy'] = f"{day}{month}{date_tokens['yy']}"
    elif extracted_year:
        date_tokens['year'] = extracted_year

    return date_tokens


def apply_case_variants(word: str) -> List[str]:
    """Generate case variations for a single word."""
    if not word:
        return []
    variants = {
        word.lower(),
        word.capitalize(),
        word.upper()
    }
    return list(variants)


def apply_leetspeak(word: str) -> List[str]:
    """Simple targeted leetspeak for given word."""
    if not word:
        return []
    w_low = word.lower()
    variants = set()

    # Full conversion
    leet_full = w_low
    for k, v in LEET_MAP.items():
        leet_full = leet_full.replace(k, v[0])
    if leet_full != w_low:
        variants.add(leet_full)
        variants.add(leet_full.capitalize())

    # Single char conversions
    for char, replacements in LEET_MAP.items():
        if char in w_low:
            for rep in replacements:
                variants.add(w_low.replace(char, rep))

    return list(variants)


def generate_profile_payloads(profile: dict, max_limit: int = MAX_GENERATION_LIMIT) -> dict:
    """
    Takes profile inputs and generates targeted password candidates categorized cleanly.
    """
    first_name = (profile.get('first_name') or '').strip()
    last_name = (profile.get('last_name') or '').strip()
    nickname = (profile.get('nickname') or '').strip()
    dob_raw = (profile.get('dob') or '').strip()
    birth_year = (profile.get('birth_year') or '').strip()
    fav_word = (profile.get('fav_word') or '').strip()
    fav_number = (profile.get('fav_number') or '').strip()
    other_info = (profile.get('other_info') or '').strip()
    
    # Custom keywords can be a list or multiline string
    custom_keywords = profile.get('custom_keywords', [])
    if isinstance(custom_keywords, str):
        custom_keywords = [k.strip() for k in custom_keywords.split('\n') if k.strip()]

    # Collect word entities
    primary_names = [n for n in [first_name, nickname, last_name] if n]
    secondary_words = [w for w in [fav_word, other_info] if w]
    secondary_words.extend([k for k in custom_keywords if k])

    # Date tokens
    date_info = parse_dob(dob_raw, birth_year)
    date_suffixes = []
    if 'ddmmyyyy' in date_info:
        date_suffixes.append(date_info['ddmmyyyy'])
    if 'ddmmyy' in date_info:
        date_suffixes.append(date_info['ddmmyy'])
    if 'ddmm' in date_info:
        date_suffixes.append(date_info['ddmm'])
    if 'yyyy' in date_info:
        date_suffixes.append(date_info['yyyy'])
    elif birth_year:
        date_suffixes.append(birth_year)

    # Number tokens
    number_suffixes = []
    if fav_number:
        number_suffixes.append(fav_number)
    for n in ['123', '12', '1', '2025', '2026', '007', '777', '999']:
        if n not in number_suffixes:
            number_suffixes.append(n)

    results_by_cat: Dict[str, Set[str]] = {
        'Direct Name & Identity': set(),
        'Name + Date of Birth': set(),
        'Full Name Combinations': set(),
        'Nickname Variations': set(),
        'Favourite Info Combinations': set(),
        'Custom Keyword Variations': set(),
        'Leetspeak & Special Chars': set(),
        'Common Audit Patterns': set(),
    }

    # 1. Direct Name & Identity
    for name in primary_names:
        for v in apply_case_variants(name):
            results_by_cat['Direct Name & Identity'].add(v)
            # Add simple numeric tails
            for num in ['123', '1', '2026']:
                results_by_cat['Direct Name & Identity'].add(f"{v}{num}")

    # 2. Name + Date of Birth (Exact requested feature)
    # e.g., yeswanth29122005, yeswanth2005, raj29122005, yesh29122005, yesh2005
    all_names_and_nicks = [n for n in [first_name, last_name, nickname] if n]
    for n in all_names_and_nicks:
        for d in date_suffixes:
            for sep in ['', '_', '@']:
                results_by_cat['Name + Date of Birth'].add(f"{n.lower()}{sep}{d}")
                results_by_cat['Name + Date of Birth'].add(f"{n.capitalize()}{sep}{d}")
            # With special chars at end
            results_by_cat['Name + Date of Birth'].add(f"{n.lower()}{d}!")
            results_by_cat['Name + Date of Birth'].add(f"{n.capitalize()}@{d}")

    # 3. Full Name Combinations (First + Last, Last + First, initials)
    # e.g., yeswanthraj, yeswanthraj29122005, rajyeswanth, yraj, yeswanth.r
    if first_name and last_name:
        fn_low, ln_low = first_name.lower(), last_name.lower()
        fn_cap, ln_cap = first_name.capitalize(), last_name.capitalize()
        f_init = fn_low[0]
        l_init = ln_low[0]

        combos = [
            f"{fn_low}{ln_low}",
            f"{fn_cap}{ln_cap}",
            f"{fn_cap}{ln_low}",
            f"{ln_low}{fn_low}",
            f"{f_init}{ln_low}",
            f"{fn_low}{l_init}",
            f"{fn_low}_{ln_low}",
            f"{fn_low}.{ln_low}",
        ]
        for c in combos:
            results_by_cat['Full Name Combinations'].add(c)
            # Combine with DOB suffixes
            for d in date_suffixes:
                for sep in ['', '_', '@']:
                    results_by_cat['Full Name Combinations'].add(f"{c}{sep}{d}")
            # Combine with favourite number
            if fav_number:
                results_by_cat['Full Name Combinations'].add(f"{c}{fav_number}")
                results_by_cat['Full Name Combinations'].add(f"{c}@{fav_number}")

    # 4. Nickname Variations (if provided)
    if nickname:
        nick_low = nickname.lower()
        nick_cap = nickname.capitalize()
        for d in date_suffixes:
            results_by_cat['Nickname Variations'].add(f"{nick_low}{d}")
            results_by_cat['Nickname Variations'].add(f"{nick_cap}{d}")
            results_by_cat['Nickname Variations'].add(f"{nick_low}_{d}")
            results_by_cat['Nickname Variations'].add(f"{nick_cap}@{d}")
        for num in number_suffixes[:5]:
            results_by_cat['Nickname Variations'].add(f"{nick_low}{num}")
            results_by_cat['Nickname Variations'].add(f"{nick_cap}#{num}")

    # 5. Favourite Info Combinations (Word, Number, Other info)
    for w in secondary_words:
        w_low = w.lower()
        w_cap = w.capitalize()
        results_by_cat['Favourite Info Combinations'].add(w_low)
        results_by_cat['Favourite Info Combinations'].add(w_cap)

        # Name + Fav Word
        if first_name:
            results_by_cat['Favourite Info Combinations'].add(f"{first_name.lower()}{w_low}")
            results_by_cat['Favourite Info Combinations'].add(f"{first_name.capitalize()}_{w_low}")

        # Fav word + Fav number / Date
        if fav_number:
            results_by_cat['Favourite Info Combinations'].add(f"{w_low}{fav_number}")
            results_by_cat['Favourite Info Combinations'].add(f"{w_cap}@{fav_number}")
        for d in date_suffixes[:2]:
            results_by_cat['Favourite Info Combinations'].add(f"{w_low}{d}")

    # 6. Custom Keywords
    for kw in custom_keywords:
        kw_clean = kw.strip()
        if not kw_clean:
            continue
        kw_low = kw_clean.lower()
        kw_cap = kw_clean.capitalize()
        results_by_cat['Custom Keyword Variations'].add(kw_low)
        results_by_cat['Custom Keyword Variations'].add(kw_cap)
        # Combine keyword with primary name
        if first_name:
            results_by_cat['Custom Keyword Variations'].add(f"{first_name.lower()}{kw_low}")
            results_by_cat['Custom Keyword Variations'].add(f"{kw_low}{first_name.lower()}")
            results_by_cat['Custom Keyword Variations'].add(f"{first_name.capitalize()}@{kw_low}")
        # Combine keyword with dates / numbers
        for d in date_suffixes[:2]:
            results_by_cat['Custom Keyword Variations'].add(f"{kw_low}{d}")
        if fav_number:
            results_by_cat['Custom Keyword Variations'].add(f"{kw_low}{fav_number}")

    # 7. Leetspeak & Special Characters
    base_pool = [first_name]
    if nickname:
        base_pool.append(nickname)
    if last_name:
        base_pool.append(last_name)

    for base in base_pool:
        leet_items = apply_leetspeak(base)
        for l in leet_items:
            results_by_cat['Leetspeak & Special Chars'].add(l)
            for d in date_suffixes[:2]:
                results_by_cat['Leetspeak & Special Chars'].add(f"{l}{d}")
            if fav_number:
                results_by_cat['Leetspeak & Special Chars'].add(f"{l}{fav_number}")
            for tail in ['!', '@123', '#1', '123']:
                results_by_cat['Leetspeak & Special Chars'].add(f"{l}{tail}")

    # 8. Common Audit Patterns (Standard corporate/lab compliance testing patterns)
    for base in [first_name.capitalize(), first_name.lower()]:
        for pattern in ['{base}123!', '{base}@123', 'Welcome@{base}', '{base}#2026', 'Password@{base}']:
            results_by_cat['Common Audit Patterns'].add(pattern.replace('{base}', base))
        if 'yyyy' in date_info:
            results_by_cat['Common Audit Patterns'].add(f"{base}@{date_info['yyyy']}")
            results_by_cat['Common Audit Patterns'].add(f"{base}_{date_info['yyyy']}")

    # Flatten, deduplicate, and preserve category tag
    all_candidates = []
    seen = set()

    for category, items in results_by_cat.items():
        for item in sorted(items):
            clean_item = item.strip()
            if clean_item and clean_item not in seen:
                seen.add(clean_item)
                all_candidates.append({
                    'text': clean_item,
                    'category': category
                })

    # Enforce limit
    if len(all_candidates) > max_limit:
        all_candidates = all_candidates[:max_limit]

    # Category counts
    final_counts = {}
    for c in all_candidates:
        cat = c['category']
        final_counts[cat] = final_counts.get(cat, 0) + 1

    return {
        'success': True,
        'message': f"Generated {len(all_candidates)} targeted password candidates.",
        'candidates': all_candidates,
        'total': len(all_candidates),
        'categories': final_counts
    }
