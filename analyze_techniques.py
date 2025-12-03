#!/usr/bin/env python3
"""
Atomic Red Team Technique Counter
Analyzes techniques by tactic and platform from the /atomics directory
Outputs technique IDs for cross-framework comparison
"""

import yaml
import os
from pathlib import Path
from collections import defaultdict

# ============================================================================
# CONFIGURATION
# ============================================================================

# Path to the atomics directory
ATOMICS_DIR = Path('/home/user/atomic-red-team/atomics')
INDEX_FILE = ATOMICS_DIR / 'Indexes' / 'index.yaml'

# Platform categorization
CLOUD_PLATFORMS = {
    'azure-ad', 'office-365', 'google-workspace', 'saas',
    'iaas', 'iaas:aws', 'iaas:azure', 'iaas:gcp',
    'azure', 'aws', 'gcp', 'containers'
}
AD_PLATFORMS = {'windows', 'linux', 'macos'}

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def get_all_technique_directories():
    """Get all technique directories (T1234 or T1234.567 format)"""
    return set([
        d.name for d in ATOMICS_DIR.iterdir()
        if d.is_dir() and d.name.startswith('T') and len(d.name) > 1 and d.name[1].isdigit()
    ])

def sort_techniques(tech_list):
    """Sort technique IDs numerically (T1234.567)"""
    def sort_key(tech_id):
        parts = tech_id.replace('T', '').split('.')
        main = int(parts[0])
        sub = int(parts[1]) if len(parts) > 1 else 0
        return (main, sub)

    return sorted(tech_list, key=sort_key)

def get_technique_platforms(tech_id):
    """Get all platforms supported by a technique's atomic tests"""
    tech_dir = ATOMICS_DIR / tech_id
    yaml_file = tech_dir / f"{tech_id}.yaml"

    if not yaml_file.exists():
        return set()

    try:
        with open(yaml_file, 'r') as f:
            data = yaml.safe_load(f)

        # Collect all platforms from all atomic tests
        all_platforms = set()
        if data and 'atomic_tests' in data:
            for test in data['atomic_tests']:
                platforms = test.get('supported_platforms', [])
                all_platforms.update([p.lower() for p in platforms if p])

        return all_platforms
    except:
        return set()

def categorize_technique(tech_id):
    """Categorize technique as AD/On-Prem, Cloud, or Hybrid"""
    platforms = get_technique_platforms(tech_id)

    if not platforms:
        return 'unknown'

    has_cloud = bool(platforms & CLOUD_PLATFORMS)
    has_ad = bool(platforms & AD_PLATFORMS)

    if has_cloud and has_ad:
        return 'hybrid'
    elif has_cloud:
        return 'cloud'
    elif has_ad:
        return 'ad'
    else:
        return 'unknown'

# ============================================================================
# MAIN ANALYSIS
# ============================================================================

def main():
    print("=" * 70)
    print("ATOMIC RED TEAM TECHNIQUE ANALYSIS")
    print("=" * 70)

    # Step 1: Get all technique directories
    all_techniques = get_all_technique_directories()
    print(f"\nTotal techniques with atomic tests: {len(all_techniques)}")

    # Step 2: Load the index to get tactic mappings
    with open(INDEX_FILE, 'r') as f:
        index_data = yaml.safe_load(f)

    # Step 3: Count techniques by tactic (only those that exist)
    print("\n" + "=" * 70)
    print("TECHNIQUES BY TACTIC (Counts)")
    print("=" * 70)

    tactic_techniques = {}
    for tactic in ['reconnaissance', 'resource-development', 'initial-access',
                   'execution', 'persistence', 'privilege-escalation',
                   'defense-evasion', 'credential-access', 'discovery',
                   'lateral-movement', 'collection', 'command-and-control',
                   'exfiltration', 'impact']:

        if tactic in index_data and index_data[tactic]:
            # Get techniques listed in index for this tactic
            index_techniques = set(index_data[tactic].keys())
            # Only count those that actually exist in /atomics
            existing = sort_techniques(index_techniques & all_techniques)
            tactic_techniques[tactic] = existing

            # Format tactic name for display
            display_name = tactic.replace('-', ' ').title()
            print(f"{display_name}: {len(existing)}")
        else:
            tactic_techniques[tactic] = []

    # Step 4: Categorize all techniques by platform
    print("\n" + "=" * 70)
    print("TECHNIQUES BY PLATFORM (Counts)")
    print("=" * 70)

    ad_techniques = []
    cloud_techniques = []
    hybrid_techniques = []

    for tech_id in all_techniques:
        category = categorize_technique(tech_id)

        if category == 'ad':
            ad_techniques.append(tech_id)
        elif category == 'cloud':
            cloud_techniques.append(tech_id)
        elif category == 'hybrid':
            hybrid_techniques.append(tech_id)

    # Sort all platform categories
    ad_techniques = sort_techniques(ad_techniques)
    cloud_techniques = sort_techniques(cloud_techniques)
    hybrid_techniques = sort_techniques(hybrid_techniques)

    print(f"AD/On-Prem (Windows, Linux, macOS): {len(ad_techniques)}")
    print(f"Cloud (Azure, AWS, GCP, etc.): {len(cloud_techniques)}")
    print(f"Hybrid (Both AD and Cloud): {len(hybrid_techniques)}")

    # ========================================================================
    # OUTPUT TECHNIQUE IDS BY PLATFORM CATEGORY
    # ========================================================================
    print("\n" + "=" * 70)
    print("AD/ON-PREM TECHNIQUE IDs")
    print("=" * 70)
    for tech in ad_techniques:
        print(tech)

    print("\n" + "=" * 70)
    print("CLOUD TECHNIQUE IDs")
    print("=" * 70)
    for tech in cloud_techniques:
        print(tech)

    print("\n" + "=" * 70)
    print("HYBRID TECHNIQUE IDs")
    print("=" * 70)
    for tech in hybrid_techniques:
        print(tech)

    # ========================================================================
    # OUTPUT TECHNIQUE IDS BY TACTIC (Selected tactics)
    # ========================================================================
    print("\n" + "=" * 70)
    print("TECHNIQUE IDs BY TACTIC")
    print("=" * 70)

    # Output selected tactics of interest
    selected_tactics = [
        ('initial-access', 'Initial Access'),
        ('persistence', 'Persistence'),
        ('privilege-escalation', 'Privilege Escalation'),
        ('defense-evasion', 'Defense Evasion'),
        ('lateral-movement', 'Lateral Movement'),
        ('exfiltration', 'Exfiltration'),
        ('impact', 'Impact')
    ]

    for tactic_key, tactic_name in selected_tactics:
        if tactic_key in tactic_techniques and tactic_techniques[tactic_key]:
            print(f"\n{tactic_name} ({len(tactic_techniques[tactic_key])}):")
            for tech in tactic_techniques[tactic_key]:
                print(f"  {tech}")

if __name__ == '__main__':
    main()
