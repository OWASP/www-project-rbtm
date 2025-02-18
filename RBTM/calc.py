import csv
import re

# Define the severity for each vulnerability
vuln_score = {
    'V1': 1, 'V2': 1, 'V3': 1, 'V4': 3, 'V5': 2, 'V6': 2, 'V7': 3, 'V8': 3, 'V9': 2,
    'V10': 3, 'V11': 2, 'V12': 2, 'V13': 1, 'V14': 1, 'V15': 3, 'V16': 3, 'V17': 2,
    'V18': 3, 'V19': 2, 'V20': 3, 'V21': 3, 'V22': 2, 'V23': 3, 'V24': 3, 'V25': 1,
    'V26': 3, 'V27': 2, 'P1': 1, 'P2': 3, 'P3': 1, 'P4': 1, 'P5': 1, 'P6': 1
}

def parse_csv(file_path):
    groups = []
    current_group = None
    headers = []
    is_header = False

    with open(file_path, 'r', encoding='utf-8-sig') as f:
        lines = f.readlines()

    for line_num, line in enumerate(lines, 1):
        line = line.strip()
        if not line:
            continue  # Skip empty lines
        if line.startswith('<p>') and line.endswith('</p>'):
            # Extract the group name between <p> and </p>
            match = re.search(r'<p>(.*?)</p>', line)
            if match:
                group_name = match.group(1).strip()
                current_group = {
                    'name': group_name,
                    'team': 'Blue' if 'Blue' in group_name else 'Red',
                    'entries': []
                }
                groups.append(current_group)
                is_header = True
            continue
        elif is_header:
            # Use csv.reader to parse the header line
            headers = next(csv.reader([line]))
            is_header = False
            continue
        elif current_group is not None:
            # Use csv.reader to parse the data line
            data = next(csv.reader([line]))
            # Fill missing fields with empty strings
            while len(data) < len(headers):
                data.append('')
            entry = dict(zip(headers, data))
            current_group['entries'].append(entry)
        else:
            continue  # Skip lines until a group is found
    return groups

def calculate_scores(groups):
    results = {}
    penalty_factor = 0.7  # Reduced penalty factor for better balance

    # Pair Blue and Red groups
    group_pairs = {}
    for group in groups:
        # Use regex to extract the group number from the group name
        match = re.search(r'\d+', group['name'])
        if match:
            group_id = match.group(0)
        else:
            continue  # Skip if no group ID is found
        if group_id not in group_pairs:
            group_pairs[group_id] = {}
        group_pairs[group_id][group['team']] = group

    for group_id, teams in group_pairs.items():
        blue_team = teams.get('Blue')
        red_team = teams.get('Red')
        if not blue_team or not red_team:
            continue  # Skip if either team is missing

        # Extract selected vulnerabilities for Blue team
        blue_vulns = set()
        for entry in blue_team['entries']:
            selected = entry.get('Selected?', '').strip().lower()
            if selected == 'x':
                vulns = [vuln.strip() for vuln in entry['Related Vulnerabilities'].split(',')]
                blue_vulns.update(vulns)

        # Extract selected vulnerabilities for Red team
        red_vulns = set()
        for entry in red_team['entries']:
            selected = entry.get('Selected?', '').strip().lower()
            if selected == 'x':
                vulns = [vuln.strip() for vuln in entry['Related Vulnerabilities'].split(',')]
                red_vulns.update(vulns)

        # Calculate scores
        common_vulns = blue_vulns & red_vulns
        red_only_vulns = red_vulns - blue_vulns

        # Blue Score: Points from common vulnerabilities minus adjusted penalty
        blue_score = sum(vuln_score.get(vuln, 0) for vuln in common_vulns)
        blue_penalty = sum(vuln_score.get(vuln, 0) for vuln in red_only_vulns) * penalty_factor
        blue_score -= blue_penalty
        blue_score = max(0, blue_score)  # Ensure score isn't negative

        # Red Score: Points from Red-only vulnerabilities
        red_score = sum(vuln_score.get(vuln, 0) for vuln in red_only_vulns)

        # Determine the winner
        if blue_score > red_score:
            winner = 'Blue'
        elif red_score > blue_score:
            winner = 'Red'
        else:
            winner = 'Tie'

        # Store the results
        results[group_id] = {
            'Blue Score': round(blue_score, 1),  # Rounded for readability
            'Red Score': round(red_score, 1),  # Rounded for readability
            'Winner': winner
        }

    return results


def main():
    file_path = 'rbtm/example_rbtm.csv'  # Replace with your CSV file name
    groups = parse_csv(file_path)
    results = calculate_scores(groups)

    # Display the results
    for group_id in sorted(results.keys(), key=int):
        result = results[group_id]
        print(f"Group {group_id}:")
        print(f"  Blue Score: {result['Blue Score']}")
        print(f"  Red Score: {result['Red Score']}")
        print(f"  Winner: {result['Winner']}\n")

if __name__ == '__main__':
    main()
