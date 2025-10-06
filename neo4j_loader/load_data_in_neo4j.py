import json
import sys
from mitreattack.stix20 import MitreAttackData
import requests
import dataclasses


@dataclasses.dataclass()
class Technique:
    id: str
    name: str
    description: str
    is_sub_technique: bool = False
    sub_techniques: list["Technique"] = dataclasses.field(default_factory=list)
    kill_chain_phases: list[dict] = dataclasses.field(default_factory=list)

    def __hash__(self):
        return hash(self.id)


@dataclasses.dataclass()
class Tactic:
    id: str
    name: str
    description: str
    techniques: list[Technique] = dataclasses.field(default_factory=list)

    def __hash__(self):
        return hash(self.id)


def get_latest_enterprise_attack_json() -> dict:
    url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    try:
        response = requests.get(url)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        print(f"[!] Failed to download data: {e}", file=sys.stderr)
        sys.exit(1)


def get_all_tactics(enterprise_attack_data: dict):
    tactics = set()
    mitre_tactics = [
        obj
        for obj in enterprise_attack_data.get("objects", [])
        if obj.get("type") == "x-mitre-tactic"
    ]

    for tactic in mitre_tactics:
        tactic_id = ""
        for refs in tactic.get("external_references", []):
            if refs.get("external_id"):
                tactic_id = refs["external_id"]
                tactics.add(
                    Tactic(
                        id=tactic_id,
                        name=tactic.get("name", ""),
                        description=tactic.get("description", "").strip(),
                    )
                )
                break
    return tactics


def get_all_techniques(enterprise_attack_data: dict):
    techniques = set()
    sub_techniques = set()
    mitre_techniques = [
        obj
        for obj in enterprise_attack_data.get("objects", [])
        if obj.get("type") == "attack-pattern"
    ]
    for technique in mitre_techniques:
        for refs in technique.get("external_references", []):
            if refs.get("external_id"):
                tech = Technique(
                    id=refs["external_id"],
                    name=technique.get("name", ""),
                    description=technique.get("description", "").strip(),
                    kill_chain_phases=technique.get("kill_chain_phases", []),
                )
                if technique.get("x_mitre_is_subtechnique", True):
                    tech.is_sub_technique = True
                    sub_techniques.add(tech)
                else:
                    tech.is_sub_technique = False
                    techniques.add(tech)
                break

    for tech in techniques:
        for sub_tech in sub_techniques:
            if sub_tech.id.startswith(tech.id + "."):
                tech.sub_techniques.append(sub_tech)
    return techniques




### FIX THIS
def correlate_tactics_and_techniques(tactics: set[Tactic], techniques: set[Technique]):
    for tech in techniques:
        for tactic in tactics:
            for phase in tech.kill_chain_phases:
                if phase.get("kill_chain_name") == "mitre-attack":
                    if tactic.name.lower() == phase.get("phase_name","").lower():
                        tactic.techniques.append(tech)
###


def main():
    """
    Main function to download and process MITRE ATT&CK data.
    """
    enterprise_attack_data: dict = get_latest_enterprise_attack_json()
    tactics = get_all_tactics(enterprise_attack_data=enterprise_attack_data)
    techniques = get_all_techniques(enterprise_attack_data=enterprise_attack_data)
    correlate_tactics_and_techniques(
        tactics=tactics, techniques=techniques
    )
    for tactic in sorted(tactics, key=lambda x: x.name):
        print(f"\nFound {len(tactic.techniques)} techniques for tactic '{tactic.name}':\n")
    

    # # You can now use the 'all_techniques' list.
    # # For example, let's print the first 3 techniques found.
    # print("\n--- Example Techniques ---")
    # # Sort by ID for consistent output
    # sorted_techniques = sorted(all_techniques, key=lambda x: x['id'])
    # for tech in sorted_techniques[:3]:
    #     print(json.dumps(tech, indent=2))
    #     print("-" * 20)

    # # You could also save the full list to a file
    # output_filename = "mitre_techniques.json"
    # with open(output_filename, "w") as f:
    #     json.dump(sorted_techniques, f, indent=2)
    # print(f"\n[*] All {len(sorted_techniques)} techniques saved to {output_filename}")


if __name__ == "__main__":
    main()
