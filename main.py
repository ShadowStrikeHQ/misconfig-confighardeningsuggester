import argparse
import logging
import os
import subprocess
import sys
import json
import yaml

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class ConfigHardeningSuggester:
    """
    Analyzes configuration files and suggests security hardening measures.
    """

    def __init__(self):
        """
        Initializes the ConfigHardeningSuggester.
        """
        self.rules = self._load_rules()  # Load hardening rules from a file
        self.logger = logging.getLogger(__name__)

    def _load_rules(self, rules_file="rules.json"):
        """
        Loads hardening rules from a JSON file.

        Args:
            rules_file (str): The path to the JSON rules file.

        Returns:
            dict: A dictionary containing the hardening rules.
        """
        try:
            with open(rules_file, "r") as f:
                rules = json.load(f)
            self.logger.info(f"Loaded rules from {rules_file}")
            return rules
        except FileNotFoundError:
            self.logger.error(f"Rules file not found: {rules_file}")
            print(f"Error: Rules file not found: {rules_file}")
            sys.exit(1)  # Exit if rules file is essential
        except json.JSONDecodeError as e:
            self.logger.error(f"Error decoding JSON in {rules_file}: {e}")
            print(f"Error: Invalid JSON in rules file: {rules_file}")
            sys.exit(1)
        except Exception as e:
            self.logger.error(f"Error loading rules: {e}")
            print(f"Error loading rules: {e}")
            sys.exit(1)

    def _run_linter(self, file_path, linter_type):
        """
        Runs yamllint or jsonlint on the file.

        Args:
            file_path (str): The path to the configuration file.
            linter_type (str): The type of linter to run ("yaml" or "json").

        Returns:
            tuple: A tuple containing the return code and the output of the linter.
        """
        try:
            if linter_type == "yaml":
                command = ["yamllint", file_path]
            elif linter_type == "json":
                command = ["jsonlint", file_path]
            else:
                self.logger.error(f"Unsupported linter type: {linter_type}")
                return 1, f"Unsupported linter type: {linter_type}"

            result = subprocess.run(command, capture_output=True, text=True, check=False) #check=False prevents raising exception if linter fails

            if result.returncode != 0:
                self.logger.warning(f"{linter_type.capitalize()}lint found issues in {file_path}:\n{result.stderr}")

            return result.returncode, result.stdout + result.stderr

        except FileNotFoundError as e:
            self.logger.error(f"Linter not found: {e}")
            print(f"Error: Linter not found. Please ensure yamllint or jsonlint is installed.")
            sys.exit(1)
        except Exception as e:
            self.logger.error(f"Error running linter: {e}")
            return 1, f"Error running linter: {e}"


    def analyze_config(self, file_path):
        """
        Analyzes a configuration file and suggests hardening measures.

        Args:
            file_path (str): The path to the configuration file.

        Returns:
            list: A list of hardening suggestions.
        """
        try:
            # Determine file type and load the content
            file_extension = os.path.splitext(file_path)[1].lower()

            if file_extension in [".yaml", ".yml"]:
                try:
                    with open(file_path, "r") as f:
                        config_data = yaml.safe_load(f)
                    self._run_linter(file_path, "yaml")  # Run yamllint
                except yaml.YAMLError as e:
                    self.logger.error(f"Error parsing YAML file {file_path}: {e}")
                    print(f"Error: Invalid YAML file: {file_path}")
                    return ["YAML Parse Error: Please check the file for syntax errors."]
                except Exception as e:
                    self.logger.error(f"Error loading YAML file {file_path}: {e}")
                    print(f"Error: Error loading YAML file: {file_path}")
                    return ["Error loading file. Please check permissions and format."]

            elif file_extension == ".json":
                try:
                    with open(file_path, "r") as f:
                        config_data = json.load(f)
                    self._run_linter(file_path, "json") # Run jsonlint
                except json.JSONDecodeError as e:
                    self.logger.error(f"Error parsing JSON file {file_path}: {e}")
                    print(f"Error: Invalid JSON file: {file_path}")
                    return ["JSON Parse Error: Please check the file for syntax errors."]
                except Exception as e:
                    self.logger.error(f"Error loading JSON file {file_path}: {e}")
                    print(f"Error: Error loading JSON file: {file_path}")
                    return ["Error loading file. Please check permissions and format."]
            else:
                self.logger.warning(f"Unsupported file type: {file_extension}")
                print(f"Warning: Unsupported file type: {file_extension}")
                return [f"Unsupported file type: {file_extension}"]

            # Apply hardening rules based on the loaded data
            suggestions = []
            for rule_name, rule_details in self.rules.items():
                if rule_details["type"] == "key_check":
                    key_path = rule_details["key_path"]
                    current_data = config_data
                    try:
                        for key in key_path.split("."):  # Assumes dot notation for nested keys
                            if key in current_data:
                                current_data = current_data[key]
                            else:
                                current_data = None # Key not found
                                break # exit loop for checking nested keys
                    except:
                        current_data = None # Error occured while accessing the config_data

                    if current_data is None: # Key doesn't exist; Suggest adding it

                        suggestion_text = f"Missing key: {key_path}. Suggestion: {rule_details['suggestion']}"
                        suggestions.append(suggestion_text)
                        self.logger.info(suggestion_text)

                    else: # Key exists. Check its value

                        if "value_check" in rule_details:
                            expected_value = rule_details["value_check"]

                            if isinstance(expected_value, list): # multiple values accepted
                                if current_data not in expected_value:
                                    suggestion_text = f"Value for key: {key_path} is: {current_data}. Suggestion: {rule_details['suggestion']}"
                                    suggestions.append(suggestion_text)
                                    self.logger.info(suggestion_text)
                            else:
                                if current_data != expected_value:
                                    suggestion_text = f"Value for key: {key_path} is: {current_data}. Suggestion: {rule_details['suggestion']}"
                                    suggestions.append(suggestion_text)
                                    self.logger.info(suggestion_text)



            return suggestions

        except Exception as e:
            self.logger.error(f"Error analyzing config file {file_path}: {e}")
            print(f"Error analyzing config file: {e}")
            return ["An unexpected error occurred during analysis."]


def setup_argparse():
    """
    Sets up the argparse for the command-line interface.

    Returns:
        argparse.ArgumentParser: The argument parser.
    """
    parser = argparse.ArgumentParser(description="Analyzes configuration files and suggests security hardening measures.")
    parser.add_argument("config_file", help="Path to the configuration file to analyze.")
    parser.add_argument("--rules", help="Path to the hardening rules JSON file. Defaults to rules.json", default="rules.json") # Added argument for rules file
    return parser


def main():
    """
    Main function to run the ConfigHardeningSuggester.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    # Input validation
    if not os.path.isfile(args.config_file):
        print(f"Error: Config file not found: {args.config_file}")
        logging.error(f"Config file not found: {args.config_file}")
        sys.exit(1)

    # Initialize ConfigHardeningSuggester with rules file from CLI
    suggester = ConfigHardeningSuggester()
    suggester.rules = suggester._load_rules(args.rules)


    suggestions = suggester.analyze_config(args.config_file)

    if suggestions:
        print("Security Hardening Suggestions:")
        for suggestion in suggestions:
            print(f"- {suggestion}")
    else:
        print("No security hardening suggestions found.")


if __name__ == "__main__":
    # Example usage (simulated rules file)
    # Create a dummy rules.json file if it doesn't exist for the example to work
    if not os.path.exists("rules.json"):
        dummy_rules = {
            "example_rule": {
                "type": "key_check",
                "key_path": "security.firewall_enabled",
                "value_check": True,
                "suggestion": "Ensure the firewall is enabled for enhanced security."
            }
        }
        with open("rules.json", "w") as f:
            json.dump(dummy_rules, f, indent=4)
    main()