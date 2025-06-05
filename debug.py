import json
import yaml
import argparse
from pathlib import Path

template = {
    "version": "0.2.0",
    "configurations": []
}

input_folder = Path(".cifuzz-findings/")

def main(args):
    cifuzz_confs = list(Path.cwd().rglob("cifuzz.yaml"))
    if not cifuzz_confs:
        print("Cannot find cifuzz.yaml")
        return
    
    cifuzz_conf = cifuzz_confs[0]
    with open(cifuzz_conf, 'r') as file:
        try:
            cifuzz_conf_data = yaml.safe_load(file)
        except yaml.YAMLError as e:
            print(f"Error parsing YAML file: {e}")
            return

    Path(".vscode").mkdir(parents=True, exist_ok=True)
    
    engine = cifuzz_conf_data["engine"] if "engine" in cifuzz_conf_data else "libfuzzer-clang"
    print("Engine:", engine)

    for folder_path in input_folder.iterdir():
        if folder_path.is_dir():
            finding_json = folder_path / "finding.json"
            if not finding_json.exists():
                print(f"Cannot find finding.json in {folder_path.name}")
                continue


            with finding_json.open('r') as file:
                finding_data = json.load(file)

            fuzz_test = finding_data["fuzz_test"]
            finding_id = finding_data["name"]

            crashing_input = folder_path / "crashing-input"

            if not crashing_input.exists():
                print(f"Cannot find crashing-input in {folder_path.name}")
                continue


            binary = (Path.cwd() / ".cifuzz/build" / engine / "address+undefined/cifuzz-spark" / fuzz_test).resolve()
            if not binary.exists():
                print(f"Cannot find binary for {binary}")
                continue

            print(fuzz_test, finding_id, crashing_input)

            config = {
                "name": f"{fuzz_test} | {finding_id}",
                "type": "cppdbg",
                "request": "launch",
                "program": binary.as_posix(),
                "args": [
                    crashing_input.absolute().resolve().as_posix()
                ],
                "cwd": "${workspaceFolder}",
                "environment": [
                    {
                        "name": "ASAN_SYMBOLIZER_PATH",
                        "value": "/usr/bin/llvm-symbolizer"
                    },
                    {
                        "name": "ASAN_OPTIONS",
                        "value": "halt_on_error=1:detect_leaks=0"
                    }
                ],
                "externalConsole": False,
                "MIMode": "gdb",
                "setupCommands": [
                    {
                        "description": "Enable pretty-printing for gdb",
                        "text": "-enable-pretty-printing",
                        "ignoreFailures": True
                    }
                ]
            }
            
            template["configurations"].append(config)

    output_file = Path(".vscode/launch.json")
    output_file.parent.mkdir(parents=True, exist_ok=True)

    with output_file.open('w') as f:
        json.dump(template, f, indent=4)

    print(f"Generated {output_file} with {len(template['configurations'])} configurations.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--corpus', action='store_true', help="Generate debug for corpus")
    
    args = parser.parse_args()
    main(args)
