from typing import List, Optional

import pefile
import yaml
import argparse


def find_entry_point_section(pe, eop_rva):
    for section in pe.sections:
        if section.contains_rva(eop_rva):
            return section

    return None


def pattern_search(data: bytes, pattern: List[Optional[int]]):
    results = []
    for i in range(0, len(data)):
        braked = False
        for j, pp in enumerate(pattern):
            if pp is None:
                continue
            if data[i+j] != pp:
                braked = True
                break
        if not braked:
            results.append(i)
    return results


def pattern_to_bytes(pattern: str) -> List[Optional[int]]:
    return list(map(lambda x: int(x, 16) if x != '?' else None, pattern.split()))


def parse_arguments(arguments):
    if not arguments:
        return '', f'out("eax") eax'

    fn_arguments, asm_arguments, asm_pushes = [], [], []
    for idx, argument in reversed(list(enumerate(arguments))):
        fn_arguments.append(
            f'{argument["name"]}: {argument["type"]}'
        )
        if idx == 0:
            asm_arguments.append(f'inout("eax") eax')
        elif idx == 1:
            asm_arguments.append(f'in("edx") {argument["name"]}')
        elif idx == 2:
            asm_arguments.append(f'in("ecx") {argument["name"]}')
        else:
            asm_pushes.append(f'push {{{argument["name"]}}}')
            asm_arguments.append(f'{argument["name"]} = in(reg) {argument["name"]}')
    return ', '.join(fn_arguments), ', '.join(asm_arguments), ', '.join(map(lambda x: f'"{x}"', asm_pushes)) \
                                                              + ',' if asm_pushes else ''


def main():
    parser = argparse.ArgumentParser(description="Simple binding generator.")
    parser.add_argument('--exe', required=True)
    parser.add_argument('--out', required=True)
    parser.add_argument('--conf', required=True)
    args = parser.parse_args()

    input = args.exe
    output = args.out
    config_file = args.conf

    with open(config_file, 'r') as f:
        config = yaml.safe_load(f)

    print(f"[INFO]    Input:  {input}.")
    print(f"[INFO]    Output: {output}.")
    print(f"[INFO]    Config: {config_file}")
    output = open(output, 'w')

    pe = pefile.PE(input, fast_load=True)
    eop = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    code_section = find_entry_point_section(pe, eop)
    if not code_section:
        return

    for idx, function in enumerate(config):
        fn_name = function['name']
        fn_pattern = function['pattern']
        args, asm_args, pushes = parse_arguments(function.get('arguments', []))

        print(f"[INFO]    Looking for pattern [{idx}]")
        res = pattern_search(code_section.get_data(), pattern_to_bytes(fn_pattern))
        if res:
            if len(res) > 1:
                print(f"[WARNING] Pattern was found more than once for pattern [{idx}]!")
                for occurrence in res:
                    print(f"\t- {hex(occurrence + 0x401000)}")
            output.write(f"""pub fn {fn_name}({args}) -> u32 {{ 
    let mut eax = {function['arguments'][0]['name'] if args else '0'} as u32;
    unsafe {{ asm! {{ {pushes}
        "call {{fn}}",
        fn = in(reg) {hex(res[0] + 0x401000)}, {asm_args}
    }} }};
    eax
}}

""")
            print(f'[INFO]    Found exactly one occurrence for pattern [{idx}] on address: {hex(res[0] + 0x401000)}!')
        else:
            print(f"[WARNING] Pattern [{0}] was not found!")

    output.close()
    print("[INFO]    Done!")


if __name__ == '__main__':
    main()
