from typing import List, Optional

import pefile
import yaml
import argparse
import logging


logging.basicConfig(level=logging.INFO)


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
    for idx, argument in enumerate(arguments):
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
            asm_arguments.insert(0, f'{argument["name"]} = in(reg) {argument["name"]}')
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

    logging.info(f"\tInput:  {input}.")
    logging.info(f"\tOutput: {output}.")
    logging.info(f"\tConfig: {config_file}")
    output = open(output, 'w')

    pe = pefile.PE(input, fast_load=True)
    eop = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    code_section = find_entry_point_section(pe, eop)
    if not code_section:
        return

    found = []

    for imp in config['imports']:
        output.write(f'use {imp};\n')
    output.write('\n')

    for idx, function in enumerate(config['functions']):
        fn_name = function['name']
        fn_pattern = function['pattern']
        args, asm_args, pushes = parse_arguments(function.get('arguments', []))

        logging.info(f"\tLooking for pattern [{idx}]")
        res = pattern_search(code_section.get_data(), pattern_to_bytes(fn_pattern))
        if res:
            if len(res) > 1:
                logging.warning(f"\tPattern was found more than once for pattern [{idx}]!")
                for occurrence in res:
                    logging.warning(f"\t\t- {hex(occurrence + 0x401000)}")
            for address in res:
                if address in found:
                    logging.warning(f'\rAddress already found with another pattern: {address + 0x401000} [{idx}]')
                found.append(address)
            output.write(f"""#[inline(never)]
pub fn {fn_name}({args}) -> u32 {{ 
    let mut eax = {function['arguments'][0]['name'] if args else '0'} as u32;
    unsafe {{ asm! {{ {pushes}
        "call {{fn}}",
        fn = in(reg) {hex(res[0] + 0x401000)}, {asm_args}
    }} }};
    eax
}}

""")
            logging.info(f'\tFound exactly one occurrence for pattern [{idx}] on address: {hex(res[0] + 0x401000)}!')
        else:
            logging.warning(f"\tPattern [{0}] was not found!")

    output.close()
    logging.info(f'\tDone!')


if __name__ == '__main__':
    main()
