import json

from binaryninja import Architecture, RegisterInfo, IntrinsicInfo, InstructionInfo, CallingConvention, Settings
from binaryninja.enums import Endianness, FlagRole, LowLevelILFlagCondition
from binaryninja.types import Type
from binaryninja.log import log_error

from . import mc


__all__ = ['Avnera']


class Avnera(Architecture):
    name = 'avnera'
    endianness = Endianness.LittleEndian
    address_size = 2
    default_int_size = 1
    opcode_display_length = 6 # enough for a `MOVW [#abs], RbRa` fusion but not for wider ones

    regs = {
        'R0': RegisterInfo('R0', 1),
        'R1': RegisterInfo('R1', 1),
        'R2': RegisterInfo('R2', 1),
        'R3': RegisterInfo('R3', 1),
        'R4': RegisterInfo('R4', 1),
        'R5': RegisterInfo('R5', 1),
        'R6': RegisterInfo('R6', 1),
        'R7': RegisterInfo('R7', 1),
        'SP': RegisterInfo('SP', 2),
    }
    stack_pointer = 'SP'

    flags = [
        'Z',  # zero
        'C',  # carry
        'N',  # negative
        'B',  # register bank
        'F4', # flag 4
        'I',  # interrupt
        'F6', # flag 6
        'F7', # flag 7
    ]
    flag_roles = {
        'Z':  FlagRole.ZeroFlagRole,
        'C':  FlagRole.CarryFlagRole,
        'N':  FlagRole.NegativeSignFlagRole,
        'B':  FlagRole.SpecialFlagRole,
        'F4': FlagRole.SpecialFlagRole,
        'I':  FlagRole.SpecialFlagRole,
        'F6': FlagRole.SpecialFlagRole,
        'F7': FlagRole.SpecialFlagRole,
    }
    flag_write_types = [
        'Z',
        'C',
        'CN',
    ]
    flags_written_by_flag_write_type = {
        'Z':  ['Z'],
        'C':  ['C'],
        'CN': ['C', 'N'],
    }

    def get_instruction_info(self, data, addr):
        try:
            if decoded := mc.decode(data, addr):
                info = InstructionInfo()
                decoded.analyze(info, addr)
                return info
        except Exception as exc:
            log_error(f'Avnera.get_instruction_info() failed at {addr:#x}: {exc}')

    def get_instruction_text(self, data, addr):
        try:
            if decoded := mc.decode(data, addr):
                encoded = data[:decoded.length()]
                recoded = mc.encode(decoded, addr)
                if encoded != recoded:
                    log_error('Instruction roundtrip error:')
                    log_error(''.join(str(token) for token in decoded.render()))
                    log_error('Old: {}'.format(encoded.hex()))
                    log_error('New: {}'.format(recoded.hex()))
                return decoded.render(), decoded.length()
        except Exception as exc:
            log_error(f'Avnera.get_instruction_text() failed at {addr:#x}: {exc}')

    def get_instruction_low_level_il(self, data, addr, il):
        try:
            if decoded := mc.decode(data, addr):
                decoded.lift(il, addr)
                return decoded.length()
        except Exception as exc:
            log_error(f'Avnera.get_instruction_low_level_il() failed at {addr:#x}: {exc}')

    def convert_to_nop(self, data, addr):
        # MOV R0, R0
        # Note that this instruction changes ZF.
        return b'\x70' * len(data)


class AvneraCCallingConvention(CallingConvention):
    caller_saved_regs = ['R7', 'R6']
    int_arg_regs = ['R5', 'R4', 'R3', 'R2', 'R1', 'R0']
    int_return_reg = 'R0'
    high_int_return_reg = 'R1'


Avnera.register()
arch = Architecture['avnera'] # waiting on Vector35/binaryninja-api#5457
arch.register_calling_convention(AvneraCCallingConvention(arch, 'default'))

settings = Settings()
settings.register_setting("arch.avnera.disassembly.pseudoOps", json.dumps({
    'title': 'Avnera Disassembly Pseudo-Op',
    'description': 'Enable use of pseudo-op instructions (MOVW, MOVP, LSL) in Avnera disassembly. Be aware that disabling this setting will impair lifting.',
    'type': 'boolean',
    'default': True
}))
