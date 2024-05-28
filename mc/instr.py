from binaryninja.enums import BranchType
from binaryninja.lowlevelil import LowLevelILLabel, LLIL_TEMP

from .tokens import *


__all__ = ['Instruction']


class Operand:
    def render(self):
        return asm(('text', 'unimplemented'))

    def lift(self, il):
        return il.unimplemented()

    def lift_assign(self, il, value):
        il.append(value)
        il.append(il.unimplemented())


class Instruction:
    opcodes = {}

    def __new__(cls, *args, decoder=None):
        if decoder is None:
            return object.__new__(cls)
        else:
            opcode = decoder.peek(0)
            if opcode in cls.opcodes:
                return object.__new__(cls.opcodes[opcode])
            else:
                return None

    def length(self):
        return 1

    def name(self):
        return type(self).__name__.split('_')[0] # slightly cursed

    def decode(self, decoder, addr):
        self.opcode = decoder.unsigned_byte()

    def encode(self, encoder, addr):
        encoder = encoder.unsigned_byte(self.opcode)

    def fuse(self, sister):
        return None

    def operands(self):
        yield from ()

    def render(self):
        tokens = asm(
            ('instr', self.name()),
            ('opsep', ' ' * (6 - len(self.name())))
        )
        for index, operand in enumerate(self.operands()):
            if index > 0:
                tokens += asm(('opsep', ', '))
            tokens += operand.render()
        return tokens

    def display(self, addr):
        print(f'{addr:04X}:\t' + ''.join(str(token) for token in self.render()))

    def analyze(self, info, addr):
        info.length += self.length()

    def lift(self, il, addr):
        operands = tuple(self.operands())
        if len(operands) == 0:
            il.append(il.unimplemented())
        else:
            il_value = self.lift_operation(il, *(operand.lift(il) for operand in operands))
            operands[0].lift_assign(il, il_value)

    def lift_operation(self, il, *il_operands):
        return il.unimplemented()


class PseudoInstruction(Instruction):
    def __init__(self, *parts):
        self.parts = parts

    def __len__(self):
        return len(self.parts)

    def __getitem__(self, index):
        return self.parts[index]

    def length(self):
        return sum(part.length() for part in self)

    def decode(self, decoder, addr):
        raise TypeError('Cannot decode pseudoinstructions')

    def encode(self, encoder, addr):
        for part in self:
            part.encode(encoder, addr)
            addr += part.length()


class Reg8Operand:
    def __init__(self, reg):
        self._reg = reg

    def render(self):
        return asm(('reg', self._reg))

    def lift(self, il):
        return il.reg(1, self._reg)

    def lift_assign(self, il, value):
        # 0000c0b9  e8f1b0             MOV   R0, [data_b0f1]
        # 0000c0bc  98fb               JNZ   #C0B9
        il.append(il.set_reg(1, self._reg, value, 'Z'))


class InstrHasReg8:
    @property
    def reg(self):
        return f'R{self.opcode & 7}'


class Reg16Operand:
    def __init__(self, regs):
        self._regs = regs

    def render(self):
        return asm(('reg', ''.join(self._regs)))

    def lift(self, il):
        return il.reg_split(1, *self._regs)

    def lift_assign(self, il, value):
        il.append(il.set_reg_split(1, *self._regs, value))
        il.append(il.set_flag('Z', il.compare_equal(1, il.reg(1, self._regs[-1]), il.const(1, 0))))


class InstrHasReg16:
    @property
    def regs(self):
        # This matches how invalid encodings seem to be processed.
        return f'R{self.opcode & 7 | 1}', f'R{self.opcode & 7}'


class InstrHasFlag:
    @property
    def flag(self):
        return ['Z', 'C', 'N', 'B', 'F4', 'I', 'F6', 'F7'][self.opcode & 7]


class FlagOperand:
    def __init__(self, flag):
        self._flag = flag

    def render(self):
        return asm(('reg', self._flag))

    def lift(self, il):
        return il.flag(self._flag)

    def lift_assign(self, il, value):
        il.append(il.set_flag(self._flag, value))


class InstrHasImm:
    def length(self):
        return super().length() + 1

    def decode(self, decoder, addr):
        super().decode(decoder, addr)
        self.imm = decoder.unsigned_byte()

    def encode(self, encoder, addr):
        super().encode(encoder, addr)
        encoder.unsigned_byte(self.imm)


class ImmOperand:
    def __init__(self, imm, *, width=1):
        self._imm = imm
        self._width = width

    def render(self):
        if self._width == 1:
            return asm(('int',  f'#{self._imm:02X}', self._imm))
        if self._width == 2:
            return asm(('addr', f'#{self._imm:04X}', self._imm))
        assert False

    def lift(self, il):
        return il.const(self._width, self._imm)


class InstrHasAbs:
    def length(self):
        return super().length() + 2

    def decode(self, decoder, addr):
        super().decode(decoder, addr)
        self.addr = decoder.unsigned_word()

    def encode(self, encoder, addr):
        super().encode(encoder, addr)
        encoder.unsigned_word(self.addr)


class MemAbsOperand:
    def __init__(self, addr, *, width=1):
        self._addr = addr
        self._width = width

    def render(self):
        return asm(
            ('begmem', '['),
            ('addr',   f'#{self._addr:04X}', self._addr),
            ('endmem', ']')
        )

    def lift(self, il):
        return il.load(self._width, il.const_pointer(2, self._addr))

    def lift_assign(self, il, value):
        il.append(il.store(self._width, il.const_pointer(2, self._addr), value))


class MemRegOperand:
    def __init__(self, regs, *, width=1):
        self._regs = regs
        self._width = width

    def render(self):
        return asm(
            ('begmem', '['),
            ('reg',    ''.join(self._regs)),
            ('endmem', ']')
        )

    def lift(self, il):
        return il.load(self._width, il.reg_split(1, *self._regs))

    def lift_assign(self, il, value):
        il.append(il.store(self._width, il.reg_split(1, *self._regs), value))


class MemIdxOperand:
    def __init__(self, regs, off):
        self._regs = regs
        self._off = off

    def render(self):
        return asm(
            ('begmem', '['),
            ('reg',    ''.join(self._regs)),
            ('opsep',  '+'),
            ('int',    f'{self._off}', self._off),
            ('endmem', ']'),
        )

    def lift(self, il):
        return il.load(1, il.add(2, il.reg_split(1, *self._regs), il.const(2, self._off)))

    def lift_assign(self, il, value):
        il.append(il.store(1, il.add(2, il.reg_split(1, *self._regs), il.const(2, self._off)), value))


class CodeOperand:
    def __init__(self, pc):
        self._pc = pc

    def render(self):
        return asm(('addr', f'#{self._pc:04X}', self._pc))


class PseudoHasReg16:
    @property
    def regs(self):
        if self[0].reg > self[1].reg:
            return (self[0].reg, self[1].reg)
        else:
            return (self[1].reg, self[0].reg)


class PseudoHasAbs:
    @property
    def addr(self):
        return min(self[0].addr, self[1].addr)


class UnaryInstruction(Instruction):
    def operands(self):
        yield Reg8Operand(self.reg)


class BinaryInstruction(Instruction):
    def operands(self):
        yield Reg8Operand('R0')
        yield Reg8Operand(self.reg)


class INC(InstrHasReg8, UnaryInstruction):
    def lift_operation(self, il, il_arg):
        return il.add(1, il_arg, il.const(1, 1), 'CN')


class ADDC(InstrHasReg8, BinaryInstruction):
    def lift_operation(self, il, il_arg1, il_arg2):
        return il.add(1, il_arg1, il.add(1, il_arg2, il.flag('C')), 'CN')


class ADD(InstrHasReg8, BinaryInstruction):
    def fuse(self, sister):
        if self.reg == 'R0' and isinstance(sister, RLC) and sister.reg != 'R0':
            return LSL(self, sister)

    def lift_operation(self, il, il_arg1, il_arg2):
        return il.add(1, il_arg1, il_arg2, 'CN')


class LSL(PseudoInstruction):
    @property
    def regs(self):
        return self[1].reg, 'R0'

    def operands(self):
        yield Reg16Operand(self.regs)

    def lift_operation(self, il, il_arg):
        return il.shift_left(2, il_arg, il.const(1, 1), 'C')


class DEC(InstrHasReg8, UnaryInstruction):
    def lift_operation(self, il, il_arg):
        return il.sub(1, il_arg, il.const(1, 1), 'CN')

    def lift(self, il, addr):
        super().lift(il, addr)
        il.append(il.set_flag('C', il.not_expr(1, il.flag('C')))) # borrow -> carry


class SUBB(InstrHasReg8, BinaryInstruction):
    def lift_operation(self, il, il_arg1, il_arg2):
        return il.sub(1, il_arg1, il.add(1, il_arg2, il.flag('C')), 'CN') # carry -> borrow

    def lift(self, il, addr):
        super().lift(il, addr)
        il.append(il.set_flag('C', il.not_expr(1, il.flag('C')))) # borrow -> carry


class RLC(InstrHasReg8, UnaryInstruction):
    def lift(self, il, addr):
        temp = LLIL_TEMP(il.temp_reg_count)
        il.append(il.set_reg(1, temp, il.test_bit(1, il.reg(1, self.reg), il.const(1, 1 << 7))))
        result = il.rotate_left_carry(1, il.reg(1, self.reg), il.const(1, 1), il.flag('C'))
        il.append(il.set_reg(1, self.reg, result, 'Z'))
        il.append(il.set_flag('C', il.reg(1, temp)))


class RRC(InstrHasReg8, UnaryInstruction):
    def lift(self, il, addr):
        temp = LLIL_TEMP(il.temp_reg_count)
        il.append(il.set_reg(1, temp, il.test_bit(1, il.reg(1, self.reg), il.const(1, 1 << 0))))
        result = il.rotate_right_carry(1, il.reg(1, self.reg), il.const(1, 1), il.flag('C'))
        il.append(il.set_reg(1, self.reg, result, 'Z'))
        il.append(il.set_flag('C', il.reg(1, temp)))


class OR(InstrHasReg8, BinaryInstruction):
    def lift_operation(self, il, il_arg1, il_arg2):
        return il.or_expr(1, il_arg1, il_arg2)

    def lift(self, il, addr):
        if self.reg == 'R1': # `OR R0, R1` -> `Z = R1:R0 == 0`
            il.append(il.set_flag('Z', il.compare_equal(1, il.reg_split(1, 'R1', 'R0'), il.const(2, 0))))
            il.append(il.set_reg(1, 'R0', il.or_expr(1, il.reg(1, 'R0'), il.reg(1, 'R1'))))
        else:
            super().lift(il, addr)


class AND(InstrHasReg8, BinaryInstruction):
    def lift_operation(self, il, il_arg1, il_arg2):
        return il.and_expr(1, il_arg1, il_arg2)


class XOR(InstrHasReg8, BinaryInstruction):
    def lift_operation(self, il, il_arg1, il_arg2):
        return il.xor_expr(1, il_arg1, il_arg2)


class BIT(Instruction):
    @property
    def bit(self):
        return self.opcode & 0x7

    def render(self):
        return Instruction.render(self) + asm(
            ('reg',    'R0'),
            ('opsep',  ', '),
            ('int',    f'{self.bit}', self.bit),
        )

    def lift(self, il, addr):
        il.append(il.set_flag('Z', il.test_bit(1, il.reg(1, 'R0'), il.const(1, 1 << self.bit))))


class CMP(InstrHasReg8, BinaryInstruction):
    def lift(self, il, addr):
        il.append(il.sub(1, il.reg(1, 'R0'), il.reg(1, self.reg), 'CN'))
        il.append(il.set_flag('C', il.not_expr(1, il.flag('C')))) # borrow -> carry
        il.append(il.set_flag('Z', il.compare_equal(1, il.reg(1, 'R0'), il.reg(1, self.reg))))


class FlagInstruction(InstrHasFlag, Instruction):
    def operands(self):
        yield FlagOperand(self.flag)


class SET(FlagInstruction):
    def name(self):
        return 'SET'

    def lift_operation(self, il, il_flag):
        return il.const(1, 1)


class CLR(FlagInstruction):
    def name(self):
        return 'CLR'

    def lift_operation(self, il, il_flag):
        return il.const(1, 0)


class INC_Reg16(InstrHasReg16, Instruction):
    def name(self):
        return 'INC'

    def operands(self):
        yield Reg16Operand(self.regs)

    def lift_operation(self, il, il_arg):
        # FIXME: completely unclear how flags work here
        return il.add(2, il_arg, il.const(2, 1))


class MoveInstruction(Instruction):
    def lift_operation(self, il, il_dest, il_src):
        return il_src


class MovePseudoInstruction(PseudoInstruction):
    def lift_operation(self, il, il_dest, il_src):
        return il_src


class MOVP(MovePseudoInstruction):
    def operands(self):
        ld_operands = tuple(self[0].operands())
        st_operands = tuple(self[1].operands())
        yield st_operands[0]
        yield ld_operands[1]

    def lift(self, il, addr):
        super().lift(il, addr)
        st_operands = tuple(self[1].operands())
        il.append(il.set_flag('Z', il.compare_equal(1, st_operands[1].lift(il), il.const(1, 0))))


class MOV_R0_Reg(InstrHasReg8, MoveInstruction):
    def operands(self):
        yield Reg8Operand('R0')
        yield Reg8Operand(self.reg)


class MOV_Reg_R0(InstrHasReg8, MoveInstruction):
    def operands(self):
        yield Reg8Operand(self.reg)
        yield Reg8Operand('R0')


class MOV_Reg_Imm(InstrHasImm, InstrHasReg8, MoveInstruction):
    def fuse(self, sister):
        if isinstance(sister, MOV_Reg_Imm) and self.opcode ^ sister.opcode == 1:
            return MOVW_Reg_Imm(self, sister)
        if isinstance(sister, MOV_MemAbs_Reg) and sister.reg == 'R0':
            return MOVP(self, sister)

    def operands(self):
        yield Reg8Operand(self.reg)
        yield ImmOperand(self.imm)


class MOVW_Reg_Imm(PseudoHasReg16, MovePseudoInstruction):
    @property
    def imm(self):
        if self[0].reg > self[1].reg:
            return self[0].imm << 8 | self[1].imm
        else:
            return self[1].imm << 8 | self[0].imm

    def operands(self):
        yield Reg16Operand(self.regs)
        yield ImmOperand(self.imm, width=2)


class MOV_R0_MemReg(InstrHasReg16, MoveInstruction):
    def operands(self):
        yield Reg8Operand('R0')
        yield MemRegOperand(self.regs)


class MOV_MemReg_R0(InstrHasReg16, MoveInstruction):
    def operands(self):
        yield MemRegOperand(self.regs)
        yield Reg8Operand('R0')


class MOV_Reg_MemAbs(InstrHasAbs, InstrHasReg8, MoveInstruction):
    def fuse(self, sister):
        if (isinstance(sister, MOV_Reg_MemAbs) and
                self.opcode ^ sister.opcode == 1 and abs(self.addr - sister.addr) == 1 and
                (self.reg > sister.reg) == (self.addr > sister.addr)):
            return MOVW_Reg_MemAbs(self, sister)

    def operands(self):
        yield Reg8Operand(self.reg)
        yield MemAbsOperand(self.addr)


class MOV_MemAbs_Reg(InstrHasAbs, InstrHasReg8, MoveInstruction):
    def fuse(self, sister):
        if (isinstance(sister, MOV_MemAbs_Reg) and
                self.opcode ^ sister.opcode == 1 and abs(self.addr - sister.addr) == 1 and
                (self.reg > sister.reg) == (self.addr > sister.addr)):
            return MOVW_MemAbs_Reg(self, sister)

    def operands(self):
        yield MemAbsOperand(self.addr)
        yield Reg8Operand(self.reg)


class MOVW_Reg_MemAbs(PseudoHasAbs, PseudoHasReg16, MovePseudoInstruction):
    def operands(self):
        yield Reg16Operand(self.regs)
        yield MemAbsOperand(self.addr, width=2)


class MOVW_MemAbs_Reg(PseudoHasAbs, PseudoHasReg16, MovePseudoInstruction):
    def operands(self):
        yield MemAbsOperand(self.addr, width=2)
        yield Reg16Operand(self.regs)


class MOV_R0_MemIdx(InstrHasImm, InstrHasReg16, MoveInstruction):
    def operands(self):
        yield Reg8Operand('R0')
        yield MemIdxOperand(self.regs, self.imm)


class MOV_MemIdx_R0(InstrHasImm, InstrHasReg16, MoveInstruction):
    def operands(self):
        yield MemIdxOperand(self.regs, self.imm)
        yield Reg8Operand('R0')


class PUSH(InstrHasReg8, Instruction):
    def operands(self):
        yield Reg8Operand(self.reg)

    def lift(self, il, addr):
        il.append(il.push(1, il.reg(1, self.reg)))


class POP(InstrHasReg8, Instruction):
    def operands(self):
        yield Reg8Operand(self.reg)

    def lift(self, il, addr):
        il.append(il.set_reg(1, self.reg, il.pop(1)))


class JMP_Rel(InstrHasFlag, Instruction):
    def length(self):
        return super().length() + 1

    def decode(self, decoder, addr):
        super().decode(decoder, addr)
        self.pc = addr + self.length() + decoder.signed_byte()

    def encode(self, encoder, addr):
        super().encode(encoder, addr)
        encoder.signed_byte(self.pc - addr - self.length())

    @property
    def inverted(self):
        return bool(self.opcode & 8 == 0)

    def name(self):
        if self.inverted:
            return f'JN{self.flag}'
        else:
            return f'J{self.flag}'

    def operands(self):
        yield CodeOperand(self.pc)

    def analyze(self, info, addr):
        super().analyze(info, addr)
        info.add_branch(BranchType.TrueBranch,  self.pc)
        info.add_branch(BranchType.FalseBranch, addr + self.length())

    def lift(self, il, addr):
        cond = il.not_expr(1, il.flag(self.flag)) if self.inverted else il.flag(self.flag)
        if_true  = (il.get_label_for_address(il.arch, self.pc) or
                    il.add_label_for_address(il.arch, self.pc))
        if_false = (il.get_label_for_address(il.arch, addr + self.length()) or
                    il.add_label_for_address(il.arch, addr + self.length()))
        if if_true and if_false: # common path; keeps LLIL clean
            il.append(il.if_expr(cond, if_true, if_false))
        else: # exceptional path; e.g. if a conditional jump falls through into another function
            if_true  = LowLevelILLabel()
            if_false = LowLevelILLabel()
            il.append(il.if_expr(cond, if_true, if_false))
            il.mark_label(if_true)
            il.append(il.jump(il.const_pointer(2, self.pc)))
            il.mark_label(if_false)
            il.append(il.jump(il.const_pointer(2, addr + self.length())))


class JMP_Abs(Instruction):
    def length(self):
        return super().length() + 2

    def decode(self, decoder, addr):
        super().decode(decoder, addr)
        self.pc = decoder.unsigned_word()

    def encode(self, encoder, addr):
        super().encode(encoder, addr)
        encoder.unsigned_word(self.pc)

    def operands(self):
        yield CodeOperand(self.pc)

    def analyze(self, info, addr):
        super().analyze(info, addr)
        info.add_branch(BranchType.UnconditionalBranch, self.pc)

    def lift(self, il, addr):
        if label := il.get_label_for_address(il.arch, self.pc):
            il.append(il.goto(label))
        else:
            il.append(il.jump(il.const_pointer(2, self.pc)))


class CALL(Instruction):
    def length(self):
        return super().length() + 2

    def decode(self, decoder, addr):
        super().decode(decoder, addr)
        self.pc = decoder.unsigned_word()

    def encode(self, encoder, addr):
        super().encode(encoder, addr)
        encoder.unsigned_word(self.pc)

    def operands(self):
        yield CodeOperand(self.pc)

    def analyze(self, info, addr):
        super().analyze(info, addr)
        info.add_branch(BranchType.CallDestination, self.pc)

    def lift(self, il, addr):
        il.append(il.call(il.const_pointer(2, self.pc)))


class RET(Instruction):
    def analyze(self, info, addr):
        super().analyze(info, addr)
        info.add_branch(BranchType.FunctionReturn)

    def lift(self, il, addr):
        il.append(il.ret(il.pop(2)))


class IRET(RET):
    pass


class UNKN(Instruction):
    def operands(self):
        yield ImmOperand(self.opcode)

    def lift(self, il, addr):
        il.append(il.unimplemented())


Instruction.opcodes.update({
    0x00: INC,
    0x01: INC,
    0x02: INC,
    0x03: INC,
    0x04: INC,
    0x05: INC,
    0x06: INC,
    0x07: INC,
    0x08: ADDC,
    0x09: ADDC,
    0x0a: ADDC,
    0x0b: ADDC,
    0x0c: ADDC,
    0x0d: ADDC,
    0x0e: ADDC,
    0x0f: ADDC,
    0x10: MOV_R0_Reg,
    0x11: MOV_R0_Reg,
    0x12: MOV_R0_Reg,
    0x13: MOV_R0_Reg,
    0x14: MOV_R0_Reg,
    0x15: MOV_R0_Reg,
    0x16: MOV_R0_Reg,
    0x17: MOV_R0_Reg,
    0x18: OR,
    0x19: OR,
    0x1a: OR,
    0x1b: OR,
    0x1c: OR,
    0x1d: OR,
    0x1e: OR,
    0x1f: OR,
    0x20: AND,
    0x21: AND,
    0x22: AND,
    0x23: AND,
    0x24: AND,
    0x25: AND,
    0x26: AND,
    0x27: AND,
    0x28: XOR,
    0x29: XOR,
    0x2a: XOR,
    0x2b: XOR,
    0x2c: XOR,
    0x2d: XOR,
    0x2e: XOR,
    0x2f: XOR,
    0x30: RLC,
    0x31: RLC,
    0x32: RLC,
    0x33: RLC,
    0x34: RLC,
    0x35: RLC,
    0x36: RLC,
    0x37: RLC,
    0x38: RRC,
    0x39: RRC,
    0x3a: RRC,
    0x3b: RRC,
    0x3c: RRC,
    0x3d: RRC,
    0x3e: RRC,
    0x3f: RRC,
    0x40: DEC,
    0x41: DEC,
    0x42: DEC,
    0x43: DEC,
    0x44: DEC,
    0x45: DEC,
    0x46: DEC,
    0x47: DEC,
    0x48: SUBB,
    0x49: SUBB,
    0x4a: SUBB,
    0x4b: SUBB,
    0x4c: SUBB,
    0x4d: SUBB,
    0x4e: SUBB,
    0x4f: SUBB,
    0x50: ADD,
    0x51: ADD,
    0x52: ADD,
    0x53: ADD,
    0x54: ADD,
    0x55: ADD,
    0x56: ADD,
    0x57: ADD,
    0x58: SET,
    0x59: SET,
    0x5a: SET,
    0x5b: SET,
    0x5c: SET,
    0x5d: SET,
    0x5e: SET,
    0x5f: SET,
    0x60: BIT,
    0x61: BIT,
    0x62: BIT,
    0x63: BIT,
    0x64: BIT,
    0x65: BIT,
    0x66: BIT,
    0x67: BIT,
    0x68: CLR,
    0x69: CLR,
    0x6a: CLR,
    0x6b: CLR,
    0x6c: CLR,
    0x6d: CLR,
    0x6e: CLR,
    0x6f: CLR,
    0x70: MOV_Reg_R0,
    0x71: MOV_Reg_R0,
    0x72: MOV_Reg_R0,
    0x73: MOV_Reg_R0,
    0x74: MOV_Reg_R0,
    0x75: MOV_Reg_R0,
    0x76: MOV_Reg_R0,
    0x77: MOV_Reg_R0,
    0x78: CMP,
    0x79: CMP,
    0x7a: CMP,
    0x7b: CMP,
    0x7c: CMP,
    0x7d: CMP,
    0x7e: CMP,
    0x7f: CMP,
    0x80: PUSH,
    0x81: PUSH,
    0x82: PUSH,
    0x83: PUSH,
    0x84: PUSH,
    0x85: PUSH,
    0x86: PUSH,
    0x87: PUSH,
    0x88: POP,
    0x89: POP,
    0x8a: POP,
    0x8b: POP,
    0x8c: POP,
    0x8d: POP,
    0x8e: POP,
    0x8f: POP,
    0x90: JMP_Rel,
    0x91: JMP_Rel,
    0x92: JMP_Rel,
    0x93: JMP_Rel,
    0x94: JMP_Rel,
    0x95: JMP_Rel,
    0x96: JMP_Rel,
    0x97: JMP_Rel,
    0x98: JMP_Rel,
    0x99: JMP_Rel,
    0x9a: JMP_Rel,
    0x9b: JMP_Rel,
    0x9c: JMP_Rel,
    0x9d: JMP_Rel,
    0x9e: JMP_Rel,
    0x9f: JMP_Rel,
    0xa0: UNKN,
    # 0xa1: UNK,
    # 0xa2: UNK,
    # 0xa3: UNK,
    # 0xa4: UNK,
    # 0xa5: UNK,
    # 0xa6: UNK,
    # 0xa7: UNK,
    # 0xa8: UNK,
    # 0xa9: UNK,
    # 0xaa: UNK,
    # 0xab: UNK,
    # 0xac: UNK,
    # 0xad: UNK,
    # 0xae: UNK,
    # 0xaf: UNK,
    # 0xb0: ,
    # 0xb1: ,
    # 0xb2: ,
    # 0xb3: ,
    # 0xb4: ,
    # 0xb5: ,
    # 0xb6: ,
    # 0xb7: ,
    # 0xb8: ,
    0xb9: RET,
    0xba: IRET,
    # 0xbb: ,
    0xbc: JMP_Abs,
    # 0xbd: ,
    # 0xbe: ,
    0xbf: CALL,
    0xc0: INC_Reg16,
    # 0xc1: INC_Reg16, # broken in CPU
    0xc2: INC_Reg16,
    # 0xc3: INC_Reg16, # broken in CPU
    0xc4: INC_Reg16,
    # 0xc5: INC_Reg16, # broken in CPU
    0xc6: INC_Reg16,
    # 0xc7: INC_Reg16, # broken in CPU
    0xc8: MOV_MemAbs_Reg,
    0xc9: MOV_MemAbs_Reg,
    0xca: MOV_MemAbs_Reg,
    0xcb: MOV_MemAbs_Reg,
    0xcc: MOV_MemAbs_Reg,
    0xcd: MOV_MemAbs_Reg,
    0xce: MOV_MemAbs_Reg,
    0xcf: MOV_MemAbs_Reg,
    0xd0: MOV_MemReg_R0,
    # 0xd1: MOV_MemReg_R0, # broken in CPU
    0xd2: MOV_MemReg_R0,
    # 0xd3: MOV_MemReg_R0, # broken in CPU
    0xd4: MOV_MemReg_R0,
    # 0xd5: MOV_MemReg_R0, # broken in CPU
    0xd6: MOV_MemReg_R0,
    # 0xd7: MOV_MemReg_R0, # broken in CPU
    0xd8: MOV_MemIdx_R0,
    # 0xd9: MOV_MemIdx_Reg, # broken in CPU
    0xda: MOV_MemIdx_R0,
    # 0xdb: MOV_MemIdx_Reg, # broken in CPU
    0xdc: MOV_MemIdx_R0,
    # 0xdd: MOV_MemIdx_Reg, # broken in CPU
    0xde: MOV_MemIdx_R0,
    # 0xdf: MOV_MemIdx_Reg, # broken in CPU
    0xe0: MOV_Reg_Imm,
    0xe1: MOV_Reg_Imm,
    0xe2: MOV_Reg_Imm,
    0xe3: MOV_Reg_Imm,
    0xe4: MOV_Reg_Imm,
    0xe5: MOV_Reg_Imm,
    0xe6: MOV_Reg_Imm,
    0xe7: MOV_Reg_Imm,
    0xe8: MOV_Reg_MemAbs,
    0xe9: MOV_Reg_MemAbs,
    0xea: MOV_Reg_MemAbs,
    0xeb: MOV_Reg_MemAbs,
    0xec: MOV_Reg_MemAbs,
    0xed: MOV_Reg_MemAbs,
    0xee: MOV_Reg_MemAbs,
    0xef: MOV_Reg_MemAbs,
    0xf0: MOV_R0_MemReg,
    # 0xf1: MOV_R0_MemReg, # broken in CPU
    0xf2: MOV_R0_MemReg,
    # 0xf3: MOV_R0_MemReg, # broken in CPU
    0xf4: MOV_R0_MemReg,
    # 0xf5: MOV_R0_MemReg, # broken in CPU
    0xf6: MOV_R0_MemReg,
    # 0xf7: MOV_R0_MemReg, # broken in CPU
    0xf8: MOV_R0_MemIdx,
    # 0xf9: MOV_Reg_MemIdx, # broken in CPU
    0xfa: MOV_R0_MemIdx,
    # 0xfb: MOV_Reg_MemIdx, # broken in CPU
    0xfc: MOV_R0_MemIdx,
    # 0xfd: MOV_Reg_MemIdx, # broken in CPU
    0xfe: MOV_R0_MemIdx,
    # 0xff: MOV_Reg_MemIdx, # broken in CPU
})
