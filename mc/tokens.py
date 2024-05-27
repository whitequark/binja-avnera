try:
    from binaryninja import InstructionTextToken
    from binaryninja.enums import InstructionTextTokenType
except ImportError:
    InstructionTextToken = None


__all__  = ['token', 'asm']


def token(kind, text, *data):
    if InstructionTextToken is None:
        return text
    else:
        if kind == 'instr':
            tokenType = InstructionTextTokenType.InstructionToken
        elif kind == 'opsep':
            tokenType = InstructionTextTokenType.OperandSeparatorToken
        elif kind == 'reg':
            tokenType = InstructionTextTokenType.RegisterToken
        elif kind == 'int':
            tokenType = InstructionTextTokenType.IntegerToken
        elif kind == 'addr':
            tokenType = InstructionTextTokenType.PossibleAddressToken
        elif kind == 'begmem':
            tokenType = InstructionTextTokenType.BeginMemoryOperandToken
        elif kind == 'endmem':
            tokenType = InstructionTextTokenType.EndMemoryOperandToken
        elif kind == 'text':
            tokenType = InstructionTextTokenType.TextToken
        else:
            raise ValueError('Invalid token kind {}'.format(kind))
        return InstructionTextToken(tokenType, text, *data)


def asm(*parts):
    return [token(*part) for part in parts]
