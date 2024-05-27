import binaryninja

from .coding import *
from .instr import Instruction


__all__ = ['iter_decode', 'iter_encode', 'decode', 'encode', 'disassemble']


def iter_decode(data, addr):
    decoder = Decoder(data)
    while True:
        try:
            instr = Instruction(decoder=decoder)
            if instr is None:
                raise NotImplementedError(
                    f'Cannot decode opcode {data[decoder.pos]:#04x} '
                    f'at address {addr + decoder.pos:#06x}')
            instr.decode(decoder, addr)
            yield instr, addr
            addr += instr.length()
        except coding.BufferTooShort:
            break


def iter_encode(iter, addr):
    encoder = Encoder()
    for instr in iter:
        instr.encode(encoder, addr)
        addr += instr.length()
    return encoder.buf


def fusion(iter):
    try:
        instr1, addr1 = next(iter)
    except StopIteration:
        return
    while True:
        try:
            instr2, addr2 = next(iter)
        except (StopIteration, NotImplementedError):
            yield instr1, addr1
            break
        if instr12 := instr1.fuse(instr2):
            yield instr12, addr1
            try:
                instr1, addr1 = next(iter)
            except (StopIteration, NotImplementedError):
                break
        else:
            yield instr1, addr1
            instr1, addr1 = instr2, addr2


def decode(data, addr):
    try:
        instr, _ = next(fusion(iter_decode(data, addr)))
        return instr
    except StopIteration:
        return None
    except NotImplementedError as e:
        binaryninja.log_warn(e)


def encode(instr, addr):
    return iter_encode([instr], addr)


def disassemble(data, addr):
    for instr, addr in iter_decode(data, addr):
        instr.display(addr)
