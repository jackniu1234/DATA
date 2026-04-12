# -*- coding: utf-8 -*-

# @author: AI Assistant
# @category: Analysis
try:
    from ghidra.ghidra_builtins import *
except:
    pass
from ghidra.program.model.symbol import FlowType

# -*- coding: utf-8 -*-
# @author: AI Assistant
# @category: Analysis
import os
import json
from ghidra.program.model.lang import OperandType
from ghidra.program.model.symbol import FlowType

program_name = str(currentProgram.getDomainFile().getName())
if program_name.endswith("exe"):
    program_name = program_name[:-4]

folder = currentProgram.getDomainFile().getParent().getName()
project_dir = r'/home/jackniu/scripts/spec-gcc'

home_dir = os.path.join(project_dir, program_name)

json_path = os.path.join(home_dir, 'all_icalls.json')

DECOMPILE_STYLE = 'firstpass'


def is_indirect_operand(instr, op_index):
    """
    检查指定索引的操作数是否具有间接性质（寄存器或内存引用）
    """
    op_type = instr.getOperandType(op_index)

    # 1. 如果操作数是寄存器 (例如 call rax)
    if OperandType.isRegister(op_type):
        return True

    # 2. 如果操作数是间接寻址 (例如 call [rax] 或 call [0x1234])
    # OperandType.INDIRECT 指的是类似 [ptr] 的形式
    if OperandType.isIndirect(op_type):
        return True

    # 3. 兜底逻辑：如果它不是一个直接的地址/标号 (Address)，通常就是间接的
    if not OperandType.isAddress(op_type) and not OperandType.isScalar(op_type):
        return True

    return False


def find_all_icalls():
    listing = currentProgram.getListing()
    instructions = listing.getInstructions(currentProgram.getMinAddress(), True)

    count = 0
    icall_list = []

    for instr in instructions:
        if monitor.isCancelled():
            break

        flow = instr.getFlowType()

        # 目标：只看 CALL
        if flow.isCall():

            # 逻辑 A：如果 Ghidra 已经标记为 Computed，直接通过
            is_indirect = flow.isComputed()

            # 逻辑 B：如果 Ghidra 没标记，我们检查操作数 (通常是第 0 个操作数)
            if not is_indirect and instr.getNumOperands() > 0:
                is_indirect = is_indirect_operand(instr, 0)

            if is_indirect:
                # 进一步过滤：排除掉那些直接跳转到具体标号的指令 (Direct Calls)
                # 如果有 Primary Reference 且是非计算性的，说明 Ghidra 已经解析出了静态地址
                refs = instr.getReferencesFrom()
                has_static_target = any(
                    r.getReferenceType().isFlow() and not r.getReferenceType().isComputed() for r in refs)

                if not has_static_target:
                    addr = instr.getMinAddress()
                    mnemonic = instr.getMnemonicString()
                    ops = instr.getDefaultOperandRepresentation(0)

                    print("[{}] {:<10} | {:<8} {:<15}".format(
                        addr, "Indirect", mnemonic, ops))
                    count += 1

                    addr_hex = "{}".format(instr.getMinAddress().toString().split(":")[-1])
                    icall_list.append(addr_hex)

    output_data = {
        "all_icalls": icall_list
    }

    # 确定保存路径：默认保存到用户的家目录下，或者你可以修改为固定路径
    try:
        with open(json_path, 'w') as f:
            json.dump(output_data, f, indent=4)
    except Exception as e:
        print("write error: {}".format(str(e)))

    print("\ntotally find {} icalls".format(count))


if __name__ == "__main__":
    find_all_icalls()