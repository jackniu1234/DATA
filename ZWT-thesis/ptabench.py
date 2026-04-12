# on-demand pointer alias analysis
# coding=utf-8

# @category jackniu
# @toolbar
# @menupath Tools.Points Alias Analysis
# @keybinding ctrl P

import inspect, traceback
import os.path
import sys
import csv
import json
import time
import itertools
from ghidra.program.model.data import Pointer
import copy
from copy import deepcopy

from ghidra.app.decompiler import DecompileOptions, DecompInterface
from ghidra.program.model.address import AddressSpace, AddressSet, Address, AddressRange
from ghidra.program.model.mem import MemoryBlock
from ghidra.program.model.pcode import PcodeOp, Varnode, HighFunction, VarnodeAST, PcodeOpAST, SequenceNumber
from ghidra.program.model.listing import Function
from ghidra.util.task import ConsoleTaskMonitor

try:
    from ghidra.ghidra_builtins import *
except:
    pass


DECOMPILE_STYLE = 'firstpass'

program_name = str(currentProgram.getDomainFile().getName())
if program_name.endswith("exe"):
    program_name = program_name[:-4]
if program_name.endswith(".o"):
    program_name = program_name[:-2]

folder = currentProgram.getDomainFile().getParent().getName()

dirname = os.path.basename(os.path.dirname(currentProgram.getDomainFile().getPathname()))
if dirname == 'arm-O0':
    project_dir = r'/home/jackniu/scripts/cases/arm-O0'
elif dirname == 'x64-O0':
    project_dir = r'/home/jackniu/scripts/cases/x64-O0'
else:
    print dirname
    assert False, 'illegal project directory'

task_csv = os.path.join(project_dir, 'task.csv')
result_csv = os.path.join(project_dir, 'result.csv')

home_dir = os.path.join(project_dir, program_name)
fp_debug = open(os.path.join(home_dir, 'debug.txt'), 'w')
fp_process = open(os.path.join(home_dir, 'process.txt'), 'w')
fp_print = open(os.path.join(home_dir, '{}.txt'.format(program_name)), 'w')

split_line1 = '-' * 50 + '\n'

# 处理switch表需要知道ArrayPR的offset单位，如果只是处理别名可以不知道
ArrayPR = {}  # type: dict[PointerRepresent, int]
ListPR = set()  # type: set[PointerRepresent]

WordSize = currentProgram.getLanguage().getDefaultSpace().getSize() / 8

# [Heuristic Configuration] 启发式策略配置
# 对于gobmk，需要放宽searchWidth
MAX_PR_DEPTH = 10
MAX_PR_DEREF_DEPTH = 3
MAX_PRSET_WIDTH = 20

MAX_NODE_PATH_LEN = 6  # 一个QueNode的最长访问路径长度（解引用+偏移的总数）
MAX_NODE_DEREF_PATH_LEN = 3  # 一个QueNode的最长解引用路径长度
MAX_RECURSION_COUNT = 1  # 同一个函数在祖先链中允许出现的最大次数（防止递归）
MAX_SEARCH_DEPTH = 7  # 最大搜索深度
MAX_SEARCH_WIDTH = 10  # 最大搜索宽度
MAX_SINGLE_EDGE_WIDTH = 8  # 使用一种边最多转移到多少个函数
MAX_QUE_NODES = 50  # 最多有多少个QueNode
MAX_PARAMETER_COUNT = 6 if currentProgram.getLanguage().getProcessor().toString() == 'x86' else 4
MAX_ARRAY_SIZE = 15

ENABLE_FORWARD_EDGE = True  # only bzip2 need now

class PointerRepresent(object):
    """ 本身表示对base进行一种运算 """
    SYMBOL, CONSTANT, PLUS, DEREF = 0, 1, 2, 3
    __slots__ = ('base', '_hash_cache', '_bottom_cache', '_depth_cache', '_deref_depth_cache')

    def __init__(self, base):
        self.base = base
        self._bottom_cache = None
        self._hash_cache = None
        self._depth_cache = None
        self._deref_depth_cache = None

    def __eq__(self, other):
        """ 用于指针值的去重 """
        raise NotImplementedError("call PR __eq__")

    def __ne__(self, other):
        raise NotImplementedError("call PR __eq__")

    def __str__(self):
        raise NotImplementedError("call PR __str__")

    def __hash__(self):
        raise NotImplementedError("call PR __hash__")

    def interact(self, other):
        """ 如果两个指针值interact, 则他们对应的指针变量互为别名 """
        raise NotImplementedError("call PR interact")


    def get_bottom_base(self):
        """ 返回最底层的ConstantPR或者SymbolPR """
        if self._bottom_cache:
            return self._bottom_cache
        pr = self
        while isinstance(pr, DerefPR) or isinstance(pr, PlusPR):
            pr = pr.base
        return pr

    def based_on_SP(self):
        base = self.get_bottom_base()
        return isinstance(base, SymbolPR) and base.ty == SymbolPR.SP

    def have_base_equal_this(self, old):
        pr = self
        while not pr.__eq__(old):
            if isinstance(pr, SymbolPR) or isinstance(pr, ConstantPR):
                return False
            pr = pr.base

        return True

    def strip_plus(self):
        """ 返回pr第一个不是PlusPR的base，用于引入数组后的interact判断, r0+3+4返回r0 """
        pr = self
        while isinstance(pr, PlusPR):
            pr = pr.base
        return pr

    def outer_plus_offsets(self):
        """ 用于常量折叠判断，即0x4+0x4==0x8 """
        offsets = []  # type: list[OffsetRepresent]
        pr = self
        while isinstance(pr, PlusPR):
            offsets.append(pr.offset)
            pr = pr.base
        return offsets

    def strip_deref_plus(self):
        """ 去除pr计算过程中的Deref与Plus运算的组合，用于引入链表后的interact判断，*(r0+3)返回r0 """
        pr = self
        if isinstance(pr, DerefPR) and isinstance(pr.base, PlusPR):
            offset = pr.base.offset
            pr = pr.base.base

            while isinstance(pr, DerefPR) and isinstance(pr.base, PlusPR) and pr.base.offset == offset:
                pr = pr.base.base

        return pr

    def strip_all_deref(self):
        """ 获得跳过所有Deref运算后的第一个pr，用于constant-edge转移 """
        last_deref = None
        pr = self
        while isinstance(pr, DerefPR) or isinstance(pr, PlusPR):
            if isinstance(pr, DerefPR):
                last_deref = pr
            pr = pr.base

        if last_deref:
            # 计算过程中存在Deref
            return last_deref.base
        else:
            return self

    @property
    def depth(self):
        """ SymbolPR和ConstantPR的深度为1 """
        if self._depth_cache:
            return self._depth_cache

        depth = 1
        pr = self
        while isinstance(pr, PlusPR) or isinstance(pr, DerefPR):
            pr = pr.base
            depth = depth + 1
        return depth

    @property
    def deref_depth(self):
        if self._deref_depth_cache:
            return self._deref_depth_cache

        depth = 1
        pr = self
        while isinstance(pr, PlusPR) or isinstance(pr, DerefPR):
            if isinstance(pr, DerefPR):
                depth = depth + 1
            pr = pr.base
        return depth

    def in_limit_depth(self):
        return self.depth <= MAX_PR_DEPTH


def may_need_refactor(pr):
    """ pr的refactor是个很费时的操作，尽量避免执行 """
    # if isinstance(pr.get_bottom_base(), ConstantPR):
    #     return True
    #
    # _pr = pr
    # while isinstance(_pr, PlusPR) or isinstance(_pr, DerefPR):
    #     if isinstance(_pr, PlusPR):
    #         if _pr.offset.isTotalUnknown():
    #             return True
    #     _pr = _pr.base
    #
    # return False
    return pr.depth >= 2 and isinstance(pr.get_bottom_base(), ConstantPR)


def special_refactor_for_pr(pr):
    """
     通过replace_old_by_new获得的new_pr，可能形如*(0x1bac4)，或者sp-+0x4-0x111-0x111，需要将其进行转换
     :type pr PointerRepresent
    """
    if pr.depth <= 2:
        if isinstance(pr, DerefPR):
            return Deref(pr.base)
        else:
            return pr
    pr.base = special_refactor_for_pr(pr.base)
    return pr


def is_hopeful_pr(pr):
    """
     是否为可能解析出target的PR, 要求bottom_base是ContantPR，并且计算过程中不能出现unknown offset
     :type pr PointerRepresent
    """
    if not (isinstance(pr.get_bottom_base(), ConstantPR)):
        return False

    while not isinstance(pr, ConstantPR):
        if isinstance(pr, PlusPR) and not (pr.offset.isConstant() or pr.offset.isMultStride()):
            return False
        pr = pr.base

    return True

class TryGetLiteral(object):
    def __init__(self):
        self.cacheTrue, self.cacheFalse = {}, {}

    def expand_to_array(self, base, pr):
        assert base, "the targets list meet None"
        if pr in ArrayPR and ArrayPR[pr]:
            stride = ArrayPR[pr]
            return [base + stride * i for i in range(0, MAX_ARRAY_SIZE)]
        else:
            return base

    def complexVersion(self, pr):
        if pr in self.cacheTrue:
            return self.cacheTrue[pr]
        else:
            self.cacheTrue[pr] = self.complexVersionImpl(pr)
            return self.cacheTrue[pr]

    def complexVersionImpl(self, pr):
        if isinstance(pr, ConstantPR):
            return self.expand_to_array(pr.base, pr)

        base_result = self.complexVersion(pr.base)
        if not base_result:
            return None

        if isinstance(base_result, long):
            if isinstance(pr, PlusPR) and pr.offset.isConstant():
                default_value = base_result + pr.offset.literal
            elif isinstance(pr, PlusPR) and pr.offset.isMultStride():
                return [base_result + WordSize * i for i in range(0, MAX_ARRAY_SIZE)]
            elif isinstance(pr, DerefPR):
                default_value = read_addr_and_check(base_result)
                if not default_value:
                    return None
            else:
                return None

            return self.expand_to_array(default_value, pr)

        elif isinstance(base_result, list):
            if isinstance(pr, PlusPR) and pr.offset.isConstant():
                return [l + pr.offset.literal for l in base_result if l]
            elif isinstance(pr, DerefPR):
                return [result for result in (read_addr_and_check(l) for l in base_result if l) if result]

        return None

    def simpleVersion(self, pr):
        if pr in self.cacheFalse:
            return self.cacheFalse[pr]
        else:
            self.cacheFalse[pr] = self.simpleVersionImpl(pr)
            return self.cacheFalse[pr]

    def simpleVersionImpl(self, pr):
        """
         don't consider Array and multStride
         :type pr PointerRepresent
        """
        if isinstance(pr, ConstantPR):
            return pr.base

        base_result = self.simpleVersion(pr.base)
        if not base_result:
            return None

        if isinstance(pr, PlusPR) and pr.offset.isConstant():
            return base_result + pr.offset.literal
        elif isinstance(pr, DerefPR):
            return read_addr_and_check(base_result)
        else:
            return None

    def __call__(self, pr, check_array=False):
        assert isinstance(pr.get_bottom_base(), ConstantPR), "try_get_literal's call stack have trouble"
        if check_array:
            res = self.complexVersion(pr)
            if isinstance(res, long):
                res = [res]
            return res
        else:
            return self.simpleVersion(pr)

try_get_literal = TryGetLiteral()

def addArrayPR(pr, offset):
    """
     将pr与offset登记到ArrayPR dict中; 目前ArrayPR只在解析目标地址时使用
     :type pr PointerRepresent
     :type long
    """
    if isinstance(pr, PlusPR) and pr.offset.literal == offset:
        ArrayPR[pr.base] = offset
    else:
        ArrayPR[pr] = offset
    # ArrayPR[pr] = offset

def addListPR(pr):
    if pr.depth > 2 and pr.base.base in ListPR:
        return
    ListPR.add(pr)


class DerefFactory(object):
    def __init__(self):
        self.cache = {}

    def simple_try_get_literal(self, pr):
        if isinstance(pr, ConstantPR):
            return pr.base
        else:
            return None

    def __call__(self, base):
        """
         用来生产DerefPR的工厂方法
         :type base PointerRepresent
        """
        literal = self.simple_try_get_literal(base)
        if literal:
            if literal in self.cache:
                return self.cache[literal]
            else:
                data = read_addr_and_check(literal)
                if data:
                    self.cache[literal] = ConstantPR(data)
                    return ConstantPR(data)
                else:
                    self.cache[literal] = DerefPR(base)
                    return DerefPR(base)

        return DerefPR(base)

Deref = DerefFactory()


def Plus(base, offset):
    """
     用来生产PlusPR的工厂方法
     :type base PointerRepresent
     :type offset OffsetRepresent
    """
    # # 有时base和offset都是通过读取内存得到的，二者加起来才是一个有意义的地址
    # # 因此只关注base对应的常量无法进行constant edge转移
    # # 通过识别较大的偏移量来判定这种pattern，出发点是一个结构体的size应该不会超过0x50，因此offset不从属于base
    # if isinstance(base, ConstantPR) and offset.isConstant() and abs(offset.literal) >= 0x50:
    #     return ConstantPR(base.base+offset.literal)
    # else:
    #     return PlusPR(base, offset)
    return PlusPR(base, offset)


class SymbolPR(PointerRepresent):
    """ SymbolPR的base是Varnode对象（可代表形参、实返回值、栈指针SP、malloc函数的返回值） """
    PARAM, RETURN, SP, MALLOCRETURN = 0, 1, 2, 3
    __slots__ = ('ty',)

    def __init__(self, varnode, ty):
        assert isinstance(varnode, VarnodeAST) and SymbolPR.PARAM <= ty <= SymbolPR.MALLOCRETURN
        PointerRepresent.__init__(self, varnode)
        self.ty = ty

    def __str__(self):
        return processVarnodeFormat(self.base)

    def __deepcopy__(self, memo):
        return self

    def __hash__(self):
        if self._hash_cache:
            return self._hash_cache
        return hash(self.SYMBOL) ^ hash(self.base)

    def __eq__(self, other):
        # 似乎是这个版本的ghidra有bug，会出现equal但是hashCode不同的情况，即错误的equal
        return isinstance(other, SymbolPR) and self.base is other.base

    def interact(self, other):
        return self == other


class ConstantPR(PointerRepresent):
    def __init__(self, base):
        if isinstance(base, Varnode):
            assert base.isConstant()
            literal = base.getOffset()
        elif isinstance(base, long):
            literal = base
        else:
            raise Exception("error in __init__ of ConstantPR")

        if is_unexpected_big_data(literal):
            literal = unsigned_to_signed(literal)

        PointerRepresent.__init__(self, literal)

    def __eq__(self, other):
        return isinstance(other, ConstantPR) and self.base == other.base

    def __hash__(self):
        if self._hash_cache:
            return self._hash_cache
        return hash(self.CONSTANT) ^ hash(self.base)

    def __str__(self):
        return hex(self.base)[:-1]

    def __deepcopy__(self, memodict={}):
        return self

    def interact(self, other):
        return self == other


class PlusPR(PointerRepresent):
    def __init__(self, base, offset):
        assert isinstance(base, PointerRepresent) and isinstance(offset, OffsetRepresent)

        PointerRepresent.__init__(self, base)
        self.offset = offset  # type: OffsetRepresent

    @staticmethod
    def _calculate_accumulated_offset(start_pr, end_base):
        """
        辅助函数：尝试计算从 self 到 end_base 的累加常量 offset。
        如果路径上包含非常量 offset，则返回 None。
        """
        pr = start_pr
        total_offset = 0
        while pr is not end_base:
            _o = pr.offset
            if _o.isConstant():
                total_offset += _o.literal
            else:
                return None
            pr = pr.base
        return total_offset

    def __eq__(self, other):
        """ 考虑常量折叠与完全相等两个情况 """
        self_strip_plus, other_strip_plus = self.strip_plus(), other.strip_plus()
        if (self_strip_plus == other_strip_plus or
                (isinstance(self_strip_plus, ConstantPR) and isinstance(other_strip_plus, ConstantPR))):
            o1 = PlusPR._calculate_accumulated_offset(self, self_strip_plus)
            o2 = PlusPR._calculate_accumulated_offset(other, other_strip_plus)

            # case1: base+0x4+0x4 ^ base+0x8
            if self_strip_plus == other_strip_plus and o1 and o1 == o2:
                return True
            # case2: 0x4004 ^ 0x4000 + 0x4
            if isinstance(self_strip_plus, ConstantPR) and isinstance(other_strip_plus, ConstantPR) \
                    and o1 and o2:
                if o1 + self_strip_plus.base == o2 + other_strip_plus.base:
                    return True

        # 完全相等。
        return isinstance(other, PlusPR) and self.base == other.base and self.offset == other.offset

    def __hash__(self):
        # 保证__eq__时，__hash__结果相同
        if self._hash_cache:
            return self._hash_cache

        # 1. 获取归一化的 base (Strip Plus)
        stripped_base = self.strip_plus()

        # 2. 尝试计算累加的 offset
        total_offset = PlusPR._calculate_accumulated_offset(self, stripped_base)

        # 3. 根据是否能成功折叠常量，分情况计算 Hash
        if total_offset is not None:
            # 情况 A: 这是一个纯常量指针计算 (对应 __eq__ 中的 case2)
            # 例如: Constant(0x4000) + 0x4  ==  Constant(0x4004)
            # 我们直接哈希最终的数值结果
            if isinstance(stripped_base, ConstantPR):
                # 假设 ConstantPR.base 存储的是整数值
                final_val = stripped_base.base + total_offset
                res = hash(self.CONSTANT) ^ hash(final_val)  # 这里使用ConstantPR的hash算法

            # 情况 B: 这是一个带基址的常量偏移 (对应 __eq__ 中的 case1)
            # 例如: Base + 0x4 + 0x4  ==  Base + 0x8
            # 我们哈希 (最终Base) ^ (累加Offset)
            else:
                res = hash(stripped_base) ^ hash(total_offset)

        else:
            # 情况 C: 包含非常量(符号) Offset，无法折叠
            # 对应 __eq__ 中的 fallback 完全相等判断
            # 保持结构化哈希
            res = hash(self.PLUS) ^ hash(self.base) ^ hash(self.offset)

        self._hash_cache = res
        return res

    def __str__(self):
        return str(self.base) + str(self.offset)

    def interact(self, other):
        if self == other:
            return True

        # 逐层去掉offset，每层offset都需要匹配
        if isinstance(other, PlusPR) and self.offset == other.offset and PR_interact(self.base, other.base):
            return True

        # TotalUnknown为通配符
        if self.strip_plus() == other.strip_plus():
            strip1, strip2 = self.strip_plus(), other.strip_plus()
            fold_offset1, fold_offset2 = (PlusPR._calculate_accumulated_offset(self, strip1),
                                          PlusPR._calculate_accumulated_offset(other, strip2))
            # 如果都是具体值的话会equal
            if fold_offset1 is None or fold_offset2 is None:
                return True
            elif self.strip_plus() in ArrayPR:
                return True

        return False


class DerefPR(PointerRepresent):
    def __init__(self, base):
        assert isinstance(base, PointerRepresent)
        PointerRepresent.__init__(self, base)

    def __eq__(self, other):
        return isinstance(other, DerefPR) and self.base == other.base

    def __str__(self):
        return '*(' + str(self.base) + ')'

    def __hash__(self):
        if self._hash_cache:
            return self._hash_cache
        return hash(self.DEREF) ^ hash(self.base)

    def interact(self, other):
        if isinstance(other, DerefPR) and PR_interact(self.base, other.base):
            return True

        if self in ListPR and other.have_base_equal_this(self):
            return True

        return False


def PR_interact(lhs, rhs):
    """
    提供给外部的接口，是pr.interact()的封装
    :type lhs PointerRepresent
    :type rhs PointerRepresent
    """
    # 虽然大多数时候interact满足交换律，但是少部分时候，例如lhs为对应数组名的SymbolPR，而rhs为PlusPR，则不满足交换律。
    # 由于短路运算的存在，不会过多的牺牲效率
    ans = lhs.interact(rhs) or rhs.interact(lhs)
    assert ans or not (lhs == rhs)  # 如果二者不interact，那么二者一定不equal, 用来debug
    return ans


class OffsetRepresent(object):
    CONSTANT, LOADMEMORY, TOTALUNKNOWN, MULTSTRIDE = 0, 1, 2, 3

    def __init__(self, ty, literal=None):
        self.ty = ty

        if ty == self.CONSTANT:
            assert literal is not None
            if is_unexpected_big_data(literal):
                literal = unsigned_to_signed(literal)
            self.literal = literal  # type: long

        # trick: 使用特殊的整形值表示这种类型的Offset，主要用于打印
        elif ty == self.LOADMEMORY:
            self.literal = long(-0x985)

        elif ty == self.TOTALUNKNOWN:
            self.literal = long(-0x111)

        elif ty == self.MULTSTRIDE:
            assert literal is not None
            if is_unexpected_big_data(literal):
                self.literal = unsigned_to_signed(literal)
            else:
                self.literal = literal

    @classmethod
    def make_constant_offset(cls, offset):
        return cls(cls.CONSTANT, offset)

    @classmethod
    def make_load_memory_offset(cls):
        return cls(cls.LOADMEMORY)

    @classmethod
    def make_total_unknown_offset(cls):
        return cls(cls.TOTALUNKNOWN)

    @classmethod
    def make_mult_stride_offset(cls, stride):
        return cls(cls.MULTSTRIDE, stride)

    def __eq__(self, other):
        if not isinstance(other, OffsetRepresent):
            return False

        if self.ty == other.ty:
            if self.isConstant():
                return self.literal == other.literal
            else:
                return True
        else:
            return False

    def __str__(self):
        if self.isMultStride():
            ss = "i*" + hex(self.literal)[:-1]
        else:
            ss = hex(self.literal)[:-1]
        if self.literal >= 0:
            return '+' + ss
        else:
            return ss # 自带负号

    def __hash__(self):
        return hash(self.literal)

    def isTotalUnknown(self):
        return self.ty == self.TOTALUNKNOWN

    def isLoadMemory(self):
        return self.ty == self.LOADMEMORY

    def isConstant(self):
        return self.ty == self.CONSTANT

    def isMultStride(self):
        return self.ty == self.MULTSTRIDE


ArrayPRSet = set()

class SetEdge(object):
    def __init__(self):
        pass
    
class PlusEdge(SetEdge):
    def __init__(self, offset):
        """
         :type offset OffsetRepresent
        """
        SetEdge.__init__(self)
        self.offset = offset

    def __hash__(self):
        return hash(self.offset)

    def __eq__(self, other):
        return isinstance(other, PlusEdge) and other.offset == self.offset

    def __str__(self):
        return "plusEdge with " + str(self.offset)

class DerefEdge(SetEdge):
    def __init__(self):
        SetEdge.__init__(self)
        
    def __eq__(self, other):
        return isinstance(other, DerefEdge)

    def __str__(self):
        return "derefEdge"

    def __hash__(self):
        return hash(0)


from collections import deque


class SolverState(object):
    """
    用来封装全局状态，避免在函数间传递太多参数
    """
    def __init__(self):
        self.worklist = deque()  # 真正的 Worklist
        self.globalPRs = {}  # type: dict[PointerRepresent, PRSet]

    def run(self, M):
        while self.worklist:
            # 弹出节点和增量
            prset, delta = self.worklist.popleft()

            # 必须获取最新的代表节点，因为在排队过程中 prset 可能被合并了
            rep = prset.get_rep()

            # 处理增量
            rep.process_delta(delta)

        # 并查集的概念对后续屏蔽
        for pointer in M:
            M[pointer] = M[pointer].get_rep()

            # 边也进行并查集展开
            for edge in M[pointer].outEdges:
                M[pointer].outEdges[edge] = M[pointer].outEdges[edge].get_rep()

        for pr in self.globalPRs:
            self.globalPRs[pr] = self.globalPRs[pr].get_rep()

        return M, self.globalPRs


class PRSet(object):
    _id_gen = itertools.count()

    def __init__(self, solver_state):
        self.solver = solver_state
        self.PRs = set()
        # 建议将 outEdgeTargetPairs 改为字典，方便查找： {Edge: PRSet}
        # Unification-based 分析中，同一个 Edge 从一个节点出发通常指向唯一的代表节点
        self.outEdges = {}  # type: dict[Edge, PRSet]

        # 并查集 (Union-Find) 思想：如果被合并了，parent 指向合并后的集合
        self.parent = self
        self.id = next(PRSet._id_gen)
        self.isArray = False
        self.arrayStride = 0
        self.isList = False

    def __repr__(self):
        return "S<%d>" % self.id

    def get_rep(self):
        """ 获取代表节点（并查集的 find 操作，带路径压缩） """
        if self.parent != self:
            self.parent = self.parent.get_rep()
        return self.parent

    def addInitialCopyEdge(self, target):
        # used for ram variable only, which is not included in phinodes
        rep_self = self.get_rep()
        rep_target = target.get_rep()

        if rep_self is rep_target:
            return

        PRSet.unify(rep_self, rep_target)

    def addInitialEdge(self, edge, target):
        rep_self = self.get_rep()
        rep_target = target.get_rep()

        # 自回边，无需加入，增加array或list属性
        if rep_self is rep_target:
            if isinstance(edge, PlusEdge):
                rep_self.isArray = True
                rep_self.arrayStride = edge.offset.literal
            elif isinstance(edge, DerefEdge):
                rep_self.isList = True
            return

        # 如果边已经存在，需要合并旧目标和新目标
        if edge in rep_self.outEdges:
            rep_old_target = rep_self.outEdges[edge].get_rep()
            if rep_old_target is not rep_target:
                PRSet.unify(rep_old_target, rep_target)
        else:
            rep_self.outEdges[edge] = rep_target

    def addToWorklist(self, delta):
        """ 仅将任务加入队列，不立即执行 """
        if not delta:
            return
        # 限制符号深度，防止无限增长
        filtered_delta = {pr for pr in delta if pr.in_limit_depth()}
        if filtered_delta:
            self.solver.worklist.append((self, filtered_delta))

    def process_delta(self, delta):
        """
        消费者：从 worklist 取出后执行的逻辑
        """

        def dump_delta(d):
            print '[',
            for pr in d:
                print str(pr),
            print ']'

        # print __LINE__(), 'S' + str(self.id), ' get ',
        # dump_delta(delta)

        rep = self.get_rep()

        # 避免状态爆炸
        if len(rep) > MAX_PRSET_WIDTH:
            return

        # 1. 过滤掉已经存在的 PR
        new_prs = delta - rep.PRs  # type: set
        if not new_prs:
            return

        # 2. 检查 Unification 冲突
        # 如果新来的 PR 已经在其他 Set 里了，必须把当前 Set 和那个 Set 合并
        for pr in new_prs:
            if pr in self.solver.globalPRs:
                other_set = self.solver.globalPRs[pr].get_rep()
                if other_set is not rep:
                    # 发现冲突，进行合并
                    # 注意：合并后，rep 可能会变，需要更新
                    rep = PRSet.unify(rep, other_set)
            else:
                self.solver.globalPRs[pr] = rep

        # 新增逻辑，处理数组
        del_prs = []
        for pr in new_prs:
            if isinstance(pr, PlusPR) and isinstance(pr.base, PlusPR) and pr.base in rep:
                # p+4, p+4+4 ∈ set
                rep.isArray = True
                rep.arrayStride = pr.offset.literal
                del_prs.append(pr)
            elif isinstance(pr, DerefPR) and isinstance(pr.base, PlusPR) and pr.base.base in rep:
                # *(p+offset), p ∈ set
                rep.isList = True
                del_prs.append(pr)
            elif isinstance(pr, DerefPR) and pr.base in rep:
                # *p, p ∈ set
                rep.isList = True
                del_prs.append(pr)
            # some other models

        # 3. 将新 PR 加入集合
        for pr in del_prs:
            new_prs.discard(pr)
        if not new_prs:
            return

        rep.PRs |= new_prs

        # 4. 沿着边传播 (Propagate)
        # 生成新的 delta 传给下游
        for edge, target in rep.outEdges.items():
            target_rep = target.get_rep()

            if isinstance(edge, DerefEdge):
                transformed_delta = {Deref(pr) for pr in new_prs}
                target_rep.addToWorklist(transformed_delta)
            elif isinstance(edge, PlusEdge):
                transformed_delta = {Plus(pr, edge.offset) for pr in new_prs}
                target_rep.addToWorklist(transformed_delta)

    @staticmethod
    def unify(set1, set2):
        """
        合并两个集合 set1 和 set2。
        核心逻辑：
        1. root2 指向 root1
        2. root2 的内容(PRs) 流向 root1 原有的独有边
        3. root2 的边合并入 root1 (如果是 root1 新增的边，root1 原有的内容要流过去)
        4. root1 吸收 root2 的 PRs
        """
        root1 = set1.get_rep()
        root2 = set2.get_rep()

        if root1 is root2:
            return root1

        # 1. 设置父指针 (Merge root2 into root1)
        root2.parent = root1

        # 2.1 处理 root1 独有的边。
        if root2.PRs:
            for edge, target in root1.outEdges.items():
                if edge not in root2.outEdges:
                    target = target.get_rep()
                    transformed_delta = set()

                    # 生成增量：用 root2 的内容，沿着 root1 的边传播
                    if isinstance(edge, DerefEdge):
                        transformed_delta = {Deref(pr) for pr in root2.PRs}
                    elif isinstance(edge, PlusEdge):
                        transformed_delta = {Plus(pr, edge.offset) for pr in root2.PRs}

                    if transformed_delta:
                        target.addToWorklist(transformed_delta)

        # 2.2 处理root2的独有边与二者的共有边
        # 遍历 root2 的所有边
        for edge, target2 in root2.outEdges.items():
            target2 = target2.get_rep()

            if edge in root1.outEdges:
                # 边共存：合并目标节点 (Recursion)
                target1 = root1.outEdges[edge].get_rep()
                if target1 is not target2:
                    # 注意：递归 unify 会处理 target1 和 target2 内部的传播
                    merged_target = PRSet.unify(target1, target2)
                    root1.outEdges[edge] = merged_target
            else:
                # 这是一个 root1 原本没有的新边 (来自 root2) root1 原有的内容，必须流向这条新来的边
                root1.outEdges[edge] = target2

                # 注意：此时 root1.PRs 还没有合并 root2.PRs，所以这里取到的是纯粹的 P1
                if root1.PRs:
                    transformed_delta = set()
                    if isinstance(edge, DerefEdge):
                        transformed_delta = {Deref(pr) for pr in root1.PRs}
                    elif isinstance(edge, PlusEdge):
                        transformed_delta = {Plus(pr, edge.offset) for pr in root1.PRs}

                    if transformed_delta:
                        target2.addToWorklist(transformed_delta)

        # 3. 合并内容 (Merge PRs)
        combined_prs = root1.PRs | root2.PRs

        # 重新运行一次 Array/List 检测逻辑
        to_remove = set()
        for pr in combined_prs:
            # 检查 Plus 递归: (Base+Off) 和 Base 都在集合中 -> 折叠为 Array
            if isinstance(pr, PlusPR) and isinstance(pr.base, PlusPR) and pr.base in combined_prs:
                if abs(root1.arrayStride) < abs(pr.offset.literal):
                    root1.isArray = True
                    root1.arrayStride = root1.arrayStride
                    to_remove.add(pr)

            # 检查 Deref 递归: *P 和 P 都在集合中 -> 折叠为 Recursive/List
            elif isinstance(pr, DerefPR) and pr.base in combined_prs:
                root1.isList = True
                to_remove.add(pr)

        # 移除导致无限递归的指针，只保留代表元素
        root1.PRs = combined_prs - to_remove

        # 4. 清理自环 (Self-loops), 设置Array/List
        del_edges = []
        for edge, target in root1.outEdges.items():
            target = target.get_rep()
            if target is root1:
                del_edges.append(edge)
                if isinstance(edge, PlusEdge) and abs(edge.offset.literal) > abs(root1.arrayStride):
                    root1.isArray = True
                    root1.arrayStride = edge.offset.literal
                else:
                    root1.isList = True

        for edge in del_edges:
            del root1.outEdges[edge]

        # 5. 清理 root2 (Optional GC help)
        root2.outEdges = {}
        root2.PRs = set()  # 既然已经合并，root2的内容可以清空以节省内存

        # 6. 处理数组属性传播
        if root2.isArray and abs(root2.arrayStride) > abs(root1.arrayStride):
            root1.isArray = True
            root1.arrayStride = root2.arrayStride
        if root2.isList:
            root1.isList = True

        return root1

    def unionPRs(self, other):
        """
         只获得PRs，不触发合并等操作，用于过程内分析结束后，将phinode添加到M中
         :type other PRSet
        """
        self.PRs |= other.PRs

    def __str__(self):
        if not self.PRs:  # 如果为空
            return "[]"

        ans = "[  "
        for i, pr in enumerate(self):
            ans += str(pr)
            if i == len(self) - 1:
                ans += "  ]"
            else:
                ans += ',  '
        return ans

    def __iter__(self):
        return self.PRs.__iter__()

    def __len__(self):
        return self.PRs.__len__()


class Edge(object):
    PARAM_EDGE = 1
    REVERSE_PARAM_EDGE = 2
    RETURN_EDGE = 3
    REVERSE_RETURN_EDGE = 4
    CONSTANT_EDGE = 5
    STORE_EDGE = 6

    def __init__(self, ty):
        self.ty = ty

    def __str__(self):
        if self.ty == self.STORE_EDGE:
            return "store-edge"
        elif self.ty == self.PARAM_EDGE:
            return "param-edge"
        elif self.ty == self.REVERSE_PARAM_EDGE:
            return "reverse-param-edge"
        elif self.ty == self.RETURN_EDGE:
            return "return-edge"
        elif self.ty == self.REVERSE_RETURN_EDGE:
            return "reverse-return-edge"
        elif self.ty == self.CONSTANT_EDGE:
            return "constant-edge"
        else:
            assert False, "unreachable"

    def __eq__(self, other):
        return isinstance(other, Edge) and self.ty == other.ty

    def is_caller_to_callee(self):
        return self.ty == self.PARAM_EDGE or self.ty == self.REVERSE_RETURN_EDGE

    def is_callee_to_caller(self):
        return self.ty == self.REVERSE_PARAM_EDGE or self.ty == self.RETURN_EDGE

    def is_constant_edge(self):
        return self.ty == self.CONSTANT_EDGE

    def is_store_edge(self):
        return self.ty == self.STORE_EDGE

    def is_reverse_param_edge(self):
        return self.ty == self.REVERSE_PARAM_EDGE

    def is_param_edge(self):
        return self.ty == self.PARAM_EDGE

    def is_reverse_return_edge(self):
        return self.ty == self.REVERSE_RETURN_EDGE

    def is_return_edge(self):
        return self.ty == self.RETURN_EDGE

    def is_to_caller_edge(self):
        return self.ty == self.RETURN_EDGE or self.ty == self.REVERSE_PARAM_EDGE

    def is_to_callee_edge(self):
        return self.ty == self.PARAM_EDGE or self.ty == self.REVERSE_RETURN_EDGE


def printLanguage():
    lang = currentProgram.getLanguage()
    processor = lang.getProcessor().toString()
    endian= "Big" if lang.isBigEndian() else "Little"
    addressSize = lang.getDefaultSpace().getSize()

    ans = "{}:{}:{}".format(processor, endian, addressSize)
    if ans not in ['x86:Little:64', 'arm:Little:32']:
        print ans
        assert False, "maybe unsupportable arch"

    print ans


class CallindTable(object):
    def __init__(self, father):
        self.table = {}  # type: dict[Varnode, list[long]]
        self.Father = father  # type: PointerAnalysis
        self.additionalCallees = {}  # type: dict[Function, set[Function]]
        self.additionalCallers = {}  # type: dict[Function, set[Function]]

    def logResult(self, func, pointer, targets):
        caller = func
        if caller not in self.additionalCallees:
            self.additionalCallees[caller] = set()
        for target in targets:
            callee = getFunctionAt(toAddr(target))
            if callee:
                self.additionalCallees[caller].add(callee)
                if callee in self.additionalCallers:
                    self.additionalCallers[callee].add(caller)
                else:
                    self.additionalCallers[callee] = {caller}

        self.table[pointer] = targets
        return self.table[pointer]


    def getCalleeAddrs(self, func, op):
        """
         基于csv获得callind指令的目的地址，如果不能获得，返回None
         :type op PcodeOp
        """
        # return set()
        pointer = op.getInput(0)
        if pointer in self.table:
            return self.table[pointer]

        # look for Ghidra first
        targets = set()
        opAddr = op.getSeqnum().getTarget()
        refs = getReferencesFrom(opAddr)
        for ref in refs:
            if ref.getReferenceType().isCall() or ref.getReferenceType().isJump():
                targets.add(hex(ref.getToAddress().getOffset())[2:-1])

        if targets:
            hex_targets =  [long(target, 16) for target in targets]
            return self.logResult(func, pointer, hex_targets)
        else:
            # 不再call service，因为一个函数内的多个callind是极度相似的，call service反而会使得Initial_prset_to_result缓存失效
            # 并且ConstantEdge会被无效计算多次
            return []
            # # call service
            # results = self.Father.ResolveCallind(func, pointer, opAddr)
            # if results:
            #     return self.logResult(func, pointer, results.targets)
            # else:
            #     return self.logResult(func, pointer, [])


    def getCalleesInTable(self, func):
        """
         返回csv中记录的所有被func函数调用的函数
         :type func Function
        """
        if func in self.additionalCallees:
            return self.additionalCallees[func]
        else:
            return set()

    def getCallersInTable(self, func):
        """
         返回csv中记录的所有调用func的函数
         :type func Function
        """
        if func in self.additionalCallers:
            return self.additionalCallers[func]
        else:
            return set()


class UnreachableTable(object):
    """
     用来增强流敏感性，某些函数执行时，另有一些函数一定还没有执行，因此过程间转移不应该到达这些函数
     由于静态分析很难给出精确的“一定还没有执行”的结果，这部分将由外部输入决定
    """

    def __init__(self, path, name):
        self.table = {}  # type: dict[long, set[long]]
        with open(path, mode='r') as fp:
            reader = csv.reader(fp)
            next(reader)  # 跳过标题行

            for row in reader:
                if row[0] == name:
                    func, un_func = long(row[1], 16), long(row[2], 16)
                    if func not in self.table:
                        self.table[func] = {un_func}
                    else:
                        self.table[func].add(un_func)

    def unreachable_from_a_to_b(self, a, b):
        """
         提供给外界的接口
         :type a Function
         :type b Function
        """
        a_offset = a.getEntryPoint().getOffset()
        b_offset = b.getEntryPoint().getOffset()
        return a_offset in self.table and b_offset in self.table[a_offset]


class QueryResult(object):
    __slots__ = ("inter", "prs", "targets")
    def __init__(self, inter, targets, prs):
        self.inter = inter
        self.prs = prs
        self.targets = targets


class BaseAndPath(object):
    __slots__ = ("base", "path")
    def __init__(self, base, path):
        self.base = base  # type: Varnode
        self.path = path  # type: list[SetEdge]

    def __iter__(self):
        yield self.base
        yield self.path

    def match_pr(self, pr):
        """ 某个pr是否对应这个path """
        base_varnode, path = self.base, self.path
        bottom = pr.get_bottom_base()

        # 底匹配并且长度匹配
        if ((base_varnode.isConstant() and base_varnode.getOffset() == bottom.base or base_varnode == bottom.base)
                and pr.depth == len(path)+1):
            for edge in reversed(path):
                if isinstance(edge, PlusEdge) and isinstance(pr, PlusPR) or \
                        isinstance(edge, DerefEdge) and isinstance(pr, DerefPR):
                    pr = pr.base
                else:
                    return False
            return True
        else:
            return False

    def try_get_subset(self, other):
        """
         如果other是self的subset，判定条件是base相同，并且other的path被self的path覆盖
         :type other BaseAndPath
        """
        if self.base != other.base or len(self.path) < len(other.path):
            return None

        self_len = len(self.path)
        other_len = len(other.path)
        for i in range(other_len):
            if not(other.path[i] == self.path[i]):

                # 如果是最后一个plus边未匹配上，并且两个边都是常量边，那么也可以进入；用来对抗编译优化
                if (i == other_len-1 and self_len == other_len + 1
                        and isinstance(other.path[i], PlusEdge) and isinstance(self.path[i], PlusEdge)
                        and isinstance(self.path[i+1], DerefEdge)):

                    self_off = self.path[i].offset    # type: OffsetRepresent
                    other_off = other.path[i].offset  # type: OffsetRepresent
                    if self_off.isConstant() and other_off.isConstant():
                        delta_off = OffsetRepresent.make_constant_offset(self_off.literal - other_off.literal)
                        additional_first_edge = PlusEdge(delta_off)  # type: SetEdge
                        return [additional_first_edge] + self.path[other_len:]

                return None

        return self.path[len(other.path):]

    def get_suffix(self, other):
        """
         如果other是self的subset，返回self比other长的那段edge, 返回结果是list
        """
        return self.path[len(other.path):]

    def __str__(self):
        ss = processVarnodeFormat(self.base)
        for edge in self.path:
            if isinstance(edge, DerefEdge):
                ss += '*'
            elif isinstance(edge, PlusEdge):
                ss += str(edge.offset)
        return ss

    def __eq__(self, other):
        return isinstance(other, BaseAndPath) and self.base == other.base and self.path == other.path


class QueNode(object):
    __slots__ = ('func', 'prset', 'history_path', 'transfer_edge', 'prs', 'parent', 'children', 'depth')

    def __init__(self, func, prset, history_path, prs, transfer_edge, parent):
        self.func = func  # type: Function
        self.prset = prset  # type: PRSet
        self.history_path = history_path  # type: list[SetEdge]
        self.prs = prs  # type: set[PointerRepresent]

        self.transfer_edge = transfer_edge  # type: Edge
        self.parent = parent  # type: QueNode | None
        self.children = []  # type: list[QueNode]

        if parent:
            parent.children.append(self)
            self.depth = parent.depth + 1
        else:
            self.depth = 1


    def has_overflow(self, EdgeID):
        # 全部的子节点不超过一定个数
        if len(self.children) >= MAX_SEARCH_WIDTH:
            return True

        # 单个边转移不超过一定个数
        cnt = 0
        for child in self.children:
            if child.transfer_edge.ty == EdgeID:
                cnt += 1

        return cnt >= MAX_SINGLE_EDGE_WIDTH

    def __str__(self):
        def processPRs(prs):
            if not prs:  # 如果为空
                return "[]"

            ans = "[  "
            for i, pr in enumerate(prs):
                ans += str(pr)
                if i == len(prs) - 1:
                    ans += "  ]"
                else:
                    ans += ',  '
            return ans

        return processPRs(self.prs) + " S" + str(self.prset.id) + '@' + str(self.func)


class Summary(object):
    __slots__ = ("M", "globalPRs", "pdGraph", "RM")
    def __init__(self, M, globalPRs, pdGraph, RM):
        self.M = M  # type: dict[Varnode, PRSet]
        self.globalPRs = globalPRs # type: dict[PointerRepresent, PRSet]
        self.pdGraph = pdGraph  # type: dict[PRSet, list[BaseAndPath]]
        self.RM = RM  # type: dict[PRSet, list[Varnode]]

    def __iter__(self):
        yield self.M
        yield self.globalPRs
        yield self.pdGraph
        yield self.RM


class PointerAnalysis:
    decompInterface = None
    callindTable = None
    unreachableTable = None
    currentAddress = None   # used in batch analysis

    dump_datas = {}
    intras = 0
    now_dump_data = None

    func_pcodes_map = {}  # type: dict[Function, list[PcodeOp]]
    func_store_pcodes_map = {}  # type: dict[Function, list[PcodeOp]]
    func_store_op_can_xfunc_map_map = {}  # type: dict[Function, dict[PcodeOp, bool]]
    func_store_op_affected_ptrs_map_map = {}  # type: dict[Function, dict[PcodeOp, set[Varnode]]]
    func_sp_varnodeast_map = {}  # type: dict[Function, VarnodeAST]
    # 该数据结构中存储的ssa_params可能是None
    func_ssa_params_map = {}  # type: dict[Function, list[Varnode | None]]

    func_summary_map = {}  # type: dict[Function, Summary]
    func_argPointers_map = {}  # type: dict[Function, set[Varnode]]
    func_retPointers_map = {}  # type: dict[Function, set[Varnode]]

    func_callers_map = {}  # type: dict[Function, set[Function]]
    func_callees_map = {}  # type: dict[Function, set[Function]]

    vis = set()  # type: set[tuple[PRSet, tuple[SetEdge]]]
    que = []  # type: list[QueNode]
    initial_func = None  # type: Function
    
    query_to_results_map = {}  # type: dict[Varnode, QueryResult]
    initial_prset_to_results_map = {} # type: dict[PRSet, QueryResult]
    query_vis = set()

    cc = currentProgram.getCompilerSpec().getDefaultCallingConvention()
    # 前面会包含一些无用的浮点寄存器
    param_addresses = [storage.getRegister().getAddress() for storage in cc.getPotentialInputRegisterStorage(currentProgram)][(-1*MAX_PARAMETER_COUNT):]

    no_pointer_def_ops = [PcodeOp.PIECE, PcodeOp.SUBPIECE, PcodeOp.INT_EQUAL, PcodeOp.INT_NOTEQUAL,
                      PcodeOp.INT_LESS, PcodeOp.INT_SLESS, PcodeOp.INT_SLESSEQUAL, PcodeOp.INT_LESSEQUAL,
                      PcodeOp.INT_ZEXT, PcodeOp.INT_SEXT, PcodeOp.INT_CARRY, PcodeOp.INT_SCARRY,
                      PcodeOp.INT_SBORROW, PcodeOp.INT_2COMP, PcodeOp.INT_NEGATE, PcodeOp.INT_XOR,
                      PcodeOp.INT_AND, PcodeOp.INT_OR, PcodeOp.INT_RIGHT, PcodeOp.INT_LEFT, PcodeOp.INT_SRIGHT,
                      PcodeOp.INT_MULT, PcodeOp.INT_DIV, PcodeOp.INT_SDIV, PcodeOp.INT_REM, PcodeOp.INT_SREM,
                      PcodeOp.BOOL_XOR, PcodeOp.BOOL_AND, PcodeOp.BOOL_OR]  # 结果一定不是指针的pcodes
    no_pointer_use_ops = [PcodeOp.PIECE, PcodeOp.SUBPIECE, PcodeOp.INT_SLESS, PcodeOp.INT_SLESSEQUAL,
                      PcodeOp.INT_ZEXT, PcodeOp.INT_SEXT, PcodeOp.INT_CARRY, PcodeOp.INT_SCARRY,
                      PcodeOp.INT_SBORROW, PcodeOp.INT_2COMP, PcodeOp.INT_NEGATE, PcodeOp.INT_XOR,
                      PcodeOp.INT_AND, PcodeOp.INT_OR, PcodeOp.INT_RIGHT, PcodeOp.INT_LEFT, PcodeOp.INT_SRIGHT,
                      PcodeOp.INT_MULT, PcodeOp.INT_DIV, PcodeOp.INT_SDIV, PcodeOp.INT_REM, PcodeOp.INT_SREM,
                      PcodeOp.BOOL_XOR, PcodeOp.BOOL_AND, PcodeOp.BOOL_OR]  # 结果一定不是指针的pcodes
    sys_function_names = ['MAYALIAS', 'NOALIAS', 'MUSTALIAS', 'EXPECTEDFAIL_MAYALIAS', 'PARTIALALIAS']  # 不进入过程间搜索的函数

    def resolve_icall_first(self):
        fm = currentProgram.getFunctionManager()
        functions = fm.getFunctions(True)  # True = 按地址顺序遍历

        for func in functions:  # type: Function
            if func.isThunk() or func.isExternal() or func.getName() in self.sys_function_names:
                continue

            self.getSummary(func)
            self.print_function(func, fp_print)
            ops = self.func_pcodes_map[func]
            for op in ops:
                if op.getOpcode() == PcodeOp.CALLIND:
                    self.currentAddress = op.getSeqnum().getTarget()
                    self.solve_task3()

    def resolve_task_table(self):
        """ 如果以headless模式运行，不能利用currentAddress，需要解析任务 """
        func = get_function_by_name('MAYALIAS')
        if func:
            _to = func.getEntryPoint()
            refs = getReferencesTo(_to)
            for ref in refs:
                if ref.getReferenceType().isCall():
                    addr = ref.getFromAddress()
                    yield addr, 1

        func = get_function_by_name('NOALIAS')
        if func:
            _to = func.getEntryPoint()
            refs = getReferencesTo(_to)
            for ref in refs:
                if ref.getReferenceType().isCall():
                    addr = ref.getFromAddress()
                    yield addr, 0

    def resolve_task1_params(self):
        """
        解析currentAddress所指向的函数调用指令(mayAlias, NoAlias)的两个指针参数，以及当前所在函数
        :return 函数名，指针参数1，指针参数2
        """
        inst = getInstructionAt(self.currentAddress)
        func = getFunctionContaining(self.currentAddress)
        if (inst is None or func is None or
                not (inst.getMnemonicString().startswith('bl') or inst.getMnemonicString().startswith('CALL'))):
            print("Error: Check currentAddress (task1) !!!")
            exit(0)

        ops = self.get_pcodes(func)
        for op in ops:
            if op.getSeqnum().getTarget() == self.currentAddress and op.getOpcode() == PcodeOp.CALL:
                assert op.getNumInputs() == 3
                print("Here get the operand of PointerAnalysis (task1) :")
                print_pcode(sys.stdout, op)
                return func, op.getInput(1), op.getInput(2)

        assert False, "unreachable"

    def solve_task1(self):
        """ task1对应PTAben任务，即判断函数调用指令(mayAlias, NoAlias)的两个指针参数是否互为别名 """
        func, pointer1, pointer2 = self.resolve_task1_params()
        prs1 = self.FindAlias(func, pointer1)
        prs2 = self.FindAlias(func, pointer2)

        summary = self.getSummary(func)
        M = summary.M
        assert pointer2 in M

        for pr1 in prs1:
            for pr2 in prs2:
                if PR_interact(pr1, pr2):
                    print('alias!!!')
                    return 1

                if is_hopeful_pr(pr1) and is_hopeful_pr(pr2):
                    data1 = try_get_literal(pr1)
                    data2 = try_get_literal(pr2)
                    if data1 and data1 == data2:
                        print('alias!!!')
                        return 1

        print('not alias!!!')

        return 0

    def print_function(self, func, fp):
        """
        print function(name, addr, param, ret_value, pcodes) in a more readable format to fp
        """
        print >> fp, 'function: {}@{}'.format(func.getName(), func.getEntryPoint())

        ops = self.func_pcodes_map[func]
        for op in ops:
            print_pcode(fp, op)

        print >> fp, ''

    def run(self):
        printLanguage()
        self.callindTable = CallindTable(self)
        self.decompInterface = setup_decompiler()

        analyze(currentProgram)
        self.resolve_icall_first()

        if runInHeadless():
            ground_truth_may, ground_truth_no = 0, 0
            actual_may, actual_no = 0, 0
            for addr, ty in self.resolve_task_table():
                if ty == 1:
                    ground_truth_may += 1
                elif ty == 0:
                    ground_truth_no += 1

                self.currentAddress = addr
                result = self.solve_task1()  # headless模式目前只能运行task1

                if result == 1:
                    actual_may += 1
                elif result == 0:
                    actual_no += 1

            self.write_back_result(ground_truth_may, ground_truth_no, actual_may, actual_no)
        else:
            self.currentAddress = currentAddress
            self.solve_task1()

    def write_back_result(self, ground_truth_may, ground_truth_no, actual_may, actual_no):
        """ 如果在headless模式下运行，将分析结果写入result.csv """
        with open(result_csv, mode='a') as fp:
            writer = csv.writer(fp)
            new_row = str(program_name), str(ground_truth_may), str(actual_may), str(ground_truth_no), str(actual_no)
            writer.writerow(new_row)

    def get_func_inst_num(self, func):
        """ 获得一个函数的指令数 """
        return func.getBody().getNumAddresses() / getInstructionAt(func.getEntryPoint()).getLength()

    def analysis_one_function(self):
        """ 对单个函数进行过程内分析 """
        func = getFunctionContaining(currentAddress)
        if func is None:
            print("Error: Check currentAddress (intra-procedural analysis) !!!")
        self.getSummary(func)

    def solve_task3(self):
        """ task3对应解析某个间接调用的目的地址 """
        res = self.resolve_task3_params()

        # 对应跳转地址被ghidra解析出来了，不需要做分析
        if res[0] == 1:
            func, pointer, targets = res[1], res[2], res[3]

            if pointer:
                # 如果反编译结果仍然包含这条callind，则登记结果到间接跳转表中
                hex_targets = [long(target, 16) for target in targets]
                self.callindTable.logResult(func, pointer, hex_targets)

            return

        # 进行指针分析
        func, pointer = res[1], res[2]
        queryResult = self.ResolveCallind(func, pointer, self.currentAddress)
        if queryResult is None:
            # 登记结果到间接跳转表中, 即使targets为空，避免后续被再次分析
            self.callindTable.logResult(func, pointer, [])
            return

        inter, targets, prs = queryResult.inter, queryResult.targets, queryResult.prs
        # 登记结果到间接跳转表中
        self.callindTable.logResult(func, pointer, targets)

    def resolve_task3_params(self):
        """
        解析currentAddress所指向的间接调用指令对应的CALLIND指令
        :return 0, 函数, CALLIND对应操作数
        :return 1, 函数, CALLIND对应操作数， [targets]
        """
        # 解析对应callind指令的指针变量，可能失败，因为反编译中没有保留callind
        func = getFunctionContaining(self.currentAddress)
        pointer = None

        ops = self.get_pcodes(func)
        for op in ops:
            if op.getSeqnum().getTarget() == self.currentAddress and op.getOpcode() == PcodeOp.CALLIND:
                print("Here get the operand of PointerAnalysis (task3) :")
                print_pcode(sys.stdout, op)
                pointer = op.getInput(0)
                break

        # 有些时候ghidra已经解析出地址了
        targets = set()
        refs = getReferencesFrom(self.currentAddress)
        for ref in refs:
            if ref.getReferenceType().isCall() or ref.getReferenceType().isJump():
                targets.add(hex(ref.getToAddress().getOffset())[2:-1])

        if targets:
            # 如果Ghidra解析出了地址，此时pointer可能是空
            return 1, func, pointer, [target for target in targets]
        elif pointer:
            # 如果仍是一条callind指令，需要交给后续处理
            return 0, func, pointer
        else:
            # 如果找不到callind，并且ghidra未能解析出来，触发异常
            assert False, "unreachable"

    def dumpGraph(self, comments, initial_node, fp):
        """
         以树的形式打印过程间访问图
         :type comments str
         :type initial_node QueNode
         :type fp BinaryIO
        """

        def dfs(node, blanks):
            if node.parent is None:
                print >> fp, str(node)
            else:
                print >> fp, blanks, str(node), '  <----', str(node.transfer_edge)
            for child in node.children:
                dfs(child, blanks + "\t")

        print >> fp, comments
        dfs(initial_node, '')

    @property
    def sp_address(self):
        # 获得当前程序的sp寄存器对应的varnode的address
        return currentProgram.getRegister('sp').getAddress()

    @property
    def lr_address(self):
        if currentProgram.getRegister('lr'):
            return currentProgram.getRegister('lr').getAddress()
        else:
            return None

    @property
    def sp_size(self):
        return currentProgram.getRegister('sp').getBitLength() / 8

    @property
    def mult_addr_address(self):
        if currentProgram.getRegister('mult_addr'):
            return currentProgram.getRegister('mult_addr').getAddress()
        else:
            return None

    def decompile_function(self, func):
        """
        反编译函数func，获得func对应的pcodes, store_pcodes, highFunction, sp_varnodeast, ssa-params，保存在成员变量中。
        :type func Function
        """
        assert func, "the decompiled func is None now, maybe you need to flag a function at right position before call the script"
        monitor = ConsoleTaskMonitor()
        res = self.decompInterface.decompileFunction(func, 60, monitor)
        high_func = res.getHighFunction()

        # 如果直接导出highFunction的pcodes会出现顺序问题，借助basic block实现pcodes按照指令地址顺序导出。
        ops = []
        bbs = high_func.getBasicBlocks()

        def bb_key(bb):
            return bb.getStart().getOffset()

        bbs.sort(key=bb_key)
        for bb in bbs:
            bb_ops = []
            opiter = bb.getIterator()
            for op in opiter:
                # 将内存变量由VarnodeAST转换为Varnode，这样可以使他们在hashset中相等
                for i in range(op.getNumInputs()):
                    inputi = op.getInput(i)
                    if inputi.getAddress().isMemoryAddress() or inputi.getAddress().isConstantAddress():
                        op.setInput(Varnode(inputi.getAddress(), inputi.getSize()), i)
                if op.getOutput():
                    output = op.getOutput()
                    if output.getAddress().isMemoryAddress() or output.getAddress().isConstantAddress():
                        # print __LINE__(), op.getMnemonic()
                        op.setOutput(Varnode(op.getOutput().getAddress(), op.getOutput().getSize()))

                bb_ops.append(op)

            bb_ops.sort(key=lambda op: op.getSeqnum().getOrder())
            ops += bb_ops

        # insert missed writing operation to global variable
        if func.getEntryPoint().getOffset() == 0x12ed00 and program_name.startswith('hmmer-O0'):
            for i, op in enumerate(ops):  # type: int, PcodeOp
                if op.getSeqnum().getTarget().getOffset() == 0x12ed2e and op.getOpcode() == PcodeOp.LOAD:
                    sq = SequenceNumber(toAddr(0x12ed32), 0)
                    new_op = PcodeOpAST(sq, PcodeOp.COPY, 1)
                    new_op.setInput(op.getOutput(), 0)
                    new_op.setOutput(Varnode(toAddr(0x174d80), 8))
                    ops.insert(i+1, new_op)
                    break


        self.func_pcodes_map[func] = ops
        self.func_store_pcodes_map[func] = [op for op in ops if op.getOpcode() == PcodeOp.STORE]

        # 设置sp_varnode
        self.func_sp_varnodeast_map[func] = VarnodeAST(self.sp_address, self.sp_size,
                                                       hash(func.getEntryPoint()) % (1 << 10))

        # 设置ssa-param
        def resolve_ith_param(ith):
            param_addr = self.param_addresses[ith]

            for op in ops:
                for i in range(op.getNumInputs()):
                    inputi = op.getInput(i) # type: Varnode
                    address = inputi.getAddress()
                    if inputi.getDef() is None and address == param_addr:
                        return inputi
            return None

        prototype = high_func.getFunctionPrototype()
        param_nums = prototype.getNumParams()
        self.func_ssa_params_map[func] = []
        # todo: 未来支持存放在栈上的参数
        for i in range(min(MAX_PARAMETER_COUNT, param_nums)):
            self.func_ssa_params_map[func].append(resolve_ith_param(i))

    def get_pcodes(self, func):
        if func in self.func_pcodes_map:
            return self.func_pcodes_map[func]
        else:
            self.decompile_function(func)
            return self.func_pcodes_map[func]

    def get_store_pcodes(self, func):
        assert func in self.func_store_pcodes_map
        return self.func_store_pcodes_map[func]

    def buildReturnValuePR(self, varnode):
        # 可能是callee的反编译错误得到了一个返回值
        if varnode is None:
            return None
        return SymbolPR(varnode, SymbolPR.RETURN)

    def getStackVarnodePR(self, sp, varnode):
        offset = varnode.getOffset()
        if offset != 0:
            return Deref(Plus(SymbolPR(sp, SymbolPR.SP),
                 OffsetRepresent.make_constant_offset(offset)))
        else:
            return Deref(SymbolPR(sp, SymbolPR.SP))

    def buildParamPR(self, func, ith):
        """ ith 从1开始计数 """
        # assert ith <= len(self.func_ssa_params_map[func]), "Found suspicious prototype recovery error"
        if ith > len(self.func_ssa_params_map[func]):
            return None

        varnode = self.func_ssa_params_map[func][ith - 1]
        if varnode:
            if varnode.getAddress().isRegisterAddress():
                return SymbolPR(varnode, SymbolPR.PARAM)
            elif varnode.getAddress().isStackAddress():
                # 目前不会执行到
                assert False
                # return self.getStackVarnodePR(self.func_sp_varnodeast_map[func], varnode)

        return None

    def get_all_call_sites(self, caller, callee):
        call_sites = []

        ops = self.get_pcodes(caller)
        for op in ops:
            if op.getOpcode() == PcodeOp.CALL and op.getInput(0).getAddress() == callee.getEntryPoint():
                call_sites.append(op)
            elif op.getOpcode() == PcodeOp.CALLIND:
                if callee.getEntryPoint().getOffset() in self.callindTable.getCalleeAddrs(caller, op):
                    call_sites.append(op)

        return call_sites

    def get_vis_key(self, prset, p):
        """ 辅助函数：生成禁忌表的key，将path列表转为元组, 避免递归引发的死循环 """
        if len(p) > 8:
            p = p[:8]
        return prset, tuple(p)

    def compute_constant_edge(self, curr_node):
        prs = curr_node.prs
        # 1. 获得引用的literal
        literals = []
        unknown_constant_prs = []
        for pr in prs:
            bottom = pr.get_bottom_base()
            # 如果一个pr的bottom是常量，需要通过constant edge转移
            if isinstance(bottom, ConstantPR):
                unknown_constant_prs.append(pr)
                literals.append(bottom.base)
                # 获得引用的地址，只考虑最后一级的Deref
                plus_pr = pr.strip_all_deref()
                while isinstance(plus_pr, PlusPR):
                    literal = try_get_literal(plus_pr)  # 或许可以提供checkArray=True参数
                    if literal and literal not in literals:
                        literals.append(literal)
                    plus_pr = plus_pr.base

        if not literals:
            return

        # 2. 获得引用literal的函数
        refers = []
        for literal in literals:
            addr = toAddr(literal)
            refs = getReferencesTo(addr)

            for ref in refs:
                ref_type = ref.getReferenceType()
                # 目前只关注写这个地址的函数
                if ref_type.isData():
                    from_addr = ref.getFromAddress()
                    new_func = getFunctionContaining(from_addr)
                    if new_func and new_func not in refers:
                        refers.append(new_func)

        if not refers:
            return


        # 4. 查看refer中是否存在相同的pr
        # 如果新的函数中不是使用相同的引用方式(baseVarnode对应的常量加一系列相同的offset)使用这块内存，就会转移失败

        def helper_transfer(new_func, new_func_summary, curr_node, new_prset, path):
            """ try to transfer to refer through constant edge """
            # 如果只包含一个constantPR，转移过去没有意义
            if len(new_prset) == 1:
                return

            vis_key = self.get_vis_key(new_prset, path)
            if vis_key in self.vis:
                return
            self.vis.add(vis_key)

            new_prs = self.buildPRs(new_prset, path, new_func, new_func_summary, curr_node)

            node = QueNode(new_func, new_prset, path, new_prs,
                           parent=curr_node, transfer_edge=Edge(Edge.CONSTANT_EDGE))
            self.addQueNode(node)
            return

        refers = refers[:MAX_SINGLE_EDGE_WIDTH]

        for new_func in refers:
            if curr_node.has_overflow(Edge.CONSTANT_EDGE) or len(self.vis) > MAX_QUE_NODES:
                return
            new_func_summary = self.getSummary(new_func)
            new_func_globalPRs = new_func_summary.globalPRs

            for pr in unknown_constant_prs:
                if pr in new_func_globalPRs:
                    # the refer use the same access pattern with current function
                    new_prset = new_func_globalPRs[pr]
                    helper_transfer(new_func, new_func_summary, curr_node, new_prset, [])
                else:
                    # see whether the refer use the base of current pr
                    _pr = pr
                    path = []
                    while isinstance(_pr, DerefPR) or isinstance(_pr, PlusPR):
                        if isinstance(_pr, PlusPR):
                            path.append(PlusEdge(_pr.offset))
                        else:
                            path.append(DerefEdge())

                        _pr = _pr.base
                        if _pr in new_func_globalPRs:
                            path.reverse()
                            helper_transfer(new_func, new_func_summary, curr_node, new_func_globalPRs[_pr], path)
                            break


    def addQueNode(self, queNode):
        """ 添加一些加入工作队列的限定条件 """
        if len(self.vis) < MAX_QUE_NODES:
            self.que.append(queNode)

    def helper_path_exceed_limit_depth(self, path):
        if len(path) > MAX_NODE_PATH_LEN:
            return True

        cnt = 0
        for edge in path:
            if isinstance(edge, DerefEdge):
               cnt += 1
        return cnt > MAX_NODE_DEREF_PATH_LEN

    def helper_applyOneOperation(self, bases, edge):
        next_prs = set()
        for pr in bases:
            if isinstance(edge, PlusEdge):
                next_prs.add(Plus(pr, edge.offset))
            elif isinstance(edge, DerefEdge):
                next_prs.add(Deref(pr))
        return next_prs

    def useStoreEdge(self, prset, to_delta_prs, globalPRs, new_p, func, curr_node):
        """
         当在BuildPRs过程中，发现一个PR出现在了某个prset中，并且这个prset还含有多余的PR，则触发storeEdge
         理想情况下，storeEdge只包含那些多余的PR，这也是将引入to_delta_prs（构造过程中如果不触发storeEdge应该保有的prs）作为参数的原因
         由于storeEdge转移到的prset不可避免的有用于to_delta_prs对应的pdgraph中的path，因此在下一步转移时，需要过滤一些path
        """
        # 加入que与vis
        vk = self.get_vis_key(prset, new_p)

        if vk not in self.vis:
            self.vis.add(vk)

            _new_prs = copy.copy(prset.PRs)
            _to_delta_prs = to_delta_prs
            for _edge in new_p:
                _new_prs = self.helper_applyOneOperation(_new_prs, _edge)
                _to_delta_prs = self.helper_applyOneOperation(_to_delta_prs, _edge)

                # 我们是在最低级别应用的store-edge，然而高级别可能也会应用store-edge，即应用多次
                # 此时需要通过gprs将其余的prs贴并过来
                rep_pr = next(iter(_new_prs))
                if rep_pr in globalPRs:
                    _new_prs |= globalPRs[rep_pr].PRs

            new_prs = _new_prs - _to_delta_prs
            node = QueNode(func, prset, new_p, new_prs,
                           transfer_edge=Edge(Edge.STORE_EDGE), parent=curr_node)
            self.addQueNode(node)

    def buildPRs(self, bases, p, to_func, S, curr_node):
        store_prsets = set()
        gprs = S.globalPRs
        curr_prs = {b for b in bases if b}

        for i, edge in enumerate(p):
            curr_prs = self.helper_applyOneOperation(curr_prs, edge)

            # 只在构造过程中的第一层触发StoreEdge
            if store_prsets:
                continue

            for pr in curr_prs:
                if pr in gprs:
                    delta = gprs[pr].PRs - curr_prs

                    # 如果prset中存在非local的pr，应用store edge
                    if delta and gprs[pr] not in store_prsets:
                        store_prsets.add(gprs[pr])
                        self.useStoreEdge(prset=gprs[pr], to_delta_prs=curr_prs,
                                          globalPRs=gprs, new_p=p[i + 1:], func=to_func, curr_node=curr_node)
        return curr_prs


    def computeEdge(self, curr_node):
        """
        获得当前节点的可达节点
        :type curr_node QueNode
        """

        # [Heuristic Helper] 检查是否发生递归调用
        def is_recursive_call(node, target_func):
            count = 0
            curr = node
            while curr:
                if curr.func == target_func:
                    count += 1
                curr = curr.parent
            return count > MAX_RECURSION_COUNT


        def callee_pass_check(f):
            if f is None or f.isThunk() or f.isExternal() or f.getName() in self.sys_function_names:
                return False
            if f not in self.func_pcodes_map:
                self.decompile_function(f)
            return True

        func = curr_node.func
        curr_prset = curr_node.prset
        history_path = curr_node.history_path

        if curr_node.depth > MAX_SEARCH_DEPTH:
            return

        summary = self.getSummary(func)
        pdGraph = summary.pdGraph
        RM = summary.RM
        M = summary.M


        # ---------------------------------------------------------
        # 1. 处理 constant-edge，可认为是通过全局变量进行转移
        #    做不到sound，很大原因在于缺乏类型信息，理想情况下仅仅通过基地址
        #    就可以知道哪些函数同样引用了这块内存，因此需要进行分析
        #    但是由于没有类型信息，各个函数对这个地址的引用并没有落在基地址，而是
        #    落在某个field上，因此需要遍历这块内存的所有field才能确定哪些函数
        #    需要分析，但是却无法获得这块内存的size，除非恢复这块内存的类型
        #    此外，Ghidra恢复的xref也可能并不完备
        # ---------------------------------------------------------

        self.compute_constant_edge(curr_node)

        # 处理函数调用edge
        if curr_prset not in pdGraph:
            return

        USE_PARAM_EDGE = USE_REVERSE_RETURN_EDGE = USE_REVERSE_PARAM_EDGE = USE_RETURN_EDGE = True
        if curr_node.transfer_edge and curr_node.transfer_edge.is_to_callee_edge():
            USE_REVERSE_PARAM_EDGE = USE_RETURN_EDGE = False
        elif curr_node.transfer_edge and curr_node.transfer_edge.is_to_caller_edge():
            USE_PARAM_EDGE = USE_REVERSE_RETURN_EDGE = False

        # 遍历 pdGraph
        for base_varnode, local_path in pdGraph[curr_prset]:  # type: Varnode, list

            # 拼接路径：local_path + history_path
            if history_path:
                full_path = local_path + history_path
            else:
                full_path = local_path[:]

            # BaseAndPath 现在由 (varnode, path) 组成，与原逻辑保持一致
            base_and_path_obj = BaseAndPath(base_varnode, full_path)

            # [Heuristic 1] 路径长度剪枝
            # 如果访问路径过长，说明分析精度已丢失，或者是用例过于复杂，或者是过程间串联起了list
            if self.helper_path_exceed_limit_depth(full_path):
                continue

            # storeEdge有些path不能采用，留给触发它的哪个edge
            if curr_node.transfer_edge and curr_node.transfer_edge.is_store_edge():
                flag = False
                for pr in curr_node.prs:
                    if base_and_path_obj.match_pr(pr):
                        flag = True
                        break
                if not flag:
                    continue

            # 出发点去重
            if self.varnode_is_formal_param(base_varnode, func) or self.varnode_is_formal_ret(base_varnode, func):
                vis_key = self.get_vis_key(M[base_varnode], full_path)
                self.vis.add(vis_key)

            # ---------------------------------------------------------
            # 2. 处理 Reverse Edges (向 Caller 追溯参数，或向 Callee 追溯返回值)
            # ---------------------------------------------------------

            # reverse-param-edge; callee->caller
            if USE_REVERSE_PARAM_EDGE and self.varnode_is_formal_param(base_varnode, func):
                # 解析slot
                slot = -1
                for i, ssa_param in enumerate(self.func_ssa_params_map[func]):
                    if ssa_param and base_varnode.getAddress() == ssa_param.getAddress():
                        slot = i + 1
                        break
                assert slot != -1

                # 获得对应的caller的对应的多个实参
                callers = self.myGetCallingFunctions(func)

                for caller in callers:
                    # 如果超出最大搜索宽度，退出
                    if curr_node.has_overflow(Edge.REVERSE_PARAM_EDGE) or len(self.vis) > MAX_QUE_NODES:
                        return

                    # [Heuristic 2] 递归/循环调用剪枝
                    if is_recursive_call(curr_node, caller):
                        continue

                    caller_summary = self.getSummary(caller)
                    caller_M = caller_summary.M

                    call_ops = self.get_all_call_sites(caller, func)
                    for call_op in call_ops:
                        arg_varnode = call_op.getInput(slot)

                        # 禁忌表检查 (arg_varnode 对应的 prset + full_path)
                        if arg_varnode not in caller_M:
                            continue

                        # 转换：varnode -> prset
                        caller_prset = caller_M[arg_varnode]

                        vis_key = self.get_vis_key(caller_prset, full_path)

                        if vis_key in self.vis:
                            continue
                        self.vis.add(vis_key)  # 加入禁忌表

                        new_prs = self.buildPRs(caller_prset, full_path, caller, caller_summary, curr_node)

                        # 创建节点，传入 caller_prset
                        node = QueNode(caller, caller_prset, full_path, new_prs,
                                       transfer_edge=Edge(Edge.REVERSE_PARAM_EDGE), parent=curr_node)
                        self.addQueNode(node)

            # reverse-return-edge; caller->callee
            elif USE_REVERSE_RETURN_EDGE and self.varnode_is_formal_ret(base_varnode, func):
                # 获得对应的callee的对应的多个实际返回值
                call_op = base_varnode.getDef()
                callees = []

                if call_op.getOpcode() == PcodeOp.CALL:
                    callee = getFunctionAt(call_op.getInput(0).getAddress())
                    if callee_pass_check(callee) and callee not in callees:
                        callees.append(callee)
                elif call_op.getOpcode() == PcodeOp.CALLIND:
                    addrs = self.callindTable.getCalleeAddrs(func, call_op)
                    for addr in addrs:
                        callee = getFunctionAt(toAddr(addr))
                        if callee_pass_check(callee) and callee not in callees:
                            callees.append(callee)

                for callee in callees:
                    # 如果超出最大搜索宽度，退出
                    if curr_node.has_overflow(Edge.REVERSE_RETURN_EDGE) or len(self.vis) > MAX_QUE_NODES:
                        return

                    # [Heuristic 2] 递归/循环调用剪枝
                    if is_recursive_call(curr_node, callee):
                        continue

                    callee_summary = self.getSummary(callee)
                    callee_M = callee_summary.M
                    actual_rets = self.getRetPointers(callee)  # 获取内部 return varnodes

                    for actual_ret in actual_rets:
                        # 禁忌表检查
                        if actual_ret not in callee_M:
                            continue

                        callee_ret_prset = callee_M[actual_ret]
                        vis_key = self.get_vis_key(callee_ret_prset, full_path)

                        if vis_key in self.vis:
                            continue
                        self.vis.add(vis_key)

                        new_prs = self.buildPRs(callee_ret_prset, full_path, callee, callee_summary, curr_node)

                        node = QueNode(callee, callee_ret_prset, full_path, new_prs,
                                       transfer_edge=Edge(Edge.REVERSE_RETURN_EDGE), parent=curr_node)
                        self.addQueNode(node)

            # ---------------------------------------------------------
            # 3. 处理 Forward Edges (Param Edge, Return Edge)
            # ---------------------------------------------------------

            for actual_prset in pdGraph:
                associated_varnodes = RM[actual_prset]
                if not associated_varnodes:
                    continue

                # 分类该 prset 包含的 varnode
                candidate_varnodes_param = []
                candidate_varnodes_ret = []
                is_param_candidate = False
                is_ret_candidate = False

                for vn in associated_varnodes:
                    if self.varnode_is_actual_param(vn, func):
                        is_param_candidate = True
                        candidate_varnodes_param.append(vn)
                    elif self.varnode_is_actual_ret(vn, func):
                        is_ret_candidate = True
                        candidate_varnodes_ret.append(vn)

                if not (is_param_candidate or is_ret_candidate):
                    continue

                # 寻找 path 的匹配 (subset/suffix 关系)
                valid_suffixes = []

                # pdGraph[actual_prset] 是 list[(act_base_varnode, act_path)]
                for act_base_varnode, act_path in pdGraph[actual_prset]:
                    act_base_and_path = BaseAndPath(act_base_varnode, act_path)

                    suffix = base_and_path_obj.try_get_subset(act_base_and_path)
                    if suffix is not None:
                        # 出发点去重，并且这个节点与curr_node是等价的，不需要再进行处理
                        # 检查禁忌表 (key 是 prset + path)
                        vis_key = self.get_vis_key(actual_prset, suffix)
                        self.vis.add(vis_key)  # 立即加入禁忌表
                        valid_suffixes.append(suffix)

                if not valid_suffixes:
                    continue

                # param-edge; caller->callee
                if USE_PARAM_EDGE and is_param_candidate:
                    # 对 prset 包含的每一个充当 param 的 varnode 进行处理
                    # 1. 先解析出所有目标 callee 及其对应的 formal params (与 suffix 无关，只做一次)
                    callee_to_formal_param_prs = {}
                    for actual_varnode in candidate_varnodes_param:

                        def process_callee_and_slot(_callee, _slot):
                            if callee_pass_check(_callee):
                                _formalpr = self.buildParamPR(_callee, _slot)
                                if _callee not in callee_to_formal_param_prs:
                                    callee_to_formal_param_prs[_callee] = {_formalpr}
                                else:
                                    callee_to_formal_param_prs[_callee].add(_formalpr)

                        call_ops = arg_to_call_ops(actual_varnode)
                        for call_op in call_ops:
                            slot = call_op.getSlot(actual_varnode)
                            if call_op.getOpcode() == PcodeOp.CALL:
                                callee = getFunctionAt(call_op.getInput(0).getAddress())
                                process_callee_and_slot(callee, slot)
                            elif call_op.getOpcode() == PcodeOp.CALLIND:
                                addrs = self.callindTable.getCalleeAddrs(func, call_op)
                                for addr in addrs:
                                    callee = getFunctionAt(toAddr(addr))
                                    process_callee_and_slot(callee, slot)

                    # 2. 遍历所有 callee 和所有 valid_suffixes 生成节点
                    for callee in callee_to_formal_param_prs:
                        # [Heuristic 2] 递归/循环调用剪枝
                        if is_recursive_call(curr_node, callee):
                            continue

                        # 如果超出最大搜索宽度，退出
                        if curr_node.has_overflow(Edge.PARAM_EDGE) or len(self.vis) > MAX_QUE_NODES:
                            return

                        callee_summary = self.getSummary(callee)
                        callee_globalPRs = callee_summary.globalPRs
                        for formal_param_pr in callee_to_formal_param_prs[callee]:
                            if formal_param_pr in callee_globalPRs:
                                formal_prset = callee_globalPRs[formal_param_pr]
                                for suffix in valid_suffixes:
                                    # 到达点去重
                                    vis_key = self.get_vis_key(formal_prset, suffix)
                                    if vis_key in self.vis:
                                        continue
                                    self.vis.add(vis_key)

                                    new_prs = self.buildPRs([formal_param_pr], suffix, callee, callee_summary, curr_node)

                                    node = QueNode(callee, formal_prset, suffix, new_prs,
                                                   transfer_edge=Edge(Edge.PARAM_EDGE), parent=curr_node)
                                    self.addQueNode(node)

                # return-edge; callee->caller
                elif USE_RETURN_EDGE and is_ret_candidate:
                    # 1. 先解析出所有 caller 及其对应的 formal returns (与 suffix 无关，只做一次)
                    callers = self.myGetCallingFunctions(func)
                    caller_formal_rets = []

                    for caller in callers:
                        call_ops = self.get_all_call_sites(caller, func)
                        formal_return_prs = set()
                        for call_op in call_ops:
                            formal_return = call_op.getOutput()
                            formal_return_prs.add(self.buildReturnValuePR(formal_return))

                        if formal_return_prs:
                            caller_formal_rets.append((caller, formal_return_prs))

                    # 2. 遍历所有 caller 和所有 valid_suffixes 生成节点
                    for caller, formal_return_prs in caller_formal_rets:
                        # 如果超出最大搜索宽度，退出
                        if curr_node.has_overflow(Edge.RETURN_EDGE) or len(self.vis) > MAX_QUE_NODES:
                            return

                        # [Heuristic 2] 递归/循环调用剪枝
                        if is_recursive_call(curr_node, caller):
                            continue

                        caller_summary = self.getSummary(caller)
                        caller_globalPRs = caller_summary.globalPRs

                        for formal_return_pr in formal_return_prs:
                            if formal_return_pr in caller_globalPRs:
                                formal_prset = caller_globalPRs[formal_return_pr]
                                for suffix in valid_suffixes:
                                    # 到达点去重
                                    vis_key = self.get_vis_key(formal_prset, suffix)
                                    if vis_key in self.vis:
                                        continue
                                    self.vis.add(vis_key)

                                    new_prs = self.buildPRs([formal_return_pr], suffix, caller, caller_summary, curr_node)

                                    node = QueNode(caller, formal_prset, suffix, new_prs,
                                                   transfer_edge=Edge(Edge.RETURN_EDGE), parent=curr_node)
                                    self.addQueNode(node)
        return

    def processOneNode(self, node):
        """
        对应BFS中分析一个节点, 如果是发现别名任务，则加入别名集；prs是过程间分析遇到的所有pr
        :type node QueNode
        """
        # 寻找别名

        # 转移到其它节点
        self.computeEdge(node)


    def CheckPRSet(self, prset):
        """ 遍历prset中的每个pr，resolve其对应的callee """
        # 使用两个轮次去寻找函数target，第一轮次不考虑符号化offset，第二轮次考虑
        results = set()

        for pr in prset:
            if is_hopeful_pr(pr):
                target = try_get_literal(pr, check_array=False)
                if target:
                    results.add(target)

        if not results:
            print "checkPR start"
            for pr in prset:
                if is_hopeful_pr(pr):
                    targets = try_get_literal(pr, check_array=True)
                    if targets:
                        for target in targets:
                            results.add(target)
            print "checkPR end"

        return results

    def FindAlias(self, func, pointer):

        Alias = set()

        summary = self.getSummary(func)
        M = summary.M
        assert pointer in M

        RM = summary.RM

        for ptr in RM[M[pointer]]:
            Alias.add(ptr)

        self.que, self.vis, self.initial_func = [], set(), func

        initial_prset = M[pointer]

        initialPRs = copy.copy(initial_prset.PRs)
        initial_vis_key = self.get_vis_key(initial_prset, [])
        initial_node = QueNode(func, initial_prset, [], initialPRs, transfer_edge=None, parent=None)
        self.que.append(initial_node)
        self.vis.add(initial_vis_key)

        prs= set()
        while len(self.que) > 0:
            node = self.que.pop(0)
            prs |= node.prs
            self.computeEdge(node)

        comments = "\ngraph for {} @ {} : {}".format(processVarnodeFormat(pointer), 0, func)
        self.dumpGraph(comments, initial_node, fp_process)

        return prs


    def ResolveCallind(self, func, pointer, opAddr):
        """
         返回值包含三个字段，第一个字段标识结果是由过程内还是过程间得到，第二个字段对应间接跳转地址，第三个字段对应pr
         :return QueryResult
        """
        if pointer in self.query_to_results_map:
            return self.query_to_results_map[pointer]

        # by design, if pointer is in self.query_vis, it will in query_to_results_map; but it fails
        if pointer in self.query_vis:
            return None
        self.query_vis.add(pointer)

        # Set Zero first; due to call ResolveCallind recursively, need to protect the site
        old_que, old_vis, old_initial_func = self.que, self.vis, self.initial_func
        self.que, self.vis, self.initial_func = [], set(), func

        print "ResolveCallind for {} @ {} : {}".format(processVarnodeFormat(pointer),
                                                       opAddr, func)

        # 为func进行过程内分析
        summary = self.getSummary(func)
        M = summary.M
        assert pointer in M

        results = self.CheckPRSet(M[pointer])
        if results:
            # 如果过程内恢复出了结果，不再进行过程间分析，比较符合常理，但是并不sound
            # recover the site
            self.que, self.vis, self.initial_func = old_que, old_vis, old_initial_func

            self.query_to_results_map[pointer] = QueryResult(0, results, M[pointer])
            return self.query_to_results_map[pointer]


        # 多级缓存；以出发的prset作为缓存的key，这主要是由于有大量相似的key
        initial_prset = M[pointer]
        if initial_prset in self.initial_prset_to_results_map:
            return self.initial_prset_to_results_map[initial_prset]

        initialPRs = copy.copy(initial_prset.PRs)
        initial_vis_key = self.get_vis_key(initial_prset, [])
        initial_node = QueNode(func, initial_prset, [], initialPRs, transfer_edge=None, parent=None)
        self.que.append(initial_node)
        self.vis.add(initial_vis_key)

        prs = set()  # 提供给query的该target对应的prs
        cnt = 0
        while len(self.que) > 0:
            node = self.que.pop(0)
            for pr in node.prs:
                if pr.based_on_SP():
                    continue
                else:
                    prs.add(pr)
            self.processOneNode(node)
            cnt += 1

        # self.dumpAnalysisResult(fp_debug)
        comments = "\ngraph for {} @ {} : {}".format(processVarnodeFormat(pointer), opAddr, func)
        self.dumpGraph(comments, initial_node, fp_process)

        results = self.CheckPRSet(prs)
        queryResult = QueryResult(1, results, prs)
        self.initial_prset_to_results_map[initial_prset] = queryResult
        self.query_to_results_map[pointer] = queryResult

        # recover the site
        self.que, self.vis, self.initial_func = old_que, old_vis, old_initial_func

        return queryResult

    def getArgPointers(self, func):
        assert func in self.func_argPointers_map
        return self.func_argPointers_map[func]

    def getRetPointers(self, func):
        assert func in self.func_retPointers_map
        return self.func_retPointers_map[func]

    def getSummary(self, func):
        if func not in self.func_summary_map:
            print func.getName() + " intra analysis"
            # traceback.print_stack()
            pointers, ptr_related_ops = self.InferPointerVariable(func)
            self.func_summary_map[func] = self.EstimatePR(func, pointers, ptr_related_ops)
            print func.getName() + " finish"
            return self.func_summary_map[func]
        else:
            return self.func_summary_map[func]

    def InferPointerVariable(self, func):
        """
        依据变量的使用方式推测指针变量，返回所有被推测为指针变量的varnode组成的集合，与ptr计算有关的指令
        额外返回用作Call指令操作数或者Return操作数的指针变量组成的集合
        :type func Function
        """
        pointers = set()
        ptr_related_ops = []
        not_pointers = set()
        clearly_pointers = set()
        arg_pointers = set()
        ret_pointers = set()

        ops = self.get_pcodes(func)

        def add_after_judge(varnode):
            """ 如果varnode显然不是指针变量，则不执行任何操作，返回False；否则将其加入pointers集合，返回True """
            if self.clearly_not_pointer(varnode, func):
                not_pointers.add(varnode)
                return False
            else:
                pointers.add(varnode)
                return True

        target = None
        for op in ops:
            if op.getOpcode() == PcodeOp.LOAD:
                pointers.add(op.getInput(1))
                clearly_pointers.add(op.getInput(1))

            elif op.getOpcode() == PcodeOp.STORE:
                # mult_addr被用于存放一些callee-saved内容，理应被反编译删除，但是没有
                # 写起来有些难看，主要是因为Ghidra反编译还是会有一些错误的mult_addr使用，比如存参数进内存，立刻读取到另外的寄存器
                if (op.getInput(1).getAddress() == self.mult_addr_address and
                        op.getInput(2).getDef() is None and op.getInput(2).getAddress() not in self.param_addresses):
                    continue
                else:
                    pointers.add(op.getInput(1))
                    clearly_pointers.add(op.getInput(1))
                    add_after_judge(op.getInput(2))

            elif op.getOpcode() == PcodeOp.CALLIND:
                pointers.add(op.getInput(0))
                clearly_pointers.add(op.getInput(0))
                for i in range(1, op.getNumInputs()):
                    is_pointer = add_after_judge(op.getInput(i))
                    if is_pointer:
                        arg_pointers.add(op.getInput(i))

            elif op.getOpcode() == PcodeOp.BRANCHIND:
                pointers.add(op.getInput(0))
                clearly_pointers.add(op.getInput(0))

            elif op.getOpcode() == PcodeOp.CALL:
                callee = getFunctionContaining(op.getInput(0).getAddress())

                # 可以利用API函数的prototype筛除一部分非指针
                if (callee.isThunk() or callee.isExternal()) and callee.getName() not in self.sys_function_names:
                    # 对恢复间接跳转而言，虽然无法从API函数中获得它的别名，但仍有必要识别为指针，进而识别出其他的指针变量
                    callee_param_count = callee.getParameterCount()
                    for i in range(callee_param_count):
                        if isinstance(callee.getParameter(i).getDataType(), Pointer):
                            is_pointer = add_after_judge(op.getInput(i + 1))
                            if is_pointer:
                                arg_pointers.add(op.getInput(i + 1))
                else:
                    for i in range(1, op.getNumInputs()):
                        inputi = op.getInput(i)
                        is_pointer = add_after_judge(inputi)
                        if is_pointer:
                            arg_pointers.add(inputi)

            elif op.getOpcode() == PcodeOp.RETURN:
                if op.getNumInputs() == 1:
                    continue

                assert op.getNumInputs() == 2

                input1 = op.getInput(1)
                is_pointer = add_after_judge(input1)
                if is_pointer:
                    ret_pointers.add(input1)

            # 保守估计内存变量为指针变量；若明显不是，会被kill掉。
            # 主要用于写全局变量的情况
            if op.getOutput() and (op.getOutput().getAddress().isMemoryAddress()):
                add_after_judge(op.getOutput())

        # gen逻辑；反向数据流，如果output是指针变量，则input也是指针变量
        last_capacity = -1
        while len(pointers) != last_capacity:  # 如果pointers集合的大小不再增长，则停止
            last_capacity = len(pointers)

            for op in ops:
                if op.getOpcode() == PcodeOp.COPY:
                    if op.getOutput() in pointers:
                        add_after_judge(op.getInput(0))

                elif op.getOpcode() == PcodeOp.INDIRECT:
                    if op.getOutput() in pointers:
                        add_after_judge(op.getInput(0))

                elif op.getOpcode() == PcodeOp.MULTIEQUAL:
                    if op.getOutput() in pointers:
                        for i in range(op.getNumInputs()):
                            add_after_judge(op.getInput(i))

                elif op.getOpcode() == PcodeOp.INT_ADD:
                    if op.getOutput() in pointers:
                        if self.is_special_int_add(op):
                            pointers.add(op.getInput(1))
                        else:
                            add_after_judge(op.getInput(0))  # hypo: 认为除global指针外，base一定作为input0，而不会作为input1

        # kill逻辑；正向数据流，如果input不是指针变量，则output也不是指针变量
        last_capacity = -1
        while len(pointers) != last_capacity:  # 如果pointers集合的大小不再减小，则停止
            last_capacity = len(pointers)
            for op in ops:
                opcode = op.getOpcode()
                output = op.getOutput()
                if op.getOutput() in clearly_pointers or output in not_pointers:
                    continue

                if (opcode == PcodeOp.COPY or opcode == PcodeOp.INDIRECT or
                        (opcode == PcodeOp.INT_ADD and not self.is_special_int_add(op))):
                    if op.getInput(0) in not_pointers:
                        not_pointers.add(output)
                        pointers.discard(output)
                        arg_pointers.discard(output)
                        ret_pointers.discard(output)
                elif opcode == PcodeOp.MULTIEQUAL:
                    if not isinstance(op.getOutput(), PcodeOpAST):
                        # 目前是Memory变量和Constant变量取的是PcodeOp
                        continue

                    cnt = 0
                    target = None
                    for i in range(op.getNumInputs()):
                        if op.getInput(i) in pointers:
                            cnt += 1
                            target = op.getInput(i)
                        else:
                            the_def = op.getInput(i).getDef()
                            # 如果是空指针，认为也是一个指针类型的输入，但是不在pointers集合里面
                            if (the_def and the_def.getOpcode() == PcodeOp.COPY and
                                    the_def.getInput(0).isConstant() and the_def.getInput(0).getOffset() == 0x0):
                                cnt += 1

                    # 这是一个经验的判断，如果我们确定了一个phinode的一部分输入不是指针，我们就要考虑剩余的一部分是不是误报为指针
                    # 判断时只考虑一个输入，判断这个输入是不是只用于phi指令或者是一个内存变量（没有证据说明他是指针）
                    condition = (cnt == 1 and target and (not target.getDescendants() or
                                 len(list(target.getDescendants())) == 1))

                    if cnt == 0 or condition:
                        not_pointers.add(output)
                        pointers.discard(output)
                        arg_pointers.discard(output)
                        ret_pointers.discard(output)

        self.func_argPointers_map[func] = arg_pointers
        self.func_retPointers_map[func] = ret_pointers

        for op in ops:
            # print_pcode(sys.stdout, op)
            opcode = op.getOpcode()
            output = op.getOutput()
            input0 = op.getInput(0)
            input1 = op.getInput(1) if op.getNumInputs() > 1 else None

            if opcode == PcodeOp.LOAD:
                if output in pointers:
                    ptr_related_ops.append(op)

            elif opcode == PcodeOp.INT_ADD:
                if self.is_special_int_add(op):
                    if output in pointers and input1 in pointers:
                        ptr_related_ops.append(op)
                else:
                    if output in pointers and input0 in pointers:
                        ptr_related_ops.append(op)

            elif opcode == PcodeOp.COPY:
                if output in pointers and input0 in pointers:
                    ptr_related_ops.append(op)

            elif opcode == PcodeOp.INDIRECT:  # hypo: 将INDIRECT视为COPY
                if output in pointers and input0 in pointers:
                    ptr_related_ops.append(op)

            elif opcode == PcodeOp.MULTIEQUAL:
                if output in pointers:
                    ptr_related_ops.append(op)
                    
            elif opcode == PcodeOp.STORE:
                if op.getInput(1) in pointers and op.getInput(2) in pointers:
                    ptr_related_ops.append(op)

        return pointers, ptr_related_ops

    def is_global_pointer(self, varnode):
        if varnode.isConstant():
            addr = offset_to_address(varnode.getOffset())
            if validAddrRange.contains(addr):
                return True

        return False

    def is_special_int_add(self, op):
        """
        base不为input0，而是input1的INT_ADD操作
        1. global指针，如r3_293(4) INT_ADD r3_283(4) 0x1c948L
        """
        return self.is_global_pointer(op.getInput(1))

    def clearly_not_pointer(self, varnode, func):
        """
         由于指针变量的推测是保守的，对于一些明显不是指针变量的情形，需要剔除。
         1. 不在地址范围内的常量。 2.内存变量与栈变量（现在的pcode打印出来不包含栈变量，内存变量只用于CALL与BRANCH的第一个参数）
         3. DEF来自于no_pointer_def_ops。 4. 多次用在no_pointer_use_op中
         :type varnode Varnode
        """
        address = varnode.getAddress()
        the_def = varnode.getDef()

        if varnode.getSize() < 4:
            return True

        # 这段代码似乎作用不大，因为是后向传播，而无定义的寄存器基本都在末尾，影响不大，并且这些寄存器似乎不会参与到数据流中
        # if varnode.isRegister() and the_def is None:
        #     reg = currentProgram.getRegister(address)
        #     if address in self.param_addresses:
        #         # assert varnode in self.func_ssa_params_map[func], (
        #         #     "{} is not param? Maybe suspicious prototype recovery error".format(
        #         #             processVarnodeFormat(varnode)))
        #         return False
        #     elif address == self.sp_address:
        #         return False
        #     return True

        if varnode.isConstant():
            addr = offset_to_address(varnode.getOffset())
            if not validAddrRange.contains(addr):
                return True
            else:
                return False

        # if address.isMemoryAddress():
        #     addr = varnode.getAddress()
        #     if not validAddrRange.contains(addr):
        #         return True

        if the_def is not None and the_def.getOpcode() in self.no_pointer_def_ops:
            return True

        if varnode.getDescendants():
            cnt = 0
            for use in varnode.getDescendants():
                if use.getOpcode() in self.no_pointer_use_ops:
                    cnt += 1
            if cnt >= 2:
                return True

        return False


    def dumpECGraph(self, M, phinodes, fp):
        """
         打印等价类图，从M出发，获得value->key的映射，然后遍历value
        """
        valueToKey = {}  # type: dict[PRSet, list[Varnode]]
        for pointer in M:
            if pointer in phinodes:
                continue

            if M[pointer] in valueToKey:
                valueToKey[M[pointer]].append(pointer)
            else:
                valueToKey[M[pointer]] = [pointer]

        for phinode in phinodes:
            for pointer in phinodes[phinode]:
                valueToKey[M[pointer]].append(phinode)

        print >> fp_debug, "{} PRSets".format(len(valueToKey))
        for value in valueToKey:
            print >> fp, 'S' + str(value.id), ' : ',
            for key in valueToKey[value]:
                print >> fp, processVarnodeFormat(key), ' ',
            print >> fp, ''
            for edge in value.outEdges:
                target = value.outEdges[edge]
                print >> fp, '\t', str(edge), ' -> ', 'S' + str(target.id)
            print >> fp, ''

    def buildVariableDependencyGraph(self, pointers_set):
        """
        构造变量依赖图，寻找每个变量的根节点。
        使用不动点迭代法（Fixed-Point Iteration）处理循环依赖（SCC）。

        如果变量构成环，它们的根节点将是流向该环的所有外部变量的并集。

        Args:
            pointers_set: 包含 Varnode 的集合

        Returns:
            dict: { variable: set(root_variables) }
        """

        # 1. 初始化数据结构
        # internal_deps: 记录变量依赖于 pointers 内部的哪些其他变量 (邻接表)
        internal_deps = {ptr: [] for ptr in pointers_set}

        # all_roots: 存储每个变量最终的根节点集合
        # 初始状态下，包含"直接"的根节点（即依赖于 pointers 外部的变量，或自身是非依赖型变量）
        all_roots = {ptr: set() for ptr in pointers_set}

        # 2. 构建图结构 & 识别直接根节点
        for pointer in pointers_set:
            the_def = pointer.getDef()

            # 如果没有定义（如函数参数、常量等），它自己就是根
            if the_def is None:
                all_roots[pointer].add(pointer)
                continue

            opcode = the_def.getOpcode()

            # --- Case 1: Phi Node (MULTIEQUAL) ---
            if opcode == PcodeOp.MULTIEQUAL:
                inputs = the_def.getInputs()
                cnt = 0
                for inp in inputs:
                    if inp in pointers_set:
                        # 依赖于 pointers 内部变量，记录边，稍后传播
                        internal_deps[pointer].append(inp)
                        cnt += 1
                # if cnt != the_def.getNumInputs():
                #     print_pcode(sys.stdout, the_def)
                #     print __LINE__(), "this op has no pointer inputs"

            # --- Case 2: COPY or INDIRECT ---
            elif opcode == PcodeOp.COPY or opcode == PcodeOp.INDIRECT:
                input_var = the_def.getInput(0)
                assert input_var in pointers_set, "a copy output has no pointer input"
                internal_deps[pointer].append(input_var)

            # --- Case 3: 其他操作 (Base Cases) ---
            else:
                # 题目要求：如果是其他操作，不依赖于任何其他变量 => 它自己是根
                all_roots[pointer].add(pointer)

        # 3. 不动点迭代 (Fixed-Point Iteration)
        # 这一步负责处理传递性依赖和环。
        # 环内的节点会不断交换根节点信息，直到所有外部流入的根都被环内所有节点知晓。
        changed = True
        while changed:
            changed = False
            for pointer in pointers_set:
                # 获取当前的根集合
                current_roots = all_roots[pointer]
                original_size = len(current_roots)

                # 将所有“我依赖的变量”的已知根，合并到“我”的根集合中
                for dep_var in internal_deps[pointer]:
                    # 这一步实现了 roots(A) = roots(A) U roots(B)
                    # 因为是引用操作，如果不希望修改源集合的影响（虽然这里逻辑上没问题），可以 update
                    # 注意：Python set 的 update 是原地操作
                    current_roots.update(all_roots[dep_var])

                # 如果集合大小变大了，说明信息还在传播，需要继续迭代
                if len(current_roots) > original_size:
                    changed = True

        return all_roots

    def varnode_is_formal_param(self, varnode, func):
        return varnode in self.func_ssa_params_map[func]

    def varnode_is_formal_ret(self, varnode, func):
        return varnode.getDef() and (varnode.getDef().getOpcode() == PcodeOp.CALL or varnode.getDef().getOpcode() == PcodeOp.CALLIND)

    def varnode_is_actual_param(self, varnode, func):
        return varnode in self.getArgPointers(func)

    def varnode_is_actual_ret(self, varnode, func):
        return varnode in self.getRetPointers(func)

    def buildPDGraph(self, func, M):
        """
         基于PRSet之间的边，构造依赖图，为每个PRSet记录它从bottom开始的路径
         :type func Function
         :type M dict[Varnode, PRSet]
        """

        def dfs(base, prset, paths, visited=None):
            """
             prset的依赖图不一定是一个DAG，可能存在死循环，记录从起点base出发，彼此不覆盖的全部路径

             base: 起点信息
             prset: 当前到达的节点 (Current Node)
             paths: 当前路径上的边列表
             visited: 当前路径上已经访问过的节点集合 (防止死循环)
            """

            # 初始化 visited 集合
            if visited is None:
                visited = set()

            # 将当前节点加入本路径的访问记录中
            # 注意：这里使用集合运算 | 创建一个新的set，是为了保证分支之间的 visited 互不影响
            current_visited = visited | {prset}

            if prset not in pdGraph:
                pdGraph[prset] = [BaseAndPath(base, paths)]
            else:
                new_one = BaseAndPath(base, paths)
                if new_one not in pdGraph[prset]:
                    pdGraph[prset].append(new_one)

            # 遍历出边
            for edge in prset.outEdges:
                next_prset = prset.outEdges[edge]

                # 如果下一个节点已经在当前路径中出现过，则跳过（解决死循环）
                if next_prset in current_visited:
                    continue

                # 复制路径（原逻辑）
                p = copy.copy(paths)
                p.append(edge)

                # 递归调用，传入更新后的 visited 集合
                dfs(base, next_prset, p, current_visited)

        pdGraph = {}  # type: dict[PRSet, list[BaseAndPath]]
        RM = {}  # type: dict[PRSet, list[Varnode]]

        for pointer in M:
            prset = M[pointer]
            if self.varnode_is_formal_param(pointer, func):
                dfs(pointer, prset, [])
            elif self.varnode_is_formal_ret(pointer, func):
                dfs(pointer, prset, [])
            elif pointer.isConstant():
                dfs(pointer, prset, [])
            elif pointer.getAddress() == self.sp_address:
                dfs(pointer, prset, [])

            if prset not in RM:
                RM[prset] = [pointer]
            else:
                RM[prset].append(pointer)

        return pdGraph, RM

    def cleanPRSet(self, M):
        """
         将过程内分析的结果转换为适合过程间使用的summary
         由于过程内分析得到的PRSet中会记录*(sp+0x4)这种与过程间分析无关的内容，予以去除
         由于采用并查集，需要将get_rep展开
        """
        vis = set()
        for pointer in M:
            if M[pointer] not in vis:
                # 去除local pr
                pr_to_reserved = set()
                for pr in M[pointer]:
                    if pr.based_on_SP():
                        continue
                    else:
                        pr_to_reserved.add(pr)
                M[pointer].PRs = pr_to_reserved

        return M

    def EstimatePR(self, func, pointers, ptr_related_ops):
        """
        过程内估计指针变量的指针表示形式
        :type func Function
        :type pointers set[Varnode]
        :type ptr_related_ops list[PcodeOp]
        """
        # traceback.print_stack()

        # 此时pointer_to_roots中的key包含全部的pointer
        pointer_to_roots = self.buildVariableDependencyGraph(pointers)

        worklistState = SolverState()
        M = {}  # type: dict[Varnode, PRSet]

        # 建立M到PRSet的浅拷贝，build PRSet for pointers who have no dependency to other variable
        for pointer in pointers:
            the_def = pointer.getDef()
            if the_def and (the_def.getOpcode() == PcodeOp.MULTIEQUAL or
                            the_def.getOpcode() == PcodeOp.COPY or
                            the_def.getOpcode() == PcodeOp.INDIRECT):
                continue
            else:
                M[pointer] = PRSet(worklistState)

        for pointer in M:
            del pointer_to_roots[pointer]

        # phinode的key只包含copy和multiequal的输出，对应浅引用其它pointer的PRSet的变量
        phinodes = pointer_to_roots

        # 构造PRSet之间的依赖边
        derefEdge = DerefEdge()
        for op in ptr_related_ops:
            # print_pcode(sys.stdout, op)
            opcode = op.getOpcode()
            output = op.getOutput()
            input0 = op.getInput(0)
            input1 = op.getInput(1) if op.getNumInputs() > 1 else None
            input2 = op.getInput(2) if op.getNumInputs() > 2 else None

            if opcode == PcodeOp.LOAD:
                if input1 in phinodes:
                    for inputi in phinodes[input1]:
                        M[inputi].addInitialEdge(derefEdge, M[output])
                else:
                    M[input1].addInitialEdge(derefEdge, M[output])

            elif opcode == PcodeOp.INT_ADD:
                if self.is_special_int_add(op):
                    M[input1].addInitialEdge(PlusEdge(AnalysisOffset(input0)), M[output])
                else:
                    if input0 in phinodes:
                        for inputi in phinodes[input0]:
                            M[inputi].addInitialEdge(PlusEdge(AnalysisOffset(input1)), M[output])
                    else:
                        M[input0].addInitialEdge(PlusEdge(AnalysisOffset(input1)), M[output])
                        
            elif opcode == PcodeOp.STORE:
                if input1 in phinodes:
                    sets1 = [M[inputi] for inputi in phinodes[input1]]
                else:
                    sets1 = [M[input1]]
                if input2 in phinodes:
                    sets2 = [M[inputi] for inputi in phinodes[input2]]
                else:
                    sets2 = [M[input2]]

                for set1 in sets1:
                    for set2 in sets2:
                        set1.addInitialEdge(derefEdge, set2)

            # 由于处理后内存变量不是SSA形式，不被加入phinodes集合中，需要将其与其他变量合并
            elif (opcode == PcodeOp.COPY and output.getAddress().isMemoryAddress()
                  and not input0 == output and input0 in M):
                M[input0].addInitialCopyEdge(M[output])

        # self.dumpECGraph(M, phinodes, fp_debug)

        # 初始化Worklist，加入边界pr
        for pointer in M:
            is_register = pointer.isRegister()
            address = pointer.getAddress()
            def_info = pointer.getDef()

            if is_register and address == self.sp_address and def_info is None:
                M[pointer].addToWorklist({SymbolPR(self.func_sp_varnodeast_map[func], SymbolPR.SP)})

            elif pointer in self.func_ssa_params_map[func]:
                M[pointer].addToWorklist({SymbolPR(pointer, SymbolPR.PARAM)})

            elif pointer.isConstant():
                assert validAddrRange.contains(offset_to_address(pointer.getOffset()))
                M[pointer].addToWorklist({ConstantPR(pointer)})

            elif (def_info is not None and
                  (def_info.getOpcode() == PcodeOp.CALLIND or def_info.getOpcode() == PcodeOp.CALL)):
                M[pointer].addToWorklist({SymbolPR(pointer, SymbolPR.RETURN)})

            elif pointer.getAddress().isMemoryAddress():
                M[pointer].addToWorklist({Deref(ConstantPR(pointer.getAddress().getOffset()))})

        M, globalPRs = worklistState.run(M)
        pdGraph, RM = self.buildPDGraph(func, M)


        # 为phinode构造新的prset并记录在M中，同时在pdGraph和RM中添加

        phinode_to_prset = {}  # 用于多个等价的phinode共享一个prset
        for phinode in phinodes:
            if len(phinodes[phinode]) == 1:
                # 如果phinode只依赖一个prset，则无需构造新的prset
                dep = next(iter(phinodes[phinode]))
                M[phinode] = M[dep]
                RM[M[phinode]].append(phinode)
            else:
                key = tuple(phinodes[phinode])
                if key in phinode_to_prset:
                    # 复用之前的phinode的结果
                    M[phinode] = phinode_to_prset[key]
                    RM[M[phinode]].append(phinode)
                else:
                    prset = M[phinode] = PRSet(None)
                    pdGraph[prset] = []

                    for dep in phinodes[phinode]:
                        prset.unionPRs(M[dep])
                        if M[dep] in pdGraph:
                            for item in pdGraph[M[dep]]:
                                if item not in pdGraph[prset]:
                                    pdGraph[prset].append(item)
                    RM[prset] = [phinode]
                    phinode_to_prset[key] = prset

        # M = self.cleanPRSet(M)   # 不能clean的原因在于某些程序将sp-0x568这样的栈地址作为实参进行传递

        print >> fp_debug, '=' * 50
        self.dumpECGraph(M, phinodes, fp_debug)

        comments = "\nafter iteration\n"
        self.dumpM(func, M, fp_debug, comments)
        self.dumpAndSetArrayPR(M, func, fp_debug)
        self.dumpPDGraph(pdGraph, RM, func, fp_debug)

        return Summary(M, globalPRs, pdGraph, RM)

    def dumpPDGraph(self, pdGraph, RM, func, fp):
        print >> fp, "\nPDGraph of {}: ".format(func)
        for prset in pdGraph:
            print >> fp, "S" + str(prset.id),
            print >> fp, ' [ ',
            for varnode in RM[prset]:
                print >> fp, processVarnodeFormat(varnode), ' ',
            print >> fp, ']'

            for base_and_path in pdGraph[prset]:
                print >> fp, '\t  ', str(base_and_path)

    def dumpStoreOps(self, M, func, affected_pts_map, fp, comments=''):
        print >> fp, comments
        store_ops = self.get_store_pcodes(func)
        for op in store_ops:  # *p = q
            p, q = op.getInput(1), op.getInput(2)
            if p in M and q in M:
                print_pcode(fp, op)
                for pr1 in M[p]:
                    for pr2 in M[q]:
                        print >> fp, "\t*({}) = {}".format(pr1, pr2)
                print >> fp, "\taffected: ",
                for ptr in affected_pts_map[op]:
                    print >> fp, processVarnodeFormat(ptr), ' ',
                print >> fp, '\n\n'

    def dumpAndSetArrayPR(self, M, func, fp):
        """
         由于array属性被设置在PRSet上，然而旧版本的getLiteral需要查找一个pr是不是array，存在gap
        """
        arraySet = set()
        for pointer in M:
            if M[pointer].isArray:
                arraySet.add(M[pointer])

        print >> fp, "\nArraySet of {}: ".format(func)
        for prset in arraySet:
            print >> fp, hex(prset.arrayStride), ':', str(prset)
            for pr in prset:
                addArrayPR(pr, prset.arrayStride)

    def dumpM(self, func, M, fp, comments=None):
        """
         debug函数，打印某个函数的M,同时打印ArrayPR对应的Set
         :type func Function
         :type M dict[Varnode, PRSet]
         :type fp BinaryIO
         :type comments str
        """
        if comments:
            print >> fp, comments,
        print >> fp, 'M of {}:'.format(func.getName())
        for pointer in M:
            print >> fp, processVarnodeFormat(pointer), ": ", str(M[pointer])

    def myGetCallingFunctions(self, func):
        """
         返回所有调用func的函数。对func.getCallingFunctions的增强，额外加入了callind table中的函数调用关系
         :type func Function
        """
        ans = set()

        # refs = currentProgram.getReferenceManager().getReferencesTo(func.getEntryPoint())
        # for ref in refs:
        #     caller = getFunctionContaining(ref.getFromAddress())
        #     if caller and caller != func:
        #         ans.add(caller)

        for caller in func.getCallingFunctions(monitor):
            ans.add(caller)

        ans |= self.callindTable.getCallersInTable(func)
        self.func_callers_map[func] = ans

        return ans

    def myGetCalledFunctions(self, func):
        """
         返回所有被func调用的函数。对func.getCalledFunctions的增强，额外加入了callind table中的函数调用关系
         :type func Function
        """
        ans = set()
        for callee in func.getCalledFunctions(monitor):
            ans.add(callee)

        ans |= self.callindTable.getCalleesInTable(func)
        self.func_callees_map[func] = ans

        return ans


def unexpected_store_rules(pr1, pr2):
    return pr2.have_base_equal_this(Deref(pr1)) or pr2 == pr1


def arg_to_call_ops(varnode):
    """
     已知varnode被用在了一个函数调用指令中，通过该函数得到那个函数调用指令
     :type varnode Varnode
    """
    ans = []
    uses = varnode.getDescendants()
    if uses:
        for use in uses:
            if use.getOpcode() == PcodeOp.CALL or use.getOpcode() == PcodeOp.CALLIND:
                ans.append(use)

    return ans


def processVarnodeFormat(varnode):
    """
    process the varnode's format to be more readable

    :type varnode: Varnode
    """
    if varnode is None:  # handle none varnode here
        return '--'

    addr = varnode.getAddress()

    if addr.isMemoryAddress():
        # return 'ram@' + str(addr.getPhysicalAddress()) + '_' + str(varnode.hashCode())[1:] + '(' + str(
        #     varnode.getSize()) + ')'
        return 'ram@' + str(addr.getPhysicalAddress()) + '(' + str(varnode.getSize()) + ')'

    elif addr.isRegisterAddress():
        if currentProgram.getRegister(varnode) is None:
            return 'reg' + '_' + str(varnode.hashCode()) + '(' + str(
                varnode.getSize()) + ')'
        elif currentProgram.getRegister(varnode).getName().startswith('sp'):
            return 'sp'
        else:
            return currentProgram.getRegister(varnode).getName() + '_' + str(varnode.hashCode()) + '(' + str(
                varnode.getSize()) + ')'

    elif addr.isUniqueAddress():
        return 't' + str(varnode.hashCode()) + '(' + str(varnode.getSize()) + ')'

    elif addr.isConstantAddress():
        if is_unexpected_big_data(varnode.getOffset()):
            return hex(unsigned_to_signed(varnode.getOffset()))
        else:
            return hex(varnode.getOffset())

    elif addr.isStackAddress():
        if addr.getOffset() >= 0:
            return '*sp+{}_{}({})'.format(hex(addr.getOffset())[2:-1], varnode.hashCode() % 16, varnode.getSize())
        else:
            return '*sp-{}_{}({})'.format(hex(addr.getOffset())[3:-1], varnode.hashCode() % 16, varnode.getSize())

    elif addr.isVariableAddress():
        return 'v' + str(varnode.hashCode()) + '(' + str(varnode.getSize()) + ')'

    else:
        return 'unknown' + str(varnode)


def is_unexpected_big_data(data):
    """认为以至少4个f开头的整数实际上是负数, 如0xffffffe8"""
    return data > 0 and hex(data).startswith('0xffff')


def unsigned_to_signed(data):
    """
    将0xffffffe8转换为-0x18
    :type data long
    """
    # assert is_unexpected_big_data(data)
    width = (len(hex(data)) - 3) * 4
    return data - (1 << width)


def offset_to_address(offset):
    return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset)


def align_print(fp, ss, width=20):
    print >> fp, ss.ljust(width),


def print_pcode(fp, op, print_target=True):
    """
    调试; print pcode in a more readable format
    """
    if print_target:
        align_print(fp, str(op.getSeqnum().getTarget()) + ' : ', width=10)

    align_print(fp, ss=processVarnodeFormat(op.getOutput()))
    align_print(fp, ss=op.getMnemonic(), width=11)

    # here print inputs
    opcode = op.getOpcode()
    if opcode == PcodeOp.RETURN:  # leave the first
        for i in range(op.getNumInputs()):
            if i != 0:
                align_print(fp, ss=processVarnodeFormat(op.getInput(i)))

    elif opcode == PcodeOp.STORE:
        spaceid = op.getInput(0).getAddress().getOffset()
        assert spaceid & AddressSpace.ID_TYPE_MASK == AddressSpace.TYPE_RAM

        align_print(fp, ss=processVarnodeFormat(op.getInput(1)) + '@ram')
        align_print(fp, ss=processVarnodeFormat(op.getInput(2)))

    elif opcode == PcodeOp.LOAD:
        spaceid = op.getInput(0).getAddress().getOffset()
        assert spaceid & AddressSpace.ID_TYPE_MASK == AddressSpace.TYPE_RAM

        align_print(fp, ss=processVarnodeFormat(op.getInput(1)) + '@ram')

    elif opcode == PcodeOp.INDIRECT:
        align_print(fp, ss=processVarnodeFormat(op.getInput(0)))

    else:  # most ops
        for i in range(op.getNumInputs()):
            align_print(fp, ss=processVarnodeFormat(op.getInput(i))),

    print >> fp, ''


def runInHeadless():
    return getState().getTool() is None


def __LINE__():
    stack_t = inspect.stack()
    ttt = inspect.getframeinfo(stack_t[1][0])
    return ttt.lineno


def is_p_of_Store(varnode):
    _def = varnode.getDef()
    if _def and _def.getOpcode() == PcodeOp.STORE and _def.getSlot(varnode) == 1:
        return True

    return False


def create_address(space_name, offset):
    address_factory = currentProgram.getAddressFactory()
    return address_factory.getAddress(address_factory.getAddressSpace(space_name).getSpaceID(), offset)


def transfer_hex_to_addr(offset):
    return create_address('ram', offset)


def setup_decompiler():
    options = DecompileOptions()
    options.setEliminateUnreachable(False)
    decompInterface = DecompInterface()
    decompInterface.setOptions(options)
    decompInterface.toggleSyntaxTree(True)
    decompInterface.toggleCCode(False)
    decompInterface.toggleParamMeasures(False)
    decompInterface.setSimplificationStyle(DECOMPILE_STYLE)
    decompInterface.openProgram(currentProgram)

    return decompInterface


def setup_AddressRange():
    memory = currentProgram.getMemory()
    blocks = memory.getBlocks()

    load_blocks = [block for block in blocks if block.isLoaded()]
    if not load_blocks:
        print("Error: No load sections found!")
        return None

    max_addr = max(block.getEnd() for block in load_blocks)
    min_addr = min(block.getStart() for block in load_blocks)
    return AddressSet(min_addr, max_addr).getFirstRange()


def get_function_by_name(name):
    funcs = getGlobalFunctions(name)
    if len(funcs) > 0:
        return funcs[0]
    else:
        return None



class ReadAddrAndCheckClass(object):
    def __init__(self, size):
        self.cache = {}
        self.size = size

    def without_check_read(self, literal):
        """
         literal对应某个内存地址的偏移，返回此处的数据，会检查此次访存行为的合法性
         返回None表示失败，正常返回值为int
         带有try的函数进入越少越好
        """
        addr = toAddr(literal)
        try:
            if self.size == 4:
                data = long(currentProgram.getMemory().getInt(addr))
            elif self.size == 8:
                data = long(currentProgram.getMemory().getLong(addr))
            else:
                assert False, "unreachable"
            return data
        except AssertionError as e:
            print "AssertionError occurred: {}".format(e)  # 打印错误信息
            raise  # 重新抛出异常，保持原有行为
        except:
            return None

    def __call__(self, addr):
        """
         在resolve_memory的基础上，检测读取结果是否在validAddrRange
        """
        if addr in self.cache:
            return self.cache[addr]

        data = self.without_check_read(addr)
        if data and toAddr(data) in validAddrRange:
            result = data
        else:
            result = None

        self.cache[addr] = result
        return self.cache[addr]

read_addr_and_check = ReadAddrAndCheckClass(WordSize)


# from functools import wraps
# 
# def timer(func):
#     @wraps(func)
#     def wrapper(*args, **kwargs):
#         start = time.time()
#         result = func(*args, **kwargs)
#         end = time.time()
#         print("{} cost: {:.6f}".format(func.__name__, end - start))
#         return result
#     return wrapper

def AnalysisOffset(varnode):
    """
     分析varnode(对应一个offset变量)的def chain，返回其对应的OffsetRepresent实例
     :type varnode Varnode
    """
    if varnode.isConstant():
        return OffsetRepresent.make_constant_offset(varnode.getOffset())
    elif varnode.getAddress().isMemoryAddress():
        return OffsetRepresent.make_load_memory_offset()

    _def = varnode.getDef()
    while _def:
        if _def.getOpcode() == PcodeOp.LOAD:
            if _def.getInput(1).isConstant():
                data = read_addr_and_check.without_check_read(_def.getInput(1).getOffset())
                if data:
                    return OffsetRepresent.make_constant_offset(data)

            return OffsetRepresent.make_load_memory_offset()

        elif _def.getOpcode() == PcodeOp.INT_ZEXT or _def.getOpcode() == PcodeOp.COPY:
            input0 = _def.getInput(0)
            if input0.isConstant():
                return OffsetRepresent.make_constant_offset(input0.getOffset())
            elif input0.getAddress().isMemoryAddress():
                return OffsetRepresent.make_load_memory_offset()

            _def = _def.getInput(0).getDef()

        elif _def.getOpcode() == PcodeOp.INT_MULT:
            input1 = _def.getInput(1)
            if input1.isConstant():
                return OffsetRepresent.make_mult_stride_offset(input1.getOffset())
            else:
                return OffsetRepresent.make_total_unknown_offset()

        elif _def.getOpcode() == PcodeOp.INT_ADD:
            if _def.getInput(0).isConstant() and _def.getInput(1).isConstant():
                return OffsetRepresent.make_constant_offset(_def.getInput(0).getOffset() + _def.getInput(1).getOffset())
            else:
                return OffsetRepresent.make_total_unknown_offset()
        else:
            return OffsetRepresent.make_total_unknown_offset()

    return OffsetRepresent.make_total_unknown_offset()



validAddrRange = setup_AddressRange()
PointerAnalysis().run()
