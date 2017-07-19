#!c:\\python27\python.exe
# -*- coding: utf-8 -*-
#

'''
Functions+ IDA Pro plugin -- better version (imho) of functions window. Splits
functions names and groups by namespaces.
'''

import re
from collections import OrderedDict

import idaapi
import idc
import idautils

from idaapi import PluginForm
from PyQt5 import QtWidgets, QtGui

__author__ = 'Arthur Gerkis'
__version__ = '0.0.1'


class FunctionState(object):
    '''Holds the state of the current function.'''

    def __init__(self):
        self._args = ''
        self._flags = 0
        self._addr = 0

    @property
    def args(self):
        '''Returns args property.'''
        return self._args

    @args.setter
    def args(self, value):
        '''Sets args property.'''
        self._args = value

    @property
    def flags(self):
        '''Returns flags property.'''
        return self._flags

    @flags.setter
    def flags(self, value):
        '''Sets flags property.'''
        self._flags = value

    @property
    def addr(self):
        '''Returns addr property.'''
        return self._addr

    @addr.setter
    def addr(self, value):
        '''Sets addr property.'''
        self._addr = value


class FunctionData(object):
    '''Holds the data of the function.'''

    def __init__(self, state):
        self._args = state.args
        self._flags = state.flags
        self._addr = state.addr

    @property
    def args(self):
        '''Returns args property.'''
        return self._args

    @property
    def flags(self):
        '''Returns flags property.'''
        return self._flags

    @property
    def addr(self):
        '''Returns ea property.'''
        return self._addr


class Cols(object):
    '''Class which is responsible for handling cols.'''

    def __init__(self):
        self.addr = None
        self.flags = None
        self.names = [
            'Function name', 'Address', 'Segment', 'Length', 'Locals',
            'Arguments', 'R', 'F', 'L', 'S', 'B', 'T', '='
        ]
        self.handlers = {
            0: lambda: None,
            1: lambda: self.ptr().format(self.addr),
            2: lambda: '{}'.format(idc.SegName(self.addr)),
            3: lambda: self.halfptr().format(idc.GetFunctionAttr(
                self.addr, idc.FUNCATTR_END) - self.addr),
            4: lambda: self.set_if_true(idc.GetFunctionAttr(
                self.addr, idc.FUNCATTR_FRSIZE)),
            5: lambda: self.set_if_true(idc.GetFunctionAttr(
                self.addr, idc.FUNCATTR_ARGSIZE)),
            6: lambda: self.is_true(not self.flags & idc.FUNC_NORET, 'R'),
            7: lambda: self.is_true(self.flags & idc.FUNC_FAR, 'F'),
            8: lambda: self.is_true(self.flags & idc.FUNC_LIB, 'L'),
            9: lambda: self.is_true(self.flags & idc.FUNC_STATIC, 'S'),
            10: lambda: self.is_true(self.flags & idc.FUNC_FRAME, 'B'),
            11: lambda: self.is_true(idc.GetType(self.addr), 'T'),
            12: lambda: self.is_true(self.flags & idc.FUNC_BOTTOMBP, '=')
        }

    def set_data(self, addr, flags):
        '''Sets data actual to current function.'''
        self.addr = addr
        self.flags = flags

    def col(self, index):
        '''Gets the data according to requested col index.'''
        return self.handlers[index]()

    def ptr(self):
        '''Returns ptr for format.'''
        if idc.__EA64__:
            return '{:16x}'
        return '{:08x}'

    def halfptr(self):
        '''Returns half ptr for format.'''
        if idc.__EA64__:
            return '{:08x}'
        return '{:04x}'

    def is_true(self, flag, char):
        '''Wrapper to conform IDA default UI view.'''
        if flag:
            return char
        return '.'

    def set_if_true(self, value):
        '''Wrapper to conform IDA default UI view.'''
        if value:
            return self.halfptr().format(value)
        return ''


class FunctionsTree(object):
    '''Builds tree of functions with all relevant information.'''

    def __init__(self):
        return

    def get(self):
        '''Returns functions tree.'''
        functions_list = self.get_list_of_functions()
        functions_tree = self.build_functions_tree(functions_list)
        return functions_tree

    def get_list_of_functions(self):
        '''Get all functions list.'''

        seg_ea = idc.BeginEA()
        functions_list = {}
        for func_ea in idautils.Functions(idc.SegStart(seg_ea), idc.SegEnd(seg_ea)):
            function_name = self.maybe_demangle(idc.GetFunctionName(func_ea))
            functions_list[function_name] = func_ea
        return functions_list

    def build_functions_tree(self, functions_list):
        '''Build tree of functions.'''

        func_state = FunctionState()
        functions_tree = OrderedDict()
        for function_name in sorted(functions_list):
            func_state.args = ''
            func_state.addr = functions_list[function_name]
            func_state.flags = idc.GetFunctionFlags(func_state.addr)
            chunks = self.get_chunks(function_name, func_state)
            self.maybe_push(chunks, functions_tree, func_state)
        return functions_tree

    def maybe_push(self, chunks, functions_tree, func_state):
        '''Add new function name or properties to the tree.'''

        name = chunks.pop(0)
        if not len(name):
            return

        # If this is the last (or one) chunk
        if not len(chunks):
            functions_tree[name + func_state.args] = FunctionData(func_state)
            return

        # If this is a new namespace, create a tree
        if name not in functions_tree:
            functions_tree[name] = OrderedDict()

        return self.maybe_push(chunks, functions_tree[name], func_state)

    def get_chunks(self, func_string, func_state):
        '''Splits function name by namespaces.'''

        new_chunks = []
        matches = re.match(r'(.*?)(?:|\((.*?)\))$', func_string)
        if not matches:
            return []

        args = ''
        if matches.group(2):
            args = '({})'.format(matches.group(2))
        func_state.args = args

        chunks = list(matches.group(1))
        if chunks[0] == '`':
            return [matches.group(1)]

        open_left_tpl = 0
        tmp_chunk = ''
        for chunk in chunks:
            if chunk == ':' and open_left_tpl == 0:
                if len(tmp_chunk):
                    new_chunks.append(tmp_chunk)
                tmp_chunk = ''
                continue
            if chunk == '<':
                open_left_tpl += 1
            if chunk == '>':
                open_left_tpl -= 1
            tmp_chunk += chunk
        new_chunks.append(tmp_chunk)
        return new_chunks

    def maybe_demangle(self, function_name):
        '''Maybe demangle name.'''

        if function_name.find('@') != -1:
            function_name = self.demangle(function_name)
        return function_name

    def demangle(self, name):
        '''Demangle name.'''

        mask = idc.GetLongPrm(idc.INF_SHORT_DN)
        demangled = idc.Demangle(name, mask)
        if demangled is None:
            return name
        return demangled


class FunctionsPlus(PluginForm):
    '''Functions+ plugin.'''

    def __init__(self):
        super(FunctionsPlus, self).__init__()

        if idc.GetLongPrm(idc.INF_PROCNAME).lower() != 'metapc':
            print "Functions+ warning: not tested in this configuration"
        self.cols = Cols()

    def populate_tree(self):
        '''Populate functions tree.'''
        self.tree.clear()
        self.build_tree(FunctionsTree().get(), self.tree)
        return

    def build_tree(self, function_tree, root):
        '''Build Qt Widget tree.'''

        if not function_tree:
            return

        if isinstance(function_tree, FunctionData):
            flags = int(function_tree.flags)
            addr = function_tree.addr

            self.cols.set_data(addr, flags)

            for index in xrange(0, len(self.cols.names)):
                if index > 0:
                    root.setText(index, self.cols.col(index))
                if flags & idc.FUNC_THUNK:
                    root.setBackground(index, QtGui.QColor("violet"))
                    root.setBackground(index, QtGui.QColor("violet"))
                if flags & idc.FUNC_LIB:
                    root.setBackground(index, QtGui.QColor("cyan"))
                    root.setBackground(index, QtGui.QColor("cyan"))
            return

        for name, tree in sorted(function_tree.iteritems()):
            func_item = QtWidgets.QTreeWidgetItem(root)
            if not isinstance(tree, FunctionData):
                word = 'items'
                tree_keys_len = len(tree.keys())
                if tree_keys_len % 10 == 1:
                    word = 'item'
                name = '{} ({} {})'.format(name, tree_keys_len, word)
            func_item.setText(0, name)
            self.build_tree(tree, func_item)

    def dblclick(self, item):
        '''Handle double click event.'''
        try:
            idaapi.jumpto(int(item.text(1), 16))
        except:
            pass

    def OnCreate(self, form):
        '''Called when the plugin form is created'''

        self.parent = self.FormToPyQtWidget(form)

        self.tree = QtWidgets.QTreeWidget()
        self.tree.setColumnCount(len(self.cols.names))
        self.tree.setHeaderLabels(self.cols.names)
        self.tree.itemDoubleClicked.connect(self.dblclick)

        layout = QtWidgets.QVBoxLayout()
        layout.addWidget(self.tree)
        layout.setSpacing(0)
        layout.setContentsMargins(0, 0, 0, 0)

        self.populate_tree()

        self.tree.setColumnWidth(0, 512)
        for index in xrange(6, len(self.cols.names)):
            self.tree.setColumnWidth(index, 32)
        self.tree.setAlternatingRowColors(True)

        self.parent.setLayout(layout)

    def OnClose(self, form):
        '''Called when the plugin form is closed.'''
        del self

    def Show(self):
        '''Creates the form is not created or focuses it if it was.'''
        return PluginForm.Show(self, "Functions+",
                               options=PluginForm.FORM_PERSIST)


def main():
    '''Main entry.'''
    funp = FunctionsPlus()
    funp.Show()


if __name__ == '__main__':
    main()
