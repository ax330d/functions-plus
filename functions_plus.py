# -*- coding: utf-8 -*-

'''
Functions+ IDA Pro plugin -- alternative version of functions window.

Splits functions names and groups by namespaces.
'''

import re
from collections import OrderedDict

# import cProfile
# import pstats
# import StringIO

import idaapi
import idc
import idautils

from idaapi import PluginForm
from PyQt5 import QtWidgets, QtGui

__author__ = 'xxxzsx, Arthur Gerkis'
__version__ = '1.0.1'


class FunctionState(object):
    '''
    Holds the state of the current function.
    '''

    def __init__(self):
        self._args = ''
        self._flags = 0
        self._addr = 0

    @property
    def args(self):
        '''
        Returns args property.
        '''
        return self._args

    @args.setter
    def args(self, value):
        '''
        Sets args property.
        '''
        self._args = value

    @property
    def flags(self):
        '''
        Returns flags property.
        '''
        return self._flags

    @flags.setter
    def flags(self, value):
        '''
        Sets flags property.
        '''
        self._flags = value

    @property
    def addr(self):
        '''
        Returns addr property.
        '''
        return self._addr

    @addr.setter
    def addr(self, value):
        '''
        Sets addr property.
        '''
        self._addr = value


class FunctionData(object):
    '''
    Holds data of the function.
    '''

    def __init__(self, state):
        self._args = state.args
        self._flags = state.flags
        self._addr = state.addr

    @property
    def args(self):
        '''
        Returns args property.
        '''
        return self._args

    @property
    def flags(self):
        '''
        Returns flags property.
        '''
        return self._flags

    @property
    def addr(self):
        '''
        Returns ea property.
        '''
        return self._addr


class Cols(object):
    '''
    Class which is responsible for handling columns.
    '''
    def __init__(self, show_extra_fields):
        self.addr = None
        self.flags = None
        self.show_extra_fields = show_extra_fields
        self.names = [
            'Name', 'Address', 'Segment', 'Length', 'Locals', 'Arguments'
        ]

        self.handlers = {
            0: lambda: None,
            1: lambda: self.fmt(self.addr),
            2: lambda: '{}'.format(idc.get_segm_name(self.addr)),
            3: lambda: self.fmt(idc.get_func_attr(self.addr, idc.FUNCATTR_END) - self.addr),
            4: lambda: self.fmt(idc.get_func_attr(self.addr, idc.FUNCATTR_FRSIZE)),
            5: lambda: self.fmt(idc.get_func_attr(self.addr, idc.FUNCATTR_ARGSIZE))
        }

        if self.show_extra_fields:
            self.names.extend(['R', 'F', 'L', 'S', 'B', 'T', '='])
            # TODO: add Lumina column info
            self.handlers.update({
                6:  lambda: self.is_true(not self.flags & idc.FUNC_NORET, 'R'),
                7:  lambda: self.is_true(self.flags & idc.FUNC_FAR, 'F'),
                8:  lambda: self.is_true(self.flags & idc.FUNC_LIB, 'L'),
                9:  lambda: self.is_true(self.flags & idc.FUNC_STATIC, 'S'),
                10: lambda: self.is_true(self.flags & idc.FUNC_FRAME, 'B'),
                11: lambda: self.is_true(idc.get_type(self.addr), 'T'),
                12: lambda: self.is_true(self.flags & idc.FUNC_BOTTOMBP, '=')
            })

    def set_data(self, addr, flags):
        '''
        Sets data actual for the current function.
        '''
        self.addr = addr
        self.flags = flags

    def item(self, index):
        '''
        Gets the data according to requested col index.
        '''

        return self.handlers[index]()

    def is_true(self, flag, char):
        '''
        Wrapper to conform IDA default UI view.
        '''
        if flag:
            return char
        return '.'

    def fmt(self, value):
        '''
        Wrapper to conform IDA default UI view.
        '''
        return '{:08X}'.format(value)


class FunctionsTree(object):
    '''
    Builds tree of functions with all relevant information.
    '''
    def __init__(self):
        self.chunks_regexp = re.compile(r'(.*?)(?:|\((.*?)\))$')
        self.simple_regexp = re.compile(r'^[a-zA-Z0-9_]*$')

    def get(self):
        '''
        Returns functions tree.
        '''

        functions_list = self.get_list_of_functions()
        functions_tree = self.build_functions_tree(functions_list)

        return functions_tree

    def get_list_of_functions(self):
        '''
        Gets all functions list.
        '''

        functions_list = {}
        seg_ea = idc.get_segm_by_sel(idc.SEG_NORM)

        for func_ea in idautils.Functions(idc.get_segm_start(seg_ea),
                                          idc.get_segm_end(seg_ea)):
            function_name = idc.get_func_name(func_ea)
            functions_list[function_name] = func_ea

        return functions_list

    def build_functions_tree(self, functions_list):
        '''
        Builds tree of functions.
        '''

        func_state = FunctionState()
        functions_tree = OrderedDict()

        for function_name in sorted(functions_list):
            func_state.args = ''
            func_state.addr = functions_list[function_name]
            func_state.flags = \
                idc.get_func_attr(func_state.addr, idc.FUNCATTR_FLAGS)
            demangled_name = self.maybe_demangle(function_name)
            chunks = self.get_chunks(demangled_name, func_state)
            self.maybe_push(chunks, functions_tree, func_state)

        return functions_tree

    def maybe_push(self, chunks, functions_tree, func_state):
        '''
        Adds new function name or properties to the tree.
        '''

        # FIXME: handle duplicate entries properly
        if isinstance(functions_tree, FunctionData):
            return

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
        '''
        Splits function name by namespaces.
        '''

        new_chunks = []
        matches = re.match(self.chunks_regexp, func_string)
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
        '''
        Demangles name of required.
        '''

        if function_name.find('@') != -1:
            function_name = self.demangle(function_name)
        return function_name

    @classmethod
    def demangle(cls, name):
        '''
        Demangles name.
        '''

        mask = idc.get_inf_attr(idc.INF_SHORT_DN)
        demangled = idc.demangle_name(name, mask)
        if demangled is None:
            return name
        return demangled


class FunctionsPlus(PluginForm):
    '''Functions+ plugin.'''

    def __init__(self):
        super(FunctionsPlus, self).__init__()
        if idc.get_inf_attr(idc.INF_PROCNAME).lower() != 'metapc':
            print('Functions+ warning: not tested in this configuration')
        self.tree = None
        self.icon = 135
        # Enable this if you want to see extra information about function
        self.show_extra_fields = False
        self.cols = Cols(self.show_extra_fields)

    def _populate_tree(self):
        '''
        Populates functions tree.
        '''
        self.tree.clear()
        self._build_tree(FunctionsTree().get(), self.tree)
        return

    def _build_tree(self, function_tree, root):
        '''
        Builds Qt Widget tree.
        '''

        if not function_tree:
            return

        if isinstance(function_tree, FunctionData):
            self._handle_function_data_instance(function_tree, root)
            return

        for name, tree in sorted(function_tree.items()):
            func_item = QtWidgets.QTreeWidgetItem(root)
            if not isinstance(tree, FunctionData):
                name = self._handle_class_name(tree, name, func_item)
            func_item.setText(0, name)
            self._build_tree(tree, func_item)

    def _handle_class_name(self, tree, name, func_item):
        '''
        Handles class name.
        '''

        tree_keys_len = len(list(tree.keys()))
        name = '{} ({} {})'.\
            format(name, tree_keys_len, self._get_word(tree_keys_len))
        font = QtGui.QFont()
        font.setBold(True)
        func_item.setFont(0, font)
        return name

    def _handle_function_data_instance(self, function_tree, root):
        '''
        Handles FunctionData instance.
        '''

        flags = int(function_tree.flags)
        addr = function_tree.addr

        self.cols.set_data(addr, flags)

        for index in range(0, len(self.cols.names)):
            if index > 0:
                root.setText(index, self.cols.item(index))
            if flags & idc.FUNC_THUNK:
                root.setBackground(index, QtGui.QColor('#E8DAEF'))
            if flags & idc.FUNC_LIB:
                root.setBackground(index, QtGui.QColor('#D1F2EB'))

    def _get_word(self, len):
        '''
        Gets proper word for number.
        '''
        word = 'items'
        if len % 10 == 1 and len % 100 != 11:
            word = 'item'
        return word

    def _dblclick(self, item):
        '''
        Handles double click event.
        '''
        try:
            idaapi.jumpto(int(item.text(1), 16))
        except:
            pass

    def OnCreate(self, form):
        '''
        Called when the plugin form is created.
        '''

        # pr = cProfile.Profile()
        # pr.enable()

        parent = self.FormToPyQtWidget(form)

        self.tree = QtWidgets.QTreeWidget()
        self.tree.setColumnCount(len(self.cols.names))
        self.tree.setHeaderLabels(self.cols.names)
        self.tree.itemDoubleClicked.connect(self._dblclick)
        # self.tree.resizeColumnToContents(True)

        layout = QtWidgets.QVBoxLayout()
        layout.addWidget(self.tree)
        layout.setSpacing(0)
        layout.setContentsMargins(0, 0, 0, 0)

        self._populate_tree()

        self.tree.setColumnWidth(0, 512)
        for index in range(6, len(self.cols.names)):
            self.tree.setColumnWidth(index, 32)
        self.tree.setAlternatingRowColors(True)

        parent.setLayout(layout)

        # pr.disable()
        # s = StringIO.StringIO()
        # ps = pstats.Stats(pr, stream=s).sort_stats('cumulative')
        # ps.print_stats()
        # print(s.getvalue())

    def OnClose(self, form):
        '''
        Called when the plugin form is closed.
        '''
        del self

    def Show(self):
        '''
        Creates the form is not created or focuses it if it was.
        '''
        return PluginForm.Show(self, 'Functions+')


class FunctionsPlusPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "Functions+"

    help = ""
    wanted_name = "Functions+"
    wanted_hotkey = ""

    # @staticmethod
    # def init():
    #     return idaapi.PLUGIN_KEEP

    @staticmethod
    def init():
        funp = FunctionsPlus()
        funp.Show()
        return idaapi.PLUGIN_KEEP

    @staticmethod
    def run(arg=0):
        funp = FunctionsPlus()
        funp.Show()

    @staticmethod
    def term():
        pass

def PLUGIN_ENTRY():
    return FunctionsPlusPlugin()
