from PyQt4 import QtGui, QtCore
from PyQt4.QtGui import QHeaderView, QGroupBox, QWidget, QIcon, QLabel, \
    QHBoxLayout, QTextEdit, QLineEdit, QFrame, QCheckBox, QMenu, QAction, \
    QPainter, QPen
from tools.singleton import Singleton
from PyQt4.QtCore import QSize, Qt, QPoint
from PyQt4.Qt import QVBoxLayout, Qt
from tools.ecu_logging import ECULogger
import sys
import inspect
import types
import logging


def log_to_str(v):
    if isinstance(v, str):
        return ["'", v.replace('\n', '\\n'), "'"].join('')
    else:
        try:return str(v).replace('\n', '\\n')
        except: return '<ERROR: CANNOT PRINT>'

def format_ex(e):
    out_str = ""
    out_str += 'Exception thrown, %s: %s\n' % (type(e), str(e))
    frames = inspect.getinnerframes(sys.exc_info()[2])
    for frame_info in reversed(frames):
        f_locals = frame_info[0].f_locals
        if '__lgw_marker_local__' in f_locals:
            continue        
        # log the frame information
        out_str += ('  File "%s", line %i, in %s\n    %s\n' % (frame_info[1], frame_info[2], frame_info[3], frame_info[4][0].lstrip()))
        # log every local variable of the frame
        for k, v in f_locals.items():
            try: out_str += ('    %s = %s\n' % (k, log_to_str(v)))
            except: pass                
    return out_str

def try_ex(fn):
    def wrapped(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except Exception as e:            
            try:
                ky = fn.__qualname__.split(".")[0]
                cls = fn.__globals__[ky]
                ECULogger().log_err(401, cls)
            except:
                ECULogger().log_err(401, fn.__qualname__)
            logging.error(format_ex(e))
            ECULogger().log_traceback()    
    return wrapped

class GBuilder(Singleton):

    def __init__(self):
        self.store_first = False
        self.store_second = False
        
    @try_ex
    def add_checkbuttons(self, table, row, col):
        wid = QWidget()
        lo = QVBoxLayout()
        wid.setLayout(lo)
        
        cb = QCheckBox()
        lo.addWidget(cb)
        wid.setFixedHeight(32)        
        table.setCellWidget(row, col, wid)
        
        return cb
        
    @try_ex
    def set_props(self, widgt, ctr_lout=False, min_sz_x=400, min_sz_y=200, max_sz_x=False, max_sz_y=False):
        
        ''' 1. add central layout'''
        if ctr_lout:
            central_wid = QtGui.QWidget()        
            central_lout = QtGui.QVBoxLayout()                
            central_wid.setLayout(central_lout)
            widgt.setCentralWidget(central_wid)
        
        ''' 2. set properies'''
        widgt.setMinimumHeight(min_sz_y)
        widgt.setMinimumWidth(min_sz_x)       
        
        if max_sz_x:
            widgt.setMaximumHeight(max_sz_y)
            widgt.setMaximumWidth(max_sz_x)        
        
    @try_ex
    def label_combobox(self, parent, text, items, funct):
        
        hl = QHBoxLayout()
        
        lab = self.label(parent, text)
        hl.addWidget(lab)
        
        cb = QtGui.QComboBox(parent)        
        cb.currentIndexChanged.connect(funct)
        
        for item in items:
            cb.addItem(item)
            
        cb.model().sort(0)
        
        hl.addWidget(cb)
        return hl, cb, lab
        
    @try_ex
    def combobox(self, parent, items, funct):
        cb = QtGui.QComboBox(parent)        
        cb.currentIndexChanged.connect(funct)
        
        for item in items:
            cb.addItem(item)
            
        cb.model().sort(0)
         
        return cb
    
    @try_ex
    def checkable_combobox(self, parent, items, funct):
        cb = CheckableComboBox(parent)        
        cb.currentIndexChanged.connect(funct)
        cb.connect_click(funct)
        
        for item in items:
            cb.addItem(item)
            
        cb.model().sort(0)
         
        return cb
    
    @try_ex
    def combobox_text(self, parent, items, funct):
        
        hl = QHBoxLayout()
        
        cb = QtGui.QComboBox(parent)        
        cb.currentIndexChanged.connect(funct)
        hl.addWidget(cb)
        
        te = QLineEdit()
        hl.addWidget(te)
        
        for item in items:
            cb.addItem(item)
        cb.model().sort(0)
        return hl, cb, te
    
    @try_ex
    def hor_line(self, parent):
        line = QFrame(parent);
        line.setFrameShape(QFrame.HLine);
        line.setFrameShadow(QFrame.Sunken);
        return line
        
    @try_ex
    def dock_widget(self, parent, dock_area=QtCore.Qt.LeftDockWidgetArea, init_dock=QtCore.Qt.LeftDockWidgetArea):
        dock_wid = QtGui.QDockWidget(parent)        
        dock_wid.setAllowedAreas(dock_area)   
        parent.addDockWidget(init_dock, dock_wid);        
        return dock_wid
    
    @try_ex
    def groupbox(self, parent, title, max_height=False, max_width=False):
        
        gb = QtGui.QGroupBox(parent)        
        gb.setTitle(title)
        
        if max_height:
            gb.setMaximumHeight(max_height)
        if max_width:
            gb.setMaximumWidth(max_width)       
        
        return gb
    
    @try_ex
    def hand_groupbox(self, parent, title, max_height=False, max_width=False):
        
        gb = HandGroupBox(parent)
        
        gb.setTitle(title)
        
        if max_height:
            gb.setMaximumHeight(max_height)
        if max_width:
            gb.setMaximumWidth(max_width)       
        
        return gb
    
    @try_ex
    def label_text(self, parent, text, label_width=False, line_width=False, fct=False):
        
        hb = QHBoxLayout()
        lab = self.label(parent, text)        
        te = QLineEdit(parent)
        hb.addWidget(lab)
        hb.addWidget(te)
        
        if fct:
            te.textEdited.connect(fct)
        
        if label_width:
            lab.setFixedWidth(label_width)
        if line_width:
            te.setFixedWidth(line_width)
        
        return [hb, te]
        
    @try_ex
    def image(self, parent, img_path, scale, pos_x=False, pos_y=False, size_x=False, size_y=False):
        pic = QtGui.QLabel(parent)
        myPixmap = QtGui.QPixmap(img_path)
        myScaledPixmap = myPixmap.scaled(pic.size() * scale, QtCore.Qt.KeepAspectRatio)
        pic.setPixmap(myScaledPixmap)
        
        if size_x:
            pic.setFixedHeight(size_y)
            pic.setFixedWidth(size_x)
        
        if pos_x:
            pic.move(pos_x, pos_y)
            
        return pic
    @try_ex
    def drop_image(self, parent, img_path, scale, pos_x=False, pos_y=False, size_x=False, size_y=False):
        pic = DragLabel(parent)
        myPixmap = QtGui.QPixmap(img_path)
        myScaledPixmap = myPixmap.scaled(pic.size() * scale, QtCore.Qt.KeepAspectRatio)
        pic.setPixmap(myScaledPixmap)
        
        if size_x:
            pic.setFixedHeight(size_y)
            pic.setFixedWidth(size_x)
        
        if pos_x:
            pic.move(pos_x, pos_y)
            
        return pic
    
    @try_ex
    def label(self, parent, text, pos_x=False, pos_y=False):
        lab = QtGui.QLabel(parent)
        lab.setText(text)        
        lab.setWordWrap(True);
        if pos_x:
            lab.move(pos_x, pos_y)
        return lab
    
    @try_ex
    def pushbutton(self, parent, text, func, icon_path=False, icon_x=False, icon_y=False):
        pb = QtGui.QPushButton()
        pb.clicked.connect(func)
        if text != None:
            pb.setText(text)
        
        if icon_path:
            pb.setIcon(QtGui.QIcon(icon_path))            
            if icon_x:
                pb.setIconSize(QSize(icon_x, icon_y))        
        return pb
    
    @try_ex
    def dragbutton(self, parent, text, func, icon_path=False, icon_x=False, icon_y=False, size_x=False, size_y=False, pos_x=False, pos_y=False):
        pb = DragButton(text, parent)
        pb.clicked.connect(func)
        
        pb.icon_path = icon_path
        
        if size_x: pb.setFixedWidth(size_x)
        if size_y: pb.setFixedHeight(size_y)
        
        if pos_x: pb.move(pos_x, pos_y)
        
        if text != None:
            pb.setText(text)        
        if icon_path:
            pb.setIcon(QtGui.QIcon(icon_path))            
            if icon_x:
                pb.setIconSize(QSize(icon_x, icon_y))        
        return pb
    
    @try_ex
    def table(self, parent, nr_rows, nr_cols, labels, stretch=True):
        
        tab = QtGui.QTableWidget(parent)
        tab.setRowCount(nr_rows)
        tab.setColumnCount(nr_cols)
        tab.setHorizontalHeaderLabels(labels)        
        
        header = tab.horizontalHeader()        
       
        
        if stretch:        
            header.setStretchLastSection(True)    
            header.setResizeMode(QHeaderView.Stretch)

        return tab
        
    @try_ex
    def toolbar(self, parent, area=QtCore.Qt.TopToolBarArea, init_area=QtCore.Qt.TopToolBarArea, actions=[]):
        toolbar = QtGui.QToolBar(parent)
        toolbar.setAllowedAreas(area)       
        parent.addToolBar(init_area, toolbar)

        for action in actions:
            toolbar.addAction(action)
           
    @try_ex 
    def update_connected(self, env_view, rel_1, rel_2, selected_env): 
        env_view.scene().clear() 
        if not self.store_first:
            self.store_first = rel_1
            self.store_second = rel_2
        try:
            DragSelection().connected[selected_env]
        except:
            return
            
        for con in DragSelection().connected[selected_env]:            
            pt_from = con.pt_from.pos() - self.store_first - self.store_second - QPoint(442, 250)
            for pt in con.pts_to:
                pt_to = pt.pos() - self.store_first - self.store_second - QPoint(442, 250)
                env_view.draw_line(pt_from, pt_to)

class GEnums(object):
        
    ''' 1. Docking Areas'''
    D_LEFT = QtCore.Qt.LeftDockWidgetArea
    D_RIGHT = QtCore.Qt.RightDockWidgetArea
    D_TOP = QtCore.Qt.TopDockWidgetArea
    D_BOTTOM = QtCore.Qt.BottomDockWidgetArea
    
    T_LEFT = QtCore.Qt.LeftToolBarArea
    T_RIGHT = QtCore.Qt.RightToolBarArea
    T_TOP = QtCore.Qt.TopToolBarArea
    T_BOTTOM = QtCore.Qt.BottomToolBarArea
  
class HandGroupBox(QGroupBox):
    
    def __init__(self, *args, **kwargs):
        QGroupBox.__init__(self, *args, **kwargs)
        
        self.cursor_in = False
    
    @try_ex
    def enterEvent(self, *args, **kwargs):
        self.setCursor(Qt.OpenHandCursor)
        self.cursor_in = True
        
    @try_ex
    def leaveEvent(self, event):
        self.setCursor(Qt.ArrowCursor)
        self.cursor_in = False
               
class EnvironmentView(QtGui.QGraphicsView):
    def __init__(self, parent):
        QtGui.QGraphicsView.__init__(self, parent)        
        self.setScene(QtGui.QGraphicsScene(self))        
        self.setSceneRect(QtCore.QRectF(self.viewport().rect()))
        self.selected_env = None

    @try_ex
    def mousePressEvent(self, event):
        self._start = event.pos()
    
    @try_ex
    def draw_line(self, start, end):        
        self.scene().addItem(QtGui.QGraphicsLineItem(QtCore.QLineF(start, end)))

    @try_ex
    def mouseReleaseEvent(self, event):
        start = QtCore.QPointF(self.mapToScene(self._start))
        end = QtCore.QPointF(self.mapToScene(event.pos()))
        self.scene().addItem(
            QtGui.QGraphicsLineItem(QtCore.QLineF(start, end)))
         
         
        for point in (start, end):
            text = self.scene().addSimpleText(
                '(%d, %d)' % (point.x(), point.y()))
            text.setBrush(QtCore.Qt.red)
            text.setPos(point)

class DragButton(QtGui.QPushButton):
  
    def __init__(self, title, parent):
        super(DragButton, self).__init__(title, parent)
        self.offset = 0
        self.icon_path = ""
        self.move_icon = None
        self.ecu_key = None
        self.func = None
        self.move_ctxt_acts = []

    @try_ex
    def enterEvent(self, *args, **kwargs):
        self.setCursor(Qt.OpenHandCursor)

    @try_ex
    def mousePressEvent(self, e):      
        super(DragButton, self).mousePressEvent(e)
        
        if e.button() == QtCore.Qt.LeftButton:

            # Drag and Drop Effect
            window = self.parent().parent().parent().parent().parent().parent()            
            popos = self.parent().pos() + self.parent().parent().parent().parent().pos() + self.parent().parent().parent().parent().parent().pos() + e.pos()            
            self.move_icon = GBuilder().drop_image(window, self.icon_path, 1.5, size_x=50, size_y=50, pos_x=popos.x(), pos_y=popos.y() - self.parent().parent().parent().parent().verticalScrollBar().value())
            self.move_icon.show()   
            self.move_icon.set_doubleclick_func(self.func) 
            self.move_icon.set_context_menu_actions(self.move_ctxt_acts)
            self.move_icon.ecu_key = self.ecu_key
            self.setCursor(Qt.ClosedHandCursor)            
            self.setChecked(True)            
            shift = QPoint(-20, -20 - self.parent().parent().parent().parent().verticalScrollBar().value())            
            self.parent().parent().parent().parent().verticalScrollBar().value()            
            self.offset = e.pos() - popos - shift
             
    @try_ex 
    def mouseReleaseEvent(self, e):
        if e.button() == Qt.LeftButton:            
            self.setCursor(Qt.ArrowCursor);
            self.setChecked(False)                                    
            try: 
                cur_pos = e.pos() - self.offset                          
                self.func(cur_pos, self.ecu_key, self.move_icon)
            except:
                pass
#                 ECULogger().log_traceback()
            
    @try_ex
    def mouseMoveEvent(self, event):
        self.move_icon.move(self.mapToParent(event.pos() - self.offset));
       
    @try_ex 
    def set_drop_func(self, drop_func):
        self.func = drop_func
        
    @try_ex
    def set_move_icon_context_acts(self, in_lst):
        self.move_ctxt_acts = in_lst 
               
class DragLabel(QtGui.QLabel):
  
    def __init__(self, parent):
        super(DragLabel, self).__init__(parent)
        self.offset = 0
        self.icon_path = ""
        self.move_icon = None
        self.double_click_func = None
        self.ecu_key = None        
        self.selected = False
        self.contextMenu = QMenu(str("Context menu"), self);
        self.env_view = None
        
    @try_ex
    def set_doubleclick_func(self, func):
        self.double_click_func = func

    @try_ex
    def enterEvent(self, *args, **kwargs):
        self.setCursor(Qt.OpenHandCursor)
        if not self.selected: 
            self.setStyleSheet('QLabel { border: 2px solid red; padding: 0px; border-radius: 15px} ')
 
    @try_ex
    def leaveEvent(self, *args, **kwargs):
        if not self.selected:
            self.setStyleSheet('QLabel {border: 0px solid red;border-radius: 15px;}')
 
    @try_ex
    def mousePressEvent(self, e):               
        if e.button() == QtCore.Qt.LeftButton:
            self.setCursor(Qt.ClosedHandCursor)    
            self.offset = e.pos()
            
            if e.modifiers() == Qt.ControlModifier:
                if self.selected:                
                    self.setStyleSheet('QLabel {border: 0px solid red;border-radius: 15px;}')
                    self.selected = False
                    try:
                        DragSelection().selected.remove(self)
                    except:
                        pass
                else:
                    self.setStyleSheet('QLabel { border: 2px solid red; background: darkred; padding: 0px; border-radius: 15px} ')
                    self.selected = True
                    DragSelection().selected.append(self)

        if e.button() == QtCore.Qt.RightButton:
            DragSelection().clicked = self
            pop = e.pos() + self.parent().pos()
            self.contextMenu.exec(self.mapToParent(pop));  # HERE POSITION

    @try_ex
    def set_context_menu_actions(self, actions):
        try:
            self.context_actions = actions        
            for action in self.context_actions:                
                if action not in self.contextMenu.children():
                    self.contextMenu.addAction(action)
        except:
            pass
        
    @try_ex
    def mouseReleaseEvent(self, e):
        if e.button() == Qt.LeftButton:            
            self.setCursor(Qt.ArrowCursor);        
            cur_pos = e.pos() - self.offset

    @try_ex
    def mouseMoveEvent(self, event):
        self.move(self.mapToParent(event.pos() - self.offset));
        
        a = self.env_view
        GBuilder().update_connected(a, None, None, self.env_view.selected_env)
        print("Move")
                
    @try_ex
    def mouseDoubleClickEvent(self, e):
        try:                
            self.double_click_func(e.pos() - self.offset, self.ecu_key, self)
        except:
            ECULogger().log_traceback()
        
#         print(DragSelection().selected)
                
class DragSelection(Singleton):
    
    def __init__(self):
        self.selected = []
        self.clicked = None        
        self.connected = {}  # List of LineConnections

        self.rel_pos = QPoint(0, 0)

class LineConnection(object):
    
    def __init__(self, pt_f, pts_to):
        self.pt_from = pt_f
        self.pts_to = pts_to
        
class CheckableComboBox(QtGui.QComboBox):
    
    def __init__(self, parent):
        super(CheckableComboBox, self).__init__(parent)
        self.view().pressed.connect(self.handleItemPressed)
        self.setModel(QtGui.QStandardItemModel(self))
        self.itm_pressed = None

    def connect_click(self, fct):
        self.itm_pressed = fct

    def handleItemPressed(self, index):
        item = self.model().itemFromIndex(index)
        if item.checkState() == QtCore.Qt.Checked:
            item.setCheckState(QtCore.Qt.Unchecked)
        else:
            item.setCheckState(QtCore.Qt.Checked)
        try: 
            self.itm_pressed(index)
        except:
            pass
    
        
