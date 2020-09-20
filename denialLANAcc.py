from scapy.all import ARP, Ether, srp
from mac_vendor_lookup import MacLookup
from asciimatics.widgets import Frame, ListBox, Layout, Divider, Text, \
    Button, TextBox, Widget, _enforce_width,_ScrollBar
from asciimatics.scene import Scene
from asciimatics.screen import Screen
from asciimatics.exceptions import ResizeScreenError, NextScene, StopApplication
import sys
from abc import ABCMeta, abstractmethod, abstractproperty
from future.utils import with_metaclass
from asciimatics.event import KeyboardEvent, MouseEvent

class Killer():

    def getHosts(self, ipAdd='192.168.0.0/24'):
        self.MACs = []
        self.IPs = []
        self.vendor = []
        self.seleccionado =[]
        self.ipAdd = ipAdd
        self.arp = ARP(pdst=self.ipAdd)
        self.ether = Ether(dst="ff:ff:ff:ff:ff:ff")

        self.packet = self.ether/self.arp

        self.result = srp(self.packet, timeout=4, verbose=0)[0]
        self.clients = []

        for _, received in self.result:
            self.seleccionado.append(0)
            self.MACs.append(received.hwsrc)
            self.vendor.append(MacLookup().lookup(received.hwsrc))
            self.IPs.append(received.psrc)
        return [ self.seleccionado,self.IPs,self.MACs, self.vendor]

    def arpSpoon():
        pass


class CheckList(Widget):
    """
    An Internal class to contain common function between list box types.
    """

    def __init__(self, height, options,centre=False, titles=None, label=None, name=None, add_scroll_bar=False,on_change=None,
                 on_select=None, validator=None):
        """
        :param height: The required number of input lines for this widget.
        :param options: The options for each row in the widget. del tipo [[],[],[]]
        :param label: An optional label for the widget.
        :param name: The name for the widget.
        :param on_change: Optional function to call when selection changes.
        :param on_select: Optional function to call when the user actually selects an entry from
            this list - e.g. by double-clicking or pressing Enter.
        :param validator: Optional function to validate selection for this widget.
        """
        super(CheckList, self).__init__(name)
        self._options = options
        self._titles = titles
        self._label = label
        self._line = 0
        self._start_line = 0
        self._required_height = height
        self._on_change = on_change
        self._on_select = on_select
        self._validator = validator
        self._search = ""
        self._scroll_bar = None
        self._add_scroll_bar = add_scroll_bar
        self._centre = centre
        self.values = 0

    def reset(self):
        pass

    def process_event(self, event):
        if isinstance(event, KeyboardEvent):
            if event.key_code == 32 :
                self._options[0][self._line] =  -(self._options[0][self._line]) + 1 #Negacion            
            if len(self._options[0]) > 0 and event.key_code == Screen.KEY_UP:
                # Move up one line in text - use value to trigger on_select.
                self._line = max(0, self._line - 1)
            elif len(self._options[0]) > 0 and event.key_code == Screen.KEY_DOWN:
                # Move down one line in text - use value to trigger on_select.
                self._line = min(len(self._options[0]) - 1, self._line + 1)
            elif len(self._options[0]) > 0 and event.key_code == Screen.KEY_PAGE_UP:
                # Move up one page.
                self._line = max(0, self._line - self._h + (1 if self._titles else 0))
            elif len(self._options[0]) > 0 and event.key_code == Screen.KEY_PAGE_DOWN:
                # Move down one page.
                self._line = min(
                    len(self._options[0]) - 1, self._line + self._h - (1 if self._titles else 0))
            elif event.key_code in [Screen.ctrl("m"), Screen.ctrl("j")]:
                # Fire select callback.
                if self._on_select:
                    self._on_select()
            else:
                return event


        elif isinstance(event, MouseEvent):
            # Mouse event - adjust for scroll bar as needed.
            if event.buttons != 0:
                # Check for normal widget.
                if (len(self._options[0]) > 0 and
                        self.is_mouse_over(event, include_label=False,
                                           width_modifier=1 if self._scroll_bar else 0)):
                    # Figure out selected line
                    new_line = event.y - self._y + self._start_line
                    if self._titles:
                        new_line -= 1
                    new_line = min(new_line, len(self._options[0]) - 1)

                    # Update selection and fire select callback if needed.
                    if new_line >= 0:
                        self._line = new_line
                        self._options[0][self._line] =  -(self._options[0][self._line]) + 1
                        if event.buttons & MouseEvent.DOUBLE_CLICK != 0 and self._on_select:
                            self._on_select()
                    return None

                # Check for scroll bar interactions:
                if self._scroll_bar:
                    event = self._scroll_bar.process_event(event)

            # Ignore other mouse events.
            return event
        else:
            # Ignore other events
            return event

        # If we got here, we processed the event - swallow it.
        return None

    def _add_or_remove_scrollbar(self, width, height, dy):
        """
        Add or remove a scrollbar from this listbox based on height and available options.

        :param width: Width of the Listbox
        :param height: Height of the Listbox.
        :param dy: Vertical offset from top of widget.
        """
        if self._scroll_bar is None and len(self._options[0]) > height:
            self._scroll_bar = _ScrollBar(
                self._frame.canvas, self._frame.palette, self._x + width - 1, self._y + dy,
                height, self._get_pos, self._set_pos)
        elif self._scroll_bar is not None and len(self._options[0]) <= height:
            self._scroll_bar = None

    def _get_pos(self):
        """
        Get current position for scroll bar.
        """
        if self._h >= len(self._options[0]):
            return 0
        else:
            return self._start_line / (len(self._options[0]) - self._h)

    def _set_pos(self, pos):
        """
        Set current position for scroll bar.
        """
        if self._h < len(self._options[0]):
            pos *= len(self._options[0]) - self._h
            pos = int(round(max(0, pos), 0))
            self._start_line = pos

    def required_height(self, offset, width):
        return self._required_height

    @property
    def start_line(self):
        """
        The line that will be drawn at the top of the visible section of this list.
        """
        return self._start_line

    @start_line.setter
    def start_line(self, new_value):
        if 0 <= new_value < len(self._options[0]):
            self._start_line = new_value

    def update(self, frame_no):
        self._draw_label()

        # Prepare to calculate new visible limits if needed.
        height = self._h
        width = self._w

        # Clear out the existing box content
        (colour, attr, bg) = self._frame.palette["field"]
        for i in range(height):
            self._frame.canvas.print_at(
                " " * self.width,
                self._x + self._offset,
                self._y + i,
                colour, attr, bg)

        # Don't bother with anything else if there are no options to render.
        if len(self._options[0]) <= 0:
            return

        # Decide whether we need to show or hide the scroll bar and adjust width accordingly.
        if self._add_scroll_bar:
            self._add_or_remove_scrollbar(width, height, 0)
        if self._scroll_bar:
            width -= 1

        # Render visible portion of the text.
        y_offset = 0
        if self._centre:
            # Always make selected text the centre - not very compatible with scroll bars, but
            # there's not much else I can do here.
            self._start_line = self._line - (height // 2)
        start_line = self._start_line
        if self._start_line < 0:
            y_offset = -self._start_line
            start_line = 0

        check_char = u"✓" if self._frame.canvas.unicode_aware else "X"

        for i in range(0,len(self._options[0])):
            if start_line <= i < start_line + height - y_offset:
                colour, attr, bg = self._pick_colours("field", i == self._line)
                if len(self._options[1][i]) > width:
                    self._options[1][i] = self._options[1][i][:width - 3] + "..."
                self._frame.canvas.print_at(
                    "[{}] -- {}    {}    {}".format(check_char if self._options[0][i] else " ",
                        self._options[1][i],self._options[2][i],self._options[3][i]),
                    self._x + self._offset,
                    self._y + y_offset + i - start_line,
                    colour, attr, bg)

        # And finally draw any scroll bar.
        if self._scroll_bar:
            self._scroll_bar.update()



    @property
    def value(self):
        return self._value

    @value.setter
    def value(self, new_value):
        # Only trigger change notification after we've changed selection
        old_value = self._value
        self._value = new_value
        for i in range(0,len(self._options[0])):
            if self._options[0][i] == new_value:
                self._line = i
                break
        else:
            # No matching value - pick a default.
            if len(self._options[0]) > 0:
                self._line = 0
                self._value = self._options[0][self._line]
            else:
                self._line = -1
                self._value = None
        if self._validator:
            self._is_valid = self._validator(self._value)
        if old_value != self._value and self._on_change:
            self._on_change()

        # Fix up the start line now that we've explicitly set a new value.
        self._start_line = max(
            0, max(self._line - self._h + 1, min(self._start_line, self._line)))


class ListView(Frame):
    def __init__(self, screen):
        super(ListView, self).__init__(screen,
                                       screen.height * 2 // 3,
                                       screen.width * 2 // 3,
                                       on_load=self._reload_list,
                                       hover_focus=True,
                                       can_scroll=False,
                                       title="Available devices")
        # Save off the model that accesses the contacts database.
        self._model = None

        # Create the form for displaying the list of contacts.
        self._list_view = CheckList(
            Widget.FILL_FRAME,
            [[]],
            name="contacts",
            add_scroll_bar=True,
            on_change=self._on_pick,
            on_select=self._edit)
        self._edit_button = Button("kill", self._edit)
        self._delete_button = Button("options", self._delete)
        layout = Layout([100], fill_frame=True)
        self.add_layout(layout)
        layout.add_widget(self._list_view)
        layout.add_widget(Divider())
        layout2 = Layout([1, 1, 1, 1])
        self.add_layout(layout2)
        layout2.add_widget(Button("Scann", self._add), 0)
        layout2.add_widget(self._edit_button, 1)
        layout2.add_widget(self._delete_button, 2)
        layout2.add_widget(Button("Quit", self._quit), 3)
        self.fix()
        self._on_pick()

    def _on_pick(self):
        self._edit_button.disabled = None if len(self._list_view._options[0]) == 0 else 1
        self._delete_button.disabled = None if len(self._list_view._options[0]) == 0 else 1

    def _reload_list(self, new_value=None):
        pass
        #self._list_view.value = new_value

    def _add(self):
        self._list_view._options = matador.getHosts()

    def _edit(self):
        pass
        #self.save()
        #self._model.current_id = self.data["contacts"]
        #raise NextScene("Edit Contact")

    def _delete(self):
        #self.save()
        #self._model.delete_contact(self.data["contacts"])
        #self._reload_list()
        pass

    @staticmethod
    def _quit():
        raise StopApplication("User pressed quit")

matador = Killer()
def demo(screen, scene):
    scenes = [
        Scene([ListView(screen)], -1, name="Main"),
        #Scene([ContactView(screen, contacts)], -1, name="Edit Contact")
    ]

    screen.play(scenes, stop_on_resize=True, start_scene=scene, allow_int=True)


last_scene = None
while True:
    try:
        Screen.wrapper(demo, catch_interrupt=True, arguments=[last_scene])
        sys.exit(0)
    except ResizeScreenError as e:
        last_scene = e.scene