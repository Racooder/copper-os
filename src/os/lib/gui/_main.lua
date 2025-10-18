local Package = {}

local main_term = term.current()

local Gui_Element = {}

function Gui_Element:new(x, y, width, height, parent)
    parent = parent or main_term
    local w, h = parent.get_size()

    local obj = {
        __super = self,

        x = x or 1,
        y = y or 1,
        width = width or w,
        height = height or h,
        background_color = colors.black,
        text_color = colors.white,
        window = window.create(parent, x, y, width, height),
    }
    setmetatable(obj, self)
    self.__index = self
    return obj
end

function Gui_Element:draw()
    self.window.setBackgroundColor(self.background_color)
    self.window.setTextColor(self.text_color)
    self.window.clear()
end

function Gui_Element:set_visible(visible)
    self.window.setVisible(visible)
end

local Text = Gui_Element:new()

function Text:new(x, y, width, height, text, parent)
    local obj = self.__super.new(self, x, y, width, height, parent)
    obj.text = text or ""
end

function Text:draw()
    self.__super.draw(self)
    self.window.setCursorPos(1, 1)
    self.window.write(self.text)
end

return Package
