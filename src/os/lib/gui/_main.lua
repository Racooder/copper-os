local Package = {}

local mainTerm = term.current()

local GuiElement = {}

function GuiElement:new(x, y, width, height, parent)
    parent = parent or mainTerm
    local w, h = parent.getSize()

    local obj = {
        __super = self,

        x = x or 1,
        y = y or 1,
        width = width or w,
        height = height or h,
        backgroundColor = colors.black,
        textColor = colors.white,
        window = window.create(parent, x, y, width, height),
    }
    setmetatable(obj, self)
    self.__index = self
    return obj
end

function GuiElement:draw()
    self.window.setBackgroundColor(self.backgroundColor)
    self.window.setTextColor(self.textColor)
    self.window.clear()
end

function GuiElement:setVisible(visible)
    self.window.setVisible(visible)
end

local Text = GuiElement:new()

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
