---
layout: default
---

# CopperUtility

CopperUtility is a collection of utility functions for various Copper OS libraries.

## Classes

### List

#### Fields

| `first` | The index of the first element in the list |
| `last`  | The index of the last element in the list  |

#### Functions

- new(): [List](#List)

Creates a new list

- pushLeft(`value`: [any](https://www.lua.org/pil/2.html))

Adds a value to the beginning of the list

- pushRight(`value`: [any](https://www.lua.org/pil/2.html))

Adds a value to the end of the list

- popLeft() : [any](https://www.lua.org/pil/2.html)

Removes and returns the first value of the list

- popRight() : [any](https://www.lua.org/pil/2.html)

Removes and returns the last value of the list

## Functions

splitString(`inputstr`: [string](https://www.lua.org/pil/2.4.html), `sep`: [string](https://www.lua.org/pil/2.4.html)) : [string](https://www.lua.org/pil/2.4.html)

Splits a string into a table of strings based on a separator.

```lua
{% include examples/CopperUtility/split_string.lua %}
```

trimString(`inputstr`: [string](https://www.lua.org/pil/2.4.html)) : [string](https://www.lua.org/pil/2.4.html)

Removes whitespaces from the start and end of a string

```lua
{% include examples/CopperUtility/trim_string.lua %}
```

concatTables(`t1`: [table](https://www.lua.org/pil/2.5.html), `t2`: [table](https://www.lua.org/pil/2.5.html)) : [table](https://www.lua.org/pil/2.5.html)

Concatenates two tables. The first table is modified.

```lua
{% include examples/CopperUtility/concat_tables.lua %}
```
