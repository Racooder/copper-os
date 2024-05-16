---
layout: page
title: CopperUtility
permalink: /libraries/CopperUtility
---

CopperUtility is a collection of utility functions for various Copper OS libraries.

## Classes

### List

#### Fields

- `first` - The index of the first element in the list
- `last` - The index of the last element in the list

#### Functions

##### new(): [List](https://github.com/Racooder/copper-os/wiki/CopperUtility#List)

##### pushLeft(`value`: [any](https://www.lua.org/pil/2.html))

Adds a value to the beginning of the list

##### pushRight(`value`: [any](https://www.lua.org/pil/2.html))

Adds a value to the end of the list

##### popLeft() : [any](https://www.lua.org/pil/2.html)

Removes and returns the first value of the list

##### popRight() : [any](https://www.lua.org/pil/2.html)

Removes and returns the last value of the list

## Functions

##### splitString(`inputstr`: [string](https://www.lua.org/pil/2.4.html), `sep`: [string](https://www.lua.org/pil/2.4.html)) : [string](https://www.lua.org/pil/2.4.html)

Splits a string into a table of strings based on a separator.

##### trimString(`inputstr`: [string](https://www.lua.org/pil/2.4.html)) : [string](https://www.lua.org/pil/2.4.html)

Removes whitespaces from the start and end of a string

##### concatTables(`t1`: [table](https://www.lua.org/pil/2.5.html), `t2`: [table](https://www.lua.org/pil/2.5.html)) : [table](https://www.lua.org/pil/2.5.html)

Concatenates two tables. The first table is modified.
