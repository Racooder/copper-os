---
layout: default
---

# Types of software

- application
- library

## Applications

Can be launched optionally with arguments and offer a graphical user interface or a command line interface.

They can also run in the background and offer an api so other applications can interact with them.

## Libraries

Can be imported and offers functions, classes and similar things that perform various tasks but without any user interface.

# Folder layout

```
/
├── os/
│   ├── app/
│   │   └── application_id/
│   │       ├── _meta.tbl
│   │       ├── _main.lua
│   │       └── ...
│   ├── data/
│   │   ├── app/
│   │   │   └── application_id/
│   │   │       └── ...
│   │   ├── lib/
│   │   │   └── library_id/
│   │   │       └── ...
│   │   └── sys/
│   │       ├── dependencies.tbl
│   │       └── ...
│   ├── home/
│   │   └── ...
│   ├── lib/
│   │   └── library_id/
│   │       ├── _meta.tbl
│   │       ├── _main.lua
│   │       ├── sub_library.lua
│   │       └── sub_group/
│   │           └── sub_library.lua
│   ├── log/
│   │   ├── app/
│   │   │   └── application_id/
│   │   │       ├── _main.log
│   │   │       └── sub_log.log
│   │   ├── lib/
│   │   │   └── library_id/
│   │   │       ├── _main.log
│   │   │       └── sub_log.log
│   │   └── sys/
│   │       └── main.log
│   └── sys/
└── startup.lua
```
