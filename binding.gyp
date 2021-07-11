{
    "includes": [ ],
      "variables": {
      "libmodbus%":"internal",
      "libmodbus_include%":"/usr/include/modbus/",
      "libmodbus_libname%":"modbus"
    },
    'targets': [
        {
            'target_name': 'modbus_binding',
            "include_dirs" : [
                "<!(node -e \"require('nan')\")"
            ],
            "conditions": [
                ["libmodbus == 'internal'", {
                    "include_dirs": [ "<(libmodbus_include)" ],
                    "libraries": [
                    "-l<(libmodbus_libname)"
                    ],
                    "conditions": [ [ "OS=='linux'", {"libraries+":["-Wl,-rpath=<@(libmodbus)/lib"]} ] ],
                    "conditions": [ [ "OS!='win'", {"libraries+":["-L<@(libmodbus)/lib"]} ] ],
                    'msvs_settings': {
                    'VCLinkerTool': {
                        'AdditionalLibraryDirectories': [
                        '<(libmodbus)/lib'
                        ],
                    },
                    }
                },
                {
                    "dependencies": [
                    "deps/libmodbus.gyp:libmodbus"
                    ]
                }
                ]
            ],
            'sources': [
                './src/main.cpp'
            ],
        },
        {
            "target_name": "action_after_build",
            "type": "none",
            "dependencies": [ "modbus_binding" ],
            "copies": [
                {
                    "files": [ "<(PRODUCT_DIR)/modbus_binding.node" ],
                    "destination": "<(module_path)"
                }
            ]
        }
    ]
}