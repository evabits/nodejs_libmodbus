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
                "<!@(node -p \"require('node-addon-api').include\")"
            ],
            "defines": ['NAPI_DISABLE_CPP_EXCEPTIONS'],
            "conditions": [
                ["libmodbus != 'internal'", {
                    "include_dirs": [ "<(libmodbus_include)" ],
                    "libraries": [
                    "-l<(libmodbus_libname)"
                    ],
                    "conditions": [ [ "OS=='linux'", {"libraries+":["-Wl,-rpath=<@(libmodbus)/lib"]} ] ],
                }
                ]
            ],
            'sources': [
                './src/main.cc'
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