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
                "<!@(node -p \"require('node-addon-api').include\")",
                "<(libmodbus_include)"
            ],
            'defines': [ 'DEBUG', '_DEBUG' ],
            'cflags': [ '-ggdb', '-O0' ],
            'cflags_cc+': [ '-ggdb', '-O0' ],
            "defines": ['NAPI_DISABLE_CPP_EXCEPTIONS'],
            "libraries": [
<<<<<<< HEAD
                "-l<(libmodbus_libname)"
=======
            "-l<(libmodbus_libname)"
>>>>>>> b3f51a170d8999536f871c2eeaaeee9ba7197a52
            ],
            "conditions": [ [ "OS=='linux'", {"libraries+":["-Wl,-rpath=<@(libmodbus)/lib"]} ] ],
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