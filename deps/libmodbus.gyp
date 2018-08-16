{
  'includes': [ 'common-libmodbus.gypi' ],
  'target_defaults': {
    'default_configuration': 'Release',
    'cflags':[
      '-std=c99'
    ],
    'configurations': {
      'Debug': {
        'defines': [ 'DEBUG', '_DEBUG' ],
        'msvs_settings': {
          'VCCLCompilerTool': {
            'RuntimeLibrary': 1, # static debug
          },
        },
      },
      'Release': {
        'defines': [ 'NDEBUG' ],
        'msvs_settings': {
          'VCCLCompilerTool': {
            'RuntimeLibrary': 0, # static release
          },
        },
      }
    },
    'msvs_settings': {
      'VCCLCompilerTool': {
      },
      'VCLibrarianTool': {
      },
      'VCLinkerTool': {
        'GenerateDebugInformation': 'true',
      },
    },
    'conditions': [
      ['OS == "win"', {
        'defines': [
          'WIN32'
        ],
      }]
    ],
  },

  'targets': [
    {
      'target_name': 'action_before_build',
      'type': 'none',
      'hard_dependency': 1,
      'actions': [
        {
          'action_name': 'unpack_libmodbus_dep',
          'inputs': [
            './libmodbus-<@(libmodbus_version).tar.gz'
          ],
          'outputs': [
            '<(SHARED_INTERMEDIATE_DIR)/libmodbus-<@(libmodbus_version)/src/modbus.c',
          '<(SHARED_INTERMEDIATE_DIR)/libmodbus-<@(libmodbus_version)/src/modbus-data.c',
          '<(SHARED_INTERMEDIATE_DIR)/libmodbus-<@(libmodbus_version)/src/modbus-rtu.c',
          '<(SHARED_INTERMEDIATE_DIR)/libmodbus-<@(libmodbus_version)/src/modbus-tcp.c',
          '<(SHARED_INTERMEDIATE_DIR)/libmodbus-<@(libmodbus_version)/src/modbus.h',
          '<(SHARED_INTERMEDIATE_DIR)/libmodbus-<@(libmodbus_version)/src/modbus-data.h',
          '<(SHARED_INTERMEDIATE_DIR)/libmodbus-<@(libmodbus_version)/src/modbus-rtu.h',
          '<(SHARED_INTERMEDIATE_DIR)/libmodbus-<@(libmodbus_version)/src/modbus-tcp.h'
          ],
          'action': ['python','./extract.py','./libmodbus-<@(libmodbus_version).tar.gz','<(SHARED_INTERMEDIATE_DIR)']
        }
      ],
      'direct_dependent_settings': {
        'include_dirs': [
          '<(SHARED_INTERMEDIATE_DIR)/libmodbus-<@(libmodbus_version)/src/',
        ]
      },
    },
    {
      'target_name': 'libmodbus',
      'type': 'static_library',
      'include_dirs': [ '<(SHARED_INTERMEDIATE_DIR)/libmodbus-<@(libmodbus_version)/src/' ],
      'dependencies': [
        'action_before_build'
      ],
      'sources': [
        '<(SHARED_INTERMEDIATE_DIR)/libmodbus-<@(libmodbus_version)/src/modbus.c',
        '<(SHARED_INTERMEDIATE_DIR)/libmodbus-<@(libmodbus_version)/src/modbus-data.c',
        '<(SHARED_INTERMEDIATE_DIR)/libmodbus-<@(libmodbus_version)/src/modbus-rtu.c',
        '<(SHARED_INTERMEDIATE_DIR)/libmodbus-<@(libmodbus_version)/src/modbus-tcp.c'
      ],
      'direct_dependent_settings': {
        'include_dirs': [ '<(SHARED_INTERMEDIATE_DIR)/libmodbus-<@(libmodbus_version)/src/' ],
        'defines': [
        ],
      },
      'cflags_cc': [
      ],
      'defines': [
      ],
      'export_dependent_settings': [
        'action_before_build',
      ]
    }
  ]
}
