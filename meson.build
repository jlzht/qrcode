project('qrcode', 'cpp',
  default_options : ['cpp_std=c++17']
)

crow_dep = dependency('crowcpp-crow', required: true)
openssl_dep = dependency('openssl', required: true)
sqlite3_dep = dependency('sqlite3', required: true)
crypt_dep = dependency('libxcrypt', required: true)
qr_dep = dependency('qr-code-generator', required: true)

executable('qrcode',
  'src/main.cpp',
  dependencies: [crow_dep, openssl_dep, sqlite3_dep, crypt_dep, qr_dep]
)
