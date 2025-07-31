from conan import ConanFile
from conan.tools.gnu import PkgConfigDeps
from conan.tools.meson import MesonToolchain
from conan.tools.cmake import CMakeDeps

class QrCode(ConanFile):
    name = "qrcode"
    version = "0.0.1"
    
    settings = "os", "compiler", "build_type", "arch"

    def requirements(self):
        self.requires("qr-code-generator/1.8.0")
        self.requires("libxcrypt/4.4.36")
        self.requires("crowcpp-crow/1.2.1")
        self.requires("sqlite3/3.46.0")
        self.requires("openssl/3.5.1")

    def generate(self):
        pc_deps = PkgConfigDeps(self)
        pc_deps.generate()
        
        tc = MesonToolchain(self)
        tc.generate()

        cmake_deps = CMakeDeps(self)
        cmake_deps.generate()
