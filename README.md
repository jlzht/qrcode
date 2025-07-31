# QR code
Pequeno projeto interativo digital

## Compilando
Instale as dependências:
- g++
- cmake
- conan
- meson

Na pasta do projeto:
```
conan install . --output-folder=build --build=missing
meson setup build --native-file build/conan_meson_native.ini
meson compile -C build
```

## Utilização
Para inicializar o servidor web, é necessário especificar um arquivo de entrada.
Esse arquivo será utilizado para criar as rotas de acesso ocultas. O número de rotas
equivale ao número de linhas do arquivo. Também é necessário especificar o arquivo de
saída (que mapeia um nome do arquivo de entrada ao seu hash correspondente) e o domínio
no qual o servidor está hospedado, utilizado para gerar os QR codes.

```
./qrcode -i <entrada> -o <saida> -p <porta> -t <template> -d <dominio>
```
