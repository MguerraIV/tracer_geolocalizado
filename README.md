# Tracerouter em Python

![Traceroute](https://img.shields.io/badge/python-3.8%2B-blue.svg) ![License](https://img.shields.io/badge/license-MIT-brightgreen.svg)

## Descrição

Este projeto é um **Tracerouter** desenvolvido em Python que rastreia o caminho que um pacote faz até chegar à rede de destino. Ele mostra um mapa interativo com marcadores que representam cada salto (hop) no caminho percorrido pelo pacote.

## Funcionalidades

- **Rastreamento de Pacotes**: Utilize o protocolo ICMP para rastrear a rota de um pacote até o destino especificado.
- **Visualização em Mapa**: Exibe um mapa interativo com marcadores para cada nó visitado, permitindo uma visualização clara do caminho percorrido.
- **Informações Geográficas**: Coleta e exibe dados geográficos dos endereços IP encontrados ao longo da rota.

## Tecnologias Utilizadas

- **Python**: Linguagem de programação utilizada para o desenvolvimento do projeto.
- **Sockets**: Utiliza sockets de rede para enviar pacotes ICMP.
- **Folium**: Biblioteca para visualização de dados geográficos que gera mapas interativos.
- **Struct**: Manipulação de dados binários para criar pacotes ICMP personalizados.
- **GeoIP**: Para obter informações geográficas dos endereços IP.
