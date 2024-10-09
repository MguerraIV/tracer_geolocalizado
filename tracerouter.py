from socket import *
import os
import sys
import struct
import time
import select
import requests
import folium

# Tipos de Retorno ICMP
ICMP_ECHO_REPLY = 0 # indica que o pacote chegou ao destino
ICMP_ECHO_REQUEST = 8 # o pacote está em um roteador intermediário
ICMP_TIME_EXCEEDED = 11 # o tempo de transmissão do pacote foi excedido 

# Número de saltos para a transmissão do pacote
MAX_HOPS = 30

def obter_localizacao(): #função para obter localização do próprio computador
    try:
        # Obtém o endereço IP público
        resposta = requests.get('https://ipinfo.io/json')
        dados = resposta.json()
        
        return dados
    
    except requests.exceptions.RequestException as e:
        print(f'Ocorreu um erro ao tentar obter a localização: {e}')


class Tracerouter:

    lista_rotas = [] # armazenar a lista de pontos pelos quais o pacote passou

    # Função de checksum para validar a integridade dos dados
    def checksum(self, string):
        csum = 0
        countTo = (len(string) // 2) * 2
        count = 0

        while count < countTo:
            thisVal = string[count + 1] * 256 + string[count]
            csum = csum + thisVal
            csum = csum & 0xffffffff
            count = count + 2

        if countTo < len(string):
            csum = csum + string[len(string) - 1]
            csum = csum & 0xffffffff

        csum = (csum >> 16) + (csum & 0xffff)
        csum = csum + (csum >> 16)
        answer = ~csum
        answer = answer & 0xffff
        answer = answer >> 8 | (answer << 8 & 0xff00)
        return answer


    # Função para criar um pacote padrão ICMP que será enviado pela rede
    def make_packet(self):
        my_checksum = 0
        my_id = os.getpid() & 0xFFFF  # Retorna o ID do processo atual

        # Cria o cabeçalho ICMP, struct.pack() empacota os dados em formato binário
        header = struct.pack("BBHHH", ICMP_ECHO_REQUEST, 0, my_checksum, my_id, 1)
        data = struct.pack("d", time.time())

        # Calcula o checksum para os dados e para o cabeçalho
        my_checksum = self.checksum(header + data)

        if sys.platform == 'darwin':
            # Converte inteiros de 16 bits de ordem do host para ordem de byte de rede
            my_checksum = htons(my_checksum) & 0xffff
        else:
            my_checksum = htons(my_checksum)

        # O cabeçalho é recriado com o checksum correto e o pacote é criado
        header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, my_checksum, my_id, 1)
        packet = header + data
        return packet


    # Função para retornar o nome do roteador de um dado IP
    def get_addr_name(self, addr):
        try:
            return gethostbyaddr(addr)[0]
        except herror:  
            return addr
        
    
    # Função para descobrir a localização fisica de um dado IP, esse valor é adicionado em lista_rotas
    def get_geo_data(self, ip_address):
        try:
            response = requests.get(f"http://ip-api.com/json/{ip_address}") # requisição para a api de geolocalização
            data = response.json() # dados retornados
            if data['status'] == 'success':
                return {
                    'ip': ip_address,
                    'coordenadas': [data['lat'], data['lon']],
                    'cidade': data['city'],
                    'pais': data['country']
                }
            else:
                return {'ip': ip_address, 'error': 'Geolocalização não encontrada'}
        except Exception as e:
            return {'ip': ip_address, 'error': str(e)}


    # Função para realizar um tracerouter único para a rota seguinte
    def single_traceroute(self, dest, ttl, timeout, time_left):
        # Obtém o número do protocolo ICMP
        icmp = getprotobyname("icmp")
        
        # Cria um socket RAW para enviar pacotes ICMP
        raw_socket = socket(AF_INET, SOCK_RAW, icmp)
        
        # Define o valor de TTL (Time To Live) para o socket, controlando quantos saltos o pacote pode fazer
        raw_socket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', ttl))
        
        # Define o tempo limite para operações no socket
        raw_socket.settimeout(timeout)

        try:
            # Gera um pacote ICMP a ser enviado
            packet = self.make_packet()
            
            # Envia o pacote para o destino especificado
            raw_socket.sendto(packet, (dest, 0))
            
            # Marca o tempo em que o pacote foi enviado
            time_sent = time.time()

            # Inicia a seleção para verificar se o socket está pronto para receber uma resposta
            started_select = time.time()
            
            # Espera até que o socket esteja pronto ou o tempo limite seja alcançado
            what_ready = select.select([raw_socket], [], [], time_left)
            
            # Calcula o tempo gasto na operação de seleção
            time_in_select = time.time() - started_select
            
            # Verifica se o socket não está pronto (timeout)
            if what_ready[0] == []:  # Timeout
                print(f"{ttl}   Timeout: O socket não está pronto")
                return time_left - (time.time() - started_select)

            # Atualiza o tempo restante
            time_left = time_left - time_in_select
            
            # Verifica se o tempo restante é menor ou igual a zero (timeout)
            if time_left <= 0:  # Timeout
                print(f"{ttl}  Timeout: Sem tempo restante")
                return time_left

            # Marca o tempo em que a resposta foi recebida
            time_received = time.time()
            
            # Recebe o pacote de resposta do socket
            rec_packet, addr = raw_socket.recvfrom(1024)
            
            # Extrai o cabeçalho ICMP da resposta recebida
            icmp_header = rec_packet[20:28]
            
            # Desempacota o cabeçalho ICMP para obter os valores relevantes
            icmp_type, code, checksum, packetID, sequence = struct.unpack("bbHHh", icmp_header)

            # Verifica se o tipo de ICMP indica que o TTL expirou
            if icmp_type == ICMP_TIME_EXCEEDED:  # TTL is 0
                addr_name = self.get_addr_name(addr[0])  # Obtém o nome do endereço
                geo_data = self.get_geo_data(addr[0])    # Obtém dados geográficos do endereço

                if geo_data.get("error") is None:        # Verifica se não houve erro nos dados geográficos
                    cidade = geo_data.get("cidade") + ', ' + geo_data.get("pais")
                    self.lista_rotas.append(geo_data)    # Adiciona dados geográficos à lista de rotas
                else:
                    cidade = geo_data.get("error")
                
                print(f"{ttl} {addr_name} ({addr[0]}) {((time_received - time_sent) * 1000):.2f} ms {cidade}")
               
                return time_left  # Retorna o tempo restante

            # Verifica se a resposta é um Echo Reply (o destino final respondeu)
            elif icmp_type == ICMP_ECHO_REPLY:  # Final destination replied
                # Obtém o tempo em que o pacote foi enviado
                byte = struct.calcsize("d")
                time_sent = struct.unpack("d", rec_packet[28:28 + byte])[0]
                addr_name = self.get_addr_name(addr[0])  # Obtém o nome do endereço
                geo_data = self.get_geo_data(addr[0])    # Obtém dados geográficos do endereço
                
                if geo_data.get("error") is None:        # Verifica se não houve erro nos dados geográficos
                    cidade = geo_data.get("cidade") + ', ' + geo_data.get("pais")
                    self.lista_rotas.append(geo_data)    # Adiciona dados geográficos à lista de rotas
                else:
                    cidade = geo_data.get("error")
                print(f"{ttl} {addr_name} ({addr[0]}) {((time_received - time_sent) * 1000):.2f} ms {cidade}")

                return -1  # Retorna -1 para indicar que o destino final respondeu

            # Lida com outros tipos de ICMP que não são Echo Reply ou Time Exceeded
            else:
                addr_name = self.get_addr_name(addr[0])  # Obtém o nome do endereço
                geo_data = self.get_geo_data(addr[0])    # Obtém dados geográficos do endereço
               
                if geo_data.get("error") is None:        # Verifica se não houve erro nos dados geográficos
                    cidade = geo_data.get("cidade") + ', ' + geo_data.get("pais")
                    self.lista_rotas.append(geo_data)    # Adiciona dados geográficos à lista de rotas
                else:
                    cidade = geo_data.get("error")

                print(f"{ttl} icmp_type: {icmp_type} {addr_name} ({addr[0]}) {((time_received - time_sent) * 1000):.2f} ms {cidade}")
               
                return time_left  # Retorna o tempo restante

        finally:  # Sempre fecha o socket ao final da execução
            raw_socket.close()


    # Função para o tracerouter, será executada até atingir o destino ou o número máximo de saltos
    def traceroute(self, host, timeout=1):
        time_left = timeout # Definição do Timeout
        dest = gethostbyname(host) # Endereço do destino

        print(f"Definindo rota para {host} com no máximo {MAX_HOPS} saltos")

        # Aumentando o TTL até o número máximo de saltos
        for ttl in range(1, MAX_HOPS):
            time_left = self.single_traceroute(dest, ttl, timeout, time_left) # Executando tracerouter para cada salto
            
            if time_left <= 0: # Quando chega ao destino a função retorna -1 e o código encerra
                break

        if ttl == MAX_HOPS: #Caso chegue ao máximo de saltos o código encerra
            print(f"Timeout: Excedeu {MAX_HOPS} saltos")

        return
    

    # Função para gerar o mapa, APENAS COM OS PONTOS QUE FORAM POSSÍVEIS LOCALIZAR
    def gerar_mapa(self):
        dados = obter_localizacao() # localização inicial (da máquina que executa o código)
        coordenadas = [] # lista para armazenar as coordenadas, usada para conectar os pontos
        
        coordenada_inicial_float = list(map(float, dados.get('loc').split(','))) 
        coordenada_inicial = dados.get('loc').split(',')
        coordenadas.append(coordenada_inicial_float)
        
        mapa = folium.Map(location=coordenada_inicial) # definição do mapa, com a lib Folium
        folium.Marker(location=coordenada_inicial, tooltip=f"{dados.get('ip')}").add_to(mapa) # adicionando pin para a coordenada inicial
        
        if len(self.lista_rotas) != 0: #percorre a lista de rotas e coloca um pin para cada ponto no mapa
            
            for rota in self.lista_rotas:
                ip_atual = rota.get('ip')
                coordenada_atual = rota.get('coordenadas')
                folium.Marker(location=coordenada_atual, tooltip=f"IP: {ip_atual}").add_to(mapa)
                coordenada_atual_float = list(map(float, coordenada_atual))
                coordenadas.append(coordenada_atual_float)
            
            # Desenha a linha conectando os marcadores
            folium.PolyLine(locations=coordenadas, color='blue', weight=2.5, opacity=1).add_to(mapa)
            return mapa
        
        return None


if __name__ == '__main__':
    tracer = Tracerouter()
    host = input("Digite o destino: ")
    tracer.traceroute(host, timeout=30)
    mapa = tracer.gerar_mapa()
    mapa.save("mapa.html")