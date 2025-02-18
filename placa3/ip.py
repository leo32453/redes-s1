from iputils import *
import struct

class IP:

    def __init__(self, enlace):
        """
        Inicia a camada de rede. Recebe como argumento uma implementação
        de camada de enlace capaz de localizar os next_hop (por exemplo,
        Ethernet com ARP).
        """
        self.callback = None  # Callback a ser chamado quando um segmento TCP é recebido
        self.enlace = enlace
        self.enlace.registrar_recebedor(self.__raw_recv)
        self.ignore_checksum = self.enlace.ignore_checksum
        self.meu_endereco = None
        # Inicializa a tabela de roteamento como uma lista vazia
        self.tabela_roteamento = []
        # Inicializa um contador global para gerenciar o idetificador dos datagramas IP enviados
        self.count_datagram_id = 0

    def __raw_recv(self, datagrama):
        dscp, ecn, identification, flags, frag_offset, ttl, proto, \
            src_addr, dst_addr, payload = read_ipv4_header(datagrama)

        # Define o próximo salto antes da condicional
        next_hop = self._next_hop(dst_addr)

        if dst_addr == self.meu_endereco:
            # Atua como host
            if proto == IPPROTO_TCP and self.callback:
                self.callback(src_addr, dst_addr, payload)
        else:
            # Atua como roteador
            # Decrementa o TTL para o encaminhamento
            ttl -= 1
            if ttl == 0:
                # TTL expirado: descarta o datagrama e envia uma mensagem ICMP "Time Exceeded"
                roteador_destino = self._next_hop(self.meu_endereco)  # Próximo salto para enviar ICMP
                tipo_mensagem = 11  # Tipo de mensagem ICMP: "Time Exceeded"
                codigo_icmp = 0  # Código ICMP para "tempo excedido durante o trânsito"

                # Monta a mensagem ICMP de tempo excedido
                checksum_icmp = calc_checksum(struct.pack('!BBHI', tipo_mensagem, 0, 0, 0) + datagrama[:28])
                mensagem_time_exceeded = struct.pack('!BBHI', tipo_mensagem, codigo_icmp, checksum_icmp, 0) + datagrama[
                                                                                                              :28]

                # Constrói o cabeçalho IP com a mensagem ICMP
                cabeçalho_ip = struct.pack('!BBHHHBBH', 0x45, 0x00, 20 + len(mensagem_time_exceeded), identification,
                                           flags + frag_offset, 0x40, IPPROTO_ICMP, 0) + str2addr(
                    self.meu_endereco) + str2addr(src_addr)
                checksum_ip = calc_checksum(cabeçalho_ip)
                cabeçalho_ip = struct.pack('!BBHHHBBH', 69, 0, 20 + len(mensagem_time_exceeded), identification,
                                           flags + frag_offset, 64, IPPROTO_ICMP, checksum_ip) + str2addr(
                    self.meu_endereco) + str2addr(src_addr)

                # Atualiza o datagrama com o cabeçalho IP e a mensagem ICMP
                datagrama = cabeçalho_ip + mensagem_time_exceeded
            else:
                # Caso TTL ainda válido, calcula o próximo salto e encaminha
                # Reconstroi o cabeçalho IP e o datagrama com o payload original
                comprimento = 20 + len(payload)  # Comprimento total do pacote (cabeçalho + payload)
                cabeçalho_ip = struct.pack('!BBHHHBBH', 0x45, 0x00, comprimento, identification, flags + frag_offset,
                                           ttl, proto, 0x00) + str2addr(src_addr) + str2addr(dst_addr)
                # Calcula o checksum real do cabeçalho IP
                checksum = calc_checksum(cabeçalho_ip)
                # Atualiza o cabeçalho com o checksum calculado
                cabeçalho_ip = struct.pack('!BBHHHBBH', 0x45, 0x00, comprimento, identification, flags + frag_offset,
                                           ttl, proto, checksum) + str2addr(src_addr) + str2addr(dst_addr)

                datagrama = cabeçalho_ip + payload

        # Envia o datagrama atualizado para o próximo salto
        self.enlace.enviar(datagrama, next_hop)

    def _next_hop(self, dest_addr):
        # Inicializa a variável que irá armazenar a melhor correspondência (next_hop)
        melhor_hop = None

        # Itera sobre a tabela de roteamento, onde cada entrada é composta por um CIDR e o próximo salto (next_hop)
        for i in self.tabela_roteamento:
            cidr, proximo_salto = i
            # Divide o CIDR em endereço de rede e a máscara de sub-rede
            endereco_rede, mascara = cidr.split('/')

            # Converte o endereço de destino (dest_addr) e o endereço de rede (endereco_rede) para formato numérico
            # Isso facilita a manipulação e comparação dos endereços
            destino, = struct.unpack('!I', str2addr(dest_addr))  # Endereço de destino em formato numérico
            rede, = struct.unpack('!I', str2addr(endereco_rede))  # Endereço de rede em formato numérico

            # Aplica a máscara de sub-rede ao endereço de destino para verificar se o destino está na mesma rede
            # Se a operação AND resultar no mesmo valor do endereço de rede, significa que o destino está dentro da rede
            if (destino & (0xFFFFFFFF << (32 - int(mascara)))) == rede:
                # Verifica se a máscara de sub-rede atual tem um prefixo maior (mais específico)
                # Se for a melhor correspondência até agora, atualiza a variável 'melhor_hop'
                if (melhor_hop is None) or (int(mascara) > int(melhor_hop[0].split('/')[1])):
                    melhor_hop = i

        # Verifica se foi encontrada uma correspondência de próximo salto (next_hop) com base na melhor máscara
        if melhor_hop is not None:
            # Retorna o próximo salto associado à melhor correspondência
            return melhor_hop[1]
        else:
            # Se nenhuma correspondência for encontrada, retorna None indicando que não há próximo salto
            return None

    def definir_endereco_host(self, meu_endereco):
        """
        Define qual o endereço IPv4 (string no formato x.y.z.w) deste host.
        Se recebermos datagramas destinados a outros endereços em vez desse,
        atuaremos como roteador em vez de atuar como host.
        """
        self.meu_endereco = meu_endereco

    def definir_tabela_encaminhamento(self, tabela):
        """
        Define a tabela de encaminhamento no formato
        [(cidr0, next_hop0), (cidr1, next_hop1), ...]

        Onde os CIDR são fornecidos no formato 'x.y.z.w/n', e os
        next_hop são fornecidos no formato 'x.y.z.w'.
        """
        self.tabela_roteamento = tabela

    def registrar_recebedor(self, callback):
        """
        Registra uma função para ser chamada quando dados vierem da camada de rede
        """
        self.callback = callback

    def enviar(self, segmento, dest_addr):
        """
        Envia segmento para dest_addr, onde dest_addr é um endereço IPv4
        (string no formato x.y.z.w).
        """
        next_hop = self._next_hop(dest_addr)
        comprimento = 20 + len(segmento)  # Comprimento total do pacote (cabeçalho + payload)

        # Monta o cabeçalho sem o checksum para calculá-lo
        header = struct.pack('!BBHHHBBH', 0x45, 0x00, comprimento, self.count_datagram_id, 0x00 + 0x00, 64, IPPROTO_TCP, 0x00) + str2addr(self.meu_endereco) + str2addr(dest_addr)
        checksum = calc_checksum(header)
        # Atualiza o cabeçalho com o checksum calculado
        header = struct.pack('!BBHHHBBH', 0x45, 0x00, comprimento, self.count_datagram_id, 0x00 + 0x00, 64, IPPROTO_TCP, checksum) + str2addr(self.meu_endereco) + str2addr(dest_addr)

        datagrama = header + segmento

        # Incrementa o identificador do datagrama para garantir Id's unicos
        self.count_datagram_id += 1

        self.enlace.enviar(datagrama, next_hop)