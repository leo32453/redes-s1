import asyncio
import random
from tcputils import *
import time

# p2 redes 2024/2
class Servidor:
    def __init__(self, rede, porta):
        # Inicializa o servidor com a rede e a porta especificada
        self.rede = rede
        self.porta = porta
        self.conexoes = {}
        self.callback = None
        
        # Registra a função de recepção de pacotes na rede
        self.rede.registrar_recebedor(self._rdt_rcv)

    def registrar_monitor_de_conexoes_aceitas(self, callback):
        # Registra um callback para monitorar conexões aceitas
        self.callback = callback

    def _rdt_rcv(self, src_addr, dst_addr, segment):
        # Processa pacotes recebidos pela rede
        (
            src_port,
            dst_port,
            seq_no,
            ack_no,
            flags,
            window_size,
            checksum,
            urg_ptr,
        ) = read_header(segment)

        # Ignora pacotes destinados a outras portas
        if dst_port != self.porta:
            return

        # Verifica a integridade do checksum
        if (
            not self.rede.ignore_checksum
            and calc_checksum(segment, src_addr, dst_addr) != 0
        ):
            return

        payload = segment[4 * (flags >> 12) :]
        id_conexao = (src_addr, src_port, dst_addr, dst_port)

        if (flags & FLAGS_SYN) == FLAGS_SYN:
            # Estabelece uma nova conexão caso um pacote SYN seja recebido
            conexao = self.conexoes[id_conexao] = ConexaoRDT(self, id_conexao)
            conexao.ack_no = new_ack_no = seq_no + 1
            conexao.seq_no = new_seq_no = random.randint(0, 0xFFFF)
            conexao.flags = new_flags = FLAGS_SYN | FLAGS_ACK

            header = make_header(dst_port, src_port, new_seq_no, new_ack_no, new_flags)
            new_segment = fix_checksum(header, dst_addr, src_addr)

            self.rede.enviar(new_segment, src_addr)

            if self.callback:
                self.callback(conexao)

        elif id_conexao in self.conexoes:
            # Passa o pacote para a conexão correspondente
            self.conexoes[id_conexao]._rdt_rcv(seq_no, ack_no, flags, payload)

        else:
            print(
                "%s:%d -> %s:%d (pacote associado a conexão desconhecida)"
                % (src_addr, src_port, dst_addr, dst_port)
            )


# config conn RDT
class ConexaoRDT:
    def __init__(self, servidor, id_conexao):
        # Inicializa uma nova conexão
        self.servidor = servidor
        self.id_conexao = id_conexao
        self.callback = None
        self.SampleRTT = None
        self.EstimatedRTT = None
        self.DevRTT = None
        self.alpha = 0.125
        self.beta = 0.25
        self.not_check = []
        self.timer = None
        self.timer_ativo = False
        self.TimeoutInterval = 1
        self.received_acks = 0
        self.segmentos_count = 0
        self.window = 1
        self.window_ocupation = 0
        self.dados_restantes = bytearray()
        self.ack_no = None
        self.seq_no = None
        self.flags = None

    def _rdt_rcv(self, seq_no, ack_no, flags, payload):
        # Trata pacotes recebidos na conexão
        tempo_recepcao_ack = time.time()

        if seq_no != self.ack_no:
            return

        if (flags & FLAGS_FIN) == FLAGS_FIN:
            # Encerra a conexão caso um FIN seja recebido
            payload = b""
            self.ack_no = novo_ack_no = seq_no + 1 + len(payload)
            self.seq_no = novo_seq_no = ack_no
            self.flags = novas_flags = FLAGS_ACK

            (dst_addr, dst_port, src_addr, src_port) = self.id_conexao
            header = make_header(
                src_port, dst_port, novo_seq_no, novo_ack_no, novas_flags
            )
            segmento = fix_checksum(header, src_addr, dst_addr)
            self.servidor.rede.enviar(segmento, dst_addr)

            self.callback(self, payload)
            return

        if (flags & FLAGS_ACK) == FLAGS_ACK and len(payload) == 0:
            # Atualiza número de sequência e acknowledgment
            self.ack_no = seq_no
            self.seq_no = ack_no

            if self.not_check:
                self.intervalo_timeout_function(tempo_recepcao_ack)
                self.received_acks += 1
                self.window += 1
                self.timer.cancel()
                self.timer_ativo = False
                self.not_check.pop(0)
                self.window_ocupation -= 1

            if self.not_check:
                self.timer = asyncio.get_event_loop().call_later(
                    self.TimeoutInterval, self.timeout
                )
                self.timer_ativo = True

            return

        self.ack_no = novo_ack_no = seq_no + len(payload)
        self.seq_no = novo_seq_no = ack_no
        self.flags = novas_flags = FLAGS_ACK

        (dst_addr, dst_port, src_addr, src_port) = self.id_conexao
        header = make_header(src_port, dst_port, novo_seq_no, novo_ack_no, novas_flags)
        segmento = fix_checksum(header, src_addr, dst_addr)
        self.servidor.rede.enviar(segmento, dst_addr)

        self.callback(self, payload)

    # Registra recebedor
    def registrar_recebedor(self, callback):

        self.callback = callback

    # envio de dados
    def enviar(self, dados):

        (dst_addr, dst_port, src_addr, src_port) = self.id_conexao
        buffer = dados

        while len(buffer) > 0:
            self.segmentos_count += 1
            payload = buffer[:MSS]
            buffer = buffer[MSS:]

            header = make_header(
                src_port, dst_port, self.seq_no, self.ack_no, FLAGS_ACK
            )
            segmento = fix_checksum(header + payload, src_addr, dst_addr)

            self.servidor.rede.enviar(segmento, dst_addr)

            self.seq_no += len(payload)

            self.timer = asyncio.get_event_loop().call_later(
                self.TimeoutInterval, self.timeout
            )
            self.timer_ativo = True

            self.not_check.append([segmento, dst_addr, time.time()])

        self.window_ocupation += self.window
        self.dados_restantes = bytearray()
        self.dados_restantes.extend(buffer)

    # timeout function
    def timeout(self):

        if self.not_check:

            self.window = self.window - self.window // 2

            segmento = self.not_check[0][0]
            dst_addr = self.not_check[0][1]
            self.servidor.rede.enviar(segmento, dst_addr)

            self.timer = asyncio.get_event_loop().call_later(
                self.TimeoutInterval, self.timeout
            )
            self.timer_ativo = True

            self.not_check[0][2] = None

    # interval function
    def intervalo_timeout_function(self, tempo_recepcao_ack):

        tempo_envio_seq = self.not_check[0][2]

        if tempo_envio_seq:
            self.SampleRTT = tempo_recepcao_ack - tempo_envio_seq
        else:
            return False

        if self.EstimatedRTT is None:
            self.DevRTT = self.SampleRTT / 2
            self.EstimatedRTT = self.SampleRTT
        else:

            self.EstimatedRTT = (
                1 - self.alpha
            ) * self.EstimatedRTT + self.alpha * self.SampleRTT
            self.DevRTT = (1 - self.beta) * self.DevRTT + self.beta * abs(
                self.SampleRTT - self.EstimatedRTT
            )

        self.TimeoutInterval = self.EstimatedRTT + 4 * self.DevRTT
        return True

    # fechamento
    def fechar(self):

        (dst_addr, dst_port, src_addr, src_port) = self.id_conexao
        header = make_header(src_port, dst_port, self.seq_no, self.ack_no, FLAGS_FIN)
        segmento = fix_checksum(header, src_addr, dst_addr)

        self.servidor.rede.enviar(segmento, dst_addr)

        # self.callback(self, b"")

        del self.servidor.conexoes[self.id_conexao]
