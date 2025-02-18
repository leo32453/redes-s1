'''
PRÁTICA 4 - REDES
PROFESSOR: Matias
ALUNOS:
    - Gabriel Andreazi Bertho, 790780
    - Guilherme Salvador Escher, 792528
    - Leo Rodrigues Aoki, 801926
    - Lucas Silva Mendes, 800247
    - Sebastião Venâncio Guimarães Neto, 790850
    - 
    -
'''

import traceback

# Definição dos caracteres especiais do protocolo SLIP
SLIP_END = b'\xC0'  # Delimitador de fim de quadro
SLIP_ESC = b'\xDB'  # Byte de escape
SLIP_ESC_END = b'\xDB\xDC'  # Representação escapada de SLIP_END
SLIP_ESC_ESC = b'\xDB\xDD'  # Representação escapada de SLIP_ESC

class CamadaEnlace:
    ignore_checksum = False

    def __init__(self, linhas_seriais):
        """
        Inicializa a camada de enlace, associando cada IP da outra ponta
        a uma linha serial específica.
        """
        self.enlaces = {}
        self.callback = None
        for ip_outra_ponta, linha_serial in linhas_seriais.items():
            enlace = Enlace(linha_serial)
            self.enlaces[ip_outra_ponta] = enlace
            enlace.registrar_recebedor(self._callback)

    def registrar_recebedor(self, callback):
        """Registra uma função callback para processar os datagramas recebidos."""
        self.callback = callback

    def enviar(self, datagrama, next_hop):
        """
        Envia um datagrama para o próximo salto (next_hop).
        Identifica qual enlace utilizar e despacha os dados corretamente.
        """
        self.enlaces[next_hop].enviar(datagrama)

    def _callback(self, datagrama):
        """
        Chama a função de callback quando um datagrama é recebido.
        Encaminha os dados processados para a camada superior.
        """
        if self.callback:
            self.callback(datagrama)

class Enlace:
    def __init__(self, linha_serial):
        """
        Inicializa a camada de enlace para a linha serial fornecida,
        registrando um recebedor de dados.
        """
        self.dados = bytearray()
        self.linha_serial = linha_serial
        self.linha_serial.registrar_recebedor(self.__raw_recv)
        self.callback = None

    def registrar_recebedor(self, callback):
        """
        Registra uma função callback para processar os datagramas recebidos.
        Esse callback será chamado quando um quadro completo for recebido.
        """
        self.callback = callback

    def enviar(self, datagrama):
        """
        Codifica e envia um datagrama usando o protocolo SLIP.
        Insere delimitadores no início e no fim e trata as sequências de escape.
        """
        datagrama_codif = datagrama.replace(SLIP_ESC, SLIP_ESC_ESC).replace(SLIP_END, SLIP_ESC_END)
        quadro = SLIP_END + datagrama_codif + SLIP_END
        self.linha_serial.enviar(quadro)

    def __raw_recv(self, dados):
        """
        Recebe os dados brutos da linha serial e processa quadros SLIP.
        Acumula os dados recebidos e separa quadros completos.
        """
        self.dados.extend(dados)
        
        while SLIP_END in self.dados:
            end = self.dados.index(SLIP_END)  # Encontra o delimitador de fim de quadro
            quadro = self.dados[:end]  # Obtém os dados do quadro
            self.dados = self.dados[end + 1:]  # Remove o quadro processado do buffer

            if len(quadro) == 0:
                continue  # Descarta quadros vazios conforme recomendado pela RFC

            try:
                # Decodifica as sequências de escape no datagrama
                datagrama = quadro.replace(SLIP_ESC_END, SLIP_END).replace(SLIP_ESC_ESC, SLIP_ESC)
                if self.callback:
                    self.callback(datagrama)  # Passa o datagrama processado para a camada superior
            except Exception as e:
                traceback.print_exc()  # Mostra o erro, mas não interrompe a execução
                self.dados.clear()  # Limpa buffer para evitar dados residuais malformados
