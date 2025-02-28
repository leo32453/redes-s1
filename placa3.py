#!/usr/bin/env python3
import asyncio
from camadafisica import ZyboSerialDriver
from tcp import Servidor        # copie o arquivo do T2
from ip import IP               # copie o arquivo do T3
from slip import CamadaEnlace   # copie o arquivo do T4
import re

from textwrap import wrap
import pprint

## Implementação da camada de aplicação

# Este é um exemplo de um programa que faz eco, ou seja, envia de volta para
# o cliente tudo que for recebido em uma conexão.

################################################################
################################################################

apelidos = {}
canais = {}

################################################################
################################################################

def validar_nome(nome):
    return re.match(br'^[a-zA-Z][a-zA-Z0-9_-]*$', nome) is not None

################################################################
################################################################
'''
## Passo 3

Trate mensagens do tipo `NICK`. Verifique se o apelido solicitado é válido usando a função `validar_nome`. Se for inválido, responda com a mensagem de erro 432 (como descrita na seção [Mensagens do protocolo](#mensagens-do-protocolo)). Senão, responda com as mensagens 001 e 422, para indicar sucesso.

## Passo 4

Adicione alguma estrutura de dados (por exemplo, um dicionário) para mapear cada apelido para a conexão correspondente. Quando um usuário pedir para definir um apelido, verifique se esse apelido já está em uso. Se estiver em uso, responda com a mensagem de erro 433 (vide seção [Mensagens do protocolo](#mensagens-do-protocolo)). Implemente também o suporte a trocar de apelido após definido um apelido inicial.

Não esqueça que devemos ignorar maiúsculas / minúsculas quando tratamos apelidos ou nomes de canais. Assim, `ApElido` deve ser considerado duplicado se alguém já estiver usando `apelido`.

:apelido_antigo NICK apelido
'''
def handle_NICK(dados, conexao):
    resposta = []
    nick = dados
    if validar_nome(nick):
        # Verifica se está em uso
        # if nick_lower in apelidos:
        if nick.lower() in list(apelido.lower() for apelido in apelidos.values()):
            resposta.append(b":server 433 " + conexao.apelido_atual + b" " + nick + b" :Nickname is already in use\r\n")
        else:
            if conexao.apelido_atual == b"*": # primeiro nome
                resposta.append(b":server 001 " + nick + b" :Welcome\r\n")
                resposta.append(b":server 422 " + nick + b" :MOTD File is missing\r\n")
            else: # muda nome
                resposta.append(b":" + conexao.apelido_atual + b" NICK " + nick + b"\r\n")
                # print(conexao.apelido_atual + b" muda para " + nick)
                # pprint.pprint(apelidos)
            conexao.apelido_atual = nick
            apelidos[conexao] = nick
    else:
        resposta.append(b":server 432 * " + nick + b" :Erroneous nickname\r\n")
    return resposta
################################################################
################################################################
'''
## Passo 5

Implemente suporte a troca de mensagens entre usuários usando `PRIVMSG`.

O seu código só vai passar no teste se você estiver acompanhando corretamente a troca de apelidos e direcionando as mensagens à conexão correta.

Ignore mensagens enviadas para apelidos que não existem ou que não estão mais em uso.

   * `PRIVMSG destinatário :conteúdo`: Envia uma mensagem de texto para um usuário ou para um canal. O nome de canais começa sempre com `#`, então o servidor consegue distinguir pelo primeiro caractere de `destinatário` se este é um canal ou se é um usuário. O servidor não deve responder nada para o remetente, mas deve enviar a mensagem da seguinte forma para o destinatário: `:remetente PRIVMSG destinatário :conteúdo`

## Passo 6

Implemente o suporte a entrar em canais com `JOIN` e a enviar mensagens para esses canais usando `PRIVMSG`.

Por enquanto, você não precisa enviar a lista de membros do canal (mensagens 353 e 366).

Não esqueça que devemos ignorar maiúsculas / minúsculas quando tratamos apelidos ou nomes de canais. Assim, `#cAnaL` deve ser considerado a mesma coisa que `#canal`.

   * `JOIN canal`: Ingressa no canal. O nome do canal deve começar com `#` e os demais caracteres devem seguir as mesmas regras dos nomes de apelidos. Caso o nome do canal seja inválido, responda com `:server 403 canal :No such channel`. Senão:

     * Envie `:apelido JOIN :canal` para o usuário que entrou e para todos os usuários que já estão dentro do canal.

     * Envie `:server 353 apelido = canal :membro1 membro2 membro3` para o usuário que entrou no canal. A lista de membros deve incluir o apelido do usuário que acabou de entrar e deve estar ordenada em ordem alfabética. Se a lista de membros for muito grande, quebre em várias mensagens desse tipo, cada uma com no máximo 512 caracteres (incluindo a terminação `'\r\n'`).

     * Envie `:server 366 apelido canal :End of /NAMES list.` para o usuário que entrou no canal, a fim de sinalizar que todos os pedaços da lista de membros já foram enviados.
'''
def handle_PRIVMSG(dados, conexao):
    # print(dados)
    destinatario, mensagem = dados.split(b" :")
    # print(destinatario + b" + " + mensagem)
    
    if destinatario.startswith(b"#"):
        # se canal existe
        destinatario = destinatario.lower()
        if destinatario.lower() in list(canal.lower() for canal in canais.keys()):
            # manda mensagem
            resposta = b":" + conexao.apelido_atual + b" PRIVMSG " + destinatario + b" :" + mensagem + b"\r\n"
            # print("Resposta:", resposta, "\n")
            # pprint.pprint(canais)
            for usuario in canais[destinatario]:
                # print(usuario)
                # print(conexao)
                # print(canais[dados])
                if conexao != usuario:
                    # print("Resposta:", resposta, "\n")
                    usuario.enviar(resposta)
                # else:
                #     print("same")
                # print("Resposta:", resposta, "\n")
                # usuario.enviar(resposta)
        else:
            print(destinatario, "nao existe")

    else:
        if destinatario.lower() in list(apelido.lower() for apelido in apelidos.values()): # se existe
            # resposta.append(b":" + conexao.apelido_atual + b" PRIVMSG " + destinatario + b" :" + mensagem + b"\r\n")
            comando = b":" + conexao.apelido_atual + b" PRIVMSG " + destinatario + b" :" + mensagem + b"\r\n"
            # get key by value
            (list(apelidos.keys())[list(apelidos.values()).index(destinatario.lower())]).enviar(comando)
            # print("Resposta:", comando, "\n")
        else:
            print(destinatario, "nao existe")
'''
     * Envie `:apelido JOIN :canal` para o usuário que entrou e para todos os usuários que já estão dentro do canal.

     * Envie `:server 353 apelido = canal :membro1 membro2 membro3` para o usuário que entrou no canal. A lista de membros deve incluir o apelido do usuário que acabou de entrar e deve estar ordenada em ordem alfabética. Se a lista de membros for muito grande, quebre em várias mensagens desse tipo, cada uma com no máximo 512 caracteres (incluindo a terminação `'\r\n'`).

     * Envie `:server 366 apelido canal :End of /NAMES list.` para o usuário que entrou no canal, a fim de sinalizar que todos os pedaços da lista de membros já foram enviados.


## Passo 9

Passe a enviar a lista dos membros de um canal (mensagens 353 e 366) quando alguém entrar no canal (`JOIN`).
'''
def handle_JOIN(dados, conexao):
    resposta = ""
    membros = []
    
    if validar_nome(dados[1:]):
        dados = dados.lower()
        # adiciona aos canais
        # se canal existe
        if dados.lower() in list(canal.lower() for canal in canais.keys()):
            canais[dados].update({conexao: conexao.apelido_atual})
        else:
            canais[dados] = {conexao: conexao.apelido_atual}

        # Envie `:apelido JOIN :canal`
        resposta = b":" + conexao.apelido_atual + b" JOIN :" + dados + b"\r\n"
        for usuario in canais[dados]:
            # print("Resposta:", resposta, "\n")
            usuario.enviar(resposta)
            membros.append(apelidos[usuario])
        # print(canais[dados])

        '''
        Envie `:server 353 apelido = canal :membro1 membro2 membro3` para o usuário que entrou no canal
        '''
        # Monta mensagem
        # print("Membros: ", membros)
        membros = sorted(membros)
        resposta = b":server 353 " + conexao.apelido_atual + b" = " + dados + b" :"
        for membro in membros:
            if membro != membros[0]:
                resposta += b" " + membro
            else:
                resposta += membro # primeiro nao tem " "
        # print("Resposta:", resposta)
        # Separa em 508 caracteres + "\r\n"
        resposta_split = wrap(str(resposta, "utf-8"), 508)
        resposta_split = list(bytes(aux,"utf-8") + b"\r\n" for aux in resposta_split)
        # print("Resposta Split:", resposta_split)
        for aux in resposta_split:
            conexao.enviar(aux)

        '''
        * Envie `:server 366 apelido canal :End of /NAMES list.` para o usuário que entrou no canal
        '''
        resposta = b":server 366 " + conexao.apelido_atual + b" " + dados + b" :End of /NAMES list.\r\n"
        conexao.enviar(resposta)

    else:
        # Caso o nome do canal seja inválido, responda com `:server 403 canal :No such channel`
        resposta = b":server 403" + dados  + b" :No such channel\r\n"
        conexao.enviar(resposta)

################################################################
'''
## Passo 7

Implemente o suporte a sair de canais com `PART`.

   * `PART canal`: Sai do canal. Envie `:apelido PART canal` para todos os membros do canal, incluindo o que pediu para sair.
'''
def handle_PART(dados, conexao):
    resposta = ""

    dados = dados.split(b" :")[0] # ignora mensagem de saida PART canal :mensagem de saida
    
    # manda mensagem
    resposta = b":" + conexao.apelido_atual + b" PART " + dados + b"\r\n"
    for usuario in canais[dados]:
        # print("Resposta:", resposta, "\n")
        usuario.enviar(resposta)

    if dados.lower() in list(canal.lower() for canal in canais.keys()):
        canais[dados].pop(conexao)
################################################################
'''
## Passo 8

Quando uma conexão fechar, envie mensagens do tipo `QUIT` para todos os usuários que estiverem em pelo menos um canal em comum com o usuário que fechou a conexão.

Você pode implementar essa funcionalidade na função `sair` do código de exemplo.

* Se um cliente fechar a conexão com o servidor, deve-se avisar todos os outros usuários que estejam em pelo menos um canal em comum com ele, enviando: `:apelido QUIT :Connection closed`

## Passo 10

Certifique-se que, quando um usuário fecha a conexão, você está retirando o nome dele da lista de membros dos canais dos quais ele fazia parte.
'''

def sair(conexao):
    # print("CONEXAO: ", conexao, conexao.apelido_atual)
    peers = []
    # print(canais)
    resposta = b":" + conexao.apelido_atual + b" QUIT :Connection closed\r\n"
    for channel in list(canais.keys()): # canais
        # channel.pop(conexao)
        # print("channel: ",channel)
        # print("canais[channel]: ")
        # pprint.pprint(canais[channel])
        for peer in canais[channel]:
            if (peer not in peers) and (peer != conexao):  
                # print("peer: ",peer)
                peers.append(peer)
                # print("peers: ",peers)
        
        # remove conexao do canal, se existe
        if conexao in canais[channel]:
            canais[channel].pop(conexao)
        # print("canais[channel].pop: ")
        # pprint.pprint(canais[channel])
        # print()

    for peer in peers:
        peer.enviar(resposta)
        # print("Enviado ", resposta, " para ", peer)
    
    # remove apelido, se existe
    # print("apelidos: ")
    # pprint.pprint(apelidos)
    if conexao in apelidos:
        apelidos.pop(conexao)
    # print("apelidos_pop: ")
    # pprint.pprint(apelidos)

    print("\n", conexao, ' - conexão fechada')
    conexao.fechar()
################################################################
'''
 * Uma mensagem do tipo `"linha\r\n"` pode ser quebrada em várias partes. Por exemplo, podemos receber primeiro `"lin"`, depois `"h"` e depois `"a\r\n"`.
    
 * Duas ou mais mensagens podem ser recebidas de uma só vez. Por exemplo, podemos receber `"linha 1\r\nlinha 2\r\nlinha 3\r\n"`.

As duas coisas também podem acontecer ao mesmo tempo. Podemos receber, por exemplo, algo do tipo `"a 1\r\nlinha 2\r\nli"`.
'''

def dados_recebidos(conexao, dados):
    # if dados == b'':
    #     return sair(conexao)
    print(conexao, dados)
    resposta = []
    if dados == b'':
        return sair(conexao)
    
    # print(b"Recebido:" + dados)
    conexao.dados_residuais = conexao.dados_residuais + dados
    # print(b"Comando:" + conexao.dados_residuais)
    # separa comando de dados e \r\n
    conexao.dados_residuais = conexao.dados_residuais.split(b'\r\n')
    for i in range(len(conexao.dados_residuais)-1):
        comando, conexao.dados_residuais[i] = conexao.dados_residuais[i].split(b" ", 1)
        if comando == b"PING":
            # `:server PONG server :payload`
            resposta.append(b":server PONG server :" + conexao.dados_residuais[i] + b"\r\n")
        elif comando == b"NICK":
            resposta = handle_NICK(conexao.dados_residuais[i], conexao)
        elif comando == b"PRIVMSG":
            handle_PRIVMSG(conexao.dados_residuais[i], conexao)
        elif comando == b"JOIN":
            handle_JOIN(conexao.dados_residuais[i], conexao)
        elif comando == b"PART":
            handle_PART(conexao.dados_residuais[i], conexao)
        else:
            print(b"Outro: " + conexao.dados_residuais[i])
    
    for res in resposta:
        # print("Resposta:", res)
        conexao.enviar(res)
    # print()
    # Caso esteja fora de ordem
    if conexao.dados_residuais[-1] == b"":
        # print(conexao.dados_residuais)
        conexao.dados_residuais = b""
    else:
        # print(conexao.dados_residuais)
        conexao.dados_residuais = conexao.dados_residuais[-1]


################################################################
################################################################

def conexao_aceita(conexao):
    print(conexao, 'nova conexão')
    conexao.registrar_recebedor(dados_recebidos)
    conexao.dados_residuais = b""
    conexao.apelido_atual = b"*"



## Integração com as demais camadas

nossa_ponta = '192.168.200.4'
outra_ponta = '192.168.200.3'
porta_tcp = 7000

driver = ZyboSerialDriver()
linha_serial = driver.obter_porta(0)

enlace = CamadaEnlace({outra_ponta: linha_serial})
rede = IP(enlace)
rede.definir_endereco_host(nossa_ponta)
rede.definir_tabela_encaminhamento([
    ('0.0.0.0/0', outra_ponta)
])
servidor = Servidor(rede, porta_tcp)
servidor.registrar_monitor_de_conexoes_aceitas(conexao_aceita)
asyncio.get_event_loop().run_forever()
