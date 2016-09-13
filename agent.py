import sys
import time
import random
from socketIO_client import SocketIO
from indra.assemblers.sbgn_assembler import SBGNAssembler
from indra import trips
from indra import reach
from indra.preassembler import Preassembler
from indra.preassembler.hierarchy_manager import hierarchies
from indra.mechlinker import MechLinker
from indra.tools import mechlinker_queries
from indra.preassembler import grounding_mapper as gm

USER_ID_LEN = 32

current_users = []
last_seen_msg_id = None

# The current model, as a list of INDRA statements
stmts = []

def ack_subscribe_agent(user_list):
    on_user_list(user_list)

def on_user_list(user_list):
    global current_users
    current_users = user_list
    print 'Users:', ', '.join(x['userName'] for x in current_users)

def on_message(data):
    global last_seen_msg_id
    global stmts
    if isinstance(data, dict) and data['id'] != last_seen_msg_id:
        last_seen_msg_id = data['id']
        if {'id': user_id} in data['targets']:
            if data['comment'].startswith('indra:'):
                text = data['comment'][6:].strip()
                if text.strip().lower() in ['start over', 'cls', 'clear']:
                    clear_model(data['userName'])
                elif text.strip().lower().startswith('read'):
                    pmcid = text[4:].strip()
                    update_model_from_paper(pmcid, data['userName'])
                elif text.strip().lower().startswith('remove'):
                    remove_arg = text[6:].strip()
                    if len(remove_arg.split(' ')) == 1:
                        remove_agent(remove_arg, data['userName'])
                        print "Remove agent:", remove_arg
                    else:
                        #remove_mechanism(remove_arg)
                        print "Remove mechanism:", remove_arg
                else:
                    update_model_from_text(text, data['userName'])
            if data['comment'] == 'biopax':
                print 'BIOPAX'
                call_biopax()
            print '<%s> %s' % (data['userName'], data['comment'])

def call_biopax():
    global stmts
    sa = SBGNAssembler()
    sa.add_statements(stmts)
    sbgn_content = sa.make_model()
    print 'BIOPAX CALLED'
    socket.emit('BioPAXRequest', sbgn_content, 'partialBiopax')

def clear_model(user_name=None):
    global stmts
    stmts = []
    if user_name:
        say('OK %s, starting a new model.' % user_name)
    params = {'room': room_id, 'userId': user_id}
    socket.emit('agentNewFileRequest', params)
    socket.emit('agentRunLayoutRequest', params)

def remove_agent(agent_name, user_name):
    global stmts
    stmts = [stmt for stmt in stmts if agent_name not in
                            [ag.name for ag in stmt.agent_list()]]
    update_model(stmts, user_name)

def update_layout():
    sa = SBGNAssembler()
    sa.add_statements(stmts)
    sbgn_content = sa.make_model()
    #params = {'room': room_id, 'userId': user_id,
    #          'graph': sbgn_content, 'type': 'sbgn'}
    #socket.emit('agentMergeGraphRequest', params)
    params = {'room': room_id, 'userId': user_id}
    socket.emit('agentNewFileRequest', params)
    sbgn_params = {'graph': sbgn_content, 'type': 'sbgn'}
    sbgn_params.update(params)
    #socket.emit('agentLoadFileRequest', sbgn_params)
    #socket.emit('agentRunLayoutRequest', sbgn_params)
    socket.emit('agentMergeGraphRequest', sbgn_params)

def update_model_from_paper(pmcid, requester_name):
    say("%s: Got it. Reading %s via INDRA. " \
        "This usually takes about a minute." % (requester_name, pmcid))
    rp = reach.process_pmc(pmcid)
    if rp is None:
        say('Sorry, there was a problem reading that paper.')
    elif not rp.statements:
        say("Sorry, I couldn't find any mechanisms in that paper.")
    else:
        update_model(rp.statements, requester_name)

def update_model_from_text(text, requester_name):
    say("%s: Got it. Assembling model..." % requester_name)
    tp = trips.process_text(text)
    update_model(tp.statements, requester_name)

def update_model(new_stmts, requester_name):
    global stmts
    stmts += new_stmts
    # Performing grounding mapping on the statements
    gmapper = gm.GroundingMapper(gm.default_grounding_map)
    stmts = gmapper.map_agents(stmts)
    pa = Preassembler(hierarchies, stmts)
    pa.combine_related()
    stmts = pa.related_stmts
    ml = MechLinker(stmts)
    linked_stmts = ml.link_statements()
    if linked_stmts:
        for linked_stmt in linked_stmts:
            if linked_stmt.inferred_stmt:
                question = mechlinker_queries.print_linked_stmt(linked_stmt)
                say(question)
                stmts.append(linked_stmt.inferred_stmt)
    say("%s: Done, updating layout." % requester_name)
    update_layout()

def say(text):
    msg = {'room': room_id, 'comment': text, 'userName': user_name,
           'userId': user_id, 'time': 1,
           'targets': [{'id': user['userId']} for user in current_users],
           }
    socket.emit('agentMessage', msg, lambda: None)


_id_symbols = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890'
def generate_id(length, symbols=_id_symbols):
    n = len(symbols)
    symbol_gen = (symbols[random.randrange(0, n)] for i in range(length))
    return ''.join(symbol_gen)

if len(sys.argv) == 1:
    print "Usage: agent.py <room_id>"
    sys.exit(1)
else:
    room_id = sys.argv[1]

user_name = 'INDRA'
user_id = generate_id(USER_ID_LEN)

socket = SocketIO('localhost', 3000)
sa_payload = {'userName': user_name,
              'room': room_id,
              'userId': user_id}
socket.on('message', on_message)
socket.on('userList', on_user_list)
socket.emit('subscribeAgent', sa_payload, ack_subscribe_agent)

try:
    socket.wait()
except KeyboardInterrupt:
    pass
print "Disconnecting..."
socket.emit('disconnect')
socket.disconnect()
