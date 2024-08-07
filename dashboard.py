# Imports
import dash
from dash import dcc
from dash import html
import dash_bootstrap_components as dbc
from dash.dependencies import Output, Input, State
from datetime import datetime, timedelta
import subprocess
import threading
import logging
import plotly.graph_objs as go


# Initialization
app = dash.Dash(__name__, external_stylesheets=[dbc.themes.BOOTSTRAP])
logging.basicConfig(level=logging.DEBUG)


"""
Definitions
"""
# Define paths and container names
container_names = {
    'amf': 'oai-amf',
    'upf': 'oai-upf',
    'smf': 'oai-smf',
}

packet_counts = {
    'amf': [],
    'upf': [],
    'smf': [],
}

packet_history = {
    'amf': [],
    'upf': [],
    'smf': [],
}

elapsed_time = {
    'amf': 0,
    'upf': 0,
    'smf': 0,
}

recording_state = {
    'amf': False,
    'upf': False,
    'smf': False,
}

interface = 'eth0'
lock = threading.Lock()

local_pcap_path = '/home/jourdan/Desktop/'
container_pcap_path = '/tmp/'

"""
Frontend
"""
def create_card(title, start_id, stop_id, graph_id, interval_id):
    """
    Helper function to create a card component for the dashboard
    Each card includes buttons to start and stop recording, and a graph to display packet counts
    """
    return dbc.Card(
        dbc.CardBody(
            [
                html.H4(title, className='card-title'),
                html.Div(
                    [
                        html.Button('Start Recording', id=start_id, className='btn btn-success mr-2'),
                        html.Button('Stop Recording', id=stop_id, className='btn btn-danger', disabled=True),
                        dbc.Tooltip('Start recording network traffic', target=start_id),
                        dbc.Tooltip('Stop recording network traffic', target=stop_id),
                    ],
                    className='text-center mb-2'
                ),
                dcc.Graph(id=graph_id),
                dcc.Interval(id=interval_id, interval=1*1000, n_intervals=0),
            ]
        ),
        className='mb-4'
    )

# Layout
app.layout = dbc.Container(
    [
        dbc.Row(
            dbc.Col(
                html.Div([
                    html.H1('Traffic Monitoring Dashboard', className='text-center'),
                ]),
                width=12
            ),
            className='mb-4'
        ),
        dbc.Row(
            [
                dbc.Col(
                    create_card('OAI-AMF', 'amf-start', 'amf-stop', 'amf-graph', 'amf-interval'),
                    width=12
                ),
                dbc.Col(
                    create_card('OAI-UPF', 'upf-start', 'upf-stop', 'upf-graph', 'upf-interval'),
                    width=12
                ),
                dbc.Col(
                    create_card('OAI-SMF', 'smf-start', 'smf-stop', 'smf-graph', 'smf-interval'),
                    width=12
                )
            ]
        ),
        html.Footer(
            dbc.Row(
                dbc.Col(
                    html.Div([
                        html.P('Jourdan, 2102516'),
                    ]),
                    className='text-center'
                )
            ),
            className='mt-4'
        )
    ],
    fluid=True
)


"""
Backend
"""
def check_and_install_tcpdump(container_name):
    """
    Check if tcpdump is installed in the container
    """
    try:
        check_command = f"docker exec {container_name} which tcpdump"
        result = subprocess.run(check_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode != 0:
            install_command = f"docker exec {container_name} bash -c 'apt-get update && apt-get install -y tcpdump'"
            subprocess.call(install_command, shell=True)
            logging.info(f"Installed tcpdump in container: {container_name}")
        else:
            logging.info(f"tcpdump already installed in container: {container_name}")
    except Exception as e:
        logging.error(f"Error checking/installing tcpdump in container {container_name}: {e}")

def read_tcpdump(container_key, container_name):
    """
    Run tcpdump in the container and read the output in real-time
    Update packet_counts dictionary with timestamps of captured packets
    """
    command = f"docker exec {container_name} tcpdump -l -i {interface} -nn -tt"
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    while process.poll() is None:
        output = process.stdout.readline()
        if output:
            with lock:
                packet_counts[container_key].append(datetime.now())
        logging.debug(f"{container_key}: Captured packet at {datetime.now()}")

def save_pcap(container_key):
    """
    Save tcpdump output to a .pcap file within the container
    """
    container_name = container_names[container_key]
    file_name = f"{container_key}_capture.pcap"
    
    # Remove existing file if it exists
    remove_command = f"docker exec {container_name} rm -f {container_pcap_path}{file_name}"
    subprocess.call(remove_command, shell=True)
    
    save_command = f"docker exec {container_name} tcpdump -i {interface} -w {container_pcap_path}{file_name}"
    subprocess.Popen(save_command, shell=True)

def copy_pcap_to_local(container_name, file_name):
    """
    Copy the .pcap file from the container to the local machine
    """
    local_path = local_pcap_path + file_name
    container_path = container_pcap_path + file_name
    command = f"docker cp {container_name}:{container_path} {local_path}"
    subprocess.call(command, shell=True)
    logging.info(f"Copied {file_name} to local path: {local_path}")

def start_tcpdump(container_key):
    container_name = container_names[container_key]
    check_and_install_tcpdump(container_name)
    logging.info(f"Starting tcpdump for container: {container_name}")
    
    save_pcap(container_key)
    
    recording_state[container_key] = True
    threading.Thread(target=read_tcpdump, args=(container_key, container_name)).start()

def stop_tcpdump(container_key):
    container_name = container_names[container_key]
    file_name = f"{container_key}_capture.pcap"
    logging.info(f"Stopping tcpdump for container: {container_name}")
    command = f"docker exec {container_name} pkill tcpdump"
    subprocess.call(command, shell=True)
    recording_state[container_key] = False
    copy_pcap_to_local(container_name, file_name)

# Callbacks to handle start/stop button state for AMF, UPF, and SMF
@app.callback(
    [Output('amf-start', 'disabled'), Output('amf-stop', 'disabled')],
    [Input('amf-start', 'n_clicks'), Input('amf-stop', 'n_clicks')],
    [State('amf-start', 'disabled'), State('amf-stop', 'disabled')]
)
def amf_buttons(start_clicks, stop_clicks, start_disabled, stop_disabled):
    if start_clicks and not start_disabled:
        start_tcpdump('amf')
        return True, False
    
    if stop_clicks and not stop_disabled:
        stop_tcpdump('amf')
        return False, True
    
    return start_disabled, stop_disabled

@app.callback(
    [Output('upf-start', 'disabled'), Output('upf-stop', 'disabled')],
    [Input('upf-start', 'n_clicks'), Input('upf-stop', 'n_clicks')],
    [State('upf-start', 'disabled'), State('upf-stop', 'disabled')]
)
def upf_buttons(start_clicks, stop_clicks, start_disabled, stop_disabled):
    if start_clicks and not start_disabled:
        start_tcpdump('upf')
        return True, False
    
    if stop_clicks and not stop_disabled:
        stop_tcpdump('upf')
        return False, True
    
    return start_disabled, stop_disabled

@app.callback(
    [Output('smf-start', 'disabled'), Output('smf-stop', 'disabled')],
    [Input('smf-start', 'n_clicks'), Input('smf-stop', 'n_clicks')],
    [State('smf-start', 'disabled'), State('smf-stop', 'disabled')]
)
def smf_buttons(start_clicks, stop_clicks, start_disabled, stop_disabled):
    if start_clicks and not start_disabled:
        start_tcpdump('smf')
        return True, False
    
    if stop_clicks and not stop_disabled:
        stop_tcpdump('smf')
        return False, True
    
    return start_disabled, stop_disabled


"""
Graphs
"""
def update_packet_history(container_key):
    """
    Update packet history for the specified container
    """
    current_time = datetime.now()
    with lock:
        recent_packets = [t for t in packet_counts[container_key] if t > current_time - timedelta(seconds=1)]
        packet_counts[container_key] = recent_packets
        packet_history[container_key].append(len(recent_packets))
        elapsed_time[container_key] += 1

        logging.debug(f"{container_key}: Updated packet history at {current_time}")

# Callbacks to update the graph for AMF, UPF, and SMF
@app.callback(
    Output('amf-graph', 'figure'),
    [Input('amf-interval', 'n_intervals')]
)
def update_amf_graph(n):
    if recording_state['amf']:
        update_packet_history('amf')
    
    with lock:
        y_data = packet_history['amf']
        x_data = list(range(len(y_data)))

    figure = {
        'data': [
            go.Scatter(
                x=x_data, 
                y=y_data, 
                mode='lines', 
                name='AMF Packets'
            )
        ],
        'layout': go.Layout(
            title='AMF Packets',
            xaxis={'title': 'Time(s)', 'rangemode': 'nonnegative'},
            yaxis={'title': 'Packets/s', 'rangemode': 'nonnegative'},
        )
    }

    return figure

@app.callback(
    Output('upf-graph', 'figure'),
    [Input('upf-interval', 'n_intervals')]
)
def update_upf_graph(n):
    if recording_state['upf']:
        update_packet_history('upf')
    
    with lock:
        y_data = packet_history['upf']
        x_data = list(range(len(y_data)))

    figure = {
        'data': [
            go.Scatter(
                x=x_data, 
                y=y_data, 
                mode='lines', 
                name='UPF Packets'
            )
        ],
        'layout': go.Layout(
            title='UPF Packets',
            xaxis={'title': 'Time(s)', 'rangemode': 'nonnegative'},
            yaxis={'title': 'Packets/s', 'rangemode': 'nonnegative'},
        )
    }

    return figure

@app.callback(
    Output('smf-graph', 'figure'),
    [Input('smf-interval', 'n_intervals')]
)
def update_smf_graph(n):
    if recording_state['smf']:
        update_packet_history('smf')
    
    with lock:
        y_data = packet_history['smf']
        x_data = list(range(len(y_data)))

    figure = {
        'data': [
            go.Scatter(
                x=x_data, 
                y=y_data, 
                mode='lines', 
                name='SMF Packets'
            )
        ],
        'layout': go.Layout(
            title='SMF Packets',
            xaxis={'title': 'Time(s)', 'rangemode': 'nonnegative'},
            yaxis={'title': 'Packets/s', 'rangemode': 'nonnegative'},
        )
    }

    return figure

if __name__ == '__main__':
    app.run_server(debug=True)
