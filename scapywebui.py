from flask import Flask, redirect, url_for, request, render_template
from werkzeug.utils import secure_filename
from scapy.all import *

app = Flask(__name__)
# app.config['UPLOAD_FOLDER'] = '/uploads'

@app.route('/uploader', methods = ['POST', 'GET'])
def uploader():
	if request.method == 'POST':
		if 'file' not in request.files:
			flash('No file part')
			return redirect(request.url)
		file = request.files['file']
		if file.filename == '':
			flash('No file selected')
			return redirect(request.url)
		filename = secure_filename(file.filename)
		file.save(filename)
		return redirect(url_for('view', filename = filename))

@app.route('/view/<filename>', methods = ['POST', 'GET'])
def view(filename):
	packets = rdpcap(filename)
	packet = []
	src = ""
	dst = ""
	for i in range(len(packets)):
		ipFrame = packets[i].getlayer(IP)
		tcpFrame = packets[i].getlayer(TCP)
		if request.method == 'POST':
			src = request.form.get("src");
			dst = request.form.get("dst");
			if src:
				if ipFrame and ipFrame.src == src:
					pktDict = {"frame": i, "source": ipFrame.src, "source-port": tcpFrame.sport, "destination": ipFrame.dst, "destination-port": tcpFrame.dport, "seq-no": tcpFrame.seq, "ack-no": tcpFrame.ack, "protocol": ipFrame.proto}
					packet.append(pktDict)
			elif dst:
				if ipFrame and ipFrame.dst == dst:
					pktDict = {"frame": i, "source": ipFrame.src, "source-port": tcpFrame.sport, "destination": ipFrame.dst, "destination-port": tcpFrame.dport, "seq-no": tcpFrame.seq, "ack-no": tcpFrame.ack, "protocol": ipFrame.proto}
					packet.append(pktDict)
			elif src and dst:
				if ipFrame and ipFrame.dst == dst and ipFrame.src == src:
					pktDict = {"frame": i, "source": ipFrame.src, "source-port": tcpFrame.sport, "destination": ipFrame.dst, "destination-port": tcpFrame.dport, "seq-no": tcpFrame.seq, "ack-no": tcpFrame.ack, "protocol": ipFrame.proto}
					packet.append(pktDict)
			else:
				if ipFrame:
					pktDict = {"frame": i, "source": ipFrame.src, "source-port": tcpFrame.sport, "destination": ipFrame.dst, "destination-port": tcpFrame.dport, "seq-no": tcpFrame.seq, "ack-no": tcpFrame.ack, "protocol": ipFrame.proto}
					packet.append(pktDict)
		else:
			if ipFrame:
				pktDict = {"frame": i, "source": ipFrame.src, "source-port": tcpFrame.sport, "destination": ipFrame.dst, "destination-port": tcpFrame.dport, "seq-no": tcpFrame.seq, "ack-no": tcpFrame.ack, "protocol": ipFrame.proto}
				packet.append(pktDict)


	return render_template('view.html', data = packet)

@app.route('/')
def index():
	return render_template('index.html')

if __name__=='__main__':
	app.run(debug = True)
