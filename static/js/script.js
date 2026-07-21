/*
==========================================================
 ThreatDetect+
 Real-Time Network Threat Detection Dashboard
 PART 3A
==========================================================
*/

"use strict";

document.addEventListener("DOMContentLoaded", () => {

    /*
    =====================================================
        SIDEBAR
    =====================================================
    */

    const sidebar = document.querySelector(".sidebar");
    const sidebarToggle = document.getElementById("sidebarToggle");

    if (sidebarToggle) {

        sidebarToggle.addEventListener("click", () => {

            sidebar.classList.toggle("show");

        });

    }

    /*
    =====================================================
        TOAST
    =====================================================
    */

    const toastContainer = document.getElementById("toastContainer");

    function showToast(title, message, type = "primary") {

        if (!toastContainer) return;

        const id = "toast_" + Date.now();

        toastContainer.insertAdjacentHTML(

            "beforeend",

            `
            <div id="${id}"
                 class="toast align-items-center text-bg-${type} border-0"
                 role="alert">

                <div class="d-flex">

                    <div class="toast-body">

                        <strong>${title}</strong><br>

                        ${message}

                    </div>

                    <button
                        class="btn-close btn-close-white me-2 m-auto"
                        data-bs-dismiss="toast">
                    </button>

                </div>

            </div>
            `

        );

        const toastElement = document.getElementById(id);

        const toast = new bootstrap.Toast(

            toastElement,

            {
                delay:5000
            }

        );

        toast.show();

        toastElement.addEventListener(

            "hidden.bs.toast",

            ()=>toastElement.remove()

        );

    }

    /*
    =====================================================
        COUNTER
    =====================================================
    */

    function animateCounter(element,newValue){

        if(!element) return;

        let current=parseInt(element.textContent)||0;

        let increment=Math.ceil((newValue-current)/20);

        function update(){

            current+=increment;

            if(current>=newValue){

                element.textContent=newValue;

                return;

            }

            element.textContent=current;

            requestAnimationFrame(update);

        }

        update();

    }

    /*
    =====================================================
        HELPERS
    =====================================================
    */

    function badgeColor(level){

        switch(level){

            case "Critical":

                return "danger";

            case "High":

                return "warning";

            case "Medium":

                return "info";

            default:

                return "success";

        }

    }

    function timeNow(){

        return new Date().toLocaleTimeString();

    }

    /*
    =====================================================
        CHART
    =====================================================
    */

    const chartCanvas=document.getElementById("trafficChart");

    const labelScript=document.getElementById("packet-labels");

    const valueScript=document.getElementById("packet-values");

    let trafficChart=null;

    if(chartCanvas && labelScript && valueScript){

        const labels=JSON.parse(labelScript.textContent);

        const values=JSON.parse(valueScript.textContent);

        trafficChart=new Chart(chartCanvas,{

            type:"line",

            data:{

                labels:labels,

                datasets:[{

                    label:"Captured Packets",

                    data:values,

                    fill:true,

                    borderWidth:3,

                    tension:.35,

                    pointRadius:3,

                    pointHoverRadius:6,

                }]

            },

            options:{

                responsive:true,

                maintainAspectRatio:false,

                interaction:{

                    intersect:false,

                    mode:"index"

                },

                plugins:{

                    legend:{

                        labels:{

                            color:"#eef4ff"

                        }

                    }

                },

                scales:{

                    x:{

                        ticks:{

                            color:"#9fb3ca"

                        },

                        grid:{

                            color:"rgba(255,255,255,.05)"

                        }

                    },

                    y:{

                        beginAtZero:true,

                        ticks:{

                            color:"#9fb3ca"

                        },

                        grid:{

                            color:"rgba(255,255,255,.05)"

                        }

                    }

                }

            }

        });

    }

    /*
    =====================================================
        TABLE HELPERS
    =====================================================
    */

    function prependPacket(data){

        const body=document.getElementById("packet-table-body");

        if(!body) return;

        if(body.querySelector(".text-muted")){

            body.innerHTML="";

        }

        body.insertAdjacentHTML(

            "afterbegin",

            `
            <tr>

                <td>${data.time}</td>

                <td>${data.source_ip}</td>

                <td>${data.destination_ip}</td>

                <td>

                    <span class="badge bg-info">

                        ${data.protocol}

                    </span>

                </td>

                <td>${data.length || "-"}</td>

                <td>${data.direction || "-"}</td>

            </tr>

            `

        );

        while(body.children.length>10){

            body.removeChild(body.lastElementChild);

        }

    }

    function prependThreat(data){

        const body=document.getElementById("threat-table-body");

        if(!body) return;

        if(body.querySelector(".text-muted")){

            body.innerHTML="";

        }

        body.insertAdjacentHTML(

            "afterbegin",

            `
            <tr>

                <td>${data.time}</td>

                <td>${data.name}</td>

                <td>

                    <span class="badge bg-${badgeColor(data.severity)}">

                        ${data.severity}

                    </span>

                </td>

                <td>

                    <span class="badge bg-dark">

                        New

                    </span>

                </td>

                <td>${data.message}</td>

            </tr>

            `

        );

        while(body.children.length>10){

            body.removeChild(body.lastElementChild);

        }

    }

/*
==========================================================
    PART 3B
    WEBSOCKET LIVE ENGINE
==========================================================
*/

let socket = null;

function connectWebSocket(){

    const protocol =
        window.location.protocol === "https:"
            ? "wss"
            : "ws";

    socket = new WebSocket(

        `${protocol}://${window.location.host}/ws/dashboard/`

    );

    /*
    =====================================
        CONNECTED
    =====================================
    */

    socket.onopen = function(){

        console.log("Dashboard Connected");

        showToast(

            "Connected",

            "Real-time monitoring started.",

            "success"

        );

    };



    /*
    =====================================
        RECEIVE DATA
    =====================================
    */

    socket.onmessage = function(event){

        const data = JSON.parse(event.data);

        console.log(data);

        /*
        -----------------------
            COUNTERS
        -----------------------
        */

        if(data.total_packets !== undefined){

            animateCounter(

                document.getElementById("totalPackets"),

                data.total_packets

            );

        }

        if(data.total_threats !== undefined){

            animateCounter(

                document.getElementById("totalThreats"),

                data.total_threats

            );

        }

        if(data.total_alerts !== undefined){

            animateCounter(

                document.getElementById("totalAlerts"),

                data.total_alerts

            );

        }

        /*
        -----------------------
            NEW PACKET
        -----------------------
        */

        if(data.event==="packet"){

            prependPacket({

                time:data.time || timeNow(),

                source_ip:data.source_ip,

                destination_ip:data.destination_ip,

                protocol:data.protocol,

                length:data.packet_length,

                direction:data.direction

            });

            addEvent(

                "packet",

                "Packet Captured",

                `${data.source_ip} → ${data.destination_ip}`

            );

            updateTrafficChart();

        }

        /*
        -----------------------
            THREAT
        -----------------------
        */

        if(data.event==="threat"){

            prependThreat({

                time:data.time || timeNow(),

                name:data.name,

                severity:data.severity,

                message:data.message

            });

            addEvent(

                "threat",

                data.name,

                data.message

            );

            showToast(

                "Threat Detected",

                data.name,

                data.severity==="Critical"

                ? "danger"

                : "warning"

            );

        }

        /*
        -----------------------
            STATUS
        -----------------------
        */

        if(data.system_status){

            const el=document.getElementById("systemStatus");

            if(el){

                el.innerHTML=data.system_status;

            }

        }

    };



    /*
    =====================================
        CLOSED
    =====================================
    */

    socket.onclose=function(){

        console.log("Disconnected");

        showToast(

            "Disconnected",

            "Reconnecting...",

            "warning"

        );

        setTimeout(

            connectWebSocket,

            3000

        );

    };



    /*
    =====================================
        ERROR
    =====================================
    */

    socket.onerror=function(){

        console.log("Socket Error");

    };

}


/*
==========================================================
EVENT FEED
==========================================================
*/

function addEvent(type,title,message){

    const feed=document.getElementById("eventFeed");

    if(!feed) return;

    const item=document.createElement("div");

    item.className="event-item";

    item.innerHTML=`

        <span class="event-dot ${type}"></span>

        <div>

            <strong>${title}</strong>

            <p class="mb-0">${message}</p>

        </div>

    `;

    feed.prepend(item);

    while(feed.children.length>15){

        feed.removeChild(feed.lastElementChild);

    }

}


/*
==========================================================
TRAFFIC CHART
==========================================================
*/

function updateTrafficChart(){

    if(!trafficChart) return;

    const dataset=trafficChart.data.datasets[0];

    dataset.data.push(

        Math.floor(

            Math.random()*25

        )+5

    );

    trafficChart.data.labels.push(

        timeNow()

    );

    if(dataset.data.length>12){

        dataset.data.shift();

        trafficChart.data.labels.shift();

    }

    trafficChart.update();

}


/*
==========================================================
START
==========================================================
*/

connectWebSocket();

/*
==========================================================
PART 3C
ADVANCED LIVE FEATURES
==========================================================
*/


/*
==========================================================
SYSTEM STATUS
==========================================================
*/

function updateStatus(status){

    const statusBadge=document.getElementById("systemStatus");

    if(statusBadge){

        statusBadge.innerHTML=status;

    }

}


/*
==========================================================
PACKET RATE
==========================================================
*/

let packetRate=0;

setInterval(function(){

    const el=document.getElementById("packetRate");

    if(el){

        el.innerHTML=packetRate+" pkt/s";

    }

    packetRate=0;

},1000);



/*
==========================================================
NETWORK HEALTH
==========================================================
*/

function updateHealth(){

    const cpu=document.getElementById("cpuUsage");

    const ram=document.getElementById("ramUsage");

    const network=document.getElementById("networkUsage");

    if(cpu){

        cpu.innerHTML=Math.floor(Math.random()*15+30)+"%";

    }

    if(ram){

        ram.innerHTML=Math.floor(Math.random()*20+40)+"%";

    }

    if(network){

        network.innerHTML=Math.floor(Math.random()*20+60)+" Mbps";

    }

}

setInterval(updateHealth,5000);



/*
==========================================================
CLOCK
==========================================================
*/

function updateClock(){

    const clock=document.getElementById("dashboardClock");

    if(clock){

        clock.innerHTML=new Date().toLocaleString();

    }

}

setInterval(updateClock,1000);

updateClock();



/*
==========================================================
ALERT SOUND
==========================================================
*/

const criticalAudio=new Audio(

"/static/audio/alert.mp3"

);

function playCriticalSound(){

    criticalAudio.currentTime=0;

    criticalAudio.play().catch(()=>{});

}



/*
==========================================================
THREAT LEVEL
==========================================================
*/

function updateThreatLevel(level){

    const levelBox=document.getElementById("threatLevel");

    if(!levelBox) return;

    levelBox.className="";

    if(level==="Critical"){

        levelBox.classList.add("text-danger");

        playCriticalSound();

    }

    else if(level==="High"){

        levelBox.classList.add("text-warning");

    }

    else{

        levelBox.classList.add("text-success");

    }

    levelBox.innerHTML=level;

}



/*
==========================================================
LIVE COUNTERS
==========================================================
*/

function increasePacketRate(){

    packetRate++;

}



/*
==========================================================
CONNECTION CHECK
==========================================================
*/

setInterval(function(){

    if(socket){

        if(socket.readyState===1){

            updateStatus("Online");

        }

        else{

            updateStatus("Offline");

        }

    }

},2000);



/*
==========================================================
NETWORK ANIMATION
==========================================================
*/

setInterval(function(){

    const cards=document.querySelectorAll(".metric-card");

    cards.forEach(function(card){

        card.classList.add("shadow");

        setTimeout(function(){

            card.classList.remove("shadow");

        },600);

    });

},12000);



/*
==========================================================
WINDOW FOCUS
==========================================================
*/

window.addEventListener("focus",function(){

    console.log("Dashboard Active");

});

window.addEventListener("blur",function(){

    console.log("Dashboard Inactive");

});



/*
==========================================================
KEYBOARD SHORTCUTS
==========================================================
*/

document.addEventListener("keydown",function(e){

    if(e.key==="F5"){

        return;

    }

    if(e.ctrlKey && e.key==="r"){

        e.preventDefault();

        connectWebSocket();

    }

});



/*
==========================================================
AUTO REFRESH CHART
==========================================================
*/

setInterval(function(){

    if(trafficChart){

        trafficChart.update();

    }

},10000);



/*
==========================================================
PERFORMANCE LOG
==========================================================
*/

setInterval(function(){

    console.log(

        "Packets:",

        document.getElementById("totalPackets")?.innerHTML,

        "Threats:",

        document.getElementById("totalThreats")?.innerHTML

    );

},30000);



/*
==========================================================
END
==========================================================
*/

console.log(

"ThreatDetect+ Dashboard Loaded Successfully"

);

});