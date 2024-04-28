const ws = true;
let socket = null;

function initWS() {
    // Establish a WebSocket connection with the server
    socket = new WebSocket('ws://' + window.location.host + '/websocket');

    // Called whenever data is received from the server over the WebSocket connection
    socket.onmessage = function (ws_message) {
        const message = JSON.parse(ws_message.data);
        const messageType = message.messageType
        if(messageType === 'chatMessage'){
            addMessageToChat(message);
        } else if (data.messageType === 'userListUpdate') {
            updateUserList(data);
        } else{
            // send message to WebRTC
            processMessageAsWebRTC(message, messageType);
        }
    }
}

function updateUserList(data) {
    const userList = document.getElementById('user-list');
    if (data.action === 'login') {
        const userItem = document.createElement('li');
        userItem.textContent = data.username;
        userItem.id = 'user-' + data.username;
        userList.appendChild(userItem);
    } else if (data.action === 'logout') {
        const userItem = document.getElementById('user-' + data.username);
        if (userItem) {
            userList.removeChild(userItem);
        }
    }
}

function deleteMessage(messageId) {
    const request = new XMLHttpRequest();
    request.onreadystatechange = function () {
        if (this.readyState === 4 && this.status === 200) {
            console.log(this.response);
        }
    }
    request.open("DELETE", "/chat-messages/" + messageId);
    request.send();
}

function chatMessageHTML(messageJSON) {
    const username = messageJSON.username;
    const message = messageJSON.message;
    const messageId = messageJSON.id;
    let messageHTML = "<br><button onclick='deleteMessage(\"" + messageId + "\")'>X</button> ";
    messageHTML += "<span id='message_" + messageId + "'><b>" + username + "</b>: " + message + "</span>";
    return messageHTML;
}

function clearChat() {
    const chatMessages = document.getElementById("chat-messages");
    chatMessages.innerHTML = "";
}

function addMessageToChat(messageJSON) {
    const chatMessages = document.getElementById("chat-messages");
    chatMessages.innerHTML += chatMessageHTML(messageJSON);
    chatMessages.scrollIntoView(false);
    chatMessages.scrollTop = chatMessages.scrollHeight - chatMessages.clientHeight;
}

function sendChat() {
    
    const chatTextBox = document.getElementById("chat-text-box");
    const message = chatTextBox.value;
    chatTextBox.value = "";
    const xsrfToken = document.getElementById('xsrf-token').value;

    if (!ws) {
        const request = new XMLHttpRequest();
        request.onreadystatechange = function () {
            if (this.readyState === 4 && this.status === 200) {
                console.log(this.response);
            }
        }
        const messageJSON = {"message": message, "xsrfToken": xsrfToken};
        request.open("POST", "/chat-messages");
        request.setRequestHeader('Content-Type', 'application/json');
        request.send(JSON.stringify(messageJSON));
    } else {
        socket.send(JSON.stringify({'messageType': 'chatMessage',
                                    'message': message}))
    }
}


function updateChat() {
    const request = new XMLHttpRequest();
    request.onreadystatechange = function () {
        if (this.readyState === 4 && this.status === 200) {
            if (this.status == 200) {
                clearChat();
                const messages = JSON.parse(this.response);
                for (const message of messages) {
                    addMessageToChat(message);
                }
            }
            const delay = (this.status == (200 || 206)) ? 20000 : 5000;
            setTimeout(updateChat, delay);
        }
    }
    request.open("GET", "/chat-messages");
    request.send();
}

function welcome() {
    document.addEventListener("keypress", function (event) {
        if (event.code === "Enter") {
            sendChat();
        }
    });


    document.getElementById("paragraph").innerHTML += "<br/>This text was added by JavaScript 😀";
    document.getElementById("chat-text-box").focus();

    updateChat();

    if (ws) {
        initWS();
    } else {
        const videoElem = document.getElementsByClassName('video-chat')[0];
        videoElem.parentElement.removeChild(videoElem);
        updateChat();
    }

    // use this line to start your video without having to click a button. Helpful for debugging
    // startVideo();
}


function logout() {
    // Create a new request to the logout endpoint
    var xhr = new XMLHttpRequest();
    xhr.open("GET", "/logout", true);  // Assuming the logout is a GET request
    xhr.onload = function() {
        if (xhr.status == 200) {
            // Optionally, redirect to the homepage or login page after successful logout
            window.location.href = '/';
        } else {
            // Handle error (if any)
            console.error("Logout failed:", xhr.responseText);
        }
    };
    xhr.send();
}