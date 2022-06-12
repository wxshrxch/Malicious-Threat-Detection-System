window.onload = function() {
    function updateLabel() {
        var enabled = chrome.extension.getBackgroundPage().enabled;
        document.getElementById("toggle_button").value = enabled ? "ON" : "OFF";
    }
    var count = document.getElementById("toggle_button").value;

    document.getElementById('toggle_button').onclick = function() {
        var background = chrome.extension.getBackgroundPage();
        background.enabled = !background.enabled;


        updateLabel();
    };

    updateLabel();
    var count = document.getElementById("toggle_button").value;
    if (count == "ON") {
        document.getElementById("toggle_button").checked = true;
    } else {
        document.getElementById("toggle_button").checked = false;
    }

}