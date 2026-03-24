const params = new URLSearchParams(window.location.search);

const domain = params.get("domain");
const originalURL = params.get("url");
const reason = params.get("reason");

document.getElementById("domainName").textContent = domain;

const proceedBtn = document.getElementById("proceedBtn");
const backBtn = document.getElementById("backBtn");


/* Hide override if malicious */

if(reason !== "manual"){
    proceedBtn.style.display = "none";
}


/* RETURN TO SAFETY */

backBtn.addEventListener("click", () => {

    chrome.tabs.query({active:true,currentWindow:true}, function(tabs){

        chrome.tabs.update(tabs[0].id, {
            url: "chrome://newtab/"
        });

    });

});


/* PROCEED ANYWAY */

proceedBtn.addEventListener("click", () => {

    chrome.runtime.sendMessage({
        type:"TEMP_ALLOW",
        domain:domain
    });

    chrome.tabs.query({active:true,currentWindow:true}, function(tabs){

        chrome.tabs.update(tabs[0].id,{
            url: originalURL
        });

    });

});