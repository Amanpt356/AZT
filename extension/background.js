let temporaryAllow = {};
let domainCache = {};
let cacheTTL = 60 * 1000;

chrome.runtime.onMessage.addListener((message)=>{

    if(message.type === "TEMP_ALLOW"){
        temporaryAllow[message.domain] = true;
    }

});


chrome.webNavigation.onBeforeNavigate.addListener(async function(details){

    if(details.frameId !== 0) return;

    let url = details.url;

    if(
        url.startsWith("chrome://") ||
        url.startsWith("chrome-extension://") ||
        url.startsWith("edge://")
    ){
        return;
    }

    let domain;

    try{
        domain = new URL(url).hostname;
    }catch{
        return;
    }

    if(temporaryAllow[domain]){
        delete temporaryAllow[domain];
        return;
    }


    if(domainCache[domain]){

        if(domainCache[domain].decision === "BLOCK"){

            let blockPage = chrome.runtime.getURL(
                `block.html?domain=${domain}&url=${encodeURIComponent(url)}&reason=${domainCache[domain].reason}`
            );

            chrome.tabs.update(details.tabId,{url:blockPage});
        }

        return;
    }


    let response = await fetch("http://127.0.0.1:8000/check_url",{

        method:"POST",

        headers:{
            "Content-Type":"application/json"
        },

        body:JSON.stringify({
            url:url,
            browser:"chrome"
        })

    });

    let result = await response.json();

    domainCache[domain] = result;

    if(result.decision === "BLOCK"){

        let blockPage = chrome.runtime.getURL(
            `block.html?domain=${domain}&url=${encodeURIComponent(url)}&reason=${result.reason}`
        );

        chrome.tabs.update(details.tabId,{url:blockPage});
    }

});