
chrome.webRequest.onBeforeRequest.addListener(
    
    function(details) {
        if(!enabled){
	        return { cancel: false };
        }

        console.log("I am going to block:", details.url)
        return {cancel: true};
    },
    {urls: blocked_sites},
    ["blocking"]
    
    
)

// css 기반 광고 차단
chrome.runtime.onMessage.addListener((b,a)=>
{chrome.tabs.insertCSS(a.tab.id,
    {code:":is(img,line):not(:root *):not(["+b+"]):not(["+b+"] *):not(["+b+"] ~ * *){clip-path:polygon(0% 0%,0% 100%,0.00001% 100%,0.00001% 0.00001%,99.9999% 0.00001%,99.9999% 99.9999%,0.00001% 99.9999%,0.00001% 100%,100% 100%,100% 0%)!important}",
    cssOrigin:"user",frameId:a.frameId,runAt:"document_start"})});
