function getCurrentTabURL(callback) {
    var queryInfo = {
        active: true,
        currentWindow: true
    };
    chrome.tabs.query(queryInfo, function(tabs) {
        var tab = tabs[0];
        var url = tab.url;
        callback(url);
    })
}

function renderURL(statusText) {
    document.getElementById("i_result").innerHTML = statusText;
}

document.addEventListener('DOMContentLoaded', function() {
    chrome.tabs.executeScript(
        function(result) {
            getCurrentTabURL(function(url) {
                renderURL(url);
            });
        }
    )
});

//css 기반 광고 차단
var a;
let b = new Uint8Array(32);
crypto.getRandomValues(b);
a = String.fromCharCode(...b.map(function(d) { return (26 * d >> 8) + 97 }));
chrome.runtime.sendMessage(a);
const c = document.createElement("script");
c.textContent = "(function(){'use strict';var f=Object.defineProperty,g=Object.getOwnPropertyDescriptor,aa=Object.getPrototypeOf,ba=Object.create,ca=Object.getOwnPropertyNames,da=Object.getOwnPropertySymbols,ea=Object.prototype.hasOwnProperty,h=Function.prototype.call,fa=Function.prototype.bind,l=Reflect.apply,n=String,ha=n.prototype.toLowerCase,ia=h.bind(n.prototype.replaceAll),p=Number,ja=Symbol.iterator;const q=Array.prototype;\n\
var ka=h.bind(q.push),la=h.bind(q.indexOf),r=h.bind(q.splice),ma=q.values,u=Error.captureStackTrace,na=setTimeout,oa=clearTimeout,pa=requestAnimationFrame,qa=cancelAnimationFrame,ra=WeakMap;const sa=ra.prototype;var ta=h.bind(sa.get),ua=h.bind(sa.set),va=h.bind(sa.has),wa=window.Map;const xa=EventTarget.prototype;var ya=xa.addEventListener,za=xa.removeEventListener;const v=Node.prototype;var Aa=v.getRootNode,Ba=v.contains,Ca=v.cloneNode,Da=w(v,'nodeName'),Ea=w(v,'nodeType'),Fa=w(v,'isConnected');\n\
const x=Element.prototype;var Ga=x.hasAttribute,Ha=h.bind(x.setAttribute),Ia=h.bind(x.removeAttribute),Ja=x.getAttributeNames,Ka=x.getElementsByTagName,La=h.bind(x.querySelectorAll);const y=Document.prototype;var Ma=w(y,'documentElement'),Na=w(y,'domain'),Oa=w(y,'firstElementChild'),Pa=w(y,'readyState'),Qa=w(y,'visibilityState'),Ra=w(DocumentFragment.prototype,'firstElementChild');const Sa=HTMLIFrameElement.prototype;\n\
var Ta=w(Sa,'contentWindow'),Ua=w(Sa,'contentDocument'),Va=w(Sa,'src'),Wa=w(window,'length');const Xa=window.StylePropertyMapReadOnly?.prototype;var Ya=Xa?.keys,Za=Xa?.getAll,z=w(NamedNodeMap.prototype,'length'),$a=window.MutationObserver,ab=$a.prototype.observe;const bb=MutationRecord.prototype;var cb=w(bb,'addedNodes'),db=h.bind(w(bb,'type')),eb=h.bind(w(bb,'attributeName'));const fb=[];function A(a,b){return l(b,a,fb)}function B(a,b,c){gb[0]=c;a=l(b,a,gb);gb.length=0;return a}const gb=[];\n\
function w(a,b){return g(a,b).get};const hb=Node.ELEMENT_NODE;function C(a,b){return ta(a.g,b)}function D(a,b,c){ua(a.g,b,c)}var E=class{constructor(){this.g=new ra}};function ib(a){a.add=a.add.bind(a);a.has=a.has.bind(a);a.delete=a.delete.bind(a);a[Symbol.iterator]=a[Symbol.iterator].bind(a)};function F(a){return'undefined'===typeof a}function H(a){return'function'===typeof a};ib(new Set);ib(new Set);var I=window.Proxy;const J=window.Reflect;var jb=J.apply,kb=J.defineProperty,lb=J.get,mb=J.set,nb=J.has,ob=J.ownKeys,pb=J.getOwnPropertyDescriptor;function K(a,...b){if(a.g)throw 1;a.g=!0;try{return a.i(a.D,...b)}catch(c){throw b=c,u&&u(b,a.K),new L(b);}}function qb(a,b,...c){if(!a.g){if(b instanceof L)throw b.F;try{return K(a,...c)}catch(d){b=d}}if(b instanceof L)throw b.F;}class rb{constructor(a,b,c){this.D=a;this.K=b;this.i=c;this.g=!1}}class L{constructor(a){this.F=a}}\n\
class M extends null{constructor(a){const b=ba(M.prototype);b.g=a;return b}}function N(a,b){function c(d,...e){d=new rb(d,c,a);try{return b(this.g,d,...e)}catch(k){return qb(d,k,...e)}}return c}\n\
const sb=N(J.construct,function(a,b,c,d){return a.M(b,c,d)}),tb=N(lb,function(a,b,c,d){return a.A(b,c,d)}),ub=N(mb,function(a,b,c,d,e){return a.O(b,c,d,e)}),vb=N(pb,function(a,b,c){return a.G(b,c)}),xb=N(nb,function(a,b,c){let d=wb(c);return-1!==d&&O(a)?d<A(a.h,z)-1:K(b,c)}),yb=N(ob,function(a,b){b=K(b);if(O(a)){let c=la(b,P);r(b,c,1);c=la(b,n(A(a.h,z)-1));r(b,c,1)}return b}),zb=N(kb,function(a,b,c,d){return a.N(b,c,d)});\n\
function Ab(a,b,c){a=new rb(a,Ab,jb);try{var d=this.g;Bb=!0;d.H.g.delete(d.L);try{K(a,b,c)}finally{Q&&0===d.H.g.size&&Cb(c[0]),Bb=!1}}catch(e){return qb(a,e,b,c)}}const Db=new E,Eb=(a,b,c)=>{let d=C(Db,b);'undefined'==typeof d&&(d=b);return K(a,d,c)};function R(a,b){class c{static g(){const e=new rb(a,c.g,l);try{return b(e,this,arguments)}catch(k){return qb(e,k,this,arguments)}}}let d=c.g;d=Fb(a,d);Gb(a,d,'name');Gb(a,d,'length');return d}function Fb(a,b){D(Db,b,a);return b}\n\
function Gb(a,b,c){f(b,c,g(a,c))}function S(a,b,c){a.hasOwnProperty(b)&&(a[b]=R(a[b],c))}function T(a,b,c){var d=g(a,b);!F(d)&&d.get&&d.configurable&&(c&&(d.get=R(d.get,c)),f(a,b,d))}function Hb(a,b,c){let d=g(a,b);d.get?(d.get=R(d.get,c),d.set&&(d.set=R(d.set,c)),f(a,b,d)):d.writable&&'function'===typeof d.value&&(a[b]=R(d.value,c))};function Ib(a,b){const c=new $a(e=>{let k=e.length;if(0!==k>>7)Jb(a,d);else for(;k--;){let m=A(e[k],cb),G=m.length;for(;G--;){let t=m[G];'IFRAME'===A(t,Da)?U(a,t):A(t,Ea)===hb&&Jb(a,t)}}}),d=A(b.document,Ma);l(ab,c,[d,{childList:!0,subtree:!0}])}function Jb(a,b){b=Ka.call(b,'IFRAME');for(let c=0,d=b.length;c<d;c++)U(a,b[c])}\n\
function U(a,b){let c=C(a.i,b);if(F(c)){l(ya,b,['load',a.o]);try{let m=Ta.call(b);if('about:'===m.location.protocol){D(a.i,b,m.document);Kb(a,m);let G=A(b,Va);var d;if(d=G&&a.C){var e=a.g.location,k=A(a.g.document,Na);const t=new URL(G);d='javascript:'===t.protocol||'about:blank'===t.href?!0:'data:'===t.protocol?!1:t.hostname===k&&t.port===e.port&&t.protocol===e.protocol}d&&f(m,a.C,{value:void 0,configurable:!0})}}catch(m){D(a.i,b,null)}}}\n\
function Kb(a,b){a=a.B;for(let c=0,d=a.length;c<d;c++)a[c](b)}\n\
var Lb=class{constructor(a,b){this.g=a;this.C=b;this.B=[];this.o=fa.call(this.o,this);this.j=fa.call(this.j,this);a=a.HTMLIFrameElement.prototype;this.i=new E;T(a,'contentWindow',this.j);T(a,'contentDocument',this.j)}J(){Ib(this,this.g)}j(a,b,c){U(this,b);return K(a,b,c)}o(a){a=a.target;try{const c=Ua.call(a);if('about:'===c.location.protocol){var b=C(this.i,a);b!==c&&(D(this.i,a,c),'uninitialized'!==A(b,Pa)&&Kb(this,c.defaultView))}}catch(c){D(this.i,a,null)}}};var Mb=class extends Lb{constructor(){super(...arguments);this.I=this.g.document.getElementsByTagName('IFRAME');this.v=0}J(){this.g.addEventListener('DOMSubtreeModified',this,!0);this.g.addEventListener('DOMContentLoaded',a=>{a.isTrusted&&(l(za,this.g,['DOMSubtreeModified',this]),l(ya,this.g,['DOMNodeInsertedIntoDocument',this,!0]),l(ya,this.g,['DOMNodeRemovedFromDocument',this,!0]))},{once:!0})}handleEvent(a){if(a.isTrusted&&(a=A(window,Wa),this.v!==a)){if(this.v<a){let b=this.I.length;for(let c=\n\
0;c<b;c++)U(this,this.I[c])}this.v=a}}};const Nb=\"623a14b8-771c-45f8-b0ce-d5fb4943ac12\";function V(a,b,c){try{let d=c(b[0]);return b[0]=d}catch(d){throw b=d,u&&u(b,a.K),new L(b);}}function Ob(a,b){a=V(a,b,n);return A(a,ha)};const Pb=new E;let Q=null;function Cb(a){Q?.(a);Q=null;qa(Qb);Qb=0;oa(Rb);Rb=0}let Qb=0,Rb=0,Bb=!1;class Sb{constructor(){this.g=new wa;this.i=0}}const Ub=(a,b,c)=>{(F(b)||null===b)&&(b=window);const d=C(Pb,b),e=c[0];if(!d||!H(e))return K(a,b,c);const k=++d.i;var m=new M(new Tb(d,k));m.apply=Ab;m=new I(e,m);m=Fb(e,m);c[0]=m;a=K(a,b,c);d.g.set(k,a);return k};class Tb{constructor(a,b){this.H=a;this.L=b}}\n\
const Vb=(a,b,c)=>{(F(b)||null===b)&&(b=window);var d=C(Pb,b);if(!d||0===c.length)return K(a,b,c);const e=V(a,c,p);d=d.g.get(e);c[0]=d;return K(a,b,c)};let Wb=!1;const W=new Set;ib(W);function Xb(a){W.has(a)||(W.add(a),Ha(a,P,''),a=Yb,null===Q&&(Q=a,Bb||('visible'!==A(document,Qa)?Rb=na(Cb):Qb=pa(Cb))))}function Yb(){for(let a of W)Ia(a,P);W.clear()}function Zb(a){B(a,Ga,P)&&Ia(a,P);a=La(a,'['+P+']');for(let b of a)Ia(b,P)}function $b(a,b,...c){if(F(a))return K(b,...c);B(document,Ba,a)&&(Wb=!0);Xb(a);return K(b,...c)}\n\
function ac(a,b){if(b=a=C(a.g,b)){b=a;var c=A(b,Fa)?A(b,Aa):void 0;F(c)||c===document?b=!1:(b=A(b,Da),b='IMG'===b||'LINE'===b?!0:!1)}a=b?a:void 0;return a?a:null}function bc(a,b,c,d,...e){a=ac(a,b);c=null===a||'clip-path'!==c?null:a;return null===c?K(d,...e):$b(c,d,...e)}function cc(a,b){a=ac(dc,a);if(null!==a)return B(document,Ba,a)&&(Wb=!0),Xb(a),b()}var ec=class{constructor(){this.g=new E}};const hc=(a,b,c)=>{a=K(a,b,c);if(!a)return a;D(fc.g,a,c[0]);c=new M(gc);c.get=tb;c.getOwnPropertyDescriptor=vb;c=new I(a,c);D(X,c,a);return c},gc={A:ic,G:ic};function ic(a,b){if('string'!==typeof b)return K(a,b);b='clipPath'===b?'clip-path':b;return bc(fc,a.D,b,a,b)}var X=new E,fc=new ec;const jc=(a,b,c)=>{a=K(a,b,c);if(!a)return a;D(dc.g,a,b);return a};var dc=new ec;function kc(a){return function(b,c,d){c=a(c)||c;return K(b,c,d)}}function lc(a,b,c){var d=ca(a);let e=d.length;for(b=kc(b);e--;){var k=d[e];c(k)||Hb(a,k,b)}d=da(a);for(e=d.length;e--;)k=d[e],c(k)||Hb(a,d[e],b)};function mc(a){return'getPropertyValue'===a||'constructor'==a}function nc(a){return C(X,a)}const oc=(a,b,c)=>{va(X.g,b)&&(b=C(X,b));let d=Ob(a,c);return bc(fc,b,d,a,b,c)};const pc=(a,b,c)=>{let d=Ob(a,c);return bc(dc,b,d,a,b,c)},qc=new E,rc=new E,sc=(a,b,c)=>{a=K(a,b,c);if(!a)return a;D(qc,a,{u:A(b,Ya),m:B(b,Za,'clip-path')});return a},tc=(a,b,c)=>{a=K(a,b,c);if(!a)return a;D(rc,a,{u:A(b,Ya),m:B(b,Za,'clip-path')});return a},uc=(a,b,c)=>{let d=c[0];if(!H(d))return K(a,b,c);const e=cc(b,()=>B(b,Za,'clip-path'));if(F(e))return K(a,b,c);c[0]=function(k,m,G){'clip-path'===m&&(arguments[0]=e);return l(d,this,arguments)};return K(a,b,c)},vc=aa((new window.URLSearchParams('')).values()).next,\n\
wc=(a,b,c)=>{a=K(a,b,c);if(va(qc.g,b)){let {u:d,m:e}=C(qc,b);'clip-path'===A(d,vc).value&&(a.value=e)}else if(va(rc.g,b)){let {u:d,m:e}=C(rc,b);'clip-path'===A(d,vc).value&&(a.value=e)}return a};const xc=(a,b,c)=>{const d=A(b,Oa);return $b(d,a,b,c)},yc=(a,b,c)=>{const d=A(b,Ra);return $b(d,a,b,c)};const Ac=(a,b,c)=>{let d=b[0];H(d)&&(b[0]=R(d,zc));return K(a,b,c)},zc=(a,b,c)=>{let d=c[0];Bc(d);if(d.length)return K(a,b,c)},Cc=(a,b,c)=>{a=K(a,b,c);if(!a)return a;Bc(a);return a};function Bc(a){let b=0,c;for(;c=a[b];)'attributes'===db(c)&&eb(c)===P?r(a,b,1):b++};const Dc=new E,Hc=(a,b,c)=>{if(!Ec(a,c))return K(a,b,c);const d=c[1];if(H(d))var e=R(d,Fc);else if('object'===typeof d)e=new M(Gc),e.get=tb,e=new I(d,e);else return K(a,b,c);D(Dc,e,d);c[1]=d;return K(a,b,c)},Ic=(a,b,c)=>{if(Ec(a,c)){const d=c[1];'object'===typeof d&&(c[1]=C(Dc,d)||d)}return K(a,b,c)},Fc=(a,b,c)=>{Wb||K(a,b,c)},Jc=()=>{},Gc={A(a,b,c){a=K(a,b,c);return H(a)?Jc:a}};function Ec(a,b){a=V(a,b,n);return'DOMSubtreeModified'!==a&&'DOMAttrModified'!==a?!0:!1};function Kc(a){return'constructor'===a||'length'===a||'item'===a||a===ja}function Lc(a){return C(Y,a)?.h}\n\
const Mc=(a,b,c)=>{a=K(a,b,c);b=la(a,P);-1!==b&&r(a,b,1);return a},Nc=(a,b,c)=>{a=K(a,b,c);return B(b,Ga,P)?1<A(b,Ja).length:a},Oc=(a,b,c)=>{var d=c[0];if(A(b,Ea)!==hb||A(d,Ea)!==hb)return K(a,b,c);b=B(b,Ca,!0);d=B(d,Ca,!0);Zb(b);Zb(d);c[0]=d;return K(a,b,c)},Qc=(a,b,c)=>{var d=C(Pc,b);if(d)return d;d=K(a,b,c);if(!d)return d;a=new Z(d);c=new M(a);c.get=tb;c.getOwnPropertyDescriptor=vb;c.has=xb;c.set=ub;c.defineProperty=zb;c.ownKeys=yb;d=new I(d,c);D(Y,d,a);D(Pc,b,d);return d},Y=new E,Pc=new E;\n\
function O(a){let b=a.h[P];b||(a.l=-1);return b}function Rc(a,b){var c=O(a);if(c){a:{var d=a.l;let e=d;for(;-1!==e;){if(c===a.h[e]){c=e;break a}e--}for(e=A(a.h,z);--e>d;)if(c===a.h[e]){c=e;break a}c=-1}a.l=c;-1!==c&&c<=b&&b++;a=b}else a=b;return a}class Z{constructor(a){this.h=a;this.l=-1}}function Sc(a,b,...c){let d=wb(b);-1!==d&&(d=Rc(this,d),-1!==d&&(b=n(d)));return K(a,b,...c)}Z.prototype.A=Sc;Z.prototype.G=Sc;function Tc(a,b){return-1===wb(b)?K(a,b):!1}Z.prototype.O=Tc;Z.prototype.N=Tc;\n\
const Uc=(a,b,c)=>{const d=C(Y,b);if(!d)return K(a,b,c);b=d.h;a=K(a,b,c);O(d)&&a--;return a},Vc=(a,b,c)=>{const d=C(Y,b);if(d){b=d.h;let e=V(a,c,p);(e|0)===e&&0<1/e&&(c[0]=Rc(d,e))}return K(a,b,c)},Wc=(a,b,c)=>{const d=C(Y,b);if(d){if(b=O(d)){a=[];c=A(d.h,z);for(let e=0;e<c;e++){let k=d.h[e];k!==b&&ka(a,k)}return A(a,ma)}b=d.h}return K(a,b,c)};function wb(a){'string'===typeof a?(a=p(a),a=(a|0)===a&&0<1/a?a:-1):a=-1;return a};const Xc=(a,b,c)=>{a=K(a,b,c);return'string'===typeof a?ia(a,' '+P+'=\"\"',''):a};(function(a){if(B(window,ea,Nb))delete window[Nb];else{var b=c=>{S(c.Function.prototype,'toString',Eb);const d=new Mb(c,Nb);d.J();a(c);ka(d.B,b)};b(window)}})(a=>{S(a,'getComputedStyle',hc);var b=a.CSSStyleDeclaration.prototype;lc(b,nc,mc);S(b,'getPropertyValue',oc);b=a.Document.prototype;var c=a.ShadowRoot.prototype;S(b,'elementFromPoint',xc);S(b,'elementsFromPoint',xc);S(c,'elementFromPoint',yc);S(c,'elementsFromPoint',yc);b=a.MutationObserver;S(b.prototype,'takeRecords',Cc);c=new M({M:Ac});c.construct=\n\
sb;c=new I(b,c);c=Fb(b,c);b.prototype.constructor=c;a.MutationObserver=c;b=a.EventTarget.prototype;S(b,'addEventListener',Hc);S(b,'removeEventListener',Ic);S(a,'requestAnimationFrame',Ub);S(a,'cancelAnimationFrame',Vb);'webkitRequestAnimationFrame'in a&&(S(a,'webkitRequestAnimationFrame',Ub),S(a,'webkitCancelAnimationFrame',Vb));D(Pb,a,new Sb);b=a.Element.prototype;S(b,'getAttributeNames',Mc);S(b,'hasAttributes',Nc);T(b,'attributes',Qc);S(a.Node.prototype,'isEqualNode',Oc);b=a.NamedNodeMap.prototype;\n\
lc(b,Lc,Kc);T(b,'length',Uc);S(b,'item',Vc);S(b,ja,Wc);b=a.Element.prototype;T(b,'innerHTML',Xc);T(b,'outerHTML',Xc);S(a.XMLSerializer.prototype,'serializeToString',Xc);S(a.Element.prototype,'computedStyleMap',jc);b=a.StylePropertyMapReadOnly.prototype;S(b,'get',pc);S(b,'getAll',pc);S(b,'values',sc);S(b,'entries',tc);S(b,'forEach',uc);S(aa((new a.URLSearchParams('')).values()),'next',wc)});var P=" + '"' + a + '"' + ";})();\n\
";
(document.head || document.documentElement).appendChild(c).remove();