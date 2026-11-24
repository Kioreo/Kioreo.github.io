(function(){const t=document.createElement("link").relList;if(t&&t.supports&&t.supports("modulepreload"))return;for(const l of document.querySelectorAll('link[rel="modulepreload"]'))s(l);new MutationObserver(l=>{for(const c of l)if(c.type==="childList")for(const f of c.addedNodes)f.tagName==="LINK"&&f.rel==="modulepreload"&&s(f)}).observe(document,{childList:!0,subtree:!0});function n(l){const c={};return l.integrity&&(c.integrity=l.integrity),l.referrerPolicy&&(c.referrerPolicy=l.referrerPolicy),l.crossOrigin==="use-credentials"?c.credentials="include":l.crossOrigin==="anonymous"?c.credentials="omit":c.credentials="same-origin",c}function s(l){if(l.ep)return;l.ep=!0;const c=n(l);fetch(l.href,c)}})();var _h={exports:{}},Go={};/**
 * @license React
 * react-jsx-runtime.production.js
 *
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */var rv;function wy(){if(rv)return Go;rv=1;var r=Symbol.for("react.transitional.element"),t=Symbol.for("react.fragment");function n(s,l,c){var f=null;if(c!==void 0&&(f=""+c),l.key!==void 0&&(f=""+l.key),"key"in l){c={};for(var d in l)d!=="key"&&(c[d]=l[d])}else c=l;return l=c.ref,{$$typeof:r,type:s,key:f,ref:l!==void 0?l:null,props:c}}return Go.Fragment=t,Go.jsx=n,Go.jsxs=n,Go}var ov;function Dy(){return ov||(ov=1,_h.exports=wy()),_h.exports}var z=Dy(),xh={exports:{}},Vo={},Sh={exports:{}},yh={};/**
 * @license React
 * scheduler.production.js
 *
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */var lv;function Ny(){return lv||(lv=1,(function(r){function t(B,H){var $=B.length;B.push(H);t:for(;0<$;){var dt=$-1>>>1,Mt=B[dt];if(0<l(Mt,H))B[dt]=H,B[$]=Mt,$=dt;else break t}}function n(B){return B.length===0?null:B[0]}function s(B){if(B.length===0)return null;var H=B[0],$=B.pop();if($!==H){B[0]=$;t:for(var dt=0,Mt=B.length,U=Mt>>>1;dt<U;){var J=2*(dt+1)-1,bt=B[J],pt=J+1,At=B[pt];if(0>l(bt,$))pt<Mt&&0>l(At,bt)?(B[dt]=At,B[pt]=$,dt=pt):(B[dt]=bt,B[J]=$,dt=J);else if(pt<Mt&&0>l(At,$))B[dt]=At,B[pt]=$,dt=pt;else break t}}return H}function l(B,H){var $=B.sortIndex-H.sortIndex;return $!==0?$:B.id-H.id}if(r.unstable_now=void 0,typeof performance=="object"&&typeof performance.now=="function"){var c=performance;r.unstable_now=function(){return c.now()}}else{var f=Date,d=f.now();r.unstable_now=function(){return f.now()-d}}var m=[],p=[],v=1,_=null,g=3,y=!1,b=!1,w=!1,M=!1,S=typeof setTimeout=="function"?setTimeout:null,P=typeof clearTimeout=="function"?clearTimeout:null,D=typeof setImmediate<"u"?setImmediate:null;function A(B){for(var H=n(p);H!==null;){if(H.callback===null)s(p);else if(H.startTime<=B)s(p),H.sortIndex=H.expirationTime,t(m,H);else break;H=n(p)}}function F(B){if(w=!1,A(B),!b)if(n(m)!==null)b=!0,O||(O=!0,q());else{var H=n(p);H!==null&&j(F,H.startTime-B)}}var O=!1,I=-1,T=5,N=-1;function X(){return M?!0:!(r.unstable_now()-N<T)}function V(){if(M=!1,O){var B=r.unstable_now();N=B;var H=!0;try{t:{b=!1,w&&(w=!1,P(I),I=-1),y=!0;var $=g;try{e:{for(A(B),_=n(m);_!==null&&!(_.expirationTime>B&&X());){var dt=_.callback;if(typeof dt=="function"){_.callback=null,g=_.priorityLevel;var Mt=dt(_.expirationTime<=B);if(B=r.unstable_now(),typeof Mt=="function"){_.callback=Mt,A(B),H=!0;break e}_===n(m)&&s(m),A(B)}else s(m);_=n(m)}if(_!==null)H=!0;else{var U=n(p);U!==null&&j(F,U.startTime-B),H=!1}}break t}finally{_=null,g=$,y=!1}H=void 0}}finally{H?q():O=!1}}}var q;if(typeof D=="function")q=function(){D(V)};else if(typeof MessageChannel<"u"){var ct=new MessageChannel,ht=ct.port2;ct.port1.onmessage=V,q=function(){ht.postMessage(null)}}else q=function(){S(V,0)};function j(B,H){I=S(function(){B(r.unstable_now())},H)}r.unstable_IdlePriority=5,r.unstable_ImmediatePriority=1,r.unstable_LowPriority=4,r.unstable_NormalPriority=3,r.unstable_Profiling=null,r.unstable_UserBlockingPriority=2,r.unstable_cancelCallback=function(B){B.callback=null},r.unstable_forceFrameRate=function(B){0>B||125<B?console.error("forceFrameRate takes a positive int between 0 and 125, forcing frame rates higher than 125 fps is not supported"):T=0<B?Math.floor(1e3/B):5},r.unstable_getCurrentPriorityLevel=function(){return g},r.unstable_next=function(B){switch(g){case 1:case 2:case 3:var H=3;break;default:H=g}var $=g;g=H;try{return B()}finally{g=$}},r.unstable_requestPaint=function(){M=!0},r.unstable_runWithPriority=function(B,H){switch(B){case 1:case 2:case 3:case 4:case 5:break;default:B=3}var $=g;g=B;try{return H()}finally{g=$}},r.unstable_scheduleCallback=function(B,H,$){var dt=r.unstable_now();switch(typeof $=="object"&&$!==null?($=$.delay,$=typeof $=="number"&&0<$?dt+$:dt):$=dt,B){case 1:var Mt=-1;break;case 2:Mt=250;break;case 5:Mt=1073741823;break;case 4:Mt=1e4;break;default:Mt=5e3}return Mt=$+Mt,B={id:v++,callback:H,priorityLevel:B,startTime:$,expirationTime:Mt,sortIndex:-1},$>dt?(B.sortIndex=$,t(p,B),n(m)===null&&B===n(p)&&(w?(P(I),I=-1):w=!0,j(F,$-dt))):(B.sortIndex=Mt,t(m,B),b||y||(b=!0,O||(O=!0,q()))),B},r.unstable_shouldYield=X,r.unstable_wrapCallback=function(B){var H=g;return function(){var $=g;g=H;try{return B.apply(this,arguments)}finally{g=$}}}})(yh)),yh}var cv;function Uy(){return cv||(cv=1,Sh.exports=Ny()),Sh.exports}var Mh={exports:{}},se={};/**
 * @license React
 * react.production.js
 *
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */var uv;function Ly(){if(uv)return se;uv=1;var r=Symbol.for("react.transitional.element"),t=Symbol.for("react.portal"),n=Symbol.for("react.fragment"),s=Symbol.for("react.strict_mode"),l=Symbol.for("react.profiler"),c=Symbol.for("react.consumer"),f=Symbol.for("react.context"),d=Symbol.for("react.forward_ref"),m=Symbol.for("react.suspense"),p=Symbol.for("react.memo"),v=Symbol.for("react.lazy"),_=Symbol.for("react.activity"),g=Symbol.iterator;function y(U){return U===null||typeof U!="object"?null:(U=g&&U[g]||U["@@iterator"],typeof U=="function"?U:null)}var b={isMounted:function(){return!1},enqueueForceUpdate:function(){},enqueueReplaceState:function(){},enqueueSetState:function(){}},w=Object.assign,M={};function S(U,J,bt){this.props=U,this.context=J,this.refs=M,this.updater=bt||b}S.prototype.isReactComponent={},S.prototype.setState=function(U,J){if(typeof U!="object"&&typeof U!="function"&&U!=null)throw Error("takes an object of state variables to update or a function which returns an object of state variables.");this.updater.enqueueSetState(this,U,J,"setState")},S.prototype.forceUpdate=function(U){this.updater.enqueueForceUpdate(this,U,"forceUpdate")};function P(){}P.prototype=S.prototype;function D(U,J,bt){this.props=U,this.context=J,this.refs=M,this.updater=bt||b}var A=D.prototype=new P;A.constructor=D,w(A,S.prototype),A.isPureReactComponent=!0;var F=Array.isArray;function O(){}var I={H:null,A:null,T:null,S:null},T=Object.prototype.hasOwnProperty;function N(U,J,bt){var pt=bt.ref;return{$$typeof:r,type:U,key:J,ref:pt!==void 0?pt:null,props:bt}}function X(U,J){return N(U.type,J,U.props)}function V(U){return typeof U=="object"&&U!==null&&U.$$typeof===r}function q(U){var J={"=":"=0",":":"=2"};return"$"+U.replace(/[=:]/g,function(bt){return J[bt]})}var ct=/\/+/g;function ht(U,J){return typeof U=="object"&&U!==null&&U.key!=null?q(""+U.key):J.toString(36)}function j(U){switch(U.status){case"fulfilled":return U.value;case"rejected":throw U.reason;default:switch(typeof U.status=="string"?U.then(O,O):(U.status="pending",U.then(function(J){U.status==="pending"&&(U.status="fulfilled",U.value=J)},function(J){U.status==="pending"&&(U.status="rejected",U.reason=J)})),U.status){case"fulfilled":return U.value;case"rejected":throw U.reason}}throw U}function B(U,J,bt,pt,At){var tt=typeof U;(tt==="undefined"||tt==="boolean")&&(U=null);var _t=!1;if(U===null)_t=!0;else switch(tt){case"bigint":case"string":case"number":_t=!0;break;case"object":switch(U.$$typeof){case r:case t:_t=!0;break;case v:return _t=U._init,B(_t(U._payload),J,bt,pt,At)}}if(_t)return At=At(U),_t=pt===""?"."+ht(U,0):pt,F(At)?(bt="",_t!=null&&(bt=_t.replace(ct,"$&/")+"/"),B(At,J,bt,"",function(jt){return jt})):At!=null&&(V(At)&&(At=X(At,bt+(At.key==null||U&&U.key===At.key?"":(""+At.key).replace(ct,"$&/")+"/")+_t)),J.push(At)),1;_t=0;var xt=pt===""?".":pt+":";if(F(U))for(var It=0;It<U.length;It++)pt=U[It],tt=xt+ht(pt,It),_t+=B(pt,J,bt,tt,At);else if(It=y(U),typeof It=="function")for(U=It.call(U),It=0;!(pt=U.next()).done;)pt=pt.value,tt=xt+ht(pt,It++),_t+=B(pt,J,bt,tt,At);else if(tt==="object"){if(typeof U.then=="function")return B(j(U),J,bt,pt,At);throw J=String(U),Error("Objects are not valid as a React child (found: "+(J==="[object Object]"?"object with keys {"+Object.keys(U).join(", ")+"}":J)+"). If you meant to render a collection of children, use an array instead.")}return _t}function H(U,J,bt){if(U==null)return U;var pt=[],At=0;return B(U,pt,"","",function(tt){return J.call(bt,tt,At++)}),pt}function $(U){if(U._status===-1){var J=U._result;J=J(),J.then(function(bt){(U._status===0||U._status===-1)&&(U._status=1,U._result=bt)},function(bt){(U._status===0||U._status===-1)&&(U._status=2,U._result=bt)}),U._status===-1&&(U._status=0,U._result=J)}if(U._status===1)return U._result.default;throw U._result}var dt=typeof reportError=="function"?reportError:function(U){if(typeof window=="object"&&typeof window.ErrorEvent=="function"){var J=new window.ErrorEvent("error",{bubbles:!0,cancelable:!0,message:typeof U=="object"&&U!==null&&typeof U.message=="string"?String(U.message):String(U),error:U});if(!window.dispatchEvent(J))return}else if(typeof process=="object"&&typeof process.emit=="function"){process.emit("uncaughtException",U);return}console.error(U)},Mt={map:H,forEach:function(U,J,bt){H(U,function(){J.apply(this,arguments)},bt)},count:function(U){var J=0;return H(U,function(){J++}),J},toArray:function(U){return H(U,function(J){return J})||[]},only:function(U){if(!V(U))throw Error("React.Children.only expected to receive a single React element child.");return U}};return se.Activity=_,se.Children=Mt,se.Component=S,se.Fragment=n,se.Profiler=l,se.PureComponent=D,se.StrictMode=s,se.Suspense=m,se.__CLIENT_INTERNALS_DO_NOT_USE_OR_WARN_USERS_THEY_CANNOT_UPGRADE=I,se.__COMPILER_RUNTIME={__proto__:null,c:function(U){return I.H.useMemoCache(U)}},se.cache=function(U){return function(){return U.apply(null,arguments)}},se.cacheSignal=function(){return null},se.cloneElement=function(U,J,bt){if(U==null)throw Error("The argument must be a React element, but you passed "+U+".");var pt=w({},U.props),At=U.key;if(J!=null)for(tt in J.key!==void 0&&(At=""+J.key),J)!T.call(J,tt)||tt==="key"||tt==="__self"||tt==="__source"||tt==="ref"&&J.ref===void 0||(pt[tt]=J[tt]);var tt=arguments.length-2;if(tt===1)pt.children=bt;else if(1<tt){for(var _t=Array(tt),xt=0;xt<tt;xt++)_t[xt]=arguments[xt+2];pt.children=_t}return N(U.type,At,pt)},se.createContext=function(U){return U={$$typeof:f,_currentValue:U,_currentValue2:U,_threadCount:0,Provider:null,Consumer:null},U.Provider=U,U.Consumer={$$typeof:c,_context:U},U},se.createElement=function(U,J,bt){var pt,At={},tt=null;if(J!=null)for(pt in J.key!==void 0&&(tt=""+J.key),J)T.call(J,pt)&&pt!=="key"&&pt!=="__self"&&pt!=="__source"&&(At[pt]=J[pt]);var _t=arguments.length-2;if(_t===1)At.children=bt;else if(1<_t){for(var xt=Array(_t),It=0;It<_t;It++)xt[It]=arguments[It+2];At.children=xt}if(U&&U.defaultProps)for(pt in _t=U.defaultProps,_t)At[pt]===void 0&&(At[pt]=_t[pt]);return N(U,tt,At)},se.createRef=function(){return{current:null}},se.forwardRef=function(U){return{$$typeof:d,render:U}},se.isValidElement=V,se.lazy=function(U){return{$$typeof:v,_payload:{_status:-1,_result:U},_init:$}},se.memo=function(U,J){return{$$typeof:p,type:U,compare:J===void 0?null:J}},se.startTransition=function(U){var J=I.T,bt={};I.T=bt;try{var pt=U(),At=I.S;At!==null&&At(bt,pt),typeof pt=="object"&&pt!==null&&typeof pt.then=="function"&&pt.then(O,dt)}catch(tt){dt(tt)}finally{J!==null&&bt.types!==null&&(J.types=bt.types),I.T=J}},se.unstable_useCacheRefresh=function(){return I.H.useCacheRefresh()},se.use=function(U){return I.H.use(U)},se.useActionState=function(U,J,bt){return I.H.useActionState(U,J,bt)},se.useCallback=function(U,J){return I.H.useCallback(U,J)},se.useContext=function(U){return I.H.useContext(U)},se.useDebugValue=function(){},se.useDeferredValue=function(U,J){return I.H.useDeferredValue(U,J)},se.useEffect=function(U,J){return I.H.useEffect(U,J)},se.useEffectEvent=function(U){return I.H.useEffectEvent(U)},se.useId=function(){return I.H.useId()},se.useImperativeHandle=function(U,J,bt){return I.H.useImperativeHandle(U,J,bt)},se.useInsertionEffect=function(U,J){return I.H.useInsertionEffect(U,J)},se.useLayoutEffect=function(U,J){return I.H.useLayoutEffect(U,J)},se.useMemo=function(U,J){return I.H.useMemo(U,J)},se.useOptimistic=function(U,J){return I.H.useOptimistic(U,J)},se.useReducer=function(U,J,bt){return I.H.useReducer(U,J,bt)},se.useRef=function(U){return I.H.useRef(U)},se.useState=function(U){return I.H.useState(U)},se.useSyncExternalStore=function(U,J,bt){return I.H.useSyncExternalStore(U,J,bt)},se.useTransition=function(){return I.H.useTransition()},se.version="19.2.0",se}var fv;function ip(){return fv||(fv=1,Mh.exports=Ly()),Mh.exports}var Eh={exports:{}},In={};/**
 * @license React
 * react-dom.production.js
 *
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */var hv;function Oy(){if(hv)return In;hv=1;var r=ip();function t(m){var p="https://react.dev/errors/"+m;if(1<arguments.length){p+="?args[]="+encodeURIComponent(arguments[1]);for(var v=2;v<arguments.length;v++)p+="&args[]="+encodeURIComponent(arguments[v])}return"Minified React error #"+m+"; visit "+p+" for the full message or use the non-minified dev environment for full errors and additional helpful warnings."}function n(){}var s={d:{f:n,r:function(){throw Error(t(522))},D:n,C:n,L:n,m:n,X:n,S:n,M:n},p:0,findDOMNode:null},l=Symbol.for("react.portal");function c(m,p,v){var _=3<arguments.length&&arguments[3]!==void 0?arguments[3]:null;return{$$typeof:l,key:_==null?null:""+_,children:m,containerInfo:p,implementation:v}}var f=r.__CLIENT_INTERNALS_DO_NOT_USE_OR_WARN_USERS_THEY_CANNOT_UPGRADE;function d(m,p){if(m==="font")return"";if(typeof p=="string")return p==="use-credentials"?p:""}return In.__DOM_INTERNALS_DO_NOT_USE_OR_WARN_USERS_THEY_CANNOT_UPGRADE=s,In.createPortal=function(m,p){var v=2<arguments.length&&arguments[2]!==void 0?arguments[2]:null;if(!p||p.nodeType!==1&&p.nodeType!==9&&p.nodeType!==11)throw Error(t(299));return c(m,p,null,v)},In.flushSync=function(m){var p=f.T,v=s.p;try{if(f.T=null,s.p=2,m)return m()}finally{f.T=p,s.p=v,s.d.f()}},In.preconnect=function(m,p){typeof m=="string"&&(p?(p=p.crossOrigin,p=typeof p=="string"?p==="use-credentials"?p:"":void 0):p=null,s.d.C(m,p))},In.prefetchDNS=function(m){typeof m=="string"&&s.d.D(m)},In.preinit=function(m,p){if(typeof m=="string"&&p&&typeof p.as=="string"){var v=p.as,_=d(v,p.crossOrigin),g=typeof p.integrity=="string"?p.integrity:void 0,y=typeof p.fetchPriority=="string"?p.fetchPriority:void 0;v==="style"?s.d.S(m,typeof p.precedence=="string"?p.precedence:void 0,{crossOrigin:_,integrity:g,fetchPriority:y}):v==="script"&&s.d.X(m,{crossOrigin:_,integrity:g,fetchPriority:y,nonce:typeof p.nonce=="string"?p.nonce:void 0})}},In.preinitModule=function(m,p){if(typeof m=="string")if(typeof p=="object"&&p!==null){if(p.as==null||p.as==="script"){var v=d(p.as,p.crossOrigin);s.d.M(m,{crossOrigin:v,integrity:typeof p.integrity=="string"?p.integrity:void 0,nonce:typeof p.nonce=="string"?p.nonce:void 0})}}else p==null&&s.d.M(m)},In.preload=function(m,p){if(typeof m=="string"&&typeof p=="object"&&p!==null&&typeof p.as=="string"){var v=p.as,_=d(v,p.crossOrigin);s.d.L(m,v,{crossOrigin:_,integrity:typeof p.integrity=="string"?p.integrity:void 0,nonce:typeof p.nonce=="string"?p.nonce:void 0,type:typeof p.type=="string"?p.type:void 0,fetchPriority:typeof p.fetchPriority=="string"?p.fetchPriority:void 0,referrerPolicy:typeof p.referrerPolicy=="string"?p.referrerPolicy:void 0,imageSrcSet:typeof p.imageSrcSet=="string"?p.imageSrcSet:void 0,imageSizes:typeof p.imageSizes=="string"?p.imageSizes:void 0,media:typeof p.media=="string"?p.media:void 0})}},In.preloadModule=function(m,p){if(typeof m=="string")if(p){var v=d(p.as,p.crossOrigin);s.d.m(m,{as:typeof p.as=="string"&&p.as!=="script"?p.as:void 0,crossOrigin:v,integrity:typeof p.integrity=="string"?p.integrity:void 0})}else s.d.m(m)},In.requestFormReset=function(m){s.d.r(m)},In.unstable_batchedUpdates=function(m,p){return m(p)},In.useFormState=function(m,p,v){return f.H.useFormState(m,p,v)},In.useFormStatus=function(){return f.H.useHostTransitionStatus()},In.version="19.2.0",In}var dv;function Py(){if(dv)return Eh.exports;dv=1;function r(){if(!(typeof __REACT_DEVTOOLS_GLOBAL_HOOK__>"u"||typeof __REACT_DEVTOOLS_GLOBAL_HOOK__.checkDCE!="function"))try{__REACT_DEVTOOLS_GLOBAL_HOOK__.checkDCE(r)}catch(t){console.error(t)}}return r(),Eh.exports=Oy(),Eh.exports}/**
 * @license React
 * react-dom-client.production.js
 *
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */var pv;function Iy(){if(pv)return Vo;pv=1;var r=Uy(),t=ip(),n=Py();function s(e){var i="https://react.dev/errors/"+e;if(1<arguments.length){i+="?args[]="+encodeURIComponent(arguments[1]);for(var a=2;a<arguments.length;a++)i+="&args[]="+encodeURIComponent(arguments[a])}return"Minified React error #"+e+"; visit "+i+" for the full message or use the non-minified dev environment for full errors and additional helpful warnings."}function l(e){return!(!e||e.nodeType!==1&&e.nodeType!==9&&e.nodeType!==11)}function c(e){var i=e,a=e;if(e.alternate)for(;i.return;)i=i.return;else{e=i;do i=e,(i.flags&4098)!==0&&(a=i.return),e=i.return;while(e)}return i.tag===3?a:null}function f(e){if(e.tag===13){var i=e.memoizedState;if(i===null&&(e=e.alternate,e!==null&&(i=e.memoizedState)),i!==null)return i.dehydrated}return null}function d(e){if(e.tag===31){var i=e.memoizedState;if(i===null&&(e=e.alternate,e!==null&&(i=e.memoizedState)),i!==null)return i.dehydrated}return null}function m(e){if(c(e)!==e)throw Error(s(188))}function p(e){var i=e.alternate;if(!i){if(i=c(e),i===null)throw Error(s(188));return i!==e?null:e}for(var a=e,o=i;;){var u=a.return;if(u===null)break;var h=u.alternate;if(h===null){if(o=u.return,o!==null){a=o;continue}break}if(u.child===h.child){for(h=u.child;h;){if(h===a)return m(u),e;if(h===o)return m(u),i;h=h.sibling}throw Error(s(188))}if(a.return!==o.return)a=u,o=h;else{for(var x=!1,C=u.child;C;){if(C===a){x=!0,a=u,o=h;break}if(C===o){x=!0,o=u,a=h;break}C=C.sibling}if(!x){for(C=h.child;C;){if(C===a){x=!0,a=h,o=u;break}if(C===o){x=!0,o=h,a=u;break}C=C.sibling}if(!x)throw Error(s(189))}}if(a.alternate!==o)throw Error(s(190))}if(a.tag!==3)throw Error(s(188));return a.stateNode.current===a?e:i}function v(e){var i=e.tag;if(i===5||i===26||i===27||i===6)return e;for(e=e.child;e!==null;){if(i=v(e),i!==null)return i;e=e.sibling}return null}var _=Object.assign,g=Symbol.for("react.element"),y=Symbol.for("react.transitional.element"),b=Symbol.for("react.portal"),w=Symbol.for("react.fragment"),M=Symbol.for("react.strict_mode"),S=Symbol.for("react.profiler"),P=Symbol.for("react.consumer"),D=Symbol.for("react.context"),A=Symbol.for("react.forward_ref"),F=Symbol.for("react.suspense"),O=Symbol.for("react.suspense_list"),I=Symbol.for("react.memo"),T=Symbol.for("react.lazy"),N=Symbol.for("react.activity"),X=Symbol.for("react.memo_cache_sentinel"),V=Symbol.iterator;function q(e){return e===null||typeof e!="object"?null:(e=V&&e[V]||e["@@iterator"],typeof e=="function"?e:null)}var ct=Symbol.for("react.client.reference");function ht(e){if(e==null)return null;if(typeof e=="function")return e.$$typeof===ct?null:e.displayName||e.name||null;if(typeof e=="string")return e;switch(e){case w:return"Fragment";case S:return"Profiler";case M:return"StrictMode";case F:return"Suspense";case O:return"SuspenseList";case N:return"Activity"}if(typeof e=="object")switch(e.$$typeof){case b:return"Portal";case D:return e.displayName||"Context";case P:return(e._context.displayName||"Context")+".Consumer";case A:var i=e.render;return e=e.displayName,e||(e=i.displayName||i.name||"",e=e!==""?"ForwardRef("+e+")":"ForwardRef"),e;case I:return i=e.displayName||null,i!==null?i:ht(e.type)||"Memo";case T:i=e._payload,e=e._init;try{return ht(e(i))}catch{}}return null}var j=Array.isArray,B=t.__CLIENT_INTERNALS_DO_NOT_USE_OR_WARN_USERS_THEY_CANNOT_UPGRADE,H=n.__DOM_INTERNALS_DO_NOT_USE_OR_WARN_USERS_THEY_CANNOT_UPGRADE,$={pending:!1,data:null,method:null,action:null},dt=[],Mt=-1;function U(e){return{current:e}}function J(e){0>Mt||(e.current=dt[Mt],dt[Mt]=null,Mt--)}function bt(e,i){Mt++,dt[Mt]=e.current,e.current=i}var pt=U(null),At=U(null),tt=U(null),_t=U(null);function xt(e,i){switch(bt(tt,i),bt(At,e),bt(pt,null),i.nodeType){case 9:case 11:e=(e=i.documentElement)&&(e=e.namespaceURI)?wg(e):0;break;default:if(e=i.tagName,i=i.namespaceURI)i=wg(i),e=Dg(i,e);else switch(e){case"svg":e=1;break;case"math":e=2;break;default:e=0}}J(pt),bt(pt,e)}function It(){J(pt),J(At),J(tt)}function jt(e){e.memoizedState!==null&&bt(_t,e);var i=pt.current,a=Dg(i,e.type);i!==a&&(bt(At,e),bt(pt,a))}function Jt(e){At.current===e&&(J(pt),J(At)),_t.current===e&&(J(_t),zo._currentValue=$)}var qe,he;function Se(e){if(qe===void 0)try{throw Error()}catch(a){var i=a.stack.trim().match(/\n( *(at )?)/);qe=i&&i[1]||"",he=-1<a.stack.indexOf(`
    at`)?" (<anonymous>)":-1<a.stack.indexOf("@")?"@unknown:0:0":""}return`
`+qe+e+he}var ye=!1;function de(e,i){if(!e||ye)return"";ye=!0;var a=Error.prepareStackTrace;Error.prepareStackTrace=void 0;try{var o={DetermineComponentFrameRoot:function(){try{if(i){var Et=function(){throw Error()};if(Object.defineProperty(Et.prototype,"props",{set:function(){throw Error()}}),typeof Reflect=="object"&&Reflect.construct){try{Reflect.construct(Et,[])}catch(ut){var lt=ut}Reflect.construct(e,[],Et)}else{try{Et.call()}catch(ut){lt=ut}e.call(Et.prototype)}}else{try{throw Error()}catch(ut){lt=ut}(Et=e())&&typeof Et.catch=="function"&&Et.catch(function(){})}}catch(ut){if(ut&&lt&&typeof ut.stack=="string")return[ut.stack,lt.stack]}return[null,null]}};o.DetermineComponentFrameRoot.displayName="DetermineComponentFrameRoot";var u=Object.getOwnPropertyDescriptor(o.DetermineComponentFrameRoot,"name");u&&u.configurable&&Object.defineProperty(o.DetermineComponentFrameRoot,"name",{value:"DetermineComponentFrameRoot"});var h=o.DetermineComponentFrameRoot(),x=h[0],C=h[1];if(x&&C){var G=x.split(`
`),it=C.split(`
`);for(u=o=0;o<G.length&&!G[o].includes("DetermineComponentFrameRoot");)o++;for(;u<it.length&&!it[u].includes("DetermineComponentFrameRoot");)u++;if(o===G.length||u===it.length)for(o=G.length-1,u=it.length-1;1<=o&&0<=u&&G[o]!==it[u];)u--;for(;1<=o&&0<=u;o--,u--)if(G[o]!==it[u]){if(o!==1||u!==1)do if(o--,u--,0>u||G[o]!==it[u]){var vt=`
`+G[o].replace(" at new "," at ");return e.displayName&&vt.includes("<anonymous>")&&(vt=vt.replace("<anonymous>",e.displayName)),vt}while(1<=o&&0<=u);break}}}finally{ye=!1,Error.prepareStackTrace=a}return(a=e?e.displayName||e.name:"")?Se(a):""}function nn(e,i){switch(e.tag){case 26:case 27:case 5:return Se(e.type);case 16:return Se("Lazy");case 13:return e.child!==i&&i!==null?Se("Suspense Fallback"):Se("Suspense");case 19:return Se("SuspenseList");case 0:case 15:return de(e.type,!1);case 11:return de(e.type.render,!1);case 1:return de(e.type,!0);case 31:return Se("Activity");default:return""}}function an(e){try{var i="",a=null;do i+=nn(e,a),a=e,e=e.return;while(e);return i}catch(o){return`
Error generating stack: `+o.message+`
`+o.stack}}var sn=Object.prototype.hasOwnProperty,fn=r.unstable_scheduleCallback,We=r.unstable_cancelCallback,rn=r.unstable_shouldYield,Z=r.unstable_requestPaint,Fe=r.unstable_now,Ce=r.unstable_getCurrentPriorityLevel,L=r.unstable_ImmediatePriority,E=r.unstable_UserBlockingPriority,et=r.unstable_NormalPriority,rt=r.unstable_LowPriority,mt=r.unstable_IdlePriority,Rt=r.log,Nt=r.unstable_setDisableYieldValue,ft=null,gt=null;function wt(e){if(typeof Rt=="function"&&Nt(e),gt&&typeof gt.setStrictMode=="function")try{gt.setStrictMode(ft,e)}catch{}}var Bt=Math.clz32?Math.clz32:Qt,Ot=Math.log,Ut=Math.LN2;function Qt(e){return e>>>=0,e===0?32:31-(Ot(e)/Ut|0)|0}var $t=256,ae=262144,W=4194304;function Ct(e){var i=e&42;if(i!==0)return i;switch(e&-e){case 1:return 1;case 2:return 2;case 4:return 4;case 8:return 8;case 16:return 16;case 32:return 32;case 64:return 64;case 128:return 128;case 256:case 512:case 1024:case 2048:case 4096:case 8192:case 16384:case 32768:case 65536:case 131072:return e&261888;case 262144:case 524288:case 1048576:case 2097152:return e&3932160;case 4194304:case 8388608:case 16777216:case 33554432:return e&62914560;case 67108864:return 67108864;case 134217728:return 134217728;case 268435456:return 268435456;case 536870912:return 536870912;case 1073741824:return 0;default:return e}}function St(e,i,a){var o=e.pendingLanes;if(o===0)return 0;var u=0,h=e.suspendedLanes,x=e.pingedLanes;e=e.warmLanes;var C=o&134217727;return C!==0?(o=C&~h,o!==0?u=Ct(o):(x&=C,x!==0?u=Ct(x):a||(a=C&~e,a!==0&&(u=Ct(a))))):(C=o&~h,C!==0?u=Ct(C):x!==0?u=Ct(x):a||(a=o&~e,a!==0&&(u=Ct(a)))),u===0?0:i!==0&&i!==u&&(i&h)===0&&(h=u&-u,a=i&-i,h>=a||h===32&&(a&4194048)!==0)?i:u}function Dt(e,i){return(e.pendingLanes&~(e.suspendedLanes&~e.pingedLanes)&i)===0}function Ft(e,i){switch(e){case 1:case 2:case 4:case 8:case 64:return i+250;case 16:case 32:case 128:case 256:case 512:case 1024:case 2048:case 4096:case 8192:case 16384:case 32768:case 65536:case 131072:case 262144:case 524288:case 1048576:case 2097152:return i+5e3;case 4194304:case 8388608:case 16777216:case 33554432:return-1;case 67108864:case 134217728:case 268435456:case 536870912:case 1073741824:return-1;default:return-1}}function Tt(){var e=W;return W<<=1,(W&62914560)===0&&(W=4194304),e}function Yt(e){for(var i=[],a=0;31>a;a++)i.push(e);return i}function Vt(e,i){e.pendingLanes|=i,i!==268435456&&(e.suspendedLanes=0,e.pingedLanes=0,e.warmLanes=0)}function Ke(e,i,a,o,u,h){var x=e.pendingLanes;e.pendingLanes=a,e.suspendedLanes=0,e.pingedLanes=0,e.warmLanes=0,e.expiredLanes&=a,e.entangledLanes&=a,e.errorRecoveryDisabledLanes&=a,e.shellSuspendCounter=0;var C=e.entanglements,G=e.expirationTimes,it=e.hiddenUpdates;for(a=x&~a;0<a;){var vt=31-Bt(a),Et=1<<vt;C[vt]=0,G[vt]=-1;var lt=it[vt];if(lt!==null)for(it[vt]=null,vt=0;vt<lt.length;vt++){var ut=lt[vt];ut!==null&&(ut.lane&=-536870913)}a&=~Et}o!==0&&Ne(e,o,0),h!==0&&u===0&&e.tag!==0&&(e.suspendedLanes|=h&~(x&~i))}function Ne(e,i,a){e.pendingLanes|=i,e.suspendedLanes&=~i;var o=31-Bt(i);e.entangledLanes|=i,e.entanglements[o]=e.entanglements[o]|1073741824|a&261930}function $n(e,i){var a=e.entangledLanes|=i;for(e=e.entanglements;a;){var o=31-Bt(a),u=1<<o;u&i|e[o]&i&&(e[o]|=i),a&=~u}}function ti(e,i){var a=i&-i;return a=(a&42)!==0?1:jr(a),(a&(e.suspendedLanes|i))!==0?0:a}function jr(e){switch(e){case 2:e=1;break;case 8:e=4;break;case 32:e=16;break;case 256:case 512:case 1024:case 2048:case 4096:case 8192:case 16384:case 32768:case 65536:case 131072:case 262144:case 524288:case 1048576:case 2097152:case 4194304:case 8388608:case 16777216:case 33554432:e=128;break;case 268435456:e=134217728;break;default:e=0}return e}function Jr(e){return e&=-e,2<e?8<e?(e&134217727)!==0?32:268435456:8:2}function Qr(){var e=H.p;return e!==0?e:(e=window.event,e===void 0?32:$g(e.type))}function qs(e,i){var a=H.p;try{return H.p=e,i()}finally{H.p=a}}var Ii=Math.random().toString(36).slice(2),pn="__reactFiber$"+Ii,Cn="__reactProps$"+Ii,Wn="__reactContainer$"+Ii,hs="__reactEvents$"+Ii,hl="__reactListeners$"+Ii,dl="__reactHandles$"+Ii,ds="__reactResources$"+Ii,Ca="__reactMarker$"+Ii;function wa(e){delete e[pn],delete e[Cn],delete e[hs],delete e[hl],delete e[dl]}function Qi(e){var i=e[pn];if(i)return i;for(var a=e.parentNode;a;){if(i=a[Wn]||a[pn]){if(a=i.alternate,i.child!==null||a!==null&&a.child!==null)for(e=zg(e);e!==null;){if(a=e[pn])return a;e=zg(e)}return i}e=a,a=e.parentNode}return null}function $i(e){if(e=e[pn]||e[Wn]){var i=e.tag;if(i===5||i===6||i===13||i===31||i===26||i===27||i===3)return e}return null}function ps(e){var i=e.tag;if(i===5||i===26||i===27||i===6)return e.stateNode;throw Error(s(33))}function Da(e){var i=e[ds];return i||(i=e[ds]={hoistableStyles:new Map,hoistableScripts:new Map}),i}function mn(e){e[Ca]=!0}var pl=new Set,R={};function Y(e,i){ot(e,i),ot(e+"Capture",i)}function ot(e,i){for(R[e]=i,e=0;e<i.length;e++)pl.add(i[e])}var at=RegExp("^[:A-Z_a-z\\u00C0-\\u00D6\\u00D8-\\u00F6\\u00F8-\\u02FF\\u0370-\\u037D\\u037F-\\u1FFF\\u200C-\\u200D\\u2070-\\u218F\\u2C00-\\u2FEF\\u3001-\\uD7FF\\uF900-\\uFDCF\\uFDF0-\\uFFFD][:A-Z_a-z\\u00C0-\\u00D6\\u00D8-\\u00F6\\u00F8-\\u02FF\\u0370-\\u037D\\u037F-\\u1FFF\\u200C-\\u200D\\u2070-\\u218F\\u2C00-\\u2FEF\\u3001-\\uD7FF\\uF900-\\uFDCF\\uFDF0-\\uFFFD\\-.0-9\\u00B7\\u0300-\\u036F\\u203F-\\u2040]*$"),st={},Pt={};function Gt(e){return sn.call(Pt,e)?!0:sn.call(st,e)?!1:at.test(e)?Pt[e]=!0:(st[e]=!0,!1)}function Lt(e,i,a){if(Gt(i))if(a===null)e.removeAttribute(i);else{switch(typeof a){case"undefined":case"function":case"symbol":e.removeAttribute(i);return;case"boolean":var o=i.toLowerCase().slice(0,5);if(o!=="data-"&&o!=="aria-"){e.removeAttribute(i);return}}e.setAttribute(i,""+a)}}function Xt(e,i,a){if(a===null)e.removeAttribute(i);else{switch(typeof a){case"undefined":case"function":case"symbol":case"boolean":e.removeAttribute(i);return}e.setAttribute(i,""+a)}}function kt(e,i,a,o){if(o===null)e.removeAttribute(a);else{switch(typeof o){case"undefined":case"function":case"symbol":case"boolean":e.removeAttribute(a);return}e.setAttributeNS(i,a,""+o)}}function te(e){switch(typeof e){case"bigint":case"boolean":case"number":case"string":case"undefined":return e;case"object":return e;default:return""}}function oe(e){var i=e.type;return(e=e.nodeName)&&e.toLowerCase()==="input"&&(i==="checkbox"||i==="radio")}function Kt(e,i,a){var o=Object.getOwnPropertyDescriptor(e.constructor.prototype,i);if(!e.hasOwnProperty(i)&&typeof o<"u"&&typeof o.get=="function"&&typeof o.set=="function"){var u=o.get,h=o.set;return Object.defineProperty(e,i,{configurable:!0,get:function(){return u.call(this)},set:function(x){a=""+x,h.call(this,x)}}),Object.defineProperty(e,i,{enumerable:o.enumerable}),{getValue:function(){return a},setValue:function(x){a=""+x},stopTracking:function(){e._valueTracker=null,delete e[i]}}}}function Te(e){if(!e._valueTracker){var i=oe(e)?"checked":"value";e._valueTracker=Kt(e,i,""+e[i])}}function je(e){if(!e)return!1;var i=e._valueTracker;if(!i)return!0;var a=i.getValue(),o="";return e&&(o=oe(e)?e.checked?"true":"false":e.value),e=o,e!==a?(i.setValue(e),!0):!1}function Ve(e){if(e=e||(typeof document<"u"?document:void 0),typeof e>"u")return null;try{return e.activeElement||e.body}catch{return e.body}}var Ue=/[\n"\\]/g;function Le(e){return e.replace(Ue,function(i){return"\\"+i.charCodeAt(0).toString(16)+" "})}function Ht(e,i,a,o,u,h,x,C){e.name="",x!=null&&typeof x!="function"&&typeof x!="symbol"&&typeof x!="boolean"?e.type=x:e.removeAttribute("type"),i!=null?x==="number"?(i===0&&e.value===""||e.value!=i)&&(e.value=""+te(i)):e.value!==""+te(i)&&(e.value=""+te(i)):x!=="submit"&&x!=="reset"||e.removeAttribute("value"),i!=null?pe(e,x,te(i)):a!=null?pe(e,x,te(a)):o!=null&&e.removeAttribute("value"),u==null&&h!=null&&(e.defaultChecked=!!h),u!=null&&(e.checked=u&&typeof u!="function"&&typeof u!="symbol"),C!=null&&typeof C!="function"&&typeof C!="symbol"&&typeof C!="boolean"?e.name=""+te(C):e.removeAttribute("name")}function Pn(e,i,a,o,u,h,x,C){if(h!=null&&typeof h!="function"&&typeof h!="symbol"&&typeof h!="boolean"&&(e.type=h),i!=null||a!=null){if(!(h!=="submit"&&h!=="reset"||i!=null)){Te(e);return}a=a!=null?""+te(a):"",i=i!=null?""+te(i):a,C||i===e.value||(e.value=i),e.defaultValue=i}o=o??u,o=typeof o!="function"&&typeof o!="symbol"&&!!o,e.checked=C?e.checked:!!o,e.defaultChecked=!!o,x!=null&&typeof x!="function"&&typeof x!="symbol"&&typeof x!="boolean"&&(e.name=x),Te(e)}function pe(e,i,a){i==="number"&&Ve(e.ownerDocument)===e||e.defaultValue===""+a||(e.defaultValue=""+a)}function yn(e,i,a,o){if(e=e.options,i){i={};for(var u=0;u<a.length;u++)i["$"+a[u]]=!0;for(a=0;a<e.length;a++)u=i.hasOwnProperty("$"+e[a].value),e[a].selected!==u&&(e[a].selected=u),u&&o&&(e[a].defaultSelected=!0)}else{for(a=""+te(a),i=null,u=0;u<e.length;u++){if(e[u].value===a){e[u].selected=!0,o&&(e[u].defaultSelected=!0);return}i!==null||e[u].disabled||(i=e[u])}i!==null&&(i.selected=!0)}}function ei(e,i,a){if(i!=null&&(i=""+te(i),i!==e.value&&(e.value=i),a==null)){e.defaultValue!==i&&(e.defaultValue=i);return}e.defaultValue=a!=null?""+te(a):""}function Ai(e,i,a,o){if(i==null){if(o!=null){if(a!=null)throw Error(s(92));if(j(o)){if(1<o.length)throw Error(s(93));o=o[0]}a=o}a==null&&(a=""),i=a}a=te(i),e.defaultValue=a,o=e.textContent,o===a&&o!==""&&o!==null&&(e.value=o),Te(e)}function ni(e,i){if(i){var a=e.firstChild;if(a&&a===e.lastChild&&a.nodeType===3){a.nodeValue=i;return}}e.textContent=i}var Oe=new Set("animationIterationCount aspectRatio borderImageOutset borderImageSlice borderImageWidth boxFlex boxFlexGroup boxOrdinalGroup columnCount columns flex flexGrow flexPositive flexShrink flexNegative flexOrder gridArea gridRow gridRowEnd gridRowSpan gridRowStart gridColumn gridColumnEnd gridColumnSpan gridColumnStart fontWeight lineClamp lineHeight opacity order orphans scale tabSize widows zIndex zoom fillOpacity floodOpacity stopOpacity strokeDasharray strokeDashoffset strokeMiterlimit strokeOpacity strokeWidth MozAnimationIterationCount MozBoxFlex MozBoxFlexGroup MozLineClamp msAnimationIterationCount msFlex msZoom msFlexGrow msFlexNegative msFlexOrder msFlexPositive msFlexShrink msGridColumn msGridColumnSpan msGridRow msGridRowSpan WebkitAnimationIterationCount WebkitBoxFlex WebKitBoxFlexGroup WebkitBoxOrdinalGroup WebkitColumnCount WebkitColumns WebkitFlex WebkitFlexGrow WebkitFlexPositive WebkitFlexShrink WebkitLineClamp".split(" "));function Je(e,i,a){var o=i.indexOf("--")===0;a==null||typeof a=="boolean"||a===""?o?e.setProperty(i,""):i==="float"?e.cssFloat="":e[i]="":o?e.setProperty(i,a):typeof a!="number"||a===0||Oe.has(i)?i==="float"?e.cssFloat=a:e[i]=(""+a).trim():e[i]=a+"px"}function Ri(e,i,a){if(i!=null&&typeof i!="object")throw Error(s(62));if(e=e.style,a!=null){for(var o in a)!a.hasOwnProperty(o)||i!=null&&i.hasOwnProperty(o)||(o.indexOf("--")===0?e.setProperty(o,""):o==="float"?e.cssFloat="":e[o]="");for(var u in i)o=i[u],i.hasOwnProperty(u)&&a[u]!==o&&Je(e,u,o)}else for(var h in i)i.hasOwnProperty(h)&&Je(e,h,i[h])}function De(e){if(e.indexOf("-")===-1)return!1;switch(e){case"annotation-xml":case"color-profile":case"font-face":case"font-face-src":case"font-face-uri":case"font-face-format":case"font-face-name":case"missing-glyph":return!1;default:return!0}}var zi=new Map([["acceptCharset","accept-charset"],["htmlFor","for"],["httpEquiv","http-equiv"],["crossOrigin","crossorigin"],["accentHeight","accent-height"],["alignmentBaseline","alignment-baseline"],["arabicForm","arabic-form"],["baselineShift","baseline-shift"],["capHeight","cap-height"],["clipPath","clip-path"],["clipRule","clip-rule"],["colorInterpolation","color-interpolation"],["colorInterpolationFilters","color-interpolation-filters"],["colorProfile","color-profile"],["colorRendering","color-rendering"],["dominantBaseline","dominant-baseline"],["enableBackground","enable-background"],["fillOpacity","fill-opacity"],["fillRule","fill-rule"],["floodColor","flood-color"],["floodOpacity","flood-opacity"],["fontFamily","font-family"],["fontSize","font-size"],["fontSizeAdjust","font-size-adjust"],["fontStretch","font-stretch"],["fontStyle","font-style"],["fontVariant","font-variant"],["fontWeight","font-weight"],["glyphName","glyph-name"],["glyphOrientationHorizontal","glyph-orientation-horizontal"],["glyphOrientationVertical","glyph-orientation-vertical"],["horizAdvX","horiz-adv-x"],["horizOriginX","horiz-origin-x"],["imageRendering","image-rendering"],["letterSpacing","letter-spacing"],["lightingColor","lighting-color"],["markerEnd","marker-end"],["markerMid","marker-mid"],["markerStart","marker-start"],["overlinePosition","overline-position"],["overlineThickness","overline-thickness"],["paintOrder","paint-order"],["panose-1","panose-1"],["pointerEvents","pointer-events"],["renderingIntent","rendering-intent"],["shapeRendering","shape-rendering"],["stopColor","stop-color"],["stopOpacity","stop-opacity"],["strikethroughPosition","strikethrough-position"],["strikethroughThickness","strikethrough-thickness"],["strokeDasharray","stroke-dasharray"],["strokeDashoffset","stroke-dashoffset"],["strokeLinecap","stroke-linecap"],["strokeLinejoin","stroke-linejoin"],["strokeMiterlimit","stroke-miterlimit"],["strokeOpacity","stroke-opacity"],["strokeWidth","stroke-width"],["textAnchor","text-anchor"],["textDecoration","text-decoration"],["textRendering","text-rendering"],["transformOrigin","transform-origin"],["underlinePosition","underline-position"],["underlineThickness","underline-thickness"],["unicodeBidi","unicode-bidi"],["unicodeRange","unicode-range"],["unitsPerEm","units-per-em"],["vAlphabetic","v-alphabetic"],["vHanging","v-hanging"],["vIdeographic","v-ideographic"],["vMathematical","v-mathematical"],["vectorEffect","vector-effect"],["vertAdvY","vert-adv-y"],["vertOriginX","vert-origin-x"],["vertOriginY","vert-origin-y"],["wordSpacing","word-spacing"],["writingMode","writing-mode"],["xmlnsXlink","xmlns:xlink"],["xHeight","x-height"]]),Na=/^[\u0000-\u001F ]*j[\r\n\t]*a[\r\n\t]*v[\r\n\t]*a[\r\n\t]*s[\r\n\t]*c[\r\n\t]*r[\r\n\t]*i[\r\n\t]*p[\r\n\t]*t[\r\n\t]*:/i;function ms(e){return Na.test(""+e)?"javascript:throw new Error('React has blocked a javascript: URL as a security precaution.')":e}function ta(){}var pu=null;function mu(e){return e=e.target||e.srcElement||window,e.correspondingUseElement&&(e=e.correspondingUseElement),e.nodeType===3?e.parentNode:e}var Ys=null,Zs=null;function Cp(e){var i=$i(e);if(i&&(e=i.stateNode)){var a=e[Cn]||null;t:switch(e=i.stateNode,i.type){case"input":if(Ht(e,a.value,a.defaultValue,a.defaultValue,a.checked,a.defaultChecked,a.type,a.name),i=a.name,a.type==="radio"&&i!=null){for(a=e;a.parentNode;)a=a.parentNode;for(a=a.querySelectorAll('input[name="'+Le(""+i)+'"][type="radio"]'),i=0;i<a.length;i++){var o=a[i];if(o!==e&&o.form===e.form){var u=o[Cn]||null;if(!u)throw Error(s(90));Ht(o,u.value,u.defaultValue,u.defaultValue,u.checked,u.defaultChecked,u.type,u.name)}}for(i=0;i<a.length;i++)o=a[i],o.form===e.form&&je(o)}break t;case"textarea":ei(e,a.value,a.defaultValue);break t;case"select":i=a.value,i!=null&&yn(e,!!a.multiple,i,!1)}}}var gu=!1;function wp(e,i,a){if(gu)return e(i,a);gu=!0;try{var o=e(i);return o}finally{if(gu=!1,(Ys!==null||Zs!==null)&&(ec(),Ys&&(i=Ys,e=Zs,Zs=Ys=null,Cp(i),e)))for(i=0;i<e.length;i++)Cp(e[i])}}function $r(e,i){var a=e.stateNode;if(a===null)return null;var o=a[Cn]||null;if(o===null)return null;a=o[i];t:switch(i){case"onClick":case"onClickCapture":case"onDoubleClick":case"onDoubleClickCapture":case"onMouseDown":case"onMouseDownCapture":case"onMouseMove":case"onMouseMoveCapture":case"onMouseUp":case"onMouseUpCapture":case"onMouseEnter":(o=!o.disabled)||(e=e.type,o=!(e==="button"||e==="input"||e==="select"||e==="textarea")),e=!o;break t;default:e=!1}if(e)return null;if(a&&typeof a!="function")throw Error(s(231,i,typeof a));return a}var ea=!(typeof window>"u"||typeof window.document>"u"||typeof window.document.createElement>"u"),vu=!1;if(ea)try{var to={};Object.defineProperty(to,"passive",{get:function(){vu=!0}}),window.addEventListener("test",to,to),window.removeEventListener("test",to,to)}catch{vu=!1}var Ua=null,_u=null,ml=null;function Dp(){if(ml)return ml;var e,i=_u,a=i.length,o,u="value"in Ua?Ua.value:Ua.textContent,h=u.length;for(e=0;e<a&&i[e]===u[e];e++);var x=a-e;for(o=1;o<=x&&i[a-o]===u[h-o];o++);return ml=u.slice(e,1<o?1-o:void 0)}function gl(e){var i=e.keyCode;return"charCode"in e?(e=e.charCode,e===0&&i===13&&(e=13)):e=i,e===10&&(e=13),32<=e||e===13?e:0}function vl(){return!0}function Np(){return!1}function qn(e){function i(a,o,u,h,x){this._reactName=a,this._targetInst=u,this.type=o,this.nativeEvent=h,this.target=x,this.currentTarget=null;for(var C in e)e.hasOwnProperty(C)&&(a=e[C],this[C]=a?a(h):h[C]);return this.isDefaultPrevented=(h.defaultPrevented!=null?h.defaultPrevented:h.returnValue===!1)?vl:Np,this.isPropagationStopped=Np,this}return _(i.prototype,{preventDefault:function(){this.defaultPrevented=!0;var a=this.nativeEvent;a&&(a.preventDefault?a.preventDefault():typeof a.returnValue!="unknown"&&(a.returnValue=!1),this.isDefaultPrevented=vl)},stopPropagation:function(){var a=this.nativeEvent;a&&(a.stopPropagation?a.stopPropagation():typeof a.cancelBubble!="unknown"&&(a.cancelBubble=!0),this.isPropagationStopped=vl)},persist:function(){},isPersistent:vl}),i}var gs={eventPhase:0,bubbles:0,cancelable:0,timeStamp:function(e){return e.timeStamp||Date.now()},defaultPrevented:0,isTrusted:0},_l=qn(gs),eo=_({},gs,{view:0,detail:0}),Rx=qn(eo),xu,Su,no,xl=_({},eo,{screenX:0,screenY:0,clientX:0,clientY:0,pageX:0,pageY:0,ctrlKey:0,shiftKey:0,altKey:0,metaKey:0,getModifierState:Mu,button:0,buttons:0,relatedTarget:function(e){return e.relatedTarget===void 0?e.fromElement===e.srcElement?e.toElement:e.fromElement:e.relatedTarget},movementX:function(e){return"movementX"in e?e.movementX:(e!==no&&(no&&e.type==="mousemove"?(xu=e.screenX-no.screenX,Su=e.screenY-no.screenY):Su=xu=0,no=e),xu)},movementY:function(e){return"movementY"in e?e.movementY:Su}}),Up=qn(xl),Cx=_({},xl,{dataTransfer:0}),wx=qn(Cx),Dx=_({},eo,{relatedTarget:0}),yu=qn(Dx),Nx=_({},gs,{animationName:0,elapsedTime:0,pseudoElement:0}),Ux=qn(Nx),Lx=_({},gs,{clipboardData:function(e){return"clipboardData"in e?e.clipboardData:window.clipboardData}}),Ox=qn(Lx),Px=_({},gs,{data:0}),Lp=qn(Px),Ix={Esc:"Escape",Spacebar:" ",Left:"ArrowLeft",Up:"ArrowUp",Right:"ArrowRight",Down:"ArrowDown",Del:"Delete",Win:"OS",Menu:"ContextMenu",Apps:"ContextMenu",Scroll:"ScrollLock",MozPrintableKey:"Unidentified"},zx={8:"Backspace",9:"Tab",12:"Clear",13:"Enter",16:"Shift",17:"Control",18:"Alt",19:"Pause",20:"CapsLock",27:"Escape",32:" ",33:"PageUp",34:"PageDown",35:"End",36:"Home",37:"ArrowLeft",38:"ArrowUp",39:"ArrowRight",40:"ArrowDown",45:"Insert",46:"Delete",112:"F1",113:"F2",114:"F3",115:"F4",116:"F5",117:"F6",118:"F7",119:"F8",120:"F9",121:"F10",122:"F11",123:"F12",144:"NumLock",145:"ScrollLock",224:"Meta"},Fx={Alt:"altKey",Control:"ctrlKey",Meta:"metaKey",Shift:"shiftKey"};function Bx(e){var i=this.nativeEvent;return i.getModifierState?i.getModifierState(e):(e=Fx[e])?!!i[e]:!1}function Mu(){return Bx}var Hx=_({},eo,{key:function(e){if(e.key){var i=Ix[e.key]||e.key;if(i!=="Unidentified")return i}return e.type==="keypress"?(e=gl(e),e===13?"Enter":String.fromCharCode(e)):e.type==="keydown"||e.type==="keyup"?zx[e.keyCode]||"Unidentified":""},code:0,location:0,ctrlKey:0,shiftKey:0,altKey:0,metaKey:0,repeat:0,locale:0,getModifierState:Mu,charCode:function(e){return e.type==="keypress"?gl(e):0},keyCode:function(e){return e.type==="keydown"||e.type==="keyup"?e.keyCode:0},which:function(e){return e.type==="keypress"?gl(e):e.type==="keydown"||e.type==="keyup"?e.keyCode:0}}),Gx=qn(Hx),Vx=_({},xl,{pointerId:0,width:0,height:0,pressure:0,tangentialPressure:0,tiltX:0,tiltY:0,twist:0,pointerType:0,isPrimary:0}),Op=qn(Vx),kx=_({},eo,{touches:0,targetTouches:0,changedTouches:0,altKey:0,metaKey:0,ctrlKey:0,shiftKey:0,getModifierState:Mu}),Xx=qn(kx),Wx=_({},gs,{propertyName:0,elapsedTime:0,pseudoElement:0}),qx=qn(Wx),Yx=_({},xl,{deltaX:function(e){return"deltaX"in e?e.deltaX:"wheelDeltaX"in e?-e.wheelDeltaX:0},deltaY:function(e){return"deltaY"in e?e.deltaY:"wheelDeltaY"in e?-e.wheelDeltaY:"wheelDelta"in e?-e.wheelDelta:0},deltaZ:0,deltaMode:0}),Zx=qn(Yx),Kx=_({},gs,{newState:0,oldState:0}),jx=qn(Kx),Jx=[9,13,27,32],Eu=ea&&"CompositionEvent"in window,io=null;ea&&"documentMode"in document&&(io=document.documentMode);var Qx=ea&&"TextEvent"in window&&!io,Pp=ea&&(!Eu||io&&8<io&&11>=io),Ip=" ",zp=!1;function Fp(e,i){switch(e){case"keyup":return Jx.indexOf(i.keyCode)!==-1;case"keydown":return i.keyCode!==229;case"keypress":case"mousedown":case"focusout":return!0;default:return!1}}function Bp(e){return e=e.detail,typeof e=="object"&&"data"in e?e.data:null}var Ks=!1;function $x(e,i){switch(e){case"compositionend":return Bp(i);case"keypress":return i.which!==32?null:(zp=!0,Ip);case"textInput":return e=i.data,e===Ip&&zp?null:e;default:return null}}function tS(e,i){if(Ks)return e==="compositionend"||!Eu&&Fp(e,i)?(e=Dp(),ml=_u=Ua=null,Ks=!1,e):null;switch(e){case"paste":return null;case"keypress":if(!(i.ctrlKey||i.altKey||i.metaKey)||i.ctrlKey&&i.altKey){if(i.char&&1<i.char.length)return i.char;if(i.which)return String.fromCharCode(i.which)}return null;case"compositionend":return Pp&&i.locale!=="ko"?null:i.data;default:return null}}var eS={color:!0,date:!0,datetime:!0,"datetime-local":!0,email:!0,month:!0,number:!0,password:!0,range:!0,search:!0,tel:!0,text:!0,time:!0,url:!0,week:!0};function Hp(e){var i=e&&e.nodeName&&e.nodeName.toLowerCase();return i==="input"?!!eS[e.type]:i==="textarea"}function Gp(e,i,a,o){Ys?Zs?Zs.push(o):Zs=[o]:Ys=o,i=lc(i,"onChange"),0<i.length&&(a=new _l("onChange","change",null,a,o),e.push({event:a,listeners:i}))}var ao=null,so=null;function nS(e){Eg(e,0)}function Sl(e){var i=ps(e);if(je(i))return e}function Vp(e,i){if(e==="change")return i}var kp=!1;if(ea){var bu;if(ea){var Tu="oninput"in document;if(!Tu){var Xp=document.createElement("div");Xp.setAttribute("oninput","return;"),Tu=typeof Xp.oninput=="function"}bu=Tu}else bu=!1;kp=bu&&(!document.documentMode||9<document.documentMode)}function Wp(){ao&&(ao.detachEvent("onpropertychange",qp),so=ao=null)}function qp(e){if(e.propertyName==="value"&&Sl(so)){var i=[];Gp(i,so,e,mu(e)),wp(nS,i)}}function iS(e,i,a){e==="focusin"?(Wp(),ao=i,so=a,ao.attachEvent("onpropertychange",qp)):e==="focusout"&&Wp()}function aS(e){if(e==="selectionchange"||e==="keyup"||e==="keydown")return Sl(so)}function sS(e,i){if(e==="click")return Sl(i)}function rS(e,i){if(e==="input"||e==="change")return Sl(i)}function oS(e,i){return e===i&&(e!==0||1/e===1/i)||e!==e&&i!==i}var ii=typeof Object.is=="function"?Object.is:oS;function ro(e,i){if(ii(e,i))return!0;if(typeof e!="object"||e===null||typeof i!="object"||i===null)return!1;var a=Object.keys(e),o=Object.keys(i);if(a.length!==o.length)return!1;for(o=0;o<a.length;o++){var u=a[o];if(!sn.call(i,u)||!ii(e[u],i[u]))return!1}return!0}function Yp(e){for(;e&&e.firstChild;)e=e.firstChild;return e}function Zp(e,i){var a=Yp(e);e=0;for(var o;a;){if(a.nodeType===3){if(o=e+a.textContent.length,e<=i&&o>=i)return{node:a,offset:i-e};e=o}t:{for(;a;){if(a.nextSibling){a=a.nextSibling;break t}a=a.parentNode}a=void 0}a=Yp(a)}}function Kp(e,i){return e&&i?e===i?!0:e&&e.nodeType===3?!1:i&&i.nodeType===3?Kp(e,i.parentNode):"contains"in e?e.contains(i):e.compareDocumentPosition?!!(e.compareDocumentPosition(i)&16):!1:!1}function jp(e){e=e!=null&&e.ownerDocument!=null&&e.ownerDocument.defaultView!=null?e.ownerDocument.defaultView:window;for(var i=Ve(e.document);i instanceof e.HTMLIFrameElement;){try{var a=typeof i.contentWindow.location.href=="string"}catch{a=!1}if(a)e=i.contentWindow;else break;i=Ve(e.document)}return i}function Au(e){var i=e&&e.nodeName&&e.nodeName.toLowerCase();return i&&(i==="input"&&(e.type==="text"||e.type==="search"||e.type==="tel"||e.type==="url"||e.type==="password")||i==="textarea"||e.contentEditable==="true")}var lS=ea&&"documentMode"in document&&11>=document.documentMode,js=null,Ru=null,oo=null,Cu=!1;function Jp(e,i,a){var o=a.window===a?a.document:a.nodeType===9?a:a.ownerDocument;Cu||js==null||js!==Ve(o)||(o=js,"selectionStart"in o&&Au(o)?o={start:o.selectionStart,end:o.selectionEnd}:(o=(o.ownerDocument&&o.ownerDocument.defaultView||window).getSelection(),o={anchorNode:o.anchorNode,anchorOffset:o.anchorOffset,focusNode:o.focusNode,focusOffset:o.focusOffset}),oo&&ro(oo,o)||(oo=o,o=lc(Ru,"onSelect"),0<o.length&&(i=new _l("onSelect","select",null,i,a),e.push({event:i,listeners:o}),i.target=js)))}function vs(e,i){var a={};return a[e.toLowerCase()]=i.toLowerCase(),a["Webkit"+e]="webkit"+i,a["Moz"+e]="moz"+i,a}var Js={animationend:vs("Animation","AnimationEnd"),animationiteration:vs("Animation","AnimationIteration"),animationstart:vs("Animation","AnimationStart"),transitionrun:vs("Transition","TransitionRun"),transitionstart:vs("Transition","TransitionStart"),transitioncancel:vs("Transition","TransitionCancel"),transitionend:vs("Transition","TransitionEnd")},wu={},Qp={};ea&&(Qp=document.createElement("div").style,"AnimationEvent"in window||(delete Js.animationend.animation,delete Js.animationiteration.animation,delete Js.animationstart.animation),"TransitionEvent"in window||delete Js.transitionend.transition);function _s(e){if(wu[e])return wu[e];if(!Js[e])return e;var i=Js[e],a;for(a in i)if(i.hasOwnProperty(a)&&a in Qp)return wu[e]=i[a];return e}var $p=_s("animationend"),tm=_s("animationiteration"),em=_s("animationstart"),cS=_s("transitionrun"),uS=_s("transitionstart"),fS=_s("transitioncancel"),nm=_s("transitionend"),im=new Map,Du="abort auxClick beforeToggle cancel canPlay canPlayThrough click close contextMenu copy cut drag dragEnd dragEnter dragExit dragLeave dragOver dragStart drop durationChange emptied encrypted ended error gotPointerCapture input invalid keyDown keyPress keyUp load loadedData loadedMetadata loadStart lostPointerCapture mouseDown mouseMove mouseOut mouseOver mouseUp paste pause play playing pointerCancel pointerDown pointerMove pointerOut pointerOver pointerUp progress rateChange reset resize seeked seeking stalled submit suspend timeUpdate touchCancel touchEnd touchStart volumeChange scroll toggle touchMove waiting wheel".split(" ");Du.push("scrollEnd");function Ci(e,i){im.set(e,i),Y(i,[e])}var yl=typeof reportError=="function"?reportError:function(e){if(typeof window=="object"&&typeof window.ErrorEvent=="function"){var i=new window.ErrorEvent("error",{bubbles:!0,cancelable:!0,message:typeof e=="object"&&e!==null&&typeof e.message=="string"?String(e.message):String(e),error:e});if(!window.dispatchEvent(i))return}else if(typeof process=="object"&&typeof process.emit=="function"){process.emit("uncaughtException",e);return}console.error(e)},pi=[],Qs=0,Nu=0;function Ml(){for(var e=Qs,i=Nu=Qs=0;i<e;){var a=pi[i];pi[i++]=null;var o=pi[i];pi[i++]=null;var u=pi[i];pi[i++]=null;var h=pi[i];if(pi[i++]=null,o!==null&&u!==null){var x=o.pending;x===null?u.next=u:(u.next=x.next,x.next=u),o.pending=u}h!==0&&am(a,u,h)}}function El(e,i,a,o){pi[Qs++]=e,pi[Qs++]=i,pi[Qs++]=a,pi[Qs++]=o,Nu|=o,e.lanes|=o,e=e.alternate,e!==null&&(e.lanes|=o)}function Uu(e,i,a,o){return El(e,i,a,o),bl(e)}function xs(e,i){return El(e,null,null,i),bl(e)}function am(e,i,a){e.lanes|=a;var o=e.alternate;o!==null&&(o.lanes|=a);for(var u=!1,h=e.return;h!==null;)h.childLanes|=a,o=h.alternate,o!==null&&(o.childLanes|=a),h.tag===22&&(e=h.stateNode,e===null||e._visibility&1||(u=!0)),e=h,h=h.return;return e.tag===3?(h=e.stateNode,u&&i!==null&&(u=31-Bt(a),e=h.hiddenUpdates,o=e[u],o===null?e[u]=[i]:o.push(i),i.lane=a|536870912),h):null}function bl(e){if(50<Do)throw Do=0,Vf=null,Error(s(185));for(var i=e.return;i!==null;)e=i,i=e.return;return e.tag===3?e.stateNode:null}var $s={};function hS(e,i,a,o){this.tag=e,this.key=a,this.sibling=this.child=this.return=this.stateNode=this.type=this.elementType=null,this.index=0,this.refCleanup=this.ref=null,this.pendingProps=i,this.dependencies=this.memoizedState=this.updateQueue=this.memoizedProps=null,this.mode=o,this.subtreeFlags=this.flags=0,this.deletions=null,this.childLanes=this.lanes=0,this.alternate=null}function ai(e,i,a,o){return new hS(e,i,a,o)}function Lu(e){return e=e.prototype,!(!e||!e.isReactComponent)}function na(e,i){var a=e.alternate;return a===null?(a=ai(e.tag,i,e.key,e.mode),a.elementType=e.elementType,a.type=e.type,a.stateNode=e.stateNode,a.alternate=e,e.alternate=a):(a.pendingProps=i,a.type=e.type,a.flags=0,a.subtreeFlags=0,a.deletions=null),a.flags=e.flags&65011712,a.childLanes=e.childLanes,a.lanes=e.lanes,a.child=e.child,a.memoizedProps=e.memoizedProps,a.memoizedState=e.memoizedState,a.updateQueue=e.updateQueue,i=e.dependencies,a.dependencies=i===null?null:{lanes:i.lanes,firstContext:i.firstContext},a.sibling=e.sibling,a.index=e.index,a.ref=e.ref,a.refCleanup=e.refCleanup,a}function sm(e,i){e.flags&=65011714;var a=e.alternate;return a===null?(e.childLanes=0,e.lanes=i,e.child=null,e.subtreeFlags=0,e.memoizedProps=null,e.memoizedState=null,e.updateQueue=null,e.dependencies=null,e.stateNode=null):(e.childLanes=a.childLanes,e.lanes=a.lanes,e.child=a.child,e.subtreeFlags=0,e.deletions=null,e.memoizedProps=a.memoizedProps,e.memoizedState=a.memoizedState,e.updateQueue=a.updateQueue,e.type=a.type,i=a.dependencies,e.dependencies=i===null?null:{lanes:i.lanes,firstContext:i.firstContext}),e}function Tl(e,i,a,o,u,h){var x=0;if(o=e,typeof e=="function")Lu(e)&&(x=1);else if(typeof e=="string")x=vy(e,a,pt.current)?26:e==="html"||e==="head"||e==="body"?27:5;else t:switch(e){case N:return e=ai(31,a,i,u),e.elementType=N,e.lanes=h,e;case w:return Ss(a.children,u,h,i);case M:x=8,u|=24;break;case S:return e=ai(12,a,i,u|2),e.elementType=S,e.lanes=h,e;case F:return e=ai(13,a,i,u),e.elementType=F,e.lanes=h,e;case O:return e=ai(19,a,i,u),e.elementType=O,e.lanes=h,e;default:if(typeof e=="object"&&e!==null)switch(e.$$typeof){case D:x=10;break t;case P:x=9;break t;case A:x=11;break t;case I:x=14;break t;case T:x=16,o=null;break t}x=29,a=Error(s(130,e===null?"null":typeof e,"")),o=null}return i=ai(x,a,i,u),i.elementType=e,i.type=o,i.lanes=h,i}function Ss(e,i,a,o){return e=ai(7,e,o,i),e.lanes=a,e}function Ou(e,i,a){return e=ai(6,e,null,i),e.lanes=a,e}function rm(e){var i=ai(18,null,null,0);return i.stateNode=e,i}function Pu(e,i,a){return i=ai(4,e.children!==null?e.children:[],e.key,i),i.lanes=a,i.stateNode={containerInfo:e.containerInfo,pendingChildren:null,implementation:e.implementation},i}var om=new WeakMap;function mi(e,i){if(typeof e=="object"&&e!==null){var a=om.get(e);return a!==void 0?a:(i={value:e,source:i,stack:an(i)},om.set(e,i),i)}return{value:e,source:i,stack:an(i)}}var tr=[],er=0,Al=null,lo=0,gi=[],vi=0,La=null,Fi=1,Bi="";function ia(e,i){tr[er++]=lo,tr[er++]=Al,Al=e,lo=i}function lm(e,i,a){gi[vi++]=Fi,gi[vi++]=Bi,gi[vi++]=La,La=e;var o=Fi;e=Bi;var u=32-Bt(o)-1;o&=~(1<<u),a+=1;var h=32-Bt(i)+u;if(30<h){var x=u-u%5;h=(o&(1<<x)-1).toString(32),o>>=x,u-=x,Fi=1<<32-Bt(i)+u|a<<u|o,Bi=h+e}else Fi=1<<h|a<<u|o,Bi=e}function Iu(e){e.return!==null&&(ia(e,1),lm(e,1,0))}function zu(e){for(;e===Al;)Al=tr[--er],tr[er]=null,lo=tr[--er],tr[er]=null;for(;e===La;)La=gi[--vi],gi[vi]=null,Bi=gi[--vi],gi[vi]=null,Fi=gi[--vi],gi[vi]=null}function cm(e,i){gi[vi++]=Fi,gi[vi++]=Bi,gi[vi++]=La,Fi=i.id,Bi=i.overflow,La=e}var wn=null,Ye=null,Me=!1,Oa=null,_i=!1,Fu=Error(s(519));function Pa(e){var i=Error(s(418,1<arguments.length&&arguments[1]!==void 0&&arguments[1]?"text":"HTML",""));throw co(mi(i,e)),Fu}function um(e){var i=e.stateNode,a=e.type,o=e.memoizedProps;switch(i[pn]=e,i[Cn]=o,a){case"dialog":ge("cancel",i),ge("close",i);break;case"iframe":case"object":case"embed":ge("load",i);break;case"video":case"audio":for(a=0;a<Uo.length;a++)ge(Uo[a],i);break;case"source":ge("error",i);break;case"img":case"image":case"link":ge("error",i),ge("load",i);break;case"details":ge("toggle",i);break;case"input":ge("invalid",i),Pn(i,o.value,o.defaultValue,o.checked,o.defaultChecked,o.type,o.name,!0);break;case"select":ge("invalid",i);break;case"textarea":ge("invalid",i),Ai(i,o.value,o.defaultValue,o.children)}a=o.children,typeof a!="string"&&typeof a!="number"&&typeof a!="bigint"||i.textContent===""+a||o.suppressHydrationWarning===!0||Rg(i.textContent,a)?(o.popover!=null&&(ge("beforetoggle",i),ge("toggle",i)),o.onScroll!=null&&ge("scroll",i),o.onScrollEnd!=null&&ge("scrollend",i),o.onClick!=null&&(i.onclick=ta),i=!0):i=!1,i||Pa(e,!0)}function fm(e){for(wn=e.return;wn;)switch(wn.tag){case 5:case 31:case 13:_i=!1;return;case 27:case 3:_i=!0;return;default:wn=wn.return}}function nr(e){if(e!==wn)return!1;if(!Me)return fm(e),Me=!0,!1;var i=e.tag,a;if((a=i!==3&&i!==27)&&((a=i===5)&&(a=e.type,a=!(a!=="form"&&a!=="button")||ih(e.type,e.memoizedProps)),a=!a),a&&Ye&&Pa(e),fm(e),i===13){if(e=e.memoizedState,e=e!==null?e.dehydrated:null,!e)throw Error(s(317));Ye=Ig(e)}else if(i===31){if(e=e.memoizedState,e=e!==null?e.dehydrated:null,!e)throw Error(s(317));Ye=Ig(e)}else i===27?(i=Ye,Ka(e.type)?(e=lh,lh=null,Ye=e):Ye=i):Ye=wn?Si(e.stateNode.nextSibling):null;return!0}function ys(){Ye=wn=null,Me=!1}function Bu(){var e=Oa;return e!==null&&(jn===null?jn=e:jn.push.apply(jn,e),Oa=null),e}function co(e){Oa===null?Oa=[e]:Oa.push(e)}var Hu=U(null),Ms=null,aa=null;function Ia(e,i,a){bt(Hu,i._currentValue),i._currentValue=a}function sa(e){e._currentValue=Hu.current,J(Hu)}function Gu(e,i,a){for(;e!==null;){var o=e.alternate;if((e.childLanes&i)!==i?(e.childLanes|=i,o!==null&&(o.childLanes|=i)):o!==null&&(o.childLanes&i)!==i&&(o.childLanes|=i),e===a)break;e=e.return}}function Vu(e,i,a,o){var u=e.child;for(u!==null&&(u.return=e);u!==null;){var h=u.dependencies;if(h!==null){var x=u.child;h=h.firstContext;t:for(;h!==null;){var C=h;h=u;for(var G=0;G<i.length;G++)if(C.context===i[G]){h.lanes|=a,C=h.alternate,C!==null&&(C.lanes|=a),Gu(h.return,a,e),o||(x=null);break t}h=C.next}}else if(u.tag===18){if(x=u.return,x===null)throw Error(s(341));x.lanes|=a,h=x.alternate,h!==null&&(h.lanes|=a),Gu(x,a,e),x=null}else x=u.child;if(x!==null)x.return=u;else for(x=u;x!==null;){if(x===e){x=null;break}if(u=x.sibling,u!==null){u.return=x.return,x=u;break}x=x.return}u=x}}function ir(e,i,a,o){e=null;for(var u=i,h=!1;u!==null;){if(!h){if((u.flags&524288)!==0)h=!0;else if((u.flags&262144)!==0)break}if(u.tag===10){var x=u.alternate;if(x===null)throw Error(s(387));if(x=x.memoizedProps,x!==null){var C=u.type;ii(u.pendingProps.value,x.value)||(e!==null?e.push(C):e=[C])}}else if(u===_t.current){if(x=u.alternate,x===null)throw Error(s(387));x.memoizedState.memoizedState!==u.memoizedState.memoizedState&&(e!==null?e.push(zo):e=[zo])}u=u.return}e!==null&&Vu(i,e,a,o),i.flags|=262144}function Rl(e){for(e=e.firstContext;e!==null;){if(!ii(e.context._currentValue,e.memoizedValue))return!0;e=e.next}return!1}function Es(e){Ms=e,aa=null,e=e.dependencies,e!==null&&(e.firstContext=null)}function Dn(e){return hm(Ms,e)}function Cl(e,i){return Ms===null&&Es(e),hm(e,i)}function hm(e,i){var a=i._currentValue;if(i={context:i,memoizedValue:a,next:null},aa===null){if(e===null)throw Error(s(308));aa=i,e.dependencies={lanes:0,firstContext:i},e.flags|=524288}else aa=aa.next=i;return a}var dS=typeof AbortController<"u"?AbortController:function(){var e=[],i=this.signal={aborted:!1,addEventListener:function(a,o){e.push(o)}};this.abort=function(){i.aborted=!0,e.forEach(function(a){return a()})}},pS=r.unstable_scheduleCallback,mS=r.unstable_NormalPriority,gn={$$typeof:D,Consumer:null,Provider:null,_currentValue:null,_currentValue2:null,_threadCount:0};function ku(){return{controller:new dS,data:new Map,refCount:0}}function uo(e){e.refCount--,e.refCount===0&&pS(mS,function(){e.controller.abort()})}var fo=null,Xu=0,ar=0,sr=null;function gS(e,i){if(fo===null){var a=fo=[];Xu=0,ar=Zf(),sr={status:"pending",value:void 0,then:function(o){a.push(o)}}}return Xu++,i.then(dm,dm),i}function dm(){if(--Xu===0&&fo!==null){sr!==null&&(sr.status="fulfilled");var e=fo;fo=null,ar=0,sr=null;for(var i=0;i<e.length;i++)(0,e[i])()}}function vS(e,i){var a=[],o={status:"pending",value:null,reason:null,then:function(u){a.push(u)}};return e.then(function(){o.status="fulfilled",o.value=i;for(var u=0;u<a.length;u++)(0,a[u])(i)},function(u){for(o.status="rejected",o.reason=u,u=0;u<a.length;u++)(0,a[u])(void 0)}),o}var pm=B.S;B.S=function(e,i){J0=Fe(),typeof i=="object"&&i!==null&&typeof i.then=="function"&&gS(e,i),pm!==null&&pm(e,i)};var bs=U(null);function Wu(){var e=bs.current;return e!==null?e:ke.pooledCache}function wl(e,i){i===null?bt(bs,bs.current):bt(bs,i.pool)}function mm(){var e=Wu();return e===null?null:{parent:gn._currentValue,pool:e}}var rr=Error(s(460)),qu=Error(s(474)),Dl=Error(s(542)),Nl={then:function(){}};function gm(e){return e=e.status,e==="fulfilled"||e==="rejected"}function vm(e,i,a){switch(a=e[a],a===void 0?e.push(i):a!==i&&(i.then(ta,ta),i=a),i.status){case"fulfilled":return i.value;case"rejected":throw e=i.reason,xm(e),e;default:if(typeof i.status=="string")i.then(ta,ta);else{if(e=ke,e!==null&&100<e.shellSuspendCounter)throw Error(s(482));e=i,e.status="pending",e.then(function(o){if(i.status==="pending"){var u=i;u.status="fulfilled",u.value=o}},function(o){if(i.status==="pending"){var u=i;u.status="rejected",u.reason=o}})}switch(i.status){case"fulfilled":return i.value;case"rejected":throw e=i.reason,xm(e),e}throw As=i,rr}}function Ts(e){try{var i=e._init;return i(e._payload)}catch(a){throw a!==null&&typeof a=="object"&&typeof a.then=="function"?(As=a,rr):a}}var As=null;function _m(){if(As===null)throw Error(s(459));var e=As;return As=null,e}function xm(e){if(e===rr||e===Dl)throw Error(s(483))}var or=null,ho=0;function Ul(e){var i=ho;return ho+=1,or===null&&(or=[]),vm(or,e,i)}function po(e,i){i=i.props.ref,e.ref=i!==void 0?i:null}function Ll(e,i){throw i.$$typeof===g?Error(s(525)):(e=Object.prototype.toString.call(i),Error(s(31,e==="[object Object]"?"object with keys {"+Object.keys(i).join(", ")+"}":e)))}function Sm(e){function i(Q,k){if(e){var nt=Q.deletions;nt===null?(Q.deletions=[k],Q.flags|=16):nt.push(k)}}function a(Q,k){if(!e)return null;for(;k!==null;)i(Q,k),k=k.sibling;return null}function o(Q){for(var k=new Map;Q!==null;)Q.key!==null?k.set(Q.key,Q):k.set(Q.index,Q),Q=Q.sibling;return k}function u(Q,k){return Q=na(Q,k),Q.index=0,Q.sibling=null,Q}function h(Q,k,nt){return Q.index=nt,e?(nt=Q.alternate,nt!==null?(nt=nt.index,nt<k?(Q.flags|=67108866,k):nt):(Q.flags|=67108866,k)):(Q.flags|=1048576,k)}function x(Q){return e&&Q.alternate===null&&(Q.flags|=67108866),Q}function C(Q,k,nt,yt){return k===null||k.tag!==6?(k=Ou(nt,Q.mode,yt),k.return=Q,k):(k=u(k,nt),k.return=Q,k)}function G(Q,k,nt,yt){var ee=nt.type;return ee===w?vt(Q,k,nt.props.children,yt,nt.key):k!==null&&(k.elementType===ee||typeof ee=="object"&&ee!==null&&ee.$$typeof===T&&Ts(ee)===k.type)?(k=u(k,nt.props),po(k,nt),k.return=Q,k):(k=Tl(nt.type,nt.key,nt.props,null,Q.mode,yt),po(k,nt),k.return=Q,k)}function it(Q,k,nt,yt){return k===null||k.tag!==4||k.stateNode.containerInfo!==nt.containerInfo||k.stateNode.implementation!==nt.implementation?(k=Pu(nt,Q.mode,yt),k.return=Q,k):(k=u(k,nt.children||[]),k.return=Q,k)}function vt(Q,k,nt,yt,ee){return k===null||k.tag!==7?(k=Ss(nt,Q.mode,yt,ee),k.return=Q,k):(k=u(k,nt),k.return=Q,k)}function Et(Q,k,nt){if(typeof k=="string"&&k!==""||typeof k=="number"||typeof k=="bigint")return k=Ou(""+k,Q.mode,nt),k.return=Q,k;if(typeof k=="object"&&k!==null){switch(k.$$typeof){case y:return nt=Tl(k.type,k.key,k.props,null,Q.mode,nt),po(nt,k),nt.return=Q,nt;case b:return k=Pu(k,Q.mode,nt),k.return=Q,k;case T:return k=Ts(k),Et(Q,k,nt)}if(j(k)||q(k))return k=Ss(k,Q.mode,nt,null),k.return=Q,k;if(typeof k.then=="function")return Et(Q,Ul(k),nt);if(k.$$typeof===D)return Et(Q,Cl(Q,k),nt);Ll(Q,k)}return null}function lt(Q,k,nt,yt){var ee=k!==null?k.key:null;if(typeof nt=="string"&&nt!==""||typeof nt=="number"||typeof nt=="bigint")return ee!==null?null:C(Q,k,""+nt,yt);if(typeof nt=="object"&&nt!==null){switch(nt.$$typeof){case y:return nt.key===ee?G(Q,k,nt,yt):null;case b:return nt.key===ee?it(Q,k,nt,yt):null;case T:return nt=Ts(nt),lt(Q,k,nt,yt)}if(j(nt)||q(nt))return ee!==null?null:vt(Q,k,nt,yt,null);if(typeof nt.then=="function")return lt(Q,k,Ul(nt),yt);if(nt.$$typeof===D)return lt(Q,k,Cl(Q,nt),yt);Ll(Q,nt)}return null}function ut(Q,k,nt,yt,ee){if(typeof yt=="string"&&yt!==""||typeof yt=="number"||typeof yt=="bigint")return Q=Q.get(nt)||null,C(k,Q,""+yt,ee);if(typeof yt=="object"&&yt!==null){switch(yt.$$typeof){case y:return Q=Q.get(yt.key===null?nt:yt.key)||null,G(k,Q,yt,ee);case b:return Q=Q.get(yt.key===null?nt:yt.key)||null,it(k,Q,yt,ee);case T:return yt=Ts(yt),ut(Q,k,nt,yt,ee)}if(j(yt)||q(yt))return Q=Q.get(nt)||null,vt(k,Q,yt,ee,null);if(typeof yt.then=="function")return ut(Q,k,nt,Ul(yt),ee);if(yt.$$typeof===D)return ut(Q,k,nt,Cl(k,yt),ee);Ll(k,yt)}return null}function Wt(Q,k,nt,yt){for(var ee=null,Ae=null,Zt=k,ce=k=0,xe=null;Zt!==null&&ce<nt.length;ce++){Zt.index>ce?(xe=Zt,Zt=null):xe=Zt.sibling;var Re=lt(Q,Zt,nt[ce],yt);if(Re===null){Zt===null&&(Zt=xe);break}e&&Zt&&Re.alternate===null&&i(Q,Zt),k=h(Re,k,ce),Ae===null?ee=Re:Ae.sibling=Re,Ae=Re,Zt=xe}if(ce===nt.length)return a(Q,Zt),Me&&ia(Q,ce),ee;if(Zt===null){for(;ce<nt.length;ce++)Zt=Et(Q,nt[ce],yt),Zt!==null&&(k=h(Zt,k,ce),Ae===null?ee=Zt:Ae.sibling=Zt,Ae=Zt);return Me&&ia(Q,ce),ee}for(Zt=o(Zt);ce<nt.length;ce++)xe=ut(Zt,Q,ce,nt[ce],yt),xe!==null&&(e&&xe.alternate!==null&&Zt.delete(xe.key===null?ce:xe.key),k=h(xe,k,ce),Ae===null?ee=xe:Ae.sibling=xe,Ae=xe);return e&&Zt.forEach(function(ts){return i(Q,ts)}),Me&&ia(Q,ce),ee}function ne(Q,k,nt,yt){if(nt==null)throw Error(s(151));for(var ee=null,Ae=null,Zt=k,ce=k=0,xe=null,Re=nt.next();Zt!==null&&!Re.done;ce++,Re=nt.next()){Zt.index>ce?(xe=Zt,Zt=null):xe=Zt.sibling;var ts=lt(Q,Zt,Re.value,yt);if(ts===null){Zt===null&&(Zt=xe);break}e&&Zt&&ts.alternate===null&&i(Q,Zt),k=h(ts,k,ce),Ae===null?ee=ts:Ae.sibling=ts,Ae=ts,Zt=xe}if(Re.done)return a(Q,Zt),Me&&ia(Q,ce),ee;if(Zt===null){for(;!Re.done;ce++,Re=nt.next())Re=Et(Q,Re.value,yt),Re!==null&&(k=h(Re,k,ce),Ae===null?ee=Re:Ae.sibling=Re,Ae=Re);return Me&&ia(Q,ce),ee}for(Zt=o(Zt);!Re.done;ce++,Re=nt.next())Re=ut(Zt,Q,ce,Re.value,yt),Re!==null&&(e&&Re.alternate!==null&&Zt.delete(Re.key===null?ce:Re.key),k=h(Re,k,ce),Ae===null?ee=Re:Ae.sibling=Re,Ae=Re);return e&&Zt.forEach(function(Cy){return i(Q,Cy)}),Me&&ia(Q,ce),ee}function Ge(Q,k,nt,yt){if(typeof nt=="object"&&nt!==null&&nt.type===w&&nt.key===null&&(nt=nt.props.children),typeof nt=="object"&&nt!==null){switch(nt.$$typeof){case y:t:{for(var ee=nt.key;k!==null;){if(k.key===ee){if(ee=nt.type,ee===w){if(k.tag===7){a(Q,k.sibling),yt=u(k,nt.props.children),yt.return=Q,Q=yt;break t}}else if(k.elementType===ee||typeof ee=="object"&&ee!==null&&ee.$$typeof===T&&Ts(ee)===k.type){a(Q,k.sibling),yt=u(k,nt.props),po(yt,nt),yt.return=Q,Q=yt;break t}a(Q,k);break}else i(Q,k);k=k.sibling}nt.type===w?(yt=Ss(nt.props.children,Q.mode,yt,nt.key),yt.return=Q,Q=yt):(yt=Tl(nt.type,nt.key,nt.props,null,Q.mode,yt),po(yt,nt),yt.return=Q,Q=yt)}return x(Q);case b:t:{for(ee=nt.key;k!==null;){if(k.key===ee)if(k.tag===4&&k.stateNode.containerInfo===nt.containerInfo&&k.stateNode.implementation===nt.implementation){a(Q,k.sibling),yt=u(k,nt.children||[]),yt.return=Q,Q=yt;break t}else{a(Q,k);break}else i(Q,k);k=k.sibling}yt=Pu(nt,Q.mode,yt),yt.return=Q,Q=yt}return x(Q);case T:return nt=Ts(nt),Ge(Q,k,nt,yt)}if(j(nt))return Wt(Q,k,nt,yt);if(q(nt)){if(ee=q(nt),typeof ee!="function")throw Error(s(150));return nt=ee.call(nt),ne(Q,k,nt,yt)}if(typeof nt.then=="function")return Ge(Q,k,Ul(nt),yt);if(nt.$$typeof===D)return Ge(Q,k,Cl(Q,nt),yt);Ll(Q,nt)}return typeof nt=="string"&&nt!==""||typeof nt=="number"||typeof nt=="bigint"?(nt=""+nt,k!==null&&k.tag===6?(a(Q,k.sibling),yt=u(k,nt),yt.return=Q,Q=yt):(a(Q,k),yt=Ou(nt,Q.mode,yt),yt.return=Q,Q=yt),x(Q)):a(Q,k)}return function(Q,k,nt,yt){try{ho=0;var ee=Ge(Q,k,nt,yt);return or=null,ee}catch(Zt){if(Zt===rr||Zt===Dl)throw Zt;var Ae=ai(29,Zt,null,Q.mode);return Ae.lanes=yt,Ae.return=Q,Ae}finally{}}}var Rs=Sm(!0),ym=Sm(!1),za=!1;function Yu(e){e.updateQueue={baseState:e.memoizedState,firstBaseUpdate:null,lastBaseUpdate:null,shared:{pending:null,lanes:0,hiddenCallbacks:null},callbacks:null}}function Zu(e,i){e=e.updateQueue,i.updateQueue===e&&(i.updateQueue={baseState:e.baseState,firstBaseUpdate:e.firstBaseUpdate,lastBaseUpdate:e.lastBaseUpdate,shared:e.shared,callbacks:null})}function Fa(e){return{lane:e,tag:0,payload:null,callback:null,next:null}}function Ba(e,i,a){var o=e.updateQueue;if(o===null)return null;if(o=o.shared,(we&2)!==0){var u=o.pending;return u===null?i.next=i:(i.next=u.next,u.next=i),o.pending=i,i=bl(e),am(e,null,a),i}return El(e,o,i,a),bl(e)}function mo(e,i,a){if(i=i.updateQueue,i!==null&&(i=i.shared,(a&4194048)!==0)){var o=i.lanes;o&=e.pendingLanes,a|=o,i.lanes=a,$n(e,a)}}function Ku(e,i){var a=e.updateQueue,o=e.alternate;if(o!==null&&(o=o.updateQueue,a===o)){var u=null,h=null;if(a=a.firstBaseUpdate,a!==null){do{var x={lane:a.lane,tag:a.tag,payload:a.payload,callback:null,next:null};h===null?u=h=x:h=h.next=x,a=a.next}while(a!==null);h===null?u=h=i:h=h.next=i}else u=h=i;a={baseState:o.baseState,firstBaseUpdate:u,lastBaseUpdate:h,shared:o.shared,callbacks:o.callbacks},e.updateQueue=a;return}e=a.lastBaseUpdate,e===null?a.firstBaseUpdate=i:e.next=i,a.lastBaseUpdate=i}var ju=!1;function go(){if(ju){var e=sr;if(e!==null)throw e}}function vo(e,i,a,o){ju=!1;var u=e.updateQueue;za=!1;var h=u.firstBaseUpdate,x=u.lastBaseUpdate,C=u.shared.pending;if(C!==null){u.shared.pending=null;var G=C,it=G.next;G.next=null,x===null?h=it:x.next=it,x=G;var vt=e.alternate;vt!==null&&(vt=vt.updateQueue,C=vt.lastBaseUpdate,C!==x&&(C===null?vt.firstBaseUpdate=it:C.next=it,vt.lastBaseUpdate=G))}if(h!==null){var Et=u.baseState;x=0,vt=it=G=null,C=h;do{var lt=C.lane&-536870913,ut=lt!==C.lane;if(ut?(_e&lt)===lt:(o&lt)===lt){lt!==0&&lt===ar&&(ju=!0),vt!==null&&(vt=vt.next={lane:0,tag:C.tag,payload:C.payload,callback:null,next:null});t:{var Wt=e,ne=C;lt=i;var Ge=a;switch(ne.tag){case 1:if(Wt=ne.payload,typeof Wt=="function"){Et=Wt.call(Ge,Et,lt);break t}Et=Wt;break t;case 3:Wt.flags=Wt.flags&-65537|128;case 0:if(Wt=ne.payload,lt=typeof Wt=="function"?Wt.call(Ge,Et,lt):Wt,lt==null)break t;Et=_({},Et,lt);break t;case 2:za=!0}}lt=C.callback,lt!==null&&(e.flags|=64,ut&&(e.flags|=8192),ut=u.callbacks,ut===null?u.callbacks=[lt]:ut.push(lt))}else ut={lane:lt,tag:C.tag,payload:C.payload,callback:C.callback,next:null},vt===null?(it=vt=ut,G=Et):vt=vt.next=ut,x|=lt;if(C=C.next,C===null){if(C=u.shared.pending,C===null)break;ut=C,C=ut.next,ut.next=null,u.lastBaseUpdate=ut,u.shared.pending=null}}while(!0);vt===null&&(G=Et),u.baseState=G,u.firstBaseUpdate=it,u.lastBaseUpdate=vt,h===null&&(u.shared.lanes=0),Xa|=x,e.lanes=x,e.memoizedState=Et}}function Mm(e,i){if(typeof e!="function")throw Error(s(191,e));e.call(i)}function Em(e,i){var a=e.callbacks;if(a!==null)for(e.callbacks=null,e=0;e<a.length;e++)Mm(a[e],i)}var lr=U(null),Ol=U(0);function bm(e,i){e=pa,bt(Ol,e),bt(lr,i),pa=e|i.baseLanes}function Ju(){bt(Ol,pa),bt(lr,lr.current)}function Qu(){pa=Ol.current,J(lr),J(Ol)}var si=U(null),xi=null;function Ha(e){var i=e.alternate;bt(hn,hn.current&1),bt(si,e),xi===null&&(i===null||lr.current!==null||i.memoizedState!==null)&&(xi=e)}function $u(e){bt(hn,hn.current),bt(si,e),xi===null&&(xi=e)}function Tm(e){e.tag===22?(bt(hn,hn.current),bt(si,e),xi===null&&(xi=e)):Ga()}function Ga(){bt(hn,hn.current),bt(si,si.current)}function ri(e){J(si),xi===e&&(xi=null),J(hn)}var hn=U(0);function Pl(e){for(var i=e;i!==null;){if(i.tag===13){var a=i.memoizedState;if(a!==null&&(a=a.dehydrated,a===null||rh(a)||oh(a)))return i}else if(i.tag===19&&(i.memoizedProps.revealOrder==="forwards"||i.memoizedProps.revealOrder==="backwards"||i.memoizedProps.revealOrder==="unstable_legacy-backwards"||i.memoizedProps.revealOrder==="together")){if((i.flags&128)!==0)return i}else if(i.child!==null){i.child.return=i,i=i.child;continue}if(i===e)break;for(;i.sibling===null;){if(i.return===null||i.return===e)return null;i=i.return}i.sibling.return=i.return,i=i.sibling}return null}var ra=0,le=null,Be=null,vn=null,Il=!1,cr=!1,Cs=!1,zl=0,_o=0,ur=null,_S=0;function on(){throw Error(s(321))}function tf(e,i){if(i===null)return!1;for(var a=0;a<i.length&&a<e.length;a++)if(!ii(e[a],i[a]))return!1;return!0}function ef(e,i,a,o,u,h){return ra=h,le=i,i.memoizedState=null,i.updateQueue=null,i.lanes=0,B.H=e===null||e.memoizedState===null?l0:vf,Cs=!1,h=a(o,u),Cs=!1,cr&&(h=Rm(i,a,o,u)),Am(e),h}function Am(e){B.H=yo;var i=Be!==null&&Be.next!==null;if(ra=0,vn=Be=le=null,Il=!1,_o=0,ur=null,i)throw Error(s(300));e===null||_n||(e=e.dependencies,e!==null&&Rl(e)&&(_n=!0))}function Rm(e,i,a,o){le=e;var u=0;do{if(cr&&(ur=null),_o=0,cr=!1,25<=u)throw Error(s(301));if(u+=1,vn=Be=null,e.updateQueue!=null){var h=e.updateQueue;h.lastEffect=null,h.events=null,h.stores=null,h.memoCache!=null&&(h.memoCache.index=0)}B.H=c0,h=i(a,o)}while(cr);return h}function xS(){var e=B.H,i=e.useState()[0];return i=typeof i.then=="function"?xo(i):i,e=e.useState()[0],(Be!==null?Be.memoizedState:null)!==e&&(le.flags|=1024),i}function nf(){var e=zl!==0;return zl=0,e}function af(e,i,a){i.updateQueue=e.updateQueue,i.flags&=-2053,e.lanes&=~a}function sf(e){if(Il){for(e=e.memoizedState;e!==null;){var i=e.queue;i!==null&&(i.pending=null),e=e.next}Il=!1}ra=0,vn=Be=le=null,cr=!1,_o=zl=0,ur=null}function Hn(){var e={memoizedState:null,baseState:null,baseQueue:null,queue:null,next:null};return vn===null?le.memoizedState=vn=e:vn=vn.next=e,vn}function dn(){if(Be===null){var e=le.alternate;e=e!==null?e.memoizedState:null}else e=Be.next;var i=vn===null?le.memoizedState:vn.next;if(i!==null)vn=i,Be=e;else{if(e===null)throw le.alternate===null?Error(s(467)):Error(s(310));Be=e,e={memoizedState:Be.memoizedState,baseState:Be.baseState,baseQueue:Be.baseQueue,queue:Be.queue,next:null},vn===null?le.memoizedState=vn=e:vn=vn.next=e}return vn}function Fl(){return{lastEffect:null,events:null,stores:null,memoCache:null}}function xo(e){var i=_o;return _o+=1,ur===null&&(ur=[]),e=vm(ur,e,i),i=le,(vn===null?i.memoizedState:vn.next)===null&&(i=i.alternate,B.H=i===null||i.memoizedState===null?l0:vf),e}function Bl(e){if(e!==null&&typeof e=="object"){if(typeof e.then=="function")return xo(e);if(e.$$typeof===D)return Dn(e)}throw Error(s(438,String(e)))}function rf(e){var i=null,a=le.updateQueue;if(a!==null&&(i=a.memoCache),i==null){var o=le.alternate;o!==null&&(o=o.updateQueue,o!==null&&(o=o.memoCache,o!=null&&(i={data:o.data.map(function(u){return u.slice()}),index:0})))}if(i==null&&(i={data:[],index:0}),a===null&&(a=Fl(),le.updateQueue=a),a.memoCache=i,a=i.data[i.index],a===void 0)for(a=i.data[i.index]=Array(e),o=0;o<e;o++)a[o]=X;return i.index++,a}function oa(e,i){return typeof i=="function"?i(e):i}function Hl(e){var i=dn();return of(i,Be,e)}function of(e,i,a){var o=e.queue;if(o===null)throw Error(s(311));o.lastRenderedReducer=a;var u=e.baseQueue,h=o.pending;if(h!==null){if(u!==null){var x=u.next;u.next=h.next,h.next=x}i.baseQueue=u=h,o.pending=null}if(h=e.baseState,u===null)e.memoizedState=h;else{i=u.next;var C=x=null,G=null,it=i,vt=!1;do{var Et=it.lane&-536870913;if(Et!==it.lane?(_e&Et)===Et:(ra&Et)===Et){var lt=it.revertLane;if(lt===0)G!==null&&(G=G.next={lane:0,revertLane:0,gesture:null,action:it.action,hasEagerState:it.hasEagerState,eagerState:it.eagerState,next:null}),Et===ar&&(vt=!0);else if((ra&lt)===lt){it=it.next,lt===ar&&(vt=!0);continue}else Et={lane:0,revertLane:it.revertLane,gesture:null,action:it.action,hasEagerState:it.hasEagerState,eagerState:it.eagerState,next:null},G===null?(C=G=Et,x=h):G=G.next=Et,le.lanes|=lt,Xa|=lt;Et=it.action,Cs&&a(h,Et),h=it.hasEagerState?it.eagerState:a(h,Et)}else lt={lane:Et,revertLane:it.revertLane,gesture:it.gesture,action:it.action,hasEagerState:it.hasEagerState,eagerState:it.eagerState,next:null},G===null?(C=G=lt,x=h):G=G.next=lt,le.lanes|=Et,Xa|=Et;it=it.next}while(it!==null&&it!==i);if(G===null?x=h:G.next=C,!ii(h,e.memoizedState)&&(_n=!0,vt&&(a=sr,a!==null)))throw a;e.memoizedState=h,e.baseState=x,e.baseQueue=G,o.lastRenderedState=h}return u===null&&(o.lanes=0),[e.memoizedState,o.dispatch]}function lf(e){var i=dn(),a=i.queue;if(a===null)throw Error(s(311));a.lastRenderedReducer=e;var o=a.dispatch,u=a.pending,h=i.memoizedState;if(u!==null){a.pending=null;var x=u=u.next;do h=e(h,x.action),x=x.next;while(x!==u);ii(h,i.memoizedState)||(_n=!0),i.memoizedState=h,i.baseQueue===null&&(i.baseState=h),a.lastRenderedState=h}return[h,o]}function Cm(e,i,a){var o=le,u=dn(),h=Me;if(h){if(a===void 0)throw Error(s(407));a=a()}else a=i();var x=!ii((Be||u).memoizedState,a);if(x&&(u.memoizedState=a,_n=!0),u=u.queue,ff(Nm.bind(null,o,u,e),[e]),u.getSnapshot!==i||x||vn!==null&&vn.memoizedState.tag&1){if(o.flags|=2048,fr(9,{destroy:void 0},Dm.bind(null,o,u,a,i),null),ke===null)throw Error(s(349));h||(ra&127)!==0||wm(o,i,a)}return a}function wm(e,i,a){e.flags|=16384,e={getSnapshot:i,value:a},i=le.updateQueue,i===null?(i=Fl(),le.updateQueue=i,i.stores=[e]):(a=i.stores,a===null?i.stores=[e]:a.push(e))}function Dm(e,i,a,o){i.value=a,i.getSnapshot=o,Um(i)&&Lm(e)}function Nm(e,i,a){return a(function(){Um(i)&&Lm(e)})}function Um(e){var i=e.getSnapshot;e=e.value;try{var a=i();return!ii(e,a)}catch{return!0}}function Lm(e){var i=xs(e,2);i!==null&&Jn(i,e,2)}function cf(e){var i=Hn();if(typeof e=="function"){var a=e;if(e=a(),Cs){wt(!0);try{a()}finally{wt(!1)}}}return i.memoizedState=i.baseState=e,i.queue={pending:null,lanes:0,dispatch:null,lastRenderedReducer:oa,lastRenderedState:e},i}function Om(e,i,a,o){return e.baseState=a,of(e,Be,typeof o=="function"?o:oa)}function SS(e,i,a,o,u){if(kl(e))throw Error(s(485));if(e=i.action,e!==null){var h={payload:u,action:e,next:null,isTransition:!0,status:"pending",value:null,reason:null,listeners:[],then:function(x){h.listeners.push(x)}};B.T!==null?a(!0):h.isTransition=!1,o(h),a=i.pending,a===null?(h.next=i.pending=h,Pm(i,h)):(h.next=a.next,i.pending=a.next=h)}}function Pm(e,i){var a=i.action,o=i.payload,u=e.state;if(i.isTransition){var h=B.T,x={};B.T=x;try{var C=a(u,o),G=B.S;G!==null&&G(x,C),Im(e,i,C)}catch(it){uf(e,i,it)}finally{h!==null&&x.types!==null&&(h.types=x.types),B.T=h}}else try{h=a(u,o),Im(e,i,h)}catch(it){uf(e,i,it)}}function Im(e,i,a){a!==null&&typeof a=="object"&&typeof a.then=="function"?a.then(function(o){zm(e,i,o)},function(o){return uf(e,i,o)}):zm(e,i,a)}function zm(e,i,a){i.status="fulfilled",i.value=a,Fm(i),e.state=a,i=e.pending,i!==null&&(a=i.next,a===i?e.pending=null:(a=a.next,i.next=a,Pm(e,a)))}function uf(e,i,a){var o=e.pending;if(e.pending=null,o!==null){o=o.next;do i.status="rejected",i.reason=a,Fm(i),i=i.next;while(i!==o)}e.action=null}function Fm(e){e=e.listeners;for(var i=0;i<e.length;i++)(0,e[i])()}function Bm(e,i){return i}function Hm(e,i){if(Me){var a=ke.formState;if(a!==null){t:{var o=le;if(Me){if(Ye){e:{for(var u=Ye,h=_i;u.nodeType!==8;){if(!h){u=null;break e}if(u=Si(u.nextSibling),u===null){u=null;break e}}h=u.data,u=h==="F!"||h==="F"?u:null}if(u){Ye=Si(u.nextSibling),o=u.data==="F!";break t}}Pa(o)}o=!1}o&&(i=a[0])}}return a=Hn(),a.memoizedState=a.baseState=i,o={pending:null,lanes:0,dispatch:null,lastRenderedReducer:Bm,lastRenderedState:i},a.queue=o,a=s0.bind(null,le,o),o.dispatch=a,o=cf(!1),h=gf.bind(null,le,!1,o.queue),o=Hn(),u={state:i,dispatch:null,action:e,pending:null},o.queue=u,a=SS.bind(null,le,u,h,a),u.dispatch=a,o.memoizedState=e,[i,a,!1]}function Gm(e){var i=dn();return Vm(i,Be,e)}function Vm(e,i,a){if(i=of(e,i,Bm)[0],e=Hl(oa)[0],typeof i=="object"&&i!==null&&typeof i.then=="function")try{var o=xo(i)}catch(x){throw x===rr?Dl:x}else o=i;i=dn();var u=i.queue,h=u.dispatch;return a!==i.memoizedState&&(le.flags|=2048,fr(9,{destroy:void 0},yS.bind(null,u,a),null)),[o,h,e]}function yS(e,i){e.action=i}function km(e){var i=dn(),a=Be;if(a!==null)return Vm(i,a,e);dn(),i=i.memoizedState,a=dn();var o=a.queue.dispatch;return a.memoizedState=e,[i,o,!1]}function fr(e,i,a,o){return e={tag:e,create:a,deps:o,inst:i,next:null},i=le.updateQueue,i===null&&(i=Fl(),le.updateQueue=i),a=i.lastEffect,a===null?i.lastEffect=e.next=e:(o=a.next,a.next=e,e.next=o,i.lastEffect=e),e}function Xm(){return dn().memoizedState}function Gl(e,i,a,o){var u=Hn();le.flags|=e,u.memoizedState=fr(1|i,{destroy:void 0},a,o===void 0?null:o)}function Vl(e,i,a,o){var u=dn();o=o===void 0?null:o;var h=u.memoizedState.inst;Be!==null&&o!==null&&tf(o,Be.memoizedState.deps)?u.memoizedState=fr(i,h,a,o):(le.flags|=e,u.memoizedState=fr(1|i,h,a,o))}function Wm(e,i){Gl(8390656,8,e,i)}function ff(e,i){Vl(2048,8,e,i)}function MS(e){le.flags|=4;var i=le.updateQueue;if(i===null)i=Fl(),le.updateQueue=i,i.events=[e];else{var a=i.events;a===null?i.events=[e]:a.push(e)}}function qm(e){var i=dn().memoizedState;return MS({ref:i,nextImpl:e}),function(){if((we&2)!==0)throw Error(s(440));return i.impl.apply(void 0,arguments)}}function Ym(e,i){return Vl(4,2,e,i)}function Zm(e,i){return Vl(4,4,e,i)}function Km(e,i){if(typeof i=="function"){e=e();var a=i(e);return function(){typeof a=="function"?a():i(null)}}if(i!=null)return e=e(),i.current=e,function(){i.current=null}}function jm(e,i,a){a=a!=null?a.concat([e]):null,Vl(4,4,Km.bind(null,i,e),a)}function hf(){}function Jm(e,i){var a=dn();i=i===void 0?null:i;var o=a.memoizedState;return i!==null&&tf(i,o[1])?o[0]:(a.memoizedState=[e,i],e)}function Qm(e,i){var a=dn();i=i===void 0?null:i;var o=a.memoizedState;if(i!==null&&tf(i,o[1]))return o[0];if(o=e(),Cs){wt(!0);try{e()}finally{wt(!1)}}return a.memoizedState=[o,i],o}function df(e,i,a){return a===void 0||(ra&1073741824)!==0&&(_e&261930)===0?e.memoizedState=i:(e.memoizedState=a,e=$0(),le.lanes|=e,Xa|=e,a)}function $m(e,i,a,o){return ii(a,i)?a:lr.current!==null?(e=df(e,a,o),ii(e,i)||(_n=!0),e):(ra&42)===0||(ra&1073741824)!==0&&(_e&261930)===0?(_n=!0,e.memoizedState=a):(e=$0(),le.lanes|=e,Xa|=e,i)}function t0(e,i,a,o,u){var h=H.p;H.p=h!==0&&8>h?h:8;var x=B.T,C={};B.T=C,gf(e,!1,i,a);try{var G=u(),it=B.S;if(it!==null&&it(C,G),G!==null&&typeof G=="object"&&typeof G.then=="function"){var vt=vS(G,o);So(e,i,vt,ci(e))}else So(e,i,o,ci(e))}catch(Et){So(e,i,{then:function(){},status:"rejected",reason:Et},ci())}finally{H.p=h,x!==null&&C.types!==null&&(x.types=C.types),B.T=x}}function ES(){}function pf(e,i,a,o){if(e.tag!==5)throw Error(s(476));var u=e0(e).queue;t0(e,u,i,$,a===null?ES:function(){return n0(e),a(o)})}function e0(e){var i=e.memoizedState;if(i!==null)return i;i={memoizedState:$,baseState:$,baseQueue:null,queue:{pending:null,lanes:0,dispatch:null,lastRenderedReducer:oa,lastRenderedState:$},next:null};var a={};return i.next={memoizedState:a,baseState:a,baseQueue:null,queue:{pending:null,lanes:0,dispatch:null,lastRenderedReducer:oa,lastRenderedState:a},next:null},e.memoizedState=i,e=e.alternate,e!==null&&(e.memoizedState=i),i}function n0(e){var i=e0(e);i.next===null&&(i=e.alternate.memoizedState),So(e,i.next.queue,{},ci())}function mf(){return Dn(zo)}function i0(){return dn().memoizedState}function a0(){return dn().memoizedState}function bS(e){for(var i=e.return;i!==null;){switch(i.tag){case 24:case 3:var a=ci();e=Fa(a);var o=Ba(i,e,a);o!==null&&(Jn(o,i,a),mo(o,i,a)),i={cache:ku()},e.payload=i;return}i=i.return}}function TS(e,i,a){var o=ci();a={lane:o,revertLane:0,gesture:null,action:a,hasEagerState:!1,eagerState:null,next:null},kl(e)?r0(i,a):(a=Uu(e,i,a,o),a!==null&&(Jn(a,e,o),o0(a,i,o)))}function s0(e,i,a){var o=ci();So(e,i,a,o)}function So(e,i,a,o){var u={lane:o,revertLane:0,gesture:null,action:a,hasEagerState:!1,eagerState:null,next:null};if(kl(e))r0(i,u);else{var h=e.alternate;if(e.lanes===0&&(h===null||h.lanes===0)&&(h=i.lastRenderedReducer,h!==null))try{var x=i.lastRenderedState,C=h(x,a);if(u.hasEagerState=!0,u.eagerState=C,ii(C,x))return El(e,i,u,0),ke===null&&Ml(),!1}catch{}finally{}if(a=Uu(e,i,u,o),a!==null)return Jn(a,e,o),o0(a,i,o),!0}return!1}function gf(e,i,a,o){if(o={lane:2,revertLane:Zf(),gesture:null,action:o,hasEagerState:!1,eagerState:null,next:null},kl(e)){if(i)throw Error(s(479))}else i=Uu(e,a,o,2),i!==null&&Jn(i,e,2)}function kl(e){var i=e.alternate;return e===le||i!==null&&i===le}function r0(e,i){cr=Il=!0;var a=e.pending;a===null?i.next=i:(i.next=a.next,a.next=i),e.pending=i}function o0(e,i,a){if((a&4194048)!==0){var o=i.lanes;o&=e.pendingLanes,a|=o,i.lanes=a,$n(e,a)}}var yo={readContext:Dn,use:Bl,useCallback:on,useContext:on,useEffect:on,useImperativeHandle:on,useLayoutEffect:on,useInsertionEffect:on,useMemo:on,useReducer:on,useRef:on,useState:on,useDebugValue:on,useDeferredValue:on,useTransition:on,useSyncExternalStore:on,useId:on,useHostTransitionStatus:on,useFormState:on,useActionState:on,useOptimistic:on,useMemoCache:on,useCacheRefresh:on};yo.useEffectEvent=on;var l0={readContext:Dn,use:Bl,useCallback:function(e,i){return Hn().memoizedState=[e,i===void 0?null:i],e},useContext:Dn,useEffect:Wm,useImperativeHandle:function(e,i,a){a=a!=null?a.concat([e]):null,Gl(4194308,4,Km.bind(null,i,e),a)},useLayoutEffect:function(e,i){return Gl(4194308,4,e,i)},useInsertionEffect:function(e,i){Gl(4,2,e,i)},useMemo:function(e,i){var a=Hn();i=i===void 0?null:i;var o=e();if(Cs){wt(!0);try{e()}finally{wt(!1)}}return a.memoizedState=[o,i],o},useReducer:function(e,i,a){var o=Hn();if(a!==void 0){var u=a(i);if(Cs){wt(!0);try{a(i)}finally{wt(!1)}}}else u=i;return o.memoizedState=o.baseState=u,e={pending:null,lanes:0,dispatch:null,lastRenderedReducer:e,lastRenderedState:u},o.queue=e,e=e.dispatch=TS.bind(null,le,e),[o.memoizedState,e]},useRef:function(e){var i=Hn();return e={current:e},i.memoizedState=e},useState:function(e){e=cf(e);var i=e.queue,a=s0.bind(null,le,i);return i.dispatch=a,[e.memoizedState,a]},useDebugValue:hf,useDeferredValue:function(e,i){var a=Hn();return df(a,e,i)},useTransition:function(){var e=cf(!1);return e=t0.bind(null,le,e.queue,!0,!1),Hn().memoizedState=e,[!1,e]},useSyncExternalStore:function(e,i,a){var o=le,u=Hn();if(Me){if(a===void 0)throw Error(s(407));a=a()}else{if(a=i(),ke===null)throw Error(s(349));(_e&127)!==0||wm(o,i,a)}u.memoizedState=a;var h={value:a,getSnapshot:i};return u.queue=h,Wm(Nm.bind(null,o,h,e),[e]),o.flags|=2048,fr(9,{destroy:void 0},Dm.bind(null,o,h,a,i),null),a},useId:function(){var e=Hn(),i=ke.identifierPrefix;if(Me){var a=Bi,o=Fi;a=(o&~(1<<32-Bt(o)-1)).toString(32)+a,i="_"+i+"R_"+a,a=zl++,0<a&&(i+="H"+a.toString(32)),i+="_"}else a=_S++,i="_"+i+"r_"+a.toString(32)+"_";return e.memoizedState=i},useHostTransitionStatus:mf,useFormState:Hm,useActionState:Hm,useOptimistic:function(e){var i=Hn();i.memoizedState=i.baseState=e;var a={pending:null,lanes:0,dispatch:null,lastRenderedReducer:null,lastRenderedState:null};return i.queue=a,i=gf.bind(null,le,!0,a),a.dispatch=i,[e,i]},useMemoCache:rf,useCacheRefresh:function(){return Hn().memoizedState=bS.bind(null,le)},useEffectEvent:function(e){var i=Hn(),a={impl:e};return i.memoizedState=a,function(){if((we&2)!==0)throw Error(s(440));return a.impl.apply(void 0,arguments)}}},vf={readContext:Dn,use:Bl,useCallback:Jm,useContext:Dn,useEffect:ff,useImperativeHandle:jm,useInsertionEffect:Ym,useLayoutEffect:Zm,useMemo:Qm,useReducer:Hl,useRef:Xm,useState:function(){return Hl(oa)},useDebugValue:hf,useDeferredValue:function(e,i){var a=dn();return $m(a,Be.memoizedState,e,i)},useTransition:function(){var e=Hl(oa)[0],i=dn().memoizedState;return[typeof e=="boolean"?e:xo(e),i]},useSyncExternalStore:Cm,useId:i0,useHostTransitionStatus:mf,useFormState:Gm,useActionState:Gm,useOptimistic:function(e,i){var a=dn();return Om(a,Be,e,i)},useMemoCache:rf,useCacheRefresh:a0};vf.useEffectEvent=qm;var c0={readContext:Dn,use:Bl,useCallback:Jm,useContext:Dn,useEffect:ff,useImperativeHandle:jm,useInsertionEffect:Ym,useLayoutEffect:Zm,useMemo:Qm,useReducer:lf,useRef:Xm,useState:function(){return lf(oa)},useDebugValue:hf,useDeferredValue:function(e,i){var a=dn();return Be===null?df(a,e,i):$m(a,Be.memoizedState,e,i)},useTransition:function(){var e=lf(oa)[0],i=dn().memoizedState;return[typeof e=="boolean"?e:xo(e),i]},useSyncExternalStore:Cm,useId:i0,useHostTransitionStatus:mf,useFormState:km,useActionState:km,useOptimistic:function(e,i){var a=dn();return Be!==null?Om(a,Be,e,i):(a.baseState=e,[e,a.queue.dispatch])},useMemoCache:rf,useCacheRefresh:a0};c0.useEffectEvent=qm;function _f(e,i,a,o){i=e.memoizedState,a=a(o,i),a=a==null?i:_({},i,a),e.memoizedState=a,e.lanes===0&&(e.updateQueue.baseState=a)}var xf={enqueueSetState:function(e,i,a){e=e._reactInternals;var o=ci(),u=Fa(o);u.payload=i,a!=null&&(u.callback=a),i=Ba(e,u,o),i!==null&&(Jn(i,e,o),mo(i,e,o))},enqueueReplaceState:function(e,i,a){e=e._reactInternals;var o=ci(),u=Fa(o);u.tag=1,u.payload=i,a!=null&&(u.callback=a),i=Ba(e,u,o),i!==null&&(Jn(i,e,o),mo(i,e,o))},enqueueForceUpdate:function(e,i){e=e._reactInternals;var a=ci(),o=Fa(a);o.tag=2,i!=null&&(o.callback=i),i=Ba(e,o,a),i!==null&&(Jn(i,e,a),mo(i,e,a))}};function u0(e,i,a,o,u,h,x){return e=e.stateNode,typeof e.shouldComponentUpdate=="function"?e.shouldComponentUpdate(o,h,x):i.prototype&&i.prototype.isPureReactComponent?!ro(a,o)||!ro(u,h):!0}function f0(e,i,a,o){e=i.state,typeof i.componentWillReceiveProps=="function"&&i.componentWillReceiveProps(a,o),typeof i.UNSAFE_componentWillReceiveProps=="function"&&i.UNSAFE_componentWillReceiveProps(a,o),i.state!==e&&xf.enqueueReplaceState(i,i.state,null)}function ws(e,i){var a=i;if("ref"in i){a={};for(var o in i)o!=="ref"&&(a[o]=i[o])}if(e=e.defaultProps){a===i&&(a=_({},a));for(var u in e)a[u]===void 0&&(a[u]=e[u])}return a}function h0(e){yl(e)}function d0(e){console.error(e)}function p0(e){yl(e)}function Xl(e,i){try{var a=e.onUncaughtError;a(i.value,{componentStack:i.stack})}catch(o){setTimeout(function(){throw o})}}function m0(e,i,a){try{var o=e.onCaughtError;o(a.value,{componentStack:a.stack,errorBoundary:i.tag===1?i.stateNode:null})}catch(u){setTimeout(function(){throw u})}}function Sf(e,i,a){return a=Fa(a),a.tag=3,a.payload={element:null},a.callback=function(){Xl(e,i)},a}function g0(e){return e=Fa(e),e.tag=3,e}function v0(e,i,a,o){var u=a.type.getDerivedStateFromError;if(typeof u=="function"){var h=o.value;e.payload=function(){return u(h)},e.callback=function(){m0(i,a,o)}}var x=a.stateNode;x!==null&&typeof x.componentDidCatch=="function"&&(e.callback=function(){m0(i,a,o),typeof u!="function"&&(Wa===null?Wa=new Set([this]):Wa.add(this));var C=o.stack;this.componentDidCatch(o.value,{componentStack:C!==null?C:""})})}function AS(e,i,a,o,u){if(a.flags|=32768,o!==null&&typeof o=="object"&&typeof o.then=="function"){if(i=a.alternate,i!==null&&ir(i,a,u,!0),a=si.current,a!==null){switch(a.tag){case 31:case 13:return xi===null?nc():a.alternate===null&&ln===0&&(ln=3),a.flags&=-257,a.flags|=65536,a.lanes=u,o===Nl?a.flags|=16384:(i=a.updateQueue,i===null?a.updateQueue=new Set([o]):i.add(o),Wf(e,o,u)),!1;case 22:return a.flags|=65536,o===Nl?a.flags|=16384:(i=a.updateQueue,i===null?(i={transitions:null,markerInstances:null,retryQueue:new Set([o])},a.updateQueue=i):(a=i.retryQueue,a===null?i.retryQueue=new Set([o]):a.add(o)),Wf(e,o,u)),!1}throw Error(s(435,a.tag))}return Wf(e,o,u),nc(),!1}if(Me)return i=si.current,i!==null?((i.flags&65536)===0&&(i.flags|=256),i.flags|=65536,i.lanes=u,o!==Fu&&(e=Error(s(422),{cause:o}),co(mi(e,a)))):(o!==Fu&&(i=Error(s(423),{cause:o}),co(mi(i,a))),e=e.current.alternate,e.flags|=65536,u&=-u,e.lanes|=u,o=mi(o,a),u=Sf(e.stateNode,o,u),Ku(e,u),ln!==4&&(ln=2)),!1;var h=Error(s(520),{cause:o});if(h=mi(h,a),wo===null?wo=[h]:wo.push(h),ln!==4&&(ln=2),i===null)return!0;o=mi(o,a),a=i;do{switch(a.tag){case 3:return a.flags|=65536,e=u&-u,a.lanes|=e,e=Sf(a.stateNode,o,e),Ku(a,e),!1;case 1:if(i=a.type,h=a.stateNode,(a.flags&128)===0&&(typeof i.getDerivedStateFromError=="function"||h!==null&&typeof h.componentDidCatch=="function"&&(Wa===null||!Wa.has(h))))return a.flags|=65536,u&=-u,a.lanes|=u,u=g0(u),v0(u,e,a,o),Ku(a,u),!1}a=a.return}while(a!==null);return!1}var yf=Error(s(461)),_n=!1;function Nn(e,i,a,o){i.child=e===null?ym(i,null,a,o):Rs(i,e.child,a,o)}function _0(e,i,a,o,u){a=a.render;var h=i.ref;if("ref"in o){var x={};for(var C in o)C!=="ref"&&(x[C]=o[C])}else x=o;return Es(i),o=ef(e,i,a,x,h,u),C=nf(),e!==null&&!_n?(af(e,i,u),la(e,i,u)):(Me&&C&&Iu(i),i.flags|=1,Nn(e,i,o,u),i.child)}function x0(e,i,a,o,u){if(e===null){var h=a.type;return typeof h=="function"&&!Lu(h)&&h.defaultProps===void 0&&a.compare===null?(i.tag=15,i.type=h,S0(e,i,h,o,u)):(e=Tl(a.type,null,o,i,i.mode,u),e.ref=i.ref,e.return=i,i.child=e)}if(h=e.child,!wf(e,u)){var x=h.memoizedProps;if(a=a.compare,a=a!==null?a:ro,a(x,o)&&e.ref===i.ref)return la(e,i,u)}return i.flags|=1,e=na(h,o),e.ref=i.ref,e.return=i,i.child=e}function S0(e,i,a,o,u){if(e!==null){var h=e.memoizedProps;if(ro(h,o)&&e.ref===i.ref)if(_n=!1,i.pendingProps=o=h,wf(e,u))(e.flags&131072)!==0&&(_n=!0);else return i.lanes=e.lanes,la(e,i,u)}return Mf(e,i,a,o,u)}function y0(e,i,a,o){var u=o.children,h=e!==null?e.memoizedState:null;if(e===null&&i.stateNode===null&&(i.stateNode={_visibility:1,_pendingMarkers:null,_retryCache:null,_transitions:null}),o.mode==="hidden"){if((i.flags&128)!==0){if(h=h!==null?h.baseLanes|a:a,e!==null){for(o=i.child=e.child,u=0;o!==null;)u=u|o.lanes|o.childLanes,o=o.sibling;o=u&~h}else o=0,i.child=null;return M0(e,i,h,a,o)}if((a&536870912)!==0)i.memoizedState={baseLanes:0,cachePool:null},e!==null&&wl(i,h!==null?h.cachePool:null),h!==null?bm(i,h):Ju(),Tm(i);else return o=i.lanes=536870912,M0(e,i,h!==null?h.baseLanes|a:a,a,o)}else h!==null?(wl(i,h.cachePool),bm(i,h),Ga(),i.memoizedState=null):(e!==null&&wl(i,null),Ju(),Ga());return Nn(e,i,u,a),i.child}function Mo(e,i){return e!==null&&e.tag===22||i.stateNode!==null||(i.stateNode={_visibility:1,_pendingMarkers:null,_retryCache:null,_transitions:null}),i.sibling}function M0(e,i,a,o,u){var h=Wu();return h=h===null?null:{parent:gn._currentValue,pool:h},i.memoizedState={baseLanes:a,cachePool:h},e!==null&&wl(i,null),Ju(),Tm(i),e!==null&&ir(e,i,o,!0),i.childLanes=u,null}function Wl(e,i){return i=Yl({mode:i.mode,children:i.children},e.mode),i.ref=e.ref,e.child=i,i.return=e,i}function E0(e,i,a){return Rs(i,e.child,null,a),e=Wl(i,i.pendingProps),e.flags|=2,ri(i),i.memoizedState=null,e}function RS(e,i,a){var o=i.pendingProps,u=(i.flags&128)!==0;if(i.flags&=-129,e===null){if(Me){if(o.mode==="hidden")return e=Wl(i,o),i.lanes=536870912,Mo(null,e);if($u(i),(e=Ye)?(e=Pg(e,_i),e=e!==null&&e.data==="&"?e:null,e!==null&&(i.memoizedState={dehydrated:e,treeContext:La!==null?{id:Fi,overflow:Bi}:null,retryLane:536870912,hydrationErrors:null},a=rm(e),a.return=i,i.child=a,wn=i,Ye=null)):e=null,e===null)throw Pa(i);return i.lanes=536870912,null}return Wl(i,o)}var h=e.memoizedState;if(h!==null){var x=h.dehydrated;if($u(i),u)if(i.flags&256)i.flags&=-257,i=E0(e,i,a);else if(i.memoizedState!==null)i.child=e.child,i.flags|=128,i=null;else throw Error(s(558));else if(_n||ir(e,i,a,!1),u=(a&e.childLanes)!==0,_n||u){if(o=ke,o!==null&&(x=ti(o,a),x!==0&&x!==h.retryLane))throw h.retryLane=x,xs(e,x),Jn(o,e,x),yf;nc(),i=E0(e,i,a)}else e=h.treeContext,Ye=Si(x.nextSibling),wn=i,Me=!0,Oa=null,_i=!1,e!==null&&cm(i,e),i=Wl(i,o),i.flags|=4096;return i}return e=na(e.child,{mode:o.mode,children:o.children}),e.ref=i.ref,i.child=e,e.return=i,e}function ql(e,i){var a=i.ref;if(a===null)e!==null&&e.ref!==null&&(i.flags|=4194816);else{if(typeof a!="function"&&typeof a!="object")throw Error(s(284));(e===null||e.ref!==a)&&(i.flags|=4194816)}}function Mf(e,i,a,o,u){return Es(i),a=ef(e,i,a,o,void 0,u),o=nf(),e!==null&&!_n?(af(e,i,u),la(e,i,u)):(Me&&o&&Iu(i),i.flags|=1,Nn(e,i,a,u),i.child)}function b0(e,i,a,o,u,h){return Es(i),i.updateQueue=null,a=Rm(i,o,a,u),Am(e),o=nf(),e!==null&&!_n?(af(e,i,h),la(e,i,h)):(Me&&o&&Iu(i),i.flags|=1,Nn(e,i,a,h),i.child)}function T0(e,i,a,o,u){if(Es(i),i.stateNode===null){var h=$s,x=a.contextType;typeof x=="object"&&x!==null&&(h=Dn(x)),h=new a(o,h),i.memoizedState=h.state!==null&&h.state!==void 0?h.state:null,h.updater=xf,i.stateNode=h,h._reactInternals=i,h=i.stateNode,h.props=o,h.state=i.memoizedState,h.refs={},Yu(i),x=a.contextType,h.context=typeof x=="object"&&x!==null?Dn(x):$s,h.state=i.memoizedState,x=a.getDerivedStateFromProps,typeof x=="function"&&(_f(i,a,x,o),h.state=i.memoizedState),typeof a.getDerivedStateFromProps=="function"||typeof h.getSnapshotBeforeUpdate=="function"||typeof h.UNSAFE_componentWillMount!="function"&&typeof h.componentWillMount!="function"||(x=h.state,typeof h.componentWillMount=="function"&&h.componentWillMount(),typeof h.UNSAFE_componentWillMount=="function"&&h.UNSAFE_componentWillMount(),x!==h.state&&xf.enqueueReplaceState(h,h.state,null),vo(i,o,h,u),go(),h.state=i.memoizedState),typeof h.componentDidMount=="function"&&(i.flags|=4194308),o=!0}else if(e===null){h=i.stateNode;var C=i.memoizedProps,G=ws(a,C);h.props=G;var it=h.context,vt=a.contextType;x=$s,typeof vt=="object"&&vt!==null&&(x=Dn(vt));var Et=a.getDerivedStateFromProps;vt=typeof Et=="function"||typeof h.getSnapshotBeforeUpdate=="function",C=i.pendingProps!==C,vt||typeof h.UNSAFE_componentWillReceiveProps!="function"&&typeof h.componentWillReceiveProps!="function"||(C||it!==x)&&f0(i,h,o,x),za=!1;var lt=i.memoizedState;h.state=lt,vo(i,o,h,u),go(),it=i.memoizedState,C||lt!==it||za?(typeof Et=="function"&&(_f(i,a,Et,o),it=i.memoizedState),(G=za||u0(i,a,G,o,lt,it,x))?(vt||typeof h.UNSAFE_componentWillMount!="function"&&typeof h.componentWillMount!="function"||(typeof h.componentWillMount=="function"&&h.componentWillMount(),typeof h.UNSAFE_componentWillMount=="function"&&h.UNSAFE_componentWillMount()),typeof h.componentDidMount=="function"&&(i.flags|=4194308)):(typeof h.componentDidMount=="function"&&(i.flags|=4194308),i.memoizedProps=o,i.memoizedState=it),h.props=o,h.state=it,h.context=x,o=G):(typeof h.componentDidMount=="function"&&(i.flags|=4194308),o=!1)}else{h=i.stateNode,Zu(e,i),x=i.memoizedProps,vt=ws(a,x),h.props=vt,Et=i.pendingProps,lt=h.context,it=a.contextType,G=$s,typeof it=="object"&&it!==null&&(G=Dn(it)),C=a.getDerivedStateFromProps,(it=typeof C=="function"||typeof h.getSnapshotBeforeUpdate=="function")||typeof h.UNSAFE_componentWillReceiveProps!="function"&&typeof h.componentWillReceiveProps!="function"||(x!==Et||lt!==G)&&f0(i,h,o,G),za=!1,lt=i.memoizedState,h.state=lt,vo(i,o,h,u),go();var ut=i.memoizedState;x!==Et||lt!==ut||za||e!==null&&e.dependencies!==null&&Rl(e.dependencies)?(typeof C=="function"&&(_f(i,a,C,o),ut=i.memoizedState),(vt=za||u0(i,a,vt,o,lt,ut,G)||e!==null&&e.dependencies!==null&&Rl(e.dependencies))?(it||typeof h.UNSAFE_componentWillUpdate!="function"&&typeof h.componentWillUpdate!="function"||(typeof h.componentWillUpdate=="function"&&h.componentWillUpdate(o,ut,G),typeof h.UNSAFE_componentWillUpdate=="function"&&h.UNSAFE_componentWillUpdate(o,ut,G)),typeof h.componentDidUpdate=="function"&&(i.flags|=4),typeof h.getSnapshotBeforeUpdate=="function"&&(i.flags|=1024)):(typeof h.componentDidUpdate!="function"||x===e.memoizedProps&&lt===e.memoizedState||(i.flags|=4),typeof h.getSnapshotBeforeUpdate!="function"||x===e.memoizedProps&&lt===e.memoizedState||(i.flags|=1024),i.memoizedProps=o,i.memoizedState=ut),h.props=o,h.state=ut,h.context=G,o=vt):(typeof h.componentDidUpdate!="function"||x===e.memoizedProps&&lt===e.memoizedState||(i.flags|=4),typeof h.getSnapshotBeforeUpdate!="function"||x===e.memoizedProps&&lt===e.memoizedState||(i.flags|=1024),o=!1)}return h=o,ql(e,i),o=(i.flags&128)!==0,h||o?(h=i.stateNode,a=o&&typeof a.getDerivedStateFromError!="function"?null:h.render(),i.flags|=1,e!==null&&o?(i.child=Rs(i,e.child,null,u),i.child=Rs(i,null,a,u)):Nn(e,i,a,u),i.memoizedState=h.state,e=i.child):e=la(e,i,u),e}function A0(e,i,a,o){return ys(),i.flags|=256,Nn(e,i,a,o),i.child}var Ef={dehydrated:null,treeContext:null,retryLane:0,hydrationErrors:null};function bf(e){return{baseLanes:e,cachePool:mm()}}function Tf(e,i,a){return e=e!==null?e.childLanes&~a:0,i&&(e|=li),e}function R0(e,i,a){var o=i.pendingProps,u=!1,h=(i.flags&128)!==0,x;if((x=h)||(x=e!==null&&e.memoizedState===null?!1:(hn.current&2)!==0),x&&(u=!0,i.flags&=-129),x=(i.flags&32)!==0,i.flags&=-33,e===null){if(Me){if(u?Ha(i):Ga(),(e=Ye)?(e=Pg(e,_i),e=e!==null&&e.data!=="&"?e:null,e!==null&&(i.memoizedState={dehydrated:e,treeContext:La!==null?{id:Fi,overflow:Bi}:null,retryLane:536870912,hydrationErrors:null},a=rm(e),a.return=i,i.child=a,wn=i,Ye=null)):e=null,e===null)throw Pa(i);return oh(e)?i.lanes=32:i.lanes=536870912,null}var C=o.children;return o=o.fallback,u?(Ga(),u=i.mode,C=Yl({mode:"hidden",children:C},u),o=Ss(o,u,a,null),C.return=i,o.return=i,C.sibling=o,i.child=C,o=i.child,o.memoizedState=bf(a),o.childLanes=Tf(e,x,a),i.memoizedState=Ef,Mo(null,o)):(Ha(i),Af(i,C))}var G=e.memoizedState;if(G!==null&&(C=G.dehydrated,C!==null)){if(h)i.flags&256?(Ha(i),i.flags&=-257,i=Rf(e,i,a)):i.memoizedState!==null?(Ga(),i.child=e.child,i.flags|=128,i=null):(Ga(),C=o.fallback,u=i.mode,o=Yl({mode:"visible",children:o.children},u),C=Ss(C,u,a,null),C.flags|=2,o.return=i,C.return=i,o.sibling=C,i.child=o,Rs(i,e.child,null,a),o=i.child,o.memoizedState=bf(a),o.childLanes=Tf(e,x,a),i.memoizedState=Ef,i=Mo(null,o));else if(Ha(i),oh(C)){if(x=C.nextSibling&&C.nextSibling.dataset,x)var it=x.dgst;x=it,o=Error(s(419)),o.stack="",o.digest=x,co({value:o,source:null,stack:null}),i=Rf(e,i,a)}else if(_n||ir(e,i,a,!1),x=(a&e.childLanes)!==0,_n||x){if(x=ke,x!==null&&(o=ti(x,a),o!==0&&o!==G.retryLane))throw G.retryLane=o,xs(e,o),Jn(x,e,o),yf;rh(C)||nc(),i=Rf(e,i,a)}else rh(C)?(i.flags|=192,i.child=e.child,i=null):(e=G.treeContext,Ye=Si(C.nextSibling),wn=i,Me=!0,Oa=null,_i=!1,e!==null&&cm(i,e),i=Af(i,o.children),i.flags|=4096);return i}return u?(Ga(),C=o.fallback,u=i.mode,G=e.child,it=G.sibling,o=na(G,{mode:"hidden",children:o.children}),o.subtreeFlags=G.subtreeFlags&65011712,it!==null?C=na(it,C):(C=Ss(C,u,a,null),C.flags|=2),C.return=i,o.return=i,o.sibling=C,i.child=o,Mo(null,o),o=i.child,C=e.child.memoizedState,C===null?C=bf(a):(u=C.cachePool,u!==null?(G=gn._currentValue,u=u.parent!==G?{parent:G,pool:G}:u):u=mm(),C={baseLanes:C.baseLanes|a,cachePool:u}),o.memoizedState=C,o.childLanes=Tf(e,x,a),i.memoizedState=Ef,Mo(e.child,o)):(Ha(i),a=e.child,e=a.sibling,a=na(a,{mode:"visible",children:o.children}),a.return=i,a.sibling=null,e!==null&&(x=i.deletions,x===null?(i.deletions=[e],i.flags|=16):x.push(e)),i.child=a,i.memoizedState=null,a)}function Af(e,i){return i=Yl({mode:"visible",children:i},e.mode),i.return=e,e.child=i}function Yl(e,i){return e=ai(22,e,null,i),e.lanes=0,e}function Rf(e,i,a){return Rs(i,e.child,null,a),e=Af(i,i.pendingProps.children),e.flags|=2,i.memoizedState=null,e}function C0(e,i,a){e.lanes|=i;var o=e.alternate;o!==null&&(o.lanes|=i),Gu(e.return,i,a)}function Cf(e,i,a,o,u,h){var x=e.memoizedState;x===null?e.memoizedState={isBackwards:i,rendering:null,renderingStartTime:0,last:o,tail:a,tailMode:u,treeForkCount:h}:(x.isBackwards=i,x.rendering=null,x.renderingStartTime=0,x.last=o,x.tail=a,x.tailMode=u,x.treeForkCount=h)}function w0(e,i,a){var o=i.pendingProps,u=o.revealOrder,h=o.tail;o=o.children;var x=hn.current,C=(x&2)!==0;if(C?(x=x&1|2,i.flags|=128):x&=1,bt(hn,x),Nn(e,i,o,a),o=Me?lo:0,!C&&e!==null&&(e.flags&128)!==0)t:for(e=i.child;e!==null;){if(e.tag===13)e.memoizedState!==null&&C0(e,a,i);else if(e.tag===19)C0(e,a,i);else if(e.child!==null){e.child.return=e,e=e.child;continue}if(e===i)break t;for(;e.sibling===null;){if(e.return===null||e.return===i)break t;e=e.return}e.sibling.return=e.return,e=e.sibling}switch(u){case"forwards":for(a=i.child,u=null;a!==null;)e=a.alternate,e!==null&&Pl(e)===null&&(u=a),a=a.sibling;a=u,a===null?(u=i.child,i.child=null):(u=a.sibling,a.sibling=null),Cf(i,!1,u,a,h,o);break;case"backwards":case"unstable_legacy-backwards":for(a=null,u=i.child,i.child=null;u!==null;){if(e=u.alternate,e!==null&&Pl(e)===null){i.child=u;break}e=u.sibling,u.sibling=a,a=u,u=e}Cf(i,!0,a,null,h,o);break;case"together":Cf(i,!1,null,null,void 0,o);break;default:i.memoizedState=null}return i.child}function la(e,i,a){if(e!==null&&(i.dependencies=e.dependencies),Xa|=i.lanes,(a&i.childLanes)===0)if(e!==null){if(ir(e,i,a,!1),(a&i.childLanes)===0)return null}else return null;if(e!==null&&i.child!==e.child)throw Error(s(153));if(i.child!==null){for(e=i.child,a=na(e,e.pendingProps),i.child=a,a.return=i;e.sibling!==null;)e=e.sibling,a=a.sibling=na(e,e.pendingProps),a.return=i;a.sibling=null}return i.child}function wf(e,i){return(e.lanes&i)!==0?!0:(e=e.dependencies,!!(e!==null&&Rl(e)))}function CS(e,i,a){switch(i.tag){case 3:xt(i,i.stateNode.containerInfo),Ia(i,gn,e.memoizedState.cache),ys();break;case 27:case 5:jt(i);break;case 4:xt(i,i.stateNode.containerInfo);break;case 10:Ia(i,i.type,i.memoizedProps.value);break;case 31:if(i.memoizedState!==null)return i.flags|=128,$u(i),null;break;case 13:var o=i.memoizedState;if(o!==null)return o.dehydrated!==null?(Ha(i),i.flags|=128,null):(a&i.child.childLanes)!==0?R0(e,i,a):(Ha(i),e=la(e,i,a),e!==null?e.sibling:null);Ha(i);break;case 19:var u=(e.flags&128)!==0;if(o=(a&i.childLanes)!==0,o||(ir(e,i,a,!1),o=(a&i.childLanes)!==0),u){if(o)return w0(e,i,a);i.flags|=128}if(u=i.memoizedState,u!==null&&(u.rendering=null,u.tail=null,u.lastEffect=null),bt(hn,hn.current),o)break;return null;case 22:return i.lanes=0,y0(e,i,a,i.pendingProps);case 24:Ia(i,gn,e.memoizedState.cache)}return la(e,i,a)}function D0(e,i,a){if(e!==null)if(e.memoizedProps!==i.pendingProps)_n=!0;else{if(!wf(e,a)&&(i.flags&128)===0)return _n=!1,CS(e,i,a);_n=(e.flags&131072)!==0}else _n=!1,Me&&(i.flags&1048576)!==0&&lm(i,lo,i.index);switch(i.lanes=0,i.tag){case 16:t:{var o=i.pendingProps;if(e=Ts(i.elementType),i.type=e,typeof e=="function")Lu(e)?(o=ws(e,o),i.tag=1,i=T0(null,i,e,o,a)):(i.tag=0,i=Mf(null,i,e,o,a));else{if(e!=null){var u=e.$$typeof;if(u===A){i.tag=11,i=_0(null,i,e,o,a);break t}else if(u===I){i.tag=14,i=x0(null,i,e,o,a);break t}}throw i=ht(e)||e,Error(s(306,i,""))}}return i;case 0:return Mf(e,i,i.type,i.pendingProps,a);case 1:return o=i.type,u=ws(o,i.pendingProps),T0(e,i,o,u,a);case 3:t:{if(xt(i,i.stateNode.containerInfo),e===null)throw Error(s(387));o=i.pendingProps;var h=i.memoizedState;u=h.element,Zu(e,i),vo(i,o,null,a);var x=i.memoizedState;if(o=x.cache,Ia(i,gn,o),o!==h.cache&&Vu(i,[gn],a,!0),go(),o=x.element,h.isDehydrated)if(h={element:o,isDehydrated:!1,cache:x.cache},i.updateQueue.baseState=h,i.memoizedState=h,i.flags&256){i=A0(e,i,o,a);break t}else if(o!==u){u=mi(Error(s(424)),i),co(u),i=A0(e,i,o,a);break t}else{switch(e=i.stateNode.containerInfo,e.nodeType){case 9:e=e.body;break;default:e=e.nodeName==="HTML"?e.ownerDocument.body:e}for(Ye=Si(e.firstChild),wn=i,Me=!0,Oa=null,_i=!0,a=ym(i,null,o,a),i.child=a;a;)a.flags=a.flags&-3|4096,a=a.sibling}else{if(ys(),o===u){i=la(e,i,a);break t}Nn(e,i,o,a)}i=i.child}return i;case 26:return ql(e,i),e===null?(a=Gg(i.type,null,i.pendingProps,null))?i.memoizedState=a:Me||(a=i.type,e=i.pendingProps,o=cc(tt.current).createElement(a),o[pn]=i,o[Cn]=e,Un(o,a,e),mn(o),i.stateNode=o):i.memoizedState=Gg(i.type,e.memoizedProps,i.pendingProps,e.memoizedState),null;case 27:return jt(i),e===null&&Me&&(o=i.stateNode=Fg(i.type,i.pendingProps,tt.current),wn=i,_i=!0,u=Ye,Ka(i.type)?(lh=u,Ye=Si(o.firstChild)):Ye=u),Nn(e,i,i.pendingProps.children,a),ql(e,i),e===null&&(i.flags|=4194304),i.child;case 5:return e===null&&Me&&((u=o=Ye)&&(o=ay(o,i.type,i.pendingProps,_i),o!==null?(i.stateNode=o,wn=i,Ye=Si(o.firstChild),_i=!1,u=!0):u=!1),u||Pa(i)),jt(i),u=i.type,h=i.pendingProps,x=e!==null?e.memoizedProps:null,o=h.children,ih(u,h)?o=null:x!==null&&ih(u,x)&&(i.flags|=32),i.memoizedState!==null&&(u=ef(e,i,xS,null,null,a),zo._currentValue=u),ql(e,i),Nn(e,i,o,a),i.child;case 6:return e===null&&Me&&((e=a=Ye)&&(a=sy(a,i.pendingProps,_i),a!==null?(i.stateNode=a,wn=i,Ye=null,e=!0):e=!1),e||Pa(i)),null;case 13:return R0(e,i,a);case 4:return xt(i,i.stateNode.containerInfo),o=i.pendingProps,e===null?i.child=Rs(i,null,o,a):Nn(e,i,o,a),i.child;case 11:return _0(e,i,i.type,i.pendingProps,a);case 7:return Nn(e,i,i.pendingProps,a),i.child;case 8:return Nn(e,i,i.pendingProps.children,a),i.child;case 12:return Nn(e,i,i.pendingProps.children,a),i.child;case 10:return o=i.pendingProps,Ia(i,i.type,o.value),Nn(e,i,o.children,a),i.child;case 9:return u=i.type._context,o=i.pendingProps.children,Es(i),u=Dn(u),o=o(u),i.flags|=1,Nn(e,i,o,a),i.child;case 14:return x0(e,i,i.type,i.pendingProps,a);case 15:return S0(e,i,i.type,i.pendingProps,a);case 19:return w0(e,i,a);case 31:return RS(e,i,a);case 22:return y0(e,i,a,i.pendingProps);case 24:return Es(i),o=Dn(gn),e===null?(u=Wu(),u===null&&(u=ke,h=ku(),u.pooledCache=h,h.refCount++,h!==null&&(u.pooledCacheLanes|=a),u=h),i.memoizedState={parent:o,cache:u},Yu(i),Ia(i,gn,u)):((e.lanes&a)!==0&&(Zu(e,i),vo(i,null,null,a),go()),u=e.memoizedState,h=i.memoizedState,u.parent!==o?(u={parent:o,cache:o},i.memoizedState=u,i.lanes===0&&(i.memoizedState=i.updateQueue.baseState=u),Ia(i,gn,o)):(o=h.cache,Ia(i,gn,o),o!==u.cache&&Vu(i,[gn],a,!0))),Nn(e,i,i.pendingProps.children,a),i.child;case 29:throw i.pendingProps}throw Error(s(156,i.tag))}function ca(e){e.flags|=4}function Df(e,i,a,o,u){if((i=(e.mode&32)!==0)&&(i=!1),i){if(e.flags|=16777216,(u&335544128)===u)if(e.stateNode.complete)e.flags|=8192;else if(ig())e.flags|=8192;else throw As=Nl,qu}else e.flags&=-16777217}function N0(e,i){if(i.type!=="stylesheet"||(i.state.loading&4)!==0)e.flags&=-16777217;else if(e.flags|=16777216,!qg(i))if(ig())e.flags|=8192;else throw As=Nl,qu}function Zl(e,i){i!==null&&(e.flags|=4),e.flags&16384&&(i=e.tag!==22?Tt():536870912,e.lanes|=i,mr|=i)}function Eo(e,i){if(!Me)switch(e.tailMode){case"hidden":i=e.tail;for(var a=null;i!==null;)i.alternate!==null&&(a=i),i=i.sibling;a===null?e.tail=null:a.sibling=null;break;case"collapsed":a=e.tail;for(var o=null;a!==null;)a.alternate!==null&&(o=a),a=a.sibling;o===null?i||e.tail===null?e.tail=null:e.tail.sibling=null:o.sibling=null}}function Ze(e){var i=e.alternate!==null&&e.alternate.child===e.child,a=0,o=0;if(i)for(var u=e.child;u!==null;)a|=u.lanes|u.childLanes,o|=u.subtreeFlags&65011712,o|=u.flags&65011712,u.return=e,u=u.sibling;else for(u=e.child;u!==null;)a|=u.lanes|u.childLanes,o|=u.subtreeFlags,o|=u.flags,u.return=e,u=u.sibling;return e.subtreeFlags|=o,e.childLanes=a,i}function wS(e,i,a){var o=i.pendingProps;switch(zu(i),i.tag){case 16:case 15:case 0:case 11:case 7:case 8:case 12:case 9:case 14:return Ze(i),null;case 1:return Ze(i),null;case 3:return a=i.stateNode,o=null,e!==null&&(o=e.memoizedState.cache),i.memoizedState.cache!==o&&(i.flags|=2048),sa(gn),It(),a.pendingContext&&(a.context=a.pendingContext,a.pendingContext=null),(e===null||e.child===null)&&(nr(i)?ca(i):e===null||e.memoizedState.isDehydrated&&(i.flags&256)===0||(i.flags|=1024,Bu())),Ze(i),null;case 26:var u=i.type,h=i.memoizedState;return e===null?(ca(i),h!==null?(Ze(i),N0(i,h)):(Ze(i),Df(i,u,null,o,a))):h?h!==e.memoizedState?(ca(i),Ze(i),N0(i,h)):(Ze(i),i.flags&=-16777217):(e=e.memoizedProps,e!==o&&ca(i),Ze(i),Df(i,u,e,o,a)),null;case 27:if(Jt(i),a=tt.current,u=i.type,e!==null&&i.stateNode!=null)e.memoizedProps!==o&&ca(i);else{if(!o){if(i.stateNode===null)throw Error(s(166));return Ze(i),null}e=pt.current,nr(i)?um(i):(e=Fg(u,o,a),i.stateNode=e,ca(i))}return Ze(i),null;case 5:if(Jt(i),u=i.type,e!==null&&i.stateNode!=null)e.memoizedProps!==o&&ca(i);else{if(!o){if(i.stateNode===null)throw Error(s(166));return Ze(i),null}if(h=pt.current,nr(i))um(i);else{var x=cc(tt.current);switch(h){case 1:h=x.createElementNS("http://www.w3.org/2000/svg",u);break;case 2:h=x.createElementNS("http://www.w3.org/1998/Math/MathML",u);break;default:switch(u){case"svg":h=x.createElementNS("http://www.w3.org/2000/svg",u);break;case"math":h=x.createElementNS("http://www.w3.org/1998/Math/MathML",u);break;case"script":h=x.createElement("div"),h.innerHTML="<script><\/script>",h=h.removeChild(h.firstChild);break;case"select":h=typeof o.is=="string"?x.createElement("select",{is:o.is}):x.createElement("select"),o.multiple?h.multiple=!0:o.size&&(h.size=o.size);break;default:h=typeof o.is=="string"?x.createElement(u,{is:o.is}):x.createElement(u)}}h[pn]=i,h[Cn]=o;t:for(x=i.child;x!==null;){if(x.tag===5||x.tag===6)h.appendChild(x.stateNode);else if(x.tag!==4&&x.tag!==27&&x.child!==null){x.child.return=x,x=x.child;continue}if(x===i)break t;for(;x.sibling===null;){if(x.return===null||x.return===i)break t;x=x.return}x.sibling.return=x.return,x=x.sibling}i.stateNode=h;t:switch(Un(h,u,o),u){case"button":case"input":case"select":case"textarea":o=!!o.autoFocus;break t;case"img":o=!0;break t;default:o=!1}o&&ca(i)}}return Ze(i),Df(i,i.type,e===null?null:e.memoizedProps,i.pendingProps,a),null;case 6:if(e&&i.stateNode!=null)e.memoizedProps!==o&&ca(i);else{if(typeof o!="string"&&i.stateNode===null)throw Error(s(166));if(e=tt.current,nr(i)){if(e=i.stateNode,a=i.memoizedProps,o=null,u=wn,u!==null)switch(u.tag){case 27:case 5:o=u.memoizedProps}e[pn]=i,e=!!(e.nodeValue===a||o!==null&&o.suppressHydrationWarning===!0||Rg(e.nodeValue,a)),e||Pa(i,!0)}else e=cc(e).createTextNode(o),e[pn]=i,i.stateNode=e}return Ze(i),null;case 31:if(a=i.memoizedState,e===null||e.memoizedState!==null){if(o=nr(i),a!==null){if(e===null){if(!o)throw Error(s(318));if(e=i.memoizedState,e=e!==null?e.dehydrated:null,!e)throw Error(s(557));e[pn]=i}else ys(),(i.flags&128)===0&&(i.memoizedState=null),i.flags|=4;Ze(i),e=!1}else a=Bu(),e!==null&&e.memoizedState!==null&&(e.memoizedState.hydrationErrors=a),e=!0;if(!e)return i.flags&256?(ri(i),i):(ri(i),null);if((i.flags&128)!==0)throw Error(s(558))}return Ze(i),null;case 13:if(o=i.memoizedState,e===null||e.memoizedState!==null&&e.memoizedState.dehydrated!==null){if(u=nr(i),o!==null&&o.dehydrated!==null){if(e===null){if(!u)throw Error(s(318));if(u=i.memoizedState,u=u!==null?u.dehydrated:null,!u)throw Error(s(317));u[pn]=i}else ys(),(i.flags&128)===0&&(i.memoizedState=null),i.flags|=4;Ze(i),u=!1}else u=Bu(),e!==null&&e.memoizedState!==null&&(e.memoizedState.hydrationErrors=u),u=!0;if(!u)return i.flags&256?(ri(i),i):(ri(i),null)}return ri(i),(i.flags&128)!==0?(i.lanes=a,i):(a=o!==null,e=e!==null&&e.memoizedState!==null,a&&(o=i.child,u=null,o.alternate!==null&&o.alternate.memoizedState!==null&&o.alternate.memoizedState.cachePool!==null&&(u=o.alternate.memoizedState.cachePool.pool),h=null,o.memoizedState!==null&&o.memoizedState.cachePool!==null&&(h=o.memoizedState.cachePool.pool),h!==u&&(o.flags|=2048)),a!==e&&a&&(i.child.flags|=8192),Zl(i,i.updateQueue),Ze(i),null);case 4:return It(),e===null&&Qf(i.stateNode.containerInfo),Ze(i),null;case 10:return sa(i.type),Ze(i),null;case 19:if(J(hn),o=i.memoizedState,o===null)return Ze(i),null;if(u=(i.flags&128)!==0,h=o.rendering,h===null)if(u)Eo(o,!1);else{if(ln!==0||e!==null&&(e.flags&128)!==0)for(e=i.child;e!==null;){if(h=Pl(e),h!==null){for(i.flags|=128,Eo(o,!1),e=h.updateQueue,i.updateQueue=e,Zl(i,e),i.subtreeFlags=0,e=a,a=i.child;a!==null;)sm(a,e),a=a.sibling;return bt(hn,hn.current&1|2),Me&&ia(i,o.treeForkCount),i.child}e=e.sibling}o.tail!==null&&Fe()>$l&&(i.flags|=128,u=!0,Eo(o,!1),i.lanes=4194304)}else{if(!u)if(e=Pl(h),e!==null){if(i.flags|=128,u=!0,e=e.updateQueue,i.updateQueue=e,Zl(i,e),Eo(o,!0),o.tail===null&&o.tailMode==="hidden"&&!h.alternate&&!Me)return Ze(i),null}else 2*Fe()-o.renderingStartTime>$l&&a!==536870912&&(i.flags|=128,u=!0,Eo(o,!1),i.lanes=4194304);o.isBackwards?(h.sibling=i.child,i.child=h):(e=o.last,e!==null?e.sibling=h:i.child=h,o.last=h)}return o.tail!==null?(e=o.tail,o.rendering=e,o.tail=e.sibling,o.renderingStartTime=Fe(),e.sibling=null,a=hn.current,bt(hn,u?a&1|2:a&1),Me&&ia(i,o.treeForkCount),e):(Ze(i),null);case 22:case 23:return ri(i),Qu(),o=i.memoizedState!==null,e!==null?e.memoizedState!==null!==o&&(i.flags|=8192):o&&(i.flags|=8192),o?(a&536870912)!==0&&(i.flags&128)===0&&(Ze(i),i.subtreeFlags&6&&(i.flags|=8192)):Ze(i),a=i.updateQueue,a!==null&&Zl(i,a.retryQueue),a=null,e!==null&&e.memoizedState!==null&&e.memoizedState.cachePool!==null&&(a=e.memoizedState.cachePool.pool),o=null,i.memoizedState!==null&&i.memoizedState.cachePool!==null&&(o=i.memoizedState.cachePool.pool),o!==a&&(i.flags|=2048),e!==null&&J(bs),null;case 24:return a=null,e!==null&&(a=e.memoizedState.cache),i.memoizedState.cache!==a&&(i.flags|=2048),sa(gn),Ze(i),null;case 25:return null;case 30:return null}throw Error(s(156,i.tag))}function DS(e,i){switch(zu(i),i.tag){case 1:return e=i.flags,e&65536?(i.flags=e&-65537|128,i):null;case 3:return sa(gn),It(),e=i.flags,(e&65536)!==0&&(e&128)===0?(i.flags=e&-65537|128,i):null;case 26:case 27:case 5:return Jt(i),null;case 31:if(i.memoizedState!==null){if(ri(i),i.alternate===null)throw Error(s(340));ys()}return e=i.flags,e&65536?(i.flags=e&-65537|128,i):null;case 13:if(ri(i),e=i.memoizedState,e!==null&&e.dehydrated!==null){if(i.alternate===null)throw Error(s(340));ys()}return e=i.flags,e&65536?(i.flags=e&-65537|128,i):null;case 19:return J(hn),null;case 4:return It(),null;case 10:return sa(i.type),null;case 22:case 23:return ri(i),Qu(),e!==null&&J(bs),e=i.flags,e&65536?(i.flags=e&-65537|128,i):null;case 24:return sa(gn),null;case 25:return null;default:return null}}function U0(e,i){switch(zu(i),i.tag){case 3:sa(gn),It();break;case 26:case 27:case 5:Jt(i);break;case 4:It();break;case 31:i.memoizedState!==null&&ri(i);break;case 13:ri(i);break;case 19:J(hn);break;case 10:sa(i.type);break;case 22:case 23:ri(i),Qu(),e!==null&&J(bs);break;case 24:sa(gn)}}function bo(e,i){try{var a=i.updateQueue,o=a!==null?a.lastEffect:null;if(o!==null){var u=o.next;a=u;do{if((a.tag&e)===e){o=void 0;var h=a.create,x=a.inst;o=h(),x.destroy=o}a=a.next}while(a!==u)}}catch(C){Ie(i,i.return,C)}}function Va(e,i,a){try{var o=i.updateQueue,u=o!==null?o.lastEffect:null;if(u!==null){var h=u.next;o=h;do{if((o.tag&e)===e){var x=o.inst,C=x.destroy;if(C!==void 0){x.destroy=void 0,u=i;var G=a,it=C;try{it()}catch(vt){Ie(u,G,vt)}}}o=o.next}while(o!==h)}}catch(vt){Ie(i,i.return,vt)}}function L0(e){var i=e.updateQueue;if(i!==null){var a=e.stateNode;try{Em(i,a)}catch(o){Ie(e,e.return,o)}}}function O0(e,i,a){a.props=ws(e.type,e.memoizedProps),a.state=e.memoizedState;try{a.componentWillUnmount()}catch(o){Ie(e,i,o)}}function To(e,i){try{var a=e.ref;if(a!==null){switch(e.tag){case 26:case 27:case 5:var o=e.stateNode;break;case 30:o=e.stateNode;break;default:o=e.stateNode}typeof a=="function"?e.refCleanup=a(o):a.current=o}}catch(u){Ie(e,i,u)}}function Hi(e,i){var a=e.ref,o=e.refCleanup;if(a!==null)if(typeof o=="function")try{o()}catch(u){Ie(e,i,u)}finally{e.refCleanup=null,e=e.alternate,e!=null&&(e.refCleanup=null)}else if(typeof a=="function")try{a(null)}catch(u){Ie(e,i,u)}else a.current=null}function P0(e){var i=e.type,a=e.memoizedProps,o=e.stateNode;try{t:switch(i){case"button":case"input":case"select":case"textarea":a.autoFocus&&o.focus();break t;case"img":a.src?o.src=a.src:a.srcSet&&(o.srcset=a.srcSet)}}catch(u){Ie(e,e.return,u)}}function Nf(e,i,a){try{var o=e.stateNode;QS(o,e.type,a,i),o[Cn]=i}catch(u){Ie(e,e.return,u)}}function I0(e){return e.tag===5||e.tag===3||e.tag===26||e.tag===27&&Ka(e.type)||e.tag===4}function Uf(e){t:for(;;){for(;e.sibling===null;){if(e.return===null||I0(e.return))return null;e=e.return}for(e.sibling.return=e.return,e=e.sibling;e.tag!==5&&e.tag!==6&&e.tag!==18;){if(e.tag===27&&Ka(e.type)||e.flags&2||e.child===null||e.tag===4)continue t;e.child.return=e,e=e.child}if(!(e.flags&2))return e.stateNode}}function Lf(e,i,a){var o=e.tag;if(o===5||o===6)e=e.stateNode,i?(a.nodeType===9?a.body:a.nodeName==="HTML"?a.ownerDocument.body:a).insertBefore(e,i):(i=a.nodeType===9?a.body:a.nodeName==="HTML"?a.ownerDocument.body:a,i.appendChild(e),a=a._reactRootContainer,a!=null||i.onclick!==null||(i.onclick=ta));else if(o!==4&&(o===27&&Ka(e.type)&&(a=e.stateNode,i=null),e=e.child,e!==null))for(Lf(e,i,a),e=e.sibling;e!==null;)Lf(e,i,a),e=e.sibling}function Kl(e,i,a){var o=e.tag;if(o===5||o===6)e=e.stateNode,i?a.insertBefore(e,i):a.appendChild(e);else if(o!==4&&(o===27&&Ka(e.type)&&(a=e.stateNode),e=e.child,e!==null))for(Kl(e,i,a),e=e.sibling;e!==null;)Kl(e,i,a),e=e.sibling}function z0(e){var i=e.stateNode,a=e.memoizedProps;try{for(var o=e.type,u=i.attributes;u.length;)i.removeAttributeNode(u[0]);Un(i,o,a),i[pn]=e,i[Cn]=a}catch(h){Ie(e,e.return,h)}}var ua=!1,xn=!1,Of=!1,F0=typeof WeakSet=="function"?WeakSet:Set,Tn=null;function NS(e,i){if(e=e.containerInfo,eh=gc,e=jp(e),Au(e)){if("selectionStart"in e)var a={start:e.selectionStart,end:e.selectionEnd};else t:{a=(a=e.ownerDocument)&&a.defaultView||window;var o=a.getSelection&&a.getSelection();if(o&&o.rangeCount!==0){a=o.anchorNode;var u=o.anchorOffset,h=o.focusNode;o=o.focusOffset;try{a.nodeType,h.nodeType}catch{a=null;break t}var x=0,C=-1,G=-1,it=0,vt=0,Et=e,lt=null;e:for(;;){for(var ut;Et!==a||u!==0&&Et.nodeType!==3||(C=x+u),Et!==h||o!==0&&Et.nodeType!==3||(G=x+o),Et.nodeType===3&&(x+=Et.nodeValue.length),(ut=Et.firstChild)!==null;)lt=Et,Et=ut;for(;;){if(Et===e)break e;if(lt===a&&++it===u&&(C=x),lt===h&&++vt===o&&(G=x),(ut=Et.nextSibling)!==null)break;Et=lt,lt=Et.parentNode}Et=ut}a=C===-1||G===-1?null:{start:C,end:G}}else a=null}a=a||{start:0,end:0}}else a=null;for(nh={focusedElem:e,selectionRange:a},gc=!1,Tn=i;Tn!==null;)if(i=Tn,e=i.child,(i.subtreeFlags&1028)!==0&&e!==null)e.return=i,Tn=e;else for(;Tn!==null;){switch(i=Tn,h=i.alternate,e=i.flags,i.tag){case 0:if((e&4)!==0&&(e=i.updateQueue,e=e!==null?e.events:null,e!==null))for(a=0;a<e.length;a++)u=e[a],u.ref.impl=u.nextImpl;break;case 11:case 15:break;case 1:if((e&1024)!==0&&h!==null){e=void 0,a=i,u=h.memoizedProps,h=h.memoizedState,o=a.stateNode;try{var Wt=ws(a.type,u);e=o.getSnapshotBeforeUpdate(Wt,h),o.__reactInternalSnapshotBeforeUpdate=e}catch(ne){Ie(a,a.return,ne)}}break;case 3:if((e&1024)!==0){if(e=i.stateNode.containerInfo,a=e.nodeType,a===9)sh(e);else if(a===1)switch(e.nodeName){case"HEAD":case"HTML":case"BODY":sh(e);break;default:e.textContent=""}}break;case 5:case 26:case 27:case 6:case 4:case 17:break;default:if((e&1024)!==0)throw Error(s(163))}if(e=i.sibling,e!==null){e.return=i.return,Tn=e;break}Tn=i.return}}function B0(e,i,a){var o=a.flags;switch(a.tag){case 0:case 11:case 15:ha(e,a),o&4&&bo(5,a);break;case 1:if(ha(e,a),o&4)if(e=a.stateNode,i===null)try{e.componentDidMount()}catch(x){Ie(a,a.return,x)}else{var u=ws(a.type,i.memoizedProps);i=i.memoizedState;try{e.componentDidUpdate(u,i,e.__reactInternalSnapshotBeforeUpdate)}catch(x){Ie(a,a.return,x)}}o&64&&L0(a),o&512&&To(a,a.return);break;case 3:if(ha(e,a),o&64&&(e=a.updateQueue,e!==null)){if(i=null,a.child!==null)switch(a.child.tag){case 27:case 5:i=a.child.stateNode;break;case 1:i=a.child.stateNode}try{Em(e,i)}catch(x){Ie(a,a.return,x)}}break;case 27:i===null&&o&4&&z0(a);case 26:case 5:ha(e,a),i===null&&o&4&&P0(a),o&512&&To(a,a.return);break;case 12:ha(e,a);break;case 31:ha(e,a),o&4&&V0(e,a);break;case 13:ha(e,a),o&4&&k0(e,a),o&64&&(e=a.memoizedState,e!==null&&(e=e.dehydrated,e!==null&&(a=HS.bind(null,a),ry(e,a))));break;case 22:if(o=a.memoizedState!==null||ua,!o){i=i!==null&&i.memoizedState!==null||xn,u=ua;var h=xn;ua=o,(xn=i)&&!h?da(e,a,(a.subtreeFlags&8772)!==0):ha(e,a),ua=u,xn=h}break;case 30:break;default:ha(e,a)}}function H0(e){var i=e.alternate;i!==null&&(e.alternate=null,H0(i)),e.child=null,e.deletions=null,e.sibling=null,e.tag===5&&(i=e.stateNode,i!==null&&wa(i)),e.stateNode=null,e.return=null,e.dependencies=null,e.memoizedProps=null,e.memoizedState=null,e.pendingProps=null,e.stateNode=null,e.updateQueue=null}var Qe=null,Yn=!1;function fa(e,i,a){for(a=a.child;a!==null;)G0(e,i,a),a=a.sibling}function G0(e,i,a){if(gt&&typeof gt.onCommitFiberUnmount=="function")try{gt.onCommitFiberUnmount(ft,a)}catch{}switch(a.tag){case 26:xn||Hi(a,i),fa(e,i,a),a.memoizedState?a.memoizedState.count--:a.stateNode&&(a=a.stateNode,a.parentNode.removeChild(a));break;case 27:xn||Hi(a,i);var o=Qe,u=Yn;Ka(a.type)&&(Qe=a.stateNode,Yn=!1),fa(e,i,a),Oo(a.stateNode),Qe=o,Yn=u;break;case 5:xn||Hi(a,i);case 6:if(o=Qe,u=Yn,Qe=null,fa(e,i,a),Qe=o,Yn=u,Qe!==null)if(Yn)try{(Qe.nodeType===9?Qe.body:Qe.nodeName==="HTML"?Qe.ownerDocument.body:Qe).removeChild(a.stateNode)}catch(h){Ie(a,i,h)}else try{Qe.removeChild(a.stateNode)}catch(h){Ie(a,i,h)}break;case 18:Qe!==null&&(Yn?(e=Qe,Lg(e.nodeType===9?e.body:e.nodeName==="HTML"?e.ownerDocument.body:e,a.stateNode),Er(e)):Lg(Qe,a.stateNode));break;case 4:o=Qe,u=Yn,Qe=a.stateNode.containerInfo,Yn=!0,fa(e,i,a),Qe=o,Yn=u;break;case 0:case 11:case 14:case 15:Va(2,a,i),xn||Va(4,a,i),fa(e,i,a);break;case 1:xn||(Hi(a,i),o=a.stateNode,typeof o.componentWillUnmount=="function"&&O0(a,i,o)),fa(e,i,a);break;case 21:fa(e,i,a);break;case 22:xn=(o=xn)||a.memoizedState!==null,fa(e,i,a),xn=o;break;default:fa(e,i,a)}}function V0(e,i){if(i.memoizedState===null&&(e=i.alternate,e!==null&&(e=e.memoizedState,e!==null))){e=e.dehydrated;try{Er(e)}catch(a){Ie(i,i.return,a)}}}function k0(e,i){if(i.memoizedState===null&&(e=i.alternate,e!==null&&(e=e.memoizedState,e!==null&&(e=e.dehydrated,e!==null))))try{Er(e)}catch(a){Ie(i,i.return,a)}}function US(e){switch(e.tag){case 31:case 13:case 19:var i=e.stateNode;return i===null&&(i=e.stateNode=new F0),i;case 22:return e=e.stateNode,i=e._retryCache,i===null&&(i=e._retryCache=new F0),i;default:throw Error(s(435,e.tag))}}function jl(e,i){var a=US(e);i.forEach(function(o){if(!a.has(o)){a.add(o);var u=GS.bind(null,e,o);o.then(u,u)}})}function Zn(e,i){var a=i.deletions;if(a!==null)for(var o=0;o<a.length;o++){var u=a[o],h=e,x=i,C=x;t:for(;C!==null;){switch(C.tag){case 27:if(Ka(C.type)){Qe=C.stateNode,Yn=!1;break t}break;case 5:Qe=C.stateNode,Yn=!1;break t;case 3:case 4:Qe=C.stateNode.containerInfo,Yn=!0;break t}C=C.return}if(Qe===null)throw Error(s(160));G0(h,x,u),Qe=null,Yn=!1,h=u.alternate,h!==null&&(h.return=null),u.return=null}if(i.subtreeFlags&13886)for(i=i.child;i!==null;)X0(i,e),i=i.sibling}var wi=null;function X0(e,i){var a=e.alternate,o=e.flags;switch(e.tag){case 0:case 11:case 14:case 15:Zn(i,e),Kn(e),o&4&&(Va(3,e,e.return),bo(3,e),Va(5,e,e.return));break;case 1:Zn(i,e),Kn(e),o&512&&(xn||a===null||Hi(a,a.return)),o&64&&ua&&(e=e.updateQueue,e!==null&&(o=e.callbacks,o!==null&&(a=e.shared.hiddenCallbacks,e.shared.hiddenCallbacks=a===null?o:a.concat(o))));break;case 26:var u=wi;if(Zn(i,e),Kn(e),o&512&&(xn||a===null||Hi(a,a.return)),o&4){var h=a!==null?a.memoizedState:null;if(o=e.memoizedState,a===null)if(o===null)if(e.stateNode===null){t:{o=e.type,a=e.memoizedProps,u=u.ownerDocument||u;e:switch(o){case"title":h=u.getElementsByTagName("title")[0],(!h||h[Ca]||h[pn]||h.namespaceURI==="http://www.w3.org/2000/svg"||h.hasAttribute("itemprop"))&&(h=u.createElement(o),u.head.insertBefore(h,u.querySelector("head > title"))),Un(h,o,a),h[pn]=e,mn(h),o=h;break t;case"link":var x=Xg("link","href",u).get(o+(a.href||""));if(x){for(var C=0;C<x.length;C++)if(h=x[C],h.getAttribute("href")===(a.href==null||a.href===""?null:a.href)&&h.getAttribute("rel")===(a.rel==null?null:a.rel)&&h.getAttribute("title")===(a.title==null?null:a.title)&&h.getAttribute("crossorigin")===(a.crossOrigin==null?null:a.crossOrigin)){x.splice(C,1);break e}}h=u.createElement(o),Un(h,o,a),u.head.appendChild(h);break;case"meta":if(x=Xg("meta","content",u).get(o+(a.content||""))){for(C=0;C<x.length;C++)if(h=x[C],h.getAttribute("content")===(a.content==null?null:""+a.content)&&h.getAttribute("name")===(a.name==null?null:a.name)&&h.getAttribute("property")===(a.property==null?null:a.property)&&h.getAttribute("http-equiv")===(a.httpEquiv==null?null:a.httpEquiv)&&h.getAttribute("charset")===(a.charSet==null?null:a.charSet)){x.splice(C,1);break e}}h=u.createElement(o),Un(h,o,a),u.head.appendChild(h);break;default:throw Error(s(468,o))}h[pn]=e,mn(h),o=h}e.stateNode=o}else Wg(u,e.type,e.stateNode);else e.stateNode=kg(u,o,e.memoizedProps);else h!==o?(h===null?a.stateNode!==null&&(a=a.stateNode,a.parentNode.removeChild(a)):h.count--,o===null?Wg(u,e.type,e.stateNode):kg(u,o,e.memoizedProps)):o===null&&e.stateNode!==null&&Nf(e,e.memoizedProps,a.memoizedProps)}break;case 27:Zn(i,e),Kn(e),o&512&&(xn||a===null||Hi(a,a.return)),a!==null&&o&4&&Nf(e,e.memoizedProps,a.memoizedProps);break;case 5:if(Zn(i,e),Kn(e),o&512&&(xn||a===null||Hi(a,a.return)),e.flags&32){u=e.stateNode;try{ni(u,"")}catch(Wt){Ie(e,e.return,Wt)}}o&4&&e.stateNode!=null&&(u=e.memoizedProps,Nf(e,u,a!==null?a.memoizedProps:u)),o&1024&&(Of=!0);break;case 6:if(Zn(i,e),Kn(e),o&4){if(e.stateNode===null)throw Error(s(162));o=e.memoizedProps,a=e.stateNode;try{a.nodeValue=o}catch(Wt){Ie(e,e.return,Wt)}}break;case 3:if(hc=null,u=wi,wi=uc(i.containerInfo),Zn(i,e),wi=u,Kn(e),o&4&&a!==null&&a.memoizedState.isDehydrated)try{Er(i.containerInfo)}catch(Wt){Ie(e,e.return,Wt)}Of&&(Of=!1,W0(e));break;case 4:o=wi,wi=uc(e.stateNode.containerInfo),Zn(i,e),Kn(e),wi=o;break;case 12:Zn(i,e),Kn(e);break;case 31:Zn(i,e),Kn(e),o&4&&(o=e.updateQueue,o!==null&&(e.updateQueue=null,jl(e,o)));break;case 13:Zn(i,e),Kn(e),e.child.flags&8192&&e.memoizedState!==null!=(a!==null&&a.memoizedState!==null)&&(Ql=Fe()),o&4&&(o=e.updateQueue,o!==null&&(e.updateQueue=null,jl(e,o)));break;case 22:u=e.memoizedState!==null;var G=a!==null&&a.memoizedState!==null,it=ua,vt=xn;if(ua=it||u,xn=vt||G,Zn(i,e),xn=vt,ua=it,Kn(e),o&8192)t:for(i=e.stateNode,i._visibility=u?i._visibility&-2:i._visibility|1,u&&(a===null||G||ua||xn||Ds(e)),a=null,i=e;;){if(i.tag===5||i.tag===26){if(a===null){G=a=i;try{if(h=G.stateNode,u)x=h.style,typeof x.setProperty=="function"?x.setProperty("display","none","important"):x.display="none";else{C=G.stateNode;var Et=G.memoizedProps.style,lt=Et!=null&&Et.hasOwnProperty("display")?Et.display:null;C.style.display=lt==null||typeof lt=="boolean"?"":(""+lt).trim()}}catch(Wt){Ie(G,G.return,Wt)}}}else if(i.tag===6){if(a===null){G=i;try{G.stateNode.nodeValue=u?"":G.memoizedProps}catch(Wt){Ie(G,G.return,Wt)}}}else if(i.tag===18){if(a===null){G=i;try{var ut=G.stateNode;u?Og(ut,!0):Og(G.stateNode,!1)}catch(Wt){Ie(G,G.return,Wt)}}}else if((i.tag!==22&&i.tag!==23||i.memoizedState===null||i===e)&&i.child!==null){i.child.return=i,i=i.child;continue}if(i===e)break t;for(;i.sibling===null;){if(i.return===null||i.return===e)break t;a===i&&(a=null),i=i.return}a===i&&(a=null),i.sibling.return=i.return,i=i.sibling}o&4&&(o=e.updateQueue,o!==null&&(a=o.retryQueue,a!==null&&(o.retryQueue=null,jl(e,a))));break;case 19:Zn(i,e),Kn(e),o&4&&(o=e.updateQueue,o!==null&&(e.updateQueue=null,jl(e,o)));break;case 30:break;case 21:break;default:Zn(i,e),Kn(e)}}function Kn(e){var i=e.flags;if(i&2){try{for(var a,o=e.return;o!==null;){if(I0(o)){a=o;break}o=o.return}if(a==null)throw Error(s(160));switch(a.tag){case 27:var u=a.stateNode,h=Uf(e);Kl(e,h,u);break;case 5:var x=a.stateNode;a.flags&32&&(ni(x,""),a.flags&=-33);var C=Uf(e);Kl(e,C,x);break;case 3:case 4:var G=a.stateNode.containerInfo,it=Uf(e);Lf(e,it,G);break;default:throw Error(s(161))}}catch(vt){Ie(e,e.return,vt)}e.flags&=-3}i&4096&&(e.flags&=-4097)}function W0(e){if(e.subtreeFlags&1024)for(e=e.child;e!==null;){var i=e;W0(i),i.tag===5&&i.flags&1024&&i.stateNode.reset(),e=e.sibling}}function ha(e,i){if(i.subtreeFlags&8772)for(i=i.child;i!==null;)B0(e,i.alternate,i),i=i.sibling}function Ds(e){for(e=e.child;e!==null;){var i=e;switch(i.tag){case 0:case 11:case 14:case 15:Va(4,i,i.return),Ds(i);break;case 1:Hi(i,i.return);var a=i.stateNode;typeof a.componentWillUnmount=="function"&&O0(i,i.return,a),Ds(i);break;case 27:Oo(i.stateNode);case 26:case 5:Hi(i,i.return),Ds(i);break;case 22:i.memoizedState===null&&Ds(i);break;case 30:Ds(i);break;default:Ds(i)}e=e.sibling}}function da(e,i,a){for(a=a&&(i.subtreeFlags&8772)!==0,i=i.child;i!==null;){var o=i.alternate,u=e,h=i,x=h.flags;switch(h.tag){case 0:case 11:case 15:da(u,h,a),bo(4,h);break;case 1:if(da(u,h,a),o=h,u=o.stateNode,typeof u.componentDidMount=="function")try{u.componentDidMount()}catch(it){Ie(o,o.return,it)}if(o=h,u=o.updateQueue,u!==null){var C=o.stateNode;try{var G=u.shared.hiddenCallbacks;if(G!==null)for(u.shared.hiddenCallbacks=null,u=0;u<G.length;u++)Mm(G[u],C)}catch(it){Ie(o,o.return,it)}}a&&x&64&&L0(h),To(h,h.return);break;case 27:z0(h);case 26:case 5:da(u,h,a),a&&o===null&&x&4&&P0(h),To(h,h.return);break;case 12:da(u,h,a);break;case 31:da(u,h,a),a&&x&4&&V0(u,h);break;case 13:da(u,h,a),a&&x&4&&k0(u,h);break;case 22:h.memoizedState===null&&da(u,h,a),To(h,h.return);break;case 30:break;default:da(u,h,a)}i=i.sibling}}function Pf(e,i){var a=null;e!==null&&e.memoizedState!==null&&e.memoizedState.cachePool!==null&&(a=e.memoizedState.cachePool.pool),e=null,i.memoizedState!==null&&i.memoizedState.cachePool!==null&&(e=i.memoizedState.cachePool.pool),e!==a&&(e!=null&&e.refCount++,a!=null&&uo(a))}function If(e,i){e=null,i.alternate!==null&&(e=i.alternate.memoizedState.cache),i=i.memoizedState.cache,i!==e&&(i.refCount++,e!=null&&uo(e))}function Di(e,i,a,o){if(i.subtreeFlags&10256)for(i=i.child;i!==null;)q0(e,i,a,o),i=i.sibling}function q0(e,i,a,o){var u=i.flags;switch(i.tag){case 0:case 11:case 15:Di(e,i,a,o),u&2048&&bo(9,i);break;case 1:Di(e,i,a,o);break;case 3:Di(e,i,a,o),u&2048&&(e=null,i.alternate!==null&&(e=i.alternate.memoizedState.cache),i=i.memoizedState.cache,i!==e&&(i.refCount++,e!=null&&uo(e)));break;case 12:if(u&2048){Di(e,i,a,o),e=i.stateNode;try{var h=i.memoizedProps,x=h.id,C=h.onPostCommit;typeof C=="function"&&C(x,i.alternate===null?"mount":"update",e.passiveEffectDuration,-0)}catch(G){Ie(i,i.return,G)}}else Di(e,i,a,o);break;case 31:Di(e,i,a,o);break;case 13:Di(e,i,a,o);break;case 23:break;case 22:h=i.stateNode,x=i.alternate,i.memoizedState!==null?h._visibility&2?Di(e,i,a,o):Ao(e,i):h._visibility&2?Di(e,i,a,o):(h._visibility|=2,hr(e,i,a,o,(i.subtreeFlags&10256)!==0||!1)),u&2048&&Pf(x,i);break;case 24:Di(e,i,a,o),u&2048&&If(i.alternate,i);break;default:Di(e,i,a,o)}}function hr(e,i,a,o,u){for(u=u&&((i.subtreeFlags&10256)!==0||!1),i=i.child;i!==null;){var h=e,x=i,C=a,G=o,it=x.flags;switch(x.tag){case 0:case 11:case 15:hr(h,x,C,G,u),bo(8,x);break;case 23:break;case 22:var vt=x.stateNode;x.memoizedState!==null?vt._visibility&2?hr(h,x,C,G,u):Ao(h,x):(vt._visibility|=2,hr(h,x,C,G,u)),u&&it&2048&&Pf(x.alternate,x);break;case 24:hr(h,x,C,G,u),u&&it&2048&&If(x.alternate,x);break;default:hr(h,x,C,G,u)}i=i.sibling}}function Ao(e,i){if(i.subtreeFlags&10256)for(i=i.child;i!==null;){var a=e,o=i,u=o.flags;switch(o.tag){case 22:Ao(a,o),u&2048&&Pf(o.alternate,o);break;case 24:Ao(a,o),u&2048&&If(o.alternate,o);break;default:Ao(a,o)}i=i.sibling}}var Ro=8192;function dr(e,i,a){if(e.subtreeFlags&Ro)for(e=e.child;e!==null;)Y0(e,i,a),e=e.sibling}function Y0(e,i,a){switch(e.tag){case 26:dr(e,i,a),e.flags&Ro&&e.memoizedState!==null&&_y(a,wi,e.memoizedState,e.memoizedProps);break;case 5:dr(e,i,a);break;case 3:case 4:var o=wi;wi=uc(e.stateNode.containerInfo),dr(e,i,a),wi=o;break;case 22:e.memoizedState===null&&(o=e.alternate,o!==null&&o.memoizedState!==null?(o=Ro,Ro=16777216,dr(e,i,a),Ro=o):dr(e,i,a));break;default:dr(e,i,a)}}function Z0(e){var i=e.alternate;if(i!==null&&(e=i.child,e!==null)){i.child=null;do i=e.sibling,e.sibling=null,e=i;while(e!==null)}}function Co(e){var i=e.deletions;if((e.flags&16)!==0){if(i!==null)for(var a=0;a<i.length;a++){var o=i[a];Tn=o,j0(o,e)}Z0(e)}if(e.subtreeFlags&10256)for(e=e.child;e!==null;)K0(e),e=e.sibling}function K0(e){switch(e.tag){case 0:case 11:case 15:Co(e),e.flags&2048&&Va(9,e,e.return);break;case 3:Co(e);break;case 12:Co(e);break;case 22:var i=e.stateNode;e.memoizedState!==null&&i._visibility&2&&(e.return===null||e.return.tag!==13)?(i._visibility&=-3,Jl(e)):Co(e);break;default:Co(e)}}function Jl(e){var i=e.deletions;if((e.flags&16)!==0){if(i!==null)for(var a=0;a<i.length;a++){var o=i[a];Tn=o,j0(o,e)}Z0(e)}for(e=e.child;e!==null;){switch(i=e,i.tag){case 0:case 11:case 15:Va(8,i,i.return),Jl(i);break;case 22:a=i.stateNode,a._visibility&2&&(a._visibility&=-3,Jl(i));break;default:Jl(i)}e=e.sibling}}function j0(e,i){for(;Tn!==null;){var a=Tn;switch(a.tag){case 0:case 11:case 15:Va(8,a,i);break;case 23:case 22:if(a.memoizedState!==null&&a.memoizedState.cachePool!==null){var o=a.memoizedState.cachePool.pool;o!=null&&o.refCount++}break;case 24:uo(a.memoizedState.cache)}if(o=a.child,o!==null)o.return=a,Tn=o;else t:for(a=e;Tn!==null;){o=Tn;var u=o.sibling,h=o.return;if(H0(o),o===a){Tn=null;break t}if(u!==null){u.return=h,Tn=u;break t}Tn=h}}}var LS={getCacheForType:function(e){var i=Dn(gn),a=i.data.get(e);return a===void 0&&(a=e(),i.data.set(e,a)),a},cacheSignal:function(){return Dn(gn).controller.signal}},OS=typeof WeakMap=="function"?WeakMap:Map,we=0,ke=null,me=null,_e=0,Pe=0,oi=null,ka=!1,pr=!1,zf=!1,pa=0,ln=0,Xa=0,Ns=0,Ff=0,li=0,mr=0,wo=null,jn=null,Bf=!1,Ql=0,J0=0,$l=1/0,tc=null,Wa=null,Mn=0,qa=null,gr=null,ma=0,Hf=0,Gf=null,Q0=null,Do=0,Vf=null;function ci(){return(we&2)!==0&&_e!==0?_e&-_e:B.T!==null?Zf():Qr()}function $0(){if(li===0)if((_e&536870912)===0||Me){var e=ae;ae<<=1,(ae&3932160)===0&&(ae=262144),li=e}else li=536870912;return e=si.current,e!==null&&(e.flags|=32),li}function Jn(e,i,a){(e===ke&&(Pe===2||Pe===9)||e.cancelPendingCommit!==null)&&(vr(e,0),Ya(e,_e,li,!1)),Vt(e,a),((we&2)===0||e!==ke)&&(e===ke&&((we&2)===0&&(Ns|=a),ln===4&&Ya(e,_e,li,!1)),Gi(e))}function tg(e,i,a){if((we&6)!==0)throw Error(s(327));var o=!a&&(i&127)===0&&(i&e.expiredLanes)===0||Dt(e,i),u=o?zS(e,i):Xf(e,i,!0),h=o;do{if(u===0){pr&&!o&&Ya(e,i,0,!1);break}else{if(a=e.current.alternate,h&&!PS(a)){u=Xf(e,i,!1),h=!1;continue}if(u===2){if(h=i,e.errorRecoveryDisabledLanes&h)var x=0;else x=e.pendingLanes&-536870913,x=x!==0?x:x&536870912?536870912:0;if(x!==0){i=x;t:{var C=e;u=wo;var G=C.current.memoizedState.isDehydrated;if(G&&(vr(C,x).flags|=256),x=Xf(C,x,!1),x!==2){if(zf&&!G){C.errorRecoveryDisabledLanes|=h,Ns|=h,u=4;break t}h=jn,jn=u,h!==null&&(jn===null?jn=h:jn.push.apply(jn,h))}u=x}if(h=!1,u!==2)continue}}if(u===1){vr(e,0),Ya(e,i,0,!0);break}t:{switch(o=e,h=u,h){case 0:case 1:throw Error(s(345));case 4:if((i&4194048)!==i)break;case 6:Ya(o,i,li,!ka);break t;case 2:jn=null;break;case 3:case 5:break;default:throw Error(s(329))}if((i&62914560)===i&&(u=Ql+300-Fe(),10<u)){if(Ya(o,i,li,!ka),St(o,0,!0)!==0)break t;ma=i,o.timeoutHandle=Ng(eg.bind(null,o,a,jn,tc,Bf,i,li,Ns,mr,ka,h,"Throttled",-0,0),u);break t}eg(o,a,jn,tc,Bf,i,li,Ns,mr,ka,h,null,-0,0)}}break}while(!0);Gi(e)}function eg(e,i,a,o,u,h,x,C,G,it,vt,Et,lt,ut){if(e.timeoutHandle=-1,Et=i.subtreeFlags,Et&8192||(Et&16785408)===16785408){Et={stylesheets:null,count:0,imgCount:0,imgBytes:0,suspenseyImages:[],waitingForImages:!0,waitingForViewTransition:!1,unsuspend:ta},Y0(i,h,Et);var Wt=(h&62914560)===h?Ql-Fe():(h&4194048)===h?J0-Fe():0;if(Wt=xy(Et,Wt),Wt!==null){ma=h,e.cancelPendingCommit=Wt(cg.bind(null,e,i,h,a,o,u,x,C,G,vt,Et,null,lt,ut)),Ya(e,h,x,!it);return}}cg(e,i,h,a,o,u,x,C,G)}function PS(e){for(var i=e;;){var a=i.tag;if((a===0||a===11||a===15)&&i.flags&16384&&(a=i.updateQueue,a!==null&&(a=a.stores,a!==null)))for(var o=0;o<a.length;o++){var u=a[o],h=u.getSnapshot;u=u.value;try{if(!ii(h(),u))return!1}catch{return!1}}if(a=i.child,i.subtreeFlags&16384&&a!==null)a.return=i,i=a;else{if(i===e)break;for(;i.sibling===null;){if(i.return===null||i.return===e)return!0;i=i.return}i.sibling.return=i.return,i=i.sibling}}return!0}function Ya(e,i,a,o){i&=~Ff,i&=~Ns,e.suspendedLanes|=i,e.pingedLanes&=~i,o&&(e.warmLanes|=i),o=e.expirationTimes;for(var u=i;0<u;){var h=31-Bt(u),x=1<<h;o[h]=-1,u&=~x}a!==0&&Ne(e,a,i)}function ec(){return(we&6)===0?(No(0),!1):!0}function kf(){if(me!==null){if(Pe===0)var e=me.return;else e=me,aa=Ms=null,sf(e),or=null,ho=0,e=me;for(;e!==null;)U0(e.alternate,e),e=e.return;me=null}}function vr(e,i){var a=e.timeoutHandle;a!==-1&&(e.timeoutHandle=-1,ey(a)),a=e.cancelPendingCommit,a!==null&&(e.cancelPendingCommit=null,a()),ma=0,kf(),ke=e,me=a=na(e.current,null),_e=i,Pe=0,oi=null,ka=!1,pr=Dt(e,i),zf=!1,mr=li=Ff=Ns=Xa=ln=0,jn=wo=null,Bf=!1,(i&8)!==0&&(i|=i&32);var o=e.entangledLanes;if(o!==0)for(e=e.entanglements,o&=i;0<o;){var u=31-Bt(o),h=1<<u;i|=e[u],o&=~h}return pa=i,Ml(),a}function ng(e,i){le=null,B.H=yo,i===rr||i===Dl?(i=_m(),Pe=3):i===qu?(i=_m(),Pe=4):Pe=i===yf?8:i!==null&&typeof i=="object"&&typeof i.then=="function"?6:1,oi=i,me===null&&(ln=1,Xl(e,mi(i,e.current)))}function ig(){var e=si.current;return e===null?!0:(_e&4194048)===_e?xi===null:(_e&62914560)===_e||(_e&536870912)!==0?e===xi:!1}function ag(){var e=B.H;return B.H=yo,e===null?yo:e}function sg(){var e=B.A;return B.A=LS,e}function nc(){ln=4,ka||(_e&4194048)!==_e&&si.current!==null||(pr=!0),(Xa&134217727)===0&&(Ns&134217727)===0||ke===null||Ya(ke,_e,li,!1)}function Xf(e,i,a){var o=we;we|=2;var u=ag(),h=sg();(ke!==e||_e!==i)&&(tc=null,vr(e,i)),i=!1;var x=ln;t:do try{if(Pe!==0&&me!==null){var C=me,G=oi;switch(Pe){case 8:kf(),x=6;break t;case 3:case 2:case 9:case 6:si.current===null&&(i=!0);var it=Pe;if(Pe=0,oi=null,_r(e,C,G,it),a&&pr){x=0;break t}break;default:it=Pe,Pe=0,oi=null,_r(e,C,G,it)}}IS(),x=ln;break}catch(vt){ng(e,vt)}while(!0);return i&&e.shellSuspendCounter++,aa=Ms=null,we=o,B.H=u,B.A=h,me===null&&(ke=null,_e=0,Ml()),x}function IS(){for(;me!==null;)rg(me)}function zS(e,i){var a=we;we|=2;var o=ag(),u=sg();ke!==e||_e!==i?(tc=null,$l=Fe()+500,vr(e,i)):pr=Dt(e,i);t:do try{if(Pe!==0&&me!==null){i=me;var h=oi;e:switch(Pe){case 1:Pe=0,oi=null,_r(e,i,h,1);break;case 2:case 9:if(gm(h)){Pe=0,oi=null,og(i);break}i=function(){Pe!==2&&Pe!==9||ke!==e||(Pe=7),Gi(e)},h.then(i,i);break t;case 3:Pe=7;break t;case 4:Pe=5;break t;case 7:gm(h)?(Pe=0,oi=null,og(i)):(Pe=0,oi=null,_r(e,i,h,7));break;case 5:var x=null;switch(me.tag){case 26:x=me.memoizedState;case 5:case 27:var C=me;if(x?qg(x):C.stateNode.complete){Pe=0,oi=null;var G=C.sibling;if(G!==null)me=G;else{var it=C.return;it!==null?(me=it,ic(it)):me=null}break e}}Pe=0,oi=null,_r(e,i,h,5);break;case 6:Pe=0,oi=null,_r(e,i,h,6);break;case 8:kf(),ln=6;break t;default:throw Error(s(462))}}FS();break}catch(vt){ng(e,vt)}while(!0);return aa=Ms=null,B.H=o,B.A=u,we=a,me!==null?0:(ke=null,_e=0,Ml(),ln)}function FS(){for(;me!==null&&!rn();)rg(me)}function rg(e){var i=D0(e.alternate,e,pa);e.memoizedProps=e.pendingProps,i===null?ic(e):me=i}function og(e){var i=e,a=i.alternate;switch(i.tag){case 15:case 0:i=b0(a,i,i.pendingProps,i.type,void 0,_e);break;case 11:i=b0(a,i,i.pendingProps,i.type.render,i.ref,_e);break;case 5:sf(i);default:U0(a,i),i=me=sm(i,pa),i=D0(a,i,pa)}e.memoizedProps=e.pendingProps,i===null?ic(e):me=i}function _r(e,i,a,o){aa=Ms=null,sf(i),or=null,ho=0;var u=i.return;try{if(AS(e,u,i,a,_e)){ln=1,Xl(e,mi(a,e.current)),me=null;return}}catch(h){if(u!==null)throw me=u,h;ln=1,Xl(e,mi(a,e.current)),me=null;return}i.flags&32768?(Me||o===1?e=!0:pr||(_e&536870912)!==0?e=!1:(ka=e=!0,(o===2||o===9||o===3||o===6)&&(o=si.current,o!==null&&o.tag===13&&(o.flags|=16384))),lg(i,e)):ic(i)}function ic(e){var i=e;do{if((i.flags&32768)!==0){lg(i,ka);return}e=i.return;var a=wS(i.alternate,i,pa);if(a!==null){me=a;return}if(i=i.sibling,i!==null){me=i;return}me=i=e}while(i!==null);ln===0&&(ln=5)}function lg(e,i){do{var a=DS(e.alternate,e);if(a!==null){a.flags&=32767,me=a;return}if(a=e.return,a!==null&&(a.flags|=32768,a.subtreeFlags=0,a.deletions=null),!i&&(e=e.sibling,e!==null)){me=e;return}me=e=a}while(e!==null);ln=6,me=null}function cg(e,i,a,o,u,h,x,C,G){e.cancelPendingCommit=null;do ac();while(Mn!==0);if((we&6)!==0)throw Error(s(327));if(i!==null){if(i===e.current)throw Error(s(177));if(h=i.lanes|i.childLanes,h|=Nu,Ke(e,a,h,x,C,G),e===ke&&(me=ke=null,_e=0),gr=i,qa=e,ma=a,Hf=h,Gf=u,Q0=o,(i.subtreeFlags&10256)!==0||(i.flags&10256)!==0?(e.callbackNode=null,e.callbackPriority=0,VS(et,function(){return pg(),null})):(e.callbackNode=null,e.callbackPriority=0),o=(i.flags&13878)!==0,(i.subtreeFlags&13878)!==0||o){o=B.T,B.T=null,u=H.p,H.p=2,x=we,we|=4;try{NS(e,i,a)}finally{we=x,H.p=u,B.T=o}}Mn=1,ug(),fg(),hg()}}function ug(){if(Mn===1){Mn=0;var e=qa,i=gr,a=(i.flags&13878)!==0;if((i.subtreeFlags&13878)!==0||a){a=B.T,B.T=null;var o=H.p;H.p=2;var u=we;we|=4;try{X0(i,e);var h=nh,x=jp(e.containerInfo),C=h.focusedElem,G=h.selectionRange;if(x!==C&&C&&C.ownerDocument&&Kp(C.ownerDocument.documentElement,C)){if(G!==null&&Au(C)){var it=G.start,vt=G.end;if(vt===void 0&&(vt=it),"selectionStart"in C)C.selectionStart=it,C.selectionEnd=Math.min(vt,C.value.length);else{var Et=C.ownerDocument||document,lt=Et&&Et.defaultView||window;if(lt.getSelection){var ut=lt.getSelection(),Wt=C.textContent.length,ne=Math.min(G.start,Wt),Ge=G.end===void 0?ne:Math.min(G.end,Wt);!ut.extend&&ne>Ge&&(x=Ge,Ge=ne,ne=x);var Q=Zp(C,ne),k=Zp(C,Ge);if(Q&&k&&(ut.rangeCount!==1||ut.anchorNode!==Q.node||ut.anchorOffset!==Q.offset||ut.focusNode!==k.node||ut.focusOffset!==k.offset)){var nt=Et.createRange();nt.setStart(Q.node,Q.offset),ut.removeAllRanges(),ne>Ge?(ut.addRange(nt),ut.extend(k.node,k.offset)):(nt.setEnd(k.node,k.offset),ut.addRange(nt))}}}}for(Et=[],ut=C;ut=ut.parentNode;)ut.nodeType===1&&Et.push({element:ut,left:ut.scrollLeft,top:ut.scrollTop});for(typeof C.focus=="function"&&C.focus(),C=0;C<Et.length;C++){var yt=Et[C];yt.element.scrollLeft=yt.left,yt.element.scrollTop=yt.top}}gc=!!eh,nh=eh=null}finally{we=u,H.p=o,B.T=a}}e.current=i,Mn=2}}function fg(){if(Mn===2){Mn=0;var e=qa,i=gr,a=(i.flags&8772)!==0;if((i.subtreeFlags&8772)!==0||a){a=B.T,B.T=null;var o=H.p;H.p=2;var u=we;we|=4;try{B0(e,i.alternate,i)}finally{we=u,H.p=o,B.T=a}}Mn=3}}function hg(){if(Mn===4||Mn===3){Mn=0,Z();var e=qa,i=gr,a=ma,o=Q0;(i.subtreeFlags&10256)!==0||(i.flags&10256)!==0?Mn=5:(Mn=0,gr=qa=null,dg(e,e.pendingLanes));var u=e.pendingLanes;if(u===0&&(Wa=null),Jr(a),i=i.stateNode,gt&&typeof gt.onCommitFiberRoot=="function")try{gt.onCommitFiberRoot(ft,i,void 0,(i.current.flags&128)===128)}catch{}if(o!==null){i=B.T,u=H.p,H.p=2,B.T=null;try{for(var h=e.onRecoverableError,x=0;x<o.length;x++){var C=o[x];h(C.value,{componentStack:C.stack})}}finally{B.T=i,H.p=u}}(ma&3)!==0&&ac(),Gi(e),u=e.pendingLanes,(a&261930)!==0&&(u&42)!==0?e===Vf?Do++:(Do=0,Vf=e):Do=0,No(0)}}function dg(e,i){(e.pooledCacheLanes&=i)===0&&(i=e.pooledCache,i!=null&&(e.pooledCache=null,uo(i)))}function ac(){return ug(),fg(),hg(),pg()}function pg(){if(Mn!==5)return!1;var e=qa,i=Hf;Hf=0;var a=Jr(ma),o=B.T,u=H.p;try{H.p=32>a?32:a,B.T=null,a=Gf,Gf=null;var h=qa,x=ma;if(Mn=0,gr=qa=null,ma=0,(we&6)!==0)throw Error(s(331));var C=we;if(we|=4,K0(h.current),q0(h,h.current,x,a),we=C,No(0,!1),gt&&typeof gt.onPostCommitFiberRoot=="function")try{gt.onPostCommitFiberRoot(ft,h)}catch{}return!0}finally{H.p=u,B.T=o,dg(e,i)}}function mg(e,i,a){i=mi(a,i),i=Sf(e.stateNode,i,2),e=Ba(e,i,2),e!==null&&(Vt(e,2),Gi(e))}function Ie(e,i,a){if(e.tag===3)mg(e,e,a);else for(;i!==null;){if(i.tag===3){mg(i,e,a);break}else if(i.tag===1){var o=i.stateNode;if(typeof i.type.getDerivedStateFromError=="function"||typeof o.componentDidCatch=="function"&&(Wa===null||!Wa.has(o))){e=mi(a,e),a=g0(2),o=Ba(i,a,2),o!==null&&(v0(a,o,i,e),Vt(o,2),Gi(o));break}}i=i.return}}function Wf(e,i,a){var o=e.pingCache;if(o===null){o=e.pingCache=new OS;var u=new Set;o.set(i,u)}else u=o.get(i),u===void 0&&(u=new Set,o.set(i,u));u.has(a)||(zf=!0,u.add(a),e=BS.bind(null,e,i,a),i.then(e,e))}function BS(e,i,a){var o=e.pingCache;o!==null&&o.delete(i),e.pingedLanes|=e.suspendedLanes&a,e.warmLanes&=~a,ke===e&&(_e&a)===a&&(ln===4||ln===3&&(_e&62914560)===_e&&300>Fe()-Ql?(we&2)===0&&vr(e,0):Ff|=a,mr===_e&&(mr=0)),Gi(e)}function gg(e,i){i===0&&(i=Tt()),e=xs(e,i),e!==null&&(Vt(e,i),Gi(e))}function HS(e){var i=e.memoizedState,a=0;i!==null&&(a=i.retryLane),gg(e,a)}function GS(e,i){var a=0;switch(e.tag){case 31:case 13:var o=e.stateNode,u=e.memoizedState;u!==null&&(a=u.retryLane);break;case 19:o=e.stateNode;break;case 22:o=e.stateNode._retryCache;break;default:throw Error(s(314))}o!==null&&o.delete(i),gg(e,a)}function VS(e,i){return fn(e,i)}var sc=null,xr=null,qf=!1,rc=!1,Yf=!1,Za=0;function Gi(e){e!==xr&&e.next===null&&(xr===null?sc=xr=e:xr=xr.next=e),rc=!0,qf||(qf=!0,XS())}function No(e,i){if(!Yf&&rc){Yf=!0;do for(var a=!1,o=sc;o!==null;){if(e!==0){var u=o.pendingLanes;if(u===0)var h=0;else{var x=o.suspendedLanes,C=o.pingedLanes;h=(1<<31-Bt(42|e)+1)-1,h&=u&~(x&~C),h=h&201326741?h&201326741|1:h?h|2:0}h!==0&&(a=!0,Sg(o,h))}else h=_e,h=St(o,o===ke?h:0,o.cancelPendingCommit!==null||o.timeoutHandle!==-1),(h&3)===0||Dt(o,h)||(a=!0,Sg(o,h));o=o.next}while(a);Yf=!1}}function kS(){vg()}function vg(){rc=qf=!1;var e=0;Za!==0&&ty()&&(e=Za);for(var i=Fe(),a=null,o=sc;o!==null;){var u=o.next,h=_g(o,i);h===0?(o.next=null,a===null?sc=u:a.next=u,u===null&&(xr=a)):(a=o,(e!==0||(h&3)!==0)&&(rc=!0)),o=u}Mn!==0&&Mn!==5||No(e),Za!==0&&(Za=0)}function _g(e,i){for(var a=e.suspendedLanes,o=e.pingedLanes,u=e.expirationTimes,h=e.pendingLanes&-62914561;0<h;){var x=31-Bt(h),C=1<<x,G=u[x];G===-1?((C&a)===0||(C&o)!==0)&&(u[x]=Ft(C,i)):G<=i&&(e.expiredLanes|=C),h&=~C}if(i=ke,a=_e,a=St(e,e===i?a:0,e.cancelPendingCommit!==null||e.timeoutHandle!==-1),o=e.callbackNode,a===0||e===i&&(Pe===2||Pe===9)||e.cancelPendingCommit!==null)return o!==null&&o!==null&&We(o),e.callbackNode=null,e.callbackPriority=0;if((a&3)===0||Dt(e,a)){if(i=a&-a,i===e.callbackPriority)return i;switch(o!==null&&We(o),Jr(a)){case 2:case 8:a=E;break;case 32:a=et;break;case 268435456:a=mt;break;default:a=et}return o=xg.bind(null,e),a=fn(a,o),e.callbackPriority=i,e.callbackNode=a,i}return o!==null&&o!==null&&We(o),e.callbackPriority=2,e.callbackNode=null,2}function xg(e,i){if(Mn!==0&&Mn!==5)return e.callbackNode=null,e.callbackPriority=0,null;var a=e.callbackNode;if(ac()&&e.callbackNode!==a)return null;var o=_e;return o=St(e,e===ke?o:0,e.cancelPendingCommit!==null||e.timeoutHandle!==-1),o===0?null:(tg(e,o,i),_g(e,Fe()),e.callbackNode!=null&&e.callbackNode===a?xg.bind(null,e):null)}function Sg(e,i){if(ac())return null;tg(e,i,!0)}function XS(){ny(function(){(we&6)!==0?fn(L,kS):vg()})}function Zf(){if(Za===0){var e=ar;e===0&&(e=$t,$t<<=1,($t&261888)===0&&($t=256)),Za=e}return Za}function yg(e){return e==null||typeof e=="symbol"||typeof e=="boolean"?null:typeof e=="function"?e:ms(""+e)}function Mg(e,i){var a=i.ownerDocument.createElement("input");return a.name=i.name,a.value=i.value,e.id&&a.setAttribute("form",e.id),i.parentNode.insertBefore(a,i),e=new FormData(e),a.parentNode.removeChild(a),e}function WS(e,i,a,o,u){if(i==="submit"&&a&&a.stateNode===u){var h=yg((u[Cn]||null).action),x=o.submitter;x&&(i=(i=x[Cn]||null)?yg(i.formAction):x.getAttribute("formAction"),i!==null&&(h=i,x=null));var C=new _l("action","action",null,o,u);e.push({event:C,listeners:[{instance:null,listener:function(){if(o.defaultPrevented){if(Za!==0){var G=x?Mg(u,x):new FormData(u);pf(a,{pending:!0,data:G,method:u.method,action:h},null,G)}}else typeof h=="function"&&(C.preventDefault(),G=x?Mg(u,x):new FormData(u),pf(a,{pending:!0,data:G,method:u.method,action:h},h,G))},currentTarget:u}]})}}for(var Kf=0;Kf<Du.length;Kf++){var jf=Du[Kf],qS=jf.toLowerCase(),YS=jf[0].toUpperCase()+jf.slice(1);Ci(qS,"on"+YS)}Ci($p,"onAnimationEnd"),Ci(tm,"onAnimationIteration"),Ci(em,"onAnimationStart"),Ci("dblclick","onDoubleClick"),Ci("focusin","onFocus"),Ci("focusout","onBlur"),Ci(cS,"onTransitionRun"),Ci(uS,"onTransitionStart"),Ci(fS,"onTransitionCancel"),Ci(nm,"onTransitionEnd"),ot("onMouseEnter",["mouseout","mouseover"]),ot("onMouseLeave",["mouseout","mouseover"]),ot("onPointerEnter",["pointerout","pointerover"]),ot("onPointerLeave",["pointerout","pointerover"]),Y("onChange","change click focusin focusout input keydown keyup selectionchange".split(" ")),Y("onSelect","focusout contextmenu dragend focusin keydown keyup mousedown mouseup selectionchange".split(" ")),Y("onBeforeInput",["compositionend","keypress","textInput","paste"]),Y("onCompositionEnd","compositionend focusout keydown keypress keyup mousedown".split(" ")),Y("onCompositionStart","compositionstart focusout keydown keypress keyup mousedown".split(" ")),Y("onCompositionUpdate","compositionupdate focusout keydown keypress keyup mousedown".split(" "));var Uo="abort canplay canplaythrough durationchange emptied encrypted ended error loadeddata loadedmetadata loadstart pause play playing progress ratechange resize seeked seeking stalled suspend timeupdate volumechange waiting".split(" "),ZS=new Set("beforetoggle cancel close invalid load scroll scrollend toggle".split(" ").concat(Uo));function Eg(e,i){i=(i&4)!==0;for(var a=0;a<e.length;a++){var o=e[a],u=o.event;o=o.listeners;t:{var h=void 0;if(i)for(var x=o.length-1;0<=x;x--){var C=o[x],G=C.instance,it=C.currentTarget;if(C=C.listener,G!==h&&u.isPropagationStopped())break t;h=C,u.currentTarget=it;try{h(u)}catch(vt){yl(vt)}u.currentTarget=null,h=G}else for(x=0;x<o.length;x++){if(C=o[x],G=C.instance,it=C.currentTarget,C=C.listener,G!==h&&u.isPropagationStopped())break t;h=C,u.currentTarget=it;try{h(u)}catch(vt){yl(vt)}u.currentTarget=null,h=G}}}}function ge(e,i){var a=i[hs];a===void 0&&(a=i[hs]=new Set);var o=e+"__bubble";a.has(o)||(bg(i,e,2,!1),a.add(o))}function Jf(e,i,a){var o=0;i&&(o|=4),bg(a,e,o,i)}var oc="_reactListening"+Math.random().toString(36).slice(2);function Qf(e){if(!e[oc]){e[oc]=!0,pl.forEach(function(a){a!=="selectionchange"&&(ZS.has(a)||Jf(a,!1,e),Jf(a,!0,e))});var i=e.nodeType===9?e:e.ownerDocument;i===null||i[oc]||(i[oc]=!0,Jf("selectionchange",!1,i))}}function bg(e,i,a,o){switch($g(i)){case 2:var u=My;break;case 8:u=Ey;break;default:u=dh}a=u.bind(null,i,a,e),u=void 0,!vu||i!=="touchstart"&&i!=="touchmove"&&i!=="wheel"||(u=!0),o?u!==void 0?e.addEventListener(i,a,{capture:!0,passive:u}):e.addEventListener(i,a,!0):u!==void 0?e.addEventListener(i,a,{passive:u}):e.addEventListener(i,a,!1)}function $f(e,i,a,o,u){var h=o;if((i&1)===0&&(i&2)===0&&o!==null)t:for(;;){if(o===null)return;var x=o.tag;if(x===3||x===4){var C=o.stateNode.containerInfo;if(C===u)break;if(x===4)for(x=o.return;x!==null;){var G=x.tag;if((G===3||G===4)&&x.stateNode.containerInfo===u)return;x=x.return}for(;C!==null;){if(x=Qi(C),x===null)return;if(G=x.tag,G===5||G===6||G===26||G===27){o=h=x;continue t}C=C.parentNode}}o=o.return}wp(function(){var it=h,vt=mu(a),Et=[];t:{var lt=im.get(e);if(lt!==void 0){var ut=_l,Wt=e;switch(e){case"keypress":if(gl(a)===0)break t;case"keydown":case"keyup":ut=Gx;break;case"focusin":Wt="focus",ut=yu;break;case"focusout":Wt="blur",ut=yu;break;case"beforeblur":case"afterblur":ut=yu;break;case"click":if(a.button===2)break t;case"auxclick":case"dblclick":case"mousedown":case"mousemove":case"mouseup":case"mouseout":case"mouseover":case"contextmenu":ut=Up;break;case"drag":case"dragend":case"dragenter":case"dragexit":case"dragleave":case"dragover":case"dragstart":case"drop":ut=wx;break;case"touchcancel":case"touchend":case"touchmove":case"touchstart":ut=Xx;break;case $p:case tm:case em:ut=Ux;break;case nm:ut=qx;break;case"scroll":case"scrollend":ut=Rx;break;case"wheel":ut=Zx;break;case"copy":case"cut":case"paste":ut=Ox;break;case"gotpointercapture":case"lostpointercapture":case"pointercancel":case"pointerdown":case"pointermove":case"pointerout":case"pointerover":case"pointerup":ut=Op;break;case"toggle":case"beforetoggle":ut=jx}var ne=(i&4)!==0,Ge=!ne&&(e==="scroll"||e==="scrollend"),Q=ne?lt!==null?lt+"Capture":null:lt;ne=[];for(var k=it,nt;k!==null;){var yt=k;if(nt=yt.stateNode,yt=yt.tag,yt!==5&&yt!==26&&yt!==27||nt===null||Q===null||(yt=$r(k,Q),yt!=null&&ne.push(Lo(k,yt,nt))),Ge)break;k=k.return}0<ne.length&&(lt=new ut(lt,Wt,null,a,vt),Et.push({event:lt,listeners:ne}))}}if((i&7)===0){t:{if(lt=e==="mouseover"||e==="pointerover",ut=e==="mouseout"||e==="pointerout",lt&&a!==pu&&(Wt=a.relatedTarget||a.fromElement)&&(Qi(Wt)||Wt[Wn]))break t;if((ut||lt)&&(lt=vt.window===vt?vt:(lt=vt.ownerDocument)?lt.defaultView||lt.parentWindow:window,ut?(Wt=a.relatedTarget||a.toElement,ut=it,Wt=Wt?Qi(Wt):null,Wt!==null&&(Ge=c(Wt),ne=Wt.tag,Wt!==Ge||ne!==5&&ne!==27&&ne!==6)&&(Wt=null)):(ut=null,Wt=it),ut!==Wt)){if(ne=Up,yt="onMouseLeave",Q="onMouseEnter",k="mouse",(e==="pointerout"||e==="pointerover")&&(ne=Op,yt="onPointerLeave",Q="onPointerEnter",k="pointer"),Ge=ut==null?lt:ps(ut),nt=Wt==null?lt:ps(Wt),lt=new ne(yt,k+"leave",ut,a,vt),lt.target=Ge,lt.relatedTarget=nt,yt=null,Qi(vt)===it&&(ne=new ne(Q,k+"enter",Wt,a,vt),ne.target=nt,ne.relatedTarget=Ge,yt=ne),Ge=yt,ut&&Wt)e:{for(ne=KS,Q=ut,k=Wt,nt=0,yt=Q;yt;yt=ne(yt))nt++;yt=0;for(var ee=k;ee;ee=ne(ee))yt++;for(;0<nt-yt;)Q=ne(Q),nt--;for(;0<yt-nt;)k=ne(k),yt--;for(;nt--;){if(Q===k||k!==null&&Q===k.alternate){ne=Q;break e}Q=ne(Q),k=ne(k)}ne=null}else ne=null;ut!==null&&Tg(Et,lt,ut,ne,!1),Wt!==null&&Ge!==null&&Tg(Et,Ge,Wt,ne,!0)}}t:{if(lt=it?ps(it):window,ut=lt.nodeName&&lt.nodeName.toLowerCase(),ut==="select"||ut==="input"&&lt.type==="file")var Ae=Vp;else if(Hp(lt))if(kp)Ae=rS;else{Ae=aS;var Zt=iS}else ut=lt.nodeName,!ut||ut.toLowerCase()!=="input"||lt.type!=="checkbox"&&lt.type!=="radio"?it&&De(it.elementType)&&(Ae=Vp):Ae=sS;if(Ae&&(Ae=Ae(e,it))){Gp(Et,Ae,a,vt);break t}Zt&&Zt(e,lt,it),e==="focusout"&&it&&lt.type==="number"&&it.memoizedProps.value!=null&&pe(lt,"number",lt.value)}switch(Zt=it?ps(it):window,e){case"focusin":(Hp(Zt)||Zt.contentEditable==="true")&&(js=Zt,Ru=it,oo=null);break;case"focusout":oo=Ru=js=null;break;case"mousedown":Cu=!0;break;case"contextmenu":case"mouseup":case"dragend":Cu=!1,Jp(Et,a,vt);break;case"selectionchange":if(lS)break;case"keydown":case"keyup":Jp(Et,a,vt)}var ce;if(Eu)t:{switch(e){case"compositionstart":var xe="onCompositionStart";break t;case"compositionend":xe="onCompositionEnd";break t;case"compositionupdate":xe="onCompositionUpdate";break t}xe=void 0}else Ks?Fp(e,a)&&(xe="onCompositionEnd"):e==="keydown"&&a.keyCode===229&&(xe="onCompositionStart");xe&&(Pp&&a.locale!=="ko"&&(Ks||xe!=="onCompositionStart"?xe==="onCompositionEnd"&&Ks&&(ce=Dp()):(Ua=vt,_u="value"in Ua?Ua.value:Ua.textContent,Ks=!0)),Zt=lc(it,xe),0<Zt.length&&(xe=new Lp(xe,e,null,a,vt),Et.push({event:xe,listeners:Zt}),ce?xe.data=ce:(ce=Bp(a),ce!==null&&(xe.data=ce)))),(ce=Qx?$x(e,a):tS(e,a))&&(xe=lc(it,"onBeforeInput"),0<xe.length&&(Zt=new Lp("onBeforeInput","beforeinput",null,a,vt),Et.push({event:Zt,listeners:xe}),Zt.data=ce)),WS(Et,e,it,a,vt)}Eg(Et,i)})}function Lo(e,i,a){return{instance:e,listener:i,currentTarget:a}}function lc(e,i){for(var a=i+"Capture",o=[];e!==null;){var u=e,h=u.stateNode;if(u=u.tag,u!==5&&u!==26&&u!==27||h===null||(u=$r(e,a),u!=null&&o.unshift(Lo(e,u,h)),u=$r(e,i),u!=null&&o.push(Lo(e,u,h))),e.tag===3)return o;e=e.return}return[]}function KS(e){if(e===null)return null;do e=e.return;while(e&&e.tag!==5&&e.tag!==27);return e||null}function Tg(e,i,a,o,u){for(var h=i._reactName,x=[];a!==null&&a!==o;){var C=a,G=C.alternate,it=C.stateNode;if(C=C.tag,G!==null&&G===o)break;C!==5&&C!==26&&C!==27||it===null||(G=it,u?(it=$r(a,h),it!=null&&x.unshift(Lo(a,it,G))):u||(it=$r(a,h),it!=null&&x.push(Lo(a,it,G)))),a=a.return}x.length!==0&&e.push({event:i,listeners:x})}var jS=/\r\n?/g,JS=/\u0000|\uFFFD/g;function Ag(e){return(typeof e=="string"?e:""+e).replace(jS,`
`).replace(JS,"")}function Rg(e,i){return i=Ag(i),Ag(e)===i}function He(e,i,a,o,u,h){switch(a){case"children":typeof o=="string"?i==="body"||i==="textarea"&&o===""||ni(e,o):(typeof o=="number"||typeof o=="bigint")&&i!=="body"&&ni(e,""+o);break;case"className":Xt(e,"class",o);break;case"tabIndex":Xt(e,"tabindex",o);break;case"dir":case"role":case"viewBox":case"width":case"height":Xt(e,a,o);break;case"style":Ri(e,o,h);break;case"data":if(i!=="object"){Xt(e,"data",o);break}case"src":case"href":if(o===""&&(i!=="a"||a!=="href")){e.removeAttribute(a);break}if(o==null||typeof o=="function"||typeof o=="symbol"||typeof o=="boolean"){e.removeAttribute(a);break}o=ms(""+o),e.setAttribute(a,o);break;case"action":case"formAction":if(typeof o=="function"){e.setAttribute(a,"javascript:throw new Error('A React form was unexpectedly submitted. If you called form.submit() manually, consider using form.requestSubmit() instead. If you\\'re trying to use event.stopPropagation() in a submit event handler, consider also calling event.preventDefault().')");break}else typeof h=="function"&&(a==="formAction"?(i!=="input"&&He(e,i,"name",u.name,u,null),He(e,i,"formEncType",u.formEncType,u,null),He(e,i,"formMethod",u.formMethod,u,null),He(e,i,"formTarget",u.formTarget,u,null)):(He(e,i,"encType",u.encType,u,null),He(e,i,"method",u.method,u,null),He(e,i,"target",u.target,u,null)));if(o==null||typeof o=="symbol"||typeof o=="boolean"){e.removeAttribute(a);break}o=ms(""+o),e.setAttribute(a,o);break;case"onClick":o!=null&&(e.onclick=ta);break;case"onScroll":o!=null&&ge("scroll",e);break;case"onScrollEnd":o!=null&&ge("scrollend",e);break;case"dangerouslySetInnerHTML":if(o!=null){if(typeof o!="object"||!("__html"in o))throw Error(s(61));if(a=o.__html,a!=null){if(u.children!=null)throw Error(s(60));e.innerHTML=a}}break;case"multiple":e.multiple=o&&typeof o!="function"&&typeof o!="symbol";break;case"muted":e.muted=o&&typeof o!="function"&&typeof o!="symbol";break;case"suppressContentEditableWarning":case"suppressHydrationWarning":case"defaultValue":case"defaultChecked":case"innerHTML":case"ref":break;case"autoFocus":break;case"xlinkHref":if(o==null||typeof o=="function"||typeof o=="boolean"||typeof o=="symbol"){e.removeAttribute("xlink:href");break}a=ms(""+o),e.setAttributeNS("http://www.w3.org/1999/xlink","xlink:href",a);break;case"contentEditable":case"spellCheck":case"draggable":case"value":case"autoReverse":case"externalResourcesRequired":case"focusable":case"preserveAlpha":o!=null&&typeof o!="function"&&typeof o!="symbol"?e.setAttribute(a,""+o):e.removeAttribute(a);break;case"inert":case"allowFullScreen":case"async":case"autoPlay":case"controls":case"default":case"defer":case"disabled":case"disablePictureInPicture":case"disableRemotePlayback":case"formNoValidate":case"hidden":case"loop":case"noModule":case"noValidate":case"open":case"playsInline":case"readOnly":case"required":case"reversed":case"scoped":case"seamless":case"itemScope":o&&typeof o!="function"&&typeof o!="symbol"?e.setAttribute(a,""):e.removeAttribute(a);break;case"capture":case"download":o===!0?e.setAttribute(a,""):o!==!1&&o!=null&&typeof o!="function"&&typeof o!="symbol"?e.setAttribute(a,o):e.removeAttribute(a);break;case"cols":case"rows":case"size":case"span":o!=null&&typeof o!="function"&&typeof o!="symbol"&&!isNaN(o)&&1<=o?e.setAttribute(a,o):e.removeAttribute(a);break;case"rowSpan":case"start":o==null||typeof o=="function"||typeof o=="symbol"||isNaN(o)?e.removeAttribute(a):e.setAttribute(a,o);break;case"popover":ge("beforetoggle",e),ge("toggle",e),Lt(e,"popover",o);break;case"xlinkActuate":kt(e,"http://www.w3.org/1999/xlink","xlink:actuate",o);break;case"xlinkArcrole":kt(e,"http://www.w3.org/1999/xlink","xlink:arcrole",o);break;case"xlinkRole":kt(e,"http://www.w3.org/1999/xlink","xlink:role",o);break;case"xlinkShow":kt(e,"http://www.w3.org/1999/xlink","xlink:show",o);break;case"xlinkTitle":kt(e,"http://www.w3.org/1999/xlink","xlink:title",o);break;case"xlinkType":kt(e,"http://www.w3.org/1999/xlink","xlink:type",o);break;case"xmlBase":kt(e,"http://www.w3.org/XML/1998/namespace","xml:base",o);break;case"xmlLang":kt(e,"http://www.w3.org/XML/1998/namespace","xml:lang",o);break;case"xmlSpace":kt(e,"http://www.w3.org/XML/1998/namespace","xml:space",o);break;case"is":Lt(e,"is",o);break;case"innerText":case"textContent":break;default:(!(2<a.length)||a[0]!=="o"&&a[0]!=="O"||a[1]!=="n"&&a[1]!=="N")&&(a=zi.get(a)||a,Lt(e,a,o))}}function th(e,i,a,o,u,h){switch(a){case"style":Ri(e,o,h);break;case"dangerouslySetInnerHTML":if(o!=null){if(typeof o!="object"||!("__html"in o))throw Error(s(61));if(a=o.__html,a!=null){if(u.children!=null)throw Error(s(60));e.innerHTML=a}}break;case"children":typeof o=="string"?ni(e,o):(typeof o=="number"||typeof o=="bigint")&&ni(e,""+o);break;case"onScroll":o!=null&&ge("scroll",e);break;case"onScrollEnd":o!=null&&ge("scrollend",e);break;case"onClick":o!=null&&(e.onclick=ta);break;case"suppressContentEditableWarning":case"suppressHydrationWarning":case"innerHTML":case"ref":break;case"innerText":case"textContent":break;default:if(!R.hasOwnProperty(a))t:{if(a[0]==="o"&&a[1]==="n"&&(u=a.endsWith("Capture"),i=a.slice(2,u?a.length-7:void 0),h=e[Cn]||null,h=h!=null?h[a]:null,typeof h=="function"&&e.removeEventListener(i,h,u),typeof o=="function")){typeof h!="function"&&h!==null&&(a in e?e[a]=null:e.hasAttribute(a)&&e.removeAttribute(a)),e.addEventListener(i,o,u);break t}a in e?e[a]=o:o===!0?e.setAttribute(a,""):Lt(e,a,o)}}}function Un(e,i,a){switch(i){case"div":case"span":case"svg":case"path":case"a":case"g":case"p":case"li":break;case"img":ge("error",e),ge("load",e);var o=!1,u=!1,h;for(h in a)if(a.hasOwnProperty(h)){var x=a[h];if(x!=null)switch(h){case"src":o=!0;break;case"srcSet":u=!0;break;case"children":case"dangerouslySetInnerHTML":throw Error(s(137,i));default:He(e,i,h,x,a,null)}}u&&He(e,i,"srcSet",a.srcSet,a,null),o&&He(e,i,"src",a.src,a,null);return;case"input":ge("invalid",e);var C=h=x=u=null,G=null,it=null;for(o in a)if(a.hasOwnProperty(o)){var vt=a[o];if(vt!=null)switch(o){case"name":u=vt;break;case"type":x=vt;break;case"checked":G=vt;break;case"defaultChecked":it=vt;break;case"value":h=vt;break;case"defaultValue":C=vt;break;case"children":case"dangerouslySetInnerHTML":if(vt!=null)throw Error(s(137,i));break;default:He(e,i,o,vt,a,null)}}Pn(e,h,C,G,it,x,u,!1);return;case"select":ge("invalid",e),o=x=h=null;for(u in a)if(a.hasOwnProperty(u)&&(C=a[u],C!=null))switch(u){case"value":h=C;break;case"defaultValue":x=C;break;case"multiple":o=C;default:He(e,i,u,C,a,null)}i=h,a=x,e.multiple=!!o,i!=null?yn(e,!!o,i,!1):a!=null&&yn(e,!!o,a,!0);return;case"textarea":ge("invalid",e),h=u=o=null;for(x in a)if(a.hasOwnProperty(x)&&(C=a[x],C!=null))switch(x){case"value":o=C;break;case"defaultValue":u=C;break;case"children":h=C;break;case"dangerouslySetInnerHTML":if(C!=null)throw Error(s(91));break;default:He(e,i,x,C,a,null)}Ai(e,o,u,h);return;case"option":for(G in a)if(a.hasOwnProperty(G)&&(o=a[G],o!=null))switch(G){case"selected":e.selected=o&&typeof o!="function"&&typeof o!="symbol";break;default:He(e,i,G,o,a,null)}return;case"dialog":ge("beforetoggle",e),ge("toggle",e),ge("cancel",e),ge("close",e);break;case"iframe":case"object":ge("load",e);break;case"video":case"audio":for(o=0;o<Uo.length;o++)ge(Uo[o],e);break;case"image":ge("error",e),ge("load",e);break;case"details":ge("toggle",e);break;case"embed":case"source":case"link":ge("error",e),ge("load",e);case"area":case"base":case"br":case"col":case"hr":case"keygen":case"meta":case"param":case"track":case"wbr":case"menuitem":for(it in a)if(a.hasOwnProperty(it)&&(o=a[it],o!=null))switch(it){case"children":case"dangerouslySetInnerHTML":throw Error(s(137,i));default:He(e,i,it,o,a,null)}return;default:if(De(i)){for(vt in a)a.hasOwnProperty(vt)&&(o=a[vt],o!==void 0&&th(e,i,vt,o,a,void 0));return}}for(C in a)a.hasOwnProperty(C)&&(o=a[C],o!=null&&He(e,i,C,o,a,null))}function QS(e,i,a,o){switch(i){case"div":case"span":case"svg":case"path":case"a":case"g":case"p":case"li":break;case"input":var u=null,h=null,x=null,C=null,G=null,it=null,vt=null;for(ut in a){var Et=a[ut];if(a.hasOwnProperty(ut)&&Et!=null)switch(ut){case"checked":break;case"value":break;case"defaultValue":G=Et;default:o.hasOwnProperty(ut)||He(e,i,ut,null,o,Et)}}for(var lt in o){var ut=o[lt];if(Et=a[lt],o.hasOwnProperty(lt)&&(ut!=null||Et!=null))switch(lt){case"type":h=ut;break;case"name":u=ut;break;case"checked":it=ut;break;case"defaultChecked":vt=ut;break;case"value":x=ut;break;case"defaultValue":C=ut;break;case"children":case"dangerouslySetInnerHTML":if(ut!=null)throw Error(s(137,i));break;default:ut!==Et&&He(e,i,lt,ut,o,Et)}}Ht(e,x,C,G,it,vt,h,u);return;case"select":ut=x=C=lt=null;for(h in a)if(G=a[h],a.hasOwnProperty(h)&&G!=null)switch(h){case"value":break;case"multiple":ut=G;default:o.hasOwnProperty(h)||He(e,i,h,null,o,G)}for(u in o)if(h=o[u],G=a[u],o.hasOwnProperty(u)&&(h!=null||G!=null))switch(u){case"value":lt=h;break;case"defaultValue":C=h;break;case"multiple":x=h;default:h!==G&&He(e,i,u,h,o,G)}i=C,a=x,o=ut,lt!=null?yn(e,!!a,lt,!1):!!o!=!!a&&(i!=null?yn(e,!!a,i,!0):yn(e,!!a,a?[]:"",!1));return;case"textarea":ut=lt=null;for(C in a)if(u=a[C],a.hasOwnProperty(C)&&u!=null&&!o.hasOwnProperty(C))switch(C){case"value":break;case"children":break;default:He(e,i,C,null,o,u)}for(x in o)if(u=o[x],h=a[x],o.hasOwnProperty(x)&&(u!=null||h!=null))switch(x){case"value":lt=u;break;case"defaultValue":ut=u;break;case"children":break;case"dangerouslySetInnerHTML":if(u!=null)throw Error(s(91));break;default:u!==h&&He(e,i,x,u,o,h)}ei(e,lt,ut);return;case"option":for(var Wt in a)if(lt=a[Wt],a.hasOwnProperty(Wt)&&lt!=null&&!o.hasOwnProperty(Wt))switch(Wt){case"selected":e.selected=!1;break;default:He(e,i,Wt,null,o,lt)}for(G in o)if(lt=o[G],ut=a[G],o.hasOwnProperty(G)&&lt!==ut&&(lt!=null||ut!=null))switch(G){case"selected":e.selected=lt&&typeof lt!="function"&&typeof lt!="symbol";break;default:He(e,i,G,lt,o,ut)}return;case"img":case"link":case"area":case"base":case"br":case"col":case"embed":case"hr":case"keygen":case"meta":case"param":case"source":case"track":case"wbr":case"menuitem":for(var ne in a)lt=a[ne],a.hasOwnProperty(ne)&&lt!=null&&!o.hasOwnProperty(ne)&&He(e,i,ne,null,o,lt);for(it in o)if(lt=o[it],ut=a[it],o.hasOwnProperty(it)&&lt!==ut&&(lt!=null||ut!=null))switch(it){case"children":case"dangerouslySetInnerHTML":if(lt!=null)throw Error(s(137,i));break;default:He(e,i,it,lt,o,ut)}return;default:if(De(i)){for(var Ge in a)lt=a[Ge],a.hasOwnProperty(Ge)&&lt!==void 0&&!o.hasOwnProperty(Ge)&&th(e,i,Ge,void 0,o,lt);for(vt in o)lt=o[vt],ut=a[vt],!o.hasOwnProperty(vt)||lt===ut||lt===void 0&&ut===void 0||th(e,i,vt,lt,o,ut);return}}for(var Q in a)lt=a[Q],a.hasOwnProperty(Q)&&lt!=null&&!o.hasOwnProperty(Q)&&He(e,i,Q,null,o,lt);for(Et in o)lt=o[Et],ut=a[Et],!o.hasOwnProperty(Et)||lt===ut||lt==null&&ut==null||He(e,i,Et,lt,o,ut)}function Cg(e){switch(e){case"css":case"script":case"font":case"img":case"image":case"input":case"link":return!0;default:return!1}}function $S(){if(typeof performance.getEntriesByType=="function"){for(var e=0,i=0,a=performance.getEntriesByType("resource"),o=0;o<a.length;o++){var u=a[o],h=u.transferSize,x=u.initiatorType,C=u.duration;if(h&&C&&Cg(x)){for(x=0,C=u.responseEnd,o+=1;o<a.length;o++){var G=a[o],it=G.startTime;if(it>C)break;var vt=G.transferSize,Et=G.initiatorType;vt&&Cg(Et)&&(G=G.responseEnd,x+=vt*(G<C?1:(C-it)/(G-it)))}if(--o,i+=8*(h+x)/(u.duration/1e3),e++,10<e)break}}if(0<e)return i/e/1e6}return navigator.connection&&(e=navigator.connection.downlink,typeof e=="number")?e:5}var eh=null,nh=null;function cc(e){return e.nodeType===9?e:e.ownerDocument}function wg(e){switch(e){case"http://www.w3.org/2000/svg":return 1;case"http://www.w3.org/1998/Math/MathML":return 2;default:return 0}}function Dg(e,i){if(e===0)switch(i){case"svg":return 1;case"math":return 2;default:return 0}return e===1&&i==="foreignObject"?0:e}function ih(e,i){return e==="textarea"||e==="noscript"||typeof i.children=="string"||typeof i.children=="number"||typeof i.children=="bigint"||typeof i.dangerouslySetInnerHTML=="object"&&i.dangerouslySetInnerHTML!==null&&i.dangerouslySetInnerHTML.__html!=null}var ah=null;function ty(){var e=window.event;return e&&e.type==="popstate"?e===ah?!1:(ah=e,!0):(ah=null,!1)}var Ng=typeof setTimeout=="function"?setTimeout:void 0,ey=typeof clearTimeout=="function"?clearTimeout:void 0,Ug=typeof Promise=="function"?Promise:void 0,ny=typeof queueMicrotask=="function"?queueMicrotask:typeof Ug<"u"?function(e){return Ug.resolve(null).then(e).catch(iy)}:Ng;function iy(e){setTimeout(function(){throw e})}function Ka(e){return e==="head"}function Lg(e,i){var a=i,o=0;do{var u=a.nextSibling;if(e.removeChild(a),u&&u.nodeType===8)if(a=u.data,a==="/$"||a==="/&"){if(o===0){e.removeChild(u),Er(i);return}o--}else if(a==="$"||a==="$?"||a==="$~"||a==="$!"||a==="&")o++;else if(a==="html")Oo(e.ownerDocument.documentElement);else if(a==="head"){a=e.ownerDocument.head,Oo(a);for(var h=a.firstChild;h;){var x=h.nextSibling,C=h.nodeName;h[Ca]||C==="SCRIPT"||C==="STYLE"||C==="LINK"&&h.rel.toLowerCase()==="stylesheet"||a.removeChild(h),h=x}}else a==="body"&&Oo(e.ownerDocument.body);a=u}while(a);Er(i)}function Og(e,i){var a=e;e=0;do{var o=a.nextSibling;if(a.nodeType===1?i?(a._stashedDisplay=a.style.display,a.style.display="none"):(a.style.display=a._stashedDisplay||"",a.getAttribute("style")===""&&a.removeAttribute("style")):a.nodeType===3&&(i?(a._stashedText=a.nodeValue,a.nodeValue=""):a.nodeValue=a._stashedText||""),o&&o.nodeType===8)if(a=o.data,a==="/$"){if(e===0)break;e--}else a!=="$"&&a!=="$?"&&a!=="$~"&&a!=="$!"||e++;a=o}while(a)}function sh(e){var i=e.firstChild;for(i&&i.nodeType===10&&(i=i.nextSibling);i;){var a=i;switch(i=i.nextSibling,a.nodeName){case"HTML":case"HEAD":case"BODY":sh(a),wa(a);continue;case"SCRIPT":case"STYLE":continue;case"LINK":if(a.rel.toLowerCase()==="stylesheet")continue}e.removeChild(a)}}function ay(e,i,a,o){for(;e.nodeType===1;){var u=a;if(e.nodeName.toLowerCase()!==i.toLowerCase()){if(!o&&(e.nodeName!=="INPUT"||e.type!=="hidden"))break}else if(o){if(!e[Ca])switch(i){case"meta":if(!e.hasAttribute("itemprop"))break;return e;case"link":if(h=e.getAttribute("rel"),h==="stylesheet"&&e.hasAttribute("data-precedence"))break;if(h!==u.rel||e.getAttribute("href")!==(u.href==null||u.href===""?null:u.href)||e.getAttribute("crossorigin")!==(u.crossOrigin==null?null:u.crossOrigin)||e.getAttribute("title")!==(u.title==null?null:u.title))break;return e;case"style":if(e.hasAttribute("data-precedence"))break;return e;case"script":if(h=e.getAttribute("src"),(h!==(u.src==null?null:u.src)||e.getAttribute("type")!==(u.type==null?null:u.type)||e.getAttribute("crossorigin")!==(u.crossOrigin==null?null:u.crossOrigin))&&h&&e.hasAttribute("async")&&!e.hasAttribute("itemprop"))break;return e;default:return e}}else if(i==="input"&&e.type==="hidden"){var h=u.name==null?null:""+u.name;if(u.type==="hidden"&&e.getAttribute("name")===h)return e}else return e;if(e=Si(e.nextSibling),e===null)break}return null}function sy(e,i,a){if(i==="")return null;for(;e.nodeType!==3;)if((e.nodeType!==1||e.nodeName!=="INPUT"||e.type!=="hidden")&&!a||(e=Si(e.nextSibling),e===null))return null;return e}function Pg(e,i){for(;e.nodeType!==8;)if((e.nodeType!==1||e.nodeName!=="INPUT"||e.type!=="hidden")&&!i||(e=Si(e.nextSibling),e===null))return null;return e}function rh(e){return e.data==="$?"||e.data==="$~"}function oh(e){return e.data==="$!"||e.data==="$?"&&e.ownerDocument.readyState!=="loading"}function ry(e,i){var a=e.ownerDocument;if(e.data==="$~")e._reactRetry=i;else if(e.data!=="$?"||a.readyState!=="loading")i();else{var o=function(){i(),a.removeEventListener("DOMContentLoaded",o)};a.addEventListener("DOMContentLoaded",o),e._reactRetry=o}}function Si(e){for(;e!=null;e=e.nextSibling){var i=e.nodeType;if(i===1||i===3)break;if(i===8){if(i=e.data,i==="$"||i==="$!"||i==="$?"||i==="$~"||i==="&"||i==="F!"||i==="F")break;if(i==="/$"||i==="/&")return null}}return e}var lh=null;function Ig(e){e=e.nextSibling;for(var i=0;e;){if(e.nodeType===8){var a=e.data;if(a==="/$"||a==="/&"){if(i===0)return Si(e.nextSibling);i--}else a!=="$"&&a!=="$!"&&a!=="$?"&&a!=="$~"&&a!=="&"||i++}e=e.nextSibling}return null}function zg(e){e=e.previousSibling;for(var i=0;e;){if(e.nodeType===8){var a=e.data;if(a==="$"||a==="$!"||a==="$?"||a==="$~"||a==="&"){if(i===0)return e;i--}else a!=="/$"&&a!=="/&"||i++}e=e.previousSibling}return null}function Fg(e,i,a){switch(i=cc(a),e){case"html":if(e=i.documentElement,!e)throw Error(s(452));return e;case"head":if(e=i.head,!e)throw Error(s(453));return e;case"body":if(e=i.body,!e)throw Error(s(454));return e;default:throw Error(s(451))}}function Oo(e){for(var i=e.attributes;i.length;)e.removeAttributeNode(i[0]);wa(e)}var yi=new Map,Bg=new Set;function uc(e){return typeof e.getRootNode=="function"?e.getRootNode():e.nodeType===9?e:e.ownerDocument}var ga=H.d;H.d={f:oy,r:ly,D:cy,C:uy,L:fy,m:hy,X:py,S:dy,M:my};function oy(){var e=ga.f(),i=ec();return e||i}function ly(e){var i=$i(e);i!==null&&i.tag===5&&i.type==="form"?n0(i):ga.r(e)}var Sr=typeof document>"u"?null:document;function Hg(e,i,a){var o=Sr;if(o&&typeof i=="string"&&i){var u=Le(i);u='link[rel="'+e+'"][href="'+u+'"]',typeof a=="string"&&(u+='[crossorigin="'+a+'"]'),Bg.has(u)||(Bg.add(u),e={rel:e,crossOrigin:a,href:i},o.querySelector(u)===null&&(i=o.createElement("link"),Un(i,"link",e),mn(i),o.head.appendChild(i)))}}function cy(e){ga.D(e),Hg("dns-prefetch",e,null)}function uy(e,i){ga.C(e,i),Hg("preconnect",e,i)}function fy(e,i,a){ga.L(e,i,a);var o=Sr;if(o&&e&&i){var u='link[rel="preload"][as="'+Le(i)+'"]';i==="image"&&a&&a.imageSrcSet?(u+='[imagesrcset="'+Le(a.imageSrcSet)+'"]',typeof a.imageSizes=="string"&&(u+='[imagesizes="'+Le(a.imageSizes)+'"]')):u+='[href="'+Le(e)+'"]';var h=u;switch(i){case"style":h=yr(e);break;case"script":h=Mr(e)}yi.has(h)||(e=_({rel:"preload",href:i==="image"&&a&&a.imageSrcSet?void 0:e,as:i},a),yi.set(h,e),o.querySelector(u)!==null||i==="style"&&o.querySelector(Po(h))||i==="script"&&o.querySelector(Io(h))||(i=o.createElement("link"),Un(i,"link",e),mn(i),o.head.appendChild(i)))}}function hy(e,i){ga.m(e,i);var a=Sr;if(a&&e){var o=i&&typeof i.as=="string"?i.as:"script",u='link[rel="modulepreload"][as="'+Le(o)+'"][href="'+Le(e)+'"]',h=u;switch(o){case"audioworklet":case"paintworklet":case"serviceworker":case"sharedworker":case"worker":case"script":h=Mr(e)}if(!yi.has(h)&&(e=_({rel:"modulepreload",href:e},i),yi.set(h,e),a.querySelector(u)===null)){switch(o){case"audioworklet":case"paintworklet":case"serviceworker":case"sharedworker":case"worker":case"script":if(a.querySelector(Io(h)))return}o=a.createElement("link"),Un(o,"link",e),mn(o),a.head.appendChild(o)}}}function dy(e,i,a){ga.S(e,i,a);var o=Sr;if(o&&e){var u=Da(o).hoistableStyles,h=yr(e);i=i||"default";var x=u.get(h);if(!x){var C={loading:0,preload:null};if(x=o.querySelector(Po(h)))C.loading=5;else{e=_({rel:"stylesheet",href:e,"data-precedence":i},a),(a=yi.get(h))&&ch(e,a);var G=x=o.createElement("link");mn(G),Un(G,"link",e),G._p=new Promise(function(it,vt){G.onload=it,G.onerror=vt}),G.addEventListener("load",function(){C.loading|=1}),G.addEventListener("error",function(){C.loading|=2}),C.loading|=4,fc(x,i,o)}x={type:"stylesheet",instance:x,count:1,state:C},u.set(h,x)}}}function py(e,i){ga.X(e,i);var a=Sr;if(a&&e){var o=Da(a).hoistableScripts,u=Mr(e),h=o.get(u);h||(h=a.querySelector(Io(u)),h||(e=_({src:e,async:!0},i),(i=yi.get(u))&&uh(e,i),h=a.createElement("script"),mn(h),Un(h,"link",e),a.head.appendChild(h)),h={type:"script",instance:h,count:1,state:null},o.set(u,h))}}function my(e,i){ga.M(e,i);var a=Sr;if(a&&e){var o=Da(a).hoistableScripts,u=Mr(e),h=o.get(u);h||(h=a.querySelector(Io(u)),h||(e=_({src:e,async:!0,type:"module"},i),(i=yi.get(u))&&uh(e,i),h=a.createElement("script"),mn(h),Un(h,"link",e),a.head.appendChild(h)),h={type:"script",instance:h,count:1,state:null},o.set(u,h))}}function Gg(e,i,a,o){var u=(u=tt.current)?uc(u):null;if(!u)throw Error(s(446));switch(e){case"meta":case"title":return null;case"style":return typeof a.precedence=="string"&&typeof a.href=="string"?(i=yr(a.href),a=Da(u).hoistableStyles,o=a.get(i),o||(o={type:"style",instance:null,count:0,state:null},a.set(i,o)),o):{type:"void",instance:null,count:0,state:null};case"link":if(a.rel==="stylesheet"&&typeof a.href=="string"&&typeof a.precedence=="string"){e=yr(a.href);var h=Da(u).hoistableStyles,x=h.get(e);if(x||(u=u.ownerDocument||u,x={type:"stylesheet",instance:null,count:0,state:{loading:0,preload:null}},h.set(e,x),(h=u.querySelector(Po(e)))&&!h._p&&(x.instance=h,x.state.loading=5),yi.has(e)||(a={rel:"preload",as:"style",href:a.href,crossOrigin:a.crossOrigin,integrity:a.integrity,media:a.media,hrefLang:a.hrefLang,referrerPolicy:a.referrerPolicy},yi.set(e,a),h||gy(u,e,a,x.state))),i&&o===null)throw Error(s(528,""));return x}if(i&&o!==null)throw Error(s(529,""));return null;case"script":return i=a.async,a=a.src,typeof a=="string"&&i&&typeof i!="function"&&typeof i!="symbol"?(i=Mr(a),a=Da(u).hoistableScripts,o=a.get(i),o||(o={type:"script",instance:null,count:0,state:null},a.set(i,o)),o):{type:"void",instance:null,count:0,state:null};default:throw Error(s(444,e))}}function yr(e){return'href="'+Le(e)+'"'}function Po(e){return'link[rel="stylesheet"]['+e+"]"}function Vg(e){return _({},e,{"data-precedence":e.precedence,precedence:null})}function gy(e,i,a,o){e.querySelector('link[rel="preload"][as="style"]['+i+"]")?o.loading=1:(i=e.createElement("link"),o.preload=i,i.addEventListener("load",function(){return o.loading|=1}),i.addEventListener("error",function(){return o.loading|=2}),Un(i,"link",a),mn(i),e.head.appendChild(i))}function Mr(e){return'[src="'+Le(e)+'"]'}function Io(e){return"script[async]"+e}function kg(e,i,a){if(i.count++,i.instance===null)switch(i.type){case"style":var o=e.querySelector('style[data-href~="'+Le(a.href)+'"]');if(o)return i.instance=o,mn(o),o;var u=_({},a,{"data-href":a.href,"data-precedence":a.precedence,href:null,precedence:null});return o=(e.ownerDocument||e).createElement("style"),mn(o),Un(o,"style",u),fc(o,a.precedence,e),i.instance=o;case"stylesheet":u=yr(a.href);var h=e.querySelector(Po(u));if(h)return i.state.loading|=4,i.instance=h,mn(h),h;o=Vg(a),(u=yi.get(u))&&ch(o,u),h=(e.ownerDocument||e).createElement("link"),mn(h);var x=h;return x._p=new Promise(function(C,G){x.onload=C,x.onerror=G}),Un(h,"link",o),i.state.loading|=4,fc(h,a.precedence,e),i.instance=h;case"script":return h=Mr(a.src),(u=e.querySelector(Io(h)))?(i.instance=u,mn(u),u):(o=a,(u=yi.get(h))&&(o=_({},a),uh(o,u)),e=e.ownerDocument||e,u=e.createElement("script"),mn(u),Un(u,"link",o),e.head.appendChild(u),i.instance=u);case"void":return null;default:throw Error(s(443,i.type))}else i.type==="stylesheet"&&(i.state.loading&4)===0&&(o=i.instance,i.state.loading|=4,fc(o,a.precedence,e));return i.instance}function fc(e,i,a){for(var o=a.querySelectorAll('link[rel="stylesheet"][data-precedence],style[data-precedence]'),u=o.length?o[o.length-1]:null,h=u,x=0;x<o.length;x++){var C=o[x];if(C.dataset.precedence===i)h=C;else if(h!==u)break}h?h.parentNode.insertBefore(e,h.nextSibling):(i=a.nodeType===9?a.head:a,i.insertBefore(e,i.firstChild))}function ch(e,i){e.crossOrigin==null&&(e.crossOrigin=i.crossOrigin),e.referrerPolicy==null&&(e.referrerPolicy=i.referrerPolicy),e.title==null&&(e.title=i.title)}function uh(e,i){e.crossOrigin==null&&(e.crossOrigin=i.crossOrigin),e.referrerPolicy==null&&(e.referrerPolicy=i.referrerPolicy),e.integrity==null&&(e.integrity=i.integrity)}var hc=null;function Xg(e,i,a){if(hc===null){var o=new Map,u=hc=new Map;u.set(a,o)}else u=hc,o=u.get(a),o||(o=new Map,u.set(a,o));if(o.has(e))return o;for(o.set(e,null),a=a.getElementsByTagName(e),u=0;u<a.length;u++){var h=a[u];if(!(h[Ca]||h[pn]||e==="link"&&h.getAttribute("rel")==="stylesheet")&&h.namespaceURI!=="http://www.w3.org/2000/svg"){var x=h.getAttribute(i)||"";x=e+x;var C=o.get(x);C?C.push(h):o.set(x,[h])}}return o}function Wg(e,i,a){e=e.ownerDocument||e,e.head.insertBefore(a,i==="title"?e.querySelector("head > title"):null)}function vy(e,i,a){if(a===1||i.itemProp!=null)return!1;switch(e){case"meta":case"title":return!0;case"style":if(typeof i.precedence!="string"||typeof i.href!="string"||i.href==="")break;return!0;case"link":if(typeof i.rel!="string"||typeof i.href!="string"||i.href===""||i.onLoad||i.onError)break;switch(i.rel){case"stylesheet":return e=i.disabled,typeof i.precedence=="string"&&e==null;default:return!0}case"script":if(i.async&&typeof i.async!="function"&&typeof i.async!="symbol"&&!i.onLoad&&!i.onError&&i.src&&typeof i.src=="string")return!0}return!1}function qg(e){return!(e.type==="stylesheet"&&(e.state.loading&3)===0)}function _y(e,i,a,o){if(a.type==="stylesheet"&&(typeof o.media!="string"||matchMedia(o.media).matches!==!1)&&(a.state.loading&4)===0){if(a.instance===null){var u=yr(o.href),h=i.querySelector(Po(u));if(h){i=h._p,i!==null&&typeof i=="object"&&typeof i.then=="function"&&(e.count++,e=dc.bind(e),i.then(e,e)),a.state.loading|=4,a.instance=h,mn(h);return}h=i.ownerDocument||i,o=Vg(o),(u=yi.get(u))&&ch(o,u),h=h.createElement("link"),mn(h);var x=h;x._p=new Promise(function(C,G){x.onload=C,x.onerror=G}),Un(h,"link",o),a.instance=h}e.stylesheets===null&&(e.stylesheets=new Map),e.stylesheets.set(a,i),(i=a.state.preload)&&(a.state.loading&3)===0&&(e.count++,a=dc.bind(e),i.addEventListener("load",a),i.addEventListener("error",a))}}var fh=0;function xy(e,i){return e.stylesheets&&e.count===0&&mc(e,e.stylesheets),0<e.count||0<e.imgCount?function(a){var o=setTimeout(function(){if(e.stylesheets&&mc(e,e.stylesheets),e.unsuspend){var h=e.unsuspend;e.unsuspend=null,h()}},6e4+i);0<e.imgBytes&&fh===0&&(fh=62500*$S());var u=setTimeout(function(){if(e.waitingForImages=!1,e.count===0&&(e.stylesheets&&mc(e,e.stylesheets),e.unsuspend)){var h=e.unsuspend;e.unsuspend=null,h()}},(e.imgBytes>fh?50:800)+i);return e.unsuspend=a,function(){e.unsuspend=null,clearTimeout(o),clearTimeout(u)}}:null}function dc(){if(this.count--,this.count===0&&(this.imgCount===0||!this.waitingForImages)){if(this.stylesheets)mc(this,this.stylesheets);else if(this.unsuspend){var e=this.unsuspend;this.unsuspend=null,e()}}}var pc=null;function mc(e,i){e.stylesheets=null,e.unsuspend!==null&&(e.count++,pc=new Map,i.forEach(Sy,e),pc=null,dc.call(e))}function Sy(e,i){if(!(i.state.loading&4)){var a=pc.get(e);if(a)var o=a.get(null);else{a=new Map,pc.set(e,a);for(var u=e.querySelectorAll("link[data-precedence],style[data-precedence]"),h=0;h<u.length;h++){var x=u[h];(x.nodeName==="LINK"||x.getAttribute("media")!=="not all")&&(a.set(x.dataset.precedence,x),o=x)}o&&a.set(null,o)}u=i.instance,x=u.getAttribute("data-precedence"),h=a.get(x)||o,h===o&&a.set(null,u),a.set(x,u),this.count++,o=dc.bind(this),u.addEventListener("load",o),u.addEventListener("error",o),h?h.parentNode.insertBefore(u,h.nextSibling):(e=e.nodeType===9?e.head:e,e.insertBefore(u,e.firstChild)),i.state.loading|=4}}var zo={$$typeof:D,Provider:null,Consumer:null,_currentValue:$,_currentValue2:$,_threadCount:0};function yy(e,i,a,o,u,h,x,C,G){this.tag=1,this.containerInfo=e,this.pingCache=this.current=this.pendingChildren=null,this.timeoutHandle=-1,this.callbackNode=this.next=this.pendingContext=this.context=this.cancelPendingCommit=null,this.callbackPriority=0,this.expirationTimes=Yt(-1),this.entangledLanes=this.shellSuspendCounter=this.errorRecoveryDisabledLanes=this.expiredLanes=this.warmLanes=this.pingedLanes=this.suspendedLanes=this.pendingLanes=0,this.entanglements=Yt(0),this.hiddenUpdates=Yt(null),this.identifierPrefix=o,this.onUncaughtError=u,this.onCaughtError=h,this.onRecoverableError=x,this.pooledCache=null,this.pooledCacheLanes=0,this.formState=G,this.incompleteTransitions=new Map}function Yg(e,i,a,o,u,h,x,C,G,it,vt,Et){return e=new yy(e,i,a,x,G,it,vt,Et,C),i=1,h===!0&&(i|=24),h=ai(3,null,null,i),e.current=h,h.stateNode=e,i=ku(),i.refCount++,e.pooledCache=i,i.refCount++,h.memoizedState={element:o,isDehydrated:a,cache:i},Yu(h),e}function Zg(e){return e?(e=$s,e):$s}function Kg(e,i,a,o,u,h){u=Zg(u),o.context===null?o.context=u:o.pendingContext=u,o=Fa(i),o.payload={element:a},h=h===void 0?null:h,h!==null&&(o.callback=h),a=Ba(e,o,i),a!==null&&(Jn(a,e,i),mo(a,e,i))}function jg(e,i){if(e=e.memoizedState,e!==null&&e.dehydrated!==null){var a=e.retryLane;e.retryLane=a!==0&&a<i?a:i}}function hh(e,i){jg(e,i),(e=e.alternate)&&jg(e,i)}function Jg(e){if(e.tag===13||e.tag===31){var i=xs(e,67108864);i!==null&&Jn(i,e,67108864),hh(e,67108864)}}function Qg(e){if(e.tag===13||e.tag===31){var i=ci();i=jr(i);var a=xs(e,i);a!==null&&Jn(a,e,i),hh(e,i)}}var gc=!0;function My(e,i,a,o){var u=B.T;B.T=null;var h=H.p;try{H.p=2,dh(e,i,a,o)}finally{H.p=h,B.T=u}}function Ey(e,i,a,o){var u=B.T;B.T=null;var h=H.p;try{H.p=8,dh(e,i,a,o)}finally{H.p=h,B.T=u}}function dh(e,i,a,o){if(gc){var u=ph(o);if(u===null)$f(e,i,o,vc,a),tv(e,o);else if(Ty(u,e,i,a,o))o.stopPropagation();else if(tv(e,o),i&4&&-1<by.indexOf(e)){for(;u!==null;){var h=$i(u);if(h!==null)switch(h.tag){case 3:if(h=h.stateNode,h.current.memoizedState.isDehydrated){var x=Ct(h.pendingLanes);if(x!==0){var C=h;for(C.pendingLanes|=2,C.entangledLanes|=2;x;){var G=1<<31-Bt(x);C.entanglements[1]|=G,x&=~G}Gi(h),(we&6)===0&&($l=Fe()+500,No(0))}}break;case 31:case 13:C=xs(h,2),C!==null&&Jn(C,h,2),ec(),hh(h,2)}if(h=ph(o),h===null&&$f(e,i,o,vc,a),h===u)break;u=h}u!==null&&o.stopPropagation()}else $f(e,i,o,null,a)}}function ph(e){return e=mu(e),mh(e)}var vc=null;function mh(e){if(vc=null,e=Qi(e),e!==null){var i=c(e);if(i===null)e=null;else{var a=i.tag;if(a===13){if(e=f(i),e!==null)return e;e=null}else if(a===31){if(e=d(i),e!==null)return e;e=null}else if(a===3){if(i.stateNode.current.memoizedState.isDehydrated)return i.tag===3?i.stateNode.containerInfo:null;e=null}else i!==e&&(e=null)}}return vc=e,null}function $g(e){switch(e){case"beforetoggle":case"cancel":case"click":case"close":case"contextmenu":case"copy":case"cut":case"auxclick":case"dblclick":case"dragend":case"dragstart":case"drop":case"focusin":case"focusout":case"input":case"invalid":case"keydown":case"keypress":case"keyup":case"mousedown":case"mouseup":case"paste":case"pause":case"play":case"pointercancel":case"pointerdown":case"pointerup":case"ratechange":case"reset":case"resize":case"seeked":case"submit":case"toggle":case"touchcancel":case"touchend":case"touchstart":case"volumechange":case"change":case"selectionchange":case"textInput":case"compositionstart":case"compositionend":case"compositionupdate":case"beforeblur":case"afterblur":case"beforeinput":case"blur":case"fullscreenchange":case"focus":case"hashchange":case"popstate":case"select":case"selectstart":return 2;case"drag":case"dragenter":case"dragexit":case"dragleave":case"dragover":case"mousemove":case"mouseout":case"mouseover":case"pointermove":case"pointerout":case"pointerover":case"scroll":case"touchmove":case"wheel":case"mouseenter":case"mouseleave":case"pointerenter":case"pointerleave":return 8;case"message":switch(Ce()){case L:return 2;case E:return 8;case et:case rt:return 32;case mt:return 268435456;default:return 32}default:return 32}}var gh=!1,ja=null,Ja=null,Qa=null,Fo=new Map,Bo=new Map,$a=[],by="mousedown mouseup touchcancel touchend touchstart auxclick dblclick pointercancel pointerdown pointerup dragend dragstart drop compositionend compositionstart keydown keypress keyup input textInput copy cut paste click change contextmenu reset".split(" ");function tv(e,i){switch(e){case"focusin":case"focusout":ja=null;break;case"dragenter":case"dragleave":Ja=null;break;case"mouseover":case"mouseout":Qa=null;break;case"pointerover":case"pointerout":Fo.delete(i.pointerId);break;case"gotpointercapture":case"lostpointercapture":Bo.delete(i.pointerId)}}function Ho(e,i,a,o,u,h){return e===null||e.nativeEvent!==h?(e={blockedOn:i,domEventName:a,eventSystemFlags:o,nativeEvent:h,targetContainers:[u]},i!==null&&(i=$i(i),i!==null&&Jg(i)),e):(e.eventSystemFlags|=o,i=e.targetContainers,u!==null&&i.indexOf(u)===-1&&i.push(u),e)}function Ty(e,i,a,o,u){switch(i){case"focusin":return ja=Ho(ja,e,i,a,o,u),!0;case"dragenter":return Ja=Ho(Ja,e,i,a,o,u),!0;case"mouseover":return Qa=Ho(Qa,e,i,a,o,u),!0;case"pointerover":var h=u.pointerId;return Fo.set(h,Ho(Fo.get(h)||null,e,i,a,o,u)),!0;case"gotpointercapture":return h=u.pointerId,Bo.set(h,Ho(Bo.get(h)||null,e,i,a,o,u)),!0}return!1}function ev(e){var i=Qi(e.target);if(i!==null){var a=c(i);if(a!==null){if(i=a.tag,i===13){if(i=f(a),i!==null){e.blockedOn=i,qs(e.priority,function(){Qg(a)});return}}else if(i===31){if(i=d(a),i!==null){e.blockedOn=i,qs(e.priority,function(){Qg(a)});return}}else if(i===3&&a.stateNode.current.memoizedState.isDehydrated){e.blockedOn=a.tag===3?a.stateNode.containerInfo:null;return}}}e.blockedOn=null}function _c(e){if(e.blockedOn!==null)return!1;for(var i=e.targetContainers;0<i.length;){var a=ph(e.nativeEvent);if(a===null){a=e.nativeEvent;var o=new a.constructor(a.type,a);pu=o,a.target.dispatchEvent(o),pu=null}else return i=$i(a),i!==null&&Jg(i),e.blockedOn=a,!1;i.shift()}return!0}function nv(e,i,a){_c(e)&&a.delete(i)}function Ay(){gh=!1,ja!==null&&_c(ja)&&(ja=null),Ja!==null&&_c(Ja)&&(Ja=null),Qa!==null&&_c(Qa)&&(Qa=null),Fo.forEach(nv),Bo.forEach(nv)}function xc(e,i){e.blockedOn===i&&(e.blockedOn=null,gh||(gh=!0,r.unstable_scheduleCallback(r.unstable_NormalPriority,Ay)))}var Sc=null;function iv(e){Sc!==e&&(Sc=e,r.unstable_scheduleCallback(r.unstable_NormalPriority,function(){Sc===e&&(Sc=null);for(var i=0;i<e.length;i+=3){var a=e[i],o=e[i+1],u=e[i+2];if(typeof o!="function"){if(mh(o||a)===null)continue;break}var h=$i(a);h!==null&&(e.splice(i,3),i-=3,pf(h,{pending:!0,data:u,method:a.method,action:o},o,u))}}))}function Er(e){function i(G){return xc(G,e)}ja!==null&&xc(ja,e),Ja!==null&&xc(Ja,e),Qa!==null&&xc(Qa,e),Fo.forEach(i),Bo.forEach(i);for(var a=0;a<$a.length;a++){var o=$a[a];o.blockedOn===e&&(o.blockedOn=null)}for(;0<$a.length&&(a=$a[0],a.blockedOn===null);)ev(a),a.blockedOn===null&&$a.shift();if(a=(e.ownerDocument||e).$$reactFormReplay,a!=null)for(o=0;o<a.length;o+=3){var u=a[o],h=a[o+1],x=u[Cn]||null;if(typeof h=="function")x||iv(a);else if(x){var C=null;if(h&&h.hasAttribute("formAction")){if(u=h,x=h[Cn]||null)C=x.formAction;else if(mh(u)!==null)continue}else C=x.action;typeof C=="function"?a[o+1]=C:(a.splice(o,3),o-=3),iv(a)}}}function av(){function e(h){h.canIntercept&&h.info==="react-transition"&&h.intercept({handler:function(){return new Promise(function(x){return u=x})},focusReset:"manual",scroll:"manual"})}function i(){u!==null&&(u(),u=null),o||setTimeout(a,20)}function a(){if(!o&&!navigation.transition){var h=navigation.currentEntry;h&&h.url!=null&&navigation.navigate(h.url,{state:h.getState(),info:"react-transition",history:"replace"})}}if(typeof navigation=="object"){var o=!1,u=null;return navigation.addEventListener("navigate",e),navigation.addEventListener("navigatesuccess",i),navigation.addEventListener("navigateerror",i),setTimeout(a,100),function(){o=!0,navigation.removeEventListener("navigate",e),navigation.removeEventListener("navigatesuccess",i),navigation.removeEventListener("navigateerror",i),u!==null&&(u(),u=null)}}}function vh(e){this._internalRoot=e}yc.prototype.render=vh.prototype.render=function(e){var i=this._internalRoot;if(i===null)throw Error(s(409));var a=i.current,o=ci();Kg(a,o,e,i,null,null)},yc.prototype.unmount=vh.prototype.unmount=function(){var e=this._internalRoot;if(e!==null){this._internalRoot=null;var i=e.containerInfo;Kg(e.current,2,null,e,null,null),ec(),i[Wn]=null}};function yc(e){this._internalRoot=e}yc.prototype.unstable_scheduleHydration=function(e){if(e){var i=Qr();e={blockedOn:null,target:e,priority:i};for(var a=0;a<$a.length&&i!==0&&i<$a[a].priority;a++);$a.splice(a,0,e),a===0&&ev(e)}};var sv=t.version;if(sv!=="19.2.0")throw Error(s(527,sv,"19.2.0"));H.findDOMNode=function(e){var i=e._reactInternals;if(i===void 0)throw typeof e.render=="function"?Error(s(188)):(e=Object.keys(e).join(","),Error(s(268,e)));return e=p(i),e=e!==null?v(e):null,e=e===null?null:e.stateNode,e};var Ry={bundleType:0,version:"19.2.0",rendererPackageName:"react-dom",currentDispatcherRef:B,reconcilerVersion:"19.2.0"};if(typeof __REACT_DEVTOOLS_GLOBAL_HOOK__<"u"){var Mc=__REACT_DEVTOOLS_GLOBAL_HOOK__;if(!Mc.isDisabled&&Mc.supportsFiber)try{ft=Mc.inject(Ry),gt=Mc}catch{}}return Vo.createRoot=function(e,i){if(!l(e))throw Error(s(299));var a=!1,o="",u=h0,h=d0,x=p0;return i!=null&&(i.unstable_strictMode===!0&&(a=!0),i.identifierPrefix!==void 0&&(o=i.identifierPrefix),i.onUncaughtError!==void 0&&(u=i.onUncaughtError),i.onCaughtError!==void 0&&(h=i.onCaughtError),i.onRecoverableError!==void 0&&(x=i.onRecoverableError)),i=Yg(e,1,!1,null,null,a,o,null,u,h,x,av),e[Wn]=i.current,Qf(e),new vh(i)},Vo.hydrateRoot=function(e,i,a){if(!l(e))throw Error(s(299));var o=!1,u="",h=h0,x=d0,C=p0,G=null;return a!=null&&(a.unstable_strictMode===!0&&(o=!0),a.identifierPrefix!==void 0&&(u=a.identifierPrefix),a.onUncaughtError!==void 0&&(h=a.onUncaughtError),a.onCaughtError!==void 0&&(x=a.onCaughtError),a.onRecoverableError!==void 0&&(C=a.onRecoverableError),a.formState!==void 0&&(G=a.formState)),i=Yg(e,1,!0,i,a??null,o,u,G,h,x,C,av),i.context=Zg(null),a=i.current,o=ci(),o=jr(o),u=Fa(o),u.callback=null,Ba(a,u,o),a=o,i.current.lanes=a,Vt(i,a),Gi(i),e[Wn]=i.current,Qf(e),new yc(i)},Vo.version="19.2.0",Vo}var mv;function zy(){if(mv)return xh.exports;mv=1;function r(){if(!(typeof __REACT_DEVTOOLS_GLOBAL_HOOK__>"u"||typeof __REACT_DEVTOOLS_GLOBAL_HOOK__.checkDCE!="function"))try{__REACT_DEVTOOLS_GLOBAL_HOOK__.checkDCE(r)}catch(t){console.error(t)}}return r(),xh.exports=Iy(),xh.exports}var Fy=zy(),cn=ip();/**
 * @license
 * Copyright 2010-2026 Three.js Authors
 * SPDX-License-Identifier: MIT
 */const ap="185",By=0,gv=1,Hy=2,Kc=1,O_=2,jo=3,us=0,Vn=1,Ma=2,ba=0,Br=1,vv=2,_v=3,xv=4,Gy=5,Fs=100,Vy=101,ky=102,Xy=103,Wy=104,qy=200,Yy=201,Zy=202,Ky=203,cd=204,ud=205,jy=206,Jy=207,Qy=208,$y=209,tM=210,eM=211,nM=212,iM=213,aM=214,fd=0,hd=1,dd=2,Vr=3,pd=4,md=5,gd=6,vd=7,P_=0,sM=1,rM=2,Yi=0,I_=1,z_=2,F_=3,B_=4,H_=5,G_=6,V_=7,k_=300,Vs=301,kr=302,bh=303,Th=304,uu=306,_d=1e3,Ea=1001,xd=1002,Ln=1003,oM=1004,Ec=1005,Bn=1006,Ah=1007,Hs=1008,di=1009,X_=1010,W_=1011,il=1012,sp=1013,ji=1014,Wi=1015,Aa=1016,rp=1017,op=1018,al=1020,q_=35902,Y_=35899,Z_=1021,K_=1022,Pi=1023,Ra=1026,Gs=1027,j_=1028,lp=1029,ks=1030,cp=1031,up=1033,jc=33776,Jc=33777,Qc=33778,$c=33779,Sd=35840,yd=35841,Md=35842,Ed=35843,bd=36196,Td=37492,Ad=37496,Rd=37488,Cd=37489,nu=37490,wd=37491,Dd=37808,Nd=37809,Ud=37810,Ld=37811,Od=37812,Pd=37813,Id=37814,zd=37815,Fd=37816,Bd=37817,Hd=37818,Gd=37819,Vd=37820,kd=37821,Xd=36492,Wd=36494,qd=36495,Yd=36283,Zd=36284,iu=36285,Kd=36286,lM=3200,jd=0,cM=1,os="",hi="srgb",au="srgb-linear",su="linear",ze="srgb",br=7680,Sv=519,uM=512,fM=513,hM=514,fp=515,dM=516,pM=517,hp=518,mM=519,yv=35044,Mv="300 es",qi=2e3,sl=2001;function gM(r){for(let t=r.length-1;t>=0;--t)if(r[t]>=65535)return!0;return!1}function ru(r){return document.createElementNS("http://www.w3.org/1999/xhtml",r)}function vM(){const r=ru("canvas");return r.style.display="block",r}const Ev={};function bv(...r){const t="THREE."+r.shift();console.log(t,...r)}function J_(r){const t=r[0];if(typeof t=="string"&&t.startsWith("TSL:")){const n=r[1];n&&n.isStackTrace?r[0]+=" "+n.getLocation():r[1]='Stack trace not available. Enable "THREE.Node.captureStackTrace" to capture stack traces.'}return r}function ie(...r){r=J_(r);const t="THREE."+r.shift();{const n=r[0];n&&n.isStackTrace?console.warn(n.getError(t)):console.warn(t,...r)}}function be(...r){r=J_(r);const t="THREE."+r.shift();{const n=r[0];n&&n.isStackTrace?console.error(n.getError(t)):console.error(t,...r)}}function Hr(...r){const t=r.join(" ");t in Ev||(Ev[t]=!0,ie(...r))}function _M(r,t,n){return new Promise(function(s,l){function c(){switch(r.clientWaitSync(t,r.SYNC_FLUSH_COMMANDS_BIT,0)){case r.WAIT_FAILED:l();break;case r.TIMEOUT_EXPIRED:setTimeout(c,n);break;default:s()}}setTimeout(c,n)})}const xM={[fd]:hd,[dd]:gd,[pd]:vd,[Vr]:md,[hd]:fd,[gd]:dd,[vd]:pd,[md]:Vr};class Ws{addEventListener(t,n){this._listeners===void 0&&(this._listeners={});const s=this._listeners;s[t]===void 0&&(s[t]=[]),s[t].indexOf(n)===-1&&s[t].push(n)}hasEventListener(t,n){const s=this._listeners;return s===void 0?!1:s[t]!==void 0&&s[t].indexOf(n)!==-1}removeEventListener(t,n){const s=this._listeners;if(s===void 0)return;const l=s[t];if(l!==void 0){const c=l.indexOf(n);c!==-1&&l.splice(c,1)}}dispatchEvent(t){const n=this._listeners;if(n===void 0)return;const s=n[t.type];if(s!==void 0){t.target=this;const l=s.slice(0);for(let c=0,f=l.length;c<f;c++)l[c].call(this,t);t.target=null}}}const zn=["00","01","02","03","04","05","06","07","08","09","0a","0b","0c","0d","0e","0f","10","11","12","13","14","15","16","17","18","19","1a","1b","1c","1d","1e","1f","20","21","22","23","24","25","26","27","28","29","2a","2b","2c","2d","2e","2f","30","31","32","33","34","35","36","37","38","39","3a","3b","3c","3d","3e","3f","40","41","42","43","44","45","46","47","48","49","4a","4b","4c","4d","4e","4f","50","51","52","53","54","55","56","57","58","59","5a","5b","5c","5d","5e","5f","60","61","62","63","64","65","66","67","68","69","6a","6b","6c","6d","6e","6f","70","71","72","73","74","75","76","77","78","79","7a","7b","7c","7d","7e","7f","80","81","82","83","84","85","86","87","88","89","8a","8b","8c","8d","8e","8f","90","91","92","93","94","95","96","97","98","99","9a","9b","9c","9d","9e","9f","a0","a1","a2","a3","a4","a5","a6","a7","a8","a9","aa","ab","ac","ad","ae","af","b0","b1","b2","b3","b4","b5","b6","b7","b8","b9","ba","bb","bc","bd","be","bf","c0","c1","c2","c3","c4","c5","c6","c7","c8","c9","ca","cb","cc","cd","ce","cf","d0","d1","d2","d3","d4","d5","d6","d7","d8","d9","da","db","dc","dd","de","df","e0","e1","e2","e3","e4","e5","e6","e7","e8","e9","ea","eb","ec","ed","ee","ef","f0","f1","f2","f3","f4","f5","f6","f7","f8","f9","fa","fb","fc","fd","fe","ff"],Rh=Math.PI/180,Jd=180/Math.PI;function Yr(){const r=Math.random()*4294967295|0,t=Math.random()*4294967295|0,n=Math.random()*4294967295|0,s=Math.random()*4294967295|0;return(zn[r&255]+zn[r>>8&255]+zn[r>>16&255]+zn[r>>24&255]+"-"+zn[t&255]+zn[t>>8&255]+"-"+zn[t>>16&15|64]+zn[t>>24&255]+"-"+zn[n&63|128]+zn[n>>8&255]+"-"+zn[n>>16&255]+zn[n>>24&255]+zn[s&255]+zn[s>>8&255]+zn[s>>16&255]+zn[s>>24&255]).toLowerCase()}function ve(r,t,n){return Math.max(t,Math.min(n,r))}function SM(r,t){return(r%t+t)%t}function Ch(r,t,n){return(1-n)*r+n*t}function ko(r,t){switch(t.constructor){case Float32Array:return r;case Uint32Array:return r/4294967295;case Uint16Array:return r/65535;case Uint8Array:return r/255;case Int32Array:return Math.max(r/2147483647,-1);case Int16Array:return Math.max(r/32767,-1);case Int8Array:return Math.max(r/127,-1);default:throw new Error("THREE.MathUtils: Invalid component type.")}}function Qn(r,t){switch(t.constructor){case Float32Array:return r;case Uint32Array:return Math.round(r*4294967295);case Uint16Array:return Math.round(r*65535);case Uint8Array:return Math.round(r*255);case Int32Array:return Math.round(r*2147483647);case Int16Array:return Math.round(r*32767);case Int8Array:return Math.round(r*127);default:throw new Error("THREE.MathUtils: Invalid component type.")}}const Ep=class Ep{constructor(t=0,n=0){this.x=t,this.y=n}get width(){return this.x}set width(t){this.x=t}get height(){return this.y}set height(t){this.y=t}set(t,n){return this.x=t,this.y=n,this}setScalar(t){return this.x=t,this.y=t,this}setX(t){return this.x=t,this}setY(t){return this.y=t,this}setComponent(t,n){switch(t){case 0:this.x=n;break;case 1:this.y=n;break;default:throw new Error("THREE.Vector2: index is out of range: "+t)}return this}getComponent(t){switch(t){case 0:return this.x;case 1:return this.y;default:throw new Error("THREE.Vector2: index is out of range: "+t)}}clone(){return new this.constructor(this.x,this.y)}copy(t){return this.x=t.x,this.y=t.y,this}add(t){return this.x+=t.x,this.y+=t.y,this}addScalar(t){return this.x+=t,this.y+=t,this}addVectors(t,n){return this.x=t.x+n.x,this.y=t.y+n.y,this}addScaledVector(t,n){return this.x+=t.x*n,this.y+=t.y*n,this}sub(t){return this.x-=t.x,this.y-=t.y,this}subScalar(t){return this.x-=t,this.y-=t,this}subVectors(t,n){return this.x=t.x-n.x,this.y=t.y-n.y,this}multiply(t){return this.x*=t.x,this.y*=t.y,this}multiplyScalar(t){return this.x*=t,this.y*=t,this}divide(t){return this.x/=t.x,this.y/=t.y,this}divideScalar(t){return this.multiplyScalar(1/t)}applyMatrix3(t){const n=this.x,s=this.y,l=t.elements;return this.x=l[0]*n+l[3]*s+l[6],this.y=l[1]*n+l[4]*s+l[7],this}min(t){return this.x=Math.min(this.x,t.x),this.y=Math.min(this.y,t.y),this}max(t){return this.x=Math.max(this.x,t.x),this.y=Math.max(this.y,t.y),this}clamp(t,n){return this.x=ve(this.x,t.x,n.x),this.y=ve(this.y,t.y,n.y),this}clampScalar(t,n){return this.x=ve(this.x,t,n),this.y=ve(this.y,t,n),this}clampLength(t,n){const s=this.length();return this.divideScalar(s||1).multiplyScalar(ve(s,t,n))}floor(){return this.x=Math.floor(this.x),this.y=Math.floor(this.y),this}ceil(){return this.x=Math.ceil(this.x),this.y=Math.ceil(this.y),this}round(){return this.x=Math.round(this.x),this.y=Math.round(this.y),this}roundToZero(){return this.x=Math.trunc(this.x),this.y=Math.trunc(this.y),this}negate(){return this.x=-this.x,this.y=-this.y,this}dot(t){return this.x*t.x+this.y*t.y}cross(t){return this.x*t.y-this.y*t.x}lengthSq(){return this.x*this.x+this.y*this.y}length(){return Math.sqrt(this.x*this.x+this.y*this.y)}manhattanLength(){return Math.abs(this.x)+Math.abs(this.y)}normalize(){return this.divideScalar(this.length()||1)}angle(){return Math.atan2(-this.y,-this.x)+Math.PI}angleTo(t){const n=Math.sqrt(this.lengthSq()*t.lengthSq());if(n===0)return Math.PI/2;const s=this.dot(t)/n;return Math.acos(ve(s,-1,1))}distanceTo(t){return Math.sqrt(this.distanceToSquared(t))}distanceToSquared(t){const n=this.x-t.x,s=this.y-t.y;return n*n+s*s}manhattanDistanceTo(t){return Math.abs(this.x-t.x)+Math.abs(this.y-t.y)}setLength(t){return this.normalize().multiplyScalar(t)}lerp(t,n){return this.x+=(t.x-this.x)*n,this.y+=(t.y-this.y)*n,this}lerpVectors(t,n,s){return this.x=t.x+(n.x-t.x)*s,this.y=t.y+(n.y-t.y)*s,this}equals(t){return t.x===this.x&&t.y===this.y}fromArray(t,n=0){return this.x=t[n],this.y=t[n+1],this}toArray(t=[],n=0){return t[n]=this.x,t[n+1]=this.y,t}fromBufferAttribute(t,n){return this.x=t.getX(n),this.y=t.getY(n),this}rotateAround(t,n){const s=Math.cos(n),l=Math.sin(n),c=this.x-t.x,f=this.y-t.y;return this.x=c*s-f*l+t.x,this.y=c*l+f*s+t.y,this}random(){return this.x=Math.random(),this.y=Math.random(),this}*[Symbol.iterator](){yield this.x,yield this.y}};Ep.prototype.isVector2=!0;let qt=Ep;class Zr{constructor(t=0,n=0,s=0,l=1){this.isQuaternion=!0,this._x=t,this._y=n,this._z=s,this._w=l}static slerpFlat(t,n,s,l,c,f,d){let m=s[l+0],p=s[l+1],v=s[l+2],_=s[l+3],g=c[f+0],y=c[f+1],b=c[f+2],w=c[f+3];if(_!==w||m!==g||p!==y||v!==b){let M=m*g+p*y+v*b+_*w;M<0&&(g=-g,y=-y,b=-b,w=-w,M=-M);let S=1-d;if(M<.9995){const P=Math.acos(M),D=Math.sin(P);S=Math.sin(S*P)/D,d=Math.sin(d*P)/D,m=m*S+g*d,p=p*S+y*d,v=v*S+b*d,_=_*S+w*d}else{m=m*S+g*d,p=p*S+y*d,v=v*S+b*d,_=_*S+w*d;const P=1/Math.sqrt(m*m+p*p+v*v+_*_);m*=P,p*=P,v*=P,_*=P}}t[n]=m,t[n+1]=p,t[n+2]=v,t[n+3]=_}static multiplyQuaternionsFlat(t,n,s,l,c,f){const d=s[l],m=s[l+1],p=s[l+2],v=s[l+3],_=c[f],g=c[f+1],y=c[f+2],b=c[f+3];return t[n]=d*b+v*_+m*y-p*g,t[n+1]=m*b+v*g+p*_-d*y,t[n+2]=p*b+v*y+d*g-m*_,t[n+3]=v*b-d*_-m*g-p*y,t}get x(){return this._x}set x(t){this._x=t,this._onChangeCallback()}get y(){return this._y}set y(t){this._y=t,this._onChangeCallback()}get z(){return this._z}set z(t){this._z=t,this._onChangeCallback()}get w(){return this._w}set w(t){this._w=t,this._onChangeCallback()}set(t,n,s,l){return this._x=t,this._y=n,this._z=s,this._w=l,this._onChangeCallback(),this}clone(){return new this.constructor(this._x,this._y,this._z,this._w)}copy(t){return this._x=t.x,this._y=t.y,this._z=t.z,this._w=t.w,this._onChangeCallback(),this}setFromEuler(t,n=!0){const s=t._x,l=t._y,c=t._z,f=t._order,d=Math.cos,m=Math.sin,p=d(s/2),v=d(l/2),_=d(c/2),g=m(s/2),y=m(l/2),b=m(c/2);switch(f){case"XYZ":this._x=g*v*_+p*y*b,this._y=p*y*_-g*v*b,this._z=p*v*b+g*y*_,this._w=p*v*_-g*y*b;break;case"YXZ":this._x=g*v*_+p*y*b,this._y=p*y*_-g*v*b,this._z=p*v*b-g*y*_,this._w=p*v*_+g*y*b;break;case"ZXY":this._x=g*v*_-p*y*b,this._y=p*y*_+g*v*b,this._z=p*v*b+g*y*_,this._w=p*v*_-g*y*b;break;case"ZYX":this._x=g*v*_-p*y*b,this._y=p*y*_+g*v*b,this._z=p*v*b-g*y*_,this._w=p*v*_+g*y*b;break;case"YZX":this._x=g*v*_+p*y*b,this._y=p*y*_+g*v*b,this._z=p*v*b-g*y*_,this._w=p*v*_-g*y*b;break;case"XZY":this._x=g*v*_-p*y*b,this._y=p*y*_-g*v*b,this._z=p*v*b+g*y*_,this._w=p*v*_+g*y*b;break;default:ie("Quaternion: .setFromEuler() encountered an unknown order: "+f)}return n===!0&&this._onChangeCallback(),this}setFromAxisAngle(t,n){const s=n/2,l=Math.sin(s);return this._x=t.x*l,this._y=t.y*l,this._z=t.z*l,this._w=Math.cos(s),this._onChangeCallback(),this}setFromRotationMatrix(t){const n=t.elements,s=n[0],l=n[4],c=n[8],f=n[1],d=n[5],m=n[9],p=n[2],v=n[6],_=n[10],g=s+d+_;if(g>0){const y=.5/Math.sqrt(g+1);this._w=.25/y,this._x=(v-m)*y,this._y=(c-p)*y,this._z=(f-l)*y}else if(s>d&&s>_){const y=2*Math.sqrt(1+s-d-_);this._w=(v-m)/y,this._x=.25*y,this._y=(l+f)/y,this._z=(c+p)/y}else if(d>_){const y=2*Math.sqrt(1+d-s-_);this._w=(c-p)/y,this._x=(l+f)/y,this._y=.25*y,this._z=(m+v)/y}else{const y=2*Math.sqrt(1+_-s-d);this._w=(f-l)/y,this._x=(c+p)/y,this._y=(m+v)/y,this._z=.25*y}return this._onChangeCallback(),this}setFromUnitVectors(t,n){let s=t.dot(n)+1;return s<1e-8?(s=0,Math.abs(t.x)>Math.abs(t.z)?(this._x=-t.y,this._y=t.x,this._z=0,this._w=s):(this._x=0,this._y=-t.z,this._z=t.y,this._w=s)):(this._x=t.y*n.z-t.z*n.y,this._y=t.z*n.x-t.x*n.z,this._z=t.x*n.y-t.y*n.x,this._w=s),this.normalize()}angleTo(t){return 2*Math.acos(Math.abs(ve(this.dot(t),-1,1)))}rotateTowards(t,n){const s=this.angleTo(t);if(s===0)return this;const l=Math.min(1,n/s);return this.slerp(t,l),this}identity(){return this.set(0,0,0,1)}invert(){return this.conjugate()}conjugate(){return this._x*=-1,this._y*=-1,this._z*=-1,this._onChangeCallback(),this}dot(t){return this._x*t._x+this._y*t._y+this._z*t._z+this._w*t._w}lengthSq(){return this._x*this._x+this._y*this._y+this._z*this._z+this._w*this._w}length(){return Math.sqrt(this._x*this._x+this._y*this._y+this._z*this._z+this._w*this._w)}normalize(){let t=this.length();return t===0?(this._x=0,this._y=0,this._z=0,this._w=1):(t=1/t,this._x=this._x*t,this._y=this._y*t,this._z=this._z*t,this._w=this._w*t),this._onChangeCallback(),this}multiply(t){return this.multiplyQuaternions(this,t)}premultiply(t){return this.multiplyQuaternions(t,this)}multiplyQuaternions(t,n){const s=t._x,l=t._y,c=t._z,f=t._w,d=n._x,m=n._y,p=n._z,v=n._w;return this._x=s*v+f*d+l*p-c*m,this._y=l*v+f*m+c*d-s*p,this._z=c*v+f*p+s*m-l*d,this._w=f*v-s*d-l*m-c*p,this._onChangeCallback(),this}slerp(t,n){let s=t._x,l=t._y,c=t._z,f=t._w,d=this.dot(t);d<0&&(s=-s,l=-l,c=-c,f=-f,d=-d);let m=1-n;if(d<.9995){const p=Math.acos(d),v=Math.sin(p);m=Math.sin(m*p)/v,n=Math.sin(n*p)/v,this._x=this._x*m+s*n,this._y=this._y*m+l*n,this._z=this._z*m+c*n,this._w=this._w*m+f*n,this._onChangeCallback()}else this._x=this._x*m+s*n,this._y=this._y*m+l*n,this._z=this._z*m+c*n,this._w=this._w*m+f*n,this.normalize();return this}slerpQuaternions(t,n,s){return this.copy(t).slerp(n,s)}random(){const t=2*Math.PI*Math.random(),n=2*Math.PI*Math.random(),s=Math.random(),l=Math.sqrt(1-s),c=Math.sqrt(s);return this.set(l*Math.sin(t),l*Math.cos(t),c*Math.sin(n),c*Math.cos(n))}equals(t){return t._x===this._x&&t._y===this._y&&t._z===this._z&&t._w===this._w}fromArray(t,n=0){return this._x=t[n],this._y=t[n+1],this._z=t[n+2],this._w=t[n+3],this._onChangeCallback(),this}toArray(t=[],n=0){return t[n]=this._x,t[n+1]=this._y,t[n+2]=this._z,t[n+3]=this._w,t}fromBufferAttribute(t,n){return this._x=t.getX(n),this._y=t.getY(n),this._z=t.getZ(n),this._w=t.getW(n),this._onChangeCallback(),this}toJSON(){return this.toArray()}_onChange(t){return this._onChangeCallback=t,this}_onChangeCallback(){}*[Symbol.iterator](){yield this._x,yield this._y,yield this._z,yield this._w}}const bp=class bp{constructor(t=0,n=0,s=0){this.x=t,this.y=n,this.z=s}set(t,n,s){return s===void 0&&(s=this.z),this.x=t,this.y=n,this.z=s,this}setScalar(t){return this.x=t,this.y=t,this.z=t,this}setX(t){return this.x=t,this}setY(t){return this.y=t,this}setZ(t){return this.z=t,this}setComponent(t,n){switch(t){case 0:this.x=n;break;case 1:this.y=n;break;case 2:this.z=n;break;default:throw new Error("THREE.Vector3: index is out of range: "+t)}return this}getComponent(t){switch(t){case 0:return this.x;case 1:return this.y;case 2:return this.z;default:throw new Error("THREE.Vector3: index is out of range: "+t)}}clone(){return new this.constructor(this.x,this.y,this.z)}copy(t){return this.x=t.x,this.y=t.y,this.z=t.z,this}add(t){return this.x+=t.x,this.y+=t.y,this.z+=t.z,this}addScalar(t){return this.x+=t,this.y+=t,this.z+=t,this}addVectors(t,n){return this.x=t.x+n.x,this.y=t.y+n.y,this.z=t.z+n.z,this}addScaledVector(t,n){return this.x+=t.x*n,this.y+=t.y*n,this.z+=t.z*n,this}sub(t){return this.x-=t.x,this.y-=t.y,this.z-=t.z,this}subScalar(t){return this.x-=t,this.y-=t,this.z-=t,this}subVectors(t,n){return this.x=t.x-n.x,this.y=t.y-n.y,this.z=t.z-n.z,this}multiply(t){return this.x*=t.x,this.y*=t.y,this.z*=t.z,this}multiplyScalar(t){return this.x*=t,this.y*=t,this.z*=t,this}multiplyVectors(t,n){return this.x=t.x*n.x,this.y=t.y*n.y,this.z=t.z*n.z,this}applyEuler(t){return this.applyQuaternion(Tv.setFromEuler(t))}applyAxisAngle(t,n){return this.applyQuaternion(Tv.setFromAxisAngle(t,n))}applyMatrix3(t){const n=this.x,s=this.y,l=this.z,c=t.elements;return this.x=c[0]*n+c[3]*s+c[6]*l,this.y=c[1]*n+c[4]*s+c[7]*l,this.z=c[2]*n+c[5]*s+c[8]*l,this}applyNormalMatrix(t){return this.applyMatrix3(t).normalize()}applyMatrix4(t){const n=this.x,s=this.y,l=this.z,c=t.elements,f=1/(c[3]*n+c[7]*s+c[11]*l+c[15]);return this.x=(c[0]*n+c[4]*s+c[8]*l+c[12])*f,this.y=(c[1]*n+c[5]*s+c[9]*l+c[13])*f,this.z=(c[2]*n+c[6]*s+c[10]*l+c[14])*f,this}applyQuaternion(t){const n=this.x,s=this.y,l=this.z,c=t.x,f=t.y,d=t.z,m=t.w,p=2*(f*l-d*s),v=2*(d*n-c*l),_=2*(c*s-f*n);return this.x=n+m*p+f*_-d*v,this.y=s+m*v+d*p-c*_,this.z=l+m*_+c*v-f*p,this}project(t){return this.applyMatrix4(t.matrixWorldInverse).applyMatrix4(t.projectionMatrix)}unproject(t){return this.applyMatrix4(t.projectionMatrixInverse).applyMatrix4(t.matrixWorld)}transformDirection(t){const n=this.x,s=this.y,l=this.z,c=t.elements;return this.x=c[0]*n+c[4]*s+c[8]*l,this.y=c[1]*n+c[5]*s+c[9]*l,this.z=c[2]*n+c[6]*s+c[10]*l,this.normalize()}divide(t){return this.x/=t.x,this.y/=t.y,this.z/=t.z,this}divideScalar(t){return this.multiplyScalar(1/t)}min(t){return this.x=Math.min(this.x,t.x),this.y=Math.min(this.y,t.y),this.z=Math.min(this.z,t.z),this}max(t){return this.x=Math.max(this.x,t.x),this.y=Math.max(this.y,t.y),this.z=Math.max(this.z,t.z),this}clamp(t,n){return this.x=ve(this.x,t.x,n.x),this.y=ve(this.y,t.y,n.y),this.z=ve(this.z,t.z,n.z),this}clampScalar(t,n){return this.x=ve(this.x,t,n),this.y=ve(this.y,t,n),this.z=ve(this.z,t,n),this}clampLength(t,n){const s=this.length();return this.divideScalar(s||1).multiplyScalar(ve(s,t,n))}floor(){return this.x=Math.floor(this.x),this.y=Math.floor(this.y),this.z=Math.floor(this.z),this}ceil(){return this.x=Math.ceil(this.x),this.y=Math.ceil(this.y),this.z=Math.ceil(this.z),this}round(){return this.x=Math.round(this.x),this.y=Math.round(this.y),this.z=Math.round(this.z),this}roundToZero(){return this.x=Math.trunc(this.x),this.y=Math.trunc(this.y),this.z=Math.trunc(this.z),this}negate(){return this.x=-this.x,this.y=-this.y,this.z=-this.z,this}dot(t){return this.x*t.x+this.y*t.y+this.z*t.z}lengthSq(){return this.x*this.x+this.y*this.y+this.z*this.z}length(){return Math.sqrt(this.x*this.x+this.y*this.y+this.z*this.z)}manhattanLength(){return Math.abs(this.x)+Math.abs(this.y)+Math.abs(this.z)}normalize(){return this.divideScalar(this.length()||1)}setLength(t){return this.normalize().multiplyScalar(t)}lerp(t,n){return this.x+=(t.x-this.x)*n,this.y+=(t.y-this.y)*n,this.z+=(t.z-this.z)*n,this}lerpVectors(t,n,s){return this.x=t.x+(n.x-t.x)*s,this.y=t.y+(n.y-t.y)*s,this.z=t.z+(n.z-t.z)*s,this}cross(t){return this.crossVectors(this,t)}crossVectors(t,n){const s=t.x,l=t.y,c=t.z,f=n.x,d=n.y,m=n.z;return this.x=l*m-c*d,this.y=c*f-s*m,this.z=s*d-l*f,this}projectOnVector(t){const n=t.lengthSq();if(n===0)return this.set(0,0,0);const s=t.dot(this)/n;return this.copy(t).multiplyScalar(s)}projectOnPlane(t){return wh.copy(this).projectOnVector(t),this.sub(wh)}reflect(t){return this.sub(wh.copy(t).multiplyScalar(2*this.dot(t)))}angleTo(t){const n=Math.sqrt(this.lengthSq()*t.lengthSq());if(n===0)return Math.PI/2;const s=this.dot(t)/n;return Math.acos(ve(s,-1,1))}distanceTo(t){return Math.sqrt(this.distanceToSquared(t))}distanceToSquared(t){const n=this.x-t.x,s=this.y-t.y,l=this.z-t.z;return n*n+s*s+l*l}manhattanDistanceTo(t){return Math.abs(this.x-t.x)+Math.abs(this.y-t.y)+Math.abs(this.z-t.z)}setFromSpherical(t){return this.setFromSphericalCoords(t.radius,t.phi,t.theta)}setFromSphericalCoords(t,n,s){const l=Math.sin(n)*t;return this.x=l*Math.sin(s),this.y=Math.cos(n)*t,this.z=l*Math.cos(s),this}setFromCylindrical(t){return this.setFromCylindricalCoords(t.radius,t.theta,t.y)}setFromCylindricalCoords(t,n,s){return this.x=t*Math.sin(n),this.y=s,this.z=t*Math.cos(n),this}setFromMatrixPosition(t){const n=t.elements;return this.x=n[12],this.y=n[13],this.z=n[14],this}setFromMatrixScale(t){const n=this.setFromMatrixColumn(t,0).length(),s=this.setFromMatrixColumn(t,1).length(),l=this.setFromMatrixColumn(t,2).length();return this.x=n,this.y=s,this.z=l,this}setFromMatrixColumn(t,n){return this.fromArray(t.elements,n*4)}setFromMatrix3Column(t,n){return this.fromArray(t.elements,n*3)}setFromEuler(t){return this.x=t._x,this.y=t._y,this.z=t._z,this}setFromColor(t){return this.x=t.r,this.y=t.g,this.z=t.b,this}equals(t){return t.x===this.x&&t.y===this.y&&t.z===this.z}fromArray(t,n=0){return this.x=t[n],this.y=t[n+1],this.z=t[n+2],this}toArray(t=[],n=0){return t[n]=this.x,t[n+1]=this.y,t[n+2]=this.z,t}fromBufferAttribute(t,n){return this.x=t.getX(n),this.y=t.getY(n),this.z=t.getZ(n),this}random(){return this.x=Math.random(),this.y=Math.random(),this.z=Math.random(),this}randomDirection(){const t=Math.random()*Math.PI*2,n=Math.random()*2-1,s=Math.sqrt(1-n*n);return this.x=s*Math.cos(t),this.y=n,this.z=s*Math.sin(t),this}*[Symbol.iterator](){yield this.x,yield this.y,yield this.z}};bp.prototype.isVector3=!0;let K=bp;const wh=new K,Tv=new Zr,Tp=class Tp{constructor(t,n,s,l,c,f,d,m,p){this.elements=[1,0,0,0,1,0,0,0,1],t!==void 0&&this.set(t,n,s,l,c,f,d,m,p)}set(t,n,s,l,c,f,d,m,p){const v=this.elements;return v[0]=t,v[1]=l,v[2]=d,v[3]=n,v[4]=c,v[5]=m,v[6]=s,v[7]=f,v[8]=p,this}identity(){return this.set(1,0,0,0,1,0,0,0,1),this}copy(t){const n=this.elements,s=t.elements;return n[0]=s[0],n[1]=s[1],n[2]=s[2],n[3]=s[3],n[4]=s[4],n[5]=s[5],n[6]=s[6],n[7]=s[7],n[8]=s[8],this}extractBasis(t,n,s){return t.setFromMatrix3Column(this,0),n.setFromMatrix3Column(this,1),s.setFromMatrix3Column(this,2),this}setFromMatrix4(t){const n=t.elements;return this.set(n[0],n[4],n[8],n[1],n[5],n[9],n[2],n[6],n[10]),this}multiply(t){return this.multiplyMatrices(this,t)}premultiply(t){return this.multiplyMatrices(t,this)}multiplyMatrices(t,n){const s=t.elements,l=n.elements,c=this.elements,f=s[0],d=s[3],m=s[6],p=s[1],v=s[4],_=s[7],g=s[2],y=s[5],b=s[8],w=l[0],M=l[3],S=l[6],P=l[1],D=l[4],A=l[7],F=l[2],O=l[5],I=l[8];return c[0]=f*w+d*P+m*F,c[3]=f*M+d*D+m*O,c[6]=f*S+d*A+m*I,c[1]=p*w+v*P+_*F,c[4]=p*M+v*D+_*O,c[7]=p*S+v*A+_*I,c[2]=g*w+y*P+b*F,c[5]=g*M+y*D+b*O,c[8]=g*S+y*A+b*I,this}multiplyScalar(t){const n=this.elements;return n[0]*=t,n[3]*=t,n[6]*=t,n[1]*=t,n[4]*=t,n[7]*=t,n[2]*=t,n[5]*=t,n[8]*=t,this}determinant(){const t=this.elements,n=t[0],s=t[1],l=t[2],c=t[3],f=t[4],d=t[5],m=t[6],p=t[7],v=t[8];return n*f*v-n*d*p-s*c*v+s*d*m+l*c*p-l*f*m}invert(){const t=this.elements,n=t[0],s=t[1],l=t[2],c=t[3],f=t[4],d=t[5],m=t[6],p=t[7],v=t[8],_=v*f-d*p,g=d*m-v*c,y=p*c-f*m,b=n*_+s*g+l*y;if(b===0)return this.set(0,0,0,0,0,0,0,0,0);const w=1/b;return t[0]=_*w,t[1]=(l*p-v*s)*w,t[2]=(d*s-l*f)*w,t[3]=g*w,t[4]=(v*n-l*m)*w,t[5]=(l*c-d*n)*w,t[6]=y*w,t[7]=(s*m-p*n)*w,t[8]=(f*n-s*c)*w,this}transpose(){let t;const n=this.elements;return t=n[1],n[1]=n[3],n[3]=t,t=n[2],n[2]=n[6],n[6]=t,t=n[5],n[5]=n[7],n[7]=t,this}getNormalMatrix(t){return this.setFromMatrix4(t).invert().transpose()}transposeIntoArray(t){const n=this.elements;return t[0]=n[0],t[1]=n[3],t[2]=n[6],t[3]=n[1],t[4]=n[4],t[5]=n[7],t[6]=n[2],t[7]=n[5],t[8]=n[8],this}setUvTransform(t,n,s,l,c,f,d){const m=Math.cos(c),p=Math.sin(c);return this.set(s*m,s*p,-s*(m*f+p*d)+f+t,-l*p,l*m,-l*(-p*f+m*d)+d+n,0,0,1),this}scale(t,n){return Hr("Matrix3: .scale() is deprecated. Use .makeScale() instead."),this.premultiply(Dh.makeScale(t,n)),this}rotate(t){return Hr("Matrix3: .rotate() is deprecated. Use .makeRotation() instead."),this.premultiply(Dh.makeRotation(-t)),this}translate(t,n){return Hr("Matrix3: .translate() is deprecated. Use .makeTranslation() instead."),this.premultiply(Dh.makeTranslation(t,n)),this}makeTranslation(t,n){return t.isVector2?this.set(1,0,t.x,0,1,t.y,0,0,1):this.set(1,0,t,0,1,n,0,0,1),this}makeRotation(t){const n=Math.cos(t),s=Math.sin(t);return this.set(n,-s,0,s,n,0,0,0,1),this}makeScale(t,n){return this.set(t,0,0,0,n,0,0,0,1),this}equals(t){const n=this.elements,s=t.elements;for(let l=0;l<9;l++)if(n[l]!==s[l])return!1;return!0}fromArray(t,n=0){for(let s=0;s<9;s++)this.elements[s]=t[s+n];return this}toArray(t=[],n=0){const s=this.elements;return t[n]=s[0],t[n+1]=s[1],t[n+2]=s[2],t[n+3]=s[3],t[n+4]=s[4],t[n+5]=s[5],t[n+6]=s[6],t[n+7]=s[7],t[n+8]=s[8],t}clone(){return new this.constructor().fromArray(this.elements)}};Tp.prototype.isMatrix3=!0;let re=Tp;const Dh=new re,Av=new re().set(.4123908,.3575843,.1804808,.212639,.7151687,.0721923,.0193308,.1191948,.9505322),Rv=new re().set(3.2409699,-1.5373832,-.4986108,-.9692436,1.8759675,.0415551,.0556301,-.203977,1.0569715);function yM(){const r={enabled:!0,workingColorSpace:au,spaces:{},convert:function(l,c,f){return this.enabled===!1||c===f||!c||!f||(this.spaces[c].transfer===ze&&(l.r=Ta(l.r),l.g=Ta(l.g),l.b=Ta(l.b)),this.spaces[c].primaries!==this.spaces[f].primaries&&(l.applyMatrix3(this.spaces[c].toXYZ),l.applyMatrix3(this.spaces[f].fromXYZ)),this.spaces[f].transfer===ze&&(l.r=Gr(l.r),l.g=Gr(l.g),l.b=Gr(l.b))),l},workingToColorSpace:function(l,c){return this.convert(l,this.workingColorSpace,c)},colorSpaceToWorking:function(l,c){return this.convert(l,c,this.workingColorSpace)},getPrimaries:function(l){return this.spaces[l].primaries},getTransfer:function(l){return l===os?su:this.spaces[l].transfer},getToneMappingMode:function(l){return this.spaces[l].outputColorSpaceConfig.toneMappingMode||"standard"},getLuminanceCoefficients:function(l,c=this.workingColorSpace){return l.fromArray(this.spaces[c].luminanceCoefficients)},define:function(l){Object.assign(this.spaces,l)},_getMatrix:function(l,c,f){return l.copy(this.spaces[c].toXYZ).multiply(this.spaces[f].fromXYZ)},_getDrawingBufferColorSpace:function(l){return this.spaces[l].outputColorSpaceConfig.drawingBufferColorSpace},_getUnpackColorSpace:function(l=this.workingColorSpace){return this.spaces[l].workingColorSpaceConfig.unpackColorSpace},fromWorkingColorSpace:function(l,c){return Hr("ColorManagement: .fromWorkingColorSpace() has been renamed to .workingToColorSpace()."),r.workingToColorSpace(l,c)},toWorkingColorSpace:function(l,c){return Hr("ColorManagement: .toWorkingColorSpace() has been renamed to .colorSpaceToWorking()."),r.colorSpaceToWorking(l,c)}},t=[.64,.33,.3,.6,.15,.06],n=[.2126,.7152,.0722],s=[.3127,.329];return r.define({[au]:{primaries:t,whitePoint:s,transfer:su,toXYZ:Av,fromXYZ:Rv,luminanceCoefficients:n,workingColorSpaceConfig:{unpackColorSpace:hi},outputColorSpaceConfig:{drawingBufferColorSpace:hi}},[hi]:{primaries:t,whitePoint:s,transfer:ze,toXYZ:Av,fromXYZ:Rv,luminanceCoefficients:n,outputColorSpaceConfig:{drawingBufferColorSpace:hi}}}),r}const Ee=yM();function Ta(r){return r<.04045?r*.0773993808:Math.pow(r*.9478672986+.0521327014,2.4)}function Gr(r){return r<.0031308?r*12.92:1.055*Math.pow(r,.41666)-.055}let Tr;class MM{static getDataURL(t,n="image/png"){if(/^data:/i.test(t.src)||typeof HTMLCanvasElement>"u")return t.src;let s;if(t instanceof HTMLCanvasElement)s=t;else{Tr===void 0&&(Tr=ru("canvas")),Tr.width=t.width,Tr.height=t.height;const l=Tr.getContext("2d");t instanceof ImageData?l.putImageData(t,0,0):l.drawImage(t,0,0,t.width,t.height),s=Tr}return s.toDataURL(n)}static sRGBToLinear(t){if(typeof HTMLImageElement<"u"&&t instanceof HTMLImageElement||typeof HTMLCanvasElement<"u"&&t instanceof HTMLCanvasElement||typeof ImageBitmap<"u"&&t instanceof ImageBitmap){const n=ru("canvas");n.width=t.width,n.height=t.height;const s=n.getContext("2d");s.drawImage(t,0,0,t.width,t.height);const l=s.getImageData(0,0,t.width,t.height),c=l.data;for(let f=0;f<c.length;f++)c[f]=Ta(c[f]/255)*255;return s.putImageData(l,0,0),n}else if(t.data){const n=t.data.slice(0);for(let s=0;s<n.length;s++)n instanceof Uint8Array||n instanceof Uint8ClampedArray?n[s]=Math.floor(Ta(n[s]/255)*255):n[s]=Ta(n[s]);return{data:n,width:t.width,height:t.height}}else return ie("ImageUtils.sRGBToLinear(): Unsupported image type. No color space conversion applied."),t}}let EM=0;class dp{constructor(t=null){this.isSource=!0,Object.defineProperty(this,"id",{value:EM++}),this.uuid=Yr(),this.data=t,this.dataReady=!0,this.version=0}getSize(t){const n=this.data;return typeof HTMLVideoElement<"u"&&n instanceof HTMLVideoElement?t.set(n.videoWidth,n.videoHeight,0):typeof VideoFrame<"u"&&n instanceof VideoFrame?t.set(n.displayWidth,n.displayHeight,0):n!==null?t.set(n.width,n.height,n.depth||0):t.set(0,0,0),t}set needsUpdate(t){t===!0&&this.version++}toJSON(t){const n=t===void 0||typeof t=="string";if(!n&&t.images[this.uuid]!==void 0)return t.images[this.uuid];const s={uuid:this.uuid,url:""},l=this.data;if(l!==null){let c;if(Array.isArray(l)){c=[];for(let f=0,d=l.length;f<d;f++)l[f].isDataTexture?c.push(Nh(l[f].image)):c.push(Nh(l[f]))}else c=Nh(l);s.url=c}return n||(t.images[this.uuid]=s),s}}function Nh(r){return typeof HTMLImageElement<"u"&&r instanceof HTMLImageElement||typeof HTMLCanvasElement<"u"&&r instanceof HTMLCanvasElement||typeof ImageBitmap<"u"&&r instanceof ImageBitmap?MM.getDataURL(r):r.data?{data:Array.from(r.data),width:r.width,height:r.height,type:r.data.constructor.name}:(ie("Texture: Unable to serialize Texture."),{})}let bM=0;const Uh=new K;class kn extends Ws{constructor(t=kn.DEFAULT_IMAGE,n=kn.DEFAULT_MAPPING,s=Ea,l=Ea,c=Bn,f=Hs,d=Pi,m=di,p=kn.DEFAULT_ANISOTROPY,v=os){super(),this.isTexture=!0,Object.defineProperty(this,"id",{value:bM++}),this.uuid=Yr(),this.name="",this.source=new dp(t),this.mipmaps=[],this.mapping=n,this.channel=0,this.wrapS=s,this.wrapT=l,this.magFilter=c,this.minFilter=f,this.anisotropy=p,this.format=d,this.internalFormat=null,this.type=m,this.offset=new qt(0,0),this.repeat=new qt(1,1),this.center=new qt(0,0),this.rotation=0,this.matrixAutoUpdate=!0,this.matrix=new re,this.generateMipmaps=!0,this.premultiplyAlpha=!1,this.flipY=!0,this.unpackAlignment=4,this.colorSpace=v,this.userData={},this.updateRanges=[],this.version=0,this.onUpdate=null,this.renderTarget=null,this.isRenderTargetTexture=!1,this.isArrayTexture=!!(t&&t.depth&&t.depth>1),this.pmremVersion=0,this.normalized=!1}get width(){return this.source.getSize(Uh).x}get height(){return this.source.getSize(Uh).y}get depth(){return this.source.getSize(Uh).z}get image(){return this.source.data}set image(t){this.source.data=t}updateMatrix(){this.matrix.setUvTransform(this.offset.x,this.offset.y,this.repeat.x,this.repeat.y,this.rotation,this.center.x,this.center.y)}addUpdateRange(t,n){this.updateRanges.push({start:t,count:n})}clearUpdateRanges(){this.updateRanges.length=0}clone(){return new this.constructor().copy(this)}copy(t){return this.name=t.name,this.source=t.source,this.mipmaps=t.mipmaps.slice(0),this.mapping=t.mapping,this.channel=t.channel,this.wrapS=t.wrapS,this.wrapT=t.wrapT,this.magFilter=t.magFilter,this.minFilter=t.minFilter,this.anisotropy=t.anisotropy,this.format=t.format,this.internalFormat=t.internalFormat,this.type=t.type,this.normalized=t.normalized,this.offset.copy(t.offset),this.repeat.copy(t.repeat),this.center.copy(t.center),this.rotation=t.rotation,this.matrixAutoUpdate=t.matrixAutoUpdate,this.matrix.copy(t.matrix),this.generateMipmaps=t.generateMipmaps,this.premultiplyAlpha=t.premultiplyAlpha,this.flipY=t.flipY,this.unpackAlignment=t.unpackAlignment,this.colorSpace=t.colorSpace,this.renderTarget=t.renderTarget,this.isRenderTargetTexture=t.isRenderTargetTexture,this.isArrayTexture=t.isArrayTexture,this.userData=JSON.parse(JSON.stringify(t.userData)),this.needsUpdate=!0,this}setValues(t){for(const n in t){const s=t[n];if(s===void 0){ie(`Texture.setValues(): parameter '${n}' has value of undefined.`);continue}const l=this[n];if(l===void 0){ie(`Texture.setValues(): property '${n}' does not exist.`);continue}l&&s&&l.isVector2&&s.isVector2||l&&s&&l.isVector3&&s.isVector3||l&&s&&l.isMatrix3&&s.isMatrix3?l.copy(s):this[n]=s}}toJSON(t){const n=t===void 0||typeof t=="string";if(!n&&t.textures[this.uuid]!==void 0)return t.textures[this.uuid];const s={metadata:{version:4.7,type:"Texture",generator:"Texture.toJSON"},uuid:this.uuid,name:this.name,image:this.source.toJSON(t).uuid,mapping:this.mapping,channel:this.channel,repeat:[this.repeat.x,this.repeat.y],offset:[this.offset.x,this.offset.y],center:[this.center.x,this.center.y],rotation:this.rotation,wrap:[this.wrapS,this.wrapT],format:this.format,internalFormat:this.internalFormat,type:this.type,normalized:this.normalized,colorSpace:this.colorSpace,minFilter:this.minFilter,magFilter:this.magFilter,anisotropy:this.anisotropy,flipY:this.flipY,generateMipmaps:this.generateMipmaps,premultiplyAlpha:this.premultiplyAlpha,unpackAlignment:this.unpackAlignment};return Object.keys(this.userData).length>0&&(s.userData=this.userData),n||(t.textures[this.uuid]=s),s}dispose(){this.dispatchEvent({type:"dispose"})}transformUv(t){if(this.mapping!==k_)return t;if(t.applyMatrix3(this.matrix),t.x<0||t.x>1)switch(this.wrapS){case _d:t.x=t.x-Math.floor(t.x);break;case Ea:t.x=t.x<0?0:1;break;case xd:Math.abs(Math.floor(t.x)%2)===1?t.x=Math.ceil(t.x)-t.x:t.x=t.x-Math.floor(t.x);break}if(t.y<0||t.y>1)switch(this.wrapT){case _d:t.y=t.y-Math.floor(t.y);break;case Ea:t.y=t.y<0?0:1;break;case xd:Math.abs(Math.floor(t.y)%2)===1?t.y=Math.ceil(t.y)-t.y:t.y=t.y-Math.floor(t.y);break}return this.flipY&&(t.y=1-t.y),t}set needsUpdate(t){t===!0&&(this.version++,this.source.needsUpdate=!0)}set needsPMREMUpdate(t){t===!0&&this.pmremVersion++}}kn.DEFAULT_IMAGE=null;kn.DEFAULT_MAPPING=k_;kn.DEFAULT_ANISOTROPY=1;const Ap=class Ap{constructor(t=0,n=0,s=0,l=1){this.x=t,this.y=n,this.z=s,this.w=l}get width(){return this.z}set width(t){this.z=t}get height(){return this.w}set height(t){this.w=t}set(t,n,s,l){return this.x=t,this.y=n,this.z=s,this.w=l,this}setScalar(t){return this.x=t,this.y=t,this.z=t,this.w=t,this}setX(t){return this.x=t,this}setY(t){return this.y=t,this}setZ(t){return this.z=t,this}setW(t){return this.w=t,this}setComponent(t,n){switch(t){case 0:this.x=n;break;case 1:this.y=n;break;case 2:this.z=n;break;case 3:this.w=n;break;default:throw new Error("THREE.Vector4: index is out of range: "+t)}return this}getComponent(t){switch(t){case 0:return this.x;case 1:return this.y;case 2:return this.z;case 3:return this.w;default:throw new Error("THREE.Vector4: index is out of range: "+t)}}clone(){return new this.constructor(this.x,this.y,this.z,this.w)}copy(t){return this.x=t.x,this.y=t.y,this.z=t.z,this.w=t.w!==void 0?t.w:1,this}add(t){return this.x+=t.x,this.y+=t.y,this.z+=t.z,this.w+=t.w,this}addScalar(t){return this.x+=t,this.y+=t,this.z+=t,this.w+=t,this}addVectors(t,n){return this.x=t.x+n.x,this.y=t.y+n.y,this.z=t.z+n.z,this.w=t.w+n.w,this}addScaledVector(t,n){return this.x+=t.x*n,this.y+=t.y*n,this.z+=t.z*n,this.w+=t.w*n,this}sub(t){return this.x-=t.x,this.y-=t.y,this.z-=t.z,this.w-=t.w,this}subScalar(t){return this.x-=t,this.y-=t,this.z-=t,this.w-=t,this}subVectors(t,n){return this.x=t.x-n.x,this.y=t.y-n.y,this.z=t.z-n.z,this.w=t.w-n.w,this}multiply(t){return this.x*=t.x,this.y*=t.y,this.z*=t.z,this.w*=t.w,this}multiplyScalar(t){return this.x*=t,this.y*=t,this.z*=t,this.w*=t,this}applyMatrix4(t){const n=this.x,s=this.y,l=this.z,c=this.w,f=t.elements;return this.x=f[0]*n+f[4]*s+f[8]*l+f[12]*c,this.y=f[1]*n+f[5]*s+f[9]*l+f[13]*c,this.z=f[2]*n+f[6]*s+f[10]*l+f[14]*c,this.w=f[3]*n+f[7]*s+f[11]*l+f[15]*c,this}divide(t){return this.x/=t.x,this.y/=t.y,this.z/=t.z,this.w/=t.w,this}divideScalar(t){return this.multiplyScalar(1/t)}setAxisAngleFromQuaternion(t){this.w=2*Math.acos(t.w);const n=Math.sqrt(1-t.w*t.w);return n<1e-4?(this.x=1,this.y=0,this.z=0):(this.x=t.x/n,this.y=t.y/n,this.z=t.z/n),this}setAxisAngleFromRotationMatrix(t){let n,s,l,c;const m=t.elements,p=m[0],v=m[4],_=m[8],g=m[1],y=m[5],b=m[9],w=m[2],M=m[6],S=m[10];if(Math.abs(v-g)<.01&&Math.abs(_-w)<.01&&Math.abs(b-M)<.01){if(Math.abs(v+g)<.1&&Math.abs(_+w)<.1&&Math.abs(b+M)<.1&&Math.abs(p+y+S-3)<.1)return this.set(1,0,0,0),this;n=Math.PI;const D=(p+1)/2,A=(y+1)/2,F=(S+1)/2,O=(v+g)/4,I=(_+w)/4,T=(b+M)/4;return D>A&&D>F?D<.01?(s=0,l=.707106781,c=.707106781):(s=Math.sqrt(D),l=O/s,c=I/s):A>F?A<.01?(s=.707106781,l=0,c=.707106781):(l=Math.sqrt(A),s=O/l,c=T/l):F<.01?(s=.707106781,l=.707106781,c=0):(c=Math.sqrt(F),s=I/c,l=T/c),this.set(s,l,c,n),this}let P=Math.sqrt((M-b)*(M-b)+(_-w)*(_-w)+(g-v)*(g-v));return Math.abs(P)<.001&&(P=1),this.x=(M-b)/P,this.y=(_-w)/P,this.z=(g-v)/P,this.w=Math.acos((p+y+S-1)/2),this}setFromMatrixPosition(t){const n=t.elements;return this.x=n[12],this.y=n[13],this.z=n[14],this.w=n[15],this}min(t){return this.x=Math.min(this.x,t.x),this.y=Math.min(this.y,t.y),this.z=Math.min(this.z,t.z),this.w=Math.min(this.w,t.w),this}max(t){return this.x=Math.max(this.x,t.x),this.y=Math.max(this.y,t.y),this.z=Math.max(this.z,t.z),this.w=Math.max(this.w,t.w),this}clamp(t,n){return this.x=ve(this.x,t.x,n.x),this.y=ve(this.y,t.y,n.y),this.z=ve(this.z,t.z,n.z),this.w=ve(this.w,t.w,n.w),this}clampScalar(t,n){return this.x=ve(this.x,t,n),this.y=ve(this.y,t,n),this.z=ve(this.z,t,n),this.w=ve(this.w,t,n),this}clampLength(t,n){const s=this.length();return this.divideScalar(s||1).multiplyScalar(ve(s,t,n))}floor(){return this.x=Math.floor(this.x),this.y=Math.floor(this.y),this.z=Math.floor(this.z),this.w=Math.floor(this.w),this}ceil(){return this.x=Math.ceil(this.x),this.y=Math.ceil(this.y),this.z=Math.ceil(this.z),this.w=Math.ceil(this.w),this}round(){return this.x=Math.round(this.x),this.y=Math.round(this.y),this.z=Math.round(this.z),this.w=Math.round(this.w),this}roundToZero(){return this.x=Math.trunc(this.x),this.y=Math.trunc(this.y),this.z=Math.trunc(this.z),this.w=Math.trunc(this.w),this}negate(){return this.x=-this.x,this.y=-this.y,this.z=-this.z,this.w=-this.w,this}dot(t){return this.x*t.x+this.y*t.y+this.z*t.z+this.w*t.w}lengthSq(){return this.x*this.x+this.y*this.y+this.z*this.z+this.w*this.w}length(){return Math.sqrt(this.x*this.x+this.y*this.y+this.z*this.z+this.w*this.w)}manhattanLength(){return Math.abs(this.x)+Math.abs(this.y)+Math.abs(this.z)+Math.abs(this.w)}normalize(){return this.divideScalar(this.length()||1)}setLength(t){return this.normalize().multiplyScalar(t)}lerp(t,n){return this.x+=(t.x-this.x)*n,this.y+=(t.y-this.y)*n,this.z+=(t.z-this.z)*n,this.w+=(t.w-this.w)*n,this}lerpVectors(t,n,s){return this.x=t.x+(n.x-t.x)*s,this.y=t.y+(n.y-t.y)*s,this.z=t.z+(n.z-t.z)*s,this.w=t.w+(n.w-t.w)*s,this}equals(t){return t.x===this.x&&t.y===this.y&&t.z===this.z&&t.w===this.w}fromArray(t,n=0){return this.x=t[n],this.y=t[n+1],this.z=t[n+2],this.w=t[n+3],this}toArray(t=[],n=0){return t[n]=this.x,t[n+1]=this.y,t[n+2]=this.z,t[n+3]=this.w,t}fromBufferAttribute(t,n){return this.x=t.getX(n),this.y=t.getY(n),this.z=t.getZ(n),this.w=t.getW(n),this}random(){return this.x=Math.random(),this.y=Math.random(),this.z=Math.random(),this.w=Math.random(),this}*[Symbol.iterator](){yield this.x,yield this.y,yield this.z,yield this.w}};Ap.prototype.isVector4=!0;let $e=Ap;class TM extends Ws{constructor(t=1,n=1,s={}){super(),s=Object.assign({generateMipmaps:!1,internalFormat:null,minFilter:Bn,depthBuffer:!0,stencilBuffer:!1,resolveDepthBuffer:!0,resolveStencilBuffer:!0,depthTexture:null,samples:0,count:1,depth:1,multiview:!1,useArrayDepthTexture:!1},s),this.isRenderTarget=!0,this.width=t,this.height=n,this.depth=s.depth,this.scissor=new $e(0,0,t,n),this.scissorTest=!1,this.viewport=new $e(0,0,t,n),this.textures=[];const l={width:t,height:n,depth:s.depth},c=new kn(l),f=s.count;for(let d=0;d<f;d++)this.textures[d]=c.clone(),this.textures[d].isRenderTargetTexture=!0,this.textures[d].renderTarget=this;this._setTextureOptions(s),this.depthBuffer=s.depthBuffer,this.stencilBuffer=s.stencilBuffer,this.resolveDepthBuffer=s.resolveDepthBuffer,this.resolveStencilBuffer=s.resolveStencilBuffer,this._depthTexture=null,this.depthTexture=s.depthTexture,this.samples=s.samples,this.multiview=s.multiview,this.useArrayDepthTexture=s.useArrayDepthTexture}_setTextureOptions(t={}){const n={minFilter:Bn,generateMipmaps:!1,flipY:!1,internalFormat:null};t.mapping!==void 0&&(n.mapping=t.mapping),t.wrapS!==void 0&&(n.wrapS=t.wrapS),t.wrapT!==void 0&&(n.wrapT=t.wrapT),t.wrapR!==void 0&&(n.wrapR=t.wrapR),t.magFilter!==void 0&&(n.magFilter=t.magFilter),t.minFilter!==void 0&&(n.minFilter=t.minFilter),t.format!==void 0&&(n.format=t.format),t.type!==void 0&&(n.type=t.type),t.anisotropy!==void 0&&(n.anisotropy=t.anisotropy),t.colorSpace!==void 0&&(n.colorSpace=t.colorSpace),t.flipY!==void 0&&(n.flipY=t.flipY),t.generateMipmaps!==void 0&&(n.generateMipmaps=t.generateMipmaps),t.internalFormat!==void 0&&(n.internalFormat=t.internalFormat);for(let s=0;s<this.textures.length;s++)this.textures[s].setValues(n)}get texture(){return this.textures[0]}set texture(t){this.textures[0]=t}set depthTexture(t){this._depthTexture!==null&&(this._depthTexture.renderTarget=null),t!==null&&(t.renderTarget=this),this._depthTexture=t}get depthTexture(){return this._depthTexture}setSize(t,n,s=1){if(this.width!==t||this.height!==n||this.depth!==s){this.width=t,this.height=n,this.depth=s;for(let l=0,c=this.textures.length;l<c;l++)this.textures[l].image.width=t,this.textures[l].image.height=n,this.textures[l].image.depth=s,this.textures[l].isData3DTexture!==!0&&(this.textures[l].isArrayTexture=this.textures[l].image.depth>1);this.dispose()}this.viewport.set(0,0,t,n),this.scissor.set(0,0,t,n)}clone(){return new this.constructor().copy(this)}copy(t){this.width=t.width,this.height=t.height,this.depth=t.depth,this.scissor.copy(t.scissor),this.scissorTest=t.scissorTest,this.viewport.copy(t.viewport),this.textures.length=0;for(let n=0,s=t.textures.length;n<s;n++){this.textures[n]=t.textures[n].clone(),this.textures[n].isRenderTargetTexture=!0,this.textures[n].renderTarget=this;const l=Object.assign({},t.textures[n].image);this.textures[n].source=new dp(l)}return this.depthBuffer=t.depthBuffer,this.stencilBuffer=t.stencilBuffer,this.resolveDepthBuffer=t.resolveDepthBuffer,this.resolveStencilBuffer=t.resolveStencilBuffer,t.depthTexture!==null&&(this.depthTexture=t.depthTexture.clone()),this.samples=t.samples,this.multiview=t.multiview,this.useArrayDepthTexture=t.useArrayDepthTexture,this}dispose(){this.dispatchEvent({type:"dispose"})}}class Zi extends TM{constructor(t=1,n=1,s={}){super(t,n,s),this.isWebGLRenderTarget=!0}}class Q_ extends kn{constructor(t=null,n=1,s=1,l=1){super(null),this.isDataArrayTexture=!0,this.image={data:t,width:n,height:s,depth:l},this.magFilter=Ln,this.minFilter=Ln,this.wrapR=Ea,this.generateMipmaps=!1,this.flipY=!1,this.unpackAlignment=1,this.layerUpdates=new Set}addLayerUpdate(t){this.layerUpdates.add(t)}clearLayerUpdates(){this.layerUpdates.clear()}}class AM extends kn{constructor(t=null,n=1,s=1,l=1){super(null),this.isData3DTexture=!0,this.image={data:t,width:n,height:s,depth:l},this.magFilter=Ln,this.minFilter=Ln,this.wrapR=Ea,this.generateMipmaps=!1,this.flipY=!1,this.unpackAlignment=1}}const cu=class cu{constructor(t,n,s,l,c,f,d,m,p,v,_,g,y,b,w,M){this.elements=[1,0,0,0,0,1,0,0,0,0,1,0,0,0,0,1],t!==void 0&&this.set(t,n,s,l,c,f,d,m,p,v,_,g,y,b,w,M)}set(t,n,s,l,c,f,d,m,p,v,_,g,y,b,w,M){const S=this.elements;return S[0]=t,S[4]=n,S[8]=s,S[12]=l,S[1]=c,S[5]=f,S[9]=d,S[13]=m,S[2]=p,S[6]=v,S[10]=_,S[14]=g,S[3]=y,S[7]=b,S[11]=w,S[15]=M,this}identity(){return this.set(1,0,0,0,0,1,0,0,0,0,1,0,0,0,0,1),this}clone(){return new cu().fromArray(this.elements)}copy(t){const n=this.elements,s=t.elements;return n[0]=s[0],n[1]=s[1],n[2]=s[2],n[3]=s[3],n[4]=s[4],n[5]=s[5],n[6]=s[6],n[7]=s[7],n[8]=s[8],n[9]=s[9],n[10]=s[10],n[11]=s[11],n[12]=s[12],n[13]=s[13],n[14]=s[14],n[15]=s[15],this}copyPosition(t){const n=this.elements,s=t.elements;return n[12]=s[12],n[13]=s[13],n[14]=s[14],this}setFromMatrix3(t){const n=t.elements;return this.set(n[0],n[3],n[6],0,n[1],n[4],n[7],0,n[2],n[5],n[8],0,0,0,0,1),this}extractBasis(t,n,s){return this.determinantAffine()===0?(t.set(1,0,0),n.set(0,1,0),s.set(0,0,1),this):(t.setFromMatrixColumn(this,0),n.setFromMatrixColumn(this,1),s.setFromMatrixColumn(this,2),this)}makeBasis(t,n,s){return this.set(t.x,n.x,s.x,0,t.y,n.y,s.y,0,t.z,n.z,s.z,0,0,0,0,1),this}extractRotation(t){if(t.determinantAffine()===0)return this.identity();const n=this.elements,s=t.elements,l=1/Ar.setFromMatrixColumn(t,0).length(),c=1/Ar.setFromMatrixColumn(t,1).length(),f=1/Ar.setFromMatrixColumn(t,2).length();return n[0]=s[0]*l,n[1]=s[1]*l,n[2]=s[2]*l,n[3]=0,n[4]=s[4]*c,n[5]=s[5]*c,n[6]=s[6]*c,n[7]=0,n[8]=s[8]*f,n[9]=s[9]*f,n[10]=s[10]*f,n[11]=0,n[12]=0,n[13]=0,n[14]=0,n[15]=1,this}makeRotationFromEuler(t){const n=this.elements,s=t.x,l=t.y,c=t.z,f=Math.cos(s),d=Math.sin(s),m=Math.cos(l),p=Math.sin(l),v=Math.cos(c),_=Math.sin(c);if(t.order==="XYZ"){const g=f*v,y=f*_,b=d*v,w=d*_;n[0]=m*v,n[4]=-m*_,n[8]=p,n[1]=y+b*p,n[5]=g-w*p,n[9]=-d*m,n[2]=w-g*p,n[6]=b+y*p,n[10]=f*m}else if(t.order==="YXZ"){const g=m*v,y=m*_,b=p*v,w=p*_;n[0]=g+w*d,n[4]=b*d-y,n[8]=f*p,n[1]=f*_,n[5]=f*v,n[9]=-d,n[2]=y*d-b,n[6]=w+g*d,n[10]=f*m}else if(t.order==="ZXY"){const g=m*v,y=m*_,b=p*v,w=p*_;n[0]=g-w*d,n[4]=-f*_,n[8]=b+y*d,n[1]=y+b*d,n[5]=f*v,n[9]=w-g*d,n[2]=-f*p,n[6]=d,n[10]=f*m}else if(t.order==="ZYX"){const g=f*v,y=f*_,b=d*v,w=d*_;n[0]=m*v,n[4]=b*p-y,n[8]=g*p+w,n[1]=m*_,n[5]=w*p+g,n[9]=y*p-b,n[2]=-p,n[6]=d*m,n[10]=f*m}else if(t.order==="YZX"){const g=f*m,y=f*p,b=d*m,w=d*p;n[0]=m*v,n[4]=w-g*_,n[8]=b*_+y,n[1]=_,n[5]=f*v,n[9]=-d*v,n[2]=-p*v,n[6]=y*_+b,n[10]=g-w*_}else if(t.order==="XZY"){const g=f*m,y=f*p,b=d*m,w=d*p;n[0]=m*v,n[4]=-_,n[8]=p*v,n[1]=g*_+w,n[5]=f*v,n[9]=y*_-b,n[2]=b*_-y,n[6]=d*v,n[10]=w*_+g}return n[3]=0,n[7]=0,n[11]=0,n[12]=0,n[13]=0,n[14]=0,n[15]=1,this}makeRotationFromQuaternion(t){return this.compose(RM,t,CM)}lookAt(t,n,s){const l=this.elements;return ui.subVectors(t,n),ui.lengthSq()===0&&(ui.z=1),ui.normalize(),es.crossVectors(s,ui),es.lengthSq()===0&&(Math.abs(s.z)===1?ui.x+=1e-4:ui.z+=1e-4,ui.normalize(),es.crossVectors(s,ui)),es.normalize(),bc.crossVectors(ui,es),l[0]=es.x,l[4]=bc.x,l[8]=ui.x,l[1]=es.y,l[5]=bc.y,l[9]=ui.y,l[2]=es.z,l[6]=bc.z,l[10]=ui.z,this}multiply(t){return this.multiplyMatrices(this,t)}premultiply(t){return this.multiplyMatrices(t,this)}multiplyMatrices(t,n){const s=t.elements,l=n.elements,c=this.elements,f=s[0],d=s[4],m=s[8],p=s[12],v=s[1],_=s[5],g=s[9],y=s[13],b=s[2],w=s[6],M=s[10],S=s[14],P=s[3],D=s[7],A=s[11],F=s[15],O=l[0],I=l[4],T=l[8],N=l[12],X=l[1],V=l[5],q=l[9],ct=l[13],ht=l[2],j=l[6],B=l[10],H=l[14],$=l[3],dt=l[7],Mt=l[11],U=l[15];return c[0]=f*O+d*X+m*ht+p*$,c[4]=f*I+d*V+m*j+p*dt,c[8]=f*T+d*q+m*B+p*Mt,c[12]=f*N+d*ct+m*H+p*U,c[1]=v*O+_*X+g*ht+y*$,c[5]=v*I+_*V+g*j+y*dt,c[9]=v*T+_*q+g*B+y*Mt,c[13]=v*N+_*ct+g*H+y*U,c[2]=b*O+w*X+M*ht+S*$,c[6]=b*I+w*V+M*j+S*dt,c[10]=b*T+w*q+M*B+S*Mt,c[14]=b*N+w*ct+M*H+S*U,c[3]=P*O+D*X+A*ht+F*$,c[7]=P*I+D*V+A*j+F*dt,c[11]=P*T+D*q+A*B+F*Mt,c[15]=P*N+D*ct+A*H+F*U,this}multiplyScalar(t){const n=this.elements;return n[0]*=t,n[4]*=t,n[8]*=t,n[12]*=t,n[1]*=t,n[5]*=t,n[9]*=t,n[13]*=t,n[2]*=t,n[6]*=t,n[10]*=t,n[14]*=t,n[3]*=t,n[7]*=t,n[11]*=t,n[15]*=t,this}determinant(){const t=this.elements,n=t[0],s=t[4],l=t[8],c=t[12],f=t[1],d=t[5],m=t[9],p=t[13],v=t[2],_=t[6],g=t[10],y=t[14],b=t[3],w=t[7],M=t[11],S=t[15],P=m*y-p*g,D=d*y-p*_,A=d*g-m*_,F=f*y-p*v,O=f*g-m*v,I=f*_-d*v;return n*(w*P-M*D+S*A)-s*(b*P-M*F+S*O)+l*(b*D-w*F+S*I)-c*(b*A-w*O+M*I)}determinantAffine(){const t=this.elements,n=t[0],s=t[4],l=t[8],c=t[1],f=t[5],d=t[9],m=t[2],p=t[6],v=t[10];return n*(f*v-d*p)-s*(c*v-d*m)+l*(c*p-f*m)}transpose(){const t=this.elements;let n;return n=t[1],t[1]=t[4],t[4]=n,n=t[2],t[2]=t[8],t[8]=n,n=t[6],t[6]=t[9],t[9]=n,n=t[3],t[3]=t[12],t[12]=n,n=t[7],t[7]=t[13],t[13]=n,n=t[11],t[11]=t[14],t[14]=n,this}setPosition(t,n,s){const l=this.elements;return t.isVector3?(l[12]=t.x,l[13]=t.y,l[14]=t.z):(l[12]=t,l[13]=n,l[14]=s),this}invert(){const t=this.elements,n=t[0],s=t[1],l=t[2],c=t[3],f=t[4],d=t[5],m=t[6],p=t[7],v=t[8],_=t[9],g=t[10],y=t[11],b=t[12],w=t[13],M=t[14],S=t[15],P=n*d-s*f,D=n*m-l*f,A=n*p-c*f,F=s*m-l*d,O=s*p-c*d,I=l*p-c*m,T=v*w-_*b,N=v*M-g*b,X=v*S-y*b,V=_*M-g*w,q=_*S-y*w,ct=g*S-y*M,ht=P*ct-D*q+A*V+F*X-O*N+I*T;if(ht===0)return this.set(0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0);const j=1/ht;return t[0]=(d*ct-m*q+p*V)*j,t[1]=(l*q-s*ct-c*V)*j,t[2]=(w*I-M*O+S*F)*j,t[3]=(g*O-_*I-y*F)*j,t[4]=(m*X-f*ct-p*N)*j,t[5]=(n*ct-l*X+c*N)*j,t[6]=(M*A-b*I-S*D)*j,t[7]=(v*I-g*A+y*D)*j,t[8]=(f*q-d*X+p*T)*j,t[9]=(s*X-n*q-c*T)*j,t[10]=(b*O-w*A+S*P)*j,t[11]=(_*A-v*O-y*P)*j,t[12]=(d*N-f*V-m*T)*j,t[13]=(n*V-s*N+l*T)*j,t[14]=(w*D-b*F-M*P)*j,t[15]=(v*F-_*D+g*P)*j,this}scale(t){const n=this.elements,s=t.x,l=t.y,c=t.z;return n[0]*=s,n[4]*=l,n[8]*=c,n[1]*=s,n[5]*=l,n[9]*=c,n[2]*=s,n[6]*=l,n[10]*=c,n[3]*=s,n[7]*=l,n[11]*=c,this}getMaxScaleOnAxis(){const t=this.elements,n=t[0]*t[0]+t[1]*t[1]+t[2]*t[2],s=t[4]*t[4]+t[5]*t[5]+t[6]*t[6],l=t[8]*t[8]+t[9]*t[9]+t[10]*t[10];return Math.sqrt(Math.max(n,s,l))}makeTranslation(t,n,s){return t.isVector3?this.set(1,0,0,t.x,0,1,0,t.y,0,0,1,t.z,0,0,0,1):this.set(1,0,0,t,0,1,0,n,0,0,1,s,0,0,0,1),this}makeRotationX(t){const n=Math.cos(t),s=Math.sin(t);return this.set(1,0,0,0,0,n,-s,0,0,s,n,0,0,0,0,1),this}makeRotationY(t){const n=Math.cos(t),s=Math.sin(t);return this.set(n,0,s,0,0,1,0,0,-s,0,n,0,0,0,0,1),this}makeRotationZ(t){const n=Math.cos(t),s=Math.sin(t);return this.set(n,-s,0,0,s,n,0,0,0,0,1,0,0,0,0,1),this}makeRotationAxis(t,n){const s=Math.cos(n),l=Math.sin(n),c=1-s,f=t.x,d=t.y,m=t.z,p=c*f,v=c*d;return this.set(p*f+s,p*d-l*m,p*m+l*d,0,p*d+l*m,v*d+s,v*m-l*f,0,p*m-l*d,v*m+l*f,c*m*m+s,0,0,0,0,1),this}makeScale(t,n,s){return this.set(t,0,0,0,0,n,0,0,0,0,s,0,0,0,0,1),this}makeShear(t,n,s,l,c,f){return this.set(1,s,c,0,t,1,f,0,n,l,1,0,0,0,0,1),this}compose(t,n,s){const l=this.elements,c=n._x,f=n._y,d=n._z,m=n._w,p=c+c,v=f+f,_=d+d,g=c*p,y=c*v,b=c*_,w=f*v,M=f*_,S=d*_,P=m*p,D=m*v,A=m*_,F=s.x,O=s.y,I=s.z;return l[0]=(1-(w+S))*F,l[1]=(y+A)*F,l[2]=(b-D)*F,l[3]=0,l[4]=(y-A)*O,l[5]=(1-(g+S))*O,l[6]=(M+P)*O,l[7]=0,l[8]=(b+D)*I,l[9]=(M-P)*I,l[10]=(1-(g+w))*I,l[11]=0,l[12]=t.x,l[13]=t.y,l[14]=t.z,l[15]=1,this}decompose(t,n,s){const l=this.elements;t.x=l[12],t.y=l[13],t.z=l[14];const c=this.determinantAffine();if(c===0)return s.set(1,1,1),n.identity(),this;let f=Ar.set(l[0],l[1],l[2]).length();const d=Ar.set(l[4],l[5],l[6]).length(),m=Ar.set(l[8],l[9],l[10]).length();c<0&&(f=-f),Ni.copy(this);const p=1/f,v=1/d,_=1/m;return Ni.elements[0]*=p,Ni.elements[1]*=p,Ni.elements[2]*=p,Ni.elements[4]*=v,Ni.elements[5]*=v,Ni.elements[6]*=v,Ni.elements[8]*=_,Ni.elements[9]*=_,Ni.elements[10]*=_,n.setFromRotationMatrix(Ni),s.x=f,s.y=d,s.z=m,this}makePerspective(t,n,s,l,c,f,d=qi,m=!1){const p=this.elements,v=2*c/(n-t),_=2*c/(s-l),g=(n+t)/(n-t),y=(s+l)/(s-l);let b,w;if(m)b=c/(f-c),w=f*c/(f-c);else if(d===qi)b=-(f+c)/(f-c),w=-2*f*c/(f-c);else if(d===sl)b=-f/(f-c),w=-f*c/(f-c);else throw new Error("THREE.Matrix4.makePerspective(): Invalid coordinate system: "+d);return p[0]=v,p[4]=0,p[8]=g,p[12]=0,p[1]=0,p[5]=_,p[9]=y,p[13]=0,p[2]=0,p[6]=0,p[10]=b,p[14]=w,p[3]=0,p[7]=0,p[11]=-1,p[15]=0,this}makeOrthographic(t,n,s,l,c,f,d=qi,m=!1){const p=this.elements,v=2/(n-t),_=2/(s-l),g=-(n+t)/(n-t),y=-(s+l)/(s-l);let b,w;if(m)b=1/(f-c),w=f/(f-c);else if(d===qi)b=-2/(f-c),w=-(f+c)/(f-c);else if(d===sl)b=-1/(f-c),w=-c/(f-c);else throw new Error("THREE.Matrix4.makeOrthographic(): Invalid coordinate system: "+d);return p[0]=v,p[4]=0,p[8]=0,p[12]=g,p[1]=0,p[5]=_,p[9]=0,p[13]=y,p[2]=0,p[6]=0,p[10]=b,p[14]=w,p[3]=0,p[7]=0,p[11]=0,p[15]=1,this}equals(t){const n=this.elements,s=t.elements;for(let l=0;l<16;l++)if(n[l]!==s[l])return!1;return!0}fromArray(t,n=0){for(let s=0;s<16;s++)this.elements[s]=t[s+n];return this}toArray(t=[],n=0){const s=this.elements;return t[n]=s[0],t[n+1]=s[1],t[n+2]=s[2],t[n+3]=s[3],t[n+4]=s[4],t[n+5]=s[5],t[n+6]=s[6],t[n+7]=s[7],t[n+8]=s[8],t[n+9]=s[9],t[n+10]=s[10],t[n+11]=s[11],t[n+12]=s[12],t[n+13]=s[13],t[n+14]=s[14],t[n+15]=s[15],t}};cu.prototype.isMatrix4=!0;let en=cu;const Ar=new K,Ni=new en,RM=new K(0,0,0),CM=new K(1,1,1),es=new K,bc=new K,ui=new K,Cv=new en,wv=new Zr;class fs{constructor(t=0,n=0,s=0,l=fs.DEFAULT_ORDER){this.isEuler=!0,this._x=t,this._y=n,this._z=s,this._order=l}get x(){return this._x}set x(t){this._x=t,this._onChangeCallback()}get y(){return this._y}set y(t){this._y=t,this._onChangeCallback()}get z(){return this._z}set z(t){this._z=t,this._onChangeCallback()}get order(){return this._order}set order(t){this._order=t,this._onChangeCallback()}set(t,n,s,l=this._order){return this._x=t,this._y=n,this._z=s,this._order=l,this._onChangeCallback(),this}clone(){return new this.constructor(this._x,this._y,this._z,this._order)}copy(t){return this._x=t._x,this._y=t._y,this._z=t._z,this._order=t._order,this._onChangeCallback(),this}setFromRotationMatrix(t,n=this._order,s=!0){const l=t.elements,c=l[0],f=l[4],d=l[8],m=l[1],p=l[5],v=l[9],_=l[2],g=l[6],y=l[10];switch(n){case"XYZ":this._y=Math.asin(ve(d,-1,1)),Math.abs(d)<.9999999?(this._x=Math.atan2(-v,y),this._z=Math.atan2(-f,c)):(this._x=Math.atan2(g,p),this._z=0);break;case"YXZ":this._x=Math.asin(-ve(v,-1,1)),Math.abs(v)<.9999999?(this._y=Math.atan2(d,y),this._z=Math.atan2(m,p)):(this._y=Math.atan2(-_,c),this._z=0);break;case"ZXY":this._x=Math.asin(ve(g,-1,1)),Math.abs(g)<.9999999?(this._y=Math.atan2(-_,y),this._z=Math.atan2(-f,p)):(this._y=0,this._z=Math.atan2(m,c));break;case"ZYX":this._y=Math.asin(-ve(_,-1,1)),Math.abs(_)<.9999999?(this._x=Math.atan2(g,y),this._z=Math.atan2(m,c)):(this._x=0,this._z=Math.atan2(-f,p));break;case"YZX":this._z=Math.asin(ve(m,-1,1)),Math.abs(m)<.9999999?(this._x=Math.atan2(-v,p),this._y=Math.atan2(-_,c)):(this._x=0,this._y=Math.atan2(d,y));break;case"XZY":this._z=Math.asin(-ve(f,-1,1)),Math.abs(f)<.9999999?(this._x=Math.atan2(g,p),this._y=Math.atan2(d,c)):(this._x=Math.atan2(-v,y),this._y=0);break;default:ie("Euler: .setFromRotationMatrix() encountered an unknown order: "+n)}return this._order=n,s===!0&&this._onChangeCallback(),this}setFromQuaternion(t,n,s){return Cv.makeRotationFromQuaternion(t),this.setFromRotationMatrix(Cv,n,s)}setFromVector3(t,n=this._order){return this.set(t.x,t.y,t.z,n)}reorder(t){return wv.setFromEuler(this),this.setFromQuaternion(wv,t)}equals(t){return t._x===this._x&&t._y===this._y&&t._z===this._z&&t._order===this._order}fromArray(t){return this._x=t[0],this._y=t[1],this._z=t[2],t[3]!==void 0&&(this._order=t[3]),this._onChangeCallback(),this}toArray(t=[],n=0){return t[n]=this._x,t[n+1]=this._y,t[n+2]=this._z,t[n+3]=this._order,t}_onChange(t){return this._onChangeCallback=t,this}_onChangeCallback(){}*[Symbol.iterator](){yield this._x,yield this._y,yield this._z,yield this._order}}fs.DEFAULT_ORDER="XYZ";class $_{constructor(){this.mask=1}set(t){this.mask=(1<<t|0)>>>0}enable(t){this.mask|=1<<t|0}enableAll(){this.mask=-1}toggle(t){this.mask^=1<<t|0}disable(t){this.mask&=~(1<<t|0)}disableAll(){this.mask=0}test(t){return(this.mask&t.mask)!==0}isEnabled(t){return(this.mask&(1<<t|0))!==0}}let wM=0;const Dv=new K,Rr=new Zr,va=new en,Tc=new K,Xo=new K,DM=new K,NM=new Zr,Nv=new K(1,0,0),Uv=new K(0,1,0),Lv=new K(0,0,1),Ov={type:"added"},UM={type:"removed"},Cr={type:"childadded",child:null},Lh={type:"childremoved",child:null};class On extends Ws{constructor(){super(),this.isObject3D=!0,Object.defineProperty(this,"id",{value:wM++}),this.uuid=Yr(),this.name="",this.type="Object3D",this.parent=null,this.children=[],this.up=On.DEFAULT_UP.clone();const t=new K,n=new fs,s=new Zr,l=new K(1,1,1);function c(){s.setFromEuler(n,!1)}function f(){n.setFromQuaternion(s,void 0,!1)}n._onChange(c),s._onChange(f),Object.defineProperties(this,{position:{configurable:!0,enumerable:!0,value:t},rotation:{configurable:!0,enumerable:!0,value:n},quaternion:{configurable:!0,enumerable:!0,value:s},scale:{configurable:!0,enumerable:!0,value:l},modelViewMatrix:{value:new en},normalMatrix:{value:new re}}),this.matrix=new en,this.matrixWorld=new en,this.matrixAutoUpdate=On.DEFAULT_MATRIX_AUTO_UPDATE,this.matrixWorldAutoUpdate=On.DEFAULT_MATRIX_WORLD_AUTO_UPDATE,this.matrixWorldNeedsUpdate=!1,this.layers=new $_,this.visible=!0,this.castShadow=!1,this.receiveShadow=!1,this.frustumCulled=!0,this.renderOrder=0,this.animations=[],this.customDepthMaterial=void 0,this.customDistanceMaterial=void 0,this.static=!1,this.userData={},this.pivot=null}onBeforeShadow(){}onAfterShadow(){}onBeforeRender(){}onAfterRender(){}applyMatrix4(t){this.matrixAutoUpdate&&this.updateMatrix(),this.matrix.premultiply(t),this.matrix.decompose(this.position,this.quaternion,this.scale)}applyQuaternion(t){return this.quaternion.premultiply(t),this}setRotationFromAxisAngle(t,n){this.quaternion.setFromAxisAngle(t,n)}setRotationFromEuler(t){this.quaternion.setFromEuler(t,!0)}setRotationFromMatrix(t){this.quaternion.setFromRotationMatrix(t)}setRotationFromQuaternion(t){this.quaternion.copy(t)}rotateOnAxis(t,n){return Rr.setFromAxisAngle(t,n),this.quaternion.multiply(Rr),this}rotateOnWorldAxis(t,n){return Rr.setFromAxisAngle(t,n),this.quaternion.premultiply(Rr),this}rotateX(t){return this.rotateOnAxis(Nv,t)}rotateY(t){return this.rotateOnAxis(Uv,t)}rotateZ(t){return this.rotateOnAxis(Lv,t)}translateOnAxis(t,n){return Dv.copy(t).applyQuaternion(this.quaternion),this.position.add(Dv.multiplyScalar(n)),this}translateX(t){return this.translateOnAxis(Nv,t)}translateY(t){return this.translateOnAxis(Uv,t)}translateZ(t){return this.translateOnAxis(Lv,t)}localToWorld(t){return this.updateWorldMatrix(!0,!1),t.applyMatrix4(this.matrixWorld)}worldToLocal(t){return this.updateWorldMatrix(!0,!1),t.applyMatrix4(va.copy(this.matrixWorld).invert())}lookAt(t,n,s){t.isVector3?Tc.copy(t):Tc.set(t,n,s);const l=this.parent;this.updateWorldMatrix(!0,!1),Xo.setFromMatrixPosition(this.matrixWorld),this.isCamera||this.isLight?va.lookAt(Xo,Tc,this.up):va.lookAt(Tc,Xo,this.up),this.quaternion.setFromRotationMatrix(va),l&&(va.extractRotation(l.matrixWorld),Rr.setFromRotationMatrix(va),this.quaternion.premultiply(Rr.invert()))}add(t){if(arguments.length>1){for(let n=0;n<arguments.length;n++)this.add(arguments[n]);return this}return t===this?(be("Object3D.add: object can't be added as a child of itself.",t),this):(t&&t.isObject3D?(t.removeFromParent(),t.parent=this,this.children.push(t),t.dispatchEvent(Ov),Cr.child=t,this.dispatchEvent(Cr),Cr.child=null):be("Object3D.add: object not an instance of THREE.Object3D.",t),this)}remove(t){if(arguments.length>1){for(let s=0;s<arguments.length;s++)this.remove(arguments[s]);return this}const n=this.children.indexOf(t);return n!==-1&&(t.parent=null,this.children.splice(n,1),t.dispatchEvent(UM),Lh.child=t,this.dispatchEvent(Lh),Lh.child=null),this}removeFromParent(){const t=this.parent;return t!==null&&t.remove(this),this}clear(){return this.remove(...this.children)}attach(t){return this.updateWorldMatrix(!0,!1),va.copy(this.matrixWorld).invert(),t.parent!==null&&(t.parent.updateWorldMatrix(!0,!1),va.multiply(t.parent.matrixWorld)),t.applyMatrix4(va),t.removeFromParent(),t.parent=this,this.children.push(t),t.updateWorldMatrix(!1,!0),t.dispatchEvent(Ov),Cr.child=t,this.dispatchEvent(Cr),Cr.child=null,this}getObjectById(t){return this.getObjectByProperty("id",t)}getObjectByName(t){return this.getObjectByProperty("name",t)}getObjectByProperty(t,n){if(this[t]===n)return this;for(let s=0,l=this.children.length;s<l;s++){const f=this.children[s].getObjectByProperty(t,n);if(f!==void 0)return f}}getObjectsByProperty(t,n,s=[]){this[t]===n&&s.push(this);const l=this.children;for(let c=0,f=l.length;c<f;c++)l[c].getObjectsByProperty(t,n,s);return s}getWorldPosition(t){return this.updateWorldMatrix(!0,!1),t.setFromMatrixPosition(this.matrixWorld)}getWorldQuaternion(t){return this.updateWorldMatrix(!0,!1),this.matrixWorld.decompose(Xo,t,DM),t}getWorldScale(t){return this.updateWorldMatrix(!0,!1),this.matrixWorld.decompose(Xo,NM,t),t}getWorldDirection(t){this.updateWorldMatrix(!0,!1);const n=this.matrixWorld.elements;return t.set(n[8],n[9],n[10]).normalize()}raycast(){}traverse(t){t(this);const n=this.children;for(let s=0,l=n.length;s<l;s++)n[s].traverse(t)}traverseVisible(t){if(this.visible===!1)return;t(this);const n=this.children;for(let s=0,l=n.length;s<l;s++)n[s].traverseVisible(t)}traverseAncestors(t){const n=this.parent;n!==null&&(t(n),n.traverseAncestors(t))}updateMatrix(){this.matrix.compose(this.position,this.quaternion,this.scale);const t=this.pivot;if(t!==null){const n=t.x,s=t.y,l=t.z,c=this.matrix.elements;c[12]+=n-c[0]*n-c[4]*s-c[8]*l,c[13]+=s-c[1]*n-c[5]*s-c[9]*l,c[14]+=l-c[2]*n-c[6]*s-c[10]*l}this.matrixWorldNeedsUpdate=!0}updateMatrixWorld(t){this.matrixAutoUpdate&&this.updateMatrix(),(this.matrixWorldNeedsUpdate||t)&&(this.matrixWorldAutoUpdate===!0&&(this.parent===null?this.matrixWorld.copy(this.matrix):this.matrixWorld.multiplyMatrices(this.parent.matrixWorld,this.matrix)),this.matrixWorldNeedsUpdate=!1,t=!0);const n=this.children;for(let s=0,l=n.length;s<l;s++)n[s].updateMatrixWorld(t)}updateWorldMatrix(t,n,s=!1){const l=this.parent;if(t===!0&&l!==null&&l.updateWorldMatrix(!0,!1),this.matrixAutoUpdate&&this.updateMatrix(),(this.matrixWorldNeedsUpdate||s)&&(this.matrixWorldAutoUpdate===!0&&(this.parent===null?this.matrixWorld.copy(this.matrix):this.matrixWorld.multiplyMatrices(this.parent.matrixWorld,this.matrix)),this.matrixWorldNeedsUpdate=!1,s=!0),n===!0){const c=this.children;for(let f=0,d=c.length;f<d;f++)c[f].updateWorldMatrix(!1,!0,s)}}toJSON(t){const n=t===void 0||typeof t=="string",s={};n&&(t={geometries:{},materials:{},textures:{},images:{},shapes:{},skeletons:{},animations:{},nodes:{}},s.metadata={version:4.7,type:"Object",generator:"Object3D.toJSON"});const l={};l.uuid=this.uuid,l.type=this.type,this.name!==""&&(l.name=this.name),this.castShadow===!0&&(l.castShadow=!0),this.receiveShadow===!0&&(l.receiveShadow=!0),this.visible===!1&&(l.visible=!1),this.frustumCulled===!1&&(l.frustumCulled=!1),this.renderOrder!==0&&(l.renderOrder=this.renderOrder),this.static!==!1&&(l.static=this.static),Object.keys(this.userData).length>0&&(l.userData=this.userData),l.layers=this.layers.mask,l.matrix=this.matrix.toArray(),l.up=this.up.toArray(),this.pivot!==null&&(l.pivot=this.pivot.toArray()),this.matrixAutoUpdate===!1&&(l.matrixAutoUpdate=!1),this.morphTargetDictionary!==void 0&&(l.morphTargetDictionary=Object.assign({},this.morphTargetDictionary)),this.morphTargetInfluences!==void 0&&(l.morphTargetInfluences=this.morphTargetInfluences.slice()),this.isInstancedMesh&&(l.type="InstancedMesh",l.count=this.count,l.instanceMatrix=this.instanceMatrix.toJSON(),this.instanceColor!==null&&(l.instanceColor=this.instanceColor.toJSON())),this.isBatchedMesh&&(l.type="BatchedMesh",l.perObjectFrustumCulled=this.perObjectFrustumCulled,l.sortObjects=this.sortObjects,l.drawRanges=this._drawRanges,l.reservedRanges=this._reservedRanges,l.geometryInfo=this._geometryInfo.map(d=>({...d,boundingBox:d.boundingBox?d.boundingBox.toJSON():void 0,boundingSphere:d.boundingSphere?d.boundingSphere.toJSON():void 0})),l.instanceInfo=this._instanceInfo.map(d=>({...d})),l.availableInstanceIds=this._availableInstanceIds.slice(),l.availableGeometryIds=this._availableGeometryIds.slice(),l.nextIndexStart=this._nextIndexStart,l.nextVertexStart=this._nextVertexStart,l.geometryCount=this._geometryCount,l.maxInstanceCount=this._maxInstanceCount,l.maxVertexCount=this._maxVertexCount,l.maxIndexCount=this._maxIndexCount,l.geometryInitialized=this._geometryInitialized,l.matricesTexture=this._matricesTexture.toJSON(t),l.indirectTexture=this._indirectTexture.toJSON(t),this._colorsTexture!==null&&(l.colorsTexture=this._colorsTexture.toJSON(t)),this.boundingSphere!==null&&(l.boundingSphere=this.boundingSphere.toJSON()),this.boundingBox!==null&&(l.boundingBox=this.boundingBox.toJSON()));function c(d,m){return d[m.uuid]===void 0&&(d[m.uuid]=m.toJSON(t)),m.uuid}if(this.isScene)this.background&&(this.background.isColor?l.background=this.background.toJSON():this.background.isTexture&&(l.background=this.background.toJSON(t).uuid)),this.environment&&this.environment.isTexture&&this.environment.isRenderTargetTexture!==!0&&(l.environment=this.environment.toJSON(t).uuid);else if(this.isMesh||this.isLine||this.isPoints){l.geometry=c(t.geometries,this.geometry);const d=this.geometry.parameters;if(d!==void 0&&d.shapes!==void 0){const m=d.shapes;if(Array.isArray(m))for(let p=0,v=m.length;p<v;p++){const _=m[p];c(t.shapes,_)}else c(t.shapes,m)}}if(this.isSkinnedMesh&&(l.bindMode=this.bindMode,l.bindMatrix=this.bindMatrix.toArray(),this.skeleton!==void 0&&(c(t.skeletons,this.skeleton),l.skeleton=this.skeleton.uuid)),this.material!==void 0)if(Array.isArray(this.material)){const d=[];for(let m=0,p=this.material.length;m<p;m++)d.push(c(t.materials,this.material[m]));l.material=d}else l.material=c(t.materials,this.material);if(this.children.length>0){l.children=[];for(let d=0;d<this.children.length;d++)l.children.push(this.children[d].toJSON(t).object)}if(this.animations.length>0){l.animations=[];for(let d=0;d<this.animations.length;d++){const m=this.animations[d];l.animations.push(c(t.animations,m))}}if(n){const d=f(t.geometries),m=f(t.materials),p=f(t.textures),v=f(t.images),_=f(t.shapes),g=f(t.skeletons),y=f(t.animations),b=f(t.nodes);d.length>0&&(s.geometries=d),m.length>0&&(s.materials=m),p.length>0&&(s.textures=p),v.length>0&&(s.images=v),_.length>0&&(s.shapes=_),g.length>0&&(s.skeletons=g),y.length>0&&(s.animations=y),b.length>0&&(s.nodes=b)}return s.object=l,s;function f(d){const m=[];for(const p in d){const v=d[p];delete v.metadata,m.push(v)}return m}}clone(t){return new this.constructor().copy(this,t)}copy(t,n=!0){if(this.name=t.name,this.up.copy(t.up),this.position.copy(t.position),this.rotation.order=t.rotation.order,this.quaternion.copy(t.quaternion),this.scale.copy(t.scale),this.pivot=t.pivot!==null?t.pivot.clone():null,this.matrix.copy(t.matrix),this.matrixWorld.copy(t.matrixWorld),this.matrixAutoUpdate=t.matrixAutoUpdate,this.matrixWorldAutoUpdate=t.matrixWorldAutoUpdate,this.matrixWorldNeedsUpdate=t.matrixWorldNeedsUpdate,this.layers.mask=t.layers.mask,this.visible=t.visible,this.castShadow=t.castShadow,this.receiveShadow=t.receiveShadow,this.frustumCulled=t.frustumCulled,this.renderOrder=t.renderOrder,this.static=t.static,this.animations=t.animations.slice(),this.userData=JSON.parse(JSON.stringify(t.userData)),n===!0)for(let s=0;s<t.children.length;s++){const l=t.children[s];this.add(l.clone())}return this}}On.DEFAULT_UP=new K(0,1,0);On.DEFAULT_MATRIX_AUTO_UPDATE=!0;On.DEFAULT_MATRIX_WORLD_AUTO_UPDATE=!0;class Fr extends On{constructor(){super(),this.isGroup=!0,this.type="Group"}}const LM={type:"move"};class Oh{constructor(){this._targetRay=null,this._grip=null,this._hand=null}getHandSpace(){return this._hand===null&&(this._hand=new Fr,this._hand.matrixAutoUpdate=!1,this._hand.visible=!1,this._hand.joints={},this._hand.inputState={pinching:!1}),this._hand}getTargetRaySpace(){return this._targetRay===null&&(this._targetRay=new Fr,this._targetRay.matrixAutoUpdate=!1,this._targetRay.visible=!1,this._targetRay.hasLinearVelocity=!1,this._targetRay.linearVelocity=new K,this._targetRay.hasAngularVelocity=!1,this._targetRay.angularVelocity=new K),this._targetRay}getGripSpace(){return this._grip===null&&(this._grip=new Fr,this._grip.matrixAutoUpdate=!1,this._grip.visible=!1,this._grip.hasLinearVelocity=!1,this._grip.linearVelocity=new K,this._grip.hasAngularVelocity=!1,this._grip.angularVelocity=new K,this._grip.eventsEnabled=!1),this._grip}dispatchEvent(t){return this._targetRay!==null&&this._targetRay.dispatchEvent(t),this._grip!==null&&this._grip.dispatchEvent(t),this._hand!==null&&this._hand.dispatchEvent(t),this}connect(t){if(t&&t.hand){const n=this._hand;if(n)for(const s of t.hand.values())this._getHandJoint(n,s)}return this.dispatchEvent({type:"connected",data:t}),this}disconnect(t){return this.dispatchEvent({type:"disconnected",data:t}),this._targetRay!==null&&(this._targetRay.visible=!1),this._grip!==null&&(this._grip.visible=!1),this._hand!==null&&(this._hand.visible=!1),this}update(t,n,s){let l=null,c=null,f=null;const d=this._targetRay,m=this._grip,p=this._hand;if(t&&n.session.visibilityState!=="visible-blurred"){if(p&&t.hand){f=!0;for(const w of t.hand.values()){const M=n.getJointPose(w,s),S=this._getHandJoint(p,w);M!==null&&(S.matrix.fromArray(M.transform.matrix),S.matrix.decompose(S.position,S.rotation,S.scale),S.matrixWorldNeedsUpdate=!0,S.jointRadius=M.radius),S.visible=M!==null}const v=p.joints["index-finger-tip"],_=p.joints["thumb-tip"],g=v.position.distanceTo(_.position),y=.02,b=.005;p.inputState.pinching&&g>y+b?(p.inputState.pinching=!1,this.dispatchEvent({type:"pinchend",handedness:t.handedness,target:this})):!p.inputState.pinching&&g<=y-b&&(p.inputState.pinching=!0,this.dispatchEvent({type:"pinchstart",handedness:t.handedness,target:this}))}else m!==null&&t.gripSpace&&(c=n.getPose(t.gripSpace,s),c!==null&&(m.matrix.fromArray(c.transform.matrix),m.matrix.decompose(m.position,m.rotation,m.scale),m.matrixWorldNeedsUpdate=!0,c.linearVelocity?(m.hasLinearVelocity=!0,m.linearVelocity.copy(c.linearVelocity)):m.hasLinearVelocity=!1,c.angularVelocity?(m.hasAngularVelocity=!0,m.angularVelocity.copy(c.angularVelocity)):m.hasAngularVelocity=!1,m.eventsEnabled&&m.dispatchEvent({type:"gripUpdated",data:t,target:this})));d!==null&&(l=n.getPose(t.targetRaySpace,s),l===null&&c!==null&&(l=c),l!==null&&(d.matrix.fromArray(l.transform.matrix),d.matrix.decompose(d.position,d.rotation,d.scale),d.matrixWorldNeedsUpdate=!0,l.linearVelocity?(d.hasLinearVelocity=!0,d.linearVelocity.copy(l.linearVelocity)):d.hasLinearVelocity=!1,l.angularVelocity?(d.hasAngularVelocity=!0,d.angularVelocity.copy(l.angularVelocity)):d.hasAngularVelocity=!1,this.dispatchEvent(LM)))}return d!==null&&(d.visible=l!==null),m!==null&&(m.visible=c!==null),p!==null&&(p.visible=f!==null),this}_getHandJoint(t,n){if(t.joints[n.jointName]===void 0){const s=new Fr;s.matrixAutoUpdate=!1,s.visible=!1,t.joints[n.jointName]=s,t.add(s)}return t.joints[n.jointName]}}const tx={aliceblue:15792383,antiquewhite:16444375,aqua:65535,aquamarine:8388564,azure:15794175,beige:16119260,bisque:16770244,black:0,blanchedalmond:16772045,blue:255,blueviolet:9055202,brown:10824234,burlywood:14596231,cadetblue:6266528,chartreuse:8388352,chocolate:13789470,coral:16744272,cornflowerblue:6591981,cornsilk:16775388,crimson:14423100,cyan:65535,darkblue:139,darkcyan:35723,darkgoldenrod:12092939,darkgray:11119017,darkgreen:25600,darkgrey:11119017,darkkhaki:12433259,darkmagenta:9109643,darkolivegreen:5597999,darkorange:16747520,darkorchid:10040012,darkred:9109504,darksalmon:15308410,darkseagreen:9419919,darkslateblue:4734347,darkslategray:3100495,darkslategrey:3100495,darkturquoise:52945,darkviolet:9699539,deeppink:16716947,deepskyblue:49151,dimgray:6908265,dimgrey:6908265,dodgerblue:2003199,firebrick:11674146,floralwhite:16775920,forestgreen:2263842,fuchsia:16711935,gainsboro:14474460,ghostwhite:16316671,gold:16766720,goldenrod:14329120,gray:8421504,green:32768,greenyellow:11403055,grey:8421504,honeydew:15794160,hotpink:16738740,indianred:13458524,indigo:4915330,ivory:16777200,khaki:15787660,lavender:15132410,lavenderblush:16773365,lawngreen:8190976,lemonchiffon:16775885,lightblue:11393254,lightcoral:15761536,lightcyan:14745599,lightgoldenrodyellow:16448210,lightgray:13882323,lightgreen:9498256,lightgrey:13882323,lightpink:16758465,lightsalmon:16752762,lightseagreen:2142890,lightskyblue:8900346,lightslategray:7833753,lightslategrey:7833753,lightsteelblue:11584734,lightyellow:16777184,lime:65280,limegreen:3329330,linen:16445670,magenta:16711935,maroon:8388608,mediumaquamarine:6737322,mediumblue:205,mediumorchid:12211667,mediumpurple:9662683,mediumseagreen:3978097,mediumslateblue:8087790,mediumspringgreen:64154,mediumturquoise:4772300,mediumvioletred:13047173,midnightblue:1644912,mintcream:16121850,mistyrose:16770273,moccasin:16770229,navajowhite:16768685,navy:128,oldlace:16643558,olive:8421376,olivedrab:7048739,orange:16753920,orangered:16729344,orchid:14315734,palegoldenrod:15657130,palegreen:10025880,paleturquoise:11529966,palevioletred:14381203,papayawhip:16773077,peachpuff:16767673,peru:13468991,pink:16761035,plum:14524637,powderblue:11591910,purple:8388736,rebeccapurple:6697881,red:16711680,rosybrown:12357519,royalblue:4286945,saddlebrown:9127187,salmon:16416882,sandybrown:16032864,seagreen:3050327,seashell:16774638,sienna:10506797,silver:12632256,skyblue:8900331,slateblue:6970061,slategray:7372944,slategrey:7372944,snow:16775930,springgreen:65407,steelblue:4620980,tan:13808780,teal:32896,thistle:14204888,tomato:16737095,turquoise:4251856,violet:15631086,wheat:16113331,white:16777215,whitesmoke:16119285,yellow:16776960,yellowgreen:10145074},ns={h:0,s:0,l:0},Ac={h:0,s:0,l:0};function Ph(r,t,n){return n<0&&(n+=1),n>1&&(n-=1),n<1/6?r+(t-r)*6*n:n<1/2?t:n<2/3?r+(t-r)*6*(2/3-n):r}class fe{constructor(t,n,s){return this.isColor=!0,this.r=1,this.g=1,this.b=1,this.set(t,n,s)}set(t,n,s){if(n===void 0&&s===void 0){const l=t;l&&l.isColor?this.copy(l):typeof l=="number"?this.setHex(l):typeof l=="string"&&this.setStyle(l)}else this.setRGB(t,n,s);return this}setScalar(t){return this.r=t,this.g=t,this.b=t,this}setHex(t,n=hi){return t=Math.floor(t),this.r=(t>>16&255)/255,this.g=(t>>8&255)/255,this.b=(t&255)/255,Ee.colorSpaceToWorking(this,n),this}setRGB(t,n,s,l=Ee.workingColorSpace){return this.r=t,this.g=n,this.b=s,Ee.colorSpaceToWorking(this,l),this}setHSL(t,n,s,l=Ee.workingColorSpace){if(t=SM(t,1),n=ve(n,0,1),s=ve(s,0,1),n===0)this.r=this.g=this.b=s;else{const c=s<=.5?s*(1+n):s+n-s*n,f=2*s-c;this.r=Ph(f,c,t+1/3),this.g=Ph(f,c,t),this.b=Ph(f,c,t-1/3)}return Ee.colorSpaceToWorking(this,l),this}setStyle(t,n=hi){function s(c){c!==void 0&&parseFloat(c)<1&&ie("Color: Alpha component of "+t+" will be ignored.")}let l;if(l=/^(\w+)\(([^\)]*)\)/.exec(t)){let c;const f=l[1],d=l[2];switch(f){case"rgb":case"rgba":if(c=/^\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*(?:,\s*(\d*\.?\d+)\s*)?$/.exec(d))return s(c[4]),this.setRGB(Math.min(255,parseInt(c[1],10))/255,Math.min(255,parseInt(c[2],10))/255,Math.min(255,parseInt(c[3],10))/255,n);if(c=/^\s*(\d+)\%\s*,\s*(\d+)\%\s*,\s*(\d+)\%\s*(?:,\s*(\d*\.?\d+)\s*)?$/.exec(d))return s(c[4]),this.setRGB(Math.min(100,parseInt(c[1],10))/100,Math.min(100,parseInt(c[2],10))/100,Math.min(100,parseInt(c[3],10))/100,n);break;case"hsl":case"hsla":if(c=/^\s*(\d*\.?\d+)\s*,\s*(\d*\.?\d+)\%\s*,\s*(\d*\.?\d+)\%\s*(?:,\s*(\d*\.?\d+)\s*)?$/.exec(d))return s(c[4]),this.setHSL(parseFloat(c[1])/360,parseFloat(c[2])/100,parseFloat(c[3])/100,n);break;default:ie("Color: Unknown color model "+t)}}else if(l=/^\#([A-Fa-f\d]+)$/.exec(t)){const c=l[1],f=c.length;if(f===3)return this.setRGB(parseInt(c.charAt(0),16)/15,parseInt(c.charAt(1),16)/15,parseInt(c.charAt(2),16)/15,n);if(f===6)return this.setHex(parseInt(c,16),n);ie("Color: Invalid hex color "+t)}else if(t&&t.length>0)return this.setColorName(t,n);return this}setColorName(t,n=hi){const s=tx[t.toLowerCase()];return s!==void 0?this.setHex(s,n):ie("Color: Unknown color "+t),this}clone(){return new this.constructor(this.r,this.g,this.b)}copy(t){return this.r=t.r,this.g=t.g,this.b=t.b,this}copySRGBToLinear(t){return this.r=Ta(t.r),this.g=Ta(t.g),this.b=Ta(t.b),this}copyLinearToSRGB(t){return this.r=Gr(t.r),this.g=Gr(t.g),this.b=Gr(t.b),this}convertSRGBToLinear(){return this.copySRGBToLinear(this),this}convertLinearToSRGB(){return this.copyLinearToSRGB(this),this}getHex(t=hi){return Ee.workingToColorSpace(Fn.copy(this),t),Math.round(ve(Fn.r*255,0,255))*65536+Math.round(ve(Fn.g*255,0,255))*256+Math.round(ve(Fn.b*255,0,255))}getHexString(t=hi){return("000000"+this.getHex(t).toString(16)).slice(-6)}getHSL(t,n=Ee.workingColorSpace){Ee.workingToColorSpace(Fn.copy(this),n);const s=Fn.r,l=Fn.g,c=Fn.b,f=Math.max(s,l,c),d=Math.min(s,l,c);let m,p;const v=(d+f)/2;if(d===f)m=0,p=0;else{const _=f-d;switch(p=v<=.5?_/(f+d):_/(2-f-d),f){case s:m=(l-c)/_+(l<c?6:0);break;case l:m=(c-s)/_+2;break;case c:m=(s-l)/_+4;break}m/=6}return t.h=m,t.s=p,t.l=v,t}getRGB(t,n=Ee.workingColorSpace){return Ee.workingToColorSpace(Fn.copy(this),n),t.r=Fn.r,t.g=Fn.g,t.b=Fn.b,t}getStyle(t=hi){Ee.workingToColorSpace(Fn.copy(this),t);const n=Fn.r,s=Fn.g,l=Fn.b;return t!==hi?`color(${t} ${n.toFixed(3)} ${s.toFixed(3)} ${l.toFixed(3)})`:`rgb(${Math.round(n*255)},${Math.round(s*255)},${Math.round(l*255)})`}offsetHSL(t,n,s){return this.getHSL(ns),this.setHSL(ns.h+t,ns.s+n,ns.l+s)}add(t){return this.r+=t.r,this.g+=t.g,this.b+=t.b,this}addColors(t,n){return this.r=t.r+n.r,this.g=t.g+n.g,this.b=t.b+n.b,this}addScalar(t){return this.r+=t,this.g+=t,this.b+=t,this}sub(t){return this.r=Math.max(0,this.r-t.r),this.g=Math.max(0,this.g-t.g),this.b=Math.max(0,this.b-t.b),this}multiply(t){return this.r*=t.r,this.g*=t.g,this.b*=t.b,this}multiplyScalar(t){return this.r*=t,this.g*=t,this.b*=t,this}lerp(t,n){return this.r+=(t.r-this.r)*n,this.g+=(t.g-this.g)*n,this.b+=(t.b-this.b)*n,this}lerpColors(t,n,s){return this.r=t.r+(n.r-t.r)*s,this.g=t.g+(n.g-t.g)*s,this.b=t.b+(n.b-t.b)*s,this}lerpHSL(t,n){this.getHSL(ns),t.getHSL(Ac);const s=Ch(ns.h,Ac.h,n),l=Ch(ns.s,Ac.s,n),c=Ch(ns.l,Ac.l,n);return this.setHSL(s,l,c),this}setFromVector3(t){return this.r=t.x,this.g=t.y,this.b=t.z,this}applyMatrix3(t){const n=this.r,s=this.g,l=this.b,c=t.elements;return this.r=c[0]*n+c[3]*s+c[6]*l,this.g=c[1]*n+c[4]*s+c[7]*l,this.b=c[2]*n+c[5]*s+c[8]*l,this}equals(t){return t.r===this.r&&t.g===this.g&&t.b===this.b}fromArray(t,n=0){return this.r=t[n],this.g=t[n+1],this.b=t[n+2],this}toArray(t=[],n=0){return t[n]=this.r,t[n+1]=this.g,t[n+2]=this.b,t}fromBufferAttribute(t,n){return this.r=t.getX(n),this.g=t.getY(n),this.b=t.getZ(n),this}toJSON(){return this.getHex()}*[Symbol.iterator](){yield this.r,yield this.g,yield this.b}}const Fn=new fe;fe.NAMES=tx;class pp{constructor(t,n=25e-5){this.isFogExp2=!0,this.name="",this.color=new fe(t),this.density=n}clone(){return new pp(this.color,this.density)}toJSON(){return{type:"FogExp2",name:this.name,color:this.color.getHex(),density:this.density}}}class Pv extends On{constructor(){super(),this.isScene=!0,this.type="Scene",this.background=null,this.environment=null,this.fog=null,this.backgroundBlurriness=0,this.backgroundIntensity=1,this.backgroundRotation=new fs,this.environmentIntensity=1,this.environmentRotation=new fs,this.overrideMaterial=null,typeof __THREE_DEVTOOLS__<"u"&&__THREE_DEVTOOLS__.dispatchEvent(new CustomEvent("observe",{detail:this}))}copy(t,n){return super.copy(t,n),t.background!==null&&(this.background=t.background.clone()),t.environment!==null&&(this.environment=t.environment.clone()),t.fog!==null&&(this.fog=t.fog.clone()),this.backgroundBlurriness=t.backgroundBlurriness,this.backgroundIntensity=t.backgroundIntensity,this.backgroundRotation.copy(t.backgroundRotation),this.environmentIntensity=t.environmentIntensity,this.environmentRotation.copy(t.environmentRotation),t.overrideMaterial!==null&&(this.overrideMaterial=t.overrideMaterial.clone()),this.matrixAutoUpdate=t.matrixAutoUpdate,this}toJSON(t){const n=super.toJSON(t);return this.fog!==null&&(n.object.fog=this.fog.toJSON()),this.backgroundBlurriness>0&&(n.object.backgroundBlurriness=this.backgroundBlurriness),this.backgroundIntensity!==1&&(n.object.backgroundIntensity=this.backgroundIntensity),n.object.backgroundRotation=this.backgroundRotation.toArray(),this.environmentIntensity!==1&&(n.object.environmentIntensity=this.environmentIntensity),n.object.environmentRotation=this.environmentRotation.toArray(),n}}const Ui=new K,_a=new K,Ih=new K,xa=new K,wr=new K,Dr=new K,Iv=new K,zh=new K,Fh=new K,Bh=new K,Hh=new $e,Gh=new $e,Vh=new $e;class Oi{constructor(t=new K,n=new K,s=new K){this.a=t,this.b=n,this.c=s}static getNormal(t,n,s,l){l.subVectors(s,n),Ui.subVectors(t,n),l.cross(Ui);const c=l.lengthSq();return c>0?l.multiplyScalar(1/Math.sqrt(c)):l.set(0,0,0)}static getBarycoord(t,n,s,l,c){Ui.subVectors(l,n),_a.subVectors(s,n),Ih.subVectors(t,n);const f=Ui.dot(Ui),d=Ui.dot(_a),m=Ui.dot(Ih),p=_a.dot(_a),v=_a.dot(Ih),_=f*p-d*d;if(_===0)return c.set(0,0,0),null;const g=1/_,y=(p*m-d*v)*g,b=(f*v-d*m)*g;return c.set(1-y-b,b,y)}static containsPoint(t,n,s,l){return this.getBarycoord(t,n,s,l,xa)===null?!1:xa.x>=0&&xa.y>=0&&xa.x+xa.y<=1}static getInterpolation(t,n,s,l,c,f,d,m){return this.getBarycoord(t,n,s,l,xa)===null?(m.x=0,m.y=0,"z"in m&&(m.z=0),"w"in m&&(m.w=0),null):(m.setScalar(0),m.addScaledVector(c,xa.x),m.addScaledVector(f,xa.y),m.addScaledVector(d,xa.z),m)}static getInterpolatedAttribute(t,n,s,l,c,f){return Hh.setScalar(0),Gh.setScalar(0),Vh.setScalar(0),Hh.fromBufferAttribute(t,n),Gh.fromBufferAttribute(t,s),Vh.fromBufferAttribute(t,l),f.setScalar(0),f.addScaledVector(Hh,c.x),f.addScaledVector(Gh,c.y),f.addScaledVector(Vh,c.z),f}static isFrontFacing(t,n,s,l){return Ui.subVectors(s,n),_a.subVectors(t,n),Ui.cross(_a).dot(l)<0}set(t,n,s){return this.a.copy(t),this.b.copy(n),this.c.copy(s),this}setFromPointsAndIndices(t,n,s,l){return this.a.copy(t[n]),this.b.copy(t[s]),this.c.copy(t[l]),this}setFromAttributeAndIndices(t,n,s,l){return this.a.fromBufferAttribute(t,n),this.b.fromBufferAttribute(t,s),this.c.fromBufferAttribute(t,l),this}clone(){return new this.constructor().copy(this)}copy(t){return this.a.copy(t.a),this.b.copy(t.b),this.c.copy(t.c),this}getArea(){return Ui.subVectors(this.c,this.b),_a.subVectors(this.a,this.b),Ui.cross(_a).length()*.5}getMidpoint(t){return t.addVectors(this.a,this.b).add(this.c).multiplyScalar(1/3)}getNormal(t){return Oi.getNormal(this.a,this.b,this.c,t)}getPlane(t){return t.setFromCoplanarPoints(this.a,this.b,this.c)}getBarycoord(t,n){return Oi.getBarycoord(t,this.a,this.b,this.c,n)}getInterpolation(t,n,s,l,c){return Oi.getInterpolation(t,this.a,this.b,this.c,n,s,l,c)}containsPoint(t){return Oi.containsPoint(t,this.a,this.b,this.c)}isFrontFacing(t){return Oi.isFrontFacing(this.a,this.b,this.c,t)}intersectsBox(t){return t.intersectsTriangle(this)}closestPointToPoint(t,n){const s=this.a,l=this.b,c=this.c;let f,d;wr.subVectors(l,s),Dr.subVectors(c,s),zh.subVectors(t,s);const m=wr.dot(zh),p=Dr.dot(zh);if(m<=0&&p<=0)return n.copy(s);Fh.subVectors(t,l);const v=wr.dot(Fh),_=Dr.dot(Fh);if(v>=0&&_<=v)return n.copy(l);const g=m*_-v*p;if(g<=0&&m>=0&&v<=0)return f=m/(m-v),n.copy(s).addScaledVector(wr,f);Bh.subVectors(t,c);const y=wr.dot(Bh),b=Dr.dot(Bh);if(b>=0&&y<=b)return n.copy(c);const w=y*p-m*b;if(w<=0&&p>=0&&b<=0)return d=p/(p-b),n.copy(s).addScaledVector(Dr,d);const M=v*b-y*_;if(M<=0&&_-v>=0&&y-b>=0)return Iv.subVectors(c,l),d=(_-v)/(_-v+(y-b)),n.copy(l).addScaledVector(Iv,d);const S=1/(M+w+g);return f=w*S,d=g*S,n.copy(s).addScaledVector(wr,f).addScaledVector(Dr,d)}equals(t){return t.a.equals(this.a)&&t.b.equals(this.b)&&t.c.equals(this.c)}}class cl{constructor(t=new K(1/0,1/0,1/0),n=new K(-1/0,-1/0,-1/0)){this.isBox3=!0,this.min=t,this.max=n}set(t,n){return this.min.copy(t),this.max.copy(n),this}setFromArray(t){this.makeEmpty();for(let n=0,s=t.length;n<s;n+=3)this.expandByPoint(Li.fromArray(t,n));return this}setFromBufferAttribute(t){this.makeEmpty();for(let n=0,s=t.count;n<s;n++)this.expandByPoint(Li.fromBufferAttribute(t,n));return this}setFromPoints(t){this.makeEmpty();for(let n=0,s=t.length;n<s;n++)this.expandByPoint(t[n]);return this}setFromCenterAndSize(t,n){const s=Li.copy(n).multiplyScalar(.5);return this.min.copy(t).sub(s),this.max.copy(t).add(s),this}setFromObject(t,n=!1){return this.makeEmpty(),this.expandByObject(t,n)}clone(){return new this.constructor().copy(this)}copy(t){return this.min.copy(t.min),this.max.copy(t.max),this}makeEmpty(){return this.min.x=this.min.y=this.min.z=1/0,this.max.x=this.max.y=this.max.z=-1/0,this}isEmpty(){return this.max.x<this.min.x||this.max.y<this.min.y||this.max.z<this.min.z}getCenter(t){return this.isEmpty()?t.set(0,0,0):t.addVectors(this.min,this.max).multiplyScalar(.5)}getSize(t){return this.isEmpty()?t.set(0,0,0):t.subVectors(this.max,this.min)}expandByPoint(t){return this.min.min(t),this.max.max(t),this}expandByVector(t){return this.min.sub(t),this.max.add(t),this}expandByScalar(t){return this.min.addScalar(-t),this.max.addScalar(t),this}expandByObject(t,n=!1){t.updateWorldMatrix(!1,!1);const s=t.geometry;if(s!==void 0){const c=s.getAttribute("position");if(n===!0&&c!==void 0&&t.isInstancedMesh!==!0)for(let f=0,d=c.count;f<d;f++)t.isMesh===!0?t.getVertexPosition(f,Li):Li.fromBufferAttribute(c,f),Li.applyMatrix4(t.matrixWorld),this.expandByPoint(Li);else t.boundingBox!==void 0?(t.boundingBox===null&&t.computeBoundingBox(),Rc.copy(t.boundingBox)):(s.boundingBox===null&&s.computeBoundingBox(),Rc.copy(s.boundingBox)),Rc.applyMatrix4(t.matrixWorld),this.union(Rc)}const l=t.children;for(let c=0,f=l.length;c<f;c++)this.expandByObject(l[c],n);return this}containsPoint(t){return t.x>=this.min.x&&t.x<=this.max.x&&t.y>=this.min.y&&t.y<=this.max.y&&t.z>=this.min.z&&t.z<=this.max.z}containsBox(t){return this.min.x<=t.min.x&&t.max.x<=this.max.x&&this.min.y<=t.min.y&&t.max.y<=this.max.y&&this.min.z<=t.min.z&&t.max.z<=this.max.z}getParameter(t,n){return n.set((t.x-this.min.x)/(this.max.x-this.min.x),(t.y-this.min.y)/(this.max.y-this.min.y),(t.z-this.min.z)/(this.max.z-this.min.z))}intersectsBox(t){return t.max.x>=this.min.x&&t.min.x<=this.max.x&&t.max.y>=this.min.y&&t.min.y<=this.max.y&&t.max.z>=this.min.z&&t.min.z<=this.max.z}intersectsSphere(t){return this.clampPoint(t.center,Li),Li.distanceToSquared(t.center)<=t.radius*t.radius}intersectsPlane(t){let n,s;return t.normal.x>0?(n=t.normal.x*this.min.x,s=t.normal.x*this.max.x):(n=t.normal.x*this.max.x,s=t.normal.x*this.min.x),t.normal.y>0?(n+=t.normal.y*this.min.y,s+=t.normal.y*this.max.y):(n+=t.normal.y*this.max.y,s+=t.normal.y*this.min.y),t.normal.z>0?(n+=t.normal.z*this.min.z,s+=t.normal.z*this.max.z):(n+=t.normal.z*this.max.z,s+=t.normal.z*this.min.z),n<=-t.constant&&s>=-t.constant}intersectsTriangle(t){if(this.isEmpty())return!1;this.getCenter(Wo),Cc.subVectors(this.max,Wo),Nr.subVectors(t.a,Wo),Ur.subVectors(t.b,Wo),Lr.subVectors(t.c,Wo),is.subVectors(Ur,Nr),as.subVectors(Lr,Ur),Us.subVectors(Nr,Lr);let n=[0,-is.z,is.y,0,-as.z,as.y,0,-Us.z,Us.y,is.z,0,-is.x,as.z,0,-as.x,Us.z,0,-Us.x,-is.y,is.x,0,-as.y,as.x,0,-Us.y,Us.x,0];return!kh(n,Nr,Ur,Lr,Cc)||(n=[1,0,0,0,1,0,0,0,1],!kh(n,Nr,Ur,Lr,Cc))?!1:(wc.crossVectors(is,as),n=[wc.x,wc.y,wc.z],kh(n,Nr,Ur,Lr,Cc))}clampPoint(t,n){return n.copy(t).clamp(this.min,this.max)}distanceToPoint(t){return this.clampPoint(t,Li).distanceTo(t)}getBoundingSphere(t){return this.isEmpty()?t.makeEmpty():(this.getCenter(t.center),t.radius=this.getSize(Li).length()*.5),t}intersect(t){return this.min.max(t.min),this.max.min(t.max),this.isEmpty()&&this.makeEmpty(),this}union(t){return this.min.min(t.min),this.max.max(t.max),this}applyMatrix4(t){return this.isEmpty()?this:(Sa[0].set(this.min.x,this.min.y,this.min.z).applyMatrix4(t),Sa[1].set(this.min.x,this.min.y,this.max.z).applyMatrix4(t),Sa[2].set(this.min.x,this.max.y,this.min.z).applyMatrix4(t),Sa[3].set(this.min.x,this.max.y,this.max.z).applyMatrix4(t),Sa[4].set(this.max.x,this.min.y,this.min.z).applyMatrix4(t),Sa[5].set(this.max.x,this.min.y,this.max.z).applyMatrix4(t),Sa[6].set(this.max.x,this.max.y,this.min.z).applyMatrix4(t),Sa[7].set(this.max.x,this.max.y,this.max.z).applyMatrix4(t),this.setFromPoints(Sa),this)}translate(t){return this.min.add(t),this.max.add(t),this}equals(t){return t.min.equals(this.min)&&t.max.equals(this.max)}toJSON(){return{min:this.min.toArray(),max:this.max.toArray()}}fromJSON(t){return this.min.fromArray(t.min),this.max.fromArray(t.max),this}}const Sa=[new K,new K,new K,new K,new K,new K,new K,new K],Li=new K,Rc=new cl,Nr=new K,Ur=new K,Lr=new K,is=new K,as=new K,Us=new K,Wo=new K,Cc=new K,wc=new K,Ls=new K;function kh(r,t,n,s,l){for(let c=0,f=r.length-3;c<=f;c+=3){Ls.fromArray(r,c);const d=l.x*Math.abs(Ls.x)+l.y*Math.abs(Ls.y)+l.z*Math.abs(Ls.z),m=t.dot(Ls),p=n.dot(Ls),v=s.dot(Ls);if(Math.max(-Math.max(m,p,v),Math.min(m,p,v))>d)return!1}return!0}const Sn=new K,Dc=new qt;let OM=0;class Ki extends Ws{constructor(t,n,s=!1){if(super(),Array.isArray(t))throw new TypeError("THREE.BufferAttribute: array should be a Typed Array.");this.isBufferAttribute=!0,Object.defineProperty(this,"id",{value:OM++}),this.name="",this.array=t,this.itemSize=n,this.count=t!==void 0?t.length/n:0,this.normalized=s,this.usage=yv,this.updateRanges=[],this.gpuType=Wi,this.version=0}onUploadCallback(){}set needsUpdate(t){t===!0&&this.version++}setUsage(t){return this.usage=t,this}addUpdateRange(t,n){this.updateRanges.push({start:t,count:n})}clearUpdateRanges(){this.updateRanges.length=0}copy(t){return this.name=t.name,this.array=new t.array.constructor(t.array),this.itemSize=t.itemSize,this.count=t.count,this.normalized=t.normalized,this.usage=t.usage,this.gpuType=t.gpuType,this}copyAt(t,n,s){t*=this.itemSize,s*=n.itemSize;for(let l=0,c=this.itemSize;l<c;l++)this.array[t+l]=n.array[s+l];return this}copyArray(t){return this.array.set(t),this}applyMatrix3(t){if(this.itemSize===2)for(let n=0,s=this.count;n<s;n++)Dc.fromBufferAttribute(this,n),Dc.applyMatrix3(t),this.setXY(n,Dc.x,Dc.y);else if(this.itemSize===3)for(let n=0,s=this.count;n<s;n++)Sn.fromBufferAttribute(this,n),Sn.applyMatrix3(t),this.setXYZ(n,Sn.x,Sn.y,Sn.z);return this}applyMatrix4(t){for(let n=0,s=this.count;n<s;n++)Sn.fromBufferAttribute(this,n),Sn.applyMatrix4(t),this.setXYZ(n,Sn.x,Sn.y,Sn.z);return this}applyNormalMatrix(t){for(let n=0,s=this.count;n<s;n++)Sn.fromBufferAttribute(this,n),Sn.applyNormalMatrix(t),this.setXYZ(n,Sn.x,Sn.y,Sn.z);return this}transformDirection(t){for(let n=0,s=this.count;n<s;n++)Sn.fromBufferAttribute(this,n),Sn.transformDirection(t),this.setXYZ(n,Sn.x,Sn.y,Sn.z);return this}set(t,n=0){return this.array.set(t,n),this}getComponent(t,n){let s=this.array[t*this.itemSize+n];return this.normalized&&(s=ko(s,this.array)),s}setComponent(t,n,s){return this.normalized&&(s=Qn(s,this.array)),this.array[t*this.itemSize+n]=s,this}getX(t){let n=this.array[t*this.itemSize];return this.normalized&&(n=ko(n,this.array)),n}setX(t,n){return this.normalized&&(n=Qn(n,this.array)),this.array[t*this.itemSize]=n,this}getY(t){let n=this.array[t*this.itemSize+1];return this.normalized&&(n=ko(n,this.array)),n}setY(t,n){return this.normalized&&(n=Qn(n,this.array)),this.array[t*this.itemSize+1]=n,this}getZ(t){let n=this.array[t*this.itemSize+2];return this.normalized&&(n=ko(n,this.array)),n}setZ(t,n){return this.normalized&&(n=Qn(n,this.array)),this.array[t*this.itemSize+2]=n,this}getW(t){let n=this.array[t*this.itemSize+3];return this.normalized&&(n=ko(n,this.array)),n}setW(t,n){return this.normalized&&(n=Qn(n,this.array)),this.array[t*this.itemSize+3]=n,this}setXY(t,n,s){return t*=this.itemSize,this.normalized&&(n=Qn(n,this.array),s=Qn(s,this.array)),this.array[t+0]=n,this.array[t+1]=s,this}setXYZ(t,n,s,l){return t*=this.itemSize,this.normalized&&(n=Qn(n,this.array),s=Qn(s,this.array),l=Qn(l,this.array)),this.array[t+0]=n,this.array[t+1]=s,this.array[t+2]=l,this}setXYZW(t,n,s,l,c){return t*=this.itemSize,this.normalized&&(n=Qn(n,this.array),s=Qn(s,this.array),l=Qn(l,this.array),c=Qn(c,this.array)),this.array[t+0]=n,this.array[t+1]=s,this.array[t+2]=l,this.array[t+3]=c,this}onUpload(t){return this.onUploadCallback=t,this}clone(){return new this.constructor(this.array,this.itemSize).copy(this)}toJSON(){const t={itemSize:this.itemSize,type:this.array.constructor.name,array:Array.from(this.array),normalized:this.normalized};return this.name!==""&&(t.name=this.name),this.usage!==yv&&(t.usage=this.usage),t}dispose(){this.dispatchEvent({type:"dispose"})}}class ex extends Ki{constructor(t,n,s){super(new Uint16Array(t),n,s)}}class nx extends Ki{constructor(t,n,s){super(new Uint32Array(t),n,s)}}class Xe extends Ki{constructor(t,n,s){super(new Float32Array(t),n,s)}}const PM=new cl,qo=new K,Xh=new K;class mp{constructor(t=new K,n=-1){this.isSphere=!0,this.center=t,this.radius=n}set(t,n){return this.center.copy(t),this.radius=n,this}setFromPoints(t,n){const s=this.center;n!==void 0?s.copy(n):PM.setFromPoints(t).getCenter(s);let l=0;for(let c=0,f=t.length;c<f;c++)l=Math.max(l,s.distanceToSquared(t[c]));return this.radius=Math.sqrt(l),this}copy(t){return this.center.copy(t.center),this.radius=t.radius,this}isEmpty(){return this.radius<0}makeEmpty(){return this.center.set(0,0,0),this.radius=-1,this}containsPoint(t){return t.distanceToSquared(this.center)<=this.radius*this.radius}distanceToPoint(t){return t.distanceTo(this.center)-this.radius}intersectsSphere(t){const n=this.radius+t.radius;return t.center.distanceToSquared(this.center)<=n*n}intersectsBox(t){return t.intersectsSphere(this)}intersectsPlane(t){return Math.abs(t.distanceToPoint(this.center))<=this.radius}clampPoint(t,n){const s=this.center.distanceToSquared(t);return n.copy(t),s>this.radius*this.radius&&(n.sub(this.center).normalize(),n.multiplyScalar(this.radius).add(this.center)),n}getBoundingBox(t){return this.isEmpty()?(t.makeEmpty(),t):(t.set(this.center,this.center),t.expandByScalar(this.radius),t)}applyMatrix4(t){return this.center.applyMatrix4(t),this.radius=this.radius*t.getMaxScaleOnAxis(),this}translate(t){return this.center.add(t),this}expandByPoint(t){if(this.isEmpty())return this.center.copy(t),this.radius=0,this;qo.subVectors(t,this.center);const n=qo.lengthSq();if(n>this.radius*this.radius){const s=Math.sqrt(n),l=(s-this.radius)*.5;this.center.addScaledVector(qo,l/s),this.radius+=l}return this}union(t){return t.isEmpty()?this:this.isEmpty()?(this.copy(t),this):(this.center.equals(t.center)===!0?this.radius=Math.max(this.radius,t.radius):(Xh.subVectors(t.center,this.center).setLength(t.radius),this.expandByPoint(qo.copy(t.center).add(Xh)),this.expandByPoint(qo.copy(t.center).sub(Xh))),this)}equals(t){return t.center.equals(this.center)&&t.radius===this.radius}clone(){return new this.constructor().copy(this)}toJSON(){return{radius:this.radius,center:this.center.toArray()}}fromJSON(t){return this.radius=t.radius,this.center.fromArray(t.center),this}}let IM=0;const Mi=new en,Wh=new On,Or=new K,fi=new cl,Yo=new cl,An=new K;class Xn extends Ws{constructor(){super(),this.isBufferGeometry=!0,Object.defineProperty(this,"id",{value:IM++}),this.uuid=Yr(),this.name="",this.type="BufferGeometry",this.index=null,this.indirect=null,this.indirectOffset=0,this.attributes={},this.morphAttributes={},this.morphTargetsRelative=!1,this.groups=[],this.boundingBox=null,this.boundingSphere=null,this.drawRange={start:0,count:1/0},this.userData={},this._transformed=!1}getIndex(){return this.index}setIndex(t){return Array.isArray(t)?this.index=new(gM(t)?nx:ex)(t,1):this.index=t,this}setIndirect(t,n=0){return this.indirect=t,this.indirectOffset=n,this}getIndirect(){return this.indirect}getAttribute(t){return this.attributes[t]}setAttribute(t,n){return this.attributes[t]=n,this}deleteAttribute(t){return delete this.attributes[t],this}hasAttribute(t){return this.attributes[t]!==void 0}addGroup(t,n,s=0){this.groups.push({start:t,count:n,materialIndex:s})}clearGroups(){this.groups=[]}setDrawRange(t,n){this.drawRange.start=t,this.drawRange.count=n}applyMatrix4(t){const n=this.attributes.position;n!==void 0&&(n.applyMatrix4(t),n.needsUpdate=!0);const s=this.attributes.normal;if(s!==void 0){const c=new re().getNormalMatrix(t);s.applyNormalMatrix(c),s.needsUpdate=!0}const l=this.attributes.tangent;return l!==void 0&&(l.transformDirection(t),l.needsUpdate=!0),this.boundingBox!==null&&this.computeBoundingBox(),this.boundingSphere!==null&&this.computeBoundingSphere(),this._transformed=!0,this}applyQuaternion(t){return Mi.makeRotationFromQuaternion(t),this.applyMatrix4(Mi),this}rotateX(t){return Mi.makeRotationX(t),this.applyMatrix4(Mi),this}rotateY(t){return Mi.makeRotationY(t),this.applyMatrix4(Mi),this}rotateZ(t){return Mi.makeRotationZ(t),this.applyMatrix4(Mi),this}translate(t,n,s){return Mi.makeTranslation(t,n,s),this.applyMatrix4(Mi),this}scale(t,n,s){return Mi.makeScale(t,n,s),this.applyMatrix4(Mi),this}lookAt(t){return Wh.lookAt(t),Wh.updateMatrix(),this.applyMatrix4(Wh.matrix),this}center(){return this.computeBoundingBox(),this.boundingBox.getCenter(Or).negate(),this.translate(Or.x,Or.y,Or.z),this}setFromPoints(t){const n=this.getAttribute("position");if(n===void 0){const s=[];for(let l=0,c=t.length;l<c;l++){const f=t[l];s.push(f.x,f.y,f.z||0)}this.setAttribute("position",new Xe(s,3))}else{const s=Math.min(t.length,n.count);for(let l=0;l<s;l++){const c=t[l];n.setXYZ(l,c.x,c.y,c.z||0)}t.length>n.count&&ie("BufferGeometry: Buffer size too small for points data. Use .dispose() and create a new geometry."),n.needsUpdate=!0}return this}computeBoundingBox(){this.boundingBox===null&&(this.boundingBox=new cl);const t=this.attributes.position,n=this.morphAttributes.position;if(t&&t.isGLBufferAttribute){be("BufferGeometry.computeBoundingBox(): GLBufferAttribute requires a manual bounding box.",this),this.boundingBox.set(new K(-1/0,-1/0,-1/0),new K(1/0,1/0,1/0));return}if(t!==void 0){if(this.boundingBox.setFromBufferAttribute(t),n)for(let s=0,l=n.length;s<l;s++){const c=n[s];fi.setFromBufferAttribute(c),this.morphTargetsRelative?(An.addVectors(this.boundingBox.min,fi.min),this.boundingBox.expandByPoint(An),An.addVectors(this.boundingBox.max,fi.max),this.boundingBox.expandByPoint(An)):(this.boundingBox.expandByPoint(fi.min),this.boundingBox.expandByPoint(fi.max))}}else this.boundingBox.makeEmpty();(isNaN(this.boundingBox.min.x)||isNaN(this.boundingBox.min.y)||isNaN(this.boundingBox.min.z))&&be('BufferGeometry.computeBoundingBox(): Computed min/max have NaN values. The "position" attribute is likely to have NaN values.',this)}computeBoundingSphere(){this.boundingSphere===null&&(this.boundingSphere=new mp);const t=this.attributes.position,n=this.morphAttributes.position;if(t&&t.isGLBufferAttribute){be("BufferGeometry.computeBoundingSphere(): GLBufferAttribute requires a manual bounding sphere.",this),this.boundingSphere.set(new K,1/0);return}if(t){const s=this.boundingSphere.center;if(fi.setFromBufferAttribute(t),n)for(let c=0,f=n.length;c<f;c++){const d=n[c];Yo.setFromBufferAttribute(d),this.morphTargetsRelative?(An.addVectors(fi.min,Yo.min),fi.expandByPoint(An),An.addVectors(fi.max,Yo.max),fi.expandByPoint(An)):(fi.expandByPoint(Yo.min),fi.expandByPoint(Yo.max))}fi.getCenter(s);let l=0;for(let c=0,f=t.count;c<f;c++)An.fromBufferAttribute(t,c),l=Math.max(l,s.distanceToSquared(An));if(n)for(let c=0,f=n.length;c<f;c++){const d=n[c],m=this.morphTargetsRelative;for(let p=0,v=d.count;p<v;p++)An.fromBufferAttribute(d,p),m&&(Or.fromBufferAttribute(t,p),An.add(Or)),l=Math.max(l,s.distanceToSquared(An))}this.boundingSphere.radius=Math.sqrt(l),isNaN(this.boundingSphere.radius)&&be('BufferGeometry.computeBoundingSphere(): Computed radius is NaN. The "position" attribute is likely to have NaN values.',this)}}computeTangents(){const t=this.index,n=this.attributes;if(t===null||n.position===void 0||n.normal===void 0||n.uv===void 0){be("BufferGeometry: .computeTangents() failed. Missing required attributes (index, position, normal or uv)");return}const s=n.position,l=n.normal,c=n.uv;let f=this.getAttribute("tangent");(f===void 0||f.count!==s.count)&&(f=new Ki(new Float32Array(4*s.count),4),this.setAttribute("tangent",f));const d=[],m=[];for(let T=0;T<s.count;T++)d[T]=new K,m[T]=new K;const p=new K,v=new K,_=new K,g=new qt,y=new qt,b=new qt,w=new K,M=new K;function S(T,N,X){p.fromBufferAttribute(s,T),v.fromBufferAttribute(s,N),_.fromBufferAttribute(s,X),g.fromBufferAttribute(c,T),y.fromBufferAttribute(c,N),b.fromBufferAttribute(c,X),v.sub(p),_.sub(p),y.sub(g),b.sub(g);const V=1/(y.x*b.y-b.x*y.y);isFinite(V)&&(w.copy(v).multiplyScalar(b.y).addScaledVector(_,-y.y).multiplyScalar(V),M.copy(_).multiplyScalar(y.x).addScaledVector(v,-b.x).multiplyScalar(V),d[T].add(w),d[N].add(w),d[X].add(w),m[T].add(M),m[N].add(M),m[X].add(M))}let P=this.groups;P.length===0&&(P=[{start:0,count:t.count}]);for(let T=0,N=P.length;T<N;++T){const X=P[T],V=X.start,q=X.count;for(let ct=V,ht=V+q;ct<ht;ct+=3)S(t.getX(ct+0),t.getX(ct+1),t.getX(ct+2))}const D=new K,A=new K,F=new K,O=new K;function I(T){F.fromBufferAttribute(l,T),O.copy(F);const N=d[T];D.copy(N),D.sub(F.multiplyScalar(F.dot(N))).normalize(),A.crossVectors(O,N);const V=A.dot(m[T])<0?-1:1;f.setXYZW(T,D.x,D.y,D.z,V)}for(let T=0,N=P.length;T<N;++T){const X=P[T],V=X.start,q=X.count;for(let ct=V,ht=V+q;ct<ht;ct+=3)I(t.getX(ct+0)),I(t.getX(ct+1)),I(t.getX(ct+2))}this._transformed=!0}computeVertexNormals(){const t=this.index,n=this.getAttribute("position");if(n!==void 0){let s=this.getAttribute("normal");if(s===void 0||s.count!==n.count)s=new Ki(new Float32Array(n.count*3),3),this.setAttribute("normal",s);else for(let g=0,y=s.count;g<y;g++)s.setXYZ(g,0,0,0);const l=new K,c=new K,f=new K,d=new K,m=new K,p=new K,v=new K,_=new K;if(t)for(let g=0,y=t.count;g<y;g+=3){const b=t.getX(g+0),w=t.getX(g+1),M=t.getX(g+2);l.fromBufferAttribute(n,b),c.fromBufferAttribute(n,w),f.fromBufferAttribute(n,M),v.subVectors(f,c),_.subVectors(l,c),v.cross(_),d.fromBufferAttribute(s,b),m.fromBufferAttribute(s,w),p.fromBufferAttribute(s,M),d.add(v),m.add(v),p.add(v),s.setXYZ(b,d.x,d.y,d.z),s.setXYZ(w,m.x,m.y,m.z),s.setXYZ(M,p.x,p.y,p.z)}else for(let g=0,y=n.count;g<y;g+=3)l.fromBufferAttribute(n,g+0),c.fromBufferAttribute(n,g+1),f.fromBufferAttribute(n,g+2),v.subVectors(f,c),_.subVectors(l,c),v.cross(_),s.setXYZ(g+0,v.x,v.y,v.z),s.setXYZ(g+1,v.x,v.y,v.z),s.setXYZ(g+2,v.x,v.y,v.z);this.normalizeNormals(),s.needsUpdate=!0}}normalizeNormals(){const t=this.attributes.normal;for(let n=0,s=t.count;n<s;n++)An.fromBufferAttribute(t,n),An.normalize(),t.setXYZ(n,An.x,An.y,An.z)}toNonIndexed(){function t(d,m){const p=d.array,v=d.itemSize,_=d.normalized,g=new p.constructor(m.length*v);let y=0,b=0;for(let w=0,M=m.length;w<M;w++){d.isInterleavedBufferAttribute?y=m[w]*d.data.stride+d.offset:y=m[w]*v;for(let S=0;S<v;S++)g[b++]=p[y++]}return new Ki(g,v,_)}if(this.index===null)return ie("BufferGeometry.toNonIndexed(): BufferGeometry is already non-indexed."),this;const n=new Xn,s=this.index.array,l=this.attributes;for(const d in l){const m=l[d],p=t(m,s);n.setAttribute(d,p)}const c=this.morphAttributes;for(const d in c){const m=[],p=c[d];for(let v=0,_=p.length;v<_;v++){const g=p[v],y=t(g,s);m.push(y)}n.morphAttributes[d]=m}n.morphTargetsRelative=this.morphTargetsRelative;const f=this.groups;for(let d=0,m=f.length;d<m;d++){const p=f[d];n.addGroup(p.start,p.count,p.materialIndex)}return n}toJSON(){const t={metadata:{version:4.7,type:"BufferGeometry",generator:"BufferGeometry.toJSON"}};if(t.uuid=this.uuid,t.type=this.parameters!==void 0&&this._transformed===!0?"BufferGeometry":this.type,this.name!==""&&(t.name=this.name),Object.keys(this.userData).length>0&&(t.userData=this.userData),this.parameters!==void 0&&this._transformed!==!0){const m=this.parameters;for(const p in m)m[p]!==void 0&&(t[p]=m[p]);return t}t.data={attributes:{}};const n=this.index;n!==null&&(t.data.index={type:n.array.constructor.name,array:Array.prototype.slice.call(n.array)});const s=this.attributes;for(const m in s){const p=s[m];t.data.attributes[m]=p.toJSON(t.data)}const l={};let c=!1;for(const m in this.morphAttributes){const p=this.morphAttributes[m],v=[];for(let _=0,g=p.length;_<g;_++){const y=p[_];v.push(y.toJSON(t.data))}v.length>0&&(l[m]=v,c=!0)}c&&(t.data.morphAttributes=l,t.data.morphTargetsRelative=this.morphTargetsRelative);const f=this.groups;f.length>0&&(t.data.groups=JSON.parse(JSON.stringify(f)));const d=this.boundingSphere;return d!==null&&(t.data.boundingSphere=d.toJSON()),t}clone(){return new this.constructor().copy(this)}copy(t){this.index=null,this.attributes={},this.morphAttributes={},this.groups=[],this.boundingBox=null,this.boundingSphere=null;const n={};this.name=t.name;const s=t.index;s!==null&&this.setIndex(s.clone());const l=t.attributes;for(const p in l){const v=l[p];this.setAttribute(p,v.clone(n))}const c=t.morphAttributes;for(const p in c){const v=[],_=c[p];for(let g=0,y=_.length;g<y;g++)v.push(_[g].clone(n));this.morphAttributes[p]=v}this.morphTargetsRelative=t.morphTargetsRelative;const f=t.groups;for(let p=0,v=f.length;p<v;p++){const _=f[p];this.addGroup(_.start,_.count,_.materialIndex)}const d=t.boundingBox;d!==null&&(this.boundingBox=d.clone());const m=t.boundingSphere;return m!==null&&(this.boundingSphere=m.clone()),this.drawRange.start=t.drawRange.start,this.drawRange.count=t.drawRange.count,this.userData=t.userData,this._transformed=t._transformed,this}dispose(){this.dispatchEvent({type:"dispose"})}}let zM=0;class ul extends Ws{constructor(){super(),this.isMaterial=!0,Object.defineProperty(this,"id",{value:zM++}),this.uuid=Yr(),this.name="",this.type="Material",this.blending=Br,this.side=us,this.vertexColors=!1,this.opacity=1,this.transparent=!1,this.alphaHash=!1,this.blendSrc=cd,this.blendDst=ud,this.blendEquation=Fs,this.blendSrcAlpha=null,this.blendDstAlpha=null,this.blendEquationAlpha=null,this.blendColor=new fe(0,0,0),this.blendAlpha=0,this.depthFunc=Vr,this.depthTest=!0,this.depthWrite=!0,this.stencilWriteMask=255,this.stencilFunc=Sv,this.stencilRef=0,this.stencilFuncMask=255,this.stencilFail=br,this.stencilZFail=br,this.stencilZPass=br,this.stencilWrite=!1,this.clippingPlanes=null,this.clipIntersection=!1,this.clipShadows=!1,this.shadowSide=null,this.colorWrite=!0,this.precision=null,this.polygonOffset=!1,this.polygonOffsetFactor=0,this.polygonOffsetUnits=0,this.dithering=!1,this.alphaToCoverage=!1,this.premultipliedAlpha=!1,this.forceSinglePass=!1,this.allowOverride=!0,this.visible=!0,this.toneMapped=!0,this.userData={},this.version=0,this._alphaTest=0}get alphaTest(){return this._alphaTest}set alphaTest(t){this._alphaTest>0!=t>0&&this.version++,this._alphaTest=t}onBeforeRender(){}onBeforeCompile(){}customProgramCacheKey(){return this.onBeforeCompile.toString()}setValues(t){if(t!==void 0)for(const n in t){const s=t[n];if(s===void 0){ie(`Material: parameter '${n}' has value of undefined.`);continue}const l=this[n];if(l===void 0){ie(`Material: '${n}' is not a property of THREE.${this.type}.`);continue}l&&l.isColor?l.set(s):l&&l.isVector2&&s&&s.isVector2||l&&l.isEuler&&s&&s.isEuler||l&&l.isVector3&&s&&s.isVector3?l.copy(s):this[n]=s}}toJSON(t){const n=t===void 0||typeof t=="string";n&&(t={textures:{},images:{}});const s={metadata:{version:4.7,type:"Material",generator:"Material.toJSON"}};s.uuid=this.uuid,s.type=this.type,this.name!==""&&(s.name=this.name),this.color&&this.color.isColor&&(s.color=this.color.getHex()),this.roughness!==void 0&&(s.roughness=this.roughness),this.metalness!==void 0&&(s.metalness=this.metalness),this.sheen!==void 0&&(s.sheen=this.sheen),this.sheenColor&&this.sheenColor.isColor&&(s.sheenColor=this.sheenColor.getHex()),this.sheenRoughness!==void 0&&(s.sheenRoughness=this.sheenRoughness),this.emissive&&this.emissive.isColor&&(s.emissive=this.emissive.getHex()),this.emissiveIntensity!==void 0&&this.emissiveIntensity!==1&&(s.emissiveIntensity=this.emissiveIntensity),this.specular&&this.specular.isColor&&(s.specular=this.specular.getHex()),this.specularIntensity!==void 0&&(s.specularIntensity=this.specularIntensity),this.specularColor&&this.specularColor.isColor&&(s.specularColor=this.specularColor.getHex()),this.shininess!==void 0&&(s.shininess=this.shininess),this.clearcoat!==void 0&&(s.clearcoat=this.clearcoat),this.clearcoatRoughness!==void 0&&(s.clearcoatRoughness=this.clearcoatRoughness),this.clearcoatMap&&this.clearcoatMap.isTexture&&(s.clearcoatMap=this.clearcoatMap.toJSON(t).uuid),this.clearcoatRoughnessMap&&this.clearcoatRoughnessMap.isTexture&&(s.clearcoatRoughnessMap=this.clearcoatRoughnessMap.toJSON(t).uuid),this.clearcoatNormalMap&&this.clearcoatNormalMap.isTexture&&(s.clearcoatNormalMap=this.clearcoatNormalMap.toJSON(t).uuid,s.clearcoatNormalScale=this.clearcoatNormalScale.toArray()),this.sheenColorMap&&this.sheenColorMap.isTexture&&(s.sheenColorMap=this.sheenColorMap.toJSON(t).uuid),this.sheenRoughnessMap&&this.sheenRoughnessMap.isTexture&&(s.sheenRoughnessMap=this.sheenRoughnessMap.toJSON(t).uuid),this.dispersion!==void 0&&(s.dispersion=this.dispersion),this.iridescence!==void 0&&(s.iridescence=this.iridescence),this.iridescenceIOR!==void 0&&(s.iridescenceIOR=this.iridescenceIOR),this.iridescenceThicknessRange!==void 0&&(s.iridescenceThicknessRange=this.iridescenceThicknessRange),this.iridescenceMap&&this.iridescenceMap.isTexture&&(s.iridescenceMap=this.iridescenceMap.toJSON(t).uuid),this.iridescenceThicknessMap&&this.iridescenceThicknessMap.isTexture&&(s.iridescenceThicknessMap=this.iridescenceThicknessMap.toJSON(t).uuid),this.anisotropy!==void 0&&(s.anisotropy=this.anisotropy),this.anisotropyRotation!==void 0&&(s.anisotropyRotation=this.anisotropyRotation),this.anisotropyMap&&this.anisotropyMap.isTexture&&(s.anisotropyMap=this.anisotropyMap.toJSON(t).uuid),this.map&&this.map.isTexture&&(s.map=this.map.toJSON(t).uuid),this.matcap&&this.matcap.isTexture&&(s.matcap=this.matcap.toJSON(t).uuid),this.alphaMap&&this.alphaMap.isTexture&&(s.alphaMap=this.alphaMap.toJSON(t).uuid),this.lightMap&&this.lightMap.isTexture&&(s.lightMap=this.lightMap.toJSON(t).uuid,s.lightMapIntensity=this.lightMapIntensity),this.aoMap&&this.aoMap.isTexture&&(s.aoMap=this.aoMap.toJSON(t).uuid,s.aoMapIntensity=this.aoMapIntensity),this.bumpMap&&this.bumpMap.isTexture&&(s.bumpMap=this.bumpMap.toJSON(t).uuid,s.bumpScale=this.bumpScale),this.normalMap&&this.normalMap.isTexture&&(s.normalMap=this.normalMap.toJSON(t).uuid,s.normalMapType=this.normalMapType,s.normalScale=this.normalScale.toArray()),this.displacementMap&&this.displacementMap.isTexture&&(s.displacementMap=this.displacementMap.toJSON(t).uuid,s.displacementScale=this.displacementScale,s.displacementBias=this.displacementBias),this.roughnessMap&&this.roughnessMap.isTexture&&(s.roughnessMap=this.roughnessMap.toJSON(t).uuid),this.metalnessMap&&this.metalnessMap.isTexture&&(s.metalnessMap=this.metalnessMap.toJSON(t).uuid),this.emissiveMap&&this.emissiveMap.isTexture&&(s.emissiveMap=this.emissiveMap.toJSON(t).uuid),this.specularMap&&this.specularMap.isTexture&&(s.specularMap=this.specularMap.toJSON(t).uuid),this.specularIntensityMap&&this.specularIntensityMap.isTexture&&(s.specularIntensityMap=this.specularIntensityMap.toJSON(t).uuid),this.specularColorMap&&this.specularColorMap.isTexture&&(s.specularColorMap=this.specularColorMap.toJSON(t).uuid),this.envMap&&this.envMap.isTexture&&(s.envMap=this.envMap.toJSON(t).uuid,this.combine!==void 0&&(s.combine=this.combine)),this.envMapRotation!==void 0&&(s.envMapRotation=this.envMapRotation.toArray()),this.envMapIntensity!==void 0&&(s.envMapIntensity=this.envMapIntensity),this.reflectivity!==void 0&&(s.reflectivity=this.reflectivity),this.refractionRatio!==void 0&&(s.refractionRatio=this.refractionRatio),this.gradientMap&&this.gradientMap.isTexture&&(s.gradientMap=this.gradientMap.toJSON(t).uuid),this.transmission!==void 0&&(s.transmission=this.transmission),this.transmissionMap&&this.transmissionMap.isTexture&&(s.transmissionMap=this.transmissionMap.toJSON(t).uuid),this.thickness!==void 0&&(s.thickness=this.thickness),this.thicknessMap&&this.thicknessMap.isTexture&&(s.thicknessMap=this.thicknessMap.toJSON(t).uuid),this.attenuationDistance!==void 0&&this.attenuationDistance!==1/0&&(s.attenuationDistance=this.attenuationDistance),this.attenuationColor!==void 0&&(s.attenuationColor=this.attenuationColor.getHex()),this.size!==void 0&&(s.size=this.size),this.shadowSide!==null&&(s.shadowSide=this.shadowSide),this.sizeAttenuation!==void 0&&(s.sizeAttenuation=this.sizeAttenuation),this.blending!==Br&&(s.blending=this.blending),this.side!==us&&(s.side=this.side),this.vertexColors===!0&&(s.vertexColors=!0),this.opacity<1&&(s.opacity=this.opacity),this.transparent===!0&&(s.transparent=!0),this.blendSrc!==cd&&(s.blendSrc=this.blendSrc),this.blendDst!==ud&&(s.blendDst=this.blendDst),this.blendEquation!==Fs&&(s.blendEquation=this.blendEquation),this.blendSrcAlpha!==null&&(s.blendSrcAlpha=this.blendSrcAlpha),this.blendDstAlpha!==null&&(s.blendDstAlpha=this.blendDstAlpha),this.blendEquationAlpha!==null&&(s.blendEquationAlpha=this.blendEquationAlpha),this.blendColor&&this.blendColor.isColor&&(s.blendColor=this.blendColor.getHex()),this.blendAlpha!==0&&(s.blendAlpha=this.blendAlpha),this.depthFunc!==Vr&&(s.depthFunc=this.depthFunc),this.depthTest===!1&&(s.depthTest=this.depthTest),this.depthWrite===!1&&(s.depthWrite=this.depthWrite),this.colorWrite===!1&&(s.colorWrite=this.colorWrite),this.stencilWriteMask!==255&&(s.stencilWriteMask=this.stencilWriteMask),this.stencilFunc!==Sv&&(s.stencilFunc=this.stencilFunc),this.stencilRef!==0&&(s.stencilRef=this.stencilRef),this.stencilFuncMask!==255&&(s.stencilFuncMask=this.stencilFuncMask),this.stencilFail!==br&&(s.stencilFail=this.stencilFail),this.stencilZFail!==br&&(s.stencilZFail=this.stencilZFail),this.stencilZPass!==br&&(s.stencilZPass=this.stencilZPass),this.stencilWrite===!0&&(s.stencilWrite=this.stencilWrite),this.rotation!==void 0&&this.rotation!==0&&(s.rotation=this.rotation),this.polygonOffset===!0&&(s.polygonOffset=!0),this.polygonOffsetFactor!==0&&(s.polygonOffsetFactor=this.polygonOffsetFactor),this.polygonOffsetUnits!==0&&(s.polygonOffsetUnits=this.polygonOffsetUnits),this.linewidth!==void 0&&this.linewidth!==1&&(s.linewidth=this.linewidth),this.dashSize!==void 0&&(s.dashSize=this.dashSize),this.gapSize!==void 0&&(s.gapSize=this.gapSize),this.scale!==void 0&&(s.scale=this.scale),this.dithering===!0&&(s.dithering=!0),this.alphaTest>0&&(s.alphaTest=this.alphaTest),this.alphaHash===!0&&(s.alphaHash=!0),this.alphaToCoverage===!0&&(s.alphaToCoverage=!0),this.premultipliedAlpha===!0&&(s.premultipliedAlpha=!0),this.forceSinglePass===!0&&(s.forceSinglePass=!0),this.allowOverride===!1&&(s.allowOverride=!1),this.wireframe===!0&&(s.wireframe=!0),this.wireframeLinewidth>1&&(s.wireframeLinewidth=this.wireframeLinewidth),this.wireframeLinecap!=="round"&&(s.wireframeLinecap=this.wireframeLinecap),this.wireframeLinejoin!=="round"&&(s.wireframeLinejoin=this.wireframeLinejoin),this.flatShading===!0&&(s.flatShading=!0),this.visible===!1&&(s.visible=!1),this.toneMapped===!1&&(s.toneMapped=!1),this.fog===!1&&(s.fog=!1),Object.keys(this.userData).length>0&&(s.userData=this.userData);function l(c){const f=[];for(const d in c){const m=c[d];delete m.metadata,f.push(m)}return f}if(n){const c=l(t.textures),f=l(t.images);c.length>0&&(s.textures=c),f.length>0&&(s.images=f)}return s}fromJSON(t,n){if(t.uuid!==void 0&&(this.uuid=t.uuid),t.name!==void 0&&(this.name=t.name),t.color!==void 0&&this.color!==void 0&&this.color.setHex(t.color),t.roughness!==void 0&&(this.roughness=t.roughness),t.metalness!==void 0&&(this.metalness=t.metalness),t.sheen!==void 0&&(this.sheen=t.sheen),t.sheenColor!==void 0&&(this.sheenColor=new fe().setHex(t.sheenColor)),t.sheenRoughness!==void 0&&(this.sheenRoughness=t.sheenRoughness),t.emissive!==void 0&&this.emissive!==void 0&&this.emissive.setHex(t.emissive),t.specular!==void 0&&this.specular!==void 0&&this.specular.setHex(t.specular),t.specularIntensity!==void 0&&(this.specularIntensity=t.specularIntensity),t.specularColor!==void 0&&this.specularColor!==void 0&&this.specularColor.setHex(t.specularColor),t.shininess!==void 0&&(this.shininess=t.shininess),t.clearcoat!==void 0&&(this.clearcoat=t.clearcoat),t.clearcoatRoughness!==void 0&&(this.clearcoatRoughness=t.clearcoatRoughness),t.dispersion!==void 0&&(this.dispersion=t.dispersion),t.iridescence!==void 0&&(this.iridescence=t.iridescence),t.iridescenceIOR!==void 0&&(this.iridescenceIOR=t.iridescenceIOR),t.iridescenceThicknessRange!==void 0&&(this.iridescenceThicknessRange=t.iridescenceThicknessRange),t.transmission!==void 0&&(this.transmission=t.transmission),t.thickness!==void 0&&(this.thickness=t.thickness),t.attenuationDistance!==void 0&&(this.attenuationDistance=t.attenuationDistance),t.attenuationColor!==void 0&&this.attenuationColor!==void 0&&this.attenuationColor.setHex(t.attenuationColor),t.anisotropy!==void 0&&(this.anisotropy=t.anisotropy),t.anisotropyRotation!==void 0&&(this.anisotropyRotation=t.anisotropyRotation),t.fog!==void 0&&(this.fog=t.fog),t.flatShading!==void 0&&(this.flatShading=t.flatShading),t.blending!==void 0&&(this.blending=t.blending),t.combine!==void 0&&(this.combine=t.combine),t.side!==void 0&&(this.side=t.side),t.shadowSide!==void 0&&(this.shadowSide=t.shadowSide),t.opacity!==void 0&&(this.opacity=t.opacity),t.transparent!==void 0&&(this.transparent=t.transparent),t.alphaTest!==void 0&&(this.alphaTest=t.alphaTest),t.alphaHash!==void 0&&(this.alphaHash=t.alphaHash),t.depthFunc!==void 0&&(this.depthFunc=t.depthFunc),t.depthTest!==void 0&&(this.depthTest=t.depthTest),t.depthWrite!==void 0&&(this.depthWrite=t.depthWrite),t.colorWrite!==void 0&&(this.colorWrite=t.colorWrite),t.blendSrc!==void 0&&(this.blendSrc=t.blendSrc),t.blendDst!==void 0&&(this.blendDst=t.blendDst),t.blendEquation!==void 0&&(this.blendEquation=t.blendEquation),t.blendSrcAlpha!==void 0&&(this.blendSrcAlpha=t.blendSrcAlpha),t.blendDstAlpha!==void 0&&(this.blendDstAlpha=t.blendDstAlpha),t.blendEquationAlpha!==void 0&&(this.blendEquationAlpha=t.blendEquationAlpha),t.blendColor!==void 0&&this.blendColor!==void 0&&this.blendColor.setHex(t.blendColor),t.blendAlpha!==void 0&&(this.blendAlpha=t.blendAlpha),t.stencilWriteMask!==void 0&&(this.stencilWriteMask=t.stencilWriteMask),t.stencilFunc!==void 0&&(this.stencilFunc=t.stencilFunc),t.stencilRef!==void 0&&(this.stencilRef=t.stencilRef),t.stencilFuncMask!==void 0&&(this.stencilFuncMask=t.stencilFuncMask),t.stencilFail!==void 0&&(this.stencilFail=t.stencilFail),t.stencilZFail!==void 0&&(this.stencilZFail=t.stencilZFail),t.stencilZPass!==void 0&&(this.stencilZPass=t.stencilZPass),t.stencilWrite!==void 0&&(this.stencilWrite=t.stencilWrite),t.wireframe!==void 0&&(this.wireframe=t.wireframe),t.wireframeLinewidth!==void 0&&(this.wireframeLinewidth=t.wireframeLinewidth),t.wireframeLinecap!==void 0&&(this.wireframeLinecap=t.wireframeLinecap),t.wireframeLinejoin!==void 0&&(this.wireframeLinejoin=t.wireframeLinejoin),t.rotation!==void 0&&(this.rotation=t.rotation),t.linewidth!==void 0&&(this.linewidth=t.linewidth),t.dashSize!==void 0&&(this.dashSize=t.dashSize),t.gapSize!==void 0&&(this.gapSize=t.gapSize),t.scale!==void 0&&(this.scale=t.scale),t.polygonOffset!==void 0&&(this.polygonOffset=t.polygonOffset),t.polygonOffsetFactor!==void 0&&(this.polygonOffsetFactor=t.polygonOffsetFactor),t.polygonOffsetUnits!==void 0&&(this.polygonOffsetUnits=t.polygonOffsetUnits),t.dithering!==void 0&&(this.dithering=t.dithering),t.alphaToCoverage!==void 0&&(this.alphaToCoverage=t.alphaToCoverage),t.premultipliedAlpha!==void 0&&(this.premultipliedAlpha=t.premultipliedAlpha),t.forceSinglePass!==void 0&&(this.forceSinglePass=t.forceSinglePass),t.allowOverride!==void 0&&(this.allowOverride=t.allowOverride),t.visible!==void 0&&(this.visible=t.visible),t.toneMapped!==void 0&&(this.toneMapped=t.toneMapped),t.userData!==void 0&&(this.userData=t.userData),t.vertexColors!==void 0&&(typeof t.vertexColors=="number"?this.vertexColors=t.vertexColors>0:this.vertexColors=t.vertexColors),t.size!==void 0&&(this.size=t.size),t.sizeAttenuation!==void 0&&(this.sizeAttenuation=t.sizeAttenuation),t.map!==void 0&&(this.map=n[t.map]||null),t.matcap!==void 0&&(this.matcap=n[t.matcap]||null),t.alphaMap!==void 0&&(this.alphaMap=n[t.alphaMap]||null),t.bumpMap!==void 0&&(this.bumpMap=n[t.bumpMap]||null),t.bumpScale!==void 0&&(this.bumpScale=t.bumpScale),t.normalMap!==void 0&&(this.normalMap=n[t.normalMap]||null),t.normalMapType!==void 0&&(this.normalMapType=t.normalMapType),t.normalScale!==void 0){let s=t.normalScale;Array.isArray(s)===!1&&(s=[s,s]),this.normalScale=new qt().fromArray(s)}return t.displacementMap!==void 0&&(this.displacementMap=n[t.displacementMap]||null),t.displacementScale!==void 0&&(this.displacementScale=t.displacementScale),t.displacementBias!==void 0&&(this.displacementBias=t.displacementBias),t.roughnessMap!==void 0&&(this.roughnessMap=n[t.roughnessMap]||null),t.metalnessMap!==void 0&&(this.metalnessMap=n[t.metalnessMap]||null),t.emissiveMap!==void 0&&(this.emissiveMap=n[t.emissiveMap]||null),t.emissiveIntensity!==void 0&&(this.emissiveIntensity=t.emissiveIntensity),t.specularMap!==void 0&&(this.specularMap=n[t.specularMap]||null),t.specularIntensityMap!==void 0&&(this.specularIntensityMap=n[t.specularIntensityMap]||null),t.specularColorMap!==void 0&&(this.specularColorMap=n[t.specularColorMap]||null),t.envMap!==void 0&&(this.envMap=n[t.envMap]||null),t.envMapRotation!==void 0&&this.envMapRotation.fromArray(t.envMapRotation),t.envMapIntensity!==void 0&&(this.envMapIntensity=t.envMapIntensity),t.reflectivity!==void 0&&(this.reflectivity=t.reflectivity),t.refractionRatio!==void 0&&(this.refractionRatio=t.refractionRatio),t.lightMap!==void 0&&(this.lightMap=n[t.lightMap]||null),t.lightMapIntensity!==void 0&&(this.lightMapIntensity=t.lightMapIntensity),t.aoMap!==void 0&&(this.aoMap=n[t.aoMap]||null),t.aoMapIntensity!==void 0&&(this.aoMapIntensity=t.aoMapIntensity),t.gradientMap!==void 0&&(this.gradientMap=n[t.gradientMap]||null),t.clearcoatMap!==void 0&&(this.clearcoatMap=n[t.clearcoatMap]||null),t.clearcoatRoughnessMap!==void 0&&(this.clearcoatRoughnessMap=n[t.clearcoatRoughnessMap]||null),t.clearcoatNormalMap!==void 0&&(this.clearcoatNormalMap=n[t.clearcoatNormalMap]||null),t.clearcoatNormalScale!==void 0&&(this.clearcoatNormalScale=new qt().fromArray(t.clearcoatNormalScale)),t.iridescenceMap!==void 0&&(this.iridescenceMap=n[t.iridescenceMap]||null),t.iridescenceThicknessMap!==void 0&&(this.iridescenceThicknessMap=n[t.iridescenceThicknessMap]||null),t.transmissionMap!==void 0&&(this.transmissionMap=n[t.transmissionMap]||null),t.thicknessMap!==void 0&&(this.thicknessMap=n[t.thicknessMap]||null),t.anisotropyMap!==void 0&&(this.anisotropyMap=n[t.anisotropyMap]||null),t.sheenColorMap!==void 0&&(this.sheenColorMap=n[t.sheenColorMap]||null),t.sheenRoughnessMap!==void 0&&(this.sheenRoughnessMap=n[t.sheenRoughnessMap]||null),this}clone(){return new this.constructor().copy(this)}copy(t){this.name=t.name,this.blending=t.blending,this.side=t.side,this.vertexColors=t.vertexColors,this.opacity=t.opacity,this.transparent=t.transparent,this.blendSrc=t.blendSrc,this.blendDst=t.blendDst,this.blendEquation=t.blendEquation,this.blendSrcAlpha=t.blendSrcAlpha,this.blendDstAlpha=t.blendDstAlpha,this.blendEquationAlpha=t.blendEquationAlpha,this.blendColor.copy(t.blendColor),this.blendAlpha=t.blendAlpha,this.depthFunc=t.depthFunc,this.depthTest=t.depthTest,this.depthWrite=t.depthWrite,this.stencilWriteMask=t.stencilWriteMask,this.stencilFunc=t.stencilFunc,this.stencilRef=t.stencilRef,this.stencilFuncMask=t.stencilFuncMask,this.stencilFail=t.stencilFail,this.stencilZFail=t.stencilZFail,this.stencilZPass=t.stencilZPass,this.stencilWrite=t.stencilWrite;const n=t.clippingPlanes;let s=null;if(n!==null){const l=n.length;s=new Array(l);for(let c=0;c!==l;++c)s[c]=n[c].clone()}return this.clippingPlanes=s,this.clipIntersection=t.clipIntersection,this.clipShadows=t.clipShadows,this.shadowSide=t.shadowSide,this.colorWrite=t.colorWrite,this.precision=t.precision,this.polygonOffset=t.polygonOffset,this.polygonOffsetFactor=t.polygonOffsetFactor,this.polygonOffsetUnits=t.polygonOffsetUnits,this.dithering=t.dithering,this.alphaTest=t.alphaTest,this.alphaHash=t.alphaHash,this.alphaToCoverage=t.alphaToCoverage,this.premultipliedAlpha=t.premultipliedAlpha,this.forceSinglePass=t.forceSinglePass,this.allowOverride=t.allowOverride,this.visible=t.visible,this.toneMapped=t.toneMapped,this.userData=JSON.parse(JSON.stringify(t.userData)),this}dispose(){this.dispatchEvent({type:"dispose"})}set needsUpdate(t){t===!0&&this.version++}}const ya=new K,qh=new K,Nc=new K,ss=new K,Yh=new K,Uc=new K,Zh=new K;class FM{constructor(t=new K,n=new K(0,0,-1)){this.origin=t,this.direction=n}set(t,n){return this.origin.copy(t),this.direction.copy(n),this}copy(t){return this.origin.copy(t.origin),this.direction.copy(t.direction),this}at(t,n){return n.copy(this.origin).addScaledVector(this.direction,t)}lookAt(t){return this.direction.copy(t).sub(this.origin).normalize(),this}recast(t){return this.origin.copy(this.at(t,ya)),this}closestPointToPoint(t,n){n.subVectors(t,this.origin);const s=n.dot(this.direction);return s<0?n.copy(this.origin):n.copy(this.origin).addScaledVector(this.direction,s)}distanceToPoint(t){return Math.sqrt(this.distanceSqToPoint(t))}distanceSqToPoint(t){const n=ya.subVectors(t,this.origin).dot(this.direction);return n<0?this.origin.distanceToSquared(t):(ya.copy(this.origin).addScaledVector(this.direction,n),ya.distanceToSquared(t))}distanceSqToSegment(t,n,s,l){qh.copy(t).add(n).multiplyScalar(.5),Nc.copy(n).sub(t).normalize(),ss.copy(this.origin).sub(qh);const c=t.distanceTo(n)*.5,f=-this.direction.dot(Nc),d=ss.dot(this.direction),m=-ss.dot(Nc),p=ss.lengthSq(),v=Math.abs(1-f*f);let _,g,y,b;if(v>0)if(_=f*m-d,g=f*d-m,b=c*v,_>=0)if(g>=-b)if(g<=b){const w=1/v;_*=w,g*=w,y=_*(_+f*g+2*d)+g*(f*_+g+2*m)+p}else g=c,_=Math.max(0,-(f*g+d)),y=-_*_+g*(g+2*m)+p;else g=-c,_=Math.max(0,-(f*g+d)),y=-_*_+g*(g+2*m)+p;else g<=-b?(_=Math.max(0,-(-f*c+d)),g=_>0?-c:Math.min(Math.max(-c,-m),c),y=-_*_+g*(g+2*m)+p):g<=b?(_=0,g=Math.min(Math.max(-c,-m),c),y=g*(g+2*m)+p):(_=Math.max(0,-(f*c+d)),g=_>0?c:Math.min(Math.max(-c,-m),c),y=-_*_+g*(g+2*m)+p);else g=f>0?-c:c,_=Math.max(0,-(f*g+d)),y=-_*_+g*(g+2*m)+p;return s&&s.copy(this.origin).addScaledVector(this.direction,_),l&&l.copy(qh).addScaledVector(Nc,g),y}intersectSphere(t,n){ya.subVectors(t.center,this.origin);const s=ya.dot(this.direction),l=ya.dot(ya)-s*s,c=t.radius*t.radius;if(l>c)return null;const f=Math.sqrt(c-l),d=s-f,m=s+f;return m<0?null:d<0?this.at(m,n):this.at(d,n)}intersectsSphere(t){return t.radius<0?!1:this.distanceSqToPoint(t.center)<=t.radius*t.radius}distanceToPlane(t){const n=t.normal.dot(this.direction);if(n===0)return t.distanceToPoint(this.origin)===0?0:null;const s=-(this.origin.dot(t.normal)+t.constant)/n;return s>=0?s:null}intersectPlane(t,n){const s=this.distanceToPlane(t);return s===null?null:this.at(s,n)}intersectsPlane(t){const n=t.distanceToPoint(this.origin);return n===0||t.normal.dot(this.direction)*n<0}intersectBox(t,n){let s,l,c,f,d,m;const p=1/this.direction.x,v=1/this.direction.y,_=1/this.direction.z,g=this.origin;return p>=0?(s=(t.min.x-g.x)*p,l=(t.max.x-g.x)*p):(s=(t.max.x-g.x)*p,l=(t.min.x-g.x)*p),v>=0?(c=(t.min.y-g.y)*v,f=(t.max.y-g.y)*v):(c=(t.max.y-g.y)*v,f=(t.min.y-g.y)*v),s>f||c>l||((c>s||isNaN(s))&&(s=c),(f<l||isNaN(l))&&(l=f),_>=0?(d=(t.min.z-g.z)*_,m=(t.max.z-g.z)*_):(d=(t.max.z-g.z)*_,m=(t.min.z-g.z)*_),s>m||d>l)||((d>s||s!==s)&&(s=d),(m<l||l!==l)&&(l=m),l<0)?null:this.at(s>=0?s:l,n)}intersectsBox(t){return this.intersectBox(t,ya)!==null}intersectTriangle(t,n,s,l,c){Yh.subVectors(n,t),Uc.subVectors(s,t),Zh.crossVectors(Yh,Uc);let f=this.direction.dot(Zh),d;if(f>0){if(l)return null;d=1}else if(f<0)d=-1,f=-f;else return null;ss.subVectors(this.origin,t);const m=d*this.direction.dot(Uc.crossVectors(ss,Uc));if(m<0)return null;const p=d*this.direction.dot(Yh.cross(ss));if(p<0||m+p>f)return null;const v=-d*ss.dot(Zh);return v<0?null:this.at(v/f,c)}applyMatrix4(t){return this.origin.applyMatrix4(t),this.direction.transformDirection(t),this}equals(t){return t.origin.equals(this.origin)&&t.direction.equals(this.direction)}clone(){return new this.constructor().copy(this)}}class $o extends ul{constructor(t){super(),this.isMeshBasicMaterial=!0,this.type="MeshBasicMaterial",this.color=new fe(16777215),this.map=null,this.lightMap=null,this.lightMapIntensity=1,this.aoMap=null,this.aoMapIntensity=1,this.specularMap=null,this.alphaMap=null,this.envMap=null,this.envMapRotation=new fs,this.combine=P_,this.reflectivity=1,this.refractionRatio=.98,this.wireframe=!1,this.wireframeLinewidth=1,this.wireframeLinecap="round",this.wireframeLinejoin="round",this.fog=!0,this.setValues(t)}copy(t){return super.copy(t),this.color.copy(t.color),this.map=t.map,this.lightMap=t.lightMap,this.lightMapIntensity=t.lightMapIntensity,this.aoMap=t.aoMap,this.aoMapIntensity=t.aoMapIntensity,this.specularMap=t.specularMap,this.alphaMap=t.alphaMap,this.envMap=t.envMap,this.envMapRotation.copy(t.envMapRotation),this.combine=t.combine,this.reflectivity=t.reflectivity,this.refractionRatio=t.refractionRatio,this.wireframe=t.wireframe,this.wireframeLinewidth=t.wireframeLinewidth,this.wireframeLinecap=t.wireframeLinecap,this.wireframeLinejoin=t.wireframeLinejoin,this.fog=t.fog,this}}const zv=new en,Os=new FM,Lc=new mp,Fv=new K,Oc=new K,Pc=new K,Ic=new K,Kh=new K,zc=new K,Bv=new K,Fc=new K;class un extends On{constructor(t=new Xn,n=new $o){super(),this.isMesh=!0,this.type="Mesh",this.geometry=t,this.material=n,this.morphTargetDictionary=void 0,this.morphTargetInfluences=void 0,this.count=1,this.updateMorphTargets()}copy(t,n){return super.copy(t,n),t.morphTargetInfluences!==void 0&&(this.morphTargetInfluences=t.morphTargetInfluences.slice()),t.morphTargetDictionary!==void 0&&(this.morphTargetDictionary=Object.assign({},t.morphTargetDictionary)),this.material=Array.isArray(t.material)?t.material.slice():t.material,this.geometry=t.geometry,this}updateMorphTargets(){const n=this.geometry.morphAttributes,s=Object.keys(n);if(s.length>0){const l=n[s[0]];if(l!==void 0){this.morphTargetInfluences=[],this.morphTargetDictionary={};for(let c=0,f=l.length;c<f;c++){const d=l[c].name||String(c);this.morphTargetInfluences.push(0),this.morphTargetDictionary[d]=c}}}}getVertexPosition(t,n){const s=this.geometry,l=s.attributes.position,c=s.morphAttributes.position,f=s.morphTargetsRelative;n.fromBufferAttribute(l,t);const d=this.morphTargetInfluences;if(c&&d){zc.set(0,0,0);for(let m=0,p=c.length;m<p;m++){const v=d[m],_=c[m];v!==0&&(Kh.fromBufferAttribute(_,t),f?zc.addScaledVector(Kh,v):zc.addScaledVector(Kh.sub(n),v))}n.add(zc)}return n}raycast(t,n){const s=this.geometry,l=this.material,c=this.matrixWorld;l!==void 0&&(s.boundingSphere===null&&s.computeBoundingSphere(),Lc.copy(s.boundingSphere),Lc.applyMatrix4(c),Os.copy(t.ray).recast(t.near),!(Lc.containsPoint(Os.origin)===!1&&(Os.intersectSphere(Lc,Fv)===null||Os.origin.distanceToSquared(Fv)>(t.far-t.near)**2))&&(zv.copy(c).invert(),Os.copy(t.ray).applyMatrix4(zv),!(s.boundingBox!==null&&Os.intersectsBox(s.boundingBox)===!1)&&this._computeIntersections(t,n,Os)))}_computeIntersections(t,n,s){let l;const c=this.geometry,f=this.material,d=c.index,m=c.attributes.position,p=c.attributes.uv,v=c.attributes.uv1,_=c.attributes.normal,g=c.groups,y=c.drawRange;if(d!==null)if(Array.isArray(f))for(let b=0,w=g.length;b<w;b++){const M=g[b],S=f[M.materialIndex],P=Math.max(M.start,y.start),D=Math.min(d.count,Math.min(M.start+M.count,y.start+y.count));for(let A=P,F=D;A<F;A+=3){const O=d.getX(A),I=d.getX(A+1),T=d.getX(A+2);l=Bc(this,S,t,s,p,v,_,O,I,T),l&&(l.faceIndex=Math.floor(A/3),l.face.materialIndex=M.materialIndex,n.push(l))}}else{const b=Math.max(0,y.start),w=Math.min(d.count,y.start+y.count);for(let M=b,S=w;M<S;M+=3){const P=d.getX(M),D=d.getX(M+1),A=d.getX(M+2);l=Bc(this,f,t,s,p,v,_,P,D,A),l&&(l.faceIndex=Math.floor(M/3),n.push(l))}}else if(m!==void 0)if(Array.isArray(f))for(let b=0,w=g.length;b<w;b++){const M=g[b],S=f[M.materialIndex],P=Math.max(M.start,y.start),D=Math.min(m.count,Math.min(M.start+M.count,y.start+y.count));for(let A=P,F=D;A<F;A+=3){const O=A,I=A+1,T=A+2;l=Bc(this,S,t,s,p,v,_,O,I,T),l&&(l.faceIndex=Math.floor(A/3),l.face.materialIndex=M.materialIndex,n.push(l))}}else{const b=Math.max(0,y.start),w=Math.min(m.count,y.start+y.count);for(let M=b,S=w;M<S;M+=3){const P=M,D=M+1,A=M+2;l=Bc(this,f,t,s,p,v,_,P,D,A),l&&(l.faceIndex=Math.floor(M/3),n.push(l))}}}}function BM(r,t,n,s,l,c,f,d){let m;if(t.side===Vn?m=s.intersectTriangle(f,c,l,!0,d):m=s.intersectTriangle(l,c,f,t.side===us,d),m===null)return null;Fc.copy(d),Fc.applyMatrix4(r.matrixWorld);const p=n.ray.origin.distanceTo(Fc);return p<n.near||p>n.far?null:{distance:p,point:Fc.clone(),object:r}}function Bc(r,t,n,s,l,c,f,d,m,p){r.getVertexPosition(d,Oc),r.getVertexPosition(m,Pc),r.getVertexPosition(p,Ic);const v=BM(r,t,n,s,Oc,Pc,Ic,Bv);if(v){const _=new K;Oi.getBarycoord(Bv,Oc,Pc,Ic,_),l&&(v.uv=Oi.getInterpolatedAttribute(l,d,m,p,_,new qt)),c&&(v.uv1=Oi.getInterpolatedAttribute(c,d,m,p,_,new qt)),f&&(v.normal=Oi.getInterpolatedAttribute(f,d,m,p,_,new K),v.normal.dot(s.direction)>0&&v.normal.multiplyScalar(-1));const g={a:d,b:m,c:p,normal:new K,materialIndex:0};Oi.getNormal(Oc,Pc,Ic,g.normal),v.face=g,v.barycoord=_}return v}class HM extends kn{constructor(t=null,n=1,s=1,l,c,f,d,m,p=Ln,v=Ln,_,g){super(null,f,d,m,p,v,l,c,_,g),this.isDataTexture=!0,this.image={data:t,width:n,height:s},this.generateMipmaps=!1,this.flipY=!1,this.unpackAlignment=1}}const jh=new K,GM=new K,VM=new re;class zs{constructor(t=new K(1,0,0),n=0){this.isPlane=!0,this.normal=t,this.constant=n}set(t,n){return this.normal.copy(t),this.constant=n,this}setComponents(t,n,s,l){return this.normal.set(t,n,s),this.constant=l,this}setFromNormalAndCoplanarPoint(t,n){return this.normal.copy(t),this.constant=-n.dot(this.normal),this}setFromCoplanarPoints(t,n,s){const l=jh.subVectors(s,n).cross(GM.subVectors(t,n)).normalize();return this.setFromNormalAndCoplanarPoint(l,t),this}copy(t){return this.normal.copy(t.normal),this.constant=t.constant,this}normalize(){const t=1/this.normal.length();return this.normal.multiplyScalar(t),this.constant*=t,this}negate(){return this.constant*=-1,this.normal.negate(),this}distanceToPoint(t){return this.normal.dot(t)+this.constant}distanceToSphere(t){return this.distanceToPoint(t.center)-t.radius}projectPoint(t,n){return n.copy(t).addScaledVector(this.normal,-this.distanceToPoint(t))}intersectLine(t,n,s=!0){const l=t.delta(jh),c=this.normal.dot(l);if(c===0)return this.distanceToPoint(t.start)===0?n.copy(t.start):null;const f=-(t.start.dot(this.normal)+this.constant)/c;return s===!0&&(f<0||f>1)?null:n.copy(t.start).addScaledVector(l,f)}intersectsLine(t){const n=this.distanceToPoint(t.start),s=this.distanceToPoint(t.end);return n<0&&s>0||s<0&&n>0}intersectsBox(t){return t.intersectsPlane(this)}intersectsSphere(t){return t.intersectsPlane(this)}coplanarPoint(t){return t.copy(this.normal).multiplyScalar(-this.constant)}applyMatrix4(t,n){const s=n||VM.getNormalMatrix(t),l=this.coplanarPoint(jh).applyMatrix4(t),c=this.normal.applyMatrix3(s).normalize();return this.constant=-l.dot(c),this}translate(t){return this.constant-=t.dot(this.normal),this}equals(t){return t.normal.equals(this.normal)&&t.constant===this.constant}clone(){return new this.constructor().copy(this)}}const Ps=new mp,kM=new qt(.5,.5),Hc=new K;class gp{constructor(t=new zs,n=new zs,s=new zs,l=new zs,c=new zs,f=new zs){this.planes=[t,n,s,l,c,f]}set(t,n,s,l,c,f){const d=this.planes;return d[0].copy(t),d[1].copy(n),d[2].copy(s),d[3].copy(l),d[4].copy(c),d[5].copy(f),this}copy(t){const n=this.planes;for(let s=0;s<6;s++)n[s].copy(t.planes[s]);return this}setFromProjectionMatrix(t,n=qi,s=!1){const l=this.planes,c=t.elements,f=c[0],d=c[1],m=c[2],p=c[3],v=c[4],_=c[5],g=c[6],y=c[7],b=c[8],w=c[9],M=c[10],S=c[11],P=c[12],D=c[13],A=c[14],F=c[15];if(l[0].setComponents(p-f,y-v,S-b,F-P).normalize(),l[1].setComponents(p+f,y+v,S+b,F+P).normalize(),l[2].setComponents(p+d,y+_,S+w,F+D).normalize(),l[3].setComponents(p-d,y-_,S-w,F-D).normalize(),s)l[4].setComponents(m,g,M,A).normalize(),l[5].setComponents(p-m,y-g,S-M,F-A).normalize();else if(l[4].setComponents(p-m,y-g,S-M,F-A).normalize(),n===qi)l[5].setComponents(p+m,y+g,S+M,F+A).normalize();else if(n===sl)l[5].setComponents(m,g,M,A).normalize();else throw new Error("THREE.Frustum.setFromProjectionMatrix(): Invalid coordinate system: "+n);return this}intersectsObject(t){if(t.boundingSphere!==void 0)t.boundingSphere===null&&t.computeBoundingSphere(),Ps.copy(t.boundingSphere).applyMatrix4(t.matrixWorld);else{const n=t.geometry;n.boundingSphere===null&&n.computeBoundingSphere(),Ps.copy(n.boundingSphere).applyMatrix4(t.matrixWorld)}return this.intersectsSphere(Ps)}intersectsSprite(t){Ps.center.set(0,0,0);const n=kM.distanceTo(t.center);return Ps.radius=.7071067811865476+n,Ps.applyMatrix4(t.matrixWorld),this.intersectsSphere(Ps)}intersectsSphere(t){const n=this.planes,s=t.center,l=-t.radius;for(let c=0;c<6;c++)if(n[c].distanceToPoint(s)<l)return!1;return!0}intersectsBox(t){const n=this.planes;for(let s=0;s<6;s++){const l=n[s];if(Hc.x=l.normal.x>0?t.max.x:t.min.x,Hc.y=l.normal.y>0?t.max.y:t.min.y,Hc.z=l.normal.z>0?t.max.z:t.min.z,l.distanceToPoint(Hc)<0)return!1}return!0}containsPoint(t){const n=this.planes;for(let s=0;s<6;s++)if(n[s].distanceToPoint(t)<0)return!1;return!0}clone(){return new this.constructor().copy(this)}}class ix extends kn{constructor(t=[],n=Vs,s,l,c,f,d,m,p,v){super(t,n,s,l,c,f,d,m,p,v),this.isCubeTexture=!0,this.flipY=!1}get images(){return this.image}set images(t){this.image=t}}class Xr extends kn{constructor(t,n,s=ji,l,c,f,d=Ln,m=Ln,p,v=Ra,_=1){if(v!==Ra&&v!==Gs)throw new Error("THREE.DepthTexture: format must be either THREE.DepthFormat or THREE.DepthStencilFormat");const g={width:t,height:n,depth:_};super(g,l,c,f,d,m,v,s,p),this.isDepthTexture=!0,this.flipY=!1,this.generateMipmaps=!1,this.compareFunction=null}copy(t){return super.copy(t),this.source=new dp(Object.assign({},t.image)),this.compareFunction=t.compareFunction,this}toJSON(t){const n=super.toJSON(t);return this.compareFunction!==null&&(n.compareFunction=this.compareFunction),n}}class XM extends Xr{constructor(t,n=ji,s=Vs,l,c,f=Ln,d=Ln,m,p=Ra){const v={width:t,height:t,depth:1},_=[v,v,v,v,v,v];super(t,t,n,s,l,c,f,d,m,p),this.image=_,this.isCubeDepthTexture=!0,this.isCubeTexture=!0}get images(){return this.image}set images(t){this.image=t}}class ax extends kn{constructor(t=null){super(),this.sourceTexture=t,this.isExternalTexture=!0}copy(t){return super.copy(t),this.sourceTexture=t.sourceTexture,this}}class cs extends Xn{constructor(t=1,n=1,s=1,l=1,c=1,f=1){super(),this.type="BoxGeometry",this.parameters={width:t,height:n,depth:s,widthSegments:l,heightSegments:c,depthSegments:f};const d=this;l=Math.floor(l),c=Math.floor(c),f=Math.floor(f);const m=[],p=[],v=[],_=[];let g=0,y=0;b("z","y","x",-1,-1,s,n,t,f,c,0),b("z","y","x",1,-1,s,n,-t,f,c,1),b("x","z","y",1,1,t,s,n,l,f,2),b("x","z","y",1,-1,t,s,-n,l,f,3),b("x","y","z",1,-1,t,n,s,l,c,4),b("x","y","z",-1,-1,t,n,-s,l,c,5),this.setIndex(m),this.setAttribute("position",new Xe(p,3)),this.setAttribute("normal",new Xe(v,3)),this.setAttribute("uv",new Xe(_,2));function b(w,M,S,P,D,A,F,O,I,T,N){const X=A/I,V=F/T,q=A/2,ct=F/2,ht=O/2,j=I+1,B=T+1;let H=0,$=0;const dt=new K;for(let Mt=0;Mt<B;Mt++){const U=Mt*V-ct;for(let J=0;J<j;J++){const bt=J*X-q;dt[w]=bt*P,dt[M]=U*D,dt[S]=ht,p.push(dt.x,dt.y,dt.z),dt[w]=0,dt[M]=0,dt[S]=O>0?1:-1,v.push(dt.x,dt.y,dt.z),_.push(J/I),_.push(1-Mt/T),H+=1}}for(let Mt=0;Mt<T;Mt++)for(let U=0;U<I;U++){const J=g+U+j*Mt,bt=g+U+j*(Mt+1),pt=g+(U+1)+j*(Mt+1),At=g+(U+1)+j*Mt;m.push(J,bt,At),m.push(bt,pt,At),$+=6}d.addGroup(y,$,N),y+=$,g+=H}}copy(t){return super.copy(t),this.parameters=Object.assign({},t.parameters),this}static fromJSON(t){return new cs(t.width,t.height,t.depth,t.widthSegments,t.heightSegments,t.depthSegments)}}class vp extends Xn{constructor(t=1,n=32,s=0,l=Math.PI*2){super(),this.type="CircleGeometry",this.parameters={radius:t,segments:n,thetaStart:s,thetaLength:l},n=Math.max(3,n);const c=[],f=[],d=[],m=[],p=new K,v=new qt;f.push(0,0,0),d.push(0,0,1),m.push(.5,.5);for(let _=0,g=3;_<=n;_++,g+=3){const y=s+_/n*l;p.x=t*Math.cos(y),p.y=t*Math.sin(y),f.push(p.x,p.y,p.z),d.push(0,0,1),v.x=(f[g]/t+1)/2,v.y=(f[g+1]/t+1)/2,m.push(v.x,v.y)}for(let _=1;_<=n;_++)c.push(_,_+1,0);this.setIndex(c),this.setAttribute("position",new Xe(f,3)),this.setAttribute("normal",new Xe(d,3)),this.setAttribute("uv",new Xe(m,2))}copy(t){return super.copy(t),this.parameters=Object.assign({},t.parameters),this}static fromJSON(t){return new vp(t.radius,t.segments,t.thetaStart,t.thetaLength)}}class ou extends Xn{constructor(t=1,n=1,s=1,l=32,c=1,f=!1,d=0,m=Math.PI*2){super(),this.type="CylinderGeometry",this.parameters={radiusTop:t,radiusBottom:n,height:s,radialSegments:l,heightSegments:c,openEnded:f,thetaStart:d,thetaLength:m};const p=this;l=Math.floor(l),c=Math.floor(c);const v=[],_=[],g=[],y=[];let b=0;const w=[],M=s/2;let S=0;P(),f===!1&&(t>0&&D(!0),n>0&&D(!1)),this.setIndex(v),this.setAttribute("position",new Xe(_,3)),this.setAttribute("normal",new Xe(g,3)),this.setAttribute("uv",new Xe(y,2));function P(){const A=new K,F=new K;let O=0;const I=(n-t)/s;for(let T=0;T<=c;T++){const N=[],X=T/c,V=X*(n-t)+t;for(let q=0;q<=l;q++){const ct=q/l,ht=ct*m+d,j=Math.sin(ht),B=Math.cos(ht);F.x=V*j,F.y=-X*s+M,F.z=V*B,_.push(F.x,F.y,F.z),A.set(j,I,B).normalize(),g.push(A.x,A.y,A.z),y.push(ct,1-X),N.push(b++)}w.push(N)}for(let T=0;T<l;T++)for(let N=0;N<c;N++){const X=w[N][T],V=w[N+1][T],q=w[N+1][T+1],ct=w[N][T+1];(t>0||N!==0)&&(v.push(X,V,ct),O+=3),(n>0||N!==c-1)&&(v.push(V,q,ct),O+=3)}p.addGroup(S,O,0),S+=O}function D(A){const F=b,O=new qt,I=new K;let T=0;const N=A===!0?t:n,X=A===!0?1:-1;for(let q=1;q<=l;q++)_.push(0,M*X,0),g.push(0,X,0),y.push(.5,.5),b++;const V=b;for(let q=0;q<=l;q++){const ht=q/l*m+d,j=Math.cos(ht),B=Math.sin(ht);I.x=N*B,I.y=M*X,I.z=N*j,_.push(I.x,I.y,I.z),g.push(0,X,0),O.x=j*.5+.5,O.y=B*.5*X+.5,y.push(O.x,O.y),b++}for(let q=0;q<l;q++){const ct=F+q,ht=V+q;A===!0?v.push(ht,ht+1,ct):v.push(ht+1,ht,ct),T+=3}p.addGroup(S,T,A===!0?1:2),S+=T}}copy(t){return super.copy(t),this.parameters=Object.assign({},t.parameters),this}static fromJSON(t){return new ou(t.radiusTop,t.radiusBottom,t.height,t.radialSegments,t.heightSegments,t.openEnded,t.thetaStart,t.thetaLength)}}class Ji{constructor(){this.type="Curve",this.arcLengthDivisions=200,this.needsUpdate=!1,this.cacheArcLengths=null}getPoint(){ie("Curve: .getPoint() not implemented.")}getPointAt(t,n){const s=this.getUtoTmapping(t);return this.getPoint(s,n)}getPoints(t=5){const n=[];for(let s=0;s<=t;s++)n.push(this.getPoint(s/t));return n}getSpacedPoints(t=5){const n=[];for(let s=0;s<=t;s++)n.push(this.getPointAt(s/t));return n}getLength(){const t=this.getLengths();return t[t.length-1]}getLengths(t=this.arcLengthDivisions){if(this.cacheArcLengths&&this.cacheArcLengths.length===t+1&&!this.needsUpdate)return this.cacheArcLengths;this.needsUpdate=!1;const n=[];let s,l=this.getPoint(0),c=0;n.push(0);for(let f=1;f<=t;f++)s=this.getPoint(f/t),c+=s.distanceTo(l),n.push(c),l=s;return this.cacheArcLengths=n,n}updateArcLengths(){this.needsUpdate=!0,this.getLengths()}getUtoTmapping(t,n=null){const s=this.getLengths();let l=0;const c=s.length;let f;n?f=n:f=t*s[c-1];let d=0,m=c-1,p;for(;d<=m;)if(l=Math.floor(d+(m-d)/2),p=s[l]-f,p<0)d=l+1;else if(p>0)m=l-1;else{m=l;break}if(l=m,s[l]===f)return l/(c-1);const v=s[l],g=s[l+1]-v,y=(f-v)/g;return(l+y)/(c-1)}getTangent(t,n){let l=t-1e-4,c=t+1e-4;l<0&&(l=0),c>1&&(c=1);const f=this.getPoint(l),d=this.getPoint(c),m=n||(f.isVector2?new qt:new K);return m.copy(d).sub(f).normalize(),m}getTangentAt(t,n){const s=this.getUtoTmapping(t);return this.getTangent(s,n)}computeFrenetFrames(t,n=!1){const s=new K,l=[],c=[],f=[],d=new K,m=new en;for(let y=0;y<=t;y++){const b=y/t;l[y]=this.getTangentAt(b,new K)}c[0]=new K,f[0]=new K;let p=Number.MAX_VALUE;const v=Math.abs(l[0].x),_=Math.abs(l[0].y),g=Math.abs(l[0].z);v<=p&&(p=v,s.set(1,0,0)),_<=p&&(p=_,s.set(0,1,0)),g<=p&&s.set(0,0,1),d.crossVectors(l[0],s).normalize(),c[0].crossVectors(l[0],d),f[0].crossVectors(l[0],c[0]);for(let y=1;y<=t;y++){if(c[y]=c[y-1].clone(),f[y]=f[y-1].clone(),d.crossVectors(l[y-1],l[y]),d.length()>Number.EPSILON){d.normalize();const b=Math.acos(ve(l[y-1].dot(l[y]),-1,1));c[y].applyMatrix4(m.makeRotationAxis(d,b))}f[y].crossVectors(l[y],c[y])}if(n===!0){let y=Math.acos(ve(c[0].dot(c[t]),-1,1));y/=t,l[0].dot(d.crossVectors(c[0],c[t]))>0&&(y=-y);for(let b=1;b<=t;b++)c[b].applyMatrix4(m.makeRotationAxis(l[b],y*b)),f[b].crossVectors(l[b],c[b])}return{tangents:l,normals:c,binormals:f}}clone(){return new this.constructor().copy(this)}copy(t){return this.arcLengthDivisions=t.arcLengthDivisions,this}toJSON(){const t={metadata:{version:4.7,type:"Curve",generator:"Curve.toJSON"}};return t.arcLengthDivisions=this.arcLengthDivisions,t.type=this.type,t}fromJSON(t){return this.arcLengthDivisions=t.arcLengthDivisions,this}}class _p extends Ji{constructor(t=0,n=0,s=1,l=1,c=0,f=Math.PI*2,d=!1,m=0){super(),this.isEllipseCurve=!0,this.type="EllipseCurve",this.aX=t,this.aY=n,this.xRadius=s,this.yRadius=l,this.aStartAngle=c,this.aEndAngle=f,this.aClockwise=d,this.aRotation=m}getPoint(t,n=new qt){const s=n,l=Math.PI*2;let c=this.aEndAngle-this.aStartAngle;const f=Math.abs(c)<Number.EPSILON;for(;c<0;)c+=l;for(;c>l;)c-=l;c<Number.EPSILON&&(f?c=0:c=l),this.aClockwise===!0&&!f&&(c===l?c=-l:c=c-l);const d=this.aStartAngle+t*c;let m=this.aX+this.xRadius*Math.cos(d),p=this.aY+this.yRadius*Math.sin(d);if(this.aRotation!==0){const v=Math.cos(this.aRotation),_=Math.sin(this.aRotation),g=m-this.aX,y=p-this.aY;m=g*v-y*_+this.aX,p=g*_+y*v+this.aY}return s.set(m,p)}copy(t){return super.copy(t),this.aX=t.aX,this.aY=t.aY,this.xRadius=t.xRadius,this.yRadius=t.yRadius,this.aStartAngle=t.aStartAngle,this.aEndAngle=t.aEndAngle,this.aClockwise=t.aClockwise,this.aRotation=t.aRotation,this}toJSON(){const t=super.toJSON();return t.aX=this.aX,t.aY=this.aY,t.xRadius=this.xRadius,t.yRadius=this.yRadius,t.aStartAngle=this.aStartAngle,t.aEndAngle=this.aEndAngle,t.aClockwise=this.aClockwise,t.aRotation=this.aRotation,t}fromJSON(t){return super.fromJSON(t),this.aX=t.aX,this.aY=t.aY,this.xRadius=t.xRadius,this.yRadius=t.yRadius,this.aStartAngle=t.aStartAngle,this.aEndAngle=t.aEndAngle,this.aClockwise=t.aClockwise,this.aRotation=t.aRotation,this}}class WM extends _p{constructor(t,n,s,l,c,f){super(t,n,s,s,l,c,f),this.isArcCurve=!0,this.type="ArcCurve"}}function xp(){let r=0,t=0,n=0,s=0;function l(c,f,d,m){r=c,t=d,n=-3*c+3*f-2*d-m,s=2*c-2*f+d+m}return{initCatmullRom:function(c,f,d,m,p){l(f,d,p*(d-c),p*(m-f))},initNonuniformCatmullRom:function(c,f,d,m,p,v,_){let g=(f-c)/p-(d-c)/(p+v)+(d-f)/v,y=(d-f)/v-(m-f)/(v+_)+(m-d)/_;g*=v,y*=v,l(f,d,g,y)},calc:function(c){const f=c*c,d=f*c;return r+t*c+n*f+s*d}}}const Hv=new K,Gv=new K,Jh=new xp,Qh=new xp,$h=new xp;class qM extends Ji{constructor(t=[],n=!1,s="centripetal",l=.5){super(),this.isCatmullRomCurve3=!0,this.type="CatmullRomCurve3",this.points=t,this.closed=n,this.curveType=s,this.tension=l}getPoint(t,n=new K){const s=n,l=this.points,c=l.length,f=(c-(this.closed?0:1))*t;let d=Math.floor(f),m=f-d;this.closed?d+=d>0?0:(Math.floor(Math.abs(d)/c)+1)*c:m===0&&d===c-1&&(d=c-2,m=1);let p,v;this.closed||d>0?p=l[(d-1)%c]:(Gv.subVectors(l[0],l[1]).add(l[0]),p=Gv);const _=l[d%c],g=l[(d+1)%c];if(this.closed||d+2<c?v=l[(d+2)%c]:(Hv.subVectors(l[c-1],l[c-2]).add(l[c-1]),v=Hv),this.curveType==="centripetal"||this.curveType==="chordal"){const y=this.curveType==="chordal"?.5:.25;let b=Math.pow(p.distanceToSquared(_),y),w=Math.pow(_.distanceToSquared(g),y),M=Math.pow(g.distanceToSquared(v),y);w<1e-4&&(w=1),b<1e-4&&(b=w),M<1e-4&&(M=w),Jh.initNonuniformCatmullRom(p.x,_.x,g.x,v.x,b,w,M),Qh.initNonuniformCatmullRom(p.y,_.y,g.y,v.y,b,w,M),$h.initNonuniformCatmullRom(p.z,_.z,g.z,v.z,b,w,M)}else this.curveType==="catmullrom"&&(Jh.initCatmullRom(p.x,_.x,g.x,v.x,this.tension),Qh.initCatmullRom(p.y,_.y,g.y,v.y,this.tension),$h.initCatmullRom(p.z,_.z,g.z,v.z,this.tension));return s.set(Jh.calc(m),Qh.calc(m),$h.calc(m)),s}copy(t){super.copy(t),this.points=[];for(let n=0,s=t.points.length;n<s;n++){const l=t.points[n];this.points.push(l.clone())}return this.closed=t.closed,this.curveType=t.curveType,this.tension=t.tension,this}toJSON(){const t=super.toJSON();t.points=[];for(let n=0,s=this.points.length;n<s;n++){const l=this.points[n];t.points.push(l.toArray())}return t.closed=this.closed,t.curveType=this.curveType,t.tension=this.tension,t}fromJSON(t){super.fromJSON(t),this.points=[];for(let n=0,s=t.points.length;n<s;n++){const l=t.points[n];this.points.push(new K().fromArray(l))}return this.closed=t.closed,this.curveType=t.curveType,this.tension=t.tension,this}}function Vv(r,t,n,s,l){const c=(s-t)*.5,f=(l-n)*.5,d=r*r,m=r*d;return(2*n-2*s+c+f)*m+(-3*n+3*s-2*c-f)*d+c*r+n}function YM(r,t){const n=1-r;return n*n*t}function ZM(r,t){return 2*(1-r)*r*t}function KM(r,t){return r*r*t}function tl(r,t,n,s){return YM(r,t)+ZM(r,n)+KM(r,s)}function jM(r,t){const n=1-r;return n*n*n*t}function JM(r,t){const n=1-r;return 3*n*n*r*t}function QM(r,t){return 3*(1-r)*r*r*t}function $M(r,t){return r*r*r*t}function el(r,t,n,s,l){return jM(r,t)+JM(r,n)+QM(r,s)+$M(r,l)}class sx extends Ji{constructor(t=new qt,n=new qt,s=new qt,l=new qt){super(),this.isCubicBezierCurve=!0,this.type="CubicBezierCurve",this.v0=t,this.v1=n,this.v2=s,this.v3=l}getPoint(t,n=new qt){const s=n,l=this.v0,c=this.v1,f=this.v2,d=this.v3;return s.set(el(t,l.x,c.x,f.x,d.x),el(t,l.y,c.y,f.y,d.y)),s}copy(t){return super.copy(t),this.v0.copy(t.v0),this.v1.copy(t.v1),this.v2.copy(t.v2),this.v3.copy(t.v3),this}toJSON(){const t=super.toJSON();return t.v0=this.v0.toArray(),t.v1=this.v1.toArray(),t.v2=this.v2.toArray(),t.v3=this.v3.toArray(),t}fromJSON(t){return super.fromJSON(t),this.v0.fromArray(t.v0),this.v1.fromArray(t.v1),this.v2.fromArray(t.v2),this.v3.fromArray(t.v3),this}}class tE extends Ji{constructor(t=new K,n=new K,s=new K,l=new K){super(),this.isCubicBezierCurve3=!0,this.type="CubicBezierCurve3",this.v0=t,this.v1=n,this.v2=s,this.v3=l}getPoint(t,n=new K){const s=n,l=this.v0,c=this.v1,f=this.v2,d=this.v3;return s.set(el(t,l.x,c.x,f.x,d.x),el(t,l.y,c.y,f.y,d.y),el(t,l.z,c.z,f.z,d.z)),s}copy(t){return super.copy(t),this.v0.copy(t.v0),this.v1.copy(t.v1),this.v2.copy(t.v2),this.v3.copy(t.v3),this}toJSON(){const t=super.toJSON();return t.v0=this.v0.toArray(),t.v1=this.v1.toArray(),t.v2=this.v2.toArray(),t.v3=this.v3.toArray(),t}fromJSON(t){return super.fromJSON(t),this.v0.fromArray(t.v0),this.v1.fromArray(t.v1),this.v2.fromArray(t.v2),this.v3.fromArray(t.v3),this}}class rx extends Ji{constructor(t=new qt,n=new qt){super(),this.isLineCurve=!0,this.type="LineCurve",this.v1=t,this.v2=n}getPoint(t,n=new qt){const s=n;return t===1?s.copy(this.v2):(s.copy(this.v2).sub(this.v1),s.multiplyScalar(t).add(this.v1)),s}getPointAt(t,n){return this.getPoint(t,n)}getTangent(t,n=new qt){return n.subVectors(this.v2,this.v1).normalize()}getTangentAt(t,n){return this.getTangent(t,n)}copy(t){return super.copy(t),this.v1.copy(t.v1),this.v2.copy(t.v2),this}toJSON(){const t=super.toJSON();return t.v1=this.v1.toArray(),t.v2=this.v2.toArray(),t}fromJSON(t){return super.fromJSON(t),this.v1.fromArray(t.v1),this.v2.fromArray(t.v2),this}}class eE extends Ji{constructor(t=new K,n=new K){super(),this.isLineCurve3=!0,this.type="LineCurve3",this.v1=t,this.v2=n}getPoint(t,n=new K){const s=n;return t===1?s.copy(this.v2):(s.copy(this.v2).sub(this.v1),s.multiplyScalar(t).add(this.v1)),s}getPointAt(t,n){return this.getPoint(t,n)}getTangent(t,n=new K){return n.subVectors(this.v2,this.v1).normalize()}getTangentAt(t,n){return this.getTangent(t,n)}copy(t){return super.copy(t),this.v1.copy(t.v1),this.v2.copy(t.v2),this}toJSON(){const t=super.toJSON();return t.v1=this.v1.toArray(),t.v2=this.v2.toArray(),t}fromJSON(t){return super.fromJSON(t),this.v1.fromArray(t.v1),this.v2.fromArray(t.v2),this}}class ox extends Ji{constructor(t=new qt,n=new qt,s=new qt){super(),this.isQuadraticBezierCurve=!0,this.type="QuadraticBezierCurve",this.v0=t,this.v1=n,this.v2=s}getPoint(t,n=new qt){const s=n,l=this.v0,c=this.v1,f=this.v2;return s.set(tl(t,l.x,c.x,f.x),tl(t,l.y,c.y,f.y)),s}copy(t){return super.copy(t),this.v0.copy(t.v0),this.v1.copy(t.v1),this.v2.copy(t.v2),this}toJSON(){const t=super.toJSON();return t.v0=this.v0.toArray(),t.v1=this.v1.toArray(),t.v2=this.v2.toArray(),t}fromJSON(t){return super.fromJSON(t),this.v0.fromArray(t.v0),this.v1.fromArray(t.v1),this.v2.fromArray(t.v2),this}}class nE extends Ji{constructor(t=new K,n=new K,s=new K){super(),this.isQuadraticBezierCurve3=!0,this.type="QuadraticBezierCurve3",this.v0=t,this.v1=n,this.v2=s}getPoint(t,n=new K){const s=n,l=this.v0,c=this.v1,f=this.v2;return s.set(tl(t,l.x,c.x,f.x),tl(t,l.y,c.y,f.y),tl(t,l.z,c.z,f.z)),s}copy(t){return super.copy(t),this.v0.copy(t.v0),this.v1.copy(t.v1),this.v2.copy(t.v2),this}toJSON(){const t=super.toJSON();return t.v0=this.v0.toArray(),t.v1=this.v1.toArray(),t.v2=this.v2.toArray(),t}fromJSON(t){return super.fromJSON(t),this.v0.fromArray(t.v0),this.v1.fromArray(t.v1),this.v2.fromArray(t.v2),this}}class lx extends Ji{constructor(t=[]){super(),this.isSplineCurve=!0,this.type="SplineCurve",this.points=t}getPoint(t,n=new qt){const s=n,l=this.points,c=(l.length-1)*t,f=Math.floor(c),d=c-f,m=l[f===0?f:f-1],p=l[f],v=l[f>l.length-2?l.length-1:f+1],_=l[f>l.length-3?l.length-1:f+2];return s.set(Vv(d,m.x,p.x,v.x,_.x),Vv(d,m.y,p.y,v.y,_.y)),s}copy(t){super.copy(t),this.points=[];for(let n=0,s=t.points.length;n<s;n++){const l=t.points[n];this.points.push(l.clone())}return this}toJSON(){const t=super.toJSON();t.points=[];for(let n=0,s=this.points.length;n<s;n++){const l=this.points[n];t.points.push(l.toArray())}return t}fromJSON(t){super.fromJSON(t),this.points=[];for(let n=0,s=t.points.length;n<s;n++){const l=t.points[n];this.points.push(new qt().fromArray(l))}return this}}var kv=Object.freeze({__proto__:null,ArcCurve:WM,CatmullRomCurve3:qM,CubicBezierCurve:sx,CubicBezierCurve3:tE,EllipseCurve:_p,LineCurve:rx,LineCurve3:eE,QuadraticBezierCurve:ox,QuadraticBezierCurve3:nE,SplineCurve:lx});class iE extends Ji{constructor(){super(),this.type="CurvePath",this.curves=[],this.autoClose=!1}add(t){this.curves.push(t)}closePath(){const t=this.curves[0].getPoint(0),n=this.curves[this.curves.length-1].getPoint(1);if(!t.equals(n)){const s=t.isVector2===!0?"LineCurve":"LineCurve3";this.curves.push(new kv[s](n,t))}return this}getPoint(t,n){const s=t*this.getLength(),l=this.getCurveLengths();let c=0;for(;c<l.length;){if(l[c]>=s){const f=l[c]-s,d=this.curves[c],m=d.getLength(),p=m===0?0:1-f/m;return d.getPointAt(p,n)}c++}return null}getLength(){const t=this.getCurveLengths();return t[t.length-1]}updateArcLengths(){this.needsUpdate=!0,this.cacheLengths=null,this.getCurveLengths()}getCurveLengths(){if(this.cacheLengths&&this.cacheLengths.length===this.curves.length)return this.cacheLengths;const t=[];let n=0;for(let s=0,l=this.curves.length;s<l;s++)n+=this.curves[s].getLength(),t.push(n);return this.cacheLengths=t,t}getSpacedPoints(t=40){const n=[];for(let s=0;s<=t;s++)n.push(this.getPoint(s/t));return this.autoClose&&n.push(n[0]),n}getPoints(t=12){const n=[];let s;for(let l=0,c=this.curves;l<c.length;l++){const f=c[l],d=f.isEllipseCurve?t*2:f.isLineCurve||f.isLineCurve3?1:f.isSplineCurve?t*f.points.length:t,m=f.getPoints(d);for(let p=0;p<m.length;p++){const v=m[p];s&&s.equals(v)||(n.push(v),s=v)}}return this.autoClose&&n.length>1&&!n[n.length-1].equals(n[0])&&n.push(n[0]),n}copy(t){super.copy(t),this.curves=[];for(let n=0,s=t.curves.length;n<s;n++){const l=t.curves[n];this.curves.push(l.clone())}return this.autoClose=t.autoClose,this}toJSON(){const t=super.toJSON();t.autoClose=this.autoClose,t.curves=[];for(let n=0,s=this.curves.length;n<s;n++){const l=this.curves[n];t.curves.push(l.toJSON())}return t}fromJSON(t){super.fromJSON(t),this.autoClose=t.autoClose,this.curves=[];for(let n=0,s=t.curves.length;n<s;n++){const l=t.curves[n];this.curves.push(new kv[l.type]().fromJSON(l))}return this}}class Xv extends iE{constructor(t){super(),this.type="Path",this.currentPoint=new qt,t&&this.setFromPoints(t)}setFromPoints(t){this.moveTo(t[0].x,t[0].y);for(let n=1,s=t.length;n<s;n++)this.lineTo(t[n].x,t[n].y);return this}moveTo(t,n){return this.currentPoint.set(t,n),this}lineTo(t,n){const s=new rx(this.currentPoint.clone(),new qt(t,n));return this.curves.push(s),this.currentPoint.set(t,n),this}quadraticCurveTo(t,n,s,l){const c=new ox(this.currentPoint.clone(),new qt(t,n),new qt(s,l));return this.curves.push(c),this.currentPoint.set(s,l),this}bezierCurveTo(t,n,s,l,c,f){const d=new sx(this.currentPoint.clone(),new qt(t,n),new qt(s,l),new qt(c,f));return this.curves.push(d),this.currentPoint.set(c,f),this}splineThru(t){const n=[this.currentPoint.clone()].concat(t),s=new lx(n);return this.curves.push(s),this.currentPoint.copy(t[t.length-1]),this}arc(t,n,s,l,c,f){const d=this.currentPoint.x,m=this.currentPoint.y;return this.absarc(t+d,n+m,s,l,c,f),this}absarc(t,n,s,l,c,f){return this.absellipse(t,n,s,s,l,c,f),this}ellipse(t,n,s,l,c,f,d,m){const p=this.currentPoint.x,v=this.currentPoint.y;return this.absellipse(t+p,n+v,s,l,c,f,d,m),this}absellipse(t,n,s,l,c,f,d,m){const p=new _p(t,n,s,l,c,f,d,m);if(this.curves.length>0){const _=p.getPoint(0);_.equals(this.currentPoint)||this.lineTo(_.x,_.y)}this.curves.push(p);const v=p.getPoint(1);return this.currentPoint.copy(v),this}copy(t){return super.copy(t),this.currentPoint.copy(t.currentPoint),this}toJSON(){const t=super.toJSON();return t.currentPoint=this.currentPoint.toArray(),t}fromJSON(t){return super.fromJSON(t),this.currentPoint.fromArray(t.currentPoint),this}}class cx extends Xv{constructor(t){super(t),this.uuid=Yr(),this.type="Shape",this.holes=[]}getPointsHoles(t){const n=[];for(let s=0,l=this.holes.length;s<l;s++)n[s]=this.holes[s].getPoints(t);return n}extractPoints(t){return{shape:this.getPoints(t),holes:this.getPointsHoles(t)}}copy(t){super.copy(t),this.holes=[];for(let n=0,s=t.holes.length;n<s;n++){const l=t.holes[n];this.holes.push(l.clone())}return this}toJSON(){const t=super.toJSON();t.uuid=this.uuid,t.holes=[];for(let n=0,s=this.holes.length;n<s;n++){const l=this.holes[n];t.holes.push(l.toJSON())}return t}fromJSON(t){super.fromJSON(t),this.uuid=t.uuid,this.holes=[];for(let n=0,s=t.holes.length;n<s;n++){const l=t.holes[n];this.holes.push(new Xv().fromJSON(l))}return this}}function aE(r,t,n=2){const s=t&&t.length,l=s?t[0]*n:r.length;let c=ux(r,0,l,n,!0);const f=[];if(!c||c.next===c.prev)return f;let d,m,p;if(s&&(c=cE(r,t,c,n)),r.length>80*n){d=r[0],m=r[1];let v=d,_=m;for(let g=n;g<l;g+=n){const y=r[g],b=r[g+1];y<d&&(d=y),b<m&&(m=b),y>v&&(v=y),b>_&&(_=b)}p=Math.max(v-d,_-m),p=p!==0?32767/p:0}return rl(c,f,n,d,m,p,0),f}function ux(r,t,n,s,l){let c;if(l===SE(r,t,n,s)>0)for(let f=t;f<n;f+=s)c=Wv(f/s|0,r[f],r[f+1],c);else for(let f=n-s;f>=t;f-=s)c=Wv(f/s|0,r[f],r[f+1],c);return c&&Wr(c,c.next)&&(ll(c),c=c.next),c}function Xs(r,t){if(!r)return r;t||(t=r);let n=r,s;do if(s=!1,!n.steiner&&(Wr(n,n.next)||tn(n.prev,n,n.next)===0)){if(ll(n),n=t=n.prev,n===n.next)break;s=!0}else n=n.next;while(s||n!==t);return t}function rl(r,t,n,s,l,c,f){if(!r)return;!f&&c&&pE(r,s,l,c);let d=r;for(;r.prev!==r.next;){const m=r.prev,p=r.next;if(c?rE(r,s,l,c):sE(r)){t.push(m.i,r.i,p.i),ll(r),r=p.next,d=p.next;continue}if(r=p,r===d){f?f===1?(r=oE(Xs(r),t),rl(r,t,n,s,l,c,2)):f===2&&lE(r,t,n,s,l,c):rl(Xs(r),t,n,s,l,c,1);break}}}function sE(r){const t=r.prev,n=r,s=r.next;if(tn(t,n,s)>=0)return!1;const l=t.x,c=n.x,f=s.x,d=t.y,m=n.y,p=s.y,v=Math.min(l,c,f),_=Math.min(d,m,p),g=Math.max(l,c,f),y=Math.max(d,m,p);let b=s.next;for(;b!==t;){if(b.x>=v&&b.x<=g&&b.y>=_&&b.y<=y&&Jo(l,d,c,m,f,p,b.x,b.y)&&tn(b.prev,b,b.next)>=0)return!1;b=b.next}return!0}function rE(r,t,n,s){const l=r.prev,c=r,f=r.next;if(tn(l,c,f)>=0)return!1;const d=l.x,m=c.x,p=f.x,v=l.y,_=c.y,g=f.y,y=Math.min(d,m,p),b=Math.min(v,_,g),w=Math.max(d,m,p),M=Math.max(v,_,g),S=Qd(y,b,t,n,s),P=Qd(w,M,t,n,s);let D=r.prevZ,A=r.nextZ;for(;D&&D.z>=S&&A&&A.z<=P;){if(D.x>=y&&D.x<=w&&D.y>=b&&D.y<=M&&D!==l&&D!==f&&Jo(d,v,m,_,p,g,D.x,D.y)&&tn(D.prev,D,D.next)>=0||(D=D.prevZ,A.x>=y&&A.x<=w&&A.y>=b&&A.y<=M&&A!==l&&A!==f&&Jo(d,v,m,_,p,g,A.x,A.y)&&tn(A.prev,A,A.next)>=0))return!1;A=A.nextZ}for(;D&&D.z>=S;){if(D.x>=y&&D.x<=w&&D.y>=b&&D.y<=M&&D!==l&&D!==f&&Jo(d,v,m,_,p,g,D.x,D.y)&&tn(D.prev,D,D.next)>=0)return!1;D=D.prevZ}for(;A&&A.z<=P;){if(A.x>=y&&A.x<=w&&A.y>=b&&A.y<=M&&A!==l&&A!==f&&Jo(d,v,m,_,p,g,A.x,A.y)&&tn(A.prev,A,A.next)>=0)return!1;A=A.nextZ}return!0}function oE(r,t){let n=r;do{const s=n.prev,l=n.next.next;!Wr(s,l)&&hx(s,n,n.next,l)&&ol(s,l)&&ol(l,s)&&(t.push(s.i,n.i,l.i),ll(n),ll(n.next),n=r=l),n=n.next}while(n!==r);return Xs(n)}function lE(r,t,n,s,l,c){let f=r;do{let d=f.next.next;for(;d!==f.prev;){if(f.i!==d.i&&vE(f,d)){let m=dx(f,d);f=Xs(f,f.next),m=Xs(m,m.next),rl(f,t,n,s,l,c,0),rl(m,t,n,s,l,c,0);return}d=d.next}f=f.next}while(f!==r)}function cE(r,t,n,s){const l=[];for(let c=0,f=t.length;c<f;c++){const d=t[c]*s,m=c<f-1?t[c+1]*s:r.length,p=ux(r,d,m,s,!1);p===p.next&&(p.steiner=!0),l.push(gE(p))}l.sort(uE);for(let c=0;c<l.length;c++)n=fE(l[c],n);return n}function uE(r,t){let n=r.x-t.x;if(n===0&&(n=r.y-t.y,n===0)){const s=(r.next.y-r.y)/(r.next.x-r.x),l=(t.next.y-t.y)/(t.next.x-t.x);n=s-l}return n}function fE(r,t){const n=hE(r,t);if(!n)return t;const s=dx(n,r);return Xs(s,s.next),Xs(n,n.next)}function hE(r,t){let n=t;const s=r.x,l=r.y;let c=-1/0,f;if(Wr(r,n))return n;do{if(Wr(r,n.next))return n.next;if(l<=n.y&&l>=n.next.y&&n.next.y!==n.y){const _=n.x+(l-n.y)*(n.next.x-n.x)/(n.next.y-n.y);if(_<=s&&_>c&&(c=_,f=n.x<n.next.x?n:n.next,_===s))return f}n=n.next}while(n!==t);if(!f)return null;const d=f,m=f.x,p=f.y;let v=1/0;n=f;do{if(s>=n.x&&n.x>=m&&s!==n.x&&fx(l<p?s:c,l,m,p,l<p?c:s,l,n.x,n.y)){const _=Math.abs(l-n.y)/(s-n.x);ol(n,r)&&(_<v||_===v&&(n.x>f.x||n.x===f.x&&dE(f,n)))&&(f=n,v=_)}n=n.next}while(n!==d);return f}function dE(r,t){return tn(r.prev,r,t.prev)<0&&tn(t.next,r,r.next)<0}function pE(r,t,n,s){let l=r;do l.z===0&&(l.z=Qd(l.x,l.y,t,n,s)),l.prevZ=l.prev,l.nextZ=l.next,l=l.next;while(l!==r);l.prevZ.nextZ=null,l.prevZ=null,mE(l)}function mE(r){let t,n=1;do{let s=r,l;r=null;let c=null;for(t=0;s;){t++;let f=s,d=0;for(let p=0;p<n&&(d++,f=f.nextZ,!!f);p++);let m=n;for(;d>0||m>0&&f;)d!==0&&(m===0||!f||s.z<=f.z)?(l=s,s=s.nextZ,d--):(l=f,f=f.nextZ,m--),c?c.nextZ=l:r=l,l.prevZ=c,c=l;s=f}c.nextZ=null,n*=2}while(t>1);return r}function Qd(r,t,n,s,l){return r=(r-n)*l|0,t=(t-s)*l|0,r=(r|r<<8)&16711935,r=(r|r<<4)&252645135,r=(r|r<<2)&858993459,r=(r|r<<1)&1431655765,t=(t|t<<8)&16711935,t=(t|t<<4)&252645135,t=(t|t<<2)&858993459,t=(t|t<<1)&1431655765,r|t<<1}function gE(r){let t=r,n=r;do(t.x<n.x||t.x===n.x&&t.y<n.y)&&(n=t),t=t.next;while(t!==r);return n}function fx(r,t,n,s,l,c,f,d){return(l-f)*(t-d)>=(r-f)*(c-d)&&(r-f)*(s-d)>=(n-f)*(t-d)&&(n-f)*(c-d)>=(l-f)*(s-d)}function Jo(r,t,n,s,l,c,f,d){return!(r===f&&t===d)&&fx(r,t,n,s,l,c,f,d)}function vE(r,t){return r.next.i!==t.i&&r.prev.i!==t.i&&!_E(r,t)&&(ol(r,t)&&ol(t,r)&&xE(r,t)&&(tn(r.prev,r,t.prev)||tn(r,t.prev,t))||Wr(r,t)&&tn(r.prev,r,r.next)>0&&tn(t.prev,t,t.next)>0)}function tn(r,t,n){return(t.y-r.y)*(n.x-t.x)-(t.x-r.x)*(n.y-t.y)}function Wr(r,t){return r.x===t.x&&r.y===t.y}function hx(r,t,n,s){const l=Vc(tn(r,t,n)),c=Vc(tn(r,t,s)),f=Vc(tn(n,s,r)),d=Vc(tn(n,s,t));return!!(l!==c&&f!==d||l===0&&Gc(r,n,t)||c===0&&Gc(r,s,t)||f===0&&Gc(n,r,s)||d===0&&Gc(n,t,s))}function Gc(r,t,n){return t.x<=Math.max(r.x,n.x)&&t.x>=Math.min(r.x,n.x)&&t.y<=Math.max(r.y,n.y)&&t.y>=Math.min(r.y,n.y)}function Vc(r){return r>0?1:r<0?-1:0}function _E(r,t){let n=r;do{if(n.i!==r.i&&n.next.i!==r.i&&n.i!==t.i&&n.next.i!==t.i&&hx(n,n.next,r,t))return!0;n=n.next}while(n!==r);return!1}function ol(r,t){return tn(r.prev,r,r.next)<0?tn(r,t,r.next)>=0&&tn(r,r.prev,t)>=0:tn(r,t,r.prev)<0||tn(r,r.next,t)<0}function xE(r,t){let n=r,s=!1;const l=(r.x+t.x)/2,c=(r.y+t.y)/2;do n.y>c!=n.next.y>c&&n.next.y!==n.y&&l<(n.next.x-n.x)*(c-n.y)/(n.next.y-n.y)+n.x&&(s=!s),n=n.next;while(n!==r);return s}function dx(r,t){const n=$d(r.i,r.x,r.y),s=$d(t.i,t.x,t.y),l=r.next,c=t.prev;return r.next=t,t.prev=r,n.next=l,l.prev=n,s.next=n,n.prev=s,c.next=s,s.prev=c,s}function Wv(r,t,n,s){const l=$d(r,t,n);return s?(l.next=s.next,l.prev=s,s.next.prev=l,s.next=l):(l.prev=l,l.next=l),l}function ll(r){r.next.prev=r.prev,r.prev.next=r.next,r.prevZ&&(r.prevZ.nextZ=r.nextZ),r.nextZ&&(r.nextZ.prevZ=r.prevZ)}function $d(r,t,n){return{i:r,x:t,y:n,prev:null,next:null,z:0,prevZ:null,nextZ:null,steiner:!1}}function SE(r,t,n,s){let l=0;for(let c=t,f=n-s;c<n;c+=s)l+=(r[f]-r[c])*(r[c+1]+r[f+1]),f=c;return l}class yE{static triangulate(t,n,s=2){return aE(t,n,s)}}class nl{static area(t){const n=t.length;let s=0;for(let l=n-1,c=0;c<n;l=c++)s+=t[l].x*t[c].y-t[c].x*t[l].y;return s*.5}static isClockWise(t){return nl.area(t)<0}static triangulateShape(t,n){const s=[],l=[],c=[];qv(t),Yv(s,t);let f=t.length;n.forEach(qv);for(let m=0;m<n.length;m++)l.push(f),f+=n[m].length,Yv(s,n[m]);const d=yE.triangulate(s,l);for(let m=0;m<d.length;m+=3)c.push(d.slice(m,m+3));return c}}function qv(r){const t=r.length;t>2&&r[t-1].equals(r[0])&&r.pop()}function Yv(r,t){for(let n=0;n<t.length;n++)r.push(t[n].x),r.push(t[n].y)}class fl extends Xn{constructor(t=1,n=1,s=1,l=1){super(),this.type="PlaneGeometry",this.parameters={width:t,height:n,widthSegments:s,heightSegments:l};const c=t/2,f=n/2,d=Math.floor(s),m=Math.floor(l),p=d+1,v=m+1,_=t/d,g=n/m,y=[],b=[],w=[],M=[];for(let S=0;S<v;S++){const P=S*g-f;for(let D=0;D<p;D++){const A=D*_-c;b.push(A,-P,0),w.push(0,0,1),M.push(D/d),M.push(1-S/m)}}for(let S=0;S<m;S++)for(let P=0;P<d;P++){const D=P+p*S,A=P+p*(S+1),F=P+1+p*(S+1),O=P+1+p*S;y.push(D,A,O),y.push(A,F,O)}this.setIndex(y),this.setAttribute("position",new Xe(b,3)),this.setAttribute("normal",new Xe(w,3)),this.setAttribute("uv",new Xe(M,2))}copy(t){return super.copy(t),this.parameters=Object.assign({},t.parameters),this}static fromJSON(t){return new fl(t.width,t.height,t.widthSegments,t.heightSegments)}}class Sp extends Xn{constructor(t=.5,n=1,s=32,l=1,c=0,f=Math.PI*2){super(),this.type="RingGeometry",this.parameters={innerRadius:t,outerRadius:n,thetaSegments:s,phiSegments:l,thetaStart:c,thetaLength:f},s=Math.max(3,s),l=Math.max(1,l);const d=[],m=[],p=[],v=[];let _=t;const g=(n-t)/l,y=new K,b=new qt;for(let w=0;w<=l;w++){for(let M=0;M<=s;M++){const S=c+M/s*f;y.x=_*Math.cos(S),y.y=_*Math.sin(S),m.push(y.x,y.y,y.z),p.push(0,0,1),b.x=(y.x/n+1)/2,b.y=(y.y/n+1)/2,v.push(b.x,b.y)}_+=g}for(let w=0;w<l;w++){const M=w*(s+1);for(let S=0;S<s;S++){const P=S+M,D=P,A=P+s+1,F=P+s+2,O=P+1;d.push(D,A,O),d.push(A,F,O)}}this.setIndex(d),this.setAttribute("position",new Xe(m,3)),this.setAttribute("normal",new Xe(p,3)),this.setAttribute("uv",new Xe(v,2))}copy(t){return super.copy(t),this.parameters=Object.assign({},t.parameters),this}static fromJSON(t){return new Sp(t.innerRadius,t.outerRadius,t.thetaSegments,t.phiSegments,t.thetaStart,t.thetaLength)}}class yp extends Xn{constructor(t=new cx([new qt(0,.5),new qt(-.5,-.5),new qt(.5,-.5)]),n=12){super(),this.type="ShapeGeometry",this.parameters={shapes:t,curveSegments:n};const s=[],l=[],c=[],f=[];let d=0,m=0;if(Array.isArray(t)===!1)p(t);else for(let v=0;v<t.length;v++)p(t[v]),this.addGroup(d,m,v),d+=m,m=0;this.setIndex(s),this.setAttribute("position",new Xe(l,3)),this.setAttribute("normal",new Xe(c,3)),this.setAttribute("uv",new Xe(f,2));function p(v){const _=l.length/3,g=v.extractPoints(n);let y=g.shape;const b=g.holes;nl.isClockWise(y)===!1&&(y=y.reverse());for(let M=0,S=b.length;M<S;M++){const P=b[M];nl.isClockWise(P)===!0&&(b[M]=P.reverse())}const w=nl.triangulateShape(y,b);for(let M=0,S=b.length;M<S;M++){const P=b[M];y=y.concat(P)}for(let M=0,S=y.length;M<S;M++){const P=y[M];l.push(P.x,P.y,0),c.push(0,0,1),f.push(P.x,P.y)}for(let M=0,S=w.length;M<S;M++){const P=w[M],D=P[0]+_,A=P[1]+_,F=P[2]+_;s.push(D,A,F),m+=3}}}copy(t){return super.copy(t),this.parameters=Object.assign({},t.parameters),this}toJSON(){const t=super.toJSON(),n=this.parameters.shapes;return ME(n,t)}static fromJSON(t,n){const s=[];for(let l=0,c=t.shapes.length;l<c;l++){const f=n[t.shapes[l]];s.push(f)}return new yp(s,t.curveSegments)}}function ME(r,t){if(t.shapes=[],Array.isArray(r))for(let n=0,s=r.length;n<s;n++){const l=r[n];t.shapes.push(l.uuid)}else t.shapes.push(r.uuid);return t}class lu extends Xn{constructor(t=1,n=32,s=16,l=0,c=Math.PI*2,f=0,d=Math.PI){super(),this.type="SphereGeometry",this.parameters={radius:t,widthSegments:n,heightSegments:s,phiStart:l,phiLength:c,thetaStart:f,thetaLength:d},n=Math.max(3,Math.floor(n)),s=Math.max(2,Math.floor(s));const m=Math.min(f+d,Math.PI);let p=0;const v=[],_=new K,g=new K,y=[],b=[],w=[],M=[];for(let S=0;S<=s;S++){const P=[],D=S/s,A=f+D*d,F=t*Math.cos(A),O=Math.sqrt(t*t-F*F);let I=0;S===0&&f===0?I=.5/n:S===s&&m===Math.PI&&(I=-.5/n);for(let T=0;T<=n;T++){const N=T/n,X=l+N*c;_.x=-O*Math.cos(X),_.y=F,_.z=O*Math.sin(X),b.push(_.x,_.y,_.z),g.copy(_).normalize(),w.push(g.x,g.y,g.z),M.push(N+I,1-D),P.push(p++)}v.push(P)}for(let S=0;S<s;S++)for(let P=0;P<n;P++){const D=v[S][P+1],A=v[S][P],F=v[S+1][P],O=v[S+1][P+1];(S!==0||f>0)&&y.push(D,A,O),(S!==s-1||m<Math.PI)&&y.push(A,F,O)}this.setIndex(y),this.setAttribute("position",new Xe(b,3)),this.setAttribute("normal",new Xe(w,3)),this.setAttribute("uv",new Xe(M,2))}copy(t){return super.copy(t),this.parameters=Object.assign({},t.parameters),this}static fromJSON(t){return new lu(t.radius,t.widthSegments,t.heightSegments,t.phiStart,t.phiLength,t.thetaStart,t.thetaLength)}}class Mp extends Xn{constructor(t=1,n=.4,s=12,l=48,c=Math.PI*2,f=0,d=Math.PI*2){super(),this.type="TorusGeometry",this.parameters={radius:t,tube:n,radialSegments:s,tubularSegments:l,arc:c,thetaStart:f,thetaLength:d},s=Math.floor(s),l=Math.floor(l);const m=[],p=[],v=[],_=[],g=new K,y=new K,b=new K;for(let w=0;w<=s;w++){const M=f+w/s*d;for(let S=0;S<=l;S++){const P=S/l*c;y.x=(t+n*Math.cos(M))*Math.cos(P),y.y=(t+n*Math.cos(M))*Math.sin(P),y.z=n*Math.sin(M),p.push(y.x,y.y,y.z),g.x=t*Math.cos(P),g.y=t*Math.sin(P),b.subVectors(y,g).normalize(),v.push(b.x,b.y,b.z),_.push(S/l),_.push(w/s)}}for(let w=1;w<=s;w++)for(let M=1;M<=l;M++){const S=(l+1)*w+M-1,P=(l+1)*(w-1)+M-1,D=(l+1)*(w-1)+M,A=(l+1)*w+M;m.push(S,P,A),m.push(P,D,A)}this.setIndex(m),this.setAttribute("position",new Xe(p,3)),this.setAttribute("normal",new Xe(v,3)),this.setAttribute("uv",new Xe(_,2))}copy(t){return super.copy(t),this.parameters=Object.assign({},t.parameters),this}static fromJSON(t){return new Mp(t.radius,t.tube,t.radialSegments,t.tubularSegments,t.arc)}}function qr(r){const t={};for(const n in r){t[n]={};for(const s in r[n]){const l=r[n][s];if(Zv(l))l.isRenderTargetTexture?(ie("UniformsUtils: Textures of render targets cannot be cloned via cloneUniforms() or mergeUniforms()."),t[n][s]=null):t[n][s]=l.clone();else if(Array.isArray(l))if(Zv(l[0])){const c=[];for(let f=0,d=l.length;f<d;f++)c[f]=l[f].clone();t[n][s]=c}else t[n][s]=l.slice();else t[n][s]=l}}return t}function Gn(r){const t={};for(let n=0;n<r.length;n++){const s=qr(r[n]);for(const l in s)t[l]=s[l]}return t}function Zv(r){return r&&(r.isColor||r.isMatrix3||r.isMatrix4||r.isVector2||r.isVector3||r.isVector4||r.isTexture||r.isQuaternion)}function EE(r){const t=[];for(let n=0;n<r.length;n++)t.push(r[n].clone());return t}function px(r){const t=r.getRenderTarget();return t===null?r.outputColorSpace:t.isXRRenderTarget===!0?t.texture.colorSpace:Ee.workingColorSpace}const bE={clone:qr,merge:Gn};var TE=`void main() {
	gl_Position = projectionMatrix * modelViewMatrix * vec4( position, 1.0 );
}`,AE=`void main() {
	gl_FragColor = vec4( 1.0, 0.0, 0.0, 1.0 );
}`;class Ti extends ul{constructor(t){super(),this.isShaderMaterial=!0,this.type="ShaderMaterial",this.defines={},this.uniforms={},this.uniformsGroups=[],this.vertexShader=TE,this.fragmentShader=AE,this.linewidth=1,this.wireframe=!1,this.wireframeLinewidth=1,this.fog=!1,this.lights=!1,this.clipping=!1,this.forceSinglePass=!0,this.extensions={clipCullDistance:!1,multiDraw:!1},this.defaultAttributeValues={color:[1,1,1],uv:[0,0],uv1:[0,0]},this.index0AttributeName=void 0,this.uniformsNeedUpdate=!1,this.glslVersion=null,t!==void 0&&this.setValues(t)}copy(t){return super.copy(t),this.fragmentShader=t.fragmentShader,this.vertexShader=t.vertexShader,this.uniforms=qr(t.uniforms),this.uniformsGroups=EE(t.uniformsGroups),this.defines=Object.assign({},t.defines),this.wireframe=t.wireframe,this.wireframeLinewidth=t.wireframeLinewidth,this.fog=t.fog,this.lights=t.lights,this.clipping=t.clipping,this.extensions=Object.assign({},t.extensions),this.glslVersion=t.glslVersion,this.defaultAttributeValues=Object.assign({},t.defaultAttributeValues),this.index0AttributeName=t.index0AttributeName,this.uniformsNeedUpdate=t.uniformsNeedUpdate,this}toJSON(t){const n=super.toJSON(t);n.glslVersion=this.glslVersion,n.uniforms={};for(const l in this.uniforms){const f=this.uniforms[l].value;f&&f.isTexture?n.uniforms[l]={type:"t",value:f.toJSON(t).uuid}:f&&f.isColor?n.uniforms[l]={type:"c",value:f.getHex()}:f&&f.isVector2?n.uniforms[l]={type:"v2",value:f.toArray()}:f&&f.isVector3?n.uniforms[l]={type:"v3",value:f.toArray()}:f&&f.isVector4?n.uniforms[l]={type:"v4",value:f.toArray()}:f&&f.isMatrix3?n.uniforms[l]={type:"m3",value:f.toArray()}:f&&f.isMatrix4?n.uniforms[l]={type:"m4",value:f.toArray()}:n.uniforms[l]={value:f}}Object.keys(this.defines).length>0&&(n.defines=this.defines),n.vertexShader=this.vertexShader,n.fragmentShader=this.fragmentShader,n.lights=this.lights,n.clipping=this.clipping;const s={};for(const l in this.extensions)this.extensions[l]===!0&&(s[l]=!0);return Object.keys(s).length>0&&(n.extensions=s),n}fromJSON(t,n){if(super.fromJSON(t,n),t.uniforms!==void 0)for(const s in t.uniforms){const l=t.uniforms[s];switch(this.uniforms[s]={},l.type){case"t":this.uniforms[s].value=n[l.value]||null;break;case"c":this.uniforms[s].value=new fe().setHex(l.value);break;case"v2":this.uniforms[s].value=new qt().fromArray(l.value);break;case"v3":this.uniforms[s].value=new K().fromArray(l.value);break;case"v4":this.uniforms[s].value=new $e().fromArray(l.value);break;case"m3":this.uniforms[s].value=new re().fromArray(l.value);break;case"m4":this.uniforms[s].value=new en().fromArray(l.value);break;default:this.uniforms[s].value=l.value}}if(t.defines!==void 0&&(this.defines=t.defines),t.vertexShader!==void 0&&(this.vertexShader=t.vertexShader),t.fragmentShader!==void 0&&(this.fragmentShader=t.fragmentShader),t.glslVersion!==void 0&&(this.glslVersion=t.glslVersion),t.extensions!==void 0)for(const s in t.extensions)this.extensions[s]=t.extensions[s];return t.lights!==void 0&&(this.lights=t.lights),t.clipping!==void 0&&(this.clipping=t.clipping),this}}class RE extends Ti{constructor(t){super(t),this.isRawShaderMaterial=!0,this.type="RawShaderMaterial"}}class Ei extends ul{constructor(t){super(),this.isMeshStandardMaterial=!0,this.type="MeshStandardMaterial",this.defines={STANDARD:""},this.color=new fe(16777215),this.roughness=1,this.metalness=0,this.map=null,this.lightMap=null,this.lightMapIntensity=1,this.aoMap=null,this.aoMapIntensity=1,this.emissive=new fe(0),this.emissiveIntensity=1,this.emissiveMap=null,this.bumpMap=null,this.bumpScale=1,this.normalMap=null,this.normalMapType=jd,this.normalScale=new qt(1,1),this.displacementMap=null,this.displacementScale=1,this.displacementBias=0,this.roughnessMap=null,this.metalnessMap=null,this.alphaMap=null,this.envMap=null,this.envMapRotation=new fs,this.envMapIntensity=1,this.wireframe=!1,this.wireframeLinewidth=1,this.wireframeLinecap="round",this.wireframeLinejoin="round",this.flatShading=!1,this.fog=!0,this.setValues(t)}copy(t){return super.copy(t),this.defines={STANDARD:""},this.color.copy(t.color),this.roughness=t.roughness,this.metalness=t.metalness,this.map=t.map,this.lightMap=t.lightMap,this.lightMapIntensity=t.lightMapIntensity,this.aoMap=t.aoMap,this.aoMapIntensity=t.aoMapIntensity,this.emissive.copy(t.emissive),this.emissiveMap=t.emissiveMap,this.emissiveIntensity=t.emissiveIntensity,this.bumpMap=t.bumpMap,this.bumpScale=t.bumpScale,this.normalMap=t.normalMap,this.normalMapType=t.normalMapType,this.normalScale.copy(t.normalScale),this.displacementMap=t.displacementMap,this.displacementScale=t.displacementScale,this.displacementBias=t.displacementBias,this.roughnessMap=t.roughnessMap,this.metalnessMap=t.metalnessMap,this.alphaMap=t.alphaMap,this.envMap=t.envMap,this.envMapRotation.copy(t.envMapRotation),this.envMapIntensity=t.envMapIntensity,this.wireframe=t.wireframe,this.wireframeLinewidth=t.wireframeLinewidth,this.wireframeLinecap=t.wireframeLinecap,this.wireframeLinejoin=t.wireframeLinejoin,this.flatShading=t.flatShading,this.fog=t.fog,this}}class CE extends ul{constructor(t){super(),this.isMeshDepthMaterial=!0,this.type="MeshDepthMaterial",this.depthPacking=lM,this.map=null,this.alphaMap=null,this.displacementMap=null,this.displacementScale=1,this.displacementBias=0,this.wireframe=!1,this.wireframeLinewidth=1,this.setValues(t)}copy(t){return super.copy(t),this.depthPacking=t.depthPacking,this.map=t.map,this.alphaMap=t.alphaMap,this.displacementMap=t.displacementMap,this.displacementScale=t.displacementScale,this.displacementBias=t.displacementBias,this.wireframe=t.wireframe,this.wireframeLinewidth=t.wireframeLinewidth,this}}class wE extends ul{constructor(t){super(),this.isMeshDistanceMaterial=!0,this.type="MeshDistanceMaterial",this.map=null,this.alphaMap=null,this.displacementMap=null,this.displacementScale=1,this.displacementBias=0,this.setValues(t)}copy(t){return super.copy(t),this.map=t.map,this.alphaMap=t.alphaMap,this.displacementMap=t.displacementMap,this.displacementScale=t.displacementScale,this.displacementBias=t.displacementBias,this}}class mx extends On{constructor(t,n=1){super(),this.isLight=!0,this.type="Light",this.color=new fe(t),this.intensity=n}dispose(){this.dispatchEvent({type:"dispose"})}copy(t,n){return super.copy(t,n),this.color.copy(t.color),this.intensity=t.intensity,this}toJSON(t){const n=super.toJSON(t);return n.object.color=this.color.getHex(),n.object.intensity=this.intensity,n}}class Kv extends mx{constructor(t,n,s){super(t,s),this.isHemisphereLight=!0,this.type="HemisphereLight",this.position.copy(On.DEFAULT_UP),this.updateMatrix(),this.groundColor=new fe(n)}copy(t,n){return super.copy(t,n),this.groundColor.copy(t.groundColor),this}toJSON(t){const n=super.toJSON(t);return n.object.groundColor=this.groundColor.getHex(),n}}const td=new en,jv=new K,Jv=new K;class DE{constructor(t){this.camera=t,this.intensity=1,this.bias=0,this.biasNode=null,this.normalBias=0,this.radius=1,this.blurSamples=8,this.mapSize=new qt(512,512),this.mapType=di,this.map=null,this.mapPass=null,this.matrix=new en,this.autoUpdate=!0,this.needsUpdate=!1,this._frustum=new gp,this._frameExtents=new qt(1,1),this._viewportCount=1,this._viewports=[new $e(0,0,1,1)]}getViewportCount(){return this._viewportCount}getFrustum(){return this._frustum}updateMatrices(t){const n=this.camera,s=this.matrix;jv.setFromMatrixPosition(t.matrixWorld),n.position.copy(jv),Jv.setFromMatrixPosition(t.target.matrixWorld),n.lookAt(Jv),n.updateMatrixWorld(),td.multiplyMatrices(n.projectionMatrix,n.matrixWorldInverse),this._frustum.setFromProjectionMatrix(td,n.coordinateSystem,n.reversedDepth),n.coordinateSystem===sl||n.reversedDepth?s.set(.5,0,0,.5,0,.5,0,.5,0,0,1,0,0,0,0,1):s.set(.5,0,0,.5,0,.5,0,.5,0,0,.5,.5,0,0,0,1),s.multiply(td)}getViewport(t){return this._viewports[t]}getFrameExtents(){return this._frameExtents}dispose(){this.map&&this.map.dispose(),this.mapPass&&this.mapPass.dispose()}copy(t){return this.camera=t.camera.clone(),this.intensity=t.intensity,this.bias=t.bias,this.radius=t.radius,this.autoUpdate=t.autoUpdate,this.needsUpdate=t.needsUpdate,this.normalBias=t.normalBias,this.blurSamples=t.blurSamples,this.mapSize.copy(t.mapSize),this.biasNode=t.biasNode,this}clone(){return new this.constructor().copy(this)}toJSON(){const t={};return this.intensity!==1&&(t.intensity=this.intensity),this.bias!==0&&(t.bias=this.bias),this.normalBias!==0&&(t.normalBias=this.normalBias),this.radius!==1&&(t.radius=this.radius),(this.mapSize.x!==512||this.mapSize.y!==512)&&(t.mapSize=this.mapSize.toArray()),t.camera=this.camera.toJSON(!1).object,delete t.camera.matrix,t}}const kc=new K,Xc=new Zr,Vi=new K;class gx extends On{constructor(){super(),this.isCamera=!0,this.type="Camera",this.matrixWorldInverse=new en,this.projectionMatrix=new en,this.projectionMatrixInverse=new en,this.coordinateSystem=qi,this._reversedDepth=!1}get reversedDepth(){return this._reversedDepth}copy(t,n){return super.copy(t,n),this.matrixWorldInverse.copy(t.matrixWorldInverse),this.projectionMatrix.copy(t.projectionMatrix),this.projectionMatrixInverse.copy(t.projectionMatrixInverse),this.coordinateSystem=t.coordinateSystem,this}getWorldDirection(t){return super.getWorldDirection(t).negate()}updateMatrixWorld(t){super.updateMatrixWorld(t),this.matrixWorld.decompose(kc,Xc,Vi),Vi.x===1&&Vi.y===1&&Vi.z===1?this.matrixWorldInverse.copy(this.matrixWorld).invert():this.matrixWorldInverse.compose(kc,Xc,Vi.set(1,1,1)).invert()}updateWorldMatrix(t,n,s=!1){super.updateWorldMatrix(t,n,s),this.matrixWorld.decompose(kc,Xc,Vi),Vi.x===1&&Vi.y===1&&Vi.z===1?this.matrixWorldInverse.copy(this.matrixWorld).invert():this.matrixWorldInverse.compose(kc,Xc,Vi.set(1,1,1)).invert()}clone(){return new this.constructor().copy(this)}}const rs=new K,Qv=new qt,$v=new qt;class bi extends gx{constructor(t=50,n=1,s=.1,l=2e3){super(),this.isPerspectiveCamera=!0,this.type="PerspectiveCamera",this.fov=t,this.zoom=1,this.near=s,this.far=l,this.focus=10,this.aspect=n,this.view=null,this.filmGauge=35,this.filmOffset=0,this.updateProjectionMatrix()}copy(t,n){return super.copy(t,n),this.fov=t.fov,this.zoom=t.zoom,this.near=t.near,this.far=t.far,this.focus=t.focus,this.aspect=t.aspect,this.view=t.view===null?null:Object.assign({},t.view),this.filmGauge=t.filmGauge,this.filmOffset=t.filmOffset,this}setFocalLength(t){const n=.5*this.getFilmHeight()/t;this.fov=Jd*2*Math.atan(n),this.updateProjectionMatrix()}getFocalLength(){const t=Math.tan(Rh*.5*this.fov);return .5*this.getFilmHeight()/t}getEffectiveFOV(){return Jd*2*Math.atan(Math.tan(Rh*.5*this.fov)/this.zoom)}getFilmWidth(){return this.filmGauge*Math.min(this.aspect,1)}getFilmHeight(){return this.filmGauge/Math.max(this.aspect,1)}getViewBounds(t,n,s){rs.set(-1,-1,.5).applyMatrix4(this.projectionMatrixInverse),n.set(rs.x,rs.y).multiplyScalar(-t/rs.z),rs.set(1,1,.5).applyMatrix4(this.projectionMatrixInverse),s.set(rs.x,rs.y).multiplyScalar(-t/rs.z)}getViewSize(t,n){return this.getViewBounds(t,Qv,$v),n.subVectors($v,Qv)}setViewOffset(t,n,s,l,c,f){this.aspect=t/n,this.view===null&&(this.view={enabled:!0,fullWidth:1,fullHeight:1,offsetX:0,offsetY:0,width:1,height:1}),this.view.enabled=!0,this.view.fullWidth=t,this.view.fullHeight=n,this.view.offsetX=s,this.view.offsetY=l,this.view.width=c,this.view.height=f,this.updateProjectionMatrix()}clearViewOffset(){this.view!==null&&(this.view.enabled=!1),this.updateProjectionMatrix()}updateProjectionMatrix(){const t=this.near;let n=t*Math.tan(Rh*.5*this.fov)/this.zoom,s=2*n,l=this.aspect*s,c=-.5*l;const f=this.view;if(this.view!==null&&this.view.enabled){const m=f.fullWidth,p=f.fullHeight;c+=f.offsetX*l/m,n-=f.offsetY*s/p,l*=f.width/m,s*=f.height/p}const d=this.filmOffset;d!==0&&(c+=t*d/this.getFilmWidth()),this.projectionMatrix.makePerspective(c,c+l,n,n-s,t,this.far,this.coordinateSystem,this.reversedDepth),this.projectionMatrixInverse.copy(this.projectionMatrix).invert()}toJSON(t){const n=super.toJSON(t);return n.object.fov=this.fov,n.object.zoom=this.zoom,n.object.near=this.near,n.object.far=this.far,n.object.focus=this.focus,n.object.aspect=this.aspect,this.view!==null&&(n.object.view=Object.assign({},this.view)),n.object.filmGauge=this.filmGauge,n.object.filmOffset=this.filmOffset,n}}class fu extends gx{constructor(t=-1,n=1,s=1,l=-1,c=.1,f=2e3){super(),this.isOrthographicCamera=!0,this.type="OrthographicCamera",this.zoom=1,this.view=null,this.left=t,this.right=n,this.top=s,this.bottom=l,this.near=c,this.far=f,this.updateProjectionMatrix()}copy(t,n){return super.copy(t,n),this.left=t.left,this.right=t.right,this.top=t.top,this.bottom=t.bottom,this.near=t.near,this.far=t.far,this.zoom=t.zoom,this.view=t.view===null?null:Object.assign({},t.view),this}setViewOffset(t,n,s,l,c,f){this.view===null&&(this.view={enabled:!0,fullWidth:1,fullHeight:1,offsetX:0,offsetY:0,width:1,height:1}),this.view.enabled=!0,this.view.fullWidth=t,this.view.fullHeight=n,this.view.offsetX=s,this.view.offsetY=l,this.view.width=c,this.view.height=f,this.updateProjectionMatrix()}clearViewOffset(){this.view!==null&&(this.view.enabled=!1),this.updateProjectionMatrix()}updateProjectionMatrix(){const t=(this.right-this.left)/(2*this.zoom),n=(this.top-this.bottom)/(2*this.zoom),s=(this.right+this.left)/2,l=(this.top+this.bottom)/2;let c=s-t,f=s+t,d=l+n,m=l-n;if(this.view!==null&&this.view.enabled){const p=(this.right-this.left)/this.view.fullWidth/this.zoom,v=(this.top-this.bottom)/this.view.fullHeight/this.zoom;c+=p*this.view.offsetX,f=c+p*this.view.width,d-=v*this.view.offsetY,m=d-v*this.view.height}this.projectionMatrix.makeOrthographic(c,f,d,m,this.near,this.far,this.coordinateSystem,this.reversedDepth),this.projectionMatrixInverse.copy(this.projectionMatrix).invert()}toJSON(t){const n=super.toJSON(t);return n.object.zoom=this.zoom,n.object.left=this.left,n.object.right=this.right,n.object.top=this.top,n.object.bottom=this.bottom,n.object.near=this.near,n.object.far=this.far,this.view!==null&&(n.object.view=Object.assign({},this.view)),n}}class NE extends DE{constructor(){super(new fu(-5,5,5,-5,.5,500)),this.isDirectionalLightShadow=!0}}class t_ extends mx{constructor(t,n){super(t,n),this.isDirectionalLight=!0,this.type="DirectionalLight",this.position.copy(On.DEFAULT_UP),this.updateMatrix(),this.target=new On,this.shadow=new NE}dispose(){super.dispose(),this.shadow.dispose()}copy(t){return super.copy(t),this.target=t.target.clone(),this.shadow=t.shadow.clone(),this}toJSON(t){const n=super.toJSON(t);return n.object.shadow=this.shadow.toJSON(),n.object.target=this.target.uuid,n}}const Pr=-90,Ir=1;class UE extends On{constructor(t,n,s){super(),this.type="CubeCamera",this.renderTarget=s,this.coordinateSystem=null,this.activeMipmapLevel=0;const l=new bi(Pr,Ir,t,n);l.layers=this.layers,this.add(l);const c=new bi(Pr,Ir,t,n);c.layers=this.layers,this.add(c);const f=new bi(Pr,Ir,t,n);f.layers=this.layers,this.add(f);const d=new bi(Pr,Ir,t,n);d.layers=this.layers,this.add(d);const m=new bi(Pr,Ir,t,n);m.layers=this.layers,this.add(m);const p=new bi(Pr,Ir,t,n);p.layers=this.layers,this.add(p)}updateCoordinateSystem(){const t=this.coordinateSystem,n=this.children.concat(),[s,l,c,f,d,m]=n;for(const p of n)this.remove(p);if(t===qi)s.up.set(0,1,0),s.lookAt(1,0,0),l.up.set(0,1,0),l.lookAt(-1,0,0),c.up.set(0,0,-1),c.lookAt(0,1,0),f.up.set(0,0,1),f.lookAt(0,-1,0),d.up.set(0,1,0),d.lookAt(0,0,1),m.up.set(0,1,0),m.lookAt(0,0,-1);else if(t===sl)s.up.set(0,-1,0),s.lookAt(-1,0,0),l.up.set(0,-1,0),l.lookAt(1,0,0),c.up.set(0,0,1),c.lookAt(0,1,0),f.up.set(0,0,-1),f.lookAt(0,-1,0),d.up.set(0,-1,0),d.lookAt(0,0,1),m.up.set(0,-1,0),m.lookAt(0,0,-1);else throw new Error("THREE.CubeCamera.updateCoordinateSystem(): Invalid coordinate system: "+t);for(const p of n)this.add(p),p.updateMatrixWorld()}update(t,n){this.parent===null&&this.updateMatrixWorld();const{renderTarget:s,activeMipmapLevel:l}=this;this.coordinateSystem!==t.coordinateSystem&&(this.coordinateSystem=t.coordinateSystem,this.updateCoordinateSystem());const[c,f,d,m,p,v]=this.children,_=t.getRenderTarget(),g=t.getActiveCubeFace(),y=t.getActiveMipmapLevel(),b=t.xr.enabled;t.xr.enabled=!1;const w=s.texture.generateMipmaps;s.texture.generateMipmaps=!1;let M=!1;t.isWebGLRenderer===!0?M=t.state.buffers.depth.getReversed():M=t.reversedDepthBuffer,t.setRenderTarget(s,0,l),M&&t.autoClear===!1&&t.clearDepth(),t.render(n,c),t.setRenderTarget(s,1,l),M&&t.autoClear===!1&&t.clearDepth(),t.render(n,f),t.setRenderTarget(s,2,l),M&&t.autoClear===!1&&t.clearDepth(),t.render(n,d),t.setRenderTarget(s,3,l),M&&t.autoClear===!1&&t.clearDepth(),t.render(n,m),t.setRenderTarget(s,4,l),M&&t.autoClear===!1&&t.clearDepth(),t.render(n,p),s.texture.generateMipmaps=w,t.setRenderTarget(s,5,l),M&&t.autoClear===!1&&t.clearDepth(),t.render(n,v),t.setRenderTarget(_,g,y),t.xr.enabled=b,s.texture.needsPMREMUpdate=!0}}class LE extends bi{constructor(t=[]){super(),this.isArrayCamera=!0,this.isMultiViewCamera=!1,this.cameras=t}}const Rp=class Rp{constructor(t,n,s,l){this.elements=[1,0,0,1],t!==void 0&&this.set(t,n,s,l)}identity(){return this.set(1,0,0,1),this}fromArray(t,n=0){for(let s=0;s<4;s++)this.elements[s]=t[s+n];return this}set(t,n,s,l){const c=this.elements;return c[0]=t,c[2]=n,c[1]=s,c[3]=l,this}};Rp.prototype.isMatrix2=!0;let e_=Rp;function n_(r,t,n,s){const l=OE(s);switch(n){case Z_:return r*t;case j_:return r*t/l.components*l.byteLength;case lp:return r*t/l.components*l.byteLength;case ks:return r*t*2/l.components*l.byteLength;case cp:return r*t*2/l.components*l.byteLength;case K_:return r*t*3/l.components*l.byteLength;case Pi:return r*t*4/l.components*l.byteLength;case up:return r*t*4/l.components*l.byteLength;case jc:case Jc:return Math.floor((r+3)/4)*Math.floor((t+3)/4)*8;case Qc:case $c:return Math.floor((r+3)/4)*Math.floor((t+3)/4)*16;case yd:case Ed:return Math.max(r,16)*Math.max(t,8)/4;case Sd:case Md:return Math.max(r,8)*Math.max(t,8)/2;case bd:case Td:case Rd:case Cd:return Math.floor((r+3)/4)*Math.floor((t+3)/4)*8;case Ad:case nu:case wd:return Math.floor((r+3)/4)*Math.floor((t+3)/4)*16;case Dd:return Math.floor((r+3)/4)*Math.floor((t+3)/4)*16;case Nd:return Math.floor((r+4)/5)*Math.floor((t+3)/4)*16;case Ud:return Math.floor((r+4)/5)*Math.floor((t+4)/5)*16;case Ld:return Math.floor((r+5)/6)*Math.floor((t+4)/5)*16;case Od:return Math.floor((r+5)/6)*Math.floor((t+5)/6)*16;case Pd:return Math.floor((r+7)/8)*Math.floor((t+4)/5)*16;case Id:return Math.floor((r+7)/8)*Math.floor((t+5)/6)*16;case zd:return Math.floor((r+7)/8)*Math.floor((t+7)/8)*16;case Fd:return Math.floor((r+9)/10)*Math.floor((t+4)/5)*16;case Bd:return Math.floor((r+9)/10)*Math.floor((t+5)/6)*16;case Hd:return Math.floor((r+9)/10)*Math.floor((t+7)/8)*16;case Gd:return Math.floor((r+9)/10)*Math.floor((t+9)/10)*16;case Vd:return Math.floor((r+11)/12)*Math.floor((t+9)/10)*16;case kd:return Math.floor((r+11)/12)*Math.floor((t+11)/12)*16;case Xd:case Wd:case qd:return Math.ceil(r/4)*Math.ceil(t/4)*16;case Yd:case Zd:return Math.ceil(r/4)*Math.ceil(t/4)*8;case iu:case Kd:return Math.ceil(r/4)*Math.ceil(t/4)*16}throw new Error(`Unable to determine texture byte length for ${n} format.`)}function OE(r){switch(r){case di:case X_:return{byteLength:1,components:1};case il:case W_:case Aa:return{byteLength:2,components:1};case rp:case op:return{byteLength:2,components:4};case ji:case sp:case Wi:return{byteLength:4,components:1};case q_:case Y_:return{byteLength:4,components:3}}throw new Error(`THREE.TextureUtils: Unknown texture type ${r}.`)}typeof __THREE_DEVTOOLS__<"u"&&__THREE_DEVTOOLS__.dispatchEvent(new CustomEvent("register",{detail:{revision:ap}}));typeof window<"u"&&(window.__THREE__?ie("WARNING: Multiple instances of Three.js being imported."):window.__THREE__=ap);/**
 * @license
 * Copyright 2010-2026 Three.js Authors
 * SPDX-License-Identifier: MIT
 */function vx(){let r=null,t=!1,n=null,s=null;function l(c,f){n(c,f),s=r.requestAnimationFrame(l)}return{start:function(){t!==!0&&n!==null&&r!==null&&(s=r.requestAnimationFrame(l),t=!0)},stop:function(){r!==null&&r.cancelAnimationFrame(s),t=!1},setAnimationLoop:function(c){n=c},setContext:function(c){r=c}}}function PE(r){const t=new WeakMap;function n(d,m){const p=d.array,v=d.usage,_=p.byteLength,g=r.createBuffer();r.bindBuffer(m,g),r.bufferData(m,p,v),d.onUploadCallback();let y;if(p instanceof Float32Array)y=r.FLOAT;else if(typeof Float16Array<"u"&&p instanceof Float16Array)y=r.HALF_FLOAT;else if(p instanceof Uint16Array)d.isFloat16BufferAttribute?y=r.HALF_FLOAT:y=r.UNSIGNED_SHORT;else if(p instanceof Int16Array)y=r.SHORT;else if(p instanceof Uint32Array)y=r.UNSIGNED_INT;else if(p instanceof Int32Array)y=r.INT;else if(p instanceof Int8Array)y=r.BYTE;else if(p instanceof Uint8Array)y=r.UNSIGNED_BYTE;else if(p instanceof Uint8ClampedArray)y=r.UNSIGNED_BYTE;else throw new Error("THREE.WebGLAttributes: Unsupported buffer data format: "+p);return{buffer:g,type:y,bytesPerElement:p.BYTES_PER_ELEMENT,version:d.version,size:_}}function s(d,m,p){const v=m.array,_=m.updateRanges;if(r.bindBuffer(p,d),_.length===0)r.bufferSubData(p,0,v);else{_.sort((y,b)=>y.start-b.start);let g=0;for(let y=1;y<_.length;y++){const b=_[g],w=_[y];w.start<=b.start+b.count+1?b.count=Math.max(b.count,w.start+w.count-b.start):(++g,_[g]=w)}_.length=g+1;for(let y=0,b=_.length;y<b;y++){const w=_[y];r.bufferSubData(p,w.start*v.BYTES_PER_ELEMENT,v,w.start,w.count)}m.clearUpdateRanges()}m.onUploadCallback()}function l(d){return d.isInterleavedBufferAttribute&&(d=d.data),t.get(d)}function c(d){d.isInterleavedBufferAttribute&&(d=d.data);const m=t.get(d);m&&(r.deleteBuffer(m.buffer),t.delete(d))}function f(d,m){if(d.isInterleavedBufferAttribute&&(d=d.data),d.isGLBufferAttribute){const v=t.get(d);(!v||v.version<d.version)&&t.set(d,{buffer:d.buffer,type:d.type,bytesPerElement:d.elementSize,version:d.version});return}const p=t.get(d);if(p===void 0)t.set(d,n(d,m));else if(p.version<d.version){if(p.size!==d.array.byteLength)throw new Error("THREE.WebGLAttributes: The size of the buffer attribute's array buffer does not match the original size. Resizing buffer attributes is not supported.");s(p.buffer,d,m),p.version=d.version}}return{get:l,remove:c,update:f}}var IE=`#ifdef USE_ALPHAHASH
	if ( diffuseColor.a < getAlphaHashThreshold( vPosition ) ) discard;
#endif`,zE=`#ifdef USE_ALPHAHASH
	const float ALPHA_HASH_SCALE = 0.05;
	float hash2D( vec2 value ) {
		return fract( 1.0e4 * sin( 17.0 * value.x + 0.1 * value.y ) * ( 0.1 + abs( sin( 13.0 * value.y + value.x ) ) ) );
	}
	float hash3D( vec3 value ) {
		return hash2D( vec2( hash2D( value.xy ), value.z ) );
	}
	float getAlphaHashThreshold( vec3 position ) {
		float maxDeriv = max(
			length( dFdx( position.xyz ) ),
			length( dFdy( position.xyz ) )
		);
		float pixScale = 1.0 / ( ALPHA_HASH_SCALE * maxDeriv );
		vec2 pixScales = vec2(
			exp2( floor( log2( pixScale ) ) ),
			exp2( ceil( log2( pixScale ) ) )
		);
		vec2 alpha = vec2(
			hash3D( floor( pixScales.x * position.xyz ) ),
			hash3D( floor( pixScales.y * position.xyz ) )
		);
		float lerpFactor = fract( log2( pixScale ) );
		float x = ( 1.0 - lerpFactor ) * alpha.x + lerpFactor * alpha.y;
		float a = min( lerpFactor, 1.0 - lerpFactor );
		vec3 cases = vec3(
			x * x / ( 2.0 * a * ( 1.0 - a ) ),
			( x - 0.5 * a ) / ( 1.0 - a ),
			1.0 - ( ( 1.0 - x ) * ( 1.0 - x ) / ( 2.0 * a * ( 1.0 - a ) ) )
		);
		float threshold = ( x < ( 1.0 - a ) )
			? ( ( x < a ) ? cases.x : cases.y )
			: cases.z;
		return clamp( threshold , 1.0e-6, 1.0 );
	}
#endif`,FE=`#ifdef USE_ALPHAMAP
	diffuseColor.a *= texture2D( alphaMap, vAlphaMapUv ).g;
#endif`,BE=`#ifdef USE_ALPHAMAP
	uniform sampler2D alphaMap;
#endif`,HE=`#ifdef USE_ALPHATEST
	#ifdef ALPHA_TO_COVERAGE
	diffuseColor.a = smoothstep( alphaTest, alphaTest + fwidth( diffuseColor.a ), diffuseColor.a );
	if ( diffuseColor.a == 0.0 ) discard;
	#else
	if ( diffuseColor.a < alphaTest ) discard;
	#endif
#endif`,GE=`#ifdef USE_ALPHATEST
	uniform float alphaTest;
#endif`,VE=`#ifdef USE_AOMAP
	float ambientOcclusion = ( texture2D( aoMap, vAoMapUv ).r - 1.0 ) * aoMapIntensity + 1.0;
	reflectedLight.indirectDiffuse *= ambientOcclusion;
	#if defined( USE_CLEARCOAT ) 
		clearcoatSpecularIndirect *= ambientOcclusion;
	#endif
	#if defined( USE_SHEEN ) 
		sheenSpecularIndirect *= ambientOcclusion;
	#endif
	#if defined( USE_ENVMAP ) && defined( STANDARD )
		float dotNV = saturate( dot( geometryNormal, geometryViewDir ) );
		reflectedLight.indirectSpecular *= computeSpecularOcclusion( dotNV, ambientOcclusion, material.roughness );
	#endif
#endif`,kE=`#ifdef USE_AOMAP
	uniform sampler2D aoMap;
	uniform float aoMapIntensity;
#endif`,XE=`#ifdef USE_BATCHING
	#if ! defined( GL_ANGLE_multi_draw )
	#define gl_DrawID _gl_DrawID
	uniform int _gl_DrawID;
	#endif
	uniform highp sampler2D batchingTexture;
	uniform highp usampler2D batchingIdTexture;
	mat4 getBatchingMatrix( const in float i ) {
		int size = textureSize( batchingTexture, 0 ).x;
		int j = int( i ) * 4;
		int x = j % size;
		int y = j / size;
		vec4 v1 = texelFetch( batchingTexture, ivec2( x, y ), 0 );
		vec4 v2 = texelFetch( batchingTexture, ivec2( x + 1, y ), 0 );
		vec4 v3 = texelFetch( batchingTexture, ivec2( x + 2, y ), 0 );
		vec4 v4 = texelFetch( batchingTexture, ivec2( x + 3, y ), 0 );
		return mat4( v1, v2, v3, v4 );
	}
	float getIndirectIndex( const in int i ) {
		int size = textureSize( batchingIdTexture, 0 ).x;
		int x = i % size;
		int y = i / size;
		return float( texelFetch( batchingIdTexture, ivec2( x, y ), 0 ).r );
	}
#endif
#ifdef USE_BATCHING_COLOR
	uniform sampler2D batchingColorTexture;
	vec4 getBatchingColor( const in float i ) {
		int size = textureSize( batchingColorTexture, 0 ).x;
		int j = int( i );
		int x = j % size;
		int y = j / size;
		return texelFetch( batchingColorTexture, ivec2( x, y ), 0 );
	}
#endif`,WE=`#ifdef USE_BATCHING
	mat4 batchingMatrix = getBatchingMatrix( getIndirectIndex( gl_DrawID ) );
#endif`,qE=`vec3 transformed = vec3( position );
#ifdef USE_ALPHAHASH
	vPosition = vec3( position );
#endif`,YE=`vec3 objectNormal = vec3( normal );
#ifdef USE_TANGENT
	vec3 objectTangent = vec3( tangent.xyz );
#endif`,ZE=`float G_BlinnPhong_Implicit( ) {
	return 0.25;
}
float D_BlinnPhong( const in float shininess, const in float dotNH ) {
	return RECIPROCAL_PI * ( shininess * 0.5 + 1.0 ) * pow( dotNH, shininess );
}
vec3 BRDF_BlinnPhong( const in vec3 lightDir, const in vec3 viewDir, const in vec3 normal, const in vec3 specularColor, const in float shininess ) {
	vec3 halfDir = normalize( lightDir + viewDir );
	float dotNH = saturate( dot( normal, halfDir ) );
	float dotVH = saturate( dot( viewDir, halfDir ) );
	vec3 F = F_Schlick( specularColor, 1.0, dotVH );
	float G = G_BlinnPhong_Implicit( );
	float D = D_BlinnPhong( shininess, dotNH );
	return F * ( G * D );
} // validated`,KE=`#ifdef USE_IRIDESCENCE
	const mat3 XYZ_TO_REC709 = mat3(
		 3.2404542, -0.9692660,  0.0556434,
		-1.5371385,  1.8760108, -0.2040259,
		-0.4985314,  0.0415560,  1.0572252
	);
	vec3 Fresnel0ToIor( vec3 fresnel0 ) {
		vec3 sqrtF0 = sqrt( fresnel0 );
		return ( vec3( 1.0 ) + sqrtF0 ) / ( vec3( 1.0 ) - sqrtF0 );
	}
	vec3 IorToFresnel0( vec3 transmittedIor, float incidentIor ) {
		return pow2( ( transmittedIor - vec3( incidentIor ) ) / ( transmittedIor + vec3( incidentIor ) ) );
	}
	float IorToFresnel0( float transmittedIor, float incidentIor ) {
		return pow2( ( transmittedIor - incidentIor ) / ( transmittedIor + incidentIor ));
	}
	vec3 evalSensitivity( float OPD, vec3 shift ) {
		float phase = 2.0 * PI * OPD * 1.0e-9;
		vec3 val = vec3( 5.4856e-13, 4.4201e-13, 5.2481e-13 );
		vec3 pos = vec3( 1.6810e+06, 1.7953e+06, 2.2084e+06 );
		vec3 var = vec3( 4.3278e+09, 9.3046e+09, 6.6121e+09 );
		vec3 xyz = val * sqrt( 2.0 * PI * var ) * cos( pos * phase + shift ) * exp( - pow2( phase ) * var );
		xyz.x += 9.7470e-14 * sqrt( 2.0 * PI * 4.5282e+09 ) * cos( 2.2399e+06 * phase + shift[ 0 ] ) * exp( - 4.5282e+09 * pow2( phase ) );
		xyz /= 1.0685e-7;
		vec3 rgb = XYZ_TO_REC709 * xyz;
		return rgb;
	}
	vec3 evalIridescence( float outsideIOR, float eta2, float cosTheta1, float thinFilmThickness, vec3 baseF0 ) {
		vec3 I;
		float iridescenceIOR = mix( outsideIOR, eta2, smoothstep( 0.0, 0.03, thinFilmThickness ) );
		float sinTheta2Sq = pow2( outsideIOR / iridescenceIOR ) * ( 1.0 - pow2( cosTheta1 ) );
		float cosTheta2Sq = 1.0 - sinTheta2Sq;
		if ( cosTheta2Sq < 0.0 ) {
			return vec3( 1.0 );
		}
		float cosTheta2 = sqrt( cosTheta2Sq );
		float R0 = IorToFresnel0( iridescenceIOR, outsideIOR );
		float R12 = F_Schlick( R0, 1.0, cosTheta1 );
		float T121 = 1.0 - R12;
		float phi12 = 0.0;
		if ( iridescenceIOR < outsideIOR ) phi12 = PI;
		float phi21 = PI - phi12;
		vec3 baseIOR = Fresnel0ToIor( clamp( baseF0, 0.0, 0.9999 ) );		vec3 R1 = IorToFresnel0( baseIOR, iridescenceIOR );
		vec3 R23 = F_Schlick( R1, 1.0, cosTheta2 );
		vec3 phi23 = vec3( 0.0 );
		if ( baseIOR[ 0 ] < iridescenceIOR ) phi23[ 0 ] = PI;
		if ( baseIOR[ 1 ] < iridescenceIOR ) phi23[ 1 ] = PI;
		if ( baseIOR[ 2 ] < iridescenceIOR ) phi23[ 2 ] = PI;
		float OPD = 2.0 * iridescenceIOR * thinFilmThickness * cosTheta2;
		vec3 phi = vec3( phi21 ) + phi23;
		vec3 R123 = clamp( R12 * R23, 1e-5, 0.9999 );
		vec3 r123 = sqrt( R123 );
		vec3 Rs = pow2( T121 ) * R23 / ( vec3( 1.0 ) - R123 );
		vec3 C0 = R12 + Rs;
		I = C0;
		vec3 Cm = Rs - T121;
		for ( int m = 1; m <= 2; ++ m ) {
			Cm *= r123;
			vec3 Sm = 2.0 * evalSensitivity( float( m ) * OPD, float( m ) * phi );
			I += Cm * Sm;
		}
		return max( I, vec3( 0.0 ) );
	}
#endif`,jE=`#ifdef USE_BUMPMAP
	uniform sampler2D bumpMap;
	uniform float bumpScale;
	vec2 dHdxy_fwd() {
		vec2 dSTdx = dFdx( vBumpMapUv );
		vec2 dSTdy = dFdy( vBumpMapUv );
		float Hll = bumpScale * texture2D( bumpMap, vBumpMapUv ).x;
		float dBx = bumpScale * texture2D( bumpMap, vBumpMapUv + dSTdx ).x - Hll;
		float dBy = bumpScale * texture2D( bumpMap, vBumpMapUv + dSTdy ).x - Hll;
		return vec2( dBx, dBy );
	}
	vec3 perturbNormalArb( vec3 surf_pos, vec3 surf_norm, vec2 dHdxy, float faceDirection ) {
		vec3 vSigmaX = normalize( dFdx( surf_pos.xyz ) );
		vec3 vSigmaY = normalize( dFdy( surf_pos.xyz ) );
		vec3 vN = surf_norm;
		vec3 R1 = cross( vSigmaY, vN );
		vec3 R2 = cross( vN, vSigmaX );
		float fDet = dot( vSigmaX, R1 ) * faceDirection;
		vec3 vGrad = sign( fDet ) * ( dHdxy.x * R1 + dHdxy.y * R2 );
		return normalize( abs( fDet ) * surf_norm - vGrad );
	}
#endif`,JE=`#if NUM_CLIPPING_PLANES > 0
	vec4 plane;
	#ifdef ALPHA_TO_COVERAGE
		float distanceToPlane, distanceGradient;
		float clipOpacity = 1.0;
		#pragma unroll_loop_start
		for ( int i = 0; i < UNION_CLIPPING_PLANES; i ++ ) {
			plane = clippingPlanes[ i ];
			distanceToPlane = - dot( vClipPosition, plane.xyz ) + plane.w;
			distanceGradient = fwidth( distanceToPlane ) / 2.0;
			clipOpacity *= smoothstep( - distanceGradient, distanceGradient, distanceToPlane );
			if ( clipOpacity == 0.0 ) discard;
		}
		#pragma unroll_loop_end
		#if UNION_CLIPPING_PLANES < NUM_CLIPPING_PLANES
			float unionClipOpacity = 1.0;
			#pragma unroll_loop_start
			for ( int i = UNION_CLIPPING_PLANES; i < NUM_CLIPPING_PLANES; i ++ ) {
				plane = clippingPlanes[ i ];
				distanceToPlane = - dot( vClipPosition, plane.xyz ) + plane.w;
				distanceGradient = fwidth( distanceToPlane ) / 2.0;
				unionClipOpacity *= 1.0 - smoothstep( - distanceGradient, distanceGradient, distanceToPlane );
			}
			#pragma unroll_loop_end
			clipOpacity *= 1.0 - unionClipOpacity;
		#endif
		diffuseColor.a *= clipOpacity;
		if ( diffuseColor.a == 0.0 ) discard;
	#else
		#pragma unroll_loop_start
		for ( int i = 0; i < UNION_CLIPPING_PLANES; i ++ ) {
			plane = clippingPlanes[ i ];
			if ( dot( vClipPosition, plane.xyz ) > plane.w ) discard;
		}
		#pragma unroll_loop_end
		#if UNION_CLIPPING_PLANES < NUM_CLIPPING_PLANES
			bool clipped = true;
			#pragma unroll_loop_start
			for ( int i = UNION_CLIPPING_PLANES; i < NUM_CLIPPING_PLANES; i ++ ) {
				plane = clippingPlanes[ i ];
				clipped = ( dot( vClipPosition, plane.xyz ) > plane.w ) && clipped;
			}
			#pragma unroll_loop_end
			if ( clipped ) discard;
		#endif
	#endif
#endif`,QE=`#if NUM_CLIPPING_PLANES > 0
	varying vec3 vClipPosition;
	uniform vec4 clippingPlanes[ NUM_CLIPPING_PLANES ];
#endif`,$E=`#if NUM_CLIPPING_PLANES > 0
	varying vec3 vClipPosition;
#endif`,t1=`#if NUM_CLIPPING_PLANES > 0
	vClipPosition = - mvPosition.xyz;
#endif`,e1=`#if defined( USE_COLOR ) || defined( USE_COLOR_ALPHA )
	diffuseColor *= vColor;
#endif`,n1=`#if defined( USE_COLOR ) || defined( USE_COLOR_ALPHA )
	varying vec4 vColor;
#endif`,i1=`#if defined( USE_COLOR ) || defined( USE_COLOR_ALPHA ) || defined( USE_INSTANCING_COLOR ) || defined( USE_BATCHING_COLOR )
	varying vec4 vColor;
#endif`,a1=`#if defined( USE_COLOR ) || defined( USE_COLOR_ALPHA ) || defined( USE_INSTANCING_COLOR ) || defined( USE_BATCHING_COLOR )
	vColor = vec4( 1.0 );
#endif
#ifdef USE_COLOR_ALPHA
	vColor *= color;
#elif defined( USE_COLOR )
	vColor.rgb *= color;
#endif
#ifdef USE_INSTANCING_COLOR
	vColor.rgb *= instanceColor.rgb;
#endif
#ifdef USE_BATCHING_COLOR
	vColor *= getBatchingColor( getIndirectIndex( gl_DrawID ) );
#endif`,s1=`#define PI 3.141592653589793
#define PI2 6.283185307179586
#define PI_HALF 1.5707963267948966
#define RECIPROCAL_PI 0.3183098861837907
#define RECIPROCAL_PI2 0.15915494309189535
#define EPSILON 1e-6
#ifndef saturate
#define saturate( a ) clamp( a, 0.0, 1.0 )
#endif
#define whiteComplement( a ) ( 1.0 - saturate( a ) )
float pow2( const in float x ) { return x*x; }
vec3 pow2( const in vec3 x ) { return x*x; }
float pow3( const in float x ) { return x*x*x; }
float pow4( const in float x ) { float x2 = x*x; return x2*x2; }
float max3( const in vec3 v ) { return max( max( v.x, v.y ), v.z ); }
float average( const in vec3 v ) { return dot( v, vec3( 0.3333333 ) ); }
highp float rand( const in vec2 uv ) {
	const highp float a = 12.9898, b = 78.233, c = 43758.5453;
	highp float dt = dot( uv.xy, vec2( a,b ) ), sn = mod( dt, PI );
	return fract( sin( sn ) * c );
}
#ifdef HIGH_PRECISION
	float precisionSafeLength( vec3 v ) { return length( v ); }
#else
	float precisionSafeLength( vec3 v ) {
		float maxComponent = max3( abs( v ) );
		return length( v / maxComponent ) * maxComponent;
	}
#endif
struct IncidentLight {
	vec3 color;
	vec3 direction;
	bool visible;
};
struct ReflectedLight {
	vec3 directDiffuse;
	vec3 directSpecular;
	vec3 indirectDiffuse;
	vec3 indirectSpecular;
};
#ifdef USE_ALPHAHASH
	varying vec3 vPosition;
#endif
vec3 transformDirection( in vec3 dir, in mat4 matrix ) {
	return normalize( ( matrix * vec4( dir, 0.0 ) ).xyz );
}
#define inverseTransformDirection transformDirectionByInverseViewMatrix
vec3 transformNormalByInverseViewMatrix( in vec3 normal, in mat4 viewMatrix ) {
	return normalize( ( vec4( normal, 0.0 ) * viewMatrix ).xyz );
}
vec3 transformDirectionByInverseViewMatrix( in vec3 dir, in mat4 viewMatrix ) {
	return normalize( ( vec4( dir, 0.0 ) * viewMatrix ).xyz );
}
bool isPerspectiveMatrix( mat4 m ) {
	return m[ 2 ][ 3 ] == - 1.0;
}
vec2 equirectUv( in vec3 dir ) {
	float u = atan( dir.z, dir.x ) * RECIPROCAL_PI2 + 0.5;
	float v = asin( clamp( dir.y, - 1.0, 1.0 ) ) * RECIPROCAL_PI + 0.5;
	return vec2( u, v );
}
vec3 BRDF_Lambert( const in vec3 diffuseColor ) {
	return RECIPROCAL_PI * diffuseColor;
}
vec3 F_Schlick( const in vec3 f0, const in float f90, const in float dotVH ) {
	float fresnel = exp2( ( - 5.55473 * dotVH - 6.98316 ) * dotVH );
	return f0 * ( 1.0 - fresnel ) + ( f90 * fresnel );
}
float F_Schlick( const in float f0, const in float f90, const in float dotVH ) {
	float fresnel = exp2( ( - 5.55473 * dotVH - 6.98316 ) * dotVH );
	return f0 * ( 1.0 - fresnel ) + ( f90 * fresnel );
} // validated`,r1=`#ifdef ENVMAP_TYPE_CUBE_UV
	#define cubeUV_minMipLevel 4.0
	#define cubeUV_minTileSize 16.0
	float getFace( vec3 direction ) {
		vec3 absDirection = abs( direction );
		float face = - 1.0;
		if ( absDirection.x > absDirection.z ) {
			if ( absDirection.x > absDirection.y )
				face = direction.x > 0.0 ? 0.0 : 3.0;
			else
				face = direction.y > 0.0 ? 1.0 : 4.0;
		} else {
			if ( absDirection.z > absDirection.y )
				face = direction.z > 0.0 ? 2.0 : 5.0;
			else
				face = direction.y > 0.0 ? 1.0 : 4.0;
		}
		return face;
	}
	vec2 getUV( vec3 direction, float face ) {
		vec2 uv;
		if ( face == 0.0 ) {
			uv = vec2( direction.z, direction.y ) / abs( direction.x );
		} else if ( face == 1.0 ) {
			uv = vec2( - direction.x, - direction.z ) / abs( direction.y );
		} else if ( face == 2.0 ) {
			uv = vec2( - direction.x, direction.y ) / abs( direction.z );
		} else if ( face == 3.0 ) {
			uv = vec2( - direction.z, direction.y ) / abs( direction.x );
		} else if ( face == 4.0 ) {
			uv = vec2( - direction.x, direction.z ) / abs( direction.y );
		} else {
			uv = vec2( direction.x, direction.y ) / abs( direction.z );
		}
		return 0.5 * ( uv + 1.0 );
	}
	vec3 bilinearCubeUV( sampler2D envMap, vec3 direction, float mipInt ) {
		float face = getFace( direction );
		float filterInt = max( cubeUV_minMipLevel - mipInt, 0.0 );
		mipInt = max( mipInt, cubeUV_minMipLevel );
		float faceSize = exp2( mipInt );
		highp vec2 uv = getUV( direction, face ) * ( faceSize - 2.0 ) + 1.0;
		if ( face > 2.0 ) {
			uv.y += faceSize;
			face -= 3.0;
		}
		uv.x += face * faceSize;
		uv.x += filterInt * 3.0 * cubeUV_minTileSize;
		uv.y += 4.0 * ( exp2( CUBEUV_MAX_MIP ) - faceSize );
		uv.x *= CUBEUV_TEXEL_WIDTH;
		uv.y *= CUBEUV_TEXEL_HEIGHT;
		#ifdef texture2DGradEXT
			return texture2DGradEXT( envMap, uv, vec2( 0.0 ), vec2( 0.0 ) ).rgb;
		#else
			return texture2D( envMap, uv ).rgb;
		#endif
	}
	#define cubeUV_r0 1.0
	#define cubeUV_m0 - 2.0
	#define cubeUV_r1 0.8
	#define cubeUV_m1 - 1.0
	#define cubeUV_r4 0.4
	#define cubeUV_m4 2.0
	#define cubeUV_r5 0.305
	#define cubeUV_m5 3.0
	#define cubeUV_r6 0.21
	#define cubeUV_m6 4.0
	float roughnessToMip( float roughness ) {
		float mip = 0.0;
		if ( roughness >= cubeUV_r1 ) {
			mip = ( cubeUV_r0 - roughness ) * ( cubeUV_m1 - cubeUV_m0 ) / ( cubeUV_r0 - cubeUV_r1 ) + cubeUV_m0;
		} else if ( roughness >= cubeUV_r4 ) {
			mip = ( cubeUV_r1 - roughness ) * ( cubeUV_m4 - cubeUV_m1 ) / ( cubeUV_r1 - cubeUV_r4 ) + cubeUV_m1;
		} else if ( roughness >= cubeUV_r5 ) {
			mip = ( cubeUV_r4 - roughness ) * ( cubeUV_m5 - cubeUV_m4 ) / ( cubeUV_r4 - cubeUV_r5 ) + cubeUV_m4;
		} else if ( roughness >= cubeUV_r6 ) {
			mip = ( cubeUV_r5 - roughness ) * ( cubeUV_m6 - cubeUV_m5 ) / ( cubeUV_r5 - cubeUV_r6 ) + cubeUV_m5;
		} else {
			mip = - 2.0 * log2( 1.16 * roughness );		}
		return mip;
	}
	vec4 textureCubeUV( sampler2D envMap, vec3 sampleDir, float roughness ) {
		float mip = clamp( roughnessToMip( roughness ), cubeUV_m0, CUBEUV_MAX_MIP );
		float mipF = fract( mip );
		float mipInt = floor( mip );
		vec3 color0 = bilinearCubeUV( envMap, sampleDir, mipInt );
		if ( mipF == 0.0 ) {
			return vec4( color0, 1.0 );
		} else {
			vec3 color1 = bilinearCubeUV( envMap, sampleDir, mipInt + 1.0 );
			return vec4( mix( color0, color1, mipF ), 1.0 );
		}
	}
#endif`,o1=`vec3 transformedNormal = objectNormal;
#ifdef USE_TANGENT
	vec3 transformedTangent = objectTangent;
#endif
#ifdef USE_BATCHING
	mat3 bm = mat3( batchingMatrix );
	transformedNormal /= vec3( dot( bm[ 0 ], bm[ 0 ] ), dot( bm[ 1 ], bm[ 1 ] ), dot( bm[ 2 ], bm[ 2 ] ) );
	transformedNormal = bm * transformedNormal;
	#ifdef USE_TANGENT
		transformedTangent = bm * transformedTangent;
	#endif
#endif
#ifdef USE_INSTANCING
	mat3 im = mat3( instanceMatrix );
	transformedNormal /= vec3( dot( im[ 0 ], im[ 0 ] ), dot( im[ 1 ], im[ 1 ] ), dot( im[ 2 ], im[ 2 ] ) );
	transformedNormal = im * transformedNormal;
	#ifdef USE_TANGENT
		transformedTangent = im * transformedTangent;
	#endif
#endif
transformedNormal = normalMatrix * transformedNormal;
#ifdef FLIP_SIDED
	transformedNormal = - transformedNormal;
#endif
#ifdef USE_TANGENT
	transformedTangent = ( modelViewMatrix * vec4( transformedTangent, 0.0 ) ).xyz;
#endif`,l1=`#ifdef USE_DISPLACEMENTMAP
	uniform sampler2D displacementMap;
	uniform float displacementScale;
	uniform float displacementBias;
#endif`,c1=`#ifdef USE_DISPLACEMENTMAP
	transformed += normalize( objectNormal ) * ( texture2D( displacementMap, vDisplacementMapUv ).x * displacementScale + displacementBias );
#endif`,u1=`#ifdef USE_EMISSIVEMAP
	vec4 emissiveColor = texture2D( emissiveMap, vEmissiveMapUv );
	#ifdef DECODE_VIDEO_TEXTURE_EMISSIVE
		emissiveColor = sRGBTransferEOTF( emissiveColor );
	#endif
	totalEmissiveRadiance *= emissiveColor.rgb;
#endif`,f1=`#ifdef USE_EMISSIVEMAP
	uniform sampler2D emissiveMap;
#endif`,h1="gl_FragColor = linearToOutputTexel( gl_FragColor );",d1=`vec4 LinearTransferOETF( in vec4 value ) {
	return value;
}
vec4 sRGBTransferEOTF( in vec4 value ) {
	return vec4( mix( pow( value.rgb * 0.9478672986 + vec3( 0.0521327014 ), vec3( 2.4 ) ), value.rgb * 0.0773993808, vec3( lessThanEqual( value.rgb, vec3( 0.04045 ) ) ) ), value.a );
}
vec4 sRGBTransferOETF( in vec4 value ) {
	return vec4( mix( pow( value.rgb, vec3( 0.41666 ) ) * 1.055 - vec3( 0.055 ), value.rgb * 12.92, vec3( lessThanEqual( value.rgb, vec3( 0.0031308 ) ) ) ), value.a );
}`,p1=`#ifdef USE_ENVMAP
	#ifdef ENV_WORLDPOS
		vec3 cameraToFrag;
		if ( isOrthographic ) {
			cameraToFrag = normalize( vec3( - viewMatrix[ 0 ][ 2 ], - viewMatrix[ 1 ][ 2 ], - viewMatrix[ 2 ][ 2 ] ) );
		} else {
			cameraToFrag = normalize( vWorldPosition - cameraPosition );
		}
		vec3 worldNormal = transformNormalByInverseViewMatrix( normal, viewMatrix );
		#ifdef ENVMAP_MODE_REFLECTION
			vec3 reflectVec = reflect( cameraToFrag, worldNormal );
		#else
			vec3 reflectVec = refract( cameraToFrag, worldNormal, refractionRatio );
		#endif
	#else
		vec3 reflectVec = vReflect;
	#endif
	#ifdef ENVMAP_TYPE_CUBE
		vec4 envColor = textureCube( envMap, envMapRotation * reflectVec );
		#ifdef ENVMAP_BLENDING_MULTIPLY
			outgoingLight = mix( outgoingLight, outgoingLight * envColor.xyz, specularStrength * reflectivity );
		#elif defined( ENVMAP_BLENDING_MIX )
			outgoingLight = mix( outgoingLight, envColor.xyz, specularStrength * reflectivity );
		#elif defined( ENVMAP_BLENDING_ADD )
			outgoingLight += envColor.xyz * specularStrength * reflectivity;
		#endif
	#endif
#endif`,m1=`#ifdef USE_ENVMAP
	uniform float envMapIntensity;
	uniform mat3 envMapRotation;
	#ifdef ENVMAP_TYPE_CUBE
		uniform samplerCube envMap;
	#else
		uniform sampler2D envMap;
	#endif
#endif`,g1=`#ifdef USE_ENVMAP
	uniform float reflectivity;
	#if defined( USE_BUMPMAP ) || defined( USE_NORMALMAP ) || defined( PHONG ) || defined( LAMBERT )
		#define ENV_WORLDPOS
	#endif
	#ifdef ENV_WORLDPOS
		varying vec3 vWorldPosition;
		uniform float refractionRatio;
	#else
		varying vec3 vReflect;
	#endif
#endif`,v1=`#ifdef USE_ENVMAP
	#if defined( USE_BUMPMAP ) || defined( USE_NORMALMAP ) || defined( PHONG ) || defined( LAMBERT )
		#define ENV_WORLDPOS
	#endif
	#ifdef ENV_WORLDPOS
		
		varying vec3 vWorldPosition;
	#else
		varying vec3 vReflect;
		uniform float refractionRatio;
	#endif
#endif`,_1=`#ifdef USE_ENVMAP
	#ifdef ENV_WORLDPOS
		vWorldPosition = worldPosition.xyz;
	#else
		vec3 cameraToVertex;
		if ( isOrthographic ) {
			cameraToVertex = normalize( vec3( - viewMatrix[ 0 ][ 2 ], - viewMatrix[ 1 ][ 2 ], - viewMatrix[ 2 ][ 2 ] ) );
		} else {
			cameraToVertex = normalize( worldPosition.xyz - cameraPosition );
		}
		vec3 worldNormal = transformNormalByInverseViewMatrix( transformedNormal, viewMatrix );
		#ifdef ENVMAP_MODE_REFLECTION
			vReflect = reflect( cameraToVertex, worldNormal );
		#else
			vReflect = refract( cameraToVertex, worldNormal, refractionRatio );
		#endif
	#endif
#endif`,x1=`#ifdef USE_FOG
	vFogDepth = - mvPosition.z;
#endif`,S1=`#ifdef USE_FOG
	varying float vFogDepth;
#endif`,y1=`#ifdef USE_FOG
	#ifdef FOG_EXP2
		float fogFactor = 1.0 - exp( - fogDensity * fogDensity * vFogDepth * vFogDepth );
	#else
		float fogFactor = smoothstep( fogNear, fogFar, vFogDepth );
	#endif
	gl_FragColor.rgb = mix( gl_FragColor.rgb, fogColor, fogFactor );
#endif`,M1=`#ifdef USE_FOG
	uniform vec3 fogColor;
	varying float vFogDepth;
	#ifdef FOG_EXP2
		uniform float fogDensity;
	#else
		uniform float fogNear;
		uniform float fogFar;
	#endif
#endif`,E1=`#ifdef USE_GRADIENTMAP
	uniform sampler2D gradientMap;
#endif
vec3 getGradientIrradiance( vec3 normal, vec3 lightDirection ) {
	float dotNL = dot( normal, lightDirection );
	vec2 coord = vec2( dotNL * 0.5 + 0.5, 0.0 );
	#ifdef USE_GRADIENTMAP
		return vec3( texture2D( gradientMap, coord ).r );
	#else
		vec2 fw = fwidth( coord ) * 0.5;
		return mix( vec3( 0.7 ), vec3( 1.0 ), smoothstep( 0.7 - fw.x, 0.7 + fw.x, coord.x ) );
	#endif
}`,b1=`#ifdef USE_LIGHTMAP
	uniform sampler2D lightMap;
	uniform float lightMapIntensity;
#endif`,T1=`LambertMaterial material;
material.diffuseColor = diffuseColor.rgb;
material.specularStrength = specularStrength;`,A1=`varying vec3 vViewPosition;
struct LambertMaterial {
	vec3 diffuseColor;
	float specularStrength;
};
void RE_Direct_Lambert( const in IncidentLight directLight, const in vec3 geometryPosition, const in vec3 geometryNormal, const in vec3 geometryViewDir, const in vec3 geometryClearcoatNormal, const in LambertMaterial material, inout ReflectedLight reflectedLight ) {
	float dotNL = saturate( dot( geometryNormal, directLight.direction ) );
	vec3 irradiance = dotNL * directLight.color;
	reflectedLight.directDiffuse += irradiance * BRDF_Lambert( material.diffuseColor );
}
void RE_IndirectDiffuse_Lambert( const in vec3 irradiance, const in vec3 geometryPosition, const in vec3 geometryNormal, const in vec3 geometryViewDir, const in vec3 geometryClearcoatNormal, const in LambertMaterial material, inout ReflectedLight reflectedLight ) {
	reflectedLight.indirectDiffuse += irradiance * BRDF_Lambert( material.diffuseColor );
}
#define RE_Direct				RE_Direct_Lambert
#define RE_IndirectDiffuse		RE_IndirectDiffuse_Lambert`,R1=`uniform bool receiveShadow;
uniform vec3 ambientLightColor;
#if defined( USE_LIGHT_PROBES )
	uniform vec3 lightProbe[ 9 ];
#endif
vec3 shGetIrradianceAt( in vec3 normal, in vec3 shCoefficients[ 9 ] ) {
	float x = normal.x, y = normal.y, z = normal.z;
	vec3 result = shCoefficients[ 0 ] * 0.886227;
	result += shCoefficients[ 1 ] * 2.0 * 0.511664 * y;
	result += shCoefficients[ 2 ] * 2.0 * 0.511664 * z;
	result += shCoefficients[ 3 ] * 2.0 * 0.511664 * x;
	result += shCoefficients[ 4 ] * 2.0 * 0.429043 * x * y;
	result += shCoefficients[ 5 ] * 2.0 * 0.429043 * y * z;
	result += shCoefficients[ 6 ] * ( 0.743125 * z * z - 0.247708 );
	result += shCoefficients[ 7 ] * 2.0 * 0.429043 * x * z;
	result += shCoefficients[ 8 ] * 0.429043 * ( x * x - y * y );
	return result;
}
vec3 getLightProbeIrradiance( const in vec3 lightProbe[ 9 ], const in vec3 normal ) {
	vec3 worldNormal = transformNormalByInverseViewMatrix( normal, viewMatrix );
	vec3 irradiance = shGetIrradianceAt( worldNormal, lightProbe );
	return irradiance;
}
vec3 getAmbientLightIrradiance( const in vec3 ambientLightColor ) {
	vec3 irradiance = ambientLightColor;
	return irradiance;
}
float getDistanceAttenuation( const in float lightDistance, const in float cutoffDistance, const in float decayExponent ) {
	float distanceFalloff = 1.0 / max( pow( lightDistance, decayExponent ), 0.01 );
	if ( cutoffDistance > 0.0 ) {
		distanceFalloff *= pow2( saturate( 1.0 - pow4( lightDistance / cutoffDistance ) ) );
	}
	return distanceFalloff;
}
float getSpotAttenuation( const in float coneCosine, const in float penumbraCosine, const in float angleCosine ) {
	return smoothstep( coneCosine, penumbraCosine, angleCosine );
}
#if NUM_DIR_LIGHTS > 0
	struct DirectionalLight {
		vec3 direction;
		vec3 color;
	};
	uniform DirectionalLight directionalLights[ NUM_DIR_LIGHTS ];
	void getDirectionalLightInfo( const in DirectionalLight directionalLight, out IncidentLight light ) {
		light.color = directionalLight.color;
		light.direction = directionalLight.direction;
		light.visible = true;
	}
#endif
#if NUM_POINT_LIGHTS > 0
	struct PointLight {
		vec3 position;
		vec3 color;
		float distance;
		float decay;
	};
	uniform PointLight pointLights[ NUM_POINT_LIGHTS ];
	void getPointLightInfo( const in PointLight pointLight, const in vec3 geometryPosition, out IncidentLight light ) {
		vec3 lVector = pointLight.position - geometryPosition;
		light.direction = normalize( lVector );
		float lightDistance = length( lVector );
		light.color = pointLight.color;
		light.color *= getDistanceAttenuation( lightDistance, pointLight.distance, pointLight.decay );
		light.visible = ( light.color != vec3( 0.0 ) );
	}
#endif
#if NUM_SPOT_LIGHTS > 0
	struct SpotLight {
		vec3 position;
		vec3 direction;
		vec3 color;
		float distance;
		float decay;
		float coneCos;
		float penumbraCos;
	};
	uniform SpotLight spotLights[ NUM_SPOT_LIGHTS ];
	void getSpotLightInfo( const in SpotLight spotLight, const in vec3 geometryPosition, out IncidentLight light ) {
		vec3 lVector = spotLight.position - geometryPosition;
		light.direction = normalize( lVector );
		float angleCos = dot( light.direction, spotLight.direction );
		float spotAttenuation = getSpotAttenuation( spotLight.coneCos, spotLight.penumbraCos, angleCos );
		if ( spotAttenuation > 0.0 ) {
			float lightDistance = length( lVector );
			light.color = spotLight.color * spotAttenuation;
			light.color *= getDistanceAttenuation( lightDistance, spotLight.distance, spotLight.decay );
			light.visible = ( light.color != vec3( 0.0 ) );
		} else {
			light.color = vec3( 0.0 );
			light.visible = false;
		}
	}
#endif
#if NUM_RECT_AREA_LIGHTS > 0
	struct RectAreaLight {
		vec3 color;
		vec3 position;
		vec3 halfWidth;
		vec3 halfHeight;
	};
	uniform sampler2D ltc_1;	uniform sampler2D ltc_2;
	uniform RectAreaLight rectAreaLights[ NUM_RECT_AREA_LIGHTS ];
#endif
#if NUM_HEMI_LIGHTS > 0
	struct HemisphereLight {
		vec3 direction;
		vec3 skyColor;
		vec3 groundColor;
	};
	uniform HemisphereLight hemisphereLights[ NUM_HEMI_LIGHTS ];
	vec3 getHemisphereLightIrradiance( const in HemisphereLight hemiLight, const in vec3 normal ) {
		float dotNL = dot( normal, hemiLight.direction );
		float hemiDiffuseWeight = 0.5 * dotNL + 0.5;
		vec3 irradiance = mix( hemiLight.groundColor, hemiLight.skyColor, hemiDiffuseWeight );
		return irradiance;
	}
#endif
#include <lightprobes_pars_fragment>`,C1=`#ifdef USE_ENVMAP
	vec3 getIBLIrradiance( const in vec3 normal ) {
		#ifdef ENVMAP_TYPE_CUBE_UV
			vec3 worldNormal = transformNormalByInverseViewMatrix( normal, viewMatrix );
			vec4 envMapColor = textureCubeUV( envMap, envMapRotation * worldNormal, 1.0 );
			return PI * envMapColor.rgb * envMapIntensity;
		#else
			return vec3( 0.0 );
		#endif
	}
	vec3 getIBLRadiance( const in vec3 viewDir, const in vec3 normal, const in float roughness ) {
		#ifdef ENVMAP_TYPE_CUBE_UV
			vec3 reflectVec = reflect( - viewDir, normal );
			reflectVec = normalize( mix( reflectVec, normal, pow4( roughness ) ) );
			reflectVec = transformDirectionByInverseViewMatrix( reflectVec, viewMatrix );
			vec4 envMapColor = textureCubeUV( envMap, envMapRotation * reflectVec, roughness );
			return envMapColor.rgb * envMapIntensity;
		#else
			return vec3( 0.0 );
		#endif
	}
	#ifdef USE_ANISOTROPY
		vec3 getIBLAnisotropyRadiance( const in vec3 viewDir, const in vec3 normal, const in float roughness, const in vec3 bitangent, const in float anisotropy ) {
			#ifdef ENVMAP_TYPE_CUBE_UV
				vec3 bentNormal = cross( bitangent, viewDir );
				bentNormal = normalize( cross( bentNormal, bitangent ) );
				bentNormal = normalize( mix( bentNormal, normal, pow2( pow2( 1.0 - anisotropy * ( 1.0 - roughness ) ) ) ) );
				return getIBLRadiance( viewDir, bentNormal, roughness );
			#else
				return vec3( 0.0 );
			#endif
		}
	#endif
#endif`,w1=`ToonMaterial material;
material.diffuseColor = diffuseColor.rgb;`,D1=`varying vec3 vViewPosition;
struct ToonMaterial {
	vec3 diffuseColor;
};
void RE_Direct_Toon( const in IncidentLight directLight, const in vec3 geometryPosition, const in vec3 geometryNormal, const in vec3 geometryViewDir, const in vec3 geometryClearcoatNormal, const in ToonMaterial material, inout ReflectedLight reflectedLight ) {
	vec3 irradiance = getGradientIrradiance( geometryNormal, directLight.direction ) * directLight.color;
	reflectedLight.directDiffuse += irradiance * BRDF_Lambert( material.diffuseColor );
}
void RE_IndirectDiffuse_Toon( const in vec3 irradiance, const in vec3 geometryPosition, const in vec3 geometryNormal, const in vec3 geometryViewDir, const in vec3 geometryClearcoatNormal, const in ToonMaterial material, inout ReflectedLight reflectedLight ) {
	reflectedLight.indirectDiffuse += irradiance * BRDF_Lambert( material.diffuseColor );
}
#define RE_Direct				RE_Direct_Toon
#define RE_IndirectDiffuse		RE_IndirectDiffuse_Toon`,N1=`BlinnPhongMaterial material;
material.diffuseColor = diffuseColor.rgb;
material.specularColor = specular;
material.specularShininess = shininess;
material.specularStrength = specularStrength;`,U1=`varying vec3 vViewPosition;
struct BlinnPhongMaterial {
	vec3 diffuseColor;
	vec3 specularColor;
	float specularShininess;
	float specularStrength;
};
void RE_Direct_BlinnPhong( const in IncidentLight directLight, const in vec3 geometryPosition, const in vec3 geometryNormal, const in vec3 geometryViewDir, const in vec3 geometryClearcoatNormal, const in BlinnPhongMaterial material, inout ReflectedLight reflectedLight ) {
	float dotNL = saturate( dot( geometryNormal, directLight.direction ) );
	vec3 irradiance = dotNL * directLight.color;
	reflectedLight.directDiffuse += irradiance * BRDF_Lambert( material.diffuseColor );
	reflectedLight.directSpecular += irradiance * BRDF_BlinnPhong( directLight.direction, geometryViewDir, geometryNormal, material.specularColor, material.specularShininess ) * material.specularStrength;
}
void RE_IndirectDiffuse_BlinnPhong( const in vec3 irradiance, const in vec3 geometryPosition, const in vec3 geometryNormal, const in vec3 geometryViewDir, const in vec3 geometryClearcoatNormal, const in BlinnPhongMaterial material, inout ReflectedLight reflectedLight ) {
	reflectedLight.indirectDiffuse += irradiance * BRDF_Lambert( material.diffuseColor );
}
#define RE_Direct				RE_Direct_BlinnPhong
#define RE_IndirectDiffuse		RE_IndirectDiffuse_BlinnPhong`,L1=`PhysicalMaterial material;
material.diffuseColor = diffuseColor.rgb;
material.diffuseContribution = diffuseColor.rgb * ( 1.0 - metalnessFactor );
material.metalness = metalnessFactor;
vec3 dxy = max( abs( dFdx( nonPerturbedNormal ) ), abs( dFdy( nonPerturbedNormal ) ) );
float geometryRoughness = max( max( dxy.x, dxy.y ), dxy.z );
material.roughness = max( roughnessFactor, 0.0525 );material.roughness += geometryRoughness;
material.roughness = min( material.roughness, 1.0 );
#ifdef IOR
	material.ior = ior;
	#ifdef USE_SPECULAR
		float specularIntensityFactor = specularIntensity;
		vec3 specularColorFactor = specularColor;
		#ifdef USE_SPECULAR_COLORMAP
			specularColorFactor *= texture2D( specularColorMap, vSpecularColorMapUv ).rgb;
		#endif
		#ifdef USE_SPECULAR_INTENSITYMAP
			specularIntensityFactor *= texture2D( specularIntensityMap, vSpecularIntensityMapUv ).a;
		#endif
		material.specularF90 = mix( specularIntensityFactor, 1.0, metalnessFactor );
	#else
		float specularIntensityFactor = 1.0;
		vec3 specularColorFactor = vec3( 1.0 );
		material.specularF90 = 1.0;
	#endif
	material.specularColor = min( pow2( ( material.ior - 1.0 ) / ( material.ior + 1.0 ) ) * specularColorFactor, vec3( 1.0 ) ) * specularIntensityFactor;
	material.specularColorBlended = mix( material.specularColor, diffuseColor.rgb, metalnessFactor );
#else
	material.specularColor = vec3( 0.04 );
	material.specularColorBlended = mix( material.specularColor, diffuseColor.rgb, metalnessFactor );
	material.specularF90 = 1.0;
#endif
#ifdef USE_CLEARCOAT
	material.clearcoat = clearcoat;
	material.clearcoatRoughness = clearcoatRoughness;
	material.clearcoatF0 = vec3( 0.04 );
	material.clearcoatF90 = 1.0;
	#ifdef USE_CLEARCOATMAP
		material.clearcoat *= texture2D( clearcoatMap, vClearcoatMapUv ).x;
	#endif
	#ifdef USE_CLEARCOAT_ROUGHNESSMAP
		material.clearcoatRoughness *= texture2D( clearcoatRoughnessMap, vClearcoatRoughnessMapUv ).y;
	#endif
	material.clearcoat = saturate( material.clearcoat );	material.clearcoatRoughness = max( material.clearcoatRoughness, 0.0525 );
	material.clearcoatRoughness += geometryRoughness;
	material.clearcoatRoughness = min( material.clearcoatRoughness, 1.0 );
#endif
#ifdef USE_DISPERSION
	material.dispersion = dispersion;
#endif
#ifdef USE_IRIDESCENCE
	material.iridescence = iridescence;
	material.iridescenceIOR = iridescenceIOR;
	#ifdef USE_IRIDESCENCEMAP
		material.iridescence *= texture2D( iridescenceMap, vIridescenceMapUv ).r;
	#endif
	#ifdef USE_IRIDESCENCE_THICKNESSMAP
		material.iridescenceThickness = (iridescenceThicknessMaximum - iridescenceThicknessMinimum) * texture2D( iridescenceThicknessMap, vIridescenceThicknessMapUv ).g + iridescenceThicknessMinimum;
	#else
		material.iridescenceThickness = iridescenceThicknessMaximum;
	#endif
#endif
#ifdef USE_SHEEN
	material.sheenColor = sheenColor;
	#ifdef USE_SHEEN_COLORMAP
		material.sheenColor *= texture2D( sheenColorMap, vSheenColorMapUv ).rgb;
	#endif
	material.sheenRoughness = clamp( sheenRoughness, 0.0001, 1.0 );
	#ifdef USE_SHEEN_ROUGHNESSMAP
		material.sheenRoughness *= texture2D( sheenRoughnessMap, vSheenRoughnessMapUv ).a;
	#endif
#endif
#ifdef USE_ANISOTROPY
	#ifdef USE_ANISOTROPYMAP
		mat2 anisotropyMat = mat2( anisotropyVector.x, anisotropyVector.y, - anisotropyVector.y, anisotropyVector.x );
		vec3 anisotropyPolar = texture2D( anisotropyMap, vAnisotropyMapUv ).rgb;
		vec2 anisotropyV = anisotropyMat * normalize( 2.0 * anisotropyPolar.rg - vec2( 1.0 ) ) * anisotropyPolar.b;
	#else
		vec2 anisotropyV = anisotropyVector;
	#endif
	material.anisotropy = length( anisotropyV );
	if( material.anisotropy == 0.0 ) {
		anisotropyV = vec2( 1.0, 0.0 );
	} else {
		anisotropyV /= material.anisotropy;
		material.anisotropy = saturate( material.anisotropy );
	}
	material.alphaT = mix( pow2( material.roughness ), 1.0, pow2( material.anisotropy ) );
	material.anisotropyT = tbn[ 0 ] * anisotropyV.x + tbn[ 1 ] * anisotropyV.y;
	material.anisotropyB = tbn[ 1 ] * anisotropyV.x - tbn[ 0 ] * anisotropyV.y;
#endif`,O1=`uniform sampler2D dfgLUT;
struct PhysicalMaterial {
	vec3 diffuseColor;
	vec3 diffuseContribution;
	vec3 specularColor;
	vec3 specularColorBlended;
	float roughness;
	float metalness;
	float specularF90;
	float dispersion;
	#ifdef USE_CLEARCOAT
		float clearcoat;
		float clearcoatRoughness;
		vec3 clearcoatF0;
		float clearcoatF90;
	#endif
	#ifdef USE_IRIDESCENCE
		float iridescence;
		float iridescenceIOR;
		float iridescenceThickness;
		vec3 iridescenceFresnel;
		vec3 iridescenceF0;
		vec3 iridescenceFresnelDielectric;
		vec3 iridescenceFresnelMetallic;
	#endif
	#ifdef USE_SHEEN
		vec3 sheenColor;
		float sheenRoughness;
	#endif
	#ifdef IOR
		float ior;
	#endif
	#ifdef USE_TRANSMISSION
		float transmission;
		float transmissionAlpha;
		float thickness;
		float attenuationDistance;
		vec3 attenuationColor;
	#endif
	#ifdef USE_ANISOTROPY
		float anisotropy;
		float alphaT;
		vec3 anisotropyT;
		vec3 anisotropyB;
	#endif
};
vec3 clearcoatSpecularDirect = vec3( 0.0 );
vec3 clearcoatSpecularIndirect = vec3( 0.0 );
vec3 sheenSpecularDirect = vec3( 0.0 );
vec3 sheenSpecularIndirect = vec3(0.0 );
vec3 Schlick_to_F0( const in vec3 f, const in float f90, const in float dotVH ) {
    float x = clamp( 1.0 - dotVH, 0.0, 1.0 );
    float x2 = x * x;
    float x5 = clamp( x * x2 * x2, 0.0, 0.9999 );
    return ( f - vec3( f90 ) * x5 ) / ( 1.0 - x5 );
}
float V_GGX_SmithCorrelated( const in float alpha, const in float dotNL, const in float dotNV ) {
	float a2 = pow2( alpha );
	float gv = dotNL * sqrt( a2 + ( 1.0 - a2 ) * pow2( dotNV ) );
	float gl = dotNV * sqrt( a2 + ( 1.0 - a2 ) * pow2( dotNL ) );
	return 0.5 / max( gv + gl, EPSILON );
}
float D_GGX( const in float alpha, const in float dotNH ) {
	float a2 = pow2( alpha );
	float denom = pow2( dotNH ) * ( a2 - 1.0 ) + 1.0;
	return RECIPROCAL_PI * a2 / pow2( denom );
}
#ifdef USE_ANISOTROPY
	float V_GGX_SmithCorrelated_Anisotropic( const in float alphaT, const in float alphaB, const in float dotTV, const in float dotBV, const in float dotTL, const in float dotBL, const in float dotNV, const in float dotNL ) {
		float gv = dotNL * length( vec3( alphaT * dotTV, alphaB * dotBV, dotNV ) );
		float gl = dotNV * length( vec3( alphaT * dotTL, alphaB * dotBL, dotNL ) );
		return 0.5 / max( gv + gl, EPSILON );
	}
	float D_GGX_Anisotropic( const in float alphaT, const in float alphaB, const in float dotNH, const in float dotTH, const in float dotBH ) {
		float a2 = alphaT * alphaB;
		highp vec3 v = vec3( alphaB * dotTH, alphaT * dotBH, a2 * dotNH );
		highp float v2 = dot( v, v );
		float w2 = a2 / v2;
		return RECIPROCAL_PI * a2 * pow2 ( w2 );
	}
#endif
#ifdef USE_CLEARCOAT
	vec3 BRDF_GGX_Clearcoat( const in vec3 lightDir, const in vec3 viewDir, const in vec3 normal, const in PhysicalMaterial material) {
		vec3 f0 = material.clearcoatF0;
		float f90 = material.clearcoatF90;
		float roughness = material.clearcoatRoughness;
		float alpha = pow2( roughness );
		vec3 halfDir = normalize( lightDir + viewDir );
		float dotNL = saturate( dot( normal, lightDir ) );
		float dotNV = saturate( dot( normal, viewDir ) );
		float dotNH = saturate( dot( normal, halfDir ) );
		float dotVH = saturate( dot( viewDir, halfDir ) );
		vec3 F = F_Schlick( f0, f90, dotVH );
		float V = V_GGX_SmithCorrelated( alpha, dotNL, dotNV );
		float D = D_GGX( alpha, dotNH );
		return F * ( V * D );
	}
#endif
vec3 BRDF_GGX( const in vec3 lightDir, const in vec3 viewDir, const in vec3 normal, const in PhysicalMaterial material ) {
	vec3 f0 = material.specularColorBlended;
	float f90 = material.specularF90;
	float roughness = material.roughness;
	float alpha = pow2( roughness );
	vec3 halfDir = normalize( lightDir + viewDir );
	float dotNL = saturate( dot( normal, lightDir ) );
	float dotNV = saturate( dot( normal, viewDir ) );
	float dotNH = saturate( dot( normal, halfDir ) );
	float dotVH = saturate( dot( viewDir, halfDir ) );
	vec3 F = F_Schlick( f0, f90, dotVH );
	#ifdef USE_IRIDESCENCE
		F = mix( F, material.iridescenceFresnel, material.iridescence );
	#endif
	#ifdef USE_ANISOTROPY
		float dotTL = dot( material.anisotropyT, lightDir );
		float dotTV = dot( material.anisotropyT, viewDir );
		float dotTH = dot( material.anisotropyT, halfDir );
		float dotBL = dot( material.anisotropyB, lightDir );
		float dotBV = dot( material.anisotropyB, viewDir );
		float dotBH = dot( material.anisotropyB, halfDir );
		float V = V_GGX_SmithCorrelated_Anisotropic( material.alphaT, alpha, dotTV, dotBV, dotTL, dotBL, dotNV, dotNL );
		float D = D_GGX_Anisotropic( material.alphaT, alpha, dotNH, dotTH, dotBH );
	#else
		float V = V_GGX_SmithCorrelated( alpha, dotNL, dotNV );
		float D = D_GGX( alpha, dotNH );
	#endif
	return F * ( V * D );
}
vec2 LTC_Uv( const in vec3 N, const in vec3 V, const in float roughness ) {
	const float LUT_SIZE = 64.0;
	const float LUT_SCALE = ( LUT_SIZE - 1.0 ) / LUT_SIZE;
	const float LUT_BIAS = 0.5 / LUT_SIZE;
	float dotNV = saturate( dot( N, V ) );
	vec2 uv = vec2( roughness, sqrt( 1.0 - dotNV ) );
	uv = uv * LUT_SCALE + LUT_BIAS;
	return uv;
}
float LTC_ClippedSphereFormFactor( const in vec3 f ) {
	float l = length( f );
	return max( ( l * l + f.z ) / ( l + 1.0 ), 0.0 );
}
vec3 LTC_EdgeVectorFormFactor( const in vec3 v1, const in vec3 v2 ) {
	float x = dot( v1, v2 );
	float y = abs( x );
	float a = 0.8543985 + ( 0.4965155 + 0.0145206 * y ) * y;
	float b = 3.4175940 + ( 4.1616724 + y ) * y;
	float v = a / b;
	float theta_sintheta = ( x > 0.0 ) ? v : 0.5 * inversesqrt( max( 1.0 - x * x, 1e-7 ) ) - v;
	return cross( v1, v2 ) * theta_sintheta;
}
vec3 LTC_Evaluate( const in vec3 N, const in vec3 V, const in vec3 P, const in mat3 mInv, const in vec3 rectCoords[ 4 ] ) {
	vec3 v1 = rectCoords[ 1 ] - rectCoords[ 0 ];
	vec3 v2 = rectCoords[ 3 ] - rectCoords[ 0 ];
	vec3 lightNormal = cross( v1, v2 );
	if( dot( lightNormal, P - rectCoords[ 0 ] ) < 0.0 ) return vec3( 0.0 );
	vec3 T1, T2;
	T1 = normalize( V - N * dot( V, N ) );
	T2 = - cross( N, T1 );
	mat3 mat = mInv * transpose( mat3( T1, T2, N ) );
	vec3 coords[ 4 ];
	coords[ 0 ] = mat * ( rectCoords[ 0 ] - P );
	coords[ 1 ] = mat * ( rectCoords[ 1 ] - P );
	coords[ 2 ] = mat * ( rectCoords[ 2 ] - P );
	coords[ 3 ] = mat * ( rectCoords[ 3 ] - P );
	coords[ 0 ] = normalize( coords[ 0 ] );
	coords[ 1 ] = normalize( coords[ 1 ] );
	coords[ 2 ] = normalize( coords[ 2 ] );
	coords[ 3 ] = normalize( coords[ 3 ] );
	vec3 vectorFormFactor = vec3( 0.0 );
	vectorFormFactor += LTC_EdgeVectorFormFactor( coords[ 0 ], coords[ 1 ] );
	vectorFormFactor += LTC_EdgeVectorFormFactor( coords[ 1 ], coords[ 2 ] );
	vectorFormFactor += LTC_EdgeVectorFormFactor( coords[ 2 ], coords[ 3 ] );
	vectorFormFactor += LTC_EdgeVectorFormFactor( coords[ 3 ], coords[ 0 ] );
	float result = LTC_ClippedSphereFormFactor( vectorFormFactor );
	return vec3( result );
}
#if defined( USE_SHEEN )
float D_Charlie( float roughness, float dotNH ) {
	float alpha = pow2( roughness );
	float invAlpha = 1.0 / alpha;
	float cos2h = dotNH * dotNH;
	float sin2h = max( 1.0 - cos2h, 0.0078125 );
	return ( 2.0 + invAlpha ) * pow( sin2h, invAlpha * 0.5 ) / ( 2.0 * PI );
}
float V_Neubelt( float dotNV, float dotNL ) {
	return saturate( 1.0 / ( 4.0 * ( dotNL + dotNV - dotNL * dotNV ) ) );
}
vec3 BRDF_Sheen( const in vec3 lightDir, const in vec3 viewDir, const in vec3 normal, vec3 sheenColor, const in float sheenRoughness ) {
	vec3 halfDir = normalize( lightDir + viewDir );
	float dotNL = saturate( dot( normal, lightDir ) );
	float dotNV = saturate( dot( normal, viewDir ) );
	float dotNH = saturate( dot( normal, halfDir ) );
	float D = D_Charlie( sheenRoughness, dotNH );
	float V = V_Neubelt( dotNV, dotNL );
	return sheenColor * ( D * V );
}
#endif
float IBLSheenBRDF( const in vec3 normal, const in vec3 viewDir, const in float roughness ) {
	float dotNV = saturate( dot( normal, viewDir ) );
	float r2 = roughness * roughness;
	float rInv = 1.0 / ( roughness + 0.1 );
	float a = -1.9362 + 1.0678 * roughness + 0.4573 * r2 - 0.8469 * rInv;
	float b = -0.6014 + 0.5538 * roughness - 0.4670 * r2 - 0.1255 * rInv;
	float DG = exp( a * dotNV + b );
	return saturate( DG );
}
vec3 EnvironmentBRDF( const in vec3 normal, const in vec3 viewDir, const in vec3 specularColor, const in float specularF90, const in float roughness ) {
	float dotNV = saturate( dot( normal, viewDir ) );
	vec2 fab = texture2D( dfgLUT, vec2( roughness, dotNV ) ).rg;
	return specularColor * fab.x + specularF90 * fab.y;
}
#ifdef USE_IRIDESCENCE
void computeMultiscatteringIridescence( const in vec3 normal, const in vec3 viewDir, const in vec3 specularColor, const in float specularF90, const in float iridescence, const in vec3 iridescenceF0, const in float roughness, inout vec3 singleScatter, inout vec3 multiScatter ) {
#else
void computeMultiscattering( const in vec3 normal, const in vec3 viewDir, const in vec3 specularColor, const in float specularF90, const in float roughness, inout vec3 singleScatter, inout vec3 multiScatter ) {
#endif
	float dotNV = saturate( dot( normal, viewDir ) );
	vec2 fab = texture2D( dfgLUT, vec2( roughness, dotNV ) ).rg;
	#ifdef USE_IRIDESCENCE
		vec3 Fr = mix( specularColor, iridescenceF0, iridescence );
	#else
		vec3 Fr = specularColor;
	#endif
	vec3 FssEss = Fr * fab.x + specularF90 * fab.y;
	float Ess = fab.x + fab.y;
	float Ems = 1.0 - Ess;
	vec3 Favg = Fr + ( 1.0 - Fr ) * 0.047619;	vec3 Fms = FssEss * Favg / ( 1.0 - Ems * Favg );
	singleScatter += FssEss;
	multiScatter += Fms * Ems;
}
vec3 BRDF_GGX_Multiscatter( const in vec3 lightDir, const in vec3 viewDir, const in vec3 normal, const in PhysicalMaterial material ) {
	vec3 singleScatter = BRDF_GGX( lightDir, viewDir, normal, material );
	float dotNL = saturate( dot( normal, lightDir ) );
	float dotNV = saturate( dot( normal, viewDir ) );
	vec2 dfgV = texture2D( dfgLUT, vec2( material.roughness, dotNV ) ).rg;
	vec2 dfgL = texture2D( dfgLUT, vec2( material.roughness, dotNL ) ).rg;
	vec3 FssEss_V = material.specularColorBlended * dfgV.x + material.specularF90 * dfgV.y;
	vec3 FssEss_L = material.specularColorBlended * dfgL.x + material.specularF90 * dfgL.y;
	float Ess_V = dfgV.x + dfgV.y;
	float Ess_L = dfgL.x + dfgL.y;
	float Ems_V = 1.0 - Ess_V;
	float Ems_L = 1.0 - Ess_L;
	vec3 Favg = material.specularColorBlended + ( 1.0 - material.specularColorBlended ) * 0.047619;
	vec3 Fms = FssEss_V * FssEss_L * Favg / ( 1.0 - Ems_V * Ems_L * Favg + EPSILON );
	float compensationFactor = Ems_V * Ems_L;
	vec3 multiScatter = Fms * compensationFactor;
	return singleScatter + multiScatter;
}
#if NUM_RECT_AREA_LIGHTS > 0
	void RE_Direct_RectArea_Physical( const in RectAreaLight rectAreaLight, const in vec3 geometryPosition, const in vec3 geometryNormal, const in vec3 geometryViewDir, const in vec3 geometryClearcoatNormal, const in PhysicalMaterial material, inout ReflectedLight reflectedLight ) {
		vec3 normal = geometryNormal;
		vec3 viewDir = geometryViewDir;
		vec3 position = geometryPosition;
		vec3 lightPos = rectAreaLight.position;
		vec3 halfWidth = rectAreaLight.halfWidth;
		vec3 halfHeight = rectAreaLight.halfHeight;
		vec3 lightColor = rectAreaLight.color;
		float roughness = material.roughness;
		vec3 rectCoords[ 4 ];
		rectCoords[ 0 ] = lightPos + halfWidth - halfHeight;		rectCoords[ 1 ] = lightPos - halfWidth - halfHeight;
		rectCoords[ 2 ] = lightPos - halfWidth + halfHeight;
		rectCoords[ 3 ] = lightPos + halfWidth + halfHeight;
		vec2 uv = LTC_Uv( normal, viewDir, roughness );
		vec4 t1 = texture2D( ltc_1, uv );
		vec4 t2 = texture2D( ltc_2, uv );
		mat3 mInv = mat3(
			vec3( t1.x, 0, t1.y ),
			vec3(    0, 1,    0 ),
			vec3( t1.z, 0, t1.w )
		);
		vec3 fresnel = ( material.specularColorBlended * t2.x + ( material.specularF90 - material.specularColorBlended ) * t2.y );
		reflectedLight.directSpecular += lightColor * fresnel * LTC_Evaluate( normal, viewDir, position, mInv, rectCoords );
		reflectedLight.directDiffuse += lightColor * material.diffuseContribution * LTC_Evaluate( normal, viewDir, position, mat3( 1.0 ), rectCoords );
		#ifdef USE_CLEARCOAT
			vec3 Ncc = geometryClearcoatNormal;
			vec2 uvClearcoat = LTC_Uv( Ncc, viewDir, material.clearcoatRoughness );
			vec4 t1Clearcoat = texture2D( ltc_1, uvClearcoat );
			vec4 t2Clearcoat = texture2D( ltc_2, uvClearcoat );
			mat3 mInvClearcoat = mat3(
				vec3( t1Clearcoat.x, 0, t1Clearcoat.y ),
				vec3(             0, 1,             0 ),
				vec3( t1Clearcoat.z, 0, t1Clearcoat.w )
			);
			vec3 fresnelClearcoat = material.clearcoatF0 * t2Clearcoat.x + ( material.clearcoatF90 - material.clearcoatF0 ) * t2Clearcoat.y;
			clearcoatSpecularDirect += lightColor * fresnelClearcoat * LTC_Evaluate( Ncc, viewDir, position, mInvClearcoat, rectCoords );
		#endif
	}
#endif
void RE_Direct_Physical( const in IncidentLight directLight, const in vec3 geometryPosition, const in vec3 geometryNormal, const in vec3 geometryViewDir, const in vec3 geometryClearcoatNormal, const in PhysicalMaterial material, inout ReflectedLight reflectedLight ) {
	float dotNL = saturate( dot( geometryNormal, directLight.direction ) );
	vec3 irradiance = dotNL * directLight.color;
	#ifdef USE_CLEARCOAT
		float dotNLcc = saturate( dot( geometryClearcoatNormal, directLight.direction ) );
		vec3 ccIrradiance = dotNLcc * directLight.color;
		clearcoatSpecularDirect += ccIrradiance * BRDF_GGX_Clearcoat( directLight.direction, geometryViewDir, geometryClearcoatNormal, material );
	#endif
	#ifdef USE_SHEEN
 
 		sheenSpecularDirect += irradiance * BRDF_Sheen( directLight.direction, geometryViewDir, geometryNormal, material.sheenColor, material.sheenRoughness );
 
 		float sheenAlbedoV = IBLSheenBRDF( geometryNormal, geometryViewDir, material.sheenRoughness );
 		float sheenAlbedoL = IBLSheenBRDF( geometryNormal, directLight.direction, material.sheenRoughness );
 
 		float sheenEnergyComp = 1.0 - max3( material.sheenColor ) * max( sheenAlbedoV, sheenAlbedoL );
 
 		irradiance *= sheenEnergyComp;
 
 	#endif
	reflectedLight.directSpecular += irradiance * BRDF_GGX_Multiscatter( directLight.direction, geometryViewDir, geometryNormal, material );
	reflectedLight.directDiffuse += irradiance * BRDF_Lambert( material.diffuseContribution );
}
void RE_IndirectDiffuse_Physical( const in vec3 irradiance, const in vec3 geometryPosition, const in vec3 geometryNormal, const in vec3 geometryViewDir, const in vec3 geometryClearcoatNormal, const in PhysicalMaterial material, inout ReflectedLight reflectedLight ) {
	vec3 diffuse = irradiance * BRDF_Lambert( material.diffuseContribution );
	#ifdef USE_SHEEN
		float sheenAlbedo = IBLSheenBRDF( geometryNormal, geometryViewDir, material.sheenRoughness );
		float sheenEnergyComp = 1.0 - max3( material.sheenColor ) * sheenAlbedo;
		diffuse *= sheenEnergyComp;
	#endif
	reflectedLight.indirectDiffuse += diffuse;
}
void RE_IndirectSpecular_Physical( const in vec3 radiance, const in vec3 irradiance, const in vec3 clearcoatRadiance, const in vec3 geometryPosition, const in vec3 geometryNormal, const in vec3 geometryViewDir, const in vec3 geometryClearcoatNormal, const in PhysicalMaterial material, inout ReflectedLight reflectedLight) {
	#ifdef USE_CLEARCOAT
		clearcoatSpecularIndirect += clearcoatRadiance * EnvironmentBRDF( geometryClearcoatNormal, geometryViewDir, material.clearcoatF0, material.clearcoatF90, material.clearcoatRoughness );
	#endif
	#ifdef USE_SHEEN
		sheenSpecularIndirect += irradiance * material.sheenColor * IBLSheenBRDF( geometryNormal, geometryViewDir, material.sheenRoughness ) * RECIPROCAL_PI;
 	#endif
	vec3 singleScatteringDielectric = vec3( 0.0 );
	vec3 multiScatteringDielectric = vec3( 0.0 );
	vec3 singleScatteringMetallic = vec3( 0.0 );
	vec3 multiScatteringMetallic = vec3( 0.0 );
	#ifdef USE_IRIDESCENCE
		computeMultiscatteringIridescence( geometryNormal, geometryViewDir, material.specularColor, material.specularF90, material.iridescence, material.iridescenceFresnelDielectric, material.roughness, singleScatteringDielectric, multiScatteringDielectric );
		computeMultiscatteringIridescence( geometryNormal, geometryViewDir, material.diffuseColor, material.specularF90, material.iridescence, material.iridescenceFresnelMetallic, material.roughness, singleScatteringMetallic, multiScatteringMetallic );
	#else
		computeMultiscattering( geometryNormal, geometryViewDir, material.specularColor, material.specularF90, material.roughness, singleScatteringDielectric, multiScatteringDielectric );
		computeMultiscattering( geometryNormal, geometryViewDir, material.diffuseColor, material.specularF90, material.roughness, singleScatteringMetallic, multiScatteringMetallic );
	#endif
	vec3 singleScattering = mix( singleScatteringDielectric, singleScatteringMetallic, material.metalness );
	vec3 multiScattering = mix( multiScatteringDielectric, multiScatteringMetallic, material.metalness );
	vec3 totalScatteringDielectric = singleScatteringDielectric + multiScatteringDielectric;
	vec3 diffuse = material.diffuseContribution * ( 1.0 - totalScatteringDielectric );
	vec3 cosineWeightedIrradiance = irradiance * RECIPROCAL_PI;
	vec3 indirectSpecular = radiance * singleScattering;
	indirectSpecular += multiScattering * cosineWeightedIrradiance;
	vec3 indirectDiffuse = diffuse * cosineWeightedIrradiance;
	#ifdef USE_SHEEN
		float sheenAlbedo = IBLSheenBRDF( geometryNormal, geometryViewDir, material.sheenRoughness );
		float sheenEnergyComp = 1.0 - max3( material.sheenColor ) * sheenAlbedo;
		indirectSpecular *= sheenEnergyComp;
		indirectDiffuse *= sheenEnergyComp;
	#endif
	reflectedLight.indirectSpecular += indirectSpecular;
	reflectedLight.indirectDiffuse += indirectDiffuse;
}
#define RE_Direct				RE_Direct_Physical
#define RE_Direct_RectArea		RE_Direct_RectArea_Physical
#define RE_IndirectDiffuse		RE_IndirectDiffuse_Physical
#define RE_IndirectSpecular		RE_IndirectSpecular_Physical
float computeSpecularOcclusion( const in float dotNV, const in float ambientOcclusion, const in float roughness ) {
	return saturate( pow( dotNV + ambientOcclusion, exp2( - 16.0 * roughness - 1.0 ) ) - 1.0 + ambientOcclusion );
}`,P1=`
vec3 geometryPosition = - vViewPosition;
vec3 geometryNormal = normal;
vec3 geometryViewDir = ( isOrthographic ) ? vec3( 0, 0, 1 ) : normalize( vViewPosition );
vec3 geometryClearcoatNormal = vec3( 0.0 );
#ifdef USE_CLEARCOAT
	geometryClearcoatNormal = clearcoatNormal;
#endif
#ifdef USE_IRIDESCENCE
	float dotNVi = saturate( dot( normal, geometryViewDir ) );
	if ( material.iridescenceThickness == 0.0 ) {
		material.iridescence = 0.0;
	} else {
		material.iridescence = saturate( material.iridescence );
	}
	if ( material.iridescence > 0.0 ) {
		material.iridescenceFresnelDielectric = evalIridescence( 1.0, material.iridescenceIOR, dotNVi, material.iridescenceThickness, material.specularColor );
		material.iridescenceFresnelMetallic = evalIridescence( 1.0, material.iridescenceIOR, dotNVi, material.iridescenceThickness, material.diffuseColor );
		material.iridescenceFresnel = mix( material.iridescenceFresnelDielectric, material.iridescenceFresnelMetallic, material.metalness );
		material.iridescenceF0 = Schlick_to_F0( material.iridescenceFresnel, 1.0, dotNVi );
	}
#endif
IncidentLight directLight;
#if ( NUM_POINT_LIGHTS > 0 ) && defined( RE_Direct )
	PointLight pointLight;
	#if defined( USE_SHADOWMAP ) && NUM_POINT_LIGHT_SHADOWS > 0
	PointLightShadow pointLightShadow;
	#endif
	#pragma unroll_loop_start
	for ( int i = 0; i < NUM_POINT_LIGHTS; i ++ ) {
		pointLight = pointLights[ i ];
		getPointLightInfo( pointLight, geometryPosition, directLight );
		#if defined( USE_SHADOWMAP ) && ( UNROLLED_LOOP_INDEX < NUM_POINT_LIGHT_SHADOWS ) && ( defined( SHADOWMAP_TYPE_PCF ) || defined( SHADOWMAP_TYPE_BASIC ) )
		pointLightShadow = pointLightShadows[ i ];
		directLight.color *= ( directLight.visible && receiveShadow ) ? getPointShadow( pointShadowMap[ i ], pointLightShadow.shadowMapSize, pointLightShadow.shadowIntensity, pointLightShadow.shadowBias, pointLightShadow.shadowRadius, vPointShadowCoord[ i ], pointLightShadow.shadowCameraNear, pointLightShadow.shadowCameraFar ) : 1.0;
		#endif
		RE_Direct( directLight, geometryPosition, geometryNormal, geometryViewDir, geometryClearcoatNormal, material, reflectedLight );
	}
	#pragma unroll_loop_end
#endif
#if ( NUM_SPOT_LIGHTS > 0 ) && defined( RE_Direct )
	SpotLight spotLight;
	vec4 spotColor;
	vec3 spotLightCoord;
	bool inSpotLightMap;
	#if defined( USE_SHADOWMAP ) && NUM_SPOT_LIGHT_SHADOWS > 0
	SpotLightShadow spotLightShadow;
	#endif
	#pragma unroll_loop_start
	for ( int i = 0; i < NUM_SPOT_LIGHTS; i ++ ) {
		spotLight = spotLights[ i ];
		getSpotLightInfo( spotLight, geometryPosition, directLight );
		#if ( UNROLLED_LOOP_INDEX < NUM_SPOT_LIGHT_SHADOWS_WITH_MAPS )
		#define SPOT_LIGHT_MAP_INDEX UNROLLED_LOOP_INDEX
		#elif ( UNROLLED_LOOP_INDEX < NUM_SPOT_LIGHT_SHADOWS )
		#define SPOT_LIGHT_MAP_INDEX NUM_SPOT_LIGHT_MAPS
		#else
		#define SPOT_LIGHT_MAP_INDEX ( UNROLLED_LOOP_INDEX - NUM_SPOT_LIGHT_SHADOWS + NUM_SPOT_LIGHT_SHADOWS_WITH_MAPS )
		#endif
		#if ( SPOT_LIGHT_MAP_INDEX < NUM_SPOT_LIGHT_MAPS )
			spotLightCoord = vSpotLightCoord[ i ].xyz / vSpotLightCoord[ i ].w;
			inSpotLightMap = all( lessThan( abs( spotLightCoord * 2. - 1. ), vec3( 1.0 ) ) );
			spotColor = texture2D( spotLightMap[ SPOT_LIGHT_MAP_INDEX ], spotLightCoord.xy );
			directLight.color = inSpotLightMap ? directLight.color * spotColor.rgb : directLight.color;
		#endif
		#undef SPOT_LIGHT_MAP_INDEX
		#if defined( USE_SHADOWMAP ) && ( UNROLLED_LOOP_INDEX < NUM_SPOT_LIGHT_SHADOWS )
		spotLightShadow = spotLightShadows[ i ];
		directLight.color *= ( directLight.visible && receiveShadow ) ? getShadow( spotShadowMap[ i ], spotLightShadow.shadowMapSize, spotLightShadow.shadowIntensity, spotLightShadow.shadowBias, spotLightShadow.shadowRadius, vSpotLightCoord[ i ] ) : 1.0;
		#endif
		RE_Direct( directLight, geometryPosition, geometryNormal, geometryViewDir, geometryClearcoatNormal, material, reflectedLight );
	}
	#pragma unroll_loop_end
#endif
#if ( NUM_DIR_LIGHTS > 0 ) && defined( RE_Direct )
	DirectionalLight directionalLight;
	#if defined( USE_SHADOWMAP ) && NUM_DIR_LIGHT_SHADOWS > 0
	DirectionalLightShadow directionalLightShadow;
	#endif
	#pragma unroll_loop_start
	for ( int i = 0; i < NUM_DIR_LIGHTS; i ++ ) {
		directionalLight = directionalLights[ i ];
		getDirectionalLightInfo( directionalLight, directLight );
		#if defined( USE_SHADOWMAP ) && ( UNROLLED_LOOP_INDEX < NUM_DIR_LIGHT_SHADOWS )
		directionalLightShadow = directionalLightShadows[ i ];
		directLight.color *= ( directLight.visible && receiveShadow ) ? getShadow( directionalShadowMap[ i ], directionalLightShadow.shadowMapSize, directionalLightShadow.shadowIntensity, directionalLightShadow.shadowBias, directionalLightShadow.shadowRadius, vDirectionalShadowCoord[ i ] ) : 1.0;
		#endif
		RE_Direct( directLight, geometryPosition, geometryNormal, geometryViewDir, geometryClearcoatNormal, material, reflectedLight );
	}
	#pragma unroll_loop_end
#endif
#if ( NUM_RECT_AREA_LIGHTS > 0 ) && defined( RE_Direct_RectArea )
	RectAreaLight rectAreaLight;
	#pragma unroll_loop_start
	for ( int i = 0; i < NUM_RECT_AREA_LIGHTS; i ++ ) {
		rectAreaLight = rectAreaLights[ i ];
		RE_Direct_RectArea( rectAreaLight, geometryPosition, geometryNormal, geometryViewDir, geometryClearcoatNormal, material, reflectedLight );
	}
	#pragma unroll_loop_end
#endif
#if defined( RE_IndirectDiffuse )
	vec3 iblIrradiance = vec3( 0.0 );
	vec3 irradiance = getAmbientLightIrradiance( ambientLightColor );
	#if defined( USE_LIGHT_PROBES )
		irradiance += getLightProbeIrradiance( lightProbe, geometryNormal );
	#endif
	#if ( NUM_HEMI_LIGHTS > 0 )
		#pragma unroll_loop_start
		for ( int i = 0; i < NUM_HEMI_LIGHTS; i ++ ) {
			irradiance += getHemisphereLightIrradiance( hemisphereLights[ i ], geometryNormal );
		}
		#pragma unroll_loop_end
	#endif
	#ifdef USE_LIGHT_PROBES_GRID
		vec3 probeWorldPos = ( ( vec4( geometryPosition, 1.0 ) - viewMatrix[ 3 ] ) * viewMatrix ).xyz;
		vec3 probeWorldNormal = transformNormalByInverseViewMatrix( geometryNormal, viewMatrix );
		irradiance += getLightProbeGridIrradiance( probeWorldPos, probeWorldNormal );
	#endif
#endif
#if defined( RE_IndirectSpecular )
	vec3 radiance = vec3( 0.0 );
	vec3 clearcoatRadiance = vec3( 0.0 );
#endif`,I1=`#if defined( RE_IndirectDiffuse )
	#ifdef USE_LIGHTMAP
		vec4 lightMapTexel = texture2D( lightMap, vLightMapUv );
		vec3 lightMapIrradiance = lightMapTexel.rgb * lightMapIntensity;
		irradiance += lightMapIrradiance;
	#endif
	#if defined( USE_ENVMAP ) && defined( ENVMAP_TYPE_CUBE_UV )
		#if defined( STANDARD ) || defined( LAMBERT ) || defined( PHONG )
			iblIrradiance += getIBLIrradiance( geometryNormal );
		#endif
	#endif
#endif
#if defined( USE_ENVMAP ) && defined( RE_IndirectSpecular )
	#ifdef USE_ANISOTROPY
		radiance += getIBLAnisotropyRadiance( geometryViewDir, geometryNormal, material.roughness, material.anisotropyB, material.anisotropy );
	#else
		radiance += getIBLRadiance( geometryViewDir, geometryNormal, material.roughness );
	#endif
	#ifdef USE_CLEARCOAT
		clearcoatRadiance += getIBLRadiance( geometryViewDir, geometryClearcoatNormal, material.clearcoatRoughness );
	#endif
#endif`,z1=`#if defined( RE_IndirectDiffuse )
	#if defined( LAMBERT ) || defined( PHONG )
		irradiance += iblIrradiance;
	#endif
	RE_IndirectDiffuse( irradiance, geometryPosition, geometryNormal, geometryViewDir, geometryClearcoatNormal, material, reflectedLight );
#endif
#if defined( RE_IndirectSpecular )
	RE_IndirectSpecular( radiance, iblIrradiance, clearcoatRadiance, geometryPosition, geometryNormal, geometryViewDir, geometryClearcoatNormal, material, reflectedLight );
#endif`,F1=`#ifdef USE_LIGHT_PROBES_GRID
uniform highp sampler3D probesSH;
uniform vec3 probesMin;
uniform vec3 probesMax;
uniform vec3 probesResolution;
vec3 getLightProbeGridIrradiance( vec3 worldPos, vec3 worldNormal ) {
	vec3 res = probesResolution;
	vec3 gridRange = probesMax - probesMin;
	vec3 resMinusOne = res - 1.0;
	vec3 probeSpacing = gridRange / resMinusOne;
	vec3 samplePos = worldPos + worldNormal * probeSpacing * 0.5;
	vec3 uvw = clamp( ( samplePos - probesMin ) / gridRange, 0.0, 1.0 );
	uvw = uvw * resMinusOne / res + 0.5 / res;
	float nz          = res.z;
	float paddedSlices = nz + 2.0;
	float atlasDepth  = 7.0 * paddedSlices;
	float uvZBase     = uvw.z * nz + 1.0;
	vec4 s0 = texture( probesSH, vec3( uvw.xy, ( uvZBase                       ) / atlasDepth ) );
	vec4 s1 = texture( probesSH, vec3( uvw.xy, ( uvZBase +       paddedSlices   ) / atlasDepth ) );
	vec4 s2 = texture( probesSH, vec3( uvw.xy, ( uvZBase + 2.0 * paddedSlices   ) / atlasDepth ) );
	vec4 s3 = texture( probesSH, vec3( uvw.xy, ( uvZBase + 3.0 * paddedSlices   ) / atlasDepth ) );
	vec4 s4 = texture( probesSH, vec3( uvw.xy, ( uvZBase + 4.0 * paddedSlices   ) / atlasDepth ) );
	vec4 s5 = texture( probesSH, vec3( uvw.xy, ( uvZBase + 5.0 * paddedSlices   ) / atlasDepth ) );
	vec4 s6 = texture( probesSH, vec3( uvw.xy, ( uvZBase + 6.0 * paddedSlices   ) / atlasDepth ) );
	vec3 c0 = s0.xyz;
	vec3 c1 = vec3( s0.w, s1.xy );
	vec3 c2 = vec3( s1.zw, s2.x );
	vec3 c3 = s2.yzw;
	vec3 c4 = s3.xyz;
	vec3 c5 = vec3( s3.w, s4.xy );
	vec3 c6 = vec3( s4.zw, s5.x );
	vec3 c7 = s5.yzw;
	vec3 c8 = s6.xyz;
	float x = worldNormal.x, y = worldNormal.y, z = worldNormal.z;
	vec3 result = c0 * 0.886227;
	result += c1 * 2.0 * 0.511664 * y;
	result += c2 * 2.0 * 0.511664 * z;
	result += c3 * 2.0 * 0.511664 * x;
	result += c4 * 2.0 * 0.429043 * x * y;
	result += c5 * 2.0 * 0.429043 * y * z;
	result += c6 * ( 0.743125 * z * z - 0.247708 );
	result += c7 * 2.0 * 0.429043 * x * z;
	result += c8 * 0.429043 * ( x * x - y * y );
	return max( result, vec3( 0.0 ) );
}
#endif`,B1=`#if defined( USE_LOGARITHMIC_DEPTH_BUFFER )
	gl_FragDepth = vIsPerspective == 0.0 ? gl_FragCoord.z : log2( vFragDepth ) * logDepthBufFC * 0.5;
#endif`,H1=`#if defined( USE_LOGARITHMIC_DEPTH_BUFFER )
	uniform float logDepthBufFC;
	varying float vFragDepth;
	varying float vIsPerspective;
#endif`,G1=`#ifdef USE_LOGARITHMIC_DEPTH_BUFFER
	varying float vFragDepth;
	varying float vIsPerspective;
#endif`,V1=`#ifdef USE_LOGARITHMIC_DEPTH_BUFFER
	vFragDepth = 1.0 + gl_Position.w;
	vIsPerspective = float( isPerspectiveMatrix( projectionMatrix ) );
#endif`,k1=`#ifdef USE_MAP
	vec4 sampledDiffuseColor = texture2D( map, vMapUv );
	#ifdef DECODE_VIDEO_TEXTURE
		sampledDiffuseColor = sRGBTransferEOTF( sampledDiffuseColor );
	#endif
	diffuseColor *= sampledDiffuseColor;
#endif`,X1=`#ifdef USE_MAP
	uniform sampler2D map;
#endif`,W1=`#if defined( USE_MAP ) || defined( USE_ALPHAMAP )
	#if defined( USE_POINTS_UV )
		vec2 uv = vUv;
	#else
		vec2 uv = ( uvTransform * vec3( gl_PointCoord.x, 1.0 - gl_PointCoord.y, 1 ) ).xy;
	#endif
#endif
#ifdef USE_MAP
	diffuseColor *= texture2D( map, uv );
#endif
#ifdef USE_ALPHAMAP
	diffuseColor.a *= texture2D( alphaMap, uv ).g;
#endif`,q1=`#if defined( USE_POINTS_UV )
	varying vec2 vUv;
#else
	#if defined( USE_MAP ) || defined( USE_ALPHAMAP )
		uniform mat3 uvTransform;
	#endif
#endif
#ifdef USE_MAP
	uniform sampler2D map;
#endif
#ifdef USE_ALPHAMAP
	uniform sampler2D alphaMap;
#endif`,Y1=`float metalnessFactor = metalness;
#ifdef USE_METALNESSMAP
	vec4 texelMetalness = texture2D( metalnessMap, vMetalnessMapUv );
	metalnessFactor *= texelMetalness.b;
#endif`,Z1=`#ifdef USE_METALNESSMAP
	uniform sampler2D metalnessMap;
#endif`,K1=`#ifdef USE_INSTANCING_MORPH
	float morphTargetInfluences[ MORPHTARGETS_COUNT ];
	float morphTargetBaseInfluence = texelFetch( morphTexture, ivec2( 0, gl_InstanceID ), 0 ).r;
	for ( int i = 0; i < MORPHTARGETS_COUNT; i ++ ) {
		morphTargetInfluences[i] =  texelFetch( morphTexture, ivec2( i + 1, gl_InstanceID ), 0 ).r;
	}
#endif`,j1=`#if defined( USE_MORPHCOLORS )
	vColor *= morphTargetBaseInfluence;
	for ( int i = 0; i < MORPHTARGETS_COUNT; i ++ ) {
		#if defined( USE_COLOR_ALPHA )
			if ( morphTargetInfluences[ i ] != 0.0 ) vColor += getMorph( gl_VertexID, i, 2 ) * morphTargetInfluences[ i ];
		#elif defined( USE_COLOR )
			if ( morphTargetInfluences[ i ] != 0.0 ) vColor += getMorph( gl_VertexID, i, 2 ).rgb * morphTargetInfluences[ i ];
		#endif
	}
#endif`,J1=`#ifdef USE_MORPHNORMALS
	objectNormal *= morphTargetBaseInfluence;
	for ( int i = 0; i < MORPHTARGETS_COUNT; i ++ ) {
		if ( morphTargetInfluences[ i ] != 0.0 ) objectNormal += getMorph( gl_VertexID, i, 1 ).xyz * morphTargetInfluences[ i ];
	}
#endif`,Q1=`#ifdef USE_MORPHTARGETS
	#ifndef USE_INSTANCING_MORPH
		uniform float morphTargetBaseInfluence;
		uniform float morphTargetInfluences[ MORPHTARGETS_COUNT ];
	#endif
	uniform sampler2DArray morphTargetsTexture;
	uniform ivec2 morphTargetsTextureSize;
	vec4 getMorph( const in int vertexIndex, const in int morphTargetIndex, const in int offset ) {
		int texelIndex = vertexIndex * MORPHTARGETS_TEXTURE_STRIDE + offset;
		int y = texelIndex / morphTargetsTextureSize.x;
		int x = texelIndex - y * morphTargetsTextureSize.x;
		ivec3 morphUV = ivec3( x, y, morphTargetIndex );
		return texelFetch( morphTargetsTexture, morphUV, 0 );
	}
#endif`,$1=`#ifdef USE_MORPHTARGETS
	transformed *= morphTargetBaseInfluence;
	for ( int i = 0; i < MORPHTARGETS_COUNT; i ++ ) {
		if ( morphTargetInfluences[ i ] != 0.0 ) transformed += getMorph( gl_VertexID, i, 0 ).xyz * morphTargetInfluences[ i ];
	}
#endif`,tb=`float faceDirection = gl_FrontFacing ? 1.0 : - 1.0;
#ifdef FLAT_SHADED
	vec3 fdx = dFdx( vViewPosition );
	vec3 fdy = dFdy( vViewPosition );
	vec3 normal = normalize( cross( fdx, fdy ) );
#else
	vec3 normal = normalize( vNormal );
	#ifdef DOUBLE_SIDED
		normal *= faceDirection;
	#endif
#endif
#if defined( USE_NORMALMAP_TANGENTSPACE ) || defined( USE_CLEARCOAT_NORMALMAP ) || defined( USE_ANISOTROPY )
	#ifdef USE_TANGENT
		mat3 tbn = mat3( normalize( vTangent ), normalize( vBitangent ), normal );
	#else
		mat3 tbn = getTangentFrame( - vViewPosition, normal,
		#if defined( USE_NORMALMAP )
			vNormalMapUv
		#elif defined( USE_CLEARCOAT_NORMALMAP )
			vClearcoatNormalMapUv
		#else
			vUv
		#endif
		);
	#endif
	#ifdef DOUBLE_SIDED
		tbn[0] *= faceDirection;
		tbn[1] *= faceDirection;
	#endif
#endif
#ifdef USE_CLEARCOAT_NORMALMAP
	#ifdef USE_TANGENT
		mat3 tbn2 = mat3( normalize( vTangent ), normalize( vBitangent ), normal );
	#else
		mat3 tbn2 = getTangentFrame( - vViewPosition, normal, vClearcoatNormalMapUv );
	#endif
	#ifdef DOUBLE_SIDED
		tbn2[0] *= faceDirection;
		tbn2[1] *= faceDirection;
	#endif
#endif
vec3 nonPerturbedNormal = normal;`,eb=`#ifdef USE_NORMALMAP_OBJECTSPACE
	normal = texture2D( normalMap, vNormalMapUv ).xyz * 2.0 - 1.0;
	#ifdef FLIP_SIDED
		normal = - normal;
	#endif
	#ifdef DOUBLE_SIDED
		normal = normal * faceDirection;
	#endif
	normal = normalize( normalMatrix * normal );
#elif defined( USE_NORMALMAP_TANGENTSPACE )
	vec3 mapN = texture2D( normalMap, vNormalMapUv ).xyz * 2.0 - 1.0;
	#if defined( USE_PACKED_NORMALMAP )
		mapN = vec3( mapN.xy, sqrt( saturate( 1.0 - dot( mapN.xy, mapN.xy ) ) ) );
	#endif
	mapN.xy *= normalScale;
	normal = normalize( tbn * mapN );
#elif defined( USE_BUMPMAP )
	normal = perturbNormalArb( - vViewPosition, normal, dHdxy_fwd(), faceDirection );
#endif`,nb=`#ifndef FLAT_SHADED
	varying vec3 vNormal;
	#ifdef USE_TANGENT
		varying vec3 vTangent;
		varying vec3 vBitangent;
	#endif
#endif`,ib=`#ifndef FLAT_SHADED
	varying vec3 vNormal;
	#ifdef USE_TANGENT
		varying vec3 vTangent;
		varying vec3 vBitangent;
	#endif
#endif`,ab=`#ifndef FLAT_SHADED
	vNormal = normalize( transformedNormal );
	#ifdef USE_TANGENT
		vTangent = normalize( transformedTangent );
		vBitangent = normalize( cross( vNormal, vTangent ) * tangent.w );
		#ifdef FLIP_SIDED
			vBitangent = - vBitangent;
		#endif
	#endif
#endif`,sb=`#ifdef USE_NORMALMAP
	uniform sampler2D normalMap;
	uniform vec2 normalScale;
#endif
#ifdef USE_NORMALMAP_OBJECTSPACE
	uniform mat3 normalMatrix;
#endif
#if ! defined ( USE_TANGENT ) && ( defined ( USE_NORMALMAP_TANGENTSPACE ) || defined ( USE_CLEARCOAT_NORMALMAP ) || defined( USE_ANISOTROPY ) )
	mat3 getTangentFrame( vec3 eye_pos, vec3 surf_norm, vec2 uv ) {
		vec3 q0 = dFdx( eye_pos.xyz );
		vec3 q1 = dFdy( eye_pos.xyz );
		vec2 st0 = dFdx( uv.st );
		vec2 st1 = dFdy( uv.st );
		vec3 N = surf_norm;
		vec3 q1perp = cross( q1, N );
		vec3 q0perp = cross( N, q0 );
		vec3 T = q1perp * st0.x + q0perp * st1.x;
		vec3 B = q1perp * st0.y + q0perp * st1.y;
		float det = max( dot( T, T ), dot( B, B ) );
		float scale = ( det == 0.0 ) ? 0.0 : inversesqrt( det );
		return mat3( T * scale, B * scale, N );
	}
#endif`,rb=`#ifdef USE_CLEARCOAT
	vec3 clearcoatNormal = nonPerturbedNormal;
#endif`,ob=`#ifdef USE_CLEARCOAT_NORMALMAP
	vec3 clearcoatMapN = texture2D( clearcoatNormalMap, vClearcoatNormalMapUv ).xyz * 2.0 - 1.0;
	clearcoatMapN.xy *= clearcoatNormalScale;
	clearcoatNormal = normalize( tbn2 * clearcoatMapN );
#endif`,lb=`#ifdef USE_CLEARCOATMAP
	uniform sampler2D clearcoatMap;
#endif
#ifdef USE_CLEARCOAT_NORMALMAP
	uniform sampler2D clearcoatNormalMap;
	uniform vec2 clearcoatNormalScale;
#endif
#ifdef USE_CLEARCOAT_ROUGHNESSMAP
	uniform sampler2D clearcoatRoughnessMap;
#endif`,cb=`#ifdef USE_IRIDESCENCEMAP
	uniform sampler2D iridescenceMap;
#endif
#ifdef USE_IRIDESCENCE_THICKNESSMAP
	uniform sampler2D iridescenceThicknessMap;
#endif`,ub=`#ifdef OPAQUE
diffuseColor.a = 1.0;
#endif
#ifdef USE_TRANSMISSION
diffuseColor.a *= material.transmissionAlpha;
#endif
gl_FragColor = vec4( outgoingLight, diffuseColor.a );`,fb=`vec3 packNormalToRGB( const in vec3 normal ) {
	return normalize( normal ) * 0.5 + 0.5;
}
vec3 unpackRGBToNormal( const in vec3 rgb ) {
	return 2.0 * rgb.xyz - 1.0;
}
const float PackUpscale = 256. / 255.;const float UnpackDownscale = 255. / 256.;const float ShiftRight8 = 1. / 256.;
const float Inv255 = 1. / 255.;
const vec4 PackFactors = vec4( 1.0, 256.0, 256.0 * 256.0, 256.0 * 256.0 * 256.0 );
const vec2 UnpackFactors2 = vec2( UnpackDownscale, 1.0 / PackFactors.g );
const vec3 UnpackFactors3 = vec3( UnpackDownscale / PackFactors.rg, 1.0 / PackFactors.b );
const vec4 UnpackFactors4 = vec4( UnpackDownscale / PackFactors.rgb, 1.0 / PackFactors.a );
vec4 packDepthToRGBA( const in float v ) {
	if( v <= 0.0 )
		return vec4( 0., 0., 0., 0. );
	if( v >= 1.0 )
		return vec4( 1., 1., 1., 1. );
	float vuf;
	float af = modf( v * PackFactors.a, vuf );
	float bf = modf( vuf * ShiftRight8, vuf );
	float gf = modf( vuf * ShiftRight8, vuf );
	return vec4( vuf * Inv255, gf * PackUpscale, bf * PackUpscale, af );
}
vec3 packDepthToRGB( const in float v ) {
	if( v <= 0.0 )
		return vec3( 0., 0., 0. );
	if( v >= 1.0 )
		return vec3( 1., 1., 1. );
	float vuf;
	float bf = modf( v * PackFactors.b, vuf );
	float gf = modf( vuf * ShiftRight8, vuf );
	return vec3( vuf * Inv255, gf * PackUpscale, bf );
}
vec2 packDepthToRG( const in float v ) {
	if( v <= 0.0 )
		return vec2( 0., 0. );
	if( v >= 1.0 )
		return vec2( 1., 1. );
	float vuf;
	float gf = modf( v * 256., vuf );
	return vec2( vuf * Inv255, gf );
}
float unpackRGBAToDepth( const in vec4 v ) {
	return dot( v, UnpackFactors4 );
}
float unpackRGBToDepth( const in vec3 v ) {
	return dot( v, UnpackFactors3 );
}
float unpackRGToDepth( const in vec2 v ) {
	return v.r * UnpackFactors2.r + v.g * UnpackFactors2.g;
}
vec4 pack2HalfToRGBA( const in vec2 v ) {
	vec4 r = vec4( v.x, fract( v.x * 255.0 ), v.y, fract( v.y * 255.0 ) );
	return vec4( r.x - r.y / 255.0, r.y, r.z - r.w / 255.0, r.w );
}
vec2 unpackRGBATo2Half( const in vec4 v ) {
	return vec2( v.x + ( v.y / 255.0 ), v.z + ( v.w / 255.0 ) );
}
float viewZToOrthographicDepth( const in float viewZ, const in float near, const in float far ) {
	return ( viewZ + near ) / ( near - far );
}
float orthographicDepthToViewZ( const in float depth, const in float near, const in float far ) {
	#ifdef USE_REVERSED_DEPTH_BUFFER
	
		return depth * ( far - near ) - far;
	#else
		return depth * ( near - far ) - near;
	#endif
}
float viewZToPerspectiveDepth( const in float viewZ, const in float near, const in float far ) {
	return ( ( near + viewZ ) * far ) / ( ( far - near ) * viewZ );
}
float perspectiveDepthToViewZ( const in float depth, const in float near, const in float far ) {
	
	#ifdef USE_REVERSED_DEPTH_BUFFER
		return ( near * far ) / ( ( near - far ) * depth - near );
	#else
		return ( near * far ) / ( ( far - near ) * depth - far );
	#endif
}`,hb=`#ifdef PREMULTIPLIED_ALPHA
	gl_FragColor.rgb *= gl_FragColor.a;
#endif`,db=`vec4 mvPosition = vec4( transformed, 1.0 );
#ifdef USE_BATCHING
	mvPosition = batchingMatrix * mvPosition;
#endif
#ifdef USE_INSTANCING
	mvPosition = instanceMatrix * mvPosition;
#endif
mvPosition = modelViewMatrix * mvPosition;
gl_Position = projectionMatrix * mvPosition;`,pb=`#ifdef DITHERING
	gl_FragColor.rgb = dithering( gl_FragColor.rgb );
#endif`,mb=`#ifdef DITHERING
	vec3 dithering( vec3 color ) {
		float grid_position = rand( gl_FragCoord.xy );
		vec3 dither_shift_RGB = vec3( 0.25 / 255.0, -0.25 / 255.0, 0.25 / 255.0 );
		dither_shift_RGB = mix( 2.0 * dither_shift_RGB, -2.0 * dither_shift_RGB, grid_position );
		return color + dither_shift_RGB;
	}
#endif`,gb=`float roughnessFactor = roughness;
#ifdef USE_ROUGHNESSMAP
	vec4 texelRoughness = texture2D( roughnessMap, vRoughnessMapUv );
	roughnessFactor *= texelRoughness.g;
#endif`,vb=`#ifdef USE_ROUGHNESSMAP
	uniform sampler2D roughnessMap;
#endif`,_b=`#if NUM_SPOT_LIGHT_COORDS > 0
	varying vec4 vSpotLightCoord[ NUM_SPOT_LIGHT_COORDS ];
#endif
#if NUM_SPOT_LIGHT_MAPS > 0
	uniform sampler2D spotLightMap[ NUM_SPOT_LIGHT_MAPS ];
#endif
#ifdef USE_SHADOWMAP
	#if NUM_DIR_LIGHT_SHADOWS > 0
		#if defined( SHADOWMAP_TYPE_PCF )
			uniform sampler2DShadow directionalShadowMap[ NUM_DIR_LIGHT_SHADOWS ];
		#else
			uniform sampler2D directionalShadowMap[ NUM_DIR_LIGHT_SHADOWS ];
		#endif
		varying vec4 vDirectionalShadowCoord[ NUM_DIR_LIGHT_SHADOWS ];
		struct DirectionalLightShadow {
			float shadowIntensity;
			float shadowBias;
			float shadowNormalBias;
			float shadowRadius;
			vec2 shadowMapSize;
		};
		uniform DirectionalLightShadow directionalLightShadows[ NUM_DIR_LIGHT_SHADOWS ];
	#endif
	#if NUM_SPOT_LIGHT_SHADOWS > 0
		#if defined( SHADOWMAP_TYPE_PCF )
			uniform sampler2DShadow spotShadowMap[ NUM_SPOT_LIGHT_SHADOWS ];
		#else
			uniform sampler2D spotShadowMap[ NUM_SPOT_LIGHT_SHADOWS ];
		#endif
		struct SpotLightShadow {
			float shadowIntensity;
			float shadowBias;
			float shadowNormalBias;
			float shadowRadius;
			vec2 shadowMapSize;
		};
		uniform SpotLightShadow spotLightShadows[ NUM_SPOT_LIGHT_SHADOWS ];
	#endif
	#if NUM_POINT_LIGHT_SHADOWS > 0
		#if defined( SHADOWMAP_TYPE_PCF )
			uniform samplerCubeShadow pointShadowMap[ NUM_POINT_LIGHT_SHADOWS ];
		#elif defined( SHADOWMAP_TYPE_BASIC )
			uniform samplerCube pointShadowMap[ NUM_POINT_LIGHT_SHADOWS ];
		#endif
		varying vec4 vPointShadowCoord[ NUM_POINT_LIGHT_SHADOWS ];
		struct PointLightShadow {
			float shadowIntensity;
			float shadowBias;
			float shadowNormalBias;
			float shadowRadius;
			vec2 shadowMapSize;
			float shadowCameraNear;
			float shadowCameraFar;
		};
		uniform PointLightShadow pointLightShadows[ NUM_POINT_LIGHT_SHADOWS ];
	#endif
	#if defined( SHADOWMAP_TYPE_PCF )
		float interleavedGradientNoise( vec2 position ) {
			return fract( 52.9829189 * fract( dot( position, vec2( 0.06711056, 0.00583715 ) ) ) );
		}
		vec2 vogelDiskSample( int sampleIndex, int samplesCount, float phi ) {
			const float goldenAngle = 2.399963229728653;
			float r = sqrt( ( float( sampleIndex ) + 0.5 ) / float( samplesCount ) );
			float theta = float( sampleIndex ) * goldenAngle + phi;
			return vec2( cos( theta ), sin( theta ) ) * r;
		}
	#endif
	#if defined( SHADOWMAP_TYPE_PCF )
		float getShadow( sampler2DShadow shadowMap, vec2 shadowMapSize, float shadowIntensity, float shadowBias, float shadowRadius, vec4 shadowCoord ) {
			float shadow = 1.0;
			shadowCoord.xyz /= shadowCoord.w;
			shadowCoord.z += shadowBias;
			bool inFrustum = shadowCoord.x >= 0.0 && shadowCoord.x <= 1.0 && shadowCoord.y >= 0.0 && shadowCoord.y <= 1.0;
			bool frustumTest = inFrustum && shadowCoord.z <= 1.0;
			if ( frustumTest ) {
				vec2 texelSize = vec2( 1.0 ) / shadowMapSize;
				float radius = shadowRadius * texelSize.x;
				float phi = interleavedGradientNoise( gl_FragCoord.xy ) * PI2;
				shadow = (
					texture( shadowMap, vec3( shadowCoord.xy + vogelDiskSample( 0, 5, phi ) * radius, shadowCoord.z ) ) +
					texture( shadowMap, vec3( shadowCoord.xy + vogelDiskSample( 1, 5, phi ) * radius, shadowCoord.z ) ) +
					texture( shadowMap, vec3( shadowCoord.xy + vogelDiskSample( 2, 5, phi ) * radius, shadowCoord.z ) ) +
					texture( shadowMap, vec3( shadowCoord.xy + vogelDiskSample( 3, 5, phi ) * radius, shadowCoord.z ) ) +
					texture( shadowMap, vec3( shadowCoord.xy + vogelDiskSample( 4, 5, phi ) * radius, shadowCoord.z ) )
				) * 0.2;
			}
			return mix( 1.0, shadow, shadowIntensity );
		}
	#elif defined( SHADOWMAP_TYPE_VSM )
		float getShadow( sampler2D shadowMap, vec2 shadowMapSize, float shadowIntensity, float shadowBias, float shadowRadius, vec4 shadowCoord ) {
			float shadow = 1.0;
			shadowCoord.xyz /= shadowCoord.w;
			#ifdef USE_REVERSED_DEPTH_BUFFER
				shadowCoord.z -= shadowBias;
			#else
				shadowCoord.z += shadowBias;
			#endif
			bool inFrustum = shadowCoord.x >= 0.0 && shadowCoord.x <= 1.0 && shadowCoord.y >= 0.0 && shadowCoord.y <= 1.0;
			bool frustumTest = inFrustum && shadowCoord.z <= 1.0;
			if ( frustumTest ) {
				vec2 distribution = texture2D( shadowMap, shadowCoord.xy ).rg;
				float mean = distribution.x;
				float variance = distribution.y * distribution.y;
				#ifdef USE_REVERSED_DEPTH_BUFFER
					float hard_shadow = step( mean, shadowCoord.z );
				#else
					float hard_shadow = step( shadowCoord.z, mean );
				#endif
				
				if ( hard_shadow == 1.0 ) {
					shadow = 1.0;
				} else {
					variance = max( variance, 0.0000001 );
					float d = shadowCoord.z - mean;
					float p_max = variance / ( variance + d * d );
					p_max = clamp( ( p_max - 0.3 ) / 0.65, 0.0, 1.0 );
					shadow = max( hard_shadow, p_max );
				}
			}
			return mix( 1.0, shadow, shadowIntensity );
		}
	#else
		float getShadow( sampler2D shadowMap, vec2 shadowMapSize, float shadowIntensity, float shadowBias, float shadowRadius, vec4 shadowCoord ) {
			float shadow = 1.0;
			shadowCoord.xyz /= shadowCoord.w;
			#ifdef USE_REVERSED_DEPTH_BUFFER
				shadowCoord.z -= shadowBias;
			#else
				shadowCoord.z += shadowBias;
			#endif
			bool inFrustum = shadowCoord.x >= 0.0 && shadowCoord.x <= 1.0 && shadowCoord.y >= 0.0 && shadowCoord.y <= 1.0;
			bool frustumTest = inFrustum && shadowCoord.z <= 1.0;
			if ( frustumTest ) {
				float depth = texture2D( shadowMap, shadowCoord.xy ).r;
				#ifdef USE_REVERSED_DEPTH_BUFFER
					shadow = step( depth, shadowCoord.z );
				#else
					shadow = step( shadowCoord.z, depth );
				#endif
			}
			return mix( 1.0, shadow, shadowIntensity );
		}
	#endif
	#if NUM_POINT_LIGHT_SHADOWS > 0
	#if defined( SHADOWMAP_TYPE_PCF )
	float getPointShadow( samplerCubeShadow shadowMap, vec2 shadowMapSize, float shadowIntensity, float shadowBias, float shadowRadius, vec4 shadowCoord, float shadowCameraNear, float shadowCameraFar ) {
		float shadow = 1.0;
		vec3 lightToPosition = shadowCoord.xyz;
		vec3 bd3D = normalize( lightToPosition );
		vec3 absVec = abs( lightToPosition );
		float viewSpaceZ = max( max( absVec.x, absVec.y ), absVec.z );
		if ( viewSpaceZ - shadowCameraFar <= 0.0 && viewSpaceZ - shadowCameraNear >= 0.0 ) {
			#ifdef USE_REVERSED_DEPTH_BUFFER
				float dp = ( shadowCameraNear * ( shadowCameraFar - viewSpaceZ ) ) / ( viewSpaceZ * ( shadowCameraFar - shadowCameraNear ) );
				dp -= shadowBias;
			#else
				float dp = ( shadowCameraFar * ( viewSpaceZ - shadowCameraNear ) ) / ( viewSpaceZ * ( shadowCameraFar - shadowCameraNear ) );
				dp += shadowBias;
			#endif
			float texelSize = shadowRadius / shadowMapSize.x;
			vec3 absDir = abs( bd3D );
			vec3 tangent = absDir.x > absDir.z ? vec3( 0.0, 1.0, 0.0 ) : vec3( 1.0, 0.0, 0.0 );
			tangent = normalize( cross( bd3D, tangent ) );
			vec3 bitangent = cross( bd3D, tangent );
			float phi = interleavedGradientNoise( gl_FragCoord.xy ) * PI2;
			vec2 sample0 = vogelDiskSample( 0, 5, phi );
			vec2 sample1 = vogelDiskSample( 1, 5, phi );
			vec2 sample2 = vogelDiskSample( 2, 5, phi );
			vec2 sample3 = vogelDiskSample( 3, 5, phi );
			vec2 sample4 = vogelDiskSample( 4, 5, phi );
			shadow = (
				texture( shadowMap, vec4( bd3D + ( tangent * sample0.x + bitangent * sample0.y ) * texelSize, dp ) ) +
				texture( shadowMap, vec4( bd3D + ( tangent * sample1.x + bitangent * sample1.y ) * texelSize, dp ) ) +
				texture( shadowMap, vec4( bd3D + ( tangent * sample2.x + bitangent * sample2.y ) * texelSize, dp ) ) +
				texture( shadowMap, vec4( bd3D + ( tangent * sample3.x + bitangent * sample3.y ) * texelSize, dp ) ) +
				texture( shadowMap, vec4( bd3D + ( tangent * sample4.x + bitangent * sample4.y ) * texelSize, dp ) )
			) * 0.2;
		}
		return mix( 1.0, shadow, shadowIntensity );
	}
	#elif defined( SHADOWMAP_TYPE_BASIC )
	float getPointShadow( samplerCube shadowMap, vec2 shadowMapSize, float shadowIntensity, float shadowBias, float shadowRadius, vec4 shadowCoord, float shadowCameraNear, float shadowCameraFar ) {
		float shadow = 1.0;
		vec3 lightToPosition = shadowCoord.xyz;
		vec3 absVec = abs( lightToPosition );
		float viewSpaceZ = max( max( absVec.x, absVec.y ), absVec.z );
		if ( viewSpaceZ - shadowCameraFar <= 0.0 && viewSpaceZ - shadowCameraNear >= 0.0 ) {
			float dp = ( shadowCameraFar * ( viewSpaceZ - shadowCameraNear ) ) / ( viewSpaceZ * ( shadowCameraFar - shadowCameraNear ) );
			dp += shadowBias;
			vec3 bd3D = normalize( lightToPosition );
			float depth = textureCube( shadowMap, bd3D ).r;
			#ifdef USE_REVERSED_DEPTH_BUFFER
				depth = 1.0 - depth;
			#endif
			shadow = step( dp, depth );
		}
		return mix( 1.0, shadow, shadowIntensity );
	}
	#endif
	#endif
#endif`,xb=`#if NUM_SPOT_LIGHT_COORDS > 0
	uniform mat4 spotLightMatrix[ NUM_SPOT_LIGHT_COORDS ];
	varying vec4 vSpotLightCoord[ NUM_SPOT_LIGHT_COORDS ];
#endif
#ifdef USE_SHADOWMAP
	#if NUM_DIR_LIGHT_SHADOWS > 0
		uniform mat4 directionalShadowMatrix[ NUM_DIR_LIGHT_SHADOWS ];
		varying vec4 vDirectionalShadowCoord[ NUM_DIR_LIGHT_SHADOWS ];
		struct DirectionalLightShadow {
			float shadowIntensity;
			float shadowBias;
			float shadowNormalBias;
			float shadowRadius;
			vec2 shadowMapSize;
		};
		uniform DirectionalLightShadow directionalLightShadows[ NUM_DIR_LIGHT_SHADOWS ];
	#endif
	#if NUM_SPOT_LIGHT_SHADOWS > 0
		struct SpotLightShadow {
			float shadowIntensity;
			float shadowBias;
			float shadowNormalBias;
			float shadowRadius;
			vec2 shadowMapSize;
		};
		uniform SpotLightShadow spotLightShadows[ NUM_SPOT_LIGHT_SHADOWS ];
	#endif
	#if NUM_POINT_LIGHT_SHADOWS > 0
		uniform mat4 pointShadowMatrix[ NUM_POINT_LIGHT_SHADOWS ];
		varying vec4 vPointShadowCoord[ NUM_POINT_LIGHT_SHADOWS ];
		struct PointLightShadow {
			float shadowIntensity;
			float shadowBias;
			float shadowNormalBias;
			float shadowRadius;
			vec2 shadowMapSize;
			float shadowCameraNear;
			float shadowCameraFar;
		};
		uniform PointLightShadow pointLightShadows[ NUM_POINT_LIGHT_SHADOWS ];
	#endif
#endif`,Sb=`#if ( defined( USE_SHADOWMAP ) && ( NUM_DIR_LIGHT_SHADOWS > 0 || NUM_POINT_LIGHT_SHADOWS > 0 ) ) || ( NUM_SPOT_LIGHT_COORDS > 0 )
	#ifdef HAS_NORMAL
		vec3 shadowWorldNormal = transformNormalByInverseViewMatrix( transformedNormal, viewMatrix );
	#else
		vec3 shadowWorldNormal = vec3( 0.0 );
	#endif
	vec4 shadowWorldPosition;
#endif
#if defined( USE_SHADOWMAP )
	#if NUM_DIR_LIGHT_SHADOWS > 0
		#pragma unroll_loop_start
		for ( int i = 0; i < NUM_DIR_LIGHT_SHADOWS; i ++ ) {
			shadowWorldPosition = worldPosition + vec4( shadowWorldNormal * directionalLightShadows[ i ].shadowNormalBias, 0 );
			vDirectionalShadowCoord[ i ] = directionalShadowMatrix[ i ] * shadowWorldPosition;
		}
		#pragma unroll_loop_end
	#endif
	#if NUM_POINT_LIGHT_SHADOWS > 0
		#pragma unroll_loop_start
		for ( int i = 0; i < NUM_POINT_LIGHT_SHADOWS; i ++ ) {
			shadowWorldPosition = worldPosition + vec4( shadowWorldNormal * pointLightShadows[ i ].shadowNormalBias, 0 );
			vPointShadowCoord[ i ] = pointShadowMatrix[ i ] * shadowWorldPosition;
		}
		#pragma unroll_loop_end
	#endif
#endif
#if NUM_SPOT_LIGHT_COORDS > 0
	#pragma unroll_loop_start
	for ( int i = 0; i < NUM_SPOT_LIGHT_COORDS; i ++ ) {
		shadowWorldPosition = worldPosition;
		#if ( defined( USE_SHADOWMAP ) && UNROLLED_LOOP_INDEX < NUM_SPOT_LIGHT_SHADOWS )
			shadowWorldPosition.xyz += shadowWorldNormal * spotLightShadows[ i ].shadowNormalBias;
		#endif
		vSpotLightCoord[ i ] = spotLightMatrix[ i ] * shadowWorldPosition;
	}
	#pragma unroll_loop_end
#endif`,yb=`float getShadowMask() {
	float shadow = 1.0;
	#ifdef USE_SHADOWMAP
	#if NUM_DIR_LIGHT_SHADOWS > 0
	DirectionalLightShadow directionalLight;
	#pragma unroll_loop_start
	for ( int i = 0; i < NUM_DIR_LIGHT_SHADOWS; i ++ ) {
		directionalLight = directionalLightShadows[ i ];
		shadow *= receiveShadow ? getShadow( directionalShadowMap[ i ], directionalLight.shadowMapSize, directionalLight.shadowIntensity, directionalLight.shadowBias, directionalLight.shadowRadius, vDirectionalShadowCoord[ i ] ) : 1.0;
	}
	#pragma unroll_loop_end
	#endif
	#if NUM_SPOT_LIGHT_SHADOWS > 0
	SpotLightShadow spotLight;
	#pragma unroll_loop_start
	for ( int i = 0; i < NUM_SPOT_LIGHT_SHADOWS; i ++ ) {
		spotLight = spotLightShadows[ i ];
		shadow *= receiveShadow ? getShadow( spotShadowMap[ i ], spotLight.shadowMapSize, spotLight.shadowIntensity, spotLight.shadowBias, spotLight.shadowRadius, vSpotLightCoord[ i ] ) : 1.0;
	}
	#pragma unroll_loop_end
	#endif
	#if NUM_POINT_LIGHT_SHADOWS > 0 && ( defined( SHADOWMAP_TYPE_PCF ) || defined( SHADOWMAP_TYPE_BASIC ) )
	PointLightShadow pointLight;
	#pragma unroll_loop_start
	for ( int i = 0; i < NUM_POINT_LIGHT_SHADOWS; i ++ ) {
		pointLight = pointLightShadows[ i ];
		shadow *= receiveShadow ? getPointShadow( pointShadowMap[ i ], pointLight.shadowMapSize, pointLight.shadowIntensity, pointLight.shadowBias, pointLight.shadowRadius, vPointShadowCoord[ i ], pointLight.shadowCameraNear, pointLight.shadowCameraFar ) : 1.0;
	}
	#pragma unroll_loop_end
	#endif
	#endif
	return shadow;
}`,Mb=`#ifdef USE_SKINNING
	mat4 boneMatX = getBoneMatrix( skinIndex.x );
	mat4 boneMatY = getBoneMatrix( skinIndex.y );
	mat4 boneMatZ = getBoneMatrix( skinIndex.z );
	mat4 boneMatW = getBoneMatrix( skinIndex.w );
#endif`,Eb=`#ifdef USE_SKINNING
	uniform mat4 bindMatrix;
	uniform mat4 bindMatrixInverse;
	uniform highp sampler2D boneTexture;
	mat4 getBoneMatrix( const in float i ) {
		int size = textureSize( boneTexture, 0 ).x;
		int j = int( i ) * 4;
		int x = j % size;
		int y = j / size;
		vec4 v1 = texelFetch( boneTexture, ivec2( x, y ), 0 );
		vec4 v2 = texelFetch( boneTexture, ivec2( x + 1, y ), 0 );
		vec4 v3 = texelFetch( boneTexture, ivec2( x + 2, y ), 0 );
		vec4 v4 = texelFetch( boneTexture, ivec2( x + 3, y ), 0 );
		return mat4( v1, v2, v3, v4 );
	}
#endif`,bb=`#ifdef USE_SKINNING
	vec4 skinVertex = bindMatrix * vec4( transformed, 1.0 );
	vec4 skinned = vec4( 0.0 );
	skinned += boneMatX * skinVertex * skinWeight.x;
	skinned += boneMatY * skinVertex * skinWeight.y;
	skinned += boneMatZ * skinVertex * skinWeight.z;
	skinned += boneMatW * skinVertex * skinWeight.w;
	transformed = ( bindMatrixInverse * skinned ).xyz;
#endif`,Tb=`#ifdef USE_SKINNING
	mat4 skinMatrix = mat4( 0.0 );
	skinMatrix += skinWeight.x * boneMatX;
	skinMatrix += skinWeight.y * boneMatY;
	skinMatrix += skinWeight.z * boneMatZ;
	skinMatrix += skinWeight.w * boneMatW;
	skinMatrix = bindMatrixInverse * skinMatrix * bindMatrix;
	objectNormal = vec4( skinMatrix * vec4( objectNormal, 0.0 ) ).xyz;
	#ifdef USE_TANGENT
		objectTangent = vec4( skinMatrix * vec4( objectTangent, 0.0 ) ).xyz;
	#endif
#endif`,Ab=`float specularStrength;
#ifdef USE_SPECULARMAP
	vec4 texelSpecular = texture2D( specularMap, vSpecularMapUv );
	specularStrength = texelSpecular.r;
#else
	specularStrength = 1.0;
#endif`,Rb=`#ifdef USE_SPECULARMAP
	uniform sampler2D specularMap;
#endif`,Cb=`#if defined( TONE_MAPPING )
	gl_FragColor.rgb = toneMapping( gl_FragColor.rgb );
#endif`,wb=`#ifndef saturate
#define saturate( a ) clamp( a, 0.0, 1.0 )
#endif
uniform float toneMappingExposure;
vec3 LinearToneMapping( vec3 color ) {
	return saturate( toneMappingExposure * color );
}
vec3 ReinhardToneMapping( vec3 color ) {
	color *= toneMappingExposure;
	return saturate( color / ( vec3( 1.0 ) + color ) );
}
vec3 CineonToneMapping( vec3 color ) {
	color *= toneMappingExposure;
	color = max( vec3( 0.0 ), color - 0.004 );
	return pow( ( color * ( 6.2 * color + 0.5 ) ) / ( color * ( 6.2 * color + 1.7 ) + 0.06 ), vec3( 2.2 ) );
}
vec3 RRTAndODTFit( vec3 v ) {
	vec3 a = v * ( v + 0.0245786 ) - 0.000090537;
	vec3 b = v * ( 0.983729 * v + 0.4329510 ) + 0.238081;
	return a / b;
}
vec3 ACESFilmicToneMapping( vec3 color ) {
	const mat3 ACESInputMat = mat3(
		vec3( 0.59719, 0.07600, 0.02840 ),		vec3( 0.35458, 0.90834, 0.13383 ),
		vec3( 0.04823, 0.01566, 0.83777 )
	);
	const mat3 ACESOutputMat = mat3(
		vec3(  1.60475, -0.10208, -0.00327 ),		vec3( -0.53108,  1.10813, -0.07276 ),
		vec3( -0.07367, -0.00605,  1.07602 )
	);
	color *= toneMappingExposure / 0.6;
	color = ACESInputMat * color;
	color = RRTAndODTFit( color );
	color = ACESOutputMat * color;
	return saturate( color );
}
const mat3 LINEAR_REC2020_TO_LINEAR_SRGB = mat3(
	vec3( 1.6605, - 0.1246, - 0.0182 ),
	vec3( - 0.5876, 1.1329, - 0.1006 ),
	vec3( - 0.0728, - 0.0083, 1.1187 )
);
const mat3 LINEAR_SRGB_TO_LINEAR_REC2020 = mat3(
	vec3( 0.6274, 0.0691, 0.0164 ),
	vec3( 0.3293, 0.9195, 0.0880 ),
	vec3( 0.0433, 0.0113, 0.8956 )
);
vec3 agxDefaultContrastApprox( vec3 x ) {
	vec3 x2 = x * x;
	vec3 x4 = x2 * x2;
	return + 15.5 * x4 * x2
		- 40.14 * x4 * x
		+ 31.96 * x4
		- 6.868 * x2 * x
		+ 0.4298 * x2
		+ 0.1191 * x
		- 0.00232;
}
vec3 AgXToneMapping( vec3 color ) {
	const mat3 AgXInsetMatrix = mat3(
		vec3( 0.856627153315983, 0.137318972929847, 0.11189821299995 ),
		vec3( 0.0951212405381588, 0.761241990602591, 0.0767994186031903 ),
		vec3( 0.0482516061458583, 0.101439036467562, 0.811302368396859 )
	);
	const mat3 AgXOutsetMatrix = mat3(
		vec3( 1.1271005818144368, - 0.1413297634984383, - 0.14132976349843826 ),
		vec3( - 0.11060664309660323, 1.157823702216272, - 0.11060664309660294 ),
		vec3( - 0.016493938717834573, - 0.016493938717834257, 1.2519364065950405 )
	);
	const float AgxMinEv = - 12.47393;	const float AgxMaxEv = 4.026069;
	color *= toneMappingExposure;
	color = LINEAR_SRGB_TO_LINEAR_REC2020 * color;
	color = AgXInsetMatrix * color;
	color = max( color, 1e-10 );	color = log2( color );
	color = ( color - AgxMinEv ) / ( AgxMaxEv - AgxMinEv );
	color = clamp( color, 0.0, 1.0 );
	color = agxDefaultContrastApprox( color );
	color = AgXOutsetMatrix * color;
	color = pow( max( vec3( 0.0 ), color ), vec3( 2.2 ) );
	color = LINEAR_REC2020_TO_LINEAR_SRGB * color;
	color = clamp( color, 0.0, 1.0 );
	return color;
}
vec3 NeutralToneMapping( vec3 color ) {
	const float StartCompression = 0.8 - 0.04;
	const float Desaturation = 0.15;
	color *= toneMappingExposure;
	float x = min( color.r, min( color.g, color.b ) );
	float offset = x < 0.08 ? x - 6.25 * x * x : 0.04;
	color -= offset;
	float peak = max( color.r, max( color.g, color.b ) );
	if ( peak < StartCompression ) return color;
	float d = 1. - StartCompression;
	float newPeak = 1. - d * d / ( peak + d - StartCompression );
	color *= newPeak / peak;
	float g = 1. - 1. / ( Desaturation * ( peak - newPeak ) + 1. );
	return mix( color, vec3( newPeak ), g );
}
vec3 CustomToneMapping( vec3 color ) { return color; }`,Db=`#ifdef USE_TRANSMISSION
	material.transmission = transmission;
	material.transmissionAlpha = 1.0;
	material.thickness = thickness;
	material.attenuationDistance = attenuationDistance;
	material.attenuationColor = attenuationColor;
	#ifdef USE_TRANSMISSIONMAP
		material.transmission *= texture2D( transmissionMap, vTransmissionMapUv ).r;
	#endif
	#ifdef USE_THICKNESSMAP
		material.thickness *= texture2D( thicknessMap, vThicknessMapUv ).g;
	#endif
	vec3 pos = vWorldPosition;
	vec3 v = normalize( cameraPosition - pos );
	vec3 n = transformNormalByInverseViewMatrix( normal, viewMatrix );
	vec4 transmitted = getIBLVolumeRefraction(
		n, v, material.roughness, material.diffuseContribution, material.specularColorBlended, material.specularF90,
		pos, modelMatrix, viewMatrix, projectionMatrix, material.dispersion, material.ior, material.thickness,
		material.attenuationColor, material.attenuationDistance );
	material.transmissionAlpha = mix( material.transmissionAlpha, transmitted.a, material.transmission );
	totalDiffuse = mix( totalDiffuse, transmitted.rgb, material.transmission );
#endif`,Nb=`#ifdef USE_TRANSMISSION
	uniform float transmission;
	uniform float thickness;
	uniform float attenuationDistance;
	uniform vec3 attenuationColor;
	#ifdef USE_TRANSMISSIONMAP
		uniform sampler2D transmissionMap;
	#endif
	#ifdef USE_THICKNESSMAP
		uniform sampler2D thicknessMap;
	#endif
	uniform vec2 transmissionSamplerSize;
	uniform sampler2D transmissionSamplerMap;
	uniform mat4 modelMatrix;
	uniform mat4 projectionMatrix;
	varying vec3 vWorldPosition;
	float w0( float a ) {
		return ( 1.0 / 6.0 ) * ( a * ( a * ( - a + 3.0 ) - 3.0 ) + 1.0 );
	}
	float w1( float a ) {
		return ( 1.0 / 6.0 ) * ( a *  a * ( 3.0 * a - 6.0 ) + 4.0 );
	}
	float w2( float a ){
		return ( 1.0 / 6.0 ) * ( a * ( a * ( - 3.0 * a + 3.0 ) + 3.0 ) + 1.0 );
	}
	float w3( float a ) {
		return ( 1.0 / 6.0 ) * ( a * a * a );
	}
	float g0( float a ) {
		return w0( a ) + w1( a );
	}
	float g1( float a ) {
		return w2( a ) + w3( a );
	}
	float h0( float a ) {
		return - 1.0 + w1( a ) / ( w0( a ) + w1( a ) );
	}
	float h1( float a ) {
		return 1.0 + w3( a ) / ( w2( a ) + w3( a ) );
	}
	vec4 bicubic( sampler2D tex, vec2 uv, vec4 texelSize, float lod ) {
		uv = uv * texelSize.zw + 0.5;
		vec2 iuv = floor( uv );
		vec2 fuv = fract( uv );
		float g0x = g0( fuv.x );
		float g1x = g1( fuv.x );
		float h0x = h0( fuv.x );
		float h1x = h1( fuv.x );
		float h0y = h0( fuv.y );
		float h1y = h1( fuv.y );
		vec2 p0 = ( vec2( iuv.x + h0x, iuv.y + h0y ) - 0.5 ) * texelSize.xy;
		vec2 p1 = ( vec2( iuv.x + h1x, iuv.y + h0y ) - 0.5 ) * texelSize.xy;
		vec2 p2 = ( vec2( iuv.x + h0x, iuv.y + h1y ) - 0.5 ) * texelSize.xy;
		vec2 p3 = ( vec2( iuv.x + h1x, iuv.y + h1y ) - 0.5 ) * texelSize.xy;
		return g0( fuv.y ) * ( g0x * textureLod( tex, p0, lod ) + g1x * textureLod( tex, p1, lod ) ) +
			g1( fuv.y ) * ( g0x * textureLod( tex, p2, lod ) + g1x * textureLod( tex, p3, lod ) );
	}
	vec4 textureBicubic( sampler2D sampler, vec2 uv, float lod ) {
		vec2 fLodSize = vec2( textureSize( sampler, int( lod ) ) );
		vec2 cLodSize = vec2( textureSize( sampler, int( lod + 1.0 ) ) );
		vec2 fLodSizeInv = 1.0 / fLodSize;
		vec2 cLodSizeInv = 1.0 / cLodSize;
		vec4 fSample = bicubic( sampler, uv, vec4( fLodSizeInv, fLodSize ), floor( lod ) );
		vec4 cSample = bicubic( sampler, uv, vec4( cLodSizeInv, cLodSize ), ceil( lod ) );
		return mix( fSample, cSample, fract( lod ) );
	}
	vec3 getVolumeTransmissionRay( const in vec3 n, const in vec3 v, const in float thickness, const in float ior, const in mat4 modelMatrix ) {
		vec3 refractionVector = refract( - v, normalize( n ), 1.0 / ior );
		vec3 modelScale;
		modelScale.x = length( vec3( modelMatrix[ 0 ].xyz ) );
		modelScale.y = length( vec3( modelMatrix[ 1 ].xyz ) );
		modelScale.z = length( vec3( modelMatrix[ 2 ].xyz ) );
		return normalize( refractionVector ) * thickness * modelScale;
	}
	float applyIorToRoughness( const in float roughness, const in float ior ) {
		return roughness * clamp( ior * 2.0 - 2.0, 0.0, 1.0 );
	}
	vec4 getTransmissionSample( const in vec2 fragCoord, const in float roughness, const in float ior ) {
		float lod = log2( transmissionSamplerSize.x ) * applyIorToRoughness( roughness, ior );
		return textureBicubic( transmissionSamplerMap, fragCoord.xy, lod );
	}
	vec3 volumeAttenuation( const in float transmissionDistance, const in vec3 attenuationColor, const in float attenuationDistance ) {
		if ( isinf( attenuationDistance ) ) {
			return vec3( 1.0 );
		} else {
			vec3 attenuationCoefficient = -log( attenuationColor ) / attenuationDistance;
			vec3 transmittance = exp( - attenuationCoefficient * transmissionDistance );			return transmittance;
		}
	}
	vec4 getIBLVolumeRefraction( const in vec3 n, const in vec3 v, const in float roughness, const in vec3 diffuseColor,
		const in vec3 specularColor, const in float specularF90, const in vec3 position, const in mat4 modelMatrix,
		const in mat4 viewMatrix, const in mat4 projMatrix, const in float dispersion, const in float ior, const in float thickness,
		const in vec3 attenuationColor, const in float attenuationDistance ) {
		vec4 transmittedLight;
		vec3 transmittance;
		#ifdef USE_DISPERSION
			float halfSpread = ( ior - 1.0 ) * 0.025 * dispersion;
			vec3 iors = vec3( ior - halfSpread, ior, ior + halfSpread );
			for ( int i = 0; i < 3; i ++ ) {
				vec3 transmissionRay = getVolumeTransmissionRay( n, v, thickness, iors[ i ], modelMatrix );
				vec3 refractedRayExit = position + transmissionRay;
				vec4 ndcPos = projMatrix * viewMatrix * vec4( refractedRayExit, 1.0 );
				vec2 refractionCoords = ndcPos.xy / ndcPos.w;
				refractionCoords += 1.0;
				refractionCoords /= 2.0;
				vec4 transmissionSample = getTransmissionSample( refractionCoords, roughness, iors[ i ] );
				transmittedLight[ i ] = transmissionSample[ i ];
				transmittedLight.a += transmissionSample.a;
				transmittance[ i ] = diffuseColor[ i ] * volumeAttenuation( length( transmissionRay ), attenuationColor, attenuationDistance )[ i ];
			}
			transmittedLight.a /= 3.0;
		#else
			vec3 transmissionRay = getVolumeTransmissionRay( n, v, thickness, ior, modelMatrix );
			vec3 refractedRayExit = position + transmissionRay;
			vec4 ndcPos = projMatrix * viewMatrix * vec4( refractedRayExit, 1.0 );
			vec2 refractionCoords = ndcPos.xy / ndcPos.w;
			refractionCoords += 1.0;
			refractionCoords /= 2.0;
			transmittedLight = getTransmissionSample( refractionCoords, roughness, ior );
			transmittance = diffuseColor * volumeAttenuation( length( transmissionRay ), attenuationColor, attenuationDistance );
		#endif
		vec3 attenuatedColor = transmittance * transmittedLight.rgb;
		vec3 F = EnvironmentBRDF( n, v, specularColor, specularF90, roughness );
		float transmittanceFactor = ( transmittance.r + transmittance.g + transmittance.b ) / 3.0;
		return vec4( ( 1.0 - F ) * attenuatedColor, 1.0 - ( 1.0 - transmittedLight.a ) * transmittanceFactor );
	}
#endif`,Ub=`#if defined( USE_UV ) || defined( USE_ANISOTROPY )
	varying vec2 vUv;
#endif
#ifdef USE_MAP
	varying vec2 vMapUv;
#endif
#ifdef USE_ALPHAMAP
	varying vec2 vAlphaMapUv;
#endif
#ifdef USE_LIGHTMAP
	varying vec2 vLightMapUv;
#endif
#ifdef USE_AOMAP
	varying vec2 vAoMapUv;
#endif
#ifdef USE_BUMPMAP
	varying vec2 vBumpMapUv;
#endif
#ifdef USE_NORMALMAP
	varying vec2 vNormalMapUv;
#endif
#ifdef USE_EMISSIVEMAP
	varying vec2 vEmissiveMapUv;
#endif
#ifdef USE_METALNESSMAP
	varying vec2 vMetalnessMapUv;
#endif
#ifdef USE_ROUGHNESSMAP
	varying vec2 vRoughnessMapUv;
#endif
#ifdef USE_ANISOTROPYMAP
	varying vec2 vAnisotropyMapUv;
#endif
#ifdef USE_CLEARCOATMAP
	varying vec2 vClearcoatMapUv;
#endif
#ifdef USE_CLEARCOAT_NORMALMAP
	varying vec2 vClearcoatNormalMapUv;
#endif
#ifdef USE_CLEARCOAT_ROUGHNESSMAP
	varying vec2 vClearcoatRoughnessMapUv;
#endif
#ifdef USE_IRIDESCENCEMAP
	varying vec2 vIridescenceMapUv;
#endif
#ifdef USE_IRIDESCENCE_THICKNESSMAP
	varying vec2 vIridescenceThicknessMapUv;
#endif
#ifdef USE_SHEEN_COLORMAP
	varying vec2 vSheenColorMapUv;
#endif
#ifdef USE_SHEEN_ROUGHNESSMAP
	varying vec2 vSheenRoughnessMapUv;
#endif
#ifdef USE_SPECULARMAP
	varying vec2 vSpecularMapUv;
#endif
#ifdef USE_SPECULAR_COLORMAP
	varying vec2 vSpecularColorMapUv;
#endif
#ifdef USE_SPECULAR_INTENSITYMAP
	varying vec2 vSpecularIntensityMapUv;
#endif
#ifdef USE_TRANSMISSIONMAP
	uniform mat3 transmissionMapTransform;
	varying vec2 vTransmissionMapUv;
#endif
#ifdef USE_THICKNESSMAP
	uniform mat3 thicknessMapTransform;
	varying vec2 vThicknessMapUv;
#endif`,Lb=`#if defined( USE_UV ) || defined( USE_ANISOTROPY )
	varying vec2 vUv;
#endif
#ifdef USE_MAP
	uniform mat3 mapTransform;
	varying vec2 vMapUv;
#endif
#ifdef USE_ALPHAMAP
	uniform mat3 alphaMapTransform;
	varying vec2 vAlphaMapUv;
#endif
#ifdef USE_LIGHTMAP
	uniform mat3 lightMapTransform;
	varying vec2 vLightMapUv;
#endif
#ifdef USE_AOMAP
	uniform mat3 aoMapTransform;
	varying vec2 vAoMapUv;
#endif
#ifdef USE_BUMPMAP
	uniform mat3 bumpMapTransform;
	varying vec2 vBumpMapUv;
#endif
#ifdef USE_NORMALMAP
	uniform mat3 normalMapTransform;
	varying vec2 vNormalMapUv;
#endif
#ifdef USE_DISPLACEMENTMAP
	uniform mat3 displacementMapTransform;
	varying vec2 vDisplacementMapUv;
#endif
#ifdef USE_EMISSIVEMAP
	uniform mat3 emissiveMapTransform;
	varying vec2 vEmissiveMapUv;
#endif
#ifdef USE_METALNESSMAP
	uniform mat3 metalnessMapTransform;
	varying vec2 vMetalnessMapUv;
#endif
#ifdef USE_ROUGHNESSMAP
	uniform mat3 roughnessMapTransform;
	varying vec2 vRoughnessMapUv;
#endif
#ifdef USE_ANISOTROPYMAP
	uniform mat3 anisotropyMapTransform;
	varying vec2 vAnisotropyMapUv;
#endif
#ifdef USE_CLEARCOATMAP
	uniform mat3 clearcoatMapTransform;
	varying vec2 vClearcoatMapUv;
#endif
#ifdef USE_CLEARCOAT_NORMALMAP
	uniform mat3 clearcoatNormalMapTransform;
	varying vec2 vClearcoatNormalMapUv;
#endif
#ifdef USE_CLEARCOAT_ROUGHNESSMAP
	uniform mat3 clearcoatRoughnessMapTransform;
	varying vec2 vClearcoatRoughnessMapUv;
#endif
#ifdef USE_SHEEN_COLORMAP
	uniform mat3 sheenColorMapTransform;
	varying vec2 vSheenColorMapUv;
#endif
#ifdef USE_SHEEN_ROUGHNESSMAP
	uniform mat3 sheenRoughnessMapTransform;
	varying vec2 vSheenRoughnessMapUv;
#endif
#ifdef USE_IRIDESCENCEMAP
	uniform mat3 iridescenceMapTransform;
	varying vec2 vIridescenceMapUv;
#endif
#ifdef USE_IRIDESCENCE_THICKNESSMAP
	uniform mat3 iridescenceThicknessMapTransform;
	varying vec2 vIridescenceThicknessMapUv;
#endif
#ifdef USE_SPECULARMAP
	uniform mat3 specularMapTransform;
	varying vec2 vSpecularMapUv;
#endif
#ifdef USE_SPECULAR_COLORMAP
	uniform mat3 specularColorMapTransform;
	varying vec2 vSpecularColorMapUv;
#endif
#ifdef USE_SPECULAR_INTENSITYMAP
	uniform mat3 specularIntensityMapTransform;
	varying vec2 vSpecularIntensityMapUv;
#endif
#ifdef USE_TRANSMISSIONMAP
	uniform mat3 transmissionMapTransform;
	varying vec2 vTransmissionMapUv;
#endif
#ifdef USE_THICKNESSMAP
	uniform mat3 thicknessMapTransform;
	varying vec2 vThicknessMapUv;
#endif`,Ob=`#if defined( USE_UV ) || defined( USE_ANISOTROPY )
	vUv = vec3( uv, 1 ).xy;
#endif
#ifdef USE_MAP
	vMapUv = ( mapTransform * vec3( MAP_UV, 1 ) ).xy;
#endif
#ifdef USE_ALPHAMAP
	vAlphaMapUv = ( alphaMapTransform * vec3( ALPHAMAP_UV, 1 ) ).xy;
#endif
#ifdef USE_LIGHTMAP
	vLightMapUv = ( lightMapTransform * vec3( LIGHTMAP_UV, 1 ) ).xy;
#endif
#ifdef USE_AOMAP
	vAoMapUv = ( aoMapTransform * vec3( AOMAP_UV, 1 ) ).xy;
#endif
#ifdef USE_BUMPMAP
	vBumpMapUv = ( bumpMapTransform * vec3( BUMPMAP_UV, 1 ) ).xy;
#endif
#ifdef USE_NORMALMAP
	vNormalMapUv = ( normalMapTransform * vec3( NORMALMAP_UV, 1 ) ).xy;
#endif
#ifdef USE_DISPLACEMENTMAP
	vDisplacementMapUv = ( displacementMapTransform * vec3( DISPLACEMENTMAP_UV, 1 ) ).xy;
#endif
#ifdef USE_EMISSIVEMAP
	vEmissiveMapUv = ( emissiveMapTransform * vec3( EMISSIVEMAP_UV, 1 ) ).xy;
#endif
#ifdef USE_METALNESSMAP
	vMetalnessMapUv = ( metalnessMapTransform * vec3( METALNESSMAP_UV, 1 ) ).xy;
#endif
#ifdef USE_ROUGHNESSMAP
	vRoughnessMapUv = ( roughnessMapTransform * vec3( ROUGHNESSMAP_UV, 1 ) ).xy;
#endif
#ifdef USE_ANISOTROPYMAP
	vAnisotropyMapUv = ( anisotropyMapTransform * vec3( ANISOTROPYMAP_UV, 1 ) ).xy;
#endif
#ifdef USE_CLEARCOATMAP
	vClearcoatMapUv = ( clearcoatMapTransform * vec3( CLEARCOATMAP_UV, 1 ) ).xy;
#endif
#ifdef USE_CLEARCOAT_NORMALMAP
	vClearcoatNormalMapUv = ( clearcoatNormalMapTransform * vec3( CLEARCOAT_NORMALMAP_UV, 1 ) ).xy;
#endif
#ifdef USE_CLEARCOAT_ROUGHNESSMAP
	vClearcoatRoughnessMapUv = ( clearcoatRoughnessMapTransform * vec3( CLEARCOAT_ROUGHNESSMAP_UV, 1 ) ).xy;
#endif
#ifdef USE_IRIDESCENCEMAP
	vIridescenceMapUv = ( iridescenceMapTransform * vec3( IRIDESCENCEMAP_UV, 1 ) ).xy;
#endif
#ifdef USE_IRIDESCENCE_THICKNESSMAP
	vIridescenceThicknessMapUv = ( iridescenceThicknessMapTransform * vec3( IRIDESCENCE_THICKNESSMAP_UV, 1 ) ).xy;
#endif
#ifdef USE_SHEEN_COLORMAP
	vSheenColorMapUv = ( sheenColorMapTransform * vec3( SHEEN_COLORMAP_UV, 1 ) ).xy;
#endif
#ifdef USE_SHEEN_ROUGHNESSMAP
	vSheenRoughnessMapUv = ( sheenRoughnessMapTransform * vec3( SHEEN_ROUGHNESSMAP_UV, 1 ) ).xy;
#endif
#ifdef USE_SPECULARMAP
	vSpecularMapUv = ( specularMapTransform * vec3( SPECULARMAP_UV, 1 ) ).xy;
#endif
#ifdef USE_SPECULAR_COLORMAP
	vSpecularColorMapUv = ( specularColorMapTransform * vec3( SPECULAR_COLORMAP_UV, 1 ) ).xy;
#endif
#ifdef USE_SPECULAR_INTENSITYMAP
	vSpecularIntensityMapUv = ( specularIntensityMapTransform * vec3( SPECULAR_INTENSITYMAP_UV, 1 ) ).xy;
#endif
#ifdef USE_TRANSMISSIONMAP
	vTransmissionMapUv = ( transmissionMapTransform * vec3( TRANSMISSIONMAP_UV, 1 ) ).xy;
#endif
#ifdef USE_THICKNESSMAP
	vThicknessMapUv = ( thicknessMapTransform * vec3( THICKNESSMAP_UV, 1 ) ).xy;
#endif`,Pb=`#if defined( USE_ENVMAP ) || defined( DISTANCE ) || defined ( USE_SHADOWMAP ) || defined ( USE_TRANSMISSION ) || NUM_SPOT_LIGHT_COORDS > 0
	vec4 worldPosition = vec4( transformed, 1.0 );
	#ifdef USE_BATCHING
		worldPosition = batchingMatrix * worldPosition;
	#endif
	#ifdef USE_INSTANCING
		worldPosition = instanceMatrix * worldPosition;
	#endif
	worldPosition = modelMatrix * worldPosition;
#endif`;const Ib=`varying vec2 vUv;
uniform mat3 uvTransform;
void main() {
	vUv = ( uvTransform * vec3( uv, 1 ) ).xy;
	gl_Position = vec4( position.xy, 1.0, 1.0 );
}`,zb=`uniform sampler2D t2D;
uniform float backgroundIntensity;
varying vec2 vUv;
void main() {
	vec4 texColor = texture2D( t2D, vUv );
	#ifdef DECODE_VIDEO_TEXTURE
		texColor = vec4( mix( pow( texColor.rgb * 0.9478672986 + vec3( 0.0521327014 ), vec3( 2.4 ) ), texColor.rgb * 0.0773993808, vec3( lessThanEqual( texColor.rgb, vec3( 0.04045 ) ) ) ), texColor.w );
	#endif
	texColor.rgb *= backgroundIntensity;
	gl_FragColor = texColor;
	#include <tonemapping_fragment>
	#include <colorspace_fragment>
}`,Fb=`varying vec3 vWorldDirection;
#include <common>
void main() {
	vWorldDirection = transformDirection( position, modelMatrix );
	#include <begin_vertex>
	#include <project_vertex>
	gl_Position.z = gl_Position.w;
}`,Bb=`#ifdef ENVMAP_TYPE_CUBE
	uniform samplerCube envMap;
#elif defined( ENVMAP_TYPE_CUBE_UV )
	uniform sampler2D envMap;
#endif
uniform float backgroundBlurriness;
uniform float backgroundIntensity;
uniform mat3 backgroundRotation;
varying vec3 vWorldDirection;
#include <cube_uv_reflection_fragment>
void main() {
	#ifdef ENVMAP_TYPE_CUBE
		vec4 texColor = textureCube( envMap, backgroundRotation * vWorldDirection );
	#elif defined( ENVMAP_TYPE_CUBE_UV )
		vec4 texColor = textureCubeUV( envMap, backgroundRotation * vWorldDirection, backgroundBlurriness );
	#else
		vec4 texColor = vec4( 0.0, 0.0, 0.0, 1.0 );
	#endif
	texColor.rgb *= backgroundIntensity;
	gl_FragColor = texColor;
	#include <tonemapping_fragment>
	#include <colorspace_fragment>
}`,Hb=`varying vec3 vWorldDirection;
#include <common>
void main() {
	vWorldDirection = transformDirection( position, modelMatrix );
	#include <begin_vertex>
	#include <project_vertex>
	gl_Position.z = gl_Position.w;
}`,Gb=`uniform samplerCube tCube;
uniform float tFlip;
uniform float opacity;
varying vec3 vWorldDirection;
void main() {
	vec4 texColor = textureCube( tCube, vec3( tFlip * vWorldDirection.x, vWorldDirection.yz ) );
	gl_FragColor = texColor;
	gl_FragColor.a *= opacity;
	#include <tonemapping_fragment>
	#include <colorspace_fragment>
}`,Vb=`#include <common>
#include <batching_pars_vertex>
#include <uv_pars_vertex>
#include <displacementmap_pars_vertex>
#include <morphtarget_pars_vertex>
#include <skinning_pars_vertex>
#include <logdepthbuf_pars_vertex>
#include <clipping_planes_pars_vertex>
varying vec2 vHighPrecisionZW;
void main() {
	#include <uv_vertex>
	#include <batching_vertex>
	#include <skinbase_vertex>
	#include <morphinstance_vertex>
	#ifdef USE_DISPLACEMENTMAP
		#include <beginnormal_vertex>
		#include <morphnormal_vertex>
		#include <skinnormal_vertex>
	#endif
	#include <begin_vertex>
	#include <morphtarget_vertex>
	#include <skinning_vertex>
	#include <displacementmap_vertex>
	#include <project_vertex>
	#include <logdepthbuf_vertex>
	#include <clipping_planes_vertex>
	vHighPrecisionZW = gl_Position.zw;
}`,kb=`#if DEPTH_PACKING == 3200
	uniform float opacity;
#endif
#include <common>
#include <packing>
#include <uv_pars_fragment>
#include <map_pars_fragment>
#include <alphamap_pars_fragment>
#include <alphatest_pars_fragment>
#include <alphahash_pars_fragment>
#include <logdepthbuf_pars_fragment>
#include <clipping_planes_pars_fragment>
varying vec2 vHighPrecisionZW;
void main() {
	vec4 diffuseColor = vec4( 1.0 );
	#include <clipping_planes_fragment>
	#if DEPTH_PACKING == 3200
		diffuseColor.a = opacity;
	#endif
	#include <map_fragment>
	#include <alphamap_fragment>
	#include <alphatest_fragment>
	#include <alphahash_fragment>
	#include <logdepthbuf_fragment>
	#ifdef USE_REVERSED_DEPTH_BUFFER
		float fragCoordZ = vHighPrecisionZW[ 0 ] / vHighPrecisionZW[ 1 ];
	#else
		float fragCoordZ = 0.5 * vHighPrecisionZW[ 0 ] / vHighPrecisionZW[ 1 ] + 0.5;
	#endif
	#if DEPTH_PACKING == 3200
		gl_FragColor = vec4( vec3( 1.0 - fragCoordZ ), opacity );
	#elif DEPTH_PACKING == 3201
		gl_FragColor = packDepthToRGBA( fragCoordZ );
	#elif DEPTH_PACKING == 3202
		gl_FragColor = vec4( packDepthToRGB( fragCoordZ ), 1.0 );
	#elif DEPTH_PACKING == 3203
		gl_FragColor = vec4( packDepthToRG( fragCoordZ ), 0.0, 1.0 );
	#endif
}`,Xb=`#define DISTANCE
varying vec3 vWorldPosition;
#include <common>
#include <batching_pars_vertex>
#include <uv_pars_vertex>
#include <displacementmap_pars_vertex>
#include <morphtarget_pars_vertex>
#include <skinning_pars_vertex>
#include <clipping_planes_pars_vertex>
void main() {
	#include <uv_vertex>
	#include <batching_vertex>
	#include <skinbase_vertex>
	#include <morphinstance_vertex>
	#ifdef USE_DISPLACEMENTMAP
		#include <beginnormal_vertex>
		#include <morphnormal_vertex>
		#include <skinnormal_vertex>
	#endif
	#include <begin_vertex>
	#include <morphtarget_vertex>
	#include <skinning_vertex>
	#include <displacementmap_vertex>
	#include <project_vertex>
	#include <worldpos_vertex>
	#include <clipping_planes_vertex>
	vWorldPosition = worldPosition.xyz;
}`,Wb=`#define DISTANCE
uniform vec3 referencePosition;
uniform float nearDistance;
uniform float farDistance;
varying vec3 vWorldPosition;
#include <common>
#include <uv_pars_fragment>
#include <map_pars_fragment>
#include <alphamap_pars_fragment>
#include <alphatest_pars_fragment>
#include <alphahash_pars_fragment>
#include <clipping_planes_pars_fragment>
void main() {
	vec4 diffuseColor = vec4( 1.0 );
	#include <clipping_planes_fragment>
	#include <map_fragment>
	#include <alphamap_fragment>
	#include <alphatest_fragment>
	#include <alphahash_fragment>
	float dist = length( vWorldPosition - referencePosition );
	dist = ( dist - nearDistance ) / ( farDistance - nearDistance );
	dist = saturate( dist );
	gl_FragColor = vec4( dist, 0.0, 0.0, 1.0 );
}`,qb=`varying vec3 vWorldDirection;
#include <common>
void main() {
	vWorldDirection = transformDirection( position, modelMatrix );
	#include <begin_vertex>
	#include <project_vertex>
}`,Yb=`uniform sampler2D tEquirect;
varying vec3 vWorldDirection;
#include <common>
void main() {
	vec3 direction = normalize( vWorldDirection );
	vec2 sampleUV = equirectUv( direction );
	gl_FragColor = texture2D( tEquirect, sampleUV );
	#include <tonemapping_fragment>
	#include <colorspace_fragment>
}`,Zb=`uniform float scale;
attribute float lineDistance;
varying float vLineDistance;
#include <common>
#include <uv_pars_vertex>
#include <color_pars_vertex>
#include <fog_pars_vertex>
#include <morphtarget_pars_vertex>
#include <logdepthbuf_pars_vertex>
#include <clipping_planes_pars_vertex>
void main() {
	vLineDistance = scale * lineDistance;
	#include <uv_vertex>
	#include <color_vertex>
	#include <morphinstance_vertex>
	#include <morphcolor_vertex>
	#include <begin_vertex>
	#include <morphtarget_vertex>
	#include <project_vertex>
	#include <logdepthbuf_vertex>
	#include <clipping_planes_vertex>
	#include <fog_vertex>
}`,Kb=`uniform vec3 diffuse;
uniform float opacity;
uniform float dashSize;
uniform float totalSize;
varying float vLineDistance;
#include <common>
#include <color_pars_fragment>
#include <uv_pars_fragment>
#include <map_pars_fragment>
#include <fog_pars_fragment>
#include <logdepthbuf_pars_fragment>
#include <clipping_planes_pars_fragment>
void main() {
	vec4 diffuseColor = vec4( diffuse, opacity );
	#include <clipping_planes_fragment>
	if ( mod( vLineDistance, totalSize ) > dashSize ) {
		discard;
	}
	vec3 outgoingLight = vec3( 0.0 );
	#include <logdepthbuf_fragment>
	#include <map_fragment>
	#include <color_fragment>
	outgoingLight = diffuseColor.rgb;
	#include <opaque_fragment>
	#include <tonemapping_fragment>
	#include <colorspace_fragment>
	#include <fog_fragment>
	#include <premultiplied_alpha_fragment>
}`,jb=`#include <common>
#include <batching_pars_vertex>
#include <uv_pars_vertex>
#include <envmap_pars_vertex>
#include <color_pars_vertex>
#include <fog_pars_vertex>
#include <morphtarget_pars_vertex>
#include <skinning_pars_vertex>
#include <logdepthbuf_pars_vertex>
#include <clipping_planes_pars_vertex>
void main() {
	#include <uv_vertex>
	#include <color_vertex>
	#include <morphinstance_vertex>
	#include <morphcolor_vertex>
	#include <batching_vertex>
	#if defined ( USE_ENVMAP ) || defined ( USE_SKINNING )
		#include <beginnormal_vertex>
		#include <morphnormal_vertex>
		#include <skinbase_vertex>
		#include <skinnormal_vertex>
		#include <defaultnormal_vertex>
	#endif
	#include <begin_vertex>
	#include <morphtarget_vertex>
	#include <skinning_vertex>
	#include <project_vertex>
	#include <logdepthbuf_vertex>
	#include <clipping_planes_vertex>
	#include <worldpos_vertex>
	#include <envmap_vertex>
	#include <fog_vertex>
}`,Jb=`uniform vec3 diffuse;
uniform float opacity;
#ifndef FLAT_SHADED
	varying vec3 vNormal;
#endif
#include <common>
#include <dithering_pars_fragment>
#include <color_pars_fragment>
#include <uv_pars_fragment>
#include <map_pars_fragment>
#include <alphamap_pars_fragment>
#include <alphatest_pars_fragment>
#include <alphahash_pars_fragment>
#include <aomap_pars_fragment>
#include <lightmap_pars_fragment>
#include <envmap_common_pars_fragment>
#include <envmap_pars_fragment>
#include <fog_pars_fragment>
#include <specularmap_pars_fragment>
#include <logdepthbuf_pars_fragment>
#include <clipping_planes_pars_fragment>
void main() {
	vec4 diffuseColor = vec4( diffuse, opacity );
	#include <clipping_planes_fragment>
	#include <logdepthbuf_fragment>
	#include <map_fragment>
	#include <color_fragment>
	#include <alphamap_fragment>
	#include <alphatest_fragment>
	#include <alphahash_fragment>
	#include <specularmap_fragment>
	ReflectedLight reflectedLight = ReflectedLight( vec3( 0.0 ), vec3( 0.0 ), vec3( 0.0 ), vec3( 0.0 ) );
	#ifdef USE_LIGHTMAP
		vec4 lightMapTexel = texture2D( lightMap, vLightMapUv );
		reflectedLight.indirectDiffuse += lightMapTexel.rgb * lightMapIntensity * RECIPROCAL_PI;
	#else
		reflectedLight.indirectDiffuse += vec3( 1.0 );
	#endif
	#include <aomap_fragment>
	reflectedLight.indirectDiffuse *= diffuseColor.rgb;
	vec3 outgoingLight = reflectedLight.indirectDiffuse;
	#include <envmap_fragment>
	#include <opaque_fragment>
	#include <tonemapping_fragment>
	#include <colorspace_fragment>
	#include <fog_fragment>
	#include <premultiplied_alpha_fragment>
	#include <dithering_fragment>
}`,Qb=`#define LAMBERT
varying vec3 vViewPosition;
#include <common>
#include <batching_pars_vertex>
#include <uv_pars_vertex>
#include <displacementmap_pars_vertex>
#include <envmap_pars_vertex>
#include <color_pars_vertex>
#include <fog_pars_vertex>
#include <normal_pars_vertex>
#include <morphtarget_pars_vertex>
#include <skinning_pars_vertex>
#include <shadowmap_pars_vertex>
#include <logdepthbuf_pars_vertex>
#include <clipping_planes_pars_vertex>
void main() {
	#include <uv_vertex>
	#include <color_vertex>
	#include <morphinstance_vertex>
	#include <morphcolor_vertex>
	#include <batching_vertex>
	#include <beginnormal_vertex>
	#include <morphnormal_vertex>
	#include <skinbase_vertex>
	#include <skinnormal_vertex>
	#include <defaultnormal_vertex>
	#include <normal_vertex>
	#include <begin_vertex>
	#include <morphtarget_vertex>
	#include <skinning_vertex>
	#include <displacementmap_vertex>
	#include <project_vertex>
	#include <logdepthbuf_vertex>
	#include <clipping_planes_vertex>
	vViewPosition = - mvPosition.xyz;
	#include <worldpos_vertex>
	#include <envmap_vertex>
	#include <shadowmap_vertex>
	#include <fog_vertex>
}`,$b=`#define LAMBERT
uniform vec3 diffuse;
uniform vec3 emissive;
uniform float opacity;
#include <common>
#include <dithering_pars_fragment>
#include <color_pars_fragment>
#include <uv_pars_fragment>
#include <map_pars_fragment>
#include <alphamap_pars_fragment>
#include <alphatest_pars_fragment>
#include <alphahash_pars_fragment>
#include <aomap_pars_fragment>
#include <lightmap_pars_fragment>
#include <emissivemap_pars_fragment>
#include <cube_uv_reflection_fragment>
#include <envmap_common_pars_fragment>
#include <envmap_pars_fragment>
#include <envmap_physical_pars_fragment>
#include <fog_pars_fragment>
#include <bsdfs>
#include <lights_pars_begin>
#include <normal_pars_fragment>
#include <lights_lambert_pars_fragment>
#include <shadowmap_pars_fragment>
#include <bumpmap_pars_fragment>
#include <normalmap_pars_fragment>
#include <specularmap_pars_fragment>
#include <logdepthbuf_pars_fragment>
#include <clipping_planes_pars_fragment>
void main() {
	vec4 diffuseColor = vec4( diffuse, opacity );
	#include <clipping_planes_fragment>
	ReflectedLight reflectedLight = ReflectedLight( vec3( 0.0 ), vec3( 0.0 ), vec3( 0.0 ), vec3( 0.0 ) );
	vec3 totalEmissiveRadiance = emissive;
	#include <logdepthbuf_fragment>
	#include <map_fragment>
	#include <color_fragment>
	#include <alphamap_fragment>
	#include <alphatest_fragment>
	#include <alphahash_fragment>
	#include <specularmap_fragment>
	#include <normal_fragment_begin>
	#include <normal_fragment_maps>
	#include <emissivemap_fragment>
	#include <lights_lambert_fragment>
	#include <lights_fragment_begin>
	#include <lights_fragment_maps>
	#include <lights_fragment_end>
	#include <aomap_fragment>
	vec3 outgoingLight = reflectedLight.directDiffuse + reflectedLight.indirectDiffuse + totalEmissiveRadiance;
	#include <envmap_fragment>
	#include <opaque_fragment>
	#include <tonemapping_fragment>
	#include <colorspace_fragment>
	#include <fog_fragment>
	#include <premultiplied_alpha_fragment>
	#include <dithering_fragment>
}`,tT=`#define MATCAP
varying vec3 vViewPosition;
#include <common>
#include <batching_pars_vertex>
#include <uv_pars_vertex>
#include <color_pars_vertex>
#include <displacementmap_pars_vertex>
#include <fog_pars_vertex>
#include <normal_pars_vertex>
#include <morphtarget_pars_vertex>
#include <skinning_pars_vertex>
#include <logdepthbuf_pars_vertex>
#include <clipping_planes_pars_vertex>
void main() {
	#include <uv_vertex>
	#include <color_vertex>
	#include <morphinstance_vertex>
	#include <morphcolor_vertex>
	#include <batching_vertex>
	#include <beginnormal_vertex>
	#include <morphnormal_vertex>
	#include <skinbase_vertex>
	#include <skinnormal_vertex>
	#include <defaultnormal_vertex>
	#include <normal_vertex>
	#include <begin_vertex>
	#include <morphtarget_vertex>
	#include <skinning_vertex>
	#include <displacementmap_vertex>
	#include <project_vertex>
	#include <logdepthbuf_vertex>
	#include <clipping_planes_vertex>
	#include <fog_vertex>
	vViewPosition = - mvPosition.xyz;
}`,eT=`#define MATCAP
uniform vec3 diffuse;
uniform float opacity;
uniform sampler2D matcap;
varying vec3 vViewPosition;
#include <common>
#include <dithering_pars_fragment>
#include <color_pars_fragment>
#include <uv_pars_fragment>
#include <map_pars_fragment>
#include <alphamap_pars_fragment>
#include <alphatest_pars_fragment>
#include <alphahash_pars_fragment>
#include <fog_pars_fragment>
#include <normal_pars_fragment>
#include <bumpmap_pars_fragment>
#include <normalmap_pars_fragment>
#include <logdepthbuf_pars_fragment>
#include <clipping_planes_pars_fragment>
void main() {
	vec4 diffuseColor = vec4( diffuse, opacity );
	#include <clipping_planes_fragment>
	#include <logdepthbuf_fragment>
	#include <map_fragment>
	#include <color_fragment>
	#include <alphamap_fragment>
	#include <alphatest_fragment>
	#include <alphahash_fragment>
	#include <normal_fragment_begin>
	#include <normal_fragment_maps>
	vec3 viewDir = normalize( vViewPosition );
	vec3 x = normalize( vec3( viewDir.z, 0.0, - viewDir.x ) );
	vec3 y = cross( viewDir, x );
	vec2 uv = vec2( dot( x, normal ), dot( y, normal ) ) * 0.495 + 0.5;
	#ifdef USE_MATCAP
		vec4 matcapColor = texture2D( matcap, uv );
	#else
		vec4 matcapColor = vec4( vec3( mix( 0.2, 0.8, uv.y ) ), 1.0 );
	#endif
	vec3 outgoingLight = diffuseColor.rgb * matcapColor.rgb;
	#include <opaque_fragment>
	#include <tonemapping_fragment>
	#include <colorspace_fragment>
	#include <fog_fragment>
	#include <premultiplied_alpha_fragment>
	#include <dithering_fragment>
}`,nT=`#define NORMAL
#if defined( FLAT_SHADED ) || defined( USE_BUMPMAP ) || defined( USE_NORMALMAP_TANGENTSPACE )
	varying vec3 vViewPosition;
#endif
#include <common>
#include <batching_pars_vertex>
#include <uv_pars_vertex>
#include <displacementmap_pars_vertex>
#include <normal_pars_vertex>
#include <morphtarget_pars_vertex>
#include <skinning_pars_vertex>
#include <logdepthbuf_pars_vertex>
#include <clipping_planes_pars_vertex>
void main() {
	#include <uv_vertex>
	#include <batching_vertex>
	#include <beginnormal_vertex>
	#include <morphinstance_vertex>
	#include <morphnormal_vertex>
	#include <skinbase_vertex>
	#include <skinnormal_vertex>
	#include <defaultnormal_vertex>
	#include <normal_vertex>
	#include <begin_vertex>
	#include <morphtarget_vertex>
	#include <skinning_vertex>
	#include <displacementmap_vertex>
	#include <project_vertex>
	#include <logdepthbuf_vertex>
	#include <clipping_planes_vertex>
#if defined( FLAT_SHADED ) || defined( USE_BUMPMAP ) || defined( USE_NORMALMAP_TANGENTSPACE )
	vViewPosition = - mvPosition.xyz;
#endif
}`,iT=`#define NORMAL
uniform float opacity;
#if defined( FLAT_SHADED ) || defined( USE_BUMPMAP ) || defined( USE_NORMALMAP_TANGENTSPACE )
	varying vec3 vViewPosition;
#endif
#include <uv_pars_fragment>
#include <normal_pars_fragment>
#include <bumpmap_pars_fragment>
#include <normalmap_pars_fragment>
#include <logdepthbuf_pars_fragment>
#include <clipping_planes_pars_fragment>
void main() {
	vec4 diffuseColor = vec4( 0.0, 0.0, 0.0, opacity );
	#include <clipping_planes_fragment>
	#include <logdepthbuf_fragment>
	#include <normal_fragment_begin>
	#include <normal_fragment_maps>
	gl_FragColor = vec4( normalize( normal ) * 0.5 + 0.5, diffuseColor.a );
	#ifdef OPAQUE
		gl_FragColor.a = 1.0;
	#endif
}`,aT=`#define PHONG
varying vec3 vViewPosition;
#include <common>
#include <batching_pars_vertex>
#include <uv_pars_vertex>
#include <displacementmap_pars_vertex>
#include <envmap_pars_vertex>
#include <color_pars_vertex>
#include <fog_pars_vertex>
#include <normal_pars_vertex>
#include <morphtarget_pars_vertex>
#include <skinning_pars_vertex>
#include <shadowmap_pars_vertex>
#include <logdepthbuf_pars_vertex>
#include <clipping_planes_pars_vertex>
void main() {
	#include <uv_vertex>
	#include <color_vertex>
	#include <morphcolor_vertex>
	#include <batching_vertex>
	#include <beginnormal_vertex>
	#include <morphinstance_vertex>
	#include <morphnormal_vertex>
	#include <skinbase_vertex>
	#include <skinnormal_vertex>
	#include <defaultnormal_vertex>
	#include <normal_vertex>
	#include <begin_vertex>
	#include <morphtarget_vertex>
	#include <skinning_vertex>
	#include <displacementmap_vertex>
	#include <project_vertex>
	#include <logdepthbuf_vertex>
	#include <clipping_planes_vertex>
	vViewPosition = - mvPosition.xyz;
	#include <worldpos_vertex>
	#include <envmap_vertex>
	#include <shadowmap_vertex>
	#include <fog_vertex>
}`,sT=`#define PHONG
uniform vec3 diffuse;
uniform vec3 emissive;
uniform vec3 specular;
uniform float shininess;
uniform float opacity;
#include <common>
#include <dithering_pars_fragment>
#include <color_pars_fragment>
#include <uv_pars_fragment>
#include <map_pars_fragment>
#include <alphamap_pars_fragment>
#include <alphatest_pars_fragment>
#include <alphahash_pars_fragment>
#include <aomap_pars_fragment>
#include <lightmap_pars_fragment>
#include <emissivemap_pars_fragment>
#include <cube_uv_reflection_fragment>
#include <envmap_common_pars_fragment>
#include <envmap_pars_fragment>
#include <envmap_physical_pars_fragment>
#include <fog_pars_fragment>
#include <bsdfs>
#include <lights_pars_begin>
#include <normal_pars_fragment>
#include <lights_phong_pars_fragment>
#include <shadowmap_pars_fragment>
#include <bumpmap_pars_fragment>
#include <normalmap_pars_fragment>
#include <specularmap_pars_fragment>
#include <logdepthbuf_pars_fragment>
#include <clipping_planes_pars_fragment>
void main() {
	vec4 diffuseColor = vec4( diffuse, opacity );
	#include <clipping_planes_fragment>
	ReflectedLight reflectedLight = ReflectedLight( vec3( 0.0 ), vec3( 0.0 ), vec3( 0.0 ), vec3( 0.0 ) );
	vec3 totalEmissiveRadiance = emissive;
	#include <logdepthbuf_fragment>
	#include <map_fragment>
	#include <color_fragment>
	#include <alphamap_fragment>
	#include <alphatest_fragment>
	#include <alphahash_fragment>
	#include <specularmap_fragment>
	#include <normal_fragment_begin>
	#include <normal_fragment_maps>
	#include <emissivemap_fragment>
	#include <lights_phong_fragment>
	#include <lights_fragment_begin>
	#include <lights_fragment_maps>
	#include <lights_fragment_end>
	#include <aomap_fragment>
	vec3 outgoingLight = reflectedLight.directDiffuse + reflectedLight.indirectDiffuse + reflectedLight.directSpecular + reflectedLight.indirectSpecular + totalEmissiveRadiance;
	#include <envmap_fragment>
	#include <opaque_fragment>
	#include <tonemapping_fragment>
	#include <colorspace_fragment>
	#include <fog_fragment>
	#include <premultiplied_alpha_fragment>
	#include <dithering_fragment>
}`,rT=`#define STANDARD
varying vec3 vViewPosition;
#ifdef USE_TRANSMISSION
	varying vec3 vWorldPosition;
#endif
#include <common>
#include <batching_pars_vertex>
#include <uv_pars_vertex>
#include <displacementmap_pars_vertex>
#include <color_pars_vertex>
#include <fog_pars_vertex>
#include <normal_pars_vertex>
#include <morphtarget_pars_vertex>
#include <skinning_pars_vertex>
#include <shadowmap_pars_vertex>
#include <logdepthbuf_pars_vertex>
#include <clipping_planes_pars_vertex>
void main() {
	#include <uv_vertex>
	#include <color_vertex>
	#include <morphinstance_vertex>
	#include <morphcolor_vertex>
	#include <batching_vertex>
	#include <beginnormal_vertex>
	#include <morphnormal_vertex>
	#include <skinbase_vertex>
	#include <skinnormal_vertex>
	#include <defaultnormal_vertex>
	#include <normal_vertex>
	#include <begin_vertex>
	#include <morphtarget_vertex>
	#include <skinning_vertex>
	#include <displacementmap_vertex>
	#include <project_vertex>
	#include <logdepthbuf_vertex>
	#include <clipping_planes_vertex>
	vViewPosition = - mvPosition.xyz;
	#include <worldpos_vertex>
	#include <shadowmap_vertex>
	#include <fog_vertex>
#ifdef USE_TRANSMISSION
	vWorldPosition = worldPosition.xyz;
#endif
}`,oT=`#define STANDARD
#ifdef PHYSICAL
	#define IOR
	#define USE_SPECULAR
#endif
uniform vec3 diffuse;
uniform vec3 emissive;
uniform float roughness;
uniform float metalness;
uniform float opacity;
#ifdef IOR
	uniform float ior;
#endif
#ifdef USE_SPECULAR
	uniform float specularIntensity;
	uniform vec3 specularColor;
	#ifdef USE_SPECULAR_COLORMAP
		uniform sampler2D specularColorMap;
	#endif
	#ifdef USE_SPECULAR_INTENSITYMAP
		uniform sampler2D specularIntensityMap;
	#endif
#endif
#ifdef USE_CLEARCOAT
	uniform float clearcoat;
	uniform float clearcoatRoughness;
#endif
#ifdef USE_DISPERSION
	uniform float dispersion;
#endif
#ifdef USE_IRIDESCENCE
	uniform float iridescence;
	uniform float iridescenceIOR;
	uniform float iridescenceThicknessMinimum;
	uniform float iridescenceThicknessMaximum;
#endif
#ifdef USE_SHEEN
	uniform vec3 sheenColor;
	uniform float sheenRoughness;
	#ifdef USE_SHEEN_COLORMAP
		uniform sampler2D sheenColorMap;
	#endif
	#ifdef USE_SHEEN_ROUGHNESSMAP
		uniform sampler2D sheenRoughnessMap;
	#endif
#endif
#ifdef USE_ANISOTROPY
	uniform vec2 anisotropyVector;
	#ifdef USE_ANISOTROPYMAP
		uniform sampler2D anisotropyMap;
	#endif
#endif
varying vec3 vViewPosition;
#include <common>
#include <dithering_pars_fragment>
#include <color_pars_fragment>
#include <uv_pars_fragment>
#include <map_pars_fragment>
#include <alphamap_pars_fragment>
#include <alphatest_pars_fragment>
#include <alphahash_pars_fragment>
#include <aomap_pars_fragment>
#include <lightmap_pars_fragment>
#include <emissivemap_pars_fragment>
#include <iridescence_fragment>
#include <cube_uv_reflection_fragment>
#include <envmap_common_pars_fragment>
#include <envmap_physical_pars_fragment>
#include <fog_pars_fragment>
#include <lights_pars_begin>
#include <normal_pars_fragment>
#include <lights_physical_pars_fragment>
#include <transmission_pars_fragment>
#include <shadowmap_pars_fragment>
#include <bumpmap_pars_fragment>
#include <normalmap_pars_fragment>
#include <clearcoat_pars_fragment>
#include <iridescence_pars_fragment>
#include <roughnessmap_pars_fragment>
#include <metalnessmap_pars_fragment>
#include <logdepthbuf_pars_fragment>
#include <clipping_planes_pars_fragment>
void main() {
	vec4 diffuseColor = vec4( diffuse, opacity );
	#include <clipping_planes_fragment>
	ReflectedLight reflectedLight = ReflectedLight( vec3( 0.0 ), vec3( 0.0 ), vec3( 0.0 ), vec3( 0.0 ) );
	vec3 totalEmissiveRadiance = emissive;
	#include <logdepthbuf_fragment>
	#include <map_fragment>
	#include <color_fragment>
	#include <alphamap_fragment>
	#include <alphatest_fragment>
	#include <alphahash_fragment>
	#include <roughnessmap_fragment>
	#include <metalnessmap_fragment>
	#include <normal_fragment_begin>
	#include <normal_fragment_maps>
	#include <clearcoat_normal_fragment_begin>
	#include <clearcoat_normal_fragment_maps>
	#include <emissivemap_fragment>
	#include <lights_physical_fragment>
	#include <lights_fragment_begin>
	#include <lights_fragment_maps>
	#include <lights_fragment_end>
	#include <aomap_fragment>
	vec3 totalDiffuse = reflectedLight.directDiffuse + reflectedLight.indirectDiffuse;
	vec3 totalSpecular = reflectedLight.directSpecular + reflectedLight.indirectSpecular;
	#include <transmission_fragment>
	vec3 outgoingLight = totalDiffuse + totalSpecular + totalEmissiveRadiance;
	#ifdef USE_SHEEN
 
		outgoingLight = outgoingLight + sheenSpecularDirect + sheenSpecularIndirect;
 
 	#endif
	#ifdef USE_CLEARCOAT
		float dotNVcc = saturate( dot( geometryClearcoatNormal, geometryViewDir ) );
		vec3 Fcc = F_Schlick( material.clearcoatF0, material.clearcoatF90, dotNVcc );
		outgoingLight = outgoingLight * ( 1.0 - material.clearcoat * Fcc ) + ( clearcoatSpecularDirect + clearcoatSpecularIndirect ) * material.clearcoat;
	#endif
	#include <opaque_fragment>
	#include <tonemapping_fragment>
	#include <colorspace_fragment>
	#include <fog_fragment>
	#include <premultiplied_alpha_fragment>
	#include <dithering_fragment>
}`,lT=`#define TOON
varying vec3 vViewPosition;
#include <common>
#include <batching_pars_vertex>
#include <uv_pars_vertex>
#include <displacementmap_pars_vertex>
#include <color_pars_vertex>
#include <fog_pars_vertex>
#include <normal_pars_vertex>
#include <morphtarget_pars_vertex>
#include <skinning_pars_vertex>
#include <shadowmap_pars_vertex>
#include <logdepthbuf_pars_vertex>
#include <clipping_planes_pars_vertex>
void main() {
	#include <uv_vertex>
	#include <color_vertex>
	#include <morphinstance_vertex>
	#include <morphcolor_vertex>
	#include <batching_vertex>
	#include <beginnormal_vertex>
	#include <morphnormal_vertex>
	#include <skinbase_vertex>
	#include <skinnormal_vertex>
	#include <defaultnormal_vertex>
	#include <normal_vertex>
	#include <begin_vertex>
	#include <morphtarget_vertex>
	#include <skinning_vertex>
	#include <displacementmap_vertex>
	#include <project_vertex>
	#include <logdepthbuf_vertex>
	#include <clipping_planes_vertex>
	vViewPosition = - mvPosition.xyz;
	#include <worldpos_vertex>
	#include <shadowmap_vertex>
	#include <fog_vertex>
}`,cT=`#define TOON
uniform vec3 diffuse;
uniform vec3 emissive;
uniform float opacity;
#include <common>
#include <dithering_pars_fragment>
#include <color_pars_fragment>
#include <uv_pars_fragment>
#include <map_pars_fragment>
#include <alphamap_pars_fragment>
#include <alphatest_pars_fragment>
#include <alphahash_pars_fragment>
#include <aomap_pars_fragment>
#include <lightmap_pars_fragment>
#include <emissivemap_pars_fragment>
#include <gradientmap_pars_fragment>
#include <fog_pars_fragment>
#include <bsdfs>
#include <lights_pars_begin>
#include <normal_pars_fragment>
#include <lights_toon_pars_fragment>
#include <shadowmap_pars_fragment>
#include <bumpmap_pars_fragment>
#include <normalmap_pars_fragment>
#include <logdepthbuf_pars_fragment>
#include <clipping_planes_pars_fragment>
void main() {
	vec4 diffuseColor = vec4( diffuse, opacity );
	#include <clipping_planes_fragment>
	ReflectedLight reflectedLight = ReflectedLight( vec3( 0.0 ), vec3( 0.0 ), vec3( 0.0 ), vec3( 0.0 ) );
	vec3 totalEmissiveRadiance = emissive;
	#include <logdepthbuf_fragment>
	#include <map_fragment>
	#include <color_fragment>
	#include <alphamap_fragment>
	#include <alphatest_fragment>
	#include <alphahash_fragment>
	#include <normal_fragment_begin>
	#include <normal_fragment_maps>
	#include <emissivemap_fragment>
	#include <lights_toon_fragment>
	#include <lights_fragment_begin>
	#include <lights_fragment_maps>
	#include <lights_fragment_end>
	#include <aomap_fragment>
	vec3 outgoingLight = reflectedLight.directDiffuse + reflectedLight.indirectDiffuse + totalEmissiveRadiance;
	#include <opaque_fragment>
	#include <tonemapping_fragment>
	#include <colorspace_fragment>
	#include <fog_fragment>
	#include <premultiplied_alpha_fragment>
	#include <dithering_fragment>
}`,uT=`uniform float size;
uniform float scale;
#include <common>
#include <color_pars_vertex>
#include <fog_pars_vertex>
#include <morphtarget_pars_vertex>
#include <logdepthbuf_pars_vertex>
#include <clipping_planes_pars_vertex>
#ifdef USE_POINTS_UV
	varying vec2 vUv;
	uniform mat3 uvTransform;
#endif
void main() {
	#ifdef USE_POINTS_UV
		vUv = ( uvTransform * vec3( uv, 1 ) ).xy;
	#endif
	#include <color_vertex>
	#include <morphinstance_vertex>
	#include <morphcolor_vertex>
	#include <begin_vertex>
	#include <morphtarget_vertex>
	#include <project_vertex>
	gl_PointSize = size;
	#ifdef USE_SIZEATTENUATION
		bool isPerspective = isPerspectiveMatrix( projectionMatrix );
		if ( isPerspective ) gl_PointSize *= ( scale / - mvPosition.z );
	#endif
	#include <logdepthbuf_vertex>
	#include <clipping_planes_vertex>
	#include <worldpos_vertex>
	#include <fog_vertex>
}`,fT=`uniform vec3 diffuse;
uniform float opacity;
#include <common>
#include <color_pars_fragment>
#include <map_particle_pars_fragment>
#include <alphatest_pars_fragment>
#include <alphahash_pars_fragment>
#include <fog_pars_fragment>
#include <logdepthbuf_pars_fragment>
#include <clipping_planes_pars_fragment>
void main() {
	vec4 diffuseColor = vec4( diffuse, opacity );
	#include <clipping_planes_fragment>
	vec3 outgoingLight = vec3( 0.0 );
	#include <logdepthbuf_fragment>
	#include <map_particle_fragment>
	#include <color_fragment>
	#include <alphatest_fragment>
	#include <alphahash_fragment>
	outgoingLight = diffuseColor.rgb;
	#include <opaque_fragment>
	#include <tonemapping_fragment>
	#include <colorspace_fragment>
	#include <fog_fragment>
	#include <premultiplied_alpha_fragment>
}`,hT=`#include <common>
#include <batching_pars_vertex>
#include <fog_pars_vertex>
#include <morphtarget_pars_vertex>
#include <skinning_pars_vertex>
#include <logdepthbuf_pars_vertex>
#include <shadowmap_pars_vertex>
void main() {
	#include <batching_vertex>
	#include <beginnormal_vertex>
	#include <morphinstance_vertex>
	#include <morphnormal_vertex>
	#include <skinbase_vertex>
	#include <skinnormal_vertex>
	#include <defaultnormal_vertex>
	#include <begin_vertex>
	#include <morphtarget_vertex>
	#include <skinning_vertex>
	#include <project_vertex>
	#include <logdepthbuf_vertex>
	#include <worldpos_vertex>
	#include <shadowmap_vertex>
	#include <fog_vertex>
}`,dT=`uniform vec3 color;
uniform float opacity;
#include <common>
#include <fog_pars_fragment>
#include <bsdfs>
#include <lights_pars_begin>
#include <logdepthbuf_pars_fragment>
#include <shadowmap_pars_fragment>
#include <shadowmask_pars_fragment>
void main() {
	#include <logdepthbuf_fragment>
	gl_FragColor = vec4( color, opacity * ( 1.0 - getShadowMask() ) );
	#include <tonemapping_fragment>
	#include <colorspace_fragment>
	#include <fog_fragment>
	#include <premultiplied_alpha_fragment>
}`,pT=`uniform float rotation;
uniform vec2 center;
#include <common>
#include <uv_pars_vertex>
#include <fog_pars_vertex>
#include <logdepthbuf_pars_vertex>
#include <clipping_planes_pars_vertex>
void main() {
	#include <uv_vertex>
	vec4 mvPosition = modelViewMatrix[ 3 ];
	vec2 scale = vec2( length( modelMatrix[ 0 ].xyz ), length( modelMatrix[ 1 ].xyz ) );
	#ifndef USE_SIZEATTENUATION
		bool isPerspective = isPerspectiveMatrix( projectionMatrix );
		if ( isPerspective ) scale *= - mvPosition.z;
	#endif
	vec2 alignedPosition = ( position.xy - ( center - vec2( 0.5 ) ) ) * scale;
	vec2 rotatedPosition;
	rotatedPosition.x = cos( rotation ) * alignedPosition.x - sin( rotation ) * alignedPosition.y;
	rotatedPosition.y = sin( rotation ) * alignedPosition.x + cos( rotation ) * alignedPosition.y;
	mvPosition.xy += rotatedPosition;
	gl_Position = projectionMatrix * mvPosition;
	#include <logdepthbuf_vertex>
	#include <clipping_planes_vertex>
	#include <fog_vertex>
}`,mT=`uniform vec3 diffuse;
uniform float opacity;
#include <common>
#include <uv_pars_fragment>
#include <map_pars_fragment>
#include <alphamap_pars_fragment>
#include <alphatest_pars_fragment>
#include <alphahash_pars_fragment>
#include <fog_pars_fragment>
#include <logdepthbuf_pars_fragment>
#include <clipping_planes_pars_fragment>
void main() {
	vec4 diffuseColor = vec4( diffuse, opacity );
	#include <clipping_planes_fragment>
	vec3 outgoingLight = vec3( 0.0 );
	#include <logdepthbuf_fragment>
	#include <map_fragment>
	#include <alphamap_fragment>
	#include <alphatest_fragment>
	#include <alphahash_fragment>
	outgoingLight = diffuseColor.rgb;
	#include <opaque_fragment>
	#include <tonemapping_fragment>
	#include <colorspace_fragment>
	#include <fog_fragment>
}`,ue={alphahash_fragment:IE,alphahash_pars_fragment:zE,alphamap_fragment:FE,alphamap_pars_fragment:BE,alphatest_fragment:HE,alphatest_pars_fragment:GE,aomap_fragment:VE,aomap_pars_fragment:kE,batching_pars_vertex:XE,batching_vertex:WE,begin_vertex:qE,beginnormal_vertex:YE,bsdfs:ZE,iridescence_fragment:KE,bumpmap_pars_fragment:jE,clipping_planes_fragment:JE,clipping_planes_pars_fragment:QE,clipping_planes_pars_vertex:$E,clipping_planes_vertex:t1,color_fragment:e1,color_pars_fragment:n1,color_pars_vertex:i1,color_vertex:a1,common:s1,cube_uv_reflection_fragment:r1,defaultnormal_vertex:o1,displacementmap_pars_vertex:l1,displacementmap_vertex:c1,emissivemap_fragment:u1,emissivemap_pars_fragment:f1,colorspace_fragment:h1,colorspace_pars_fragment:d1,envmap_fragment:p1,envmap_common_pars_fragment:m1,envmap_pars_fragment:g1,envmap_pars_vertex:v1,envmap_physical_pars_fragment:C1,envmap_vertex:_1,fog_vertex:x1,fog_pars_vertex:S1,fog_fragment:y1,fog_pars_fragment:M1,gradientmap_pars_fragment:E1,lightmap_pars_fragment:b1,lights_lambert_fragment:T1,lights_lambert_pars_fragment:A1,lights_pars_begin:R1,lights_toon_fragment:w1,lights_toon_pars_fragment:D1,lights_phong_fragment:N1,lights_phong_pars_fragment:U1,lights_physical_fragment:L1,lights_physical_pars_fragment:O1,lights_fragment_begin:P1,lights_fragment_maps:I1,lights_fragment_end:z1,lightprobes_pars_fragment:F1,logdepthbuf_fragment:B1,logdepthbuf_pars_fragment:H1,logdepthbuf_pars_vertex:G1,logdepthbuf_vertex:V1,map_fragment:k1,map_pars_fragment:X1,map_particle_fragment:W1,map_particle_pars_fragment:q1,metalnessmap_fragment:Y1,metalnessmap_pars_fragment:Z1,morphinstance_vertex:K1,morphcolor_vertex:j1,morphnormal_vertex:J1,morphtarget_pars_vertex:Q1,morphtarget_vertex:$1,normal_fragment_begin:tb,normal_fragment_maps:eb,normal_pars_fragment:nb,normal_pars_vertex:ib,normal_vertex:ab,normalmap_pars_fragment:sb,clearcoat_normal_fragment_begin:rb,clearcoat_normal_fragment_maps:ob,clearcoat_pars_fragment:lb,iridescence_pars_fragment:cb,opaque_fragment:ub,packing:fb,premultiplied_alpha_fragment:hb,project_vertex:db,dithering_fragment:pb,dithering_pars_fragment:mb,roughnessmap_fragment:gb,roughnessmap_pars_fragment:vb,shadowmap_pars_fragment:_b,shadowmap_pars_vertex:xb,shadowmap_vertex:Sb,shadowmask_pars_fragment:yb,skinbase_vertex:Mb,skinning_pars_vertex:Eb,skinning_vertex:bb,skinnormal_vertex:Tb,specularmap_fragment:Ab,specularmap_pars_fragment:Rb,tonemapping_fragment:Cb,tonemapping_pars_fragment:wb,transmission_fragment:Db,transmission_pars_fragment:Nb,uv_pars_fragment:Ub,uv_pars_vertex:Lb,uv_vertex:Ob,worldpos_vertex:Pb,background_vert:Ib,background_frag:zb,backgroundCube_vert:Fb,backgroundCube_frag:Bb,cube_vert:Hb,cube_frag:Gb,depth_vert:Vb,depth_frag:kb,distance_vert:Xb,distance_frag:Wb,equirect_vert:qb,equirect_frag:Yb,linedashed_vert:Zb,linedashed_frag:Kb,meshbasic_vert:jb,meshbasic_frag:Jb,meshlambert_vert:Qb,meshlambert_frag:$b,meshmatcap_vert:tT,meshmatcap_frag:eT,meshnormal_vert:nT,meshnormal_frag:iT,meshphong_vert:aT,meshphong_frag:sT,meshphysical_vert:rT,meshphysical_frag:oT,meshtoon_vert:lT,meshtoon_frag:cT,points_vert:uT,points_frag:fT,shadow_vert:hT,shadow_frag:dT,sprite_vert:pT,sprite_frag:mT},zt={common:{diffuse:{value:new fe(16777215)},opacity:{value:1},map:{value:null},mapTransform:{value:new re},alphaMap:{value:null},alphaMapTransform:{value:new re},alphaTest:{value:0}},specularmap:{specularMap:{value:null},specularMapTransform:{value:new re}},envmap:{envMap:{value:null},envMapRotation:{value:new re},reflectivity:{value:1},ior:{value:1.5},refractionRatio:{value:.98},dfgLUT:{value:null}},aomap:{aoMap:{value:null},aoMapIntensity:{value:1},aoMapTransform:{value:new re}},lightmap:{lightMap:{value:null},lightMapIntensity:{value:1},lightMapTransform:{value:new re}},bumpmap:{bumpMap:{value:null},bumpMapTransform:{value:new re},bumpScale:{value:1}},normalmap:{normalMap:{value:null},normalMapTransform:{value:new re},normalScale:{value:new qt(1,1)}},displacementmap:{displacementMap:{value:null},displacementMapTransform:{value:new re},displacementScale:{value:1},displacementBias:{value:0}},emissivemap:{emissiveMap:{value:null},emissiveMapTransform:{value:new re}},metalnessmap:{metalnessMap:{value:null},metalnessMapTransform:{value:new re}},roughnessmap:{roughnessMap:{value:null},roughnessMapTransform:{value:new re}},gradientmap:{gradientMap:{value:null}},fog:{fogDensity:{value:25e-5},fogNear:{value:1},fogFar:{value:2e3},fogColor:{value:new fe(16777215)}},lights:{ambientLightColor:{value:[]},lightProbe:{value:[]},directionalLights:{value:[],properties:{direction:{},color:{}}},directionalLightShadows:{value:[],properties:{shadowIntensity:1,shadowBias:{},shadowNormalBias:{},shadowRadius:{},shadowMapSize:{}}},directionalShadowMatrix:{value:[]},spotLights:{value:[],properties:{color:{},position:{},direction:{},distance:{},coneCos:{},penumbraCos:{},decay:{}}},spotLightShadows:{value:[],properties:{shadowIntensity:1,shadowBias:{},shadowNormalBias:{},shadowRadius:{},shadowMapSize:{}}},spotLightMap:{value:[]},spotLightMatrix:{value:[]},pointLights:{value:[],properties:{color:{},position:{},decay:{},distance:{}}},pointLightShadows:{value:[],properties:{shadowIntensity:1,shadowBias:{},shadowNormalBias:{},shadowRadius:{},shadowMapSize:{},shadowCameraNear:{},shadowCameraFar:{}}},pointShadowMatrix:{value:[]},hemisphereLights:{value:[],properties:{direction:{},skyColor:{},groundColor:{}}},rectAreaLights:{value:[],properties:{color:{},position:{},width:{},height:{}}},ltc_1:{value:null},ltc_2:{value:null},probesSH:{value:null},probesMin:{value:new K},probesMax:{value:new K},probesResolution:{value:new K}},points:{diffuse:{value:new fe(16777215)},opacity:{value:1},size:{value:1},scale:{value:1},map:{value:null},alphaMap:{value:null},alphaMapTransform:{value:new re},alphaTest:{value:0},uvTransform:{value:new re}},sprite:{diffuse:{value:new fe(16777215)},opacity:{value:1},center:{value:new qt(.5,.5)},rotation:{value:0},map:{value:null},mapTransform:{value:new re},alphaMap:{value:null},alphaMapTransform:{value:new re},alphaTest:{value:0}}},Xi={basic:{uniforms:Gn([zt.common,zt.specularmap,zt.envmap,zt.aomap,zt.lightmap,zt.fog]),vertexShader:ue.meshbasic_vert,fragmentShader:ue.meshbasic_frag},lambert:{uniforms:Gn([zt.common,zt.specularmap,zt.envmap,zt.aomap,zt.lightmap,zt.emissivemap,zt.bumpmap,zt.normalmap,zt.displacementmap,zt.fog,zt.lights,{emissive:{value:new fe(0)},envMapIntensity:{value:1}}]),vertexShader:ue.meshlambert_vert,fragmentShader:ue.meshlambert_frag},phong:{uniforms:Gn([zt.common,zt.specularmap,zt.envmap,zt.aomap,zt.lightmap,zt.emissivemap,zt.bumpmap,zt.normalmap,zt.displacementmap,zt.fog,zt.lights,{emissive:{value:new fe(0)},specular:{value:new fe(1118481)},shininess:{value:30},envMapIntensity:{value:1}}]),vertexShader:ue.meshphong_vert,fragmentShader:ue.meshphong_frag},standard:{uniforms:Gn([zt.common,zt.envmap,zt.aomap,zt.lightmap,zt.emissivemap,zt.bumpmap,zt.normalmap,zt.displacementmap,zt.roughnessmap,zt.metalnessmap,zt.fog,zt.lights,{emissive:{value:new fe(0)},roughness:{value:1},metalness:{value:0},envMapIntensity:{value:1}}]),vertexShader:ue.meshphysical_vert,fragmentShader:ue.meshphysical_frag},toon:{uniforms:Gn([zt.common,zt.aomap,zt.lightmap,zt.emissivemap,zt.bumpmap,zt.normalmap,zt.displacementmap,zt.gradientmap,zt.fog,zt.lights,{emissive:{value:new fe(0)}}]),vertexShader:ue.meshtoon_vert,fragmentShader:ue.meshtoon_frag},matcap:{uniforms:Gn([zt.common,zt.bumpmap,zt.normalmap,zt.displacementmap,zt.fog,{matcap:{value:null}}]),vertexShader:ue.meshmatcap_vert,fragmentShader:ue.meshmatcap_frag},points:{uniforms:Gn([zt.points,zt.fog]),vertexShader:ue.points_vert,fragmentShader:ue.points_frag},dashed:{uniforms:Gn([zt.common,zt.fog,{scale:{value:1},dashSize:{value:1},totalSize:{value:2}}]),vertexShader:ue.linedashed_vert,fragmentShader:ue.linedashed_frag},depth:{uniforms:Gn([zt.common,zt.displacementmap]),vertexShader:ue.depth_vert,fragmentShader:ue.depth_frag},normal:{uniforms:Gn([zt.common,zt.bumpmap,zt.normalmap,zt.displacementmap,{opacity:{value:1}}]),vertexShader:ue.meshnormal_vert,fragmentShader:ue.meshnormal_frag},sprite:{uniforms:Gn([zt.sprite,zt.fog]),vertexShader:ue.sprite_vert,fragmentShader:ue.sprite_frag},background:{uniforms:{uvTransform:{value:new re},t2D:{value:null},backgroundIntensity:{value:1}},vertexShader:ue.background_vert,fragmentShader:ue.background_frag},backgroundCube:{uniforms:{envMap:{value:null},backgroundBlurriness:{value:0},backgroundIntensity:{value:1},backgroundRotation:{value:new re}},vertexShader:ue.backgroundCube_vert,fragmentShader:ue.backgroundCube_frag},cube:{uniforms:{tCube:{value:null},tFlip:{value:-1},opacity:{value:1}},vertexShader:ue.cube_vert,fragmentShader:ue.cube_frag},equirect:{uniforms:{tEquirect:{value:null}},vertexShader:ue.equirect_vert,fragmentShader:ue.equirect_frag},distance:{uniforms:Gn([zt.common,zt.displacementmap,{referencePosition:{value:new K},nearDistance:{value:1},farDistance:{value:1e3}}]),vertexShader:ue.distance_vert,fragmentShader:ue.distance_frag},shadow:{uniforms:Gn([zt.lights,zt.fog,{color:{value:new fe(0)},opacity:{value:1}}]),vertexShader:ue.shadow_vert,fragmentShader:ue.shadow_frag}};Xi.physical={uniforms:Gn([Xi.standard.uniforms,{clearcoat:{value:0},clearcoatMap:{value:null},clearcoatMapTransform:{value:new re},clearcoatNormalMap:{value:null},clearcoatNormalMapTransform:{value:new re},clearcoatNormalScale:{value:new qt(1,1)},clearcoatRoughness:{value:0},clearcoatRoughnessMap:{value:null},clearcoatRoughnessMapTransform:{value:new re},dispersion:{value:0},iridescence:{value:0},iridescenceMap:{value:null},iridescenceMapTransform:{value:new re},iridescenceIOR:{value:1.3},iridescenceThicknessMinimum:{value:100},iridescenceThicknessMaximum:{value:400},iridescenceThicknessMap:{value:null},iridescenceThicknessMapTransform:{value:new re},sheen:{value:0},sheenColor:{value:new fe(0)},sheenColorMap:{value:null},sheenColorMapTransform:{value:new re},sheenRoughness:{value:1},sheenRoughnessMap:{value:null},sheenRoughnessMapTransform:{value:new re},transmission:{value:0},transmissionMap:{value:null},transmissionMapTransform:{value:new re},transmissionSamplerSize:{value:new qt},transmissionSamplerMap:{value:null},thickness:{value:0},thicknessMap:{value:null},thicknessMapTransform:{value:new re},attenuationDistance:{value:0},attenuationColor:{value:new fe(0)},specularColor:{value:new fe(1,1,1)},specularColorMap:{value:null},specularColorMapTransform:{value:new re},specularIntensity:{value:1},specularIntensityMap:{value:null},specularIntensityMapTransform:{value:new re},anisotropyVector:{value:new qt},anisotropyMap:{value:null},anisotropyMapTransform:{value:new re}}]),vertexShader:ue.meshphysical_vert,fragmentShader:ue.meshphysical_frag};const Wc={r:0,b:0,g:0},gT=new en,_x=new re;_x.set(-1,0,0,0,1,0,0,0,1);function vT(r,t,n,s,l,c){const f=new fe(0);let d=l===!0?0:1,m,p,v=null,_=0,g=null;function y(P){let D=P.isScene===!0?P.background:null;if(D&&D.isTexture){const A=P.backgroundBlurriness>0;D=t.get(D,A)}return D}function b(P){let D=!1;const A=y(P);A===null?M(f,d):A&&A.isColor&&(M(A,1),D=!0);const F=r.xr.getEnvironmentBlendMode();F==="additive"?n.buffers.color.setClear(0,0,0,1,c):F==="alpha-blend"&&n.buffers.color.setClear(0,0,0,0,c),(r.autoClear||D)&&(n.buffers.depth.setTest(!0),n.buffers.depth.setMask(!0),n.buffers.color.setMask(!0),r.clear(r.autoClearColor,r.autoClearDepth,r.autoClearStencil))}function w(P,D){const A=y(D);A&&(A.isCubeTexture||A.mapping===uu)?(p===void 0&&(p=new un(new cs(1,1,1),new Ti({name:"BackgroundCubeMaterial",uniforms:qr(Xi.backgroundCube.uniforms),vertexShader:Xi.backgroundCube.vertexShader,fragmentShader:Xi.backgroundCube.fragmentShader,side:Vn,depthTest:!1,depthWrite:!1,fog:!1,allowOverride:!1})),p.geometry.deleteAttribute("normal"),p.geometry.deleteAttribute("uv"),p.onBeforeRender=function(F,O,I){this.matrixWorld.copyPosition(I.matrixWorld)},Object.defineProperty(p.material,"envMap",{get:function(){return this.uniforms.envMap.value}}),s.update(p)),p.material.uniforms.envMap.value=A,p.material.uniforms.backgroundBlurriness.value=D.backgroundBlurriness,p.material.uniforms.backgroundIntensity.value=D.backgroundIntensity,p.material.uniforms.backgroundRotation.value.setFromMatrix4(gT.makeRotationFromEuler(D.backgroundRotation)).transpose(),A.isCubeTexture&&A.isRenderTargetTexture===!1&&p.material.uniforms.backgroundRotation.value.premultiply(_x),p.material.toneMapped=Ee.getTransfer(A.colorSpace)!==ze,(v!==A||_!==A.version||g!==r.toneMapping)&&(p.material.needsUpdate=!0,v=A,_=A.version,g=r.toneMapping),p.layers.enableAll(),P.unshift(p,p.geometry,p.material,0,0,null)):A&&A.isTexture&&(m===void 0&&(m=new un(new fl(2,2),new Ti({name:"BackgroundMaterial",uniforms:qr(Xi.background.uniforms),vertexShader:Xi.background.vertexShader,fragmentShader:Xi.background.fragmentShader,side:us,depthTest:!1,depthWrite:!1,fog:!1,allowOverride:!1})),m.geometry.deleteAttribute("normal"),Object.defineProperty(m.material,"map",{get:function(){return this.uniforms.t2D.value}}),s.update(m)),m.material.uniforms.t2D.value=A,m.material.uniforms.backgroundIntensity.value=D.backgroundIntensity,m.material.toneMapped=Ee.getTransfer(A.colorSpace)!==ze,A.matrixAutoUpdate===!0&&A.updateMatrix(),m.material.uniforms.uvTransform.value.copy(A.matrix),(v!==A||_!==A.version||g!==r.toneMapping)&&(m.material.needsUpdate=!0,v=A,_=A.version,g=r.toneMapping),m.layers.enableAll(),P.unshift(m,m.geometry,m.material,0,0,null))}function M(P,D){P.getRGB(Wc,px(r)),n.buffers.color.setClear(Wc.r,Wc.g,Wc.b,D,c)}function S(){p!==void 0&&(p.geometry.dispose(),p.material.dispose(),p=void 0),m!==void 0&&(m.geometry.dispose(),m.material.dispose(),m=void 0)}return{getClearColor:function(){return f},setClearColor:function(P,D=1){f.set(P),d=D,M(f,d)},getClearAlpha:function(){return d},setClearAlpha:function(P){d=P,M(f,d)},render:b,addToRenderList:w,dispose:S}}function _T(r,t){const n=r.getParameter(r.MAX_VERTEX_ATTRIBS),s={},l=g(null);let c=l,f=!1;function d(V,q,ct,ht,j){let B=!1;const H=_(V,ht,ct,q);c!==H&&(c=H,p(c.object)),B=y(V,ht,ct,j),B&&b(V,ht,ct,j),j!==null&&t.update(j,r.ELEMENT_ARRAY_BUFFER),(B||f)&&(f=!1,A(V,q,ct,ht),j!==null&&r.bindBuffer(r.ELEMENT_ARRAY_BUFFER,t.get(j).buffer))}function m(){return r.createVertexArray()}function p(V){return r.bindVertexArray(V)}function v(V){return r.deleteVertexArray(V)}function _(V,q,ct,ht){const j=ht.wireframe===!0;let B=s[q.id];B===void 0&&(B={},s[q.id]=B);const H=V.isInstancedMesh===!0?V.id:0;let $=B[H];$===void 0&&($={},B[H]=$);let dt=$[ct.id];dt===void 0&&(dt={},$[ct.id]=dt);let Mt=dt[j];return Mt===void 0&&(Mt=g(m()),dt[j]=Mt),Mt}function g(V){const q=[],ct=[],ht=[];for(let j=0;j<n;j++)q[j]=0,ct[j]=0,ht[j]=0;return{geometry:null,program:null,wireframe:!1,newAttributes:q,enabledAttributes:ct,attributeDivisors:ht,object:V,attributes:{},index:null}}function y(V,q,ct,ht){const j=c.attributes,B=q.attributes;let H=0;const $=ct.getAttributes();for(const dt in $)if($[dt].location>=0){const U=j[dt];let J=B[dt];if(J===void 0&&(dt==="instanceMatrix"&&V.instanceMatrix&&(J=V.instanceMatrix),dt==="instanceColor"&&V.instanceColor&&(J=V.instanceColor)),U===void 0||U.attribute!==J||J&&U.data!==J.data)return!0;H++}return c.attributesNum!==H||c.index!==ht}function b(V,q,ct,ht){const j={},B=q.attributes;let H=0;const $=ct.getAttributes();for(const dt in $)if($[dt].location>=0){let U=B[dt];U===void 0&&(dt==="instanceMatrix"&&V.instanceMatrix&&(U=V.instanceMatrix),dt==="instanceColor"&&V.instanceColor&&(U=V.instanceColor));const J={};J.attribute=U,U&&U.data&&(J.data=U.data),j[dt]=J,H++}c.attributes=j,c.attributesNum=H,c.index=ht}function w(){const V=c.newAttributes;for(let q=0,ct=V.length;q<ct;q++)V[q]=0}function M(V){S(V,0)}function S(V,q){const ct=c.newAttributes,ht=c.enabledAttributes,j=c.attributeDivisors;ct[V]=1,ht[V]===0&&(r.enableVertexAttribArray(V),ht[V]=1),j[V]!==q&&(r.vertexAttribDivisor(V,q),j[V]=q)}function P(){const V=c.newAttributes,q=c.enabledAttributes;for(let ct=0,ht=q.length;ct<ht;ct++)q[ct]!==V[ct]&&(r.disableVertexAttribArray(ct),q[ct]=0)}function D(V,q,ct,ht,j,B,H){H===!0?r.vertexAttribIPointer(V,q,ct,j,B):r.vertexAttribPointer(V,q,ct,ht,j,B)}function A(V,q,ct,ht){w();const j=ht.attributes,B=ct.getAttributes(),H=q.defaultAttributeValues;for(const $ in B){const dt=B[$];if(dt.location>=0){let Mt=j[$];if(Mt===void 0&&($==="instanceMatrix"&&V.instanceMatrix&&(Mt=V.instanceMatrix),$==="instanceColor"&&V.instanceColor&&(Mt=V.instanceColor)),Mt!==void 0){const U=Mt.normalized,J=Mt.itemSize,bt=t.get(Mt);if(bt===void 0)continue;const pt=bt.buffer,At=bt.type,tt=bt.bytesPerElement,_t=At===r.INT||At===r.UNSIGNED_INT||Mt.gpuType===sp;if(Mt.isInterleavedBufferAttribute){const xt=Mt.data,It=xt.stride,jt=Mt.offset;if(xt.isInstancedInterleavedBuffer){for(let Jt=0;Jt<dt.locationSize;Jt++)S(dt.location+Jt,xt.meshPerAttribute);V.isInstancedMesh!==!0&&ht._maxInstanceCount===void 0&&(ht._maxInstanceCount=xt.meshPerAttribute*xt.count)}else for(let Jt=0;Jt<dt.locationSize;Jt++)M(dt.location+Jt);r.bindBuffer(r.ARRAY_BUFFER,pt);for(let Jt=0;Jt<dt.locationSize;Jt++)D(dt.location+Jt,J/dt.locationSize,At,U,It*tt,(jt+J/dt.locationSize*Jt)*tt,_t)}else{if(Mt.isInstancedBufferAttribute){for(let xt=0;xt<dt.locationSize;xt++)S(dt.location+xt,Mt.meshPerAttribute);V.isInstancedMesh!==!0&&ht._maxInstanceCount===void 0&&(ht._maxInstanceCount=Mt.meshPerAttribute*Mt.count)}else for(let xt=0;xt<dt.locationSize;xt++)M(dt.location+xt);r.bindBuffer(r.ARRAY_BUFFER,pt);for(let xt=0;xt<dt.locationSize;xt++)D(dt.location+xt,J/dt.locationSize,At,U,J*tt,J/dt.locationSize*xt*tt,_t)}}else if(H!==void 0){const U=H[$];if(U!==void 0)switch(U.length){case 2:r.vertexAttrib2fv(dt.location,U);break;case 3:r.vertexAttrib3fv(dt.location,U);break;case 4:r.vertexAttrib4fv(dt.location,U);break;default:r.vertexAttrib1fv(dt.location,U)}}}}P()}function F(){N();for(const V in s){const q=s[V];for(const ct in q){const ht=q[ct];for(const j in ht){const B=ht[j];for(const H in B)v(B[H].object),delete B[H];delete ht[j]}}delete s[V]}}function O(V){if(s[V.id]===void 0)return;const q=s[V.id];for(const ct in q){const ht=q[ct];for(const j in ht){const B=ht[j];for(const H in B)v(B[H].object),delete B[H];delete ht[j]}}delete s[V.id]}function I(V){for(const q in s){const ct=s[q];for(const ht in ct){const j=ct[ht];if(j[V.id]===void 0)continue;const B=j[V.id];for(const H in B)v(B[H].object),delete B[H];delete j[V.id]}}}function T(V){for(const q in s){const ct=s[q],ht=V.isInstancedMesh===!0?V.id:0,j=ct[ht];if(j!==void 0){for(const B in j){const H=j[B];for(const $ in H)v(H[$].object),delete H[$];delete j[B]}delete ct[ht],Object.keys(ct).length===0&&delete s[q]}}}function N(){X(),f=!0,c!==l&&(c=l,p(c.object))}function X(){l.geometry=null,l.program=null,l.wireframe=!1}return{setup:d,reset:N,resetDefaultState:X,dispose:F,releaseStatesOfGeometry:O,releaseStatesOfObject:T,releaseStatesOfProgram:I,initAttributes:w,enableAttribute:M,disableUnusedAttributes:P}}function xT(r,t,n){let s;function l(m){s=m}function c(m,p){r.drawArrays(s,m,p),n.update(p,s,1)}function f(m,p,v){v!==0&&(r.drawArraysInstanced(s,m,p,v),n.update(p,s,v))}function d(m,p,v){if(v===0)return;t.get("WEBGL_multi_draw").multiDrawArraysWEBGL(s,m,0,p,0,v);let g=0;for(let y=0;y<v;y++)g+=p[y];n.update(g,s,1)}this.setMode=l,this.render=c,this.renderInstances=f,this.renderMultiDraw=d}function ST(r,t,n,s){let l;function c(){if(l!==void 0)return l;if(t.has("EXT_texture_filter_anisotropic")===!0){const I=t.get("EXT_texture_filter_anisotropic");l=r.getParameter(I.MAX_TEXTURE_MAX_ANISOTROPY_EXT)}else l=0;return l}function f(I){return!(I!==Pi&&s.convert(I)!==r.getParameter(r.IMPLEMENTATION_COLOR_READ_FORMAT))}function d(I){const T=I===Aa&&(t.has("EXT_color_buffer_half_float")||t.has("EXT_color_buffer_float"));return!(I!==di&&s.convert(I)!==r.getParameter(r.IMPLEMENTATION_COLOR_READ_TYPE)&&I!==Wi&&!T)}function m(I){if(I==="highp"){if(r.getShaderPrecisionFormat(r.VERTEX_SHADER,r.HIGH_FLOAT).precision>0&&r.getShaderPrecisionFormat(r.FRAGMENT_SHADER,r.HIGH_FLOAT).precision>0)return"highp";I="mediump"}return I==="mediump"&&r.getShaderPrecisionFormat(r.VERTEX_SHADER,r.MEDIUM_FLOAT).precision>0&&r.getShaderPrecisionFormat(r.FRAGMENT_SHADER,r.MEDIUM_FLOAT).precision>0?"mediump":"lowp"}let p=n.precision!==void 0?n.precision:"highp";const v=m(p);v!==p&&(ie("WebGLRenderer:",p,"not supported, using",v,"instead."),p=v);const _=n.logarithmicDepthBuffer===!0,g=n.reversedDepthBuffer===!0&&t.has("EXT_clip_control");n.reversedDepthBuffer===!0&&g===!1&&ie("WebGLRenderer: Unable to use reversed depth buffer due to missing EXT_clip_control extension. Fallback to default depth buffer.");const y=r.getParameter(r.MAX_TEXTURE_IMAGE_UNITS),b=r.getParameter(r.MAX_VERTEX_TEXTURE_IMAGE_UNITS),w=r.getParameter(r.MAX_TEXTURE_SIZE),M=r.getParameter(r.MAX_CUBE_MAP_TEXTURE_SIZE),S=r.getParameter(r.MAX_VERTEX_ATTRIBS),P=r.getParameter(r.MAX_VERTEX_UNIFORM_VECTORS),D=r.getParameter(r.MAX_VARYING_VECTORS),A=r.getParameter(r.MAX_FRAGMENT_UNIFORM_VECTORS),F=r.getParameter(r.MAX_SAMPLES),O=r.getParameter(r.SAMPLES);return{isWebGL2:!0,getMaxAnisotropy:c,getMaxPrecision:m,textureFormatReadable:f,textureTypeReadable:d,precision:p,logarithmicDepthBuffer:_,reversedDepthBuffer:g,maxTextures:y,maxVertexTextures:b,maxTextureSize:w,maxCubemapSize:M,maxAttributes:S,maxVertexUniforms:P,maxVaryings:D,maxFragmentUniforms:A,maxSamples:F,samples:O}}function yT(r){const t=this;let n=null,s=0,l=!1,c=!1;const f=new zs,d=new re,m={value:null,needsUpdate:!1};this.uniform=m,this.numPlanes=0,this.numIntersection=0,this.init=function(_,g){const y=_.length!==0||g||s!==0||l;return l=g,s=_.length,y},this.beginShadows=function(){c=!0,v(null)},this.endShadows=function(){c=!1},this.setGlobalState=function(_,g){n=v(_,g,0)},this.setState=function(_,g,y){const b=_.clippingPlanes,w=_.clipIntersection,M=_.clipShadows,S=r.get(_);if(!l||b===null||b.length===0||c&&!M)c?v(null):p();else{const P=c?0:s,D=P*4;let A=S.clippingState||null;m.value=A,A=v(b,g,D,y);for(let F=0;F!==D;++F)A[F]=n[F];S.clippingState=A,this.numIntersection=w?this.numPlanes:0,this.numPlanes+=P}};function p(){m.value!==n&&(m.value=n,m.needsUpdate=s>0),t.numPlanes=s,t.numIntersection=0}function v(_,g,y,b){const w=_!==null?_.length:0;let M=null;if(w!==0){if(M=m.value,b!==!0||M===null){const S=y+w*4,P=g.matrixWorldInverse;d.getNormalMatrix(P),(M===null||M.length<S)&&(M=new Float32Array(S));for(let D=0,A=y;D!==w;++D,A+=4)f.copy(_[D]).applyMatrix4(P,d),f.normal.toArray(M,A),M[A+3]=f.constant}m.value=M,m.needsUpdate=!0}return t.numPlanes=w,t.numIntersection=0,M}}const ls=4,i_=[.125,.215,.35,.446,.526,.582],Bs=20,MT=256,Zo=new fu,a_=new fe;let ed=null,nd=0,id=0,ad=!1;const ET=new K;class s_{constructor(t){this._renderer=t,this._pingPongRenderTarget=null,this._lodMax=0,this._cubeSize=0,this._sizeLods=[],this._sigmas=[],this._lodMeshes=[],this._backgroundBox=null,this._cubemapMaterial=null,this._equirectMaterial=null,this._blurMaterial=null,this._ggxMaterial=null}fromScene(t,n=0,s=.1,l=100,c={}){const{size:f=256,position:d=ET}=c;ed=this._renderer.getRenderTarget(),nd=this._renderer.getActiveCubeFace(),id=this._renderer.getActiveMipmapLevel(),ad=this._renderer.xr.enabled,this._renderer.xr.enabled=!1,this._setSize(f);const m=this._allocateTargets();return m.depthBuffer=!0,this._sceneToCubeUV(t,s,l,m,d),n>0&&this._blur(m,0,0,n),this._applyPMREM(m),this._cleanup(m),m}fromEquirectangular(t,n=null){return this._fromTexture(t,n)}fromCubemap(t,n=null){return this._fromTexture(t,n)}compileCubemapShader(){this._cubemapMaterial===null&&(this._cubemapMaterial=l_(),this._compileMaterial(this._cubemapMaterial))}compileEquirectangularShader(){this._equirectMaterial===null&&(this._equirectMaterial=o_(),this._compileMaterial(this._equirectMaterial))}dispose(){this._dispose(),this._cubemapMaterial!==null&&this._cubemapMaterial.dispose(),this._equirectMaterial!==null&&this._equirectMaterial.dispose(),this._backgroundBox!==null&&(this._backgroundBox.geometry.dispose(),this._backgroundBox.material.dispose())}_setSize(t){this._lodMax=Math.floor(Math.log2(t)),this._cubeSize=Math.pow(2,this._lodMax)}_dispose(){this._blurMaterial!==null&&this._blurMaterial.dispose(),this._ggxMaterial!==null&&this._ggxMaterial.dispose(),this._pingPongRenderTarget!==null&&this._pingPongRenderTarget.dispose();for(let t=0;t<this._lodMeshes.length;t++)this._lodMeshes[t].geometry.dispose()}_cleanup(t){this._renderer.setRenderTarget(ed,nd,id),this._renderer.xr.enabled=ad,t.scissorTest=!1,zr(t,0,0,t.width,t.height)}_fromTexture(t,n){t.mapping===Vs||t.mapping===kr?this._setSize(t.image.length===0?16:t.image[0].width||t.image[0].image.width):this._setSize(t.image.width/4),ed=this._renderer.getRenderTarget(),nd=this._renderer.getActiveCubeFace(),id=this._renderer.getActiveMipmapLevel(),ad=this._renderer.xr.enabled,this._renderer.xr.enabled=!1;const s=n||this._allocateTargets();return this._textureToCubeUV(t,s),this._applyPMREM(s),this._cleanup(s),s}_allocateTargets(){const t=3*Math.max(this._cubeSize,112),n=4*this._cubeSize,s={magFilter:Bn,minFilter:Bn,generateMipmaps:!1,type:Aa,format:Pi,colorSpace:au,depthBuffer:!1},l=r_(t,n,s);if(this._pingPongRenderTarget===null||this._pingPongRenderTarget.width!==t||this._pingPongRenderTarget.height!==n){this._pingPongRenderTarget!==null&&this._dispose(),this._pingPongRenderTarget=r_(t,n,s);const{_lodMax:c}=this;({lodMeshes:this._lodMeshes,sizeLods:this._sizeLods,sigmas:this._sigmas}=bT(c)),this._blurMaterial=AT(c,t,n),this._ggxMaterial=TT(c,t,n)}return l}_compileMaterial(t){const n=new un(new Xn,t);this._renderer.compile(n,Zo)}_sceneToCubeUV(t,n,s,l,c){const m=new bi(90,1,n,s),p=[1,-1,1,1,1,1],v=[1,1,1,-1,-1,-1],_=this._renderer,g=_.autoClear,y=_.toneMapping;_.getClearColor(a_),_.toneMapping=Yi,_.autoClear=!1,_.state.buffers.depth.getReversed()&&(_.setRenderTarget(l),_.clearDepth(),_.setRenderTarget(null)),this._backgroundBox===null&&(this._backgroundBox=new un(new cs,new $o({name:"PMREM.Background",side:Vn,depthWrite:!1,depthTest:!1})));const w=this._backgroundBox,M=w.material;let S=!1;const P=t.background;P?P.isColor&&(M.color.copy(P),t.background=null,S=!0):(M.color.copy(a_),S=!0);for(let D=0;D<6;D++){const A=D%3;A===0?(m.up.set(0,p[D],0),m.position.set(c.x,c.y,c.z),m.lookAt(c.x+v[D],c.y,c.z)):A===1?(m.up.set(0,0,p[D]),m.position.set(c.x,c.y,c.z),m.lookAt(c.x,c.y+v[D],c.z)):(m.up.set(0,p[D],0),m.position.set(c.x,c.y,c.z),m.lookAt(c.x,c.y,c.z+v[D]));const F=this._cubeSize;zr(l,A*F,D>2?F:0,F,F),_.setRenderTarget(l),S&&_.render(w,m),_.render(t,m)}_.toneMapping=y,_.autoClear=g,t.background=P}_textureToCubeUV(t,n){const s=this._renderer,l=t.mapping===Vs||t.mapping===kr;l?(this._cubemapMaterial===null&&(this._cubemapMaterial=l_()),this._cubemapMaterial.uniforms.flipEnvMap.value=t.isRenderTargetTexture===!1?-1:1):this._equirectMaterial===null&&(this._equirectMaterial=o_());const c=l?this._cubemapMaterial:this._equirectMaterial,f=this._lodMeshes[0];f.material=c;const d=c.uniforms;d.envMap.value=t;const m=this._cubeSize;zr(n,0,0,3*m,2*m),s.setRenderTarget(n),s.render(f,Zo)}_applyPMREM(t){const n=this._renderer,s=n.autoClear;n.autoClear=!1;const l=this._lodMeshes.length;for(let c=1;c<l;c++)this._applyGGXFilter(t,c-1,c);n.autoClear=s}_applyGGXFilter(t,n,s){const l=this._renderer,c=this._pingPongRenderTarget,f=this._ggxMaterial,d=this._lodMeshes[s];d.material=f;const m=f.uniforms,p=s/(this._lodMeshes.length-1),v=n/(this._lodMeshes.length-1),_=Math.sqrt(p*p-v*v),g=0+p*1.25,y=_*g,{_lodMax:b}=this,w=this._sizeLods[s],M=3*w*(s>b-ls?s-b+ls:0),S=4*(this._cubeSize-w);m.envMap.value=t.texture,m.roughness.value=y,m.mipInt.value=b-n,zr(c,M,S,3*w,2*w),l.setRenderTarget(c),l.render(d,Zo),m.envMap.value=c.texture,m.roughness.value=0,m.mipInt.value=b-s,zr(t,M,S,3*w,2*w),l.setRenderTarget(t),l.render(d,Zo)}_blur(t,n,s,l,c){const f=this._pingPongRenderTarget;this._halfBlur(t,f,n,s,l,"latitudinal",c),this._halfBlur(f,t,s,s,l,"longitudinal",c)}_halfBlur(t,n,s,l,c,f,d){const m=this._renderer,p=this._blurMaterial;f!=="latitudinal"&&f!=="longitudinal"&&be("blur direction must be either latitudinal or longitudinal!");const v=3,_=this._lodMeshes[l];_.material=p;const g=p.uniforms,y=this._sizeLods[s]-1,b=isFinite(c)?Math.PI/(2*y):2*Math.PI/(2*Bs-1),w=c/b,M=isFinite(c)?1+Math.floor(v*w):Bs;M>Bs&&ie(`sigmaRadians, ${c}, is too large and will clip, as it requested ${M} samples when the maximum is set to ${Bs}`);const S=[];let P=0;for(let I=0;I<Bs;++I){const T=I/w,N=Math.exp(-T*T/2);S.push(N),I===0?P+=N:I<M&&(P+=2*N)}for(let I=0;I<S.length;I++)S[I]=S[I]/P;g.envMap.value=t.texture,g.samples.value=M,g.weights.value=S,g.latitudinal.value=f==="latitudinal",d&&(g.poleAxis.value=d);const{_lodMax:D}=this;g.dTheta.value=b,g.mipInt.value=D-s;const A=this._sizeLods[l],F=3*A*(l>D-ls?l-D+ls:0),O=4*(this._cubeSize-A);zr(n,F,O,3*A,2*A),m.setRenderTarget(n),m.render(_,Zo)}}function bT(r){const t=[],n=[],s=[];let l=r;const c=r-ls+1+i_.length;for(let f=0;f<c;f++){const d=Math.pow(2,l);t.push(d);let m=1/d;f>r-ls?m=i_[f-r+ls-1]:f===0&&(m=0),n.push(m);const p=1/(d-2),v=-p,_=1+p,g=[v,v,_,v,_,_,v,v,_,_,v,_],y=6,b=6,w=3,M=2,S=1,P=new Float32Array(w*b*y),D=new Float32Array(M*b*y),A=new Float32Array(S*b*y);for(let O=0;O<y;O++){const I=O%3*2/3-1,T=O>2?0:-1,N=[I,T,0,I+2/3,T,0,I+2/3,T+1,0,I,T,0,I+2/3,T+1,0,I,T+1,0];P.set(N,w*b*O),D.set(g,M*b*O);const X=[O,O,O,O,O,O];A.set(X,S*b*O)}const F=new Xn;F.setAttribute("position",new Ki(P,w)),F.setAttribute("uv",new Ki(D,M)),F.setAttribute("faceIndex",new Ki(A,S)),s.push(new un(F,null)),l>ls&&l--}return{lodMeshes:s,sizeLods:t,sigmas:n}}function r_(r,t,n){const s=new Zi(r,t,n);return s.texture.mapping=uu,s.texture.name="PMREM.cubeUv",s.scissorTest=!0,s}function zr(r,t,n,s,l){r.viewport.set(t,n,s,l),r.scissor.set(t,n,s,l)}function TT(r,t,n){return new Ti({name:"PMREMGGXConvolution",defines:{GGX_SAMPLES:MT,CUBEUV_TEXEL_WIDTH:1/t,CUBEUV_TEXEL_HEIGHT:1/n,CUBEUV_MAX_MIP:`${r}.0`},uniforms:{envMap:{value:null},roughness:{value:0},mipInt:{value:0}},vertexShader:hu(),fragmentShader:`

			precision highp float;
			precision highp int;

			varying vec3 vOutputDirection;

			uniform sampler2D envMap;
			uniform float roughness;
			uniform float mipInt;

			#define ENVMAP_TYPE_CUBE_UV
			#include <cube_uv_reflection_fragment>

			#define PI 3.14159265359

			// Van der Corput radical inverse
			float radicalInverse_VdC(uint bits) {
				bits = (bits << 16u) | (bits >> 16u);
				bits = ((bits & 0x55555555u) << 1u) | ((bits & 0xAAAAAAAAu) >> 1u);
				bits = ((bits & 0x33333333u) << 2u) | ((bits & 0xCCCCCCCCu) >> 2u);
				bits = ((bits & 0x0F0F0F0Fu) << 4u) | ((bits & 0xF0F0F0F0u) >> 4u);
				bits = ((bits & 0x00FF00FFu) << 8u) | ((bits & 0xFF00FF00u) >> 8u);
				return float(bits) * 2.3283064365386963e-10; // / 0x100000000
			}

			// Hammersley sequence
			vec2 hammersley(uint i, uint N) {
				return vec2(float(i) / float(N), radicalInverse_VdC(i));
			}

			// GGX VNDF importance sampling (Eric Heitz 2018)
			// "Sampling the GGX Distribution of Visible Normals"
			// https://jcgt.org/published/0007/04/01/
			vec3 importanceSampleGGX_VNDF(vec2 Xi, vec3 V, float roughness) {
				float alpha = roughness * roughness;

				// Section 4.1: Orthonormal basis
				vec3 T1 = vec3(1.0, 0.0, 0.0);
				vec3 T2 = cross(V, T1);

				// Section 4.2: Parameterization of projected area
				float r = sqrt(Xi.x);
				float phi = 2.0 * PI * Xi.y;
				float t1 = r * cos(phi);
				float t2 = r * sin(phi);
				float s = 0.5 * (1.0 + V.z);
				t2 = (1.0 - s) * sqrt(1.0 - t1 * t1) + s * t2;

				// Section 4.3: Reprojection onto hemisphere
				vec3 Nh = t1 * T1 + t2 * T2 + sqrt(max(0.0, 1.0 - t1 * t1 - t2 * t2)) * V;

				// Section 3.4: Transform back to ellipsoid configuration
				return normalize(vec3(alpha * Nh.x, alpha * Nh.y, max(0.0, Nh.z)));
			}

			void main() {
				vec3 N = normalize(vOutputDirection);
				vec3 V = N; // Assume view direction equals normal for pre-filtering

				vec3 prefilteredColor = vec3(0.0);
				float totalWeight = 0.0;

				// For very low roughness, just sample the environment directly
				if (roughness < 0.001) {
					gl_FragColor = vec4(bilinearCubeUV(envMap, N, mipInt), 1.0);
					return;
				}

				// Tangent space basis for VNDF sampling
				vec3 up = abs(N.z) < 0.999 ? vec3(0.0, 0.0, 1.0) : vec3(1.0, 0.0, 0.0);
				vec3 tangent = normalize(cross(up, N));
				vec3 bitangent = cross(N, tangent);

				for(uint i = 0u; i < uint(GGX_SAMPLES); i++) {
					vec2 Xi = hammersley(i, uint(GGX_SAMPLES));

					// For PMREM, V = N, so in tangent space V is always (0, 0, 1)
					vec3 H_tangent = importanceSampleGGX_VNDF(Xi, vec3(0.0, 0.0, 1.0), roughness);

					// Transform H back to world space
					vec3 H = normalize(tangent * H_tangent.x + bitangent * H_tangent.y + N * H_tangent.z);
					vec3 L = normalize(2.0 * dot(V, H) * H - V);

					float NdotL = max(dot(N, L), 0.0);

					if(NdotL > 0.0) {
						// Sample environment at fixed mip level
						// VNDF importance sampling handles the distribution filtering
						vec3 sampleColor = bilinearCubeUV(envMap, L, mipInt);

						// Weight by NdotL for the split-sum approximation
						// VNDF PDF naturally accounts for the visible microfacet distribution
						prefilteredColor += sampleColor * NdotL;
						totalWeight += NdotL;
					}
				}

				if (totalWeight > 0.0) {
					prefilteredColor = prefilteredColor / totalWeight;
				}

				gl_FragColor = vec4(prefilteredColor, 1.0);
			}
		`,blending:ba,depthTest:!1,depthWrite:!1})}function AT(r,t,n){const s=new Float32Array(Bs),l=new K(0,1,0);return new Ti({name:"SphericalGaussianBlur",defines:{n:Bs,CUBEUV_TEXEL_WIDTH:1/t,CUBEUV_TEXEL_HEIGHT:1/n,CUBEUV_MAX_MIP:`${r}.0`},uniforms:{envMap:{value:null},samples:{value:1},weights:{value:s},latitudinal:{value:!1},dTheta:{value:0},mipInt:{value:0},poleAxis:{value:l}},vertexShader:hu(),fragmentShader:`

			precision mediump float;
			precision mediump int;

			varying vec3 vOutputDirection;

			uniform sampler2D envMap;
			uniform int samples;
			uniform float weights[ n ];
			uniform bool latitudinal;
			uniform float dTheta;
			uniform float mipInt;
			uniform vec3 poleAxis;

			#define ENVMAP_TYPE_CUBE_UV
			#include <cube_uv_reflection_fragment>

			vec3 getSample( float theta, vec3 axis ) {

				float cosTheta = cos( theta );
				// Rodrigues' axis-angle rotation
				vec3 sampleDirection = vOutputDirection * cosTheta
					+ cross( axis, vOutputDirection ) * sin( theta )
					+ axis * dot( axis, vOutputDirection ) * ( 1.0 - cosTheta );

				return bilinearCubeUV( envMap, sampleDirection, mipInt );

			}

			void main() {

				vec3 axis = latitudinal ? poleAxis : cross( poleAxis, vOutputDirection );

				if ( all( equal( axis, vec3( 0.0 ) ) ) ) {

					axis = vec3( vOutputDirection.z, 0.0, - vOutputDirection.x );

				}

				axis = normalize( axis );

				gl_FragColor = vec4( 0.0, 0.0, 0.0, 1.0 );
				gl_FragColor.rgb += weights[ 0 ] * getSample( 0.0, axis );

				for ( int i = 1; i < n; i++ ) {

					if ( i >= samples ) {

						break;

					}

					float theta = dTheta * float( i );
					gl_FragColor.rgb += weights[ i ] * getSample( -1.0 * theta, axis );
					gl_FragColor.rgb += weights[ i ] * getSample( theta, axis );

				}

			}
		`,blending:ba,depthTest:!1,depthWrite:!1})}function o_(){return new Ti({name:"EquirectangularToCubeUV",uniforms:{envMap:{value:null}},vertexShader:hu(),fragmentShader:`

			precision mediump float;
			precision mediump int;

			varying vec3 vOutputDirection;

			uniform sampler2D envMap;

			#include <common>

			void main() {

				vec3 outputDirection = normalize( vOutputDirection );
				vec2 uv = equirectUv( outputDirection );

				gl_FragColor = vec4( texture2D ( envMap, uv ).rgb, 1.0 );

			}
		`,blending:ba,depthTest:!1,depthWrite:!1})}function l_(){return new Ti({name:"CubemapToCubeUV",uniforms:{envMap:{value:null},flipEnvMap:{value:-1}},vertexShader:hu(),fragmentShader:`

			precision mediump float;
			precision mediump int;

			uniform float flipEnvMap;

			varying vec3 vOutputDirection;

			uniform samplerCube envMap;

			void main() {

				gl_FragColor = textureCube( envMap, vec3( flipEnvMap * vOutputDirection.x, vOutputDirection.yz ) );

			}
		`,blending:ba,depthTest:!1,depthWrite:!1})}function hu(){return`

		precision mediump float;
		precision mediump int;

		attribute float faceIndex;

		varying vec3 vOutputDirection;

		// RH coordinate system; PMREM face-indexing convention
		vec3 getDirection( vec2 uv, float face ) {

			uv = 2.0 * uv - 1.0;

			vec3 direction = vec3( uv, 1.0 );

			if ( face == 0.0 ) {

				direction = direction.zyx; // ( 1, v, u ) pos x

			} else if ( face == 1.0 ) {

				direction = direction.xzy;
				direction.xz *= -1.0; // ( -u, 1, -v ) pos y

			} else if ( face == 2.0 ) {

				direction.x *= -1.0; // ( -u, v, 1 ) pos z

			} else if ( face == 3.0 ) {

				direction = direction.zyx;
				direction.xz *= -1.0; // ( -1, v, -u ) neg x

			} else if ( face == 4.0 ) {

				direction = direction.xzy;
				direction.xy *= -1.0; // ( -u, -1, v ) neg y

			} else if ( face == 5.0 ) {

				direction.z *= -1.0; // ( u, v, -1 ) neg z

			}

			return direction;

		}

		void main() {

			vOutputDirection = getDirection( uv, faceIndex );
			gl_Position = vec4( position, 1.0 );

		}
	`}class xx extends Zi{constructor(t=1,n={}){super(t,t,n),this.isWebGLCubeRenderTarget=!0;const s={width:t,height:t,depth:1},l=[s,s,s,s,s,s];this.texture=new ix(l),this._setTextureOptions(n),this.texture.isRenderTargetTexture=!0}fromEquirectangularTexture(t,n){this.texture.type=n.type,this.texture.colorSpace=n.colorSpace,this.texture.generateMipmaps=n.generateMipmaps,this.texture.minFilter=n.minFilter,this.texture.magFilter=n.magFilter;const s={uniforms:{tEquirect:{value:null}},vertexShader:`

				varying vec3 vWorldDirection;

				vec3 transformDirection( in vec3 dir, in mat4 matrix ) {

					return normalize( ( matrix * vec4( dir, 0.0 ) ).xyz );

				}

				void main() {

					vWorldDirection = transformDirection( position, modelMatrix );

					#include <begin_vertex>
					#include <project_vertex>

				}
			`,fragmentShader:`

				uniform sampler2D tEquirect;

				varying vec3 vWorldDirection;

				#include <common>

				void main() {

					vec3 direction = normalize( vWorldDirection );

					vec2 sampleUV = equirectUv( direction );

					gl_FragColor = texture2D( tEquirect, sampleUV );

				}
			`},l=new cs(5,5,5),c=new Ti({name:"CubemapFromEquirect",uniforms:qr(s.uniforms),vertexShader:s.vertexShader,fragmentShader:s.fragmentShader,side:Vn,blending:ba});c.uniforms.tEquirect.value=n;const f=new un(l,c),d=n.minFilter;return n.minFilter===Hs&&(n.minFilter=Bn),new UE(1,10,this).update(t,f),n.minFilter=d,f.geometry.dispose(),f.material.dispose(),this}clear(t,n=!0,s=!0,l=!0){const c=t.getRenderTarget();for(let f=0;f<6;f++)t.setRenderTarget(this,f),t.clear(n,s,l);t.setRenderTarget(c)}}function RT(r){let t=new WeakMap,n=new WeakMap,s=null;function l(g,y=!1){return g==null?null:y?f(g):c(g)}function c(g){if(g&&g.isTexture){const y=g.mapping;if(y===bh||y===Th)if(t.has(g)){const b=t.get(g).texture;return d(b,g.mapping)}else{const b=g.image;if(b&&b.height>0){const w=new xx(b.height);return w.fromEquirectangularTexture(r,g),t.set(g,w),g.addEventListener("dispose",p),d(w.texture,g.mapping)}else return null}}return g}function f(g){if(g&&g.isTexture){const y=g.mapping,b=y===bh||y===Th,w=y===Vs||y===kr;if(b||w){let M=n.get(g);const S=M!==void 0?M.texture.pmremVersion:0;if(g.isRenderTargetTexture&&g.pmremVersion!==S)return s===null&&(s=new s_(r)),M=b?s.fromEquirectangular(g,M):s.fromCubemap(g,M),M.texture.pmremVersion=g.pmremVersion,n.set(g,M),M.texture;if(M!==void 0)return M.texture;{const P=g.image;return b&&P&&P.height>0||w&&P&&m(P)?(s===null&&(s=new s_(r)),M=b?s.fromEquirectangular(g):s.fromCubemap(g),M.texture.pmremVersion=g.pmremVersion,n.set(g,M),g.addEventListener("dispose",v),M.texture):null}}}return g}function d(g,y){return y===bh?g.mapping=Vs:y===Th&&(g.mapping=kr),g}function m(g){let y=0;const b=6;for(let w=0;w<b;w++)g[w]!==void 0&&y++;return y===b}function p(g){const y=g.target;y.removeEventListener("dispose",p);const b=t.get(y);b!==void 0&&(t.delete(y),b.dispose())}function v(g){const y=g.target;y.removeEventListener("dispose",v);const b=n.get(y);b!==void 0&&(n.delete(y),b.dispose())}function _(){t=new WeakMap,n=new WeakMap,s!==null&&(s.dispose(),s=null)}return{get:l,dispose:_}}function CT(r){const t={};function n(s){if(t[s]!==void 0)return t[s];const l=r.getExtension(s);return t[s]=l,l}return{has:function(s){return n(s)!==null},init:function(){n("EXT_color_buffer_float"),n("WEBGL_clip_cull_distance"),n("OES_texture_float_linear"),n("EXT_color_buffer_half_float"),n("WEBGL_multisampled_render_to_texture"),n("WEBGL_render_shared_exponent")},get:function(s){const l=n(s);return l===null&&Hr("WebGLRenderer: "+s+" extension not supported."),l}}}function wT(r,t,n,s){const l={},c=new WeakMap;function f(_){const g=_.target;g.index!==null&&t.remove(g.index);for(const b in g.attributes)t.remove(g.attributes[b]);g.removeEventListener("dispose",f),delete l[g.id];const y=c.get(g);y&&(t.remove(y),c.delete(g)),s.releaseStatesOfGeometry(g),g.isInstancedBufferGeometry===!0&&delete g._maxInstanceCount,n.memory.geometries--}function d(_,g){return l[g.id]===!0||(g.addEventListener("dispose",f),l[g.id]=!0,n.memory.geometries++),g}function m(_){const g=_.attributes;for(const y in g)t.update(g[y],r.ARRAY_BUFFER)}function p(_){const g=[],y=_.index,b=_.attributes.position;let w=0;if(b===void 0)return;if(y!==null){const P=y.array;w=y.version;for(let D=0,A=P.length;D<A;D+=3){const F=P[D+0],O=P[D+1],I=P[D+2];g.push(F,O,O,I,I,F)}}else{const P=b.array;w=b.version;for(let D=0,A=P.length/3-1;D<A;D+=3){const F=D+0,O=D+1,I=D+2;g.push(F,O,O,I,I,F)}}const M=new(b.count>=65535?nx:ex)(g,1);M.version=w;const S=c.get(_);S&&t.remove(S),c.set(_,M)}function v(_){const g=c.get(_);if(g){const y=_.index;y!==null&&g.version<y.version&&p(_)}else p(_);return c.get(_)}return{get:d,update:m,getWireframeAttribute:v}}function DT(r,t,n){let s;function l(_){s=_}let c,f;function d(_){c=_.type,f=_.bytesPerElement}function m(_,g){r.drawElements(s,g,c,_*f),n.update(g,s,1)}function p(_,g,y){y!==0&&(r.drawElementsInstanced(s,g,c,_*f,y),n.update(g,s,y))}function v(_,g,y){if(y===0)return;t.get("WEBGL_multi_draw").multiDrawElementsWEBGL(s,g,0,c,_,0,y);let w=0;for(let M=0;M<y;M++)w+=g[M];n.update(w,s,1)}this.setMode=l,this.setIndex=d,this.render=m,this.renderInstances=p,this.renderMultiDraw=v}function NT(r){const t={geometries:0,textures:0},n={frame:0,calls:0,triangles:0,points:0,lines:0};function s(c,f,d){switch(n.calls++,f){case r.TRIANGLES:n.triangles+=d*(c/3);break;case r.LINES:n.lines+=d*(c/2);break;case r.LINE_STRIP:n.lines+=d*(c-1);break;case r.LINE_LOOP:n.lines+=d*c;break;case r.POINTS:n.points+=d*c;break;default:be("WebGLInfo: Unknown draw mode:",f);break}}function l(){n.calls=0,n.triangles=0,n.points=0,n.lines=0}return{memory:t,render:n,programs:null,autoReset:!0,reset:l,update:s}}function UT(r,t,n){const s=new WeakMap,l=new $e;function c(f,d,m){const p=f.morphTargetInfluences,v=d.morphAttributes.position||d.morphAttributes.normal||d.morphAttributes.color,_=v!==void 0?v.length:0;let g=s.get(d);if(g===void 0||g.count!==_){let X=function(){T.dispose(),s.delete(d),d.removeEventListener("dispose",X)};var y=X;g!==void 0&&g.texture.dispose();const b=d.morphAttributes.position!==void 0,w=d.morphAttributes.normal!==void 0,M=d.morphAttributes.color!==void 0,S=d.morphAttributes.position||[],P=d.morphAttributes.normal||[],D=d.morphAttributes.color||[];let A=0;b===!0&&(A=1),w===!0&&(A=2),M===!0&&(A=3);let F=d.attributes.position.count*A,O=1;F>t.maxTextureSize&&(O=Math.ceil(F/t.maxTextureSize),F=t.maxTextureSize);const I=new Float32Array(F*O*4*_),T=new Q_(I,F,O,_);T.type=Wi,T.needsUpdate=!0;const N=A*4;for(let V=0;V<_;V++){const q=S[V],ct=P[V],ht=D[V],j=F*O*4*V;for(let B=0;B<q.count;B++){const H=B*N;b===!0&&(l.fromBufferAttribute(q,B),I[j+H+0]=l.x,I[j+H+1]=l.y,I[j+H+2]=l.z,I[j+H+3]=0),w===!0&&(l.fromBufferAttribute(ct,B),I[j+H+4]=l.x,I[j+H+5]=l.y,I[j+H+6]=l.z,I[j+H+7]=0),M===!0&&(l.fromBufferAttribute(ht,B),I[j+H+8]=l.x,I[j+H+9]=l.y,I[j+H+10]=l.z,I[j+H+11]=ht.itemSize===4?l.w:1)}}g={count:_,texture:T,size:new qt(F,O)},s.set(d,g),d.addEventListener("dispose",X)}if(f.isInstancedMesh===!0&&f.morphTexture!==null)m.getUniforms().setValue(r,"morphTexture",f.morphTexture,n);else{let b=0;for(let M=0;M<p.length;M++)b+=p[M];const w=d.morphTargetsRelative?1:1-b;m.getUniforms().setValue(r,"morphTargetBaseInfluence",w),m.getUniforms().setValue(r,"morphTargetInfluences",p)}m.getUniforms().setValue(r,"morphTargetsTexture",g.texture,n),m.getUniforms().setValue(r,"morphTargetsTextureSize",g.size)}return{update:c}}function LT(r,t,n,s,l){let c=new WeakMap;function f(p){const v=l.render.frame,_=p.geometry,g=t.get(p,_);if(c.get(g)!==v&&(t.update(g),c.set(g,v)),p.isInstancedMesh&&(p.hasEventListener("dispose",m)===!1&&p.addEventListener("dispose",m),c.get(p)!==v&&(n.update(p.instanceMatrix,r.ARRAY_BUFFER),p.instanceColor!==null&&n.update(p.instanceColor,r.ARRAY_BUFFER),c.set(p,v))),p.isSkinnedMesh){const y=p.skeleton;c.get(y)!==v&&(y.update(),c.set(y,v))}return g}function d(){c=new WeakMap}function m(p){const v=p.target;v.removeEventListener("dispose",m),s.releaseStatesOfObject(v),n.remove(v.instanceMatrix),v.instanceColor!==null&&n.remove(v.instanceColor)}return{update:f,dispose:d}}const OT={[I_]:"LINEAR_TONE_MAPPING",[z_]:"REINHARD_TONE_MAPPING",[F_]:"CINEON_TONE_MAPPING",[B_]:"ACES_FILMIC_TONE_MAPPING",[G_]:"AGX_TONE_MAPPING",[V_]:"NEUTRAL_TONE_MAPPING",[H_]:"CUSTOM_TONE_MAPPING"};function PT(r,t,n,s,l,c){const f=new Zi(t,n,{type:r,depthBuffer:l,stencilBuffer:c,samples:s?4:0,depthTexture:l?new Xr(t,n):void 0}),d=new Zi(t,n,{type:Aa,depthBuffer:!1,stencilBuffer:!1}),m=new Xn;m.setAttribute("position",new Xe([-1,3,0,-1,-1,0,3,-1,0],3)),m.setAttribute("uv",new Xe([0,2,0,0,2,0],2));const p=new RE({uniforms:{tDiffuse:{value:null}},vertexShader:`
			precision highp float;

			uniform mat4 modelViewMatrix;
			uniform mat4 projectionMatrix;

			attribute vec3 position;
			attribute vec2 uv;

			varying vec2 vUv;

			void main() {
				vUv = uv;
				gl_Position = projectionMatrix * modelViewMatrix * vec4( position, 1.0 );
			}`,fragmentShader:`
			precision highp float;

			uniform sampler2D tDiffuse;

			varying vec2 vUv;

			#include <tonemapping_pars_fragment>
			#include <colorspace_pars_fragment>

			void main() {
				gl_FragColor = texture2D( tDiffuse, vUv );

				#ifdef LINEAR_TONE_MAPPING
					gl_FragColor.rgb = LinearToneMapping( gl_FragColor.rgb );
				#elif defined( REINHARD_TONE_MAPPING )
					gl_FragColor.rgb = ReinhardToneMapping( gl_FragColor.rgb );
				#elif defined( CINEON_TONE_MAPPING )
					gl_FragColor.rgb = CineonToneMapping( gl_FragColor.rgb );
				#elif defined( ACES_FILMIC_TONE_MAPPING )
					gl_FragColor.rgb = ACESFilmicToneMapping( gl_FragColor.rgb );
				#elif defined( AGX_TONE_MAPPING )
					gl_FragColor.rgb = AgXToneMapping( gl_FragColor.rgb );
				#elif defined( NEUTRAL_TONE_MAPPING )
					gl_FragColor.rgb = NeutralToneMapping( gl_FragColor.rgb );
				#elif defined( CUSTOM_TONE_MAPPING )
					gl_FragColor.rgb = CustomToneMapping( gl_FragColor.rgb );
				#endif

				#ifdef SRGB_TRANSFER
					gl_FragColor = sRGBTransferOETF( gl_FragColor );
				#endif
			}`,depthTest:!1,depthWrite:!1}),v=new un(m,p),_=new fu(-1,1,1,-1,0,1);let g=null,y=null,b=!1,w,M=null,S=[],P=!1;this.setSize=function(D,A){f.setSize(D,A),d.setSize(D,A);for(let F=0;F<S.length;F++){const O=S[F];O.setSize&&O.setSize(D,A)}},this.setEffects=function(D){S=D,P=S.length>0&&S[0].isRenderPass===!0;const A=f.width,F=f.height;for(let O=0;O<S.length;O++){const I=S[O];I.setSize&&I.setSize(A,F)}},this.begin=function(D,A){if(b||D.toneMapping===Yi&&S.length===0)return!1;if(M=A,A!==null){const F=A.width,O=A.height;(f.width!==F||f.height!==O)&&this.setSize(F,O)}return P===!1&&D.setRenderTarget(f),w=D.toneMapping,D.toneMapping=Yi,!0},this.hasRenderPass=function(){return P},this.end=function(D,A){D.toneMapping=w,b=!0;let F=f,O=d;for(let I=0;I<S.length;I++){const T=S[I];if(T.enabled!==!1&&(T.render(D,O,F,A),T.needsSwap!==!1)){const N=F;F=O,O=N}}if(g!==D.outputColorSpace||y!==D.toneMapping){g=D.outputColorSpace,y=D.toneMapping,p.defines={},Ee.getTransfer(g)===ze&&(p.defines.SRGB_TRANSFER="");const I=OT[y];I&&(p.defines[I]=""),p.needsUpdate=!0}p.uniforms.tDiffuse.value=F.texture,D.setRenderTarget(M),D.render(v,_),M=null,b=!1},this.isCompositing=function(){return b},this.dispose=function(){f.depthTexture&&f.depthTexture.dispose(),f.dispose(),d.dispose(),m.dispose(),p.dispose()}}const Sx=new kn,tp=new Xr(1,1),yx=new Q_,Mx=new AM,Ex=new ix,c_=[],u_=[],f_=new Float32Array(16),h_=new Float32Array(9),d_=new Float32Array(4);function Kr(r,t,n){const s=r[0];if(s<=0||s>0)return r;const l=t*n;let c=c_[l];if(c===void 0&&(c=new Float32Array(l),c_[l]=c),t!==0){s.toArray(c,0);for(let f=1,d=0;f!==t;++f)d+=n,r[f].toArray(c,d)}return c}function En(r,t){if(r.length!==t.length)return!1;for(let n=0,s=r.length;n<s;n++)if(r[n]!==t[n])return!1;return!0}function bn(r,t){for(let n=0,s=t.length;n<s;n++)r[n]=t[n]}function du(r,t){let n=u_[t];n===void 0&&(n=new Int32Array(t),u_[t]=n);for(let s=0;s!==t;++s)n[s]=r.allocateTextureUnit();return n}function IT(r,t){const n=this.cache;n[0]!==t&&(r.uniform1f(this.addr,t),n[0]=t)}function zT(r,t){const n=this.cache;if(t.x!==void 0)(n[0]!==t.x||n[1]!==t.y)&&(r.uniform2f(this.addr,t.x,t.y),n[0]=t.x,n[1]=t.y);else{if(En(n,t))return;r.uniform2fv(this.addr,t),bn(n,t)}}function FT(r,t){const n=this.cache;if(t.x!==void 0)(n[0]!==t.x||n[1]!==t.y||n[2]!==t.z)&&(r.uniform3f(this.addr,t.x,t.y,t.z),n[0]=t.x,n[1]=t.y,n[2]=t.z);else if(t.r!==void 0)(n[0]!==t.r||n[1]!==t.g||n[2]!==t.b)&&(r.uniform3f(this.addr,t.r,t.g,t.b),n[0]=t.r,n[1]=t.g,n[2]=t.b);else{if(En(n,t))return;r.uniform3fv(this.addr,t),bn(n,t)}}function BT(r,t){const n=this.cache;if(t.x!==void 0)(n[0]!==t.x||n[1]!==t.y||n[2]!==t.z||n[3]!==t.w)&&(r.uniform4f(this.addr,t.x,t.y,t.z,t.w),n[0]=t.x,n[1]=t.y,n[2]=t.z,n[3]=t.w);else{if(En(n,t))return;r.uniform4fv(this.addr,t),bn(n,t)}}function HT(r,t){const n=this.cache,s=t.elements;if(s===void 0){if(En(n,t))return;r.uniformMatrix2fv(this.addr,!1,t),bn(n,t)}else{if(En(n,s))return;d_.set(s),r.uniformMatrix2fv(this.addr,!1,d_),bn(n,s)}}function GT(r,t){const n=this.cache,s=t.elements;if(s===void 0){if(En(n,t))return;r.uniformMatrix3fv(this.addr,!1,t),bn(n,t)}else{if(En(n,s))return;h_.set(s),r.uniformMatrix3fv(this.addr,!1,h_),bn(n,s)}}function VT(r,t){const n=this.cache,s=t.elements;if(s===void 0){if(En(n,t))return;r.uniformMatrix4fv(this.addr,!1,t),bn(n,t)}else{if(En(n,s))return;f_.set(s),r.uniformMatrix4fv(this.addr,!1,f_),bn(n,s)}}function kT(r,t){const n=this.cache;n[0]!==t&&(r.uniform1i(this.addr,t),n[0]=t)}function XT(r,t){const n=this.cache;if(t.x!==void 0)(n[0]!==t.x||n[1]!==t.y)&&(r.uniform2i(this.addr,t.x,t.y),n[0]=t.x,n[1]=t.y);else{if(En(n,t))return;r.uniform2iv(this.addr,t),bn(n,t)}}function WT(r,t){const n=this.cache;if(t.x!==void 0)(n[0]!==t.x||n[1]!==t.y||n[2]!==t.z)&&(r.uniform3i(this.addr,t.x,t.y,t.z),n[0]=t.x,n[1]=t.y,n[2]=t.z);else{if(En(n,t))return;r.uniform3iv(this.addr,t),bn(n,t)}}function qT(r,t){const n=this.cache;if(t.x!==void 0)(n[0]!==t.x||n[1]!==t.y||n[2]!==t.z||n[3]!==t.w)&&(r.uniform4i(this.addr,t.x,t.y,t.z,t.w),n[0]=t.x,n[1]=t.y,n[2]=t.z,n[3]=t.w);else{if(En(n,t))return;r.uniform4iv(this.addr,t),bn(n,t)}}function YT(r,t){const n=this.cache;n[0]!==t&&(r.uniform1ui(this.addr,t),n[0]=t)}function ZT(r,t){const n=this.cache;if(t.x!==void 0)(n[0]!==t.x||n[1]!==t.y)&&(r.uniform2ui(this.addr,t.x,t.y),n[0]=t.x,n[1]=t.y);else{if(En(n,t))return;r.uniform2uiv(this.addr,t),bn(n,t)}}function KT(r,t){const n=this.cache;if(t.x!==void 0)(n[0]!==t.x||n[1]!==t.y||n[2]!==t.z)&&(r.uniform3ui(this.addr,t.x,t.y,t.z),n[0]=t.x,n[1]=t.y,n[2]=t.z);else{if(En(n,t))return;r.uniform3uiv(this.addr,t),bn(n,t)}}function jT(r,t){const n=this.cache;if(t.x!==void 0)(n[0]!==t.x||n[1]!==t.y||n[2]!==t.z||n[3]!==t.w)&&(r.uniform4ui(this.addr,t.x,t.y,t.z,t.w),n[0]=t.x,n[1]=t.y,n[2]=t.z,n[3]=t.w);else{if(En(n,t))return;r.uniform4uiv(this.addr,t),bn(n,t)}}function JT(r,t,n){const s=this.cache,l=n.allocateTextureUnit();s[0]!==l&&(r.uniform1i(this.addr,l),s[0]=l);let c;this.type===r.SAMPLER_2D_SHADOW?(tp.compareFunction=n.isReversedDepthBuffer()?hp:fp,c=tp):c=Sx,n.setTexture2D(t||c,l)}function QT(r,t,n){const s=this.cache,l=n.allocateTextureUnit();s[0]!==l&&(r.uniform1i(this.addr,l),s[0]=l),n.setTexture3D(t||Mx,l)}function $T(r,t,n){const s=this.cache,l=n.allocateTextureUnit();s[0]!==l&&(r.uniform1i(this.addr,l),s[0]=l),n.setTextureCube(t||Ex,l)}function tA(r,t,n){const s=this.cache,l=n.allocateTextureUnit();s[0]!==l&&(r.uniform1i(this.addr,l),s[0]=l),n.setTexture2DArray(t||yx,l)}function eA(r){switch(r){case 5126:return IT;case 35664:return zT;case 35665:return FT;case 35666:return BT;case 35674:return HT;case 35675:return GT;case 35676:return VT;case 5124:case 35670:return kT;case 35667:case 35671:return XT;case 35668:case 35672:return WT;case 35669:case 35673:return qT;case 5125:return YT;case 36294:return ZT;case 36295:return KT;case 36296:return jT;case 35678:case 36198:case 36298:case 36306:case 35682:return JT;case 35679:case 36299:case 36307:return QT;case 35680:case 36300:case 36308:case 36293:return $T;case 36289:case 36303:case 36311:case 36292:return tA}}function nA(r,t){r.uniform1fv(this.addr,t)}function iA(r,t){const n=Kr(t,this.size,2);r.uniform2fv(this.addr,n)}function aA(r,t){const n=Kr(t,this.size,3);r.uniform3fv(this.addr,n)}function sA(r,t){const n=Kr(t,this.size,4);r.uniform4fv(this.addr,n)}function rA(r,t){const n=Kr(t,this.size,4);r.uniformMatrix2fv(this.addr,!1,n)}function oA(r,t){const n=Kr(t,this.size,9);r.uniformMatrix3fv(this.addr,!1,n)}function lA(r,t){const n=Kr(t,this.size,16);r.uniformMatrix4fv(this.addr,!1,n)}function cA(r,t){r.uniform1iv(this.addr,t)}function uA(r,t){r.uniform2iv(this.addr,t)}function fA(r,t){r.uniform3iv(this.addr,t)}function hA(r,t){r.uniform4iv(this.addr,t)}function dA(r,t){r.uniform1uiv(this.addr,t)}function pA(r,t){r.uniform2uiv(this.addr,t)}function mA(r,t){r.uniform3uiv(this.addr,t)}function gA(r,t){r.uniform4uiv(this.addr,t)}function vA(r,t,n){const s=this.cache,l=t.length,c=du(n,l);En(s,c)||(r.uniform1iv(this.addr,c),bn(s,c));let f;this.type===r.SAMPLER_2D_SHADOW?f=tp:f=Sx;for(let d=0;d!==l;++d)n.setTexture2D(t[d]||f,c[d])}function _A(r,t,n){const s=this.cache,l=t.length,c=du(n,l);En(s,c)||(r.uniform1iv(this.addr,c),bn(s,c));for(let f=0;f!==l;++f)n.setTexture3D(t[f]||Mx,c[f])}function xA(r,t,n){const s=this.cache,l=t.length,c=du(n,l);En(s,c)||(r.uniform1iv(this.addr,c),bn(s,c));for(let f=0;f!==l;++f)n.setTextureCube(t[f]||Ex,c[f])}function SA(r,t,n){const s=this.cache,l=t.length,c=du(n,l);En(s,c)||(r.uniform1iv(this.addr,c),bn(s,c));for(let f=0;f!==l;++f)n.setTexture2DArray(t[f]||yx,c[f])}function yA(r){switch(r){case 5126:return nA;case 35664:return iA;case 35665:return aA;case 35666:return sA;case 35674:return rA;case 35675:return oA;case 35676:return lA;case 5124:case 35670:return cA;case 35667:case 35671:return uA;case 35668:case 35672:return fA;case 35669:case 35673:return hA;case 5125:return dA;case 36294:return pA;case 36295:return mA;case 36296:return gA;case 35678:case 36198:case 36298:case 36306:case 35682:return vA;case 35679:case 36299:case 36307:return _A;case 35680:case 36300:case 36308:case 36293:return xA;case 36289:case 36303:case 36311:case 36292:return SA}}class MA{constructor(t,n,s){this.id=t,this.addr=s,this.cache=[],this.type=n.type,this.setValue=eA(n.type)}}class EA{constructor(t,n,s){this.id=t,this.addr=s,this.cache=[],this.type=n.type,this.size=n.size,this.setValue=yA(n.type)}}class bA{constructor(t){this.id=t,this.seq=[],this.map={}}setValue(t,n,s){const l=this.seq;for(let c=0,f=l.length;c!==f;++c){const d=l[c];d.setValue(t,n[d.id],s)}}}const sd=/(\w+)(\])?(\[|\.)?/g;function p_(r,t){r.seq.push(t),r.map[t.id]=t}function TA(r,t,n){const s=r.name,l=s.length;for(sd.lastIndex=0;;){const c=sd.exec(s),f=sd.lastIndex;let d=c[1];const m=c[2]==="]",p=c[3];if(m&&(d=d|0),p===void 0||p==="["&&f+2===l){p_(n,p===void 0?new MA(d,r,t):new EA(d,r,t));break}else{let _=n.map[d];_===void 0&&(_=new bA(d),p_(n,_)),n=_}}}class tu{constructor(t,n){this.seq=[],this.map={};const s=t.getProgramParameter(n,t.ACTIVE_UNIFORMS);for(let f=0;f<s;++f){const d=t.getActiveUniform(n,f),m=t.getUniformLocation(n,d.name);TA(d,m,this)}const l=[],c=[];for(const f of this.seq)f.type===t.SAMPLER_2D_SHADOW||f.type===t.SAMPLER_CUBE_SHADOW||f.type===t.SAMPLER_2D_ARRAY_SHADOW?l.push(f):c.push(f);l.length>0&&(this.seq=l.concat(c))}setValue(t,n,s,l){const c=this.map[n];c!==void 0&&c.setValue(t,s,l)}setOptional(t,n,s){const l=n[s];l!==void 0&&this.setValue(t,s,l)}static upload(t,n,s,l){for(let c=0,f=n.length;c!==f;++c){const d=n[c],m=s[d.id];m.needsUpdate!==!1&&d.setValue(t,m.value,l)}}static seqWithValue(t,n){const s=[];for(let l=0,c=t.length;l!==c;++l){const f=t[l];f.id in n&&s.push(f)}return s}}function m_(r,t,n){const s=r.createShader(t);return r.shaderSource(s,n),r.compileShader(s),s}const AA=37297;let RA=0;function CA(r,t){const n=r.split(`
`),s=[],l=Math.max(t-6,0),c=Math.min(t+6,n.length);for(let f=l;f<c;f++){const d=f+1;s.push(`${d===t?">":" "} ${d}: ${n[f]}`)}return s.join(`
`)}const g_=new re;function wA(r){Ee._getMatrix(g_,Ee.workingColorSpace,r);const t=`mat3( ${g_.elements.map(n=>n.toFixed(4))} )`;switch(Ee.getTransfer(r)){case su:return[t,"LinearTransferOETF"];case ze:return[t,"sRGBTransferOETF"];default:return ie("WebGLProgram: Unsupported color space: ",r),[t,"LinearTransferOETF"]}}function v_(r,t,n){const s=r.getShaderParameter(t,r.COMPILE_STATUS),c=(r.getShaderInfoLog(t)||"").trim();if(s&&c==="")return"";const f=/ERROR: 0:(\d+)/.exec(c);if(f){const d=parseInt(f[1]);return n.toUpperCase()+`

`+c+`

`+CA(r.getShaderSource(t),d)}else return c}function DA(r,t){const n=wA(t);return[`vec4 ${r}( vec4 value ) {`,`	return ${n[1]}( vec4( value.rgb * ${n[0]}, value.a ) );`,"}"].join(`
`)}const NA={[I_]:"Linear",[z_]:"Reinhard",[F_]:"Cineon",[B_]:"ACESFilmic",[G_]:"AgX",[V_]:"Neutral",[H_]:"Custom"};function UA(r,t){const n=NA[t];return n===void 0?(ie("WebGLProgram: Unsupported toneMapping:",t),"vec3 "+r+"( vec3 color ) { return LinearToneMapping( color ); }"):"vec3 "+r+"( vec3 color ) { return "+n+"ToneMapping( color ); }"}const qc=new K;function LA(){Ee.getLuminanceCoefficients(qc);const r=qc.x.toFixed(4),t=qc.y.toFixed(4),n=qc.z.toFixed(4);return["float luminance( const in vec3 rgb ) {",`	const vec3 weights = vec3( ${r}, ${t}, ${n} );`,"	return dot( weights, rgb );","}"].join(`
`)}function OA(r){return[r.extensionClipCullDistance?"#extension GL_ANGLE_clip_cull_distance : require":"",r.extensionMultiDraw?"#extension GL_ANGLE_multi_draw : require":""].filter(Qo).join(`
`)}function PA(r){const t=[];for(const n in r){const s=r[n];s!==!1&&t.push("#define "+n+" "+s)}return t.join(`
`)}function IA(r,t){const n={},s=r.getProgramParameter(t,r.ACTIVE_ATTRIBUTES);for(let l=0;l<s;l++){const c=r.getActiveAttrib(t,l),f=c.name;let d=1;c.type===r.FLOAT_MAT2&&(d=2),c.type===r.FLOAT_MAT3&&(d=3),c.type===r.FLOAT_MAT4&&(d=4),n[f]={type:c.type,location:r.getAttribLocation(t,f),locationSize:d}}return n}function Qo(r){return r!==""}function __(r,t){const n=t.numSpotLightShadows+t.numSpotLightMaps-t.numSpotLightShadowsWithMaps;return r.replace(/NUM_DIR_LIGHTS/g,t.numDirLights).replace(/NUM_SPOT_LIGHTS/g,t.numSpotLights).replace(/NUM_SPOT_LIGHT_MAPS/g,t.numSpotLightMaps).replace(/NUM_SPOT_LIGHT_COORDS/g,n).replace(/NUM_RECT_AREA_LIGHTS/g,t.numRectAreaLights).replace(/NUM_POINT_LIGHTS/g,t.numPointLights).replace(/NUM_HEMI_LIGHTS/g,t.numHemiLights).replace(/NUM_DIR_LIGHT_SHADOWS/g,t.numDirLightShadows).replace(/NUM_SPOT_LIGHT_SHADOWS_WITH_MAPS/g,t.numSpotLightShadowsWithMaps).replace(/NUM_SPOT_LIGHT_SHADOWS/g,t.numSpotLightShadows).replace(/NUM_POINT_LIGHT_SHADOWS/g,t.numPointLightShadows)}function x_(r,t){return r.replace(/NUM_CLIPPING_PLANES/g,t.numClippingPlanes).replace(/UNION_CLIPPING_PLANES/g,t.numClippingPlanes-t.numClipIntersection)}const zA=/^[ \t]*#include +<([\w\d./]+)>/gm;function ep(r){return r.replace(zA,BA)}const FA=new Map;function BA(r,t){let n=ue[t];if(n===void 0){const s=FA.get(t);if(s!==void 0)n=ue[s],ie('WebGLRenderer: Shader chunk "%s" has been deprecated. Use "%s" instead.',t,s);else throw new Error("THREE.WebGLProgram: Can not resolve #include <"+t+">")}return ep(n)}const HA=/#pragma unroll_loop_start\s+for\s*\(\s*int\s+i\s*=\s*(\d+)\s*;\s*i\s*<\s*(\d+)\s*;\s*i\s*\+\+\s*\)\s*{([\s\S]+?)}\s+#pragma unroll_loop_end/g;function S_(r){return r.replace(HA,GA)}function GA(r,t,n,s){let l="";for(let c=parseInt(t);c<parseInt(n);c++)l+=s.replace(/\[\s*i\s*\]/g,"[ "+c+" ]").replace(/UNROLLED_LOOP_INDEX/g,c);return l}function y_(r){let t=`precision ${r.precision} float;
	precision ${r.precision} int;
	precision ${r.precision} sampler2D;
	precision ${r.precision} samplerCube;
	precision ${r.precision} sampler3D;
	precision ${r.precision} sampler2DArray;
	precision ${r.precision} sampler2DShadow;
	precision ${r.precision} samplerCubeShadow;
	precision ${r.precision} sampler2DArrayShadow;
	precision ${r.precision} isampler2D;
	precision ${r.precision} isampler3D;
	precision ${r.precision} isamplerCube;
	precision ${r.precision} isampler2DArray;
	precision ${r.precision} usampler2D;
	precision ${r.precision} usampler3D;
	precision ${r.precision} usamplerCube;
	precision ${r.precision} usampler2DArray;
	`;return r.precision==="highp"?t+=`
#define HIGH_PRECISION`:r.precision==="mediump"?t+=`
#define MEDIUM_PRECISION`:r.precision==="lowp"&&(t+=`
#define LOW_PRECISION`),t}const VA={[Kc]:"SHADOWMAP_TYPE_PCF",[jo]:"SHADOWMAP_TYPE_VSM"};function kA(r){return VA[r.shadowMapType]||"SHADOWMAP_TYPE_BASIC"}const XA={[Vs]:"ENVMAP_TYPE_CUBE",[kr]:"ENVMAP_TYPE_CUBE",[uu]:"ENVMAP_TYPE_CUBE_UV"};function WA(r){return r.envMap===!1?"ENVMAP_TYPE_CUBE":XA[r.envMapMode]||"ENVMAP_TYPE_CUBE"}const qA={[kr]:"ENVMAP_MODE_REFRACTION"};function YA(r){return r.envMap===!1?"ENVMAP_MODE_REFLECTION":qA[r.envMapMode]||"ENVMAP_MODE_REFLECTION"}const ZA={[P_]:"ENVMAP_BLENDING_MULTIPLY",[sM]:"ENVMAP_BLENDING_MIX",[rM]:"ENVMAP_BLENDING_ADD"};function KA(r){return r.envMap===!1?"ENVMAP_BLENDING_NONE":ZA[r.combine]||"ENVMAP_BLENDING_NONE"}function jA(r){const t=r.envMapCubeUVHeight;if(t===null)return null;const n=Math.log2(t)-2,s=1/t;return{texelWidth:1/(3*Math.max(Math.pow(2,n),112)),texelHeight:s,maxMip:n}}function JA(r,t,n,s){const l=r.getContext(),c=n.defines;let f=n.vertexShader,d=n.fragmentShader;const m=kA(n),p=WA(n),v=YA(n),_=KA(n),g=jA(n),y=OA(n),b=PA(c),w=l.createProgram();let M,S,P=n.glslVersion?"#version "+n.glslVersion+`
`:"";n.isRawShaderMaterial?(M=["#define SHADER_TYPE "+n.shaderType,"#define SHADER_NAME "+n.shaderName,b].filter(Qo).join(`
`),M.length>0&&(M+=`
`),S=["#define SHADER_TYPE "+n.shaderType,"#define SHADER_NAME "+n.shaderName,b].filter(Qo).join(`
`),S.length>0&&(S+=`
`)):(M=[y_(n),"#define SHADER_TYPE "+n.shaderType,"#define SHADER_NAME "+n.shaderName,b,n.extensionClipCullDistance?"#define USE_CLIP_DISTANCE":"",n.batching?"#define USE_BATCHING":"",n.batchingColor?"#define USE_BATCHING_COLOR":"",n.instancing?"#define USE_INSTANCING":"",n.instancingColor?"#define USE_INSTANCING_COLOR":"",n.instancingMorph?"#define USE_INSTANCING_MORPH":"",n.useFog&&n.fog?"#define USE_FOG":"",n.useFog&&n.fogExp2?"#define FOG_EXP2":"",n.map?"#define USE_MAP":"",n.envMap?"#define USE_ENVMAP":"",n.envMap?"#define "+v:"",n.lightMap?"#define USE_LIGHTMAP":"",n.aoMap?"#define USE_AOMAP":"",n.bumpMap?"#define USE_BUMPMAP":"",n.normalMap?"#define USE_NORMALMAP":"",n.normalMapObjectSpace?"#define USE_NORMALMAP_OBJECTSPACE":"",n.normalMapTangentSpace?"#define USE_NORMALMAP_TANGENTSPACE":"",n.displacementMap?"#define USE_DISPLACEMENTMAP":"",n.emissiveMap?"#define USE_EMISSIVEMAP":"",n.anisotropy?"#define USE_ANISOTROPY":"",n.anisotropyMap?"#define USE_ANISOTROPYMAP":"",n.clearcoatMap?"#define USE_CLEARCOATMAP":"",n.clearcoatRoughnessMap?"#define USE_CLEARCOAT_ROUGHNESSMAP":"",n.clearcoatNormalMap?"#define USE_CLEARCOAT_NORMALMAP":"",n.iridescenceMap?"#define USE_IRIDESCENCEMAP":"",n.iridescenceThicknessMap?"#define USE_IRIDESCENCE_THICKNESSMAP":"",n.specularMap?"#define USE_SPECULARMAP":"",n.specularColorMap?"#define USE_SPECULAR_COLORMAP":"",n.specularIntensityMap?"#define USE_SPECULAR_INTENSITYMAP":"",n.roughnessMap?"#define USE_ROUGHNESSMAP":"",n.metalnessMap?"#define USE_METALNESSMAP":"",n.alphaMap?"#define USE_ALPHAMAP":"",n.alphaHash?"#define USE_ALPHAHASH":"",n.transmission?"#define USE_TRANSMISSION":"",n.transmissionMap?"#define USE_TRANSMISSIONMAP":"",n.thicknessMap?"#define USE_THICKNESSMAP":"",n.sheenColorMap?"#define USE_SHEEN_COLORMAP":"",n.sheenRoughnessMap?"#define USE_SHEEN_ROUGHNESSMAP":"",n.mapUv?"#define MAP_UV "+n.mapUv:"",n.alphaMapUv?"#define ALPHAMAP_UV "+n.alphaMapUv:"",n.lightMapUv?"#define LIGHTMAP_UV "+n.lightMapUv:"",n.aoMapUv?"#define AOMAP_UV "+n.aoMapUv:"",n.emissiveMapUv?"#define EMISSIVEMAP_UV "+n.emissiveMapUv:"",n.bumpMapUv?"#define BUMPMAP_UV "+n.bumpMapUv:"",n.normalMapUv?"#define NORMALMAP_UV "+n.normalMapUv:"",n.displacementMapUv?"#define DISPLACEMENTMAP_UV "+n.displacementMapUv:"",n.metalnessMapUv?"#define METALNESSMAP_UV "+n.metalnessMapUv:"",n.roughnessMapUv?"#define ROUGHNESSMAP_UV "+n.roughnessMapUv:"",n.anisotropyMapUv?"#define ANISOTROPYMAP_UV "+n.anisotropyMapUv:"",n.clearcoatMapUv?"#define CLEARCOATMAP_UV "+n.clearcoatMapUv:"",n.clearcoatNormalMapUv?"#define CLEARCOAT_NORMALMAP_UV "+n.clearcoatNormalMapUv:"",n.clearcoatRoughnessMapUv?"#define CLEARCOAT_ROUGHNESSMAP_UV "+n.clearcoatRoughnessMapUv:"",n.iridescenceMapUv?"#define IRIDESCENCEMAP_UV "+n.iridescenceMapUv:"",n.iridescenceThicknessMapUv?"#define IRIDESCENCE_THICKNESSMAP_UV "+n.iridescenceThicknessMapUv:"",n.sheenColorMapUv?"#define SHEEN_COLORMAP_UV "+n.sheenColorMapUv:"",n.sheenRoughnessMapUv?"#define SHEEN_ROUGHNESSMAP_UV "+n.sheenRoughnessMapUv:"",n.specularMapUv?"#define SPECULARMAP_UV "+n.specularMapUv:"",n.specularColorMapUv?"#define SPECULAR_COLORMAP_UV "+n.specularColorMapUv:"",n.specularIntensityMapUv?"#define SPECULAR_INTENSITYMAP_UV "+n.specularIntensityMapUv:"",n.transmissionMapUv?"#define TRANSMISSIONMAP_UV "+n.transmissionMapUv:"",n.thicknessMapUv?"#define THICKNESSMAP_UV "+n.thicknessMapUv:"",n.vertexTangents&&n.flatShading===!1?"#define USE_TANGENT":"",n.vertexNormals?"#define HAS_NORMAL":"",n.vertexColors?"#define USE_COLOR":"",n.vertexAlphas?"#define USE_COLOR_ALPHA":"",n.vertexUv1s?"#define USE_UV1":"",n.vertexUv2s?"#define USE_UV2":"",n.vertexUv3s?"#define USE_UV3":"",n.pointsUvs?"#define USE_POINTS_UV":"",n.flatShading?"#define FLAT_SHADED":"",n.skinning?"#define USE_SKINNING":"",n.morphTargets?"#define USE_MORPHTARGETS":"",n.morphNormals&&n.flatShading===!1?"#define USE_MORPHNORMALS":"",n.morphColors?"#define USE_MORPHCOLORS":"",n.morphTargetsCount>0?"#define MORPHTARGETS_TEXTURE_STRIDE "+n.morphTextureStride:"",n.morphTargetsCount>0?"#define MORPHTARGETS_COUNT "+n.morphTargetsCount:"",n.doubleSided?"#define DOUBLE_SIDED":"",n.flipSided?"#define FLIP_SIDED":"",n.shadowMapEnabled?"#define USE_SHADOWMAP":"",n.shadowMapEnabled?"#define "+m:"",n.sizeAttenuation?"#define USE_SIZEATTENUATION":"",n.numLightProbes>0?"#define USE_LIGHT_PROBES":"",n.logarithmicDepthBuffer?"#define USE_LOGARITHMIC_DEPTH_BUFFER":"",n.reversedDepthBuffer?"#define USE_REVERSED_DEPTH_BUFFER":"","uniform mat4 modelMatrix;","uniform mat4 modelViewMatrix;","uniform mat4 projectionMatrix;","uniform mat4 viewMatrix;","uniform mat3 normalMatrix;","uniform vec3 cameraPosition;","uniform bool isOrthographic;","#ifdef USE_INSTANCING","	attribute mat4 instanceMatrix;","#endif","#ifdef USE_INSTANCING_COLOR","	attribute vec3 instanceColor;","#endif","#ifdef USE_INSTANCING_MORPH","	uniform sampler2D morphTexture;","#endif","attribute vec3 position;","attribute vec3 normal;","attribute vec2 uv;","#ifdef USE_UV1","	attribute vec2 uv1;","#endif","#ifdef USE_UV2","	attribute vec2 uv2;","#endif","#ifdef USE_UV3","	attribute vec2 uv3;","#endif","#ifdef USE_TANGENT","	attribute vec4 tangent;","#endif","#if defined( USE_COLOR_ALPHA )","	attribute vec4 color;","#elif defined( USE_COLOR )","	attribute vec3 color;","#endif","#ifdef USE_SKINNING","	attribute vec4 skinIndex;","	attribute vec4 skinWeight;","#endif",`
`].filter(Qo).join(`
`),S=[y_(n),"#define SHADER_TYPE "+n.shaderType,"#define SHADER_NAME "+n.shaderName,b,n.useFog&&n.fog?"#define USE_FOG":"",n.useFog&&n.fogExp2?"#define FOG_EXP2":"",n.alphaToCoverage?"#define ALPHA_TO_COVERAGE":"",n.map?"#define USE_MAP":"",n.matcap?"#define USE_MATCAP":"",n.envMap?"#define USE_ENVMAP":"",n.envMap?"#define "+p:"",n.envMap?"#define "+v:"",n.envMap?"#define "+_:"",g?"#define CUBEUV_TEXEL_WIDTH "+g.texelWidth:"",g?"#define CUBEUV_TEXEL_HEIGHT "+g.texelHeight:"",g?"#define CUBEUV_MAX_MIP "+g.maxMip+".0":"",n.lightMap?"#define USE_LIGHTMAP":"",n.aoMap?"#define USE_AOMAP":"",n.bumpMap?"#define USE_BUMPMAP":"",n.normalMap?"#define USE_NORMALMAP":"",n.normalMapObjectSpace?"#define USE_NORMALMAP_OBJECTSPACE":"",n.normalMapTangentSpace?"#define USE_NORMALMAP_TANGENTSPACE":"",n.packedNormalMap?"#define USE_PACKED_NORMALMAP":"",n.emissiveMap?"#define USE_EMISSIVEMAP":"",n.anisotropy?"#define USE_ANISOTROPY":"",n.anisotropyMap?"#define USE_ANISOTROPYMAP":"",n.clearcoat?"#define USE_CLEARCOAT":"",n.clearcoatMap?"#define USE_CLEARCOATMAP":"",n.clearcoatRoughnessMap?"#define USE_CLEARCOAT_ROUGHNESSMAP":"",n.clearcoatNormalMap?"#define USE_CLEARCOAT_NORMALMAP":"",n.dispersion?"#define USE_DISPERSION":"",n.iridescence?"#define USE_IRIDESCENCE":"",n.iridescenceMap?"#define USE_IRIDESCENCEMAP":"",n.iridescenceThicknessMap?"#define USE_IRIDESCENCE_THICKNESSMAP":"",n.specularMap?"#define USE_SPECULARMAP":"",n.specularColorMap?"#define USE_SPECULAR_COLORMAP":"",n.specularIntensityMap?"#define USE_SPECULAR_INTENSITYMAP":"",n.roughnessMap?"#define USE_ROUGHNESSMAP":"",n.metalnessMap?"#define USE_METALNESSMAP":"",n.alphaMap?"#define USE_ALPHAMAP":"",n.alphaTest?"#define USE_ALPHATEST":"",n.alphaHash?"#define USE_ALPHAHASH":"",n.sheen?"#define USE_SHEEN":"",n.sheenColorMap?"#define USE_SHEEN_COLORMAP":"",n.sheenRoughnessMap?"#define USE_SHEEN_ROUGHNESSMAP":"",n.transmission?"#define USE_TRANSMISSION":"",n.transmissionMap?"#define USE_TRANSMISSIONMAP":"",n.thicknessMap?"#define USE_THICKNESSMAP":"",n.vertexTangents&&n.flatShading===!1?"#define USE_TANGENT":"",n.vertexColors||n.instancingColor?"#define USE_COLOR":"",n.vertexAlphas||n.batchingColor?"#define USE_COLOR_ALPHA":"",n.vertexUv1s?"#define USE_UV1":"",n.vertexUv2s?"#define USE_UV2":"",n.vertexUv3s?"#define USE_UV3":"",n.pointsUvs?"#define USE_POINTS_UV":"",n.gradientMap?"#define USE_GRADIENTMAP":"",n.flatShading?"#define FLAT_SHADED":"",n.doubleSided?"#define DOUBLE_SIDED":"",n.flipSided?"#define FLIP_SIDED":"",n.shadowMapEnabled?"#define USE_SHADOWMAP":"",n.shadowMapEnabled?"#define "+m:"",n.premultipliedAlpha?"#define PREMULTIPLIED_ALPHA":"",n.numLightProbes>0?"#define USE_LIGHT_PROBES":"",n.numLightProbeGrids>0?"#define USE_LIGHT_PROBES_GRID":"",n.decodeVideoTexture?"#define DECODE_VIDEO_TEXTURE":"",n.decodeVideoTextureEmissive?"#define DECODE_VIDEO_TEXTURE_EMISSIVE":"",n.logarithmicDepthBuffer?"#define USE_LOGARITHMIC_DEPTH_BUFFER":"",n.reversedDepthBuffer?"#define USE_REVERSED_DEPTH_BUFFER":"","uniform mat4 viewMatrix;","uniform vec3 cameraPosition;","uniform bool isOrthographic;",n.toneMapping!==Yi?"#define TONE_MAPPING":"",n.toneMapping!==Yi?ue.tonemapping_pars_fragment:"",n.toneMapping!==Yi?UA("toneMapping",n.toneMapping):"",n.dithering?"#define DITHERING":"",n.opaque?"#define OPAQUE":"",ue.colorspace_pars_fragment,DA("linearToOutputTexel",n.outputColorSpace),LA(),n.useDepthPacking?"#define DEPTH_PACKING "+n.depthPacking:"",`
`].filter(Qo).join(`
`)),f=ep(f),f=__(f,n),f=x_(f,n),d=ep(d),d=__(d,n),d=x_(d,n),f=S_(f),d=S_(d),n.isRawShaderMaterial!==!0&&(P=`#version 300 es
`,M=[y,"#define attribute in","#define varying out","#define texture2D texture"].join(`
`)+`
`+M,S=["#define varying in",n.glslVersion===Mv?"":"layout(location = 0) out highp vec4 pc_fragColor;",n.glslVersion===Mv?"":"#define gl_FragColor pc_fragColor","#define gl_FragDepthEXT gl_FragDepth","#define texture2D texture","#define textureCube texture","#define texture2DProj textureProj","#define texture2DLodEXT textureLod","#define texture2DProjLodEXT textureProjLod","#define textureCubeLodEXT textureLod","#define texture2DGradEXT textureGrad","#define texture2DProjGradEXT textureProjGrad","#define textureCubeGradEXT textureGrad"].join(`
`)+`
`+S);const D=P+M+f,A=P+S+d,F=m_(l,l.VERTEX_SHADER,D),O=m_(l,l.FRAGMENT_SHADER,A);l.attachShader(w,F),l.attachShader(w,O),n.index0AttributeName!==void 0?l.bindAttribLocation(w,0,n.index0AttributeName):n.hasPositionAttribute===!0&&l.bindAttribLocation(w,0,"position"),l.linkProgram(w);function I(V){if(r.debug.checkShaderErrors){const q=l.getProgramInfoLog(w)||"",ct=l.getShaderInfoLog(F)||"",ht=l.getShaderInfoLog(O)||"",j=q.trim(),B=ct.trim(),H=ht.trim();let $=!0,dt=!0;if(l.getProgramParameter(w,l.LINK_STATUS)===!1)if($=!1,typeof r.debug.onShaderError=="function")r.debug.onShaderError(l,w,F,O);else{const Mt=v_(l,F,"vertex"),U=v_(l,O,"fragment");be("WebGLProgram: Shader Error "+l.getError()+" - VALIDATE_STATUS "+l.getProgramParameter(w,l.VALIDATE_STATUS)+`

Material Name: `+V.name+`
Material Type: `+V.type+`

Program Info Log: `+j+`
`+Mt+`
`+U)}else j!==""?ie("WebGLProgram: Program Info Log:",j):(B===""||H==="")&&(dt=!1);dt&&(V.diagnostics={runnable:$,programLog:j,vertexShader:{log:B,prefix:M},fragmentShader:{log:H,prefix:S}})}l.deleteShader(F),l.deleteShader(O),T=new tu(l,w),N=IA(l,w)}let T;this.getUniforms=function(){return T===void 0&&I(this),T};let N;this.getAttributes=function(){return N===void 0&&I(this),N};let X=n.rendererExtensionParallelShaderCompile===!1;return this.isReady=function(){return X===!1&&(X=l.getProgramParameter(w,AA)),X},this.destroy=function(){s.releaseStatesOfProgram(this),l.deleteProgram(w),this.program=void 0},this.type=n.shaderType,this.name=n.shaderName,this.id=RA++,this.cacheKey=t,this.usedTimes=1,this.program=w,this.vertexShader=F,this.fragmentShader=O,this}let QA=0;class $A{constructor(){this.shaderCache=new Map,this.materialCache=new Map}update(t,n,s){const l=this._getShaderCacheForMaterial(t);return l.has(n)===!1&&(l.add(n),n.usedTimes++),l.has(s)===!1&&(l.add(s),s.usedTimes++),this}remove(t){const n=this.materialCache.get(t);for(const s of n)s.usedTimes--,s.usedTimes===0&&this.shaderCache.delete(s.code);return this.materialCache.delete(t),this}getVertexShaderStage(t){return this._getShaderStage(t.vertexShader)}getFragmentShaderStage(t){return this._getShaderStage(t.fragmentShader)}dispose(){this.shaderCache.clear(),this.materialCache.clear()}_getShaderCacheForMaterial(t){const n=this.materialCache;let s=n.get(t);return s===void 0&&(s=new Set,n.set(t,s)),s}_getShaderStage(t){const n=this.shaderCache;let s=n.get(t);return s===void 0&&(s=new t2(t),n.set(t,s)),s}}class t2{constructor(t){this.id=QA++,this.code=t,this.usedTimes=0}}function e2(r){return r===ks||r===nu||r===iu}function n2(r,t,n,s,l,c){const f=new $_,d=new $A,m=new Set,p=[],v=new Map,_=s.logarithmicDepthBuffer;let g=s.precision;const y={MeshDepthMaterial:"depth",MeshDistanceMaterial:"distance",MeshNormalMaterial:"normal",MeshBasicMaterial:"basic",MeshLambertMaterial:"lambert",MeshPhongMaterial:"phong",MeshToonMaterial:"toon",MeshStandardMaterial:"physical",MeshPhysicalMaterial:"physical",MeshMatcapMaterial:"matcap",LineBasicMaterial:"basic",LineDashedMaterial:"dashed",PointsMaterial:"points",ShadowMaterial:"shadow",SpriteMaterial:"sprite"};function b(T){return m.add(T),T===0?"uv":`uv${T}`}function w(T,N,X,V,q,ct){const ht=V.fog,j=q.geometry,B=T.isMeshStandardMaterial||T.isMeshLambertMaterial||T.isMeshPhongMaterial?V.environment:null,H=T.isMeshStandardMaterial||T.isMeshLambertMaterial&&!T.envMap||T.isMeshPhongMaterial&&!T.envMap,$=t.get(T.envMap||B,H),dt=$&&$.mapping===uu?$.image.height:null,Mt=y[T.type];T.precision!==null&&(g=s.getMaxPrecision(T.precision),g!==T.precision&&ie("WebGLProgram.getParameters:",T.precision,"not supported, using",g,"instead."));const U=j.morphAttributes.position||j.morphAttributes.normal||j.morphAttributes.color,J=U!==void 0?U.length:0;let bt=0;j.morphAttributes.position!==void 0&&(bt=1),j.morphAttributes.normal!==void 0&&(bt=2),j.morphAttributes.color!==void 0&&(bt=3);let pt,At,tt,_t;if(Mt){const Vt=Xi[Mt];pt=Vt.vertexShader,At=Vt.fragmentShader}else{pt=T.vertexShader,At=T.fragmentShader;const Vt=d.getVertexShaderStage(T),Ke=d.getFragmentShaderStage(T);d.update(T,Vt,Ke),tt=Vt.id,_t=Ke.id}const xt=r.getRenderTarget(),It=r.state.buffers.depth.getReversed(),jt=q.isInstancedMesh===!0,Jt=q.isBatchedMesh===!0,qe=!!T.map,he=!!T.matcap,Se=!!$,ye=!!T.aoMap,de=!!T.lightMap,nn=!!T.bumpMap&&T.wireframe===!1,an=!!T.normalMap,sn=!!T.displacementMap,fn=!!T.emissiveMap,We=!!T.metalnessMap,rn=!!T.roughnessMap,Z=T.anisotropy>0,Fe=T.clearcoat>0,Ce=T.dispersion>0,L=T.iridescence>0,E=T.sheen>0,et=T.transmission>0,rt=Z&&!!T.anisotropyMap,mt=Fe&&!!T.clearcoatMap,Rt=Fe&&!!T.clearcoatNormalMap,Nt=Fe&&!!T.clearcoatRoughnessMap,ft=L&&!!T.iridescenceMap,gt=L&&!!T.iridescenceThicknessMap,wt=E&&!!T.sheenColorMap,Bt=E&&!!T.sheenRoughnessMap,Ot=!!T.specularMap,Ut=!!T.specularColorMap,Qt=!!T.specularIntensityMap,$t=et&&!!T.transmissionMap,ae=et&&!!T.thicknessMap,W=!!T.gradientMap,Ct=!!T.alphaMap,St=T.alphaTest>0,Dt=!!T.alphaHash,Ft=!!T.extensions;let Tt=Yi;T.toneMapped&&(xt===null||xt.isXRRenderTarget===!0)&&(Tt=r.toneMapping);const Yt={shaderID:Mt,shaderType:T.type,shaderName:T.name,vertexShader:pt,fragmentShader:At,defines:T.defines,customVertexShaderID:tt,customFragmentShaderID:_t,isRawShaderMaterial:T.isRawShaderMaterial===!0,glslVersion:T.glslVersion,precision:g,batching:Jt,batchingColor:Jt&&q._colorsTexture!==null,instancing:jt,instancingColor:jt&&q.instanceColor!==null,instancingMorph:jt&&q.morphTexture!==null,outputColorSpace:xt===null?r.outputColorSpace:xt.isXRRenderTarget===!0?xt.texture.colorSpace:Ee.workingColorSpace,alphaToCoverage:!!T.alphaToCoverage,map:qe,matcap:he,envMap:Se,envMapMode:Se&&$.mapping,envMapCubeUVHeight:dt,aoMap:ye,lightMap:de,bumpMap:nn,normalMap:an,displacementMap:sn,emissiveMap:fn,normalMapObjectSpace:an&&T.normalMapType===cM,normalMapTangentSpace:an&&T.normalMapType===jd,packedNormalMap:an&&T.normalMapType===jd&&e2(T.normalMap.format),metalnessMap:We,roughnessMap:rn,anisotropy:Z,anisotropyMap:rt,clearcoat:Fe,clearcoatMap:mt,clearcoatNormalMap:Rt,clearcoatRoughnessMap:Nt,dispersion:Ce,iridescence:L,iridescenceMap:ft,iridescenceThicknessMap:gt,sheen:E,sheenColorMap:wt,sheenRoughnessMap:Bt,specularMap:Ot,specularColorMap:Ut,specularIntensityMap:Qt,transmission:et,transmissionMap:$t,thicknessMap:ae,gradientMap:W,opaque:T.transparent===!1&&T.blending===Br&&T.alphaToCoverage===!1,alphaMap:Ct,alphaTest:St,alphaHash:Dt,combine:T.combine,mapUv:qe&&b(T.map.channel),aoMapUv:ye&&b(T.aoMap.channel),lightMapUv:de&&b(T.lightMap.channel),bumpMapUv:nn&&b(T.bumpMap.channel),normalMapUv:an&&b(T.normalMap.channel),displacementMapUv:sn&&b(T.displacementMap.channel),emissiveMapUv:fn&&b(T.emissiveMap.channel),metalnessMapUv:We&&b(T.metalnessMap.channel),roughnessMapUv:rn&&b(T.roughnessMap.channel),anisotropyMapUv:rt&&b(T.anisotropyMap.channel),clearcoatMapUv:mt&&b(T.clearcoatMap.channel),clearcoatNormalMapUv:Rt&&b(T.clearcoatNormalMap.channel),clearcoatRoughnessMapUv:Nt&&b(T.clearcoatRoughnessMap.channel),iridescenceMapUv:ft&&b(T.iridescenceMap.channel),iridescenceThicknessMapUv:gt&&b(T.iridescenceThicknessMap.channel),sheenColorMapUv:wt&&b(T.sheenColorMap.channel),sheenRoughnessMapUv:Bt&&b(T.sheenRoughnessMap.channel),specularMapUv:Ot&&b(T.specularMap.channel),specularColorMapUv:Ut&&b(T.specularColorMap.channel),specularIntensityMapUv:Qt&&b(T.specularIntensityMap.channel),transmissionMapUv:$t&&b(T.transmissionMap.channel),thicknessMapUv:ae&&b(T.thicknessMap.channel),alphaMapUv:Ct&&b(T.alphaMap.channel),vertexTangents:!!j.attributes.tangent&&(an||Z),vertexNormals:!!j.attributes.normal,vertexColors:T.vertexColors,vertexAlphas:T.vertexColors===!0&&!!j.attributes.color&&j.attributes.color.itemSize===4,pointsUvs:q.isPoints===!0&&!!j.attributes.uv&&(qe||Ct),fog:!!ht,useFog:T.fog===!0,fogExp2:!!ht&&ht.isFogExp2,flatShading:T.wireframe===!1&&(T.flatShading===!0||j.attributes.normal===void 0&&an===!1&&(T.isMeshLambertMaterial||T.isMeshPhongMaterial||T.isMeshStandardMaterial||T.isMeshPhysicalMaterial)),sizeAttenuation:T.sizeAttenuation===!0,logarithmicDepthBuffer:_,reversedDepthBuffer:It,skinning:q.isSkinnedMesh===!0,hasPositionAttribute:j.attributes.position!==void 0,morphTargets:j.morphAttributes.position!==void 0,morphNormals:j.morphAttributes.normal!==void 0,morphColors:j.morphAttributes.color!==void 0,morphTargetsCount:J,morphTextureStride:bt,numDirLights:N.directional.length,numPointLights:N.point.length,numSpotLights:N.spot.length,numSpotLightMaps:N.spotLightMap.length,numRectAreaLights:N.rectArea.length,numHemiLights:N.hemi.length,numDirLightShadows:N.directionalShadowMap.length,numPointLightShadows:N.pointShadowMap.length,numSpotLightShadows:N.spotShadowMap.length,numSpotLightShadowsWithMaps:N.numSpotLightShadowsWithMaps,numLightProbes:N.numLightProbes,numLightProbeGrids:ct.length,numClippingPlanes:c.numPlanes,numClipIntersection:c.numIntersection,dithering:T.dithering,shadowMapEnabled:r.shadowMap.enabled&&X.length>0,shadowMapType:r.shadowMap.type,toneMapping:Tt,decodeVideoTexture:qe&&T.map.isVideoTexture===!0&&Ee.getTransfer(T.map.colorSpace)===ze,decodeVideoTextureEmissive:fn&&T.emissiveMap.isVideoTexture===!0&&Ee.getTransfer(T.emissiveMap.colorSpace)===ze,premultipliedAlpha:T.premultipliedAlpha,doubleSided:T.side===Ma,flipSided:T.side===Vn,useDepthPacking:T.depthPacking>=0,depthPacking:T.depthPacking||0,index0AttributeName:T.index0AttributeName,extensionClipCullDistance:Ft&&T.extensions.clipCullDistance===!0&&n.has("WEBGL_clip_cull_distance"),extensionMultiDraw:(Ft&&T.extensions.multiDraw===!0||Jt)&&n.has("WEBGL_multi_draw"),rendererExtensionParallelShaderCompile:n.has("KHR_parallel_shader_compile"),customProgramCacheKey:T.customProgramCacheKey()};return Yt.vertexUv1s=m.has(1),Yt.vertexUv2s=m.has(2),Yt.vertexUv3s=m.has(3),m.clear(),Yt}function M(T){const N=[];if(T.shaderID?N.push(T.shaderID):(N.push(T.customVertexShaderID),N.push(T.customFragmentShaderID)),T.defines!==void 0)for(const X in T.defines)N.push(X),N.push(T.defines[X]);return T.isRawShaderMaterial===!1&&(S(N,T),P(N,T),N.push(r.outputColorSpace)),N.push(T.customProgramCacheKey),N.join()}function S(T,N){T.push(N.precision),T.push(N.outputColorSpace),T.push(N.envMapMode),T.push(N.envMapCubeUVHeight),T.push(N.mapUv),T.push(N.alphaMapUv),T.push(N.lightMapUv),T.push(N.aoMapUv),T.push(N.bumpMapUv),T.push(N.normalMapUv),T.push(N.displacementMapUv),T.push(N.emissiveMapUv),T.push(N.metalnessMapUv),T.push(N.roughnessMapUv),T.push(N.anisotropyMapUv),T.push(N.clearcoatMapUv),T.push(N.clearcoatNormalMapUv),T.push(N.clearcoatRoughnessMapUv),T.push(N.iridescenceMapUv),T.push(N.iridescenceThicknessMapUv),T.push(N.sheenColorMapUv),T.push(N.sheenRoughnessMapUv),T.push(N.specularMapUv),T.push(N.specularColorMapUv),T.push(N.specularIntensityMapUv),T.push(N.transmissionMapUv),T.push(N.thicknessMapUv),T.push(N.combine),T.push(N.fogExp2),T.push(N.sizeAttenuation),T.push(N.morphTargetsCount),T.push(N.morphAttributeCount),T.push(N.numDirLights),T.push(N.numPointLights),T.push(N.numSpotLights),T.push(N.numSpotLightMaps),T.push(N.numHemiLights),T.push(N.numRectAreaLights),T.push(N.numDirLightShadows),T.push(N.numPointLightShadows),T.push(N.numSpotLightShadows),T.push(N.numSpotLightShadowsWithMaps),T.push(N.numLightProbes),T.push(N.shadowMapType),T.push(N.toneMapping),T.push(N.numClippingPlanes),T.push(N.numClipIntersection),T.push(N.depthPacking)}function P(T,N){f.disableAll(),N.instancing&&f.enable(0),N.instancingColor&&f.enable(1),N.instancingMorph&&f.enable(2),N.matcap&&f.enable(3),N.envMap&&f.enable(4),N.normalMapObjectSpace&&f.enable(5),N.normalMapTangentSpace&&f.enable(6),N.clearcoat&&f.enable(7),N.iridescence&&f.enable(8),N.alphaTest&&f.enable(9),N.vertexColors&&f.enable(10),N.vertexAlphas&&f.enable(11),N.vertexUv1s&&f.enable(12),N.vertexUv2s&&f.enable(13),N.vertexUv3s&&f.enable(14),N.vertexTangents&&f.enable(15),N.anisotropy&&f.enable(16),N.alphaHash&&f.enable(17),N.batching&&f.enable(18),N.dispersion&&f.enable(19),N.batchingColor&&f.enable(20),N.gradientMap&&f.enable(21),N.packedNormalMap&&f.enable(22),N.vertexNormals&&f.enable(23),T.push(f.mask),f.disableAll(),N.fog&&f.enable(0),N.useFog&&f.enable(1),N.flatShading&&f.enable(2),N.logarithmicDepthBuffer&&f.enable(3),N.reversedDepthBuffer&&f.enable(4),N.skinning&&f.enable(5),N.morphTargets&&f.enable(6),N.morphNormals&&f.enable(7),N.morphColors&&f.enable(8),N.premultipliedAlpha&&f.enable(9),N.shadowMapEnabled&&f.enable(10),N.doubleSided&&f.enable(11),N.flipSided&&f.enable(12),N.useDepthPacking&&f.enable(13),N.dithering&&f.enable(14),N.transmission&&f.enable(15),N.sheen&&f.enable(16),N.opaque&&f.enable(17),N.pointsUvs&&f.enable(18),N.decodeVideoTexture&&f.enable(19),N.decodeVideoTextureEmissive&&f.enable(20),N.alphaToCoverage&&f.enable(21),N.numLightProbeGrids>0&&f.enable(22),N.hasPositionAttribute&&f.enable(23),T.push(f.mask)}function D(T){const N=y[T.type];let X;if(N){const V=Xi[N];X=bE.clone(V.uniforms)}else X=T.uniforms;return X}function A(T,N){let X=v.get(N);return X!==void 0?++X.usedTimes:(X=new JA(r,N,T,l),p.push(X),v.set(N,X)),X}function F(T){if(--T.usedTimes===0){const N=p.indexOf(T);p[N]=p[p.length-1],p.pop(),v.delete(T.cacheKey),T.destroy()}}function O(T){d.remove(T)}function I(){d.dispose()}return{getParameters:w,getProgramCacheKey:M,getUniforms:D,acquireProgram:A,releaseProgram:F,releaseShaderCache:O,programs:p,dispose:I}}function i2(){let r=new WeakMap;function t(f){return r.has(f)}function n(f){let d=r.get(f);return d===void 0&&(d={},r.set(f,d)),d}function s(f){r.delete(f)}function l(f,d,m){r.get(f)[d]=m}function c(){r=new WeakMap}return{has:t,get:n,remove:s,update:l,dispose:c}}function a2(r,t){return r.groupOrder!==t.groupOrder?r.groupOrder-t.groupOrder:r.renderOrder!==t.renderOrder?r.renderOrder-t.renderOrder:r.material.id!==t.material.id?r.material.id-t.material.id:r.materialVariant!==t.materialVariant?r.materialVariant-t.materialVariant:r.z!==t.z?r.z-t.z:r.id-t.id}function M_(r,t){return r.groupOrder!==t.groupOrder?r.groupOrder-t.groupOrder:r.renderOrder!==t.renderOrder?r.renderOrder-t.renderOrder:r.z!==t.z?t.z-r.z:r.id-t.id}function E_(){const r=[];let t=0;const n=[],s=[],l=[];function c(){t=0,n.length=0,s.length=0,l.length=0}function f(g){let y=0;return g.isInstancedMesh&&(y+=2),g.isSkinnedMesh&&(y+=1),y}function d(g,y,b,w,M,S){let P=r[t];return P===void 0?(P={id:g.id,object:g,geometry:y,material:b,materialVariant:f(g),groupOrder:w,renderOrder:g.renderOrder,z:M,group:S},r[t]=P):(P.id=g.id,P.object=g,P.geometry=y,P.material=b,P.materialVariant=f(g),P.groupOrder=w,P.renderOrder=g.renderOrder,P.z=M,P.group=S),t++,P}function m(g,y,b,w,M,S){const P=d(g,y,b,w,M,S);b.transmission>0?s.push(P):b.transparent===!0?l.push(P):n.push(P)}function p(g,y,b,w,M,S){const P=d(g,y,b,w,M,S);b.transmission>0?s.unshift(P):b.transparent===!0?l.unshift(P):n.unshift(P)}function v(g,y,b){n.length>1&&n.sort(g||a2),s.length>1&&s.sort(y||M_),l.length>1&&l.sort(y||M_),b&&(n.reverse(),s.reverse(),l.reverse())}function _(){for(let g=t,y=r.length;g<y;g++){const b=r[g];if(b.id===null)break;b.id=null,b.object=null,b.geometry=null,b.material=null,b.group=null}}return{opaque:n,transmissive:s,transparent:l,init:c,push:m,unshift:p,finish:_,sort:v}}function s2(){let r=new WeakMap;function t(s,l){const c=r.get(s);let f;return c===void 0?(f=new E_,r.set(s,[f])):l>=c.length?(f=new E_,c.push(f)):f=c[l],f}function n(){r=new WeakMap}return{get:t,dispose:n}}function r2(){const r={};return{get:function(t){if(r[t.id]!==void 0)return r[t.id];let n;switch(t.type){case"DirectionalLight":n={direction:new K,color:new fe};break;case"SpotLight":n={position:new K,direction:new K,color:new fe,distance:0,coneCos:0,penumbraCos:0,decay:0};break;case"PointLight":n={position:new K,color:new fe,distance:0,decay:0};break;case"HemisphereLight":n={direction:new K,skyColor:new fe,groundColor:new fe};break;case"RectAreaLight":n={color:new fe,position:new K,halfWidth:new K,halfHeight:new K};break}return r[t.id]=n,n}}}function o2(){const r={};return{get:function(t){if(r[t.id]!==void 0)return r[t.id];let n;switch(t.type){case"DirectionalLight":n={shadowIntensity:1,shadowBias:0,shadowNormalBias:0,shadowRadius:1,shadowMapSize:new qt};break;case"SpotLight":n={shadowIntensity:1,shadowBias:0,shadowNormalBias:0,shadowRadius:1,shadowMapSize:new qt};break;case"PointLight":n={shadowIntensity:1,shadowBias:0,shadowNormalBias:0,shadowRadius:1,shadowMapSize:new qt,shadowCameraNear:1,shadowCameraFar:1e3};break}return r[t.id]=n,n}}}let l2=0;function c2(r,t){return(t.castShadow?2:0)-(r.castShadow?2:0)+(t.map?1:0)-(r.map?1:0)}function u2(r){const t=new r2,n=o2(),s={version:0,hash:{directionalLength:-1,pointLength:-1,spotLength:-1,rectAreaLength:-1,hemiLength:-1,numDirectionalShadows:-1,numPointShadows:-1,numSpotShadows:-1,numSpotMaps:-1,numLightProbes:-1},ambient:[0,0,0],probe:[],directional:[],directionalShadow:[],directionalShadowMap:[],directionalShadowMatrix:[],spot:[],spotLightMap:[],spotShadow:[],spotShadowMap:[],spotLightMatrix:[],rectArea:[],rectAreaLTC1:null,rectAreaLTC2:null,point:[],pointShadow:[],pointShadowMap:[],pointShadowMatrix:[],hemi:[],numSpotLightShadowsWithMaps:0,numLightProbes:0};for(let p=0;p<9;p++)s.probe.push(new K);const l=new K,c=new en,f=new en;function d(p){let v=0,_=0,g=0;for(let N=0;N<9;N++)s.probe[N].set(0,0,0);let y=0,b=0,w=0,M=0,S=0,P=0,D=0,A=0,F=0,O=0,I=0;p.sort(c2);for(let N=0,X=p.length;N<X;N++){const V=p[N],q=V.color,ct=V.intensity,ht=V.distance;let j=null;if(V.shadow&&V.shadow.map&&(V.shadow.map.texture.format===ks?j=V.shadow.map.texture:j=V.shadow.map.depthTexture||V.shadow.map.texture),V.isAmbientLight)v+=q.r*ct,_+=q.g*ct,g+=q.b*ct;else if(V.isLightProbe){for(let B=0;B<9;B++)s.probe[B].addScaledVector(V.sh.coefficients[B],ct);I++}else if(V.isDirectionalLight){const B=t.get(V);if(B.color.copy(V.color).multiplyScalar(V.intensity),V.castShadow){const H=V.shadow,$=n.get(V);$.shadowIntensity=H.intensity,$.shadowBias=H.bias,$.shadowNormalBias=H.normalBias,$.shadowRadius=H.radius,$.shadowMapSize=H.mapSize,s.directionalShadow[y]=$,s.directionalShadowMap[y]=j,s.directionalShadowMatrix[y]=V.shadow.matrix,P++}s.directional[y]=B,y++}else if(V.isSpotLight){const B=t.get(V);B.position.setFromMatrixPosition(V.matrixWorld),B.color.copy(q).multiplyScalar(ct),B.distance=ht,B.coneCos=Math.cos(V.angle),B.penumbraCos=Math.cos(V.angle*(1-V.penumbra)),B.decay=V.decay,s.spot[w]=B;const H=V.shadow;if(V.map&&(s.spotLightMap[F]=V.map,F++,H.updateMatrices(V),V.castShadow&&O++),s.spotLightMatrix[w]=H.matrix,V.castShadow){const $=n.get(V);$.shadowIntensity=H.intensity,$.shadowBias=H.bias,$.shadowNormalBias=H.normalBias,$.shadowRadius=H.radius,$.shadowMapSize=H.mapSize,s.spotShadow[w]=$,s.spotShadowMap[w]=j,A++}w++}else if(V.isRectAreaLight){const B=t.get(V);B.color.copy(q).multiplyScalar(ct),B.halfWidth.set(V.width*.5,0,0),B.halfHeight.set(0,V.height*.5,0),s.rectArea[M]=B,M++}else if(V.isPointLight){const B=t.get(V);if(B.color.copy(V.color).multiplyScalar(V.intensity),B.distance=V.distance,B.decay=V.decay,V.castShadow){const H=V.shadow,$=n.get(V);$.shadowIntensity=H.intensity,$.shadowBias=H.bias,$.shadowNormalBias=H.normalBias,$.shadowRadius=H.radius,$.shadowMapSize=H.mapSize,$.shadowCameraNear=H.camera.near,$.shadowCameraFar=H.camera.far,s.pointShadow[b]=$,s.pointShadowMap[b]=j,s.pointShadowMatrix[b]=V.shadow.matrix,D++}s.point[b]=B,b++}else if(V.isHemisphereLight){const B=t.get(V);B.skyColor.copy(V.color).multiplyScalar(ct),B.groundColor.copy(V.groundColor).multiplyScalar(ct),s.hemi[S]=B,S++}}M>0&&(r.has("OES_texture_float_linear")===!0?(s.rectAreaLTC1=zt.LTC_FLOAT_1,s.rectAreaLTC2=zt.LTC_FLOAT_2):(s.rectAreaLTC1=zt.LTC_HALF_1,s.rectAreaLTC2=zt.LTC_HALF_2)),s.ambient[0]=v,s.ambient[1]=_,s.ambient[2]=g;const T=s.hash;(T.directionalLength!==y||T.pointLength!==b||T.spotLength!==w||T.rectAreaLength!==M||T.hemiLength!==S||T.numDirectionalShadows!==P||T.numPointShadows!==D||T.numSpotShadows!==A||T.numSpotMaps!==F||T.numLightProbes!==I)&&(s.directional.length=y,s.spot.length=w,s.rectArea.length=M,s.point.length=b,s.hemi.length=S,s.directionalShadow.length=P,s.directionalShadowMap.length=P,s.pointShadow.length=D,s.pointShadowMap.length=D,s.spotShadow.length=A,s.spotShadowMap.length=A,s.directionalShadowMatrix.length=P,s.pointShadowMatrix.length=D,s.spotLightMatrix.length=A+F-O,s.spotLightMap.length=F,s.numSpotLightShadowsWithMaps=O,s.numLightProbes=I,T.directionalLength=y,T.pointLength=b,T.spotLength=w,T.rectAreaLength=M,T.hemiLength=S,T.numDirectionalShadows=P,T.numPointShadows=D,T.numSpotShadows=A,T.numSpotMaps=F,T.numLightProbes=I,s.version=l2++)}function m(p,v){let _=0,g=0,y=0,b=0,w=0;const M=v.matrixWorldInverse;for(let S=0,P=p.length;S<P;S++){const D=p[S];if(D.isDirectionalLight){const A=s.directional[_];A.direction.setFromMatrixPosition(D.matrixWorld),l.setFromMatrixPosition(D.target.matrixWorld),A.direction.sub(l),A.direction.transformDirection(M),_++}else if(D.isSpotLight){const A=s.spot[y];A.position.setFromMatrixPosition(D.matrixWorld),A.position.applyMatrix4(M),A.direction.setFromMatrixPosition(D.matrixWorld),l.setFromMatrixPosition(D.target.matrixWorld),A.direction.sub(l),A.direction.transformDirection(M),y++}else if(D.isRectAreaLight){const A=s.rectArea[b];A.position.setFromMatrixPosition(D.matrixWorld),A.position.applyMatrix4(M),f.identity(),c.copy(D.matrixWorld),c.premultiply(M),f.extractRotation(c),A.halfWidth.set(D.width*.5,0,0),A.halfHeight.set(0,D.height*.5,0),A.halfWidth.applyMatrix4(f),A.halfHeight.applyMatrix4(f),b++}else if(D.isPointLight){const A=s.point[g];A.position.setFromMatrixPosition(D.matrixWorld),A.position.applyMatrix4(M),g++}else if(D.isHemisphereLight){const A=s.hemi[w];A.direction.setFromMatrixPosition(D.matrixWorld),A.direction.transformDirection(M),w++}}}return{setup:d,setupView:m,state:s}}function b_(r){const t=new u2(r),n=[],s=[],l=[];function c(g){_.camera=g,n.length=0,s.length=0,l.length=0}function f(g){n.push(g)}function d(g){s.push(g)}function m(g){l.push(g)}function p(){t.setup(n)}function v(g){t.setupView(n,g)}const _={lightsArray:n,shadowsArray:s,lightProbeGridArray:l,camera:null,lights:t,transmissionRenderTarget:{},textureUnits:0};return{init:c,state:_,setupLights:p,setupLightsView:v,pushLight:f,pushShadow:d,pushLightProbeGrid:m}}function f2(r){let t=new WeakMap;function n(l,c=0){const f=t.get(l);let d;return f===void 0?(d=new b_(r),t.set(l,[d])):c>=f.length?(d=new b_(r),f.push(d)):d=f[c],d}function s(){t=new WeakMap}return{get:n,dispose:s}}const h2=`void main() {
	gl_Position = vec4( position, 1.0 );
}`,d2=`uniform sampler2D shadow_pass;
uniform vec2 resolution;
uniform float radius;
void main() {
	const float samples = float( VSM_SAMPLES );
	float mean = 0.0;
	float squared_mean = 0.0;
	float uvStride = samples <= 1.0 ? 0.0 : 2.0 / ( samples - 1.0 );
	float uvStart = samples <= 1.0 ? 0.0 : - 1.0;
	for ( float i = 0.0; i < samples; i ++ ) {
		float uvOffset = uvStart + i * uvStride;
		#ifdef HORIZONTAL_PASS
			vec2 distribution = texture2D( shadow_pass, ( gl_FragCoord.xy + vec2( uvOffset, 0.0 ) * radius ) / resolution ).rg;
			mean += distribution.x;
			squared_mean += distribution.y * distribution.y + distribution.x * distribution.x;
		#else
			float depth = texture2D( shadow_pass, ( gl_FragCoord.xy + vec2( 0.0, uvOffset ) * radius ) / resolution ).r;
			mean += depth;
			squared_mean += depth * depth;
		#endif
	}
	mean = mean / samples;
	squared_mean = squared_mean / samples;
	float std_dev = sqrt( max( 0.0, squared_mean - mean * mean ) );
	gl_FragColor = vec4( mean, std_dev, 0.0, 1.0 );
}`,p2=[new K(1,0,0),new K(-1,0,0),new K(0,1,0),new K(0,-1,0),new K(0,0,1),new K(0,0,-1)],m2=[new K(0,-1,0),new K(0,-1,0),new K(0,0,1),new K(0,0,-1),new K(0,-1,0),new K(0,-1,0)],T_=new en,Ko=new K,rd=new K;function g2(r,t,n){let s=new gp;const l=new qt,c=new qt,f=new $e,d=new CE,m=new wE,p={},v=n.maxTextureSize,_={[us]:Vn,[Vn]:us,[Ma]:Ma},g=new Ti({defines:{VSM_SAMPLES:8},uniforms:{shadow_pass:{value:null},resolution:{value:new qt},radius:{value:4}},vertexShader:h2,fragmentShader:d2}),y=g.clone();y.defines.HORIZONTAL_PASS=1;const b=new Xn;b.setAttribute("position",new Ki(new Float32Array([-1,-1,.5,3,-1,.5,-1,3,.5]),3));const w=new un(b,g),M=this;this.enabled=!1,this.autoUpdate=!0,this.needsUpdate=!1,this.type=Kc;let S=this.type;this.render=function(O,I,T){if(M.enabled===!1||M.autoUpdate===!1&&M.needsUpdate===!1||O.length===0)return;this.type===O_&&(ie("WebGLShadowMap: PCFSoftShadowMap has been deprecated. Using PCFShadowMap instead."),this.type=Kc);const N=r.getRenderTarget(),X=r.getActiveCubeFace(),V=r.getActiveMipmapLevel(),q=r.state;q.setBlending(ba),q.buffers.depth.getReversed()===!0?q.buffers.color.setClear(0,0,0,0):q.buffers.color.setClear(1,1,1,1),q.buffers.depth.setTest(!0),q.setScissorTest(!1);const ct=S!==this.type;ct&&I.traverse(function(ht){ht.material&&(Array.isArray(ht.material)?ht.material.forEach(j=>j.needsUpdate=!0):ht.material.needsUpdate=!0)});for(let ht=0,j=O.length;ht<j;ht++){const B=O[ht],H=B.shadow;if(H===void 0){ie("WebGLShadowMap:",B,"has no shadow.");continue}if(H.autoUpdate===!1&&H.needsUpdate===!1)continue;l.copy(H.mapSize);const $=H.getFrameExtents();l.multiply($),c.copy(H.mapSize),(l.x>v||l.y>v)&&(l.x>v&&(c.x=Math.floor(v/$.x),l.x=c.x*$.x,H.mapSize.x=c.x),l.y>v&&(c.y=Math.floor(v/$.y),l.y=c.y*$.y,H.mapSize.y=c.y));const dt=r.state.buffers.depth.getReversed();if(H.camera._reversedDepth=dt,H.map===null||ct===!0){if(H.map!==null&&(H.map.depthTexture!==null&&(H.map.depthTexture.dispose(),H.map.depthTexture=null),H.map.dispose()),this.type===jo){if(B.isPointLight){ie("WebGLShadowMap: VSM shadow maps are not supported for PointLights. Use PCF or BasicShadowMap instead.");continue}H.map=new Zi(l.x,l.y,{format:ks,type:Aa,minFilter:Bn,magFilter:Bn,generateMipmaps:!1}),H.map.texture.name=B.name+".shadowMap",H.map.depthTexture=new Xr(l.x,l.y,Wi),H.map.depthTexture.name=B.name+".shadowMapDepth",H.map.depthTexture.format=Ra,H.map.depthTexture.compareFunction=null,H.map.depthTexture.minFilter=Ln,H.map.depthTexture.magFilter=Ln}else B.isPointLight?(H.map=new xx(l.x),H.map.depthTexture=new XM(l.x,ji)):(H.map=new Zi(l.x,l.y),H.map.depthTexture=new Xr(l.x,l.y,ji)),H.map.depthTexture.name=B.name+".shadowMap",H.map.depthTexture.format=Ra,this.type===Kc?(H.map.depthTexture.compareFunction=dt?hp:fp,H.map.depthTexture.minFilter=Bn,H.map.depthTexture.magFilter=Bn):(H.map.depthTexture.compareFunction=null,H.map.depthTexture.minFilter=Ln,H.map.depthTexture.magFilter=Ln);H.camera.updateProjectionMatrix()}const Mt=H.map.isWebGLCubeRenderTarget?6:1;for(let U=0;U<Mt;U++){if(H.map.isWebGLCubeRenderTarget)r.setRenderTarget(H.map,U),r.clear();else{U===0&&(r.setRenderTarget(H.map),r.clear());const J=H.getViewport(U);f.set(c.x*J.x,c.y*J.y,c.x*J.z,c.y*J.w),q.viewport(f)}if(B.isPointLight){const J=H.camera,bt=H.matrix,pt=B.distance||J.far;pt!==J.far&&(J.far=pt,J.updateProjectionMatrix()),Ko.setFromMatrixPosition(B.matrixWorld),J.position.copy(Ko),rd.copy(J.position),rd.add(p2[U]),J.up.copy(m2[U]),J.lookAt(rd),J.updateMatrixWorld(),bt.makeTranslation(-Ko.x,-Ko.y,-Ko.z),T_.multiplyMatrices(J.projectionMatrix,J.matrixWorldInverse),H._frustum.setFromProjectionMatrix(T_,J.coordinateSystem,J.reversedDepth)}else H.updateMatrices(B);s=H.getFrustum(),A(I,T,H.camera,B,this.type)}H.isPointLightShadow!==!0&&this.type===jo&&P(H,T),H.needsUpdate=!1}S=this.type,M.needsUpdate=!1,r.setRenderTarget(N,X,V)};function P(O,I){const T=t.update(w);g.defines.VSM_SAMPLES!==O.blurSamples&&(g.defines.VSM_SAMPLES=O.blurSamples,y.defines.VSM_SAMPLES=O.blurSamples,g.needsUpdate=!0,y.needsUpdate=!0),O.mapPass===null&&(O.mapPass=new Zi(l.x,l.y,{format:ks,type:Aa})),g.uniforms.shadow_pass.value=O.map.depthTexture,g.uniforms.resolution.value=O.mapSize,g.uniforms.radius.value=O.radius,r.setRenderTarget(O.mapPass),r.clear(),r.renderBufferDirect(I,null,T,g,w,null),y.uniforms.shadow_pass.value=O.mapPass.texture,y.uniforms.resolution.value=O.mapSize,y.uniforms.radius.value=O.radius,r.setRenderTarget(O.map),r.clear(),r.renderBufferDirect(I,null,T,y,w,null)}function D(O,I,T,N){let X=null;const V=T.isPointLight===!0?O.customDistanceMaterial:O.customDepthMaterial;if(V!==void 0)X=V;else if(X=T.isPointLight===!0?m:d,r.localClippingEnabled&&I.clipShadows===!0&&Array.isArray(I.clippingPlanes)&&I.clippingPlanes.length!==0||I.displacementMap&&I.displacementScale!==0||I.alphaMap&&I.alphaTest>0||I.map&&I.alphaTest>0||I.alphaToCoverage===!0){const q=X.uuid,ct=I.uuid;let ht=p[q];ht===void 0&&(ht={},p[q]=ht);let j=ht[ct];j===void 0&&(j=X.clone(),ht[ct]=j,I.addEventListener("dispose",F)),X=j}if(X.visible=I.visible,X.wireframe=I.wireframe,N===jo?X.side=I.shadowSide!==null?I.shadowSide:I.side:X.side=I.shadowSide!==null?I.shadowSide:_[I.side],X.alphaMap=I.alphaMap,X.alphaTest=I.alphaToCoverage===!0?.5:I.alphaTest,X.map=I.map,X.clipShadows=I.clipShadows,X.clippingPlanes=I.clippingPlanes,X.clipIntersection=I.clipIntersection,X.displacementMap=I.displacementMap,X.displacementScale=I.displacementScale,X.displacementBias=I.displacementBias,X.wireframeLinewidth=I.wireframeLinewidth,X.linewidth=I.linewidth,T.isPointLight===!0&&X.isMeshDistanceMaterial===!0){const q=r.properties.get(X);q.light=T}return X}function A(O,I,T,N,X){if(O.visible===!1)return;if(O.layers.test(I.layers)&&(O.isMesh||O.isLine||O.isPoints)&&(O.castShadow||O.receiveShadow&&X===jo)&&(!O.frustumCulled||s.intersectsObject(O))){O.modelViewMatrix.multiplyMatrices(T.matrixWorldInverse,O.matrixWorld);const ct=t.update(O),ht=O.material;if(Array.isArray(ht)){const j=ct.groups;for(let B=0,H=j.length;B<H;B++){const $=j[B],dt=ht[$.materialIndex];if(dt&&dt.visible){const Mt=D(O,dt,N,X);O.onBeforeShadow(r,O,I,T,ct,Mt,$),r.renderBufferDirect(T,null,ct,Mt,O,$),O.onAfterShadow(r,O,I,T,ct,Mt,$)}}}else if(ht.visible){const j=D(O,ht,N,X);O.onBeforeShadow(r,O,I,T,ct,j,null),r.renderBufferDirect(T,null,ct,j,O,null),O.onAfterShadow(r,O,I,T,ct,j,null)}}const q=O.children;for(let ct=0,ht=q.length;ct<ht;ct++)A(q[ct],I,T,N,X)}function F(O){O.target.removeEventListener("dispose",F);for(const T in p){const N=p[T],X=O.target.uuid;X in N&&(N[X].dispose(),delete N[X])}}}function v2(r,t){function n(){let W=!1;const Ct=new $e;let St=null;const Dt=new $e(0,0,0,0);return{setMask:function(Ft){St!==Ft&&!W&&(r.colorMask(Ft,Ft,Ft,Ft),St=Ft)},setLocked:function(Ft){W=Ft},setClear:function(Ft,Tt,Yt,Vt,Ke){Ke===!0&&(Ft*=Vt,Tt*=Vt,Yt*=Vt),Ct.set(Ft,Tt,Yt,Vt),Dt.equals(Ct)===!1&&(r.clearColor(Ft,Tt,Yt,Vt),Dt.copy(Ct))},reset:function(){W=!1,St=null,Dt.set(-1,0,0,0)}}}function s(){let W=!1,Ct=!1,St=null,Dt=null,Ft=null;return{setReversed:function(Tt){if(Ct!==Tt){const Yt=t.get("EXT_clip_control");Tt?Yt.clipControlEXT(Yt.LOWER_LEFT_EXT,Yt.ZERO_TO_ONE_EXT):Yt.clipControlEXT(Yt.LOWER_LEFT_EXT,Yt.NEGATIVE_ONE_TO_ONE_EXT),Ct=Tt;const Vt=Ft;Ft=null,this.setClear(Vt)}},getReversed:function(){return Ct},setTest:function(Tt){Tt?xt(r.DEPTH_TEST):It(r.DEPTH_TEST)},setMask:function(Tt){St!==Tt&&!W&&(r.depthMask(Tt),St=Tt)},setFunc:function(Tt){if(Ct&&(Tt=xM[Tt]),Dt!==Tt){switch(Tt){case fd:r.depthFunc(r.NEVER);break;case hd:r.depthFunc(r.ALWAYS);break;case dd:r.depthFunc(r.LESS);break;case Vr:r.depthFunc(r.LEQUAL);break;case pd:r.depthFunc(r.EQUAL);break;case md:r.depthFunc(r.GEQUAL);break;case gd:r.depthFunc(r.GREATER);break;case vd:r.depthFunc(r.NOTEQUAL);break;default:r.depthFunc(r.LEQUAL)}Dt=Tt}},setLocked:function(Tt){W=Tt},setClear:function(Tt){Ft!==Tt&&(Ft=Tt,Ct&&(Tt=1-Tt),r.clearDepth(Tt))},reset:function(){W=!1,St=null,Dt=null,Ft=null,Ct=!1}}}function l(){let W=!1,Ct=null,St=null,Dt=null,Ft=null,Tt=null,Yt=null,Vt=null,Ke=null;return{setTest:function(Ne){W||(Ne?xt(r.STENCIL_TEST):It(r.STENCIL_TEST))},setMask:function(Ne){Ct!==Ne&&!W&&(r.stencilMask(Ne),Ct=Ne)},setFunc:function(Ne,$n,ti){(St!==Ne||Dt!==$n||Ft!==ti)&&(r.stencilFunc(Ne,$n,ti),St=Ne,Dt=$n,Ft=ti)},setOp:function(Ne,$n,ti){(Tt!==Ne||Yt!==$n||Vt!==ti)&&(r.stencilOp(Ne,$n,ti),Tt=Ne,Yt=$n,Vt=ti)},setLocked:function(Ne){W=Ne},setClear:function(Ne){Ke!==Ne&&(r.clearStencil(Ne),Ke=Ne)},reset:function(){W=!1,Ct=null,St=null,Dt=null,Ft=null,Tt=null,Yt=null,Vt=null,Ke=null}}}const c=new n,f=new s,d=new l,m=new WeakMap,p=new WeakMap;let v={},_={},g={},y=new WeakMap,b=[],w=null,M=!1,S=null,P=null,D=null,A=null,F=null,O=null,I=null,T=new fe(0,0,0),N=0,X=!1,V=null,q=null,ct=null,ht=null,j=null;const B=r.getParameter(r.MAX_COMBINED_TEXTURE_IMAGE_UNITS);let H=!1,$=0;const dt=r.getParameter(r.VERSION);dt.indexOf("WebGL")!==-1?($=parseFloat(/^WebGL (\d)/.exec(dt)[1]),H=$>=1):dt.indexOf("OpenGL ES")!==-1&&($=parseFloat(/^OpenGL ES (\d)/.exec(dt)[1]),H=$>=2);let Mt=null,U={};const J=r.getParameter(r.SCISSOR_BOX),bt=r.getParameter(r.VIEWPORT),pt=new $e().fromArray(J),At=new $e().fromArray(bt);function tt(W,Ct,St,Dt){const Ft=new Uint8Array(4),Tt=r.createTexture();r.bindTexture(W,Tt),r.texParameteri(W,r.TEXTURE_MIN_FILTER,r.NEAREST),r.texParameteri(W,r.TEXTURE_MAG_FILTER,r.NEAREST);for(let Yt=0;Yt<St;Yt++)W===r.TEXTURE_3D||W===r.TEXTURE_2D_ARRAY?r.texImage3D(Ct,0,r.RGBA,1,1,Dt,0,r.RGBA,r.UNSIGNED_BYTE,Ft):r.texImage2D(Ct+Yt,0,r.RGBA,1,1,0,r.RGBA,r.UNSIGNED_BYTE,Ft);return Tt}const _t={};_t[r.TEXTURE_2D]=tt(r.TEXTURE_2D,r.TEXTURE_2D,1),_t[r.TEXTURE_CUBE_MAP]=tt(r.TEXTURE_CUBE_MAP,r.TEXTURE_CUBE_MAP_POSITIVE_X,6),_t[r.TEXTURE_2D_ARRAY]=tt(r.TEXTURE_2D_ARRAY,r.TEXTURE_2D_ARRAY,1,1),_t[r.TEXTURE_3D]=tt(r.TEXTURE_3D,r.TEXTURE_3D,1,1),c.setClear(0,0,0,1),f.setClear(1),d.setClear(0),xt(r.DEPTH_TEST),f.setFunc(Vr),nn(!1),an(gv),xt(r.CULL_FACE),ye(ba);function xt(W){v[W]!==!0&&(r.enable(W),v[W]=!0)}function It(W){v[W]!==!1&&(r.disable(W),v[W]=!1)}function jt(W,Ct){return g[W]!==Ct?(r.bindFramebuffer(W,Ct),g[W]=Ct,W===r.DRAW_FRAMEBUFFER&&(g[r.FRAMEBUFFER]=Ct),W===r.FRAMEBUFFER&&(g[r.DRAW_FRAMEBUFFER]=Ct),!0):!1}function Jt(W,Ct){let St=b,Dt=!1;if(W){St=y.get(Ct),St===void 0&&(St=[],y.set(Ct,St));const Ft=W.textures;if(St.length!==Ft.length||St[0]!==r.COLOR_ATTACHMENT0){for(let Tt=0,Yt=Ft.length;Tt<Yt;Tt++)St[Tt]=r.COLOR_ATTACHMENT0+Tt;St.length=Ft.length,Dt=!0}}else St[0]!==r.BACK&&(St[0]=r.BACK,Dt=!0);Dt&&r.drawBuffers(St)}function qe(W){return w!==W?(r.useProgram(W),w=W,!0):!1}const he={[Fs]:r.FUNC_ADD,[Vy]:r.FUNC_SUBTRACT,[ky]:r.FUNC_REVERSE_SUBTRACT};he[Xy]=r.MIN,he[Wy]=r.MAX;const Se={[qy]:r.ZERO,[Yy]:r.ONE,[Zy]:r.SRC_COLOR,[cd]:r.SRC_ALPHA,[tM]:r.SRC_ALPHA_SATURATE,[Qy]:r.DST_COLOR,[jy]:r.DST_ALPHA,[Ky]:r.ONE_MINUS_SRC_COLOR,[ud]:r.ONE_MINUS_SRC_ALPHA,[$y]:r.ONE_MINUS_DST_COLOR,[Jy]:r.ONE_MINUS_DST_ALPHA,[eM]:r.CONSTANT_COLOR,[nM]:r.ONE_MINUS_CONSTANT_COLOR,[iM]:r.CONSTANT_ALPHA,[aM]:r.ONE_MINUS_CONSTANT_ALPHA};function ye(W,Ct,St,Dt,Ft,Tt,Yt,Vt,Ke,Ne){if(W===ba){M===!0&&(It(r.BLEND),M=!1);return}if(M===!1&&(xt(r.BLEND),M=!0),W!==Gy){if(W!==S||Ne!==X){if((P!==Fs||F!==Fs)&&(r.blendEquation(r.FUNC_ADD),P=Fs,F=Fs),Ne)switch(W){case Br:r.blendFuncSeparate(r.ONE,r.ONE_MINUS_SRC_ALPHA,r.ONE,r.ONE_MINUS_SRC_ALPHA);break;case vv:r.blendFunc(r.ONE,r.ONE);break;case _v:r.blendFuncSeparate(r.ZERO,r.ONE_MINUS_SRC_COLOR,r.ZERO,r.ONE);break;case xv:r.blendFuncSeparate(r.DST_COLOR,r.ONE_MINUS_SRC_ALPHA,r.ZERO,r.ONE);break;default:be("WebGLState: Invalid blending: ",W);break}else switch(W){case Br:r.blendFuncSeparate(r.SRC_ALPHA,r.ONE_MINUS_SRC_ALPHA,r.ONE,r.ONE_MINUS_SRC_ALPHA);break;case vv:r.blendFuncSeparate(r.SRC_ALPHA,r.ONE,r.ONE,r.ONE);break;case _v:be("WebGLState: SubtractiveBlending requires material.premultipliedAlpha = true");break;case xv:be("WebGLState: MultiplyBlending requires material.premultipliedAlpha = true");break;default:be("WebGLState: Invalid blending: ",W);break}D=null,A=null,O=null,I=null,T.set(0,0,0),N=0,S=W,X=Ne}return}Ft=Ft||Ct,Tt=Tt||St,Yt=Yt||Dt,(Ct!==P||Ft!==F)&&(r.blendEquationSeparate(he[Ct],he[Ft]),P=Ct,F=Ft),(St!==D||Dt!==A||Tt!==O||Yt!==I)&&(r.blendFuncSeparate(Se[St],Se[Dt],Se[Tt],Se[Yt]),D=St,A=Dt,O=Tt,I=Yt),(Vt.equals(T)===!1||Ke!==N)&&(r.blendColor(Vt.r,Vt.g,Vt.b,Ke),T.copy(Vt),N=Ke),S=W,X=!1}function de(W,Ct){W.side===Ma?It(r.CULL_FACE):xt(r.CULL_FACE);let St=W.side===Vn;Ct&&(St=!St),nn(St),W.blending===Br&&W.transparent===!1?ye(ba):ye(W.blending,W.blendEquation,W.blendSrc,W.blendDst,W.blendEquationAlpha,W.blendSrcAlpha,W.blendDstAlpha,W.blendColor,W.blendAlpha,W.premultipliedAlpha),f.setFunc(W.depthFunc),f.setTest(W.depthTest),f.setMask(W.depthWrite),c.setMask(W.colorWrite);const Dt=W.stencilWrite;d.setTest(Dt),Dt&&(d.setMask(W.stencilWriteMask),d.setFunc(W.stencilFunc,W.stencilRef,W.stencilFuncMask),d.setOp(W.stencilFail,W.stencilZFail,W.stencilZPass)),fn(W.polygonOffset,W.polygonOffsetFactor,W.polygonOffsetUnits),W.alphaToCoverage===!0?xt(r.SAMPLE_ALPHA_TO_COVERAGE):It(r.SAMPLE_ALPHA_TO_COVERAGE)}function nn(W){V!==W&&(W?r.frontFace(r.CW):r.frontFace(r.CCW),V=W)}function an(W){W!==By?(xt(r.CULL_FACE),W!==q&&(W===gv?r.cullFace(r.BACK):W===Hy?r.cullFace(r.FRONT):r.cullFace(r.FRONT_AND_BACK))):It(r.CULL_FACE),q=W}function sn(W){W!==ct&&(H&&r.lineWidth(W),ct=W)}function fn(W,Ct,St){W?(xt(r.POLYGON_OFFSET_FILL),(ht!==Ct||j!==St)&&(ht=Ct,j=St,f.getReversed()&&(Ct=-Ct),r.polygonOffset(Ct,St))):It(r.POLYGON_OFFSET_FILL)}function We(W){W?xt(r.SCISSOR_TEST):It(r.SCISSOR_TEST)}function rn(W){W===void 0&&(W=r.TEXTURE0+B-1),Mt!==W&&(r.activeTexture(W),Mt=W)}function Z(W,Ct,St){St===void 0&&(Mt===null?St=r.TEXTURE0+B-1:St=Mt);let Dt=U[St];Dt===void 0&&(Dt={type:void 0,texture:void 0},U[St]=Dt),(Dt.type!==W||Dt.texture!==Ct)&&(Mt!==St&&(r.activeTexture(St),Mt=St),r.bindTexture(W,Ct||_t[W]),Dt.type=W,Dt.texture=Ct)}function Fe(){const W=U[Mt];W!==void 0&&W.type!==void 0&&(r.bindTexture(W.type,null),W.type=void 0,W.texture=void 0)}function Ce(){try{r.compressedTexImage2D(...arguments)}catch(W){be("WebGLState:",W)}}function L(){try{r.compressedTexImage3D(...arguments)}catch(W){be("WebGLState:",W)}}function E(){try{r.texSubImage2D(...arguments)}catch(W){be("WebGLState:",W)}}function et(){try{r.texSubImage3D(...arguments)}catch(W){be("WebGLState:",W)}}function rt(){try{r.compressedTexSubImage2D(...arguments)}catch(W){be("WebGLState:",W)}}function mt(){try{r.compressedTexSubImage3D(...arguments)}catch(W){be("WebGLState:",W)}}function Rt(){try{r.texStorage2D(...arguments)}catch(W){be("WebGLState:",W)}}function Nt(){try{r.texStorage3D(...arguments)}catch(W){be("WebGLState:",W)}}function ft(){try{r.texImage2D(...arguments)}catch(W){be("WebGLState:",W)}}function gt(){try{r.texImage3D(...arguments)}catch(W){be("WebGLState:",W)}}function wt(W){return _[W]!==void 0?_[W]:r.getParameter(W)}function Bt(W,Ct){_[W]!==Ct&&(r.pixelStorei(W,Ct),_[W]=Ct)}function Ot(W){pt.equals(W)===!1&&(r.scissor(W.x,W.y,W.z,W.w),pt.copy(W))}function Ut(W){At.equals(W)===!1&&(r.viewport(W.x,W.y,W.z,W.w),At.copy(W))}function Qt(W,Ct){let St=p.get(Ct);St===void 0&&(St=new WeakMap,p.set(Ct,St));let Dt=St.get(W);Dt===void 0&&(Dt=r.getUniformBlockIndex(Ct,W.name),St.set(W,Dt))}function $t(W,Ct){const Dt=p.get(Ct).get(W);m.get(Ct)!==Dt&&(r.uniformBlockBinding(Ct,Dt,W.__bindingPointIndex),m.set(Ct,Dt))}function ae(){r.disable(r.BLEND),r.disable(r.CULL_FACE),r.disable(r.DEPTH_TEST),r.disable(r.POLYGON_OFFSET_FILL),r.disable(r.SCISSOR_TEST),r.disable(r.STENCIL_TEST),r.disable(r.SAMPLE_ALPHA_TO_COVERAGE),r.blendEquation(r.FUNC_ADD),r.blendFunc(r.ONE,r.ZERO),r.blendFuncSeparate(r.ONE,r.ZERO,r.ONE,r.ZERO),r.blendColor(0,0,0,0),r.colorMask(!0,!0,!0,!0),r.clearColor(0,0,0,0),r.depthMask(!0),r.depthFunc(r.LESS),f.setReversed(!1),r.clearDepth(1),r.stencilMask(4294967295),r.stencilFunc(r.ALWAYS,0,4294967295),r.stencilOp(r.KEEP,r.KEEP,r.KEEP),r.clearStencil(0),r.cullFace(r.BACK),r.frontFace(r.CCW),r.polygonOffset(0,0),r.activeTexture(r.TEXTURE0),r.bindFramebuffer(r.FRAMEBUFFER,null),r.bindFramebuffer(r.DRAW_FRAMEBUFFER,null),r.bindFramebuffer(r.READ_FRAMEBUFFER,null),r.useProgram(null),r.lineWidth(1),r.scissor(0,0,r.canvas.width,r.canvas.height),r.viewport(0,0,r.canvas.width,r.canvas.height),r.pixelStorei(r.PACK_ALIGNMENT,4),r.pixelStorei(r.UNPACK_ALIGNMENT,4),r.pixelStorei(r.UNPACK_FLIP_Y_WEBGL,!1),r.pixelStorei(r.UNPACK_PREMULTIPLY_ALPHA_WEBGL,!1),r.pixelStorei(r.UNPACK_COLORSPACE_CONVERSION_WEBGL,r.BROWSER_DEFAULT_WEBGL),r.pixelStorei(r.PACK_ROW_LENGTH,0),r.pixelStorei(r.PACK_SKIP_PIXELS,0),r.pixelStorei(r.PACK_SKIP_ROWS,0),r.pixelStorei(r.UNPACK_ROW_LENGTH,0),r.pixelStorei(r.UNPACK_IMAGE_HEIGHT,0),r.pixelStorei(r.UNPACK_SKIP_PIXELS,0),r.pixelStorei(r.UNPACK_SKIP_ROWS,0),r.pixelStorei(r.UNPACK_SKIP_IMAGES,0),v={},_={},Mt=null,U={},g={},y=new WeakMap,b=[],w=null,M=!1,S=null,P=null,D=null,A=null,F=null,O=null,I=null,T=new fe(0,0,0),N=0,X=!1,V=null,q=null,ct=null,ht=null,j=null,pt.set(0,0,r.canvas.width,r.canvas.height),At.set(0,0,r.canvas.width,r.canvas.height),c.reset(),f.reset(),d.reset()}return{buffers:{color:c,depth:f,stencil:d},enable:xt,disable:It,bindFramebuffer:jt,drawBuffers:Jt,useProgram:qe,setBlending:ye,setMaterial:de,setFlipSided:nn,setCullFace:an,setLineWidth:sn,setPolygonOffset:fn,setScissorTest:We,activeTexture:rn,bindTexture:Z,unbindTexture:Fe,compressedTexImage2D:Ce,compressedTexImage3D:L,texImage2D:ft,texImage3D:gt,pixelStorei:Bt,getParameter:wt,updateUBOMapping:Qt,uniformBlockBinding:$t,texStorage2D:Rt,texStorage3D:Nt,texSubImage2D:E,texSubImage3D:et,compressedTexSubImage2D:rt,compressedTexSubImage3D:mt,scissor:Ot,viewport:Ut,reset:ae}}function _2(r,t,n,s,l,c,f){const d=t.has("WEBGL_multisampled_render_to_texture")?t.get("WEBGL_multisampled_render_to_texture"):null,m=typeof navigator>"u"?!1:/OculusBrowser/g.test(navigator.userAgent),p=new qt,v=new WeakMap,_=new Set;let g;const y=new WeakMap;let b=!1;try{b=typeof OffscreenCanvas<"u"&&new OffscreenCanvas(1,1).getContext("2d")!==null}catch{}function w(L,E){return b?new OffscreenCanvas(L,E):ru("canvas")}function M(L,E,et){let rt=1;const mt=Ce(L);if((mt.width>et||mt.height>et)&&(rt=et/Math.max(mt.width,mt.height)),rt<1)if(typeof HTMLImageElement<"u"&&L instanceof HTMLImageElement||typeof HTMLCanvasElement<"u"&&L instanceof HTMLCanvasElement||typeof ImageBitmap<"u"&&L instanceof ImageBitmap||typeof VideoFrame<"u"&&L instanceof VideoFrame){const Rt=Math.floor(rt*mt.width),Nt=Math.floor(rt*mt.height);g===void 0&&(g=w(Rt,Nt));const ft=E?w(Rt,Nt):g;return ft.width=Rt,ft.height=Nt,ft.getContext("2d").drawImage(L,0,0,Rt,Nt),ie("WebGLRenderer: Texture has been resized from ("+mt.width+"x"+mt.height+") to ("+Rt+"x"+Nt+")."),ft}else return"data"in L&&ie("WebGLRenderer: Image in DataTexture is too big ("+mt.width+"x"+mt.height+")."),L;return L}function S(L){return L.generateMipmaps}function P(L){r.generateMipmap(L)}function D(L){return L.isWebGLCubeRenderTarget?r.TEXTURE_CUBE_MAP:L.isWebGL3DRenderTarget?r.TEXTURE_3D:L.isWebGLArrayRenderTarget||L.isCompressedArrayTexture?r.TEXTURE_2D_ARRAY:r.TEXTURE_2D}function A(L,E,et,rt,mt,Rt=!1){if(L!==null){if(r[L]!==void 0)return r[L];ie("WebGLRenderer: Attempt to use non-existing WebGL internal format '"+L+"'")}let Nt;rt&&(Nt=t.get("EXT_texture_norm16"),Nt||ie("WebGLRenderer: Unable to use normalized textures without EXT_texture_norm16 extension"));let ft=E;if(E===r.RED&&(et===r.FLOAT&&(ft=r.R32F),et===r.HALF_FLOAT&&(ft=r.R16F),et===r.UNSIGNED_BYTE&&(ft=r.R8),et===r.UNSIGNED_SHORT&&Nt&&(ft=Nt.R16_EXT),et===r.SHORT&&Nt&&(ft=Nt.R16_SNORM_EXT)),E===r.RED_INTEGER&&(et===r.UNSIGNED_BYTE&&(ft=r.R8UI),et===r.UNSIGNED_SHORT&&(ft=r.R16UI),et===r.UNSIGNED_INT&&(ft=r.R32UI),et===r.BYTE&&(ft=r.R8I),et===r.SHORT&&(ft=r.R16I),et===r.INT&&(ft=r.R32I)),E===r.RG&&(et===r.FLOAT&&(ft=r.RG32F),et===r.HALF_FLOAT&&(ft=r.RG16F),et===r.UNSIGNED_BYTE&&(ft=r.RG8),et===r.UNSIGNED_SHORT&&Nt&&(ft=Nt.RG16_EXT),et===r.SHORT&&Nt&&(ft=Nt.RG16_SNORM_EXT)),E===r.RG_INTEGER&&(et===r.UNSIGNED_BYTE&&(ft=r.RG8UI),et===r.UNSIGNED_SHORT&&(ft=r.RG16UI),et===r.UNSIGNED_INT&&(ft=r.RG32UI),et===r.BYTE&&(ft=r.RG8I),et===r.SHORT&&(ft=r.RG16I),et===r.INT&&(ft=r.RG32I)),E===r.RGB_INTEGER&&(et===r.UNSIGNED_BYTE&&(ft=r.RGB8UI),et===r.UNSIGNED_SHORT&&(ft=r.RGB16UI),et===r.UNSIGNED_INT&&(ft=r.RGB32UI),et===r.BYTE&&(ft=r.RGB8I),et===r.SHORT&&(ft=r.RGB16I),et===r.INT&&(ft=r.RGB32I)),E===r.RGBA_INTEGER&&(et===r.UNSIGNED_BYTE&&(ft=r.RGBA8UI),et===r.UNSIGNED_SHORT&&(ft=r.RGBA16UI),et===r.UNSIGNED_INT&&(ft=r.RGBA32UI),et===r.BYTE&&(ft=r.RGBA8I),et===r.SHORT&&(ft=r.RGBA16I),et===r.INT&&(ft=r.RGBA32I)),E===r.RGB&&(et===r.UNSIGNED_SHORT&&Nt&&(ft=Nt.RGB16_EXT),et===r.SHORT&&Nt&&(ft=Nt.RGB16_SNORM_EXT),et===r.UNSIGNED_INT_5_9_9_9_REV&&(ft=r.RGB9_E5),et===r.UNSIGNED_INT_10F_11F_11F_REV&&(ft=r.R11F_G11F_B10F)),E===r.RGBA){const gt=Rt?su:Ee.getTransfer(mt);et===r.FLOAT&&(ft=r.RGBA32F),et===r.HALF_FLOAT&&(ft=r.RGBA16F),et===r.UNSIGNED_BYTE&&(ft=gt===ze?r.SRGB8_ALPHA8:r.RGBA8),et===r.UNSIGNED_SHORT&&Nt&&(ft=Nt.RGBA16_EXT),et===r.SHORT&&Nt&&(ft=Nt.RGBA16_SNORM_EXT),et===r.UNSIGNED_SHORT_4_4_4_4&&(ft=r.RGBA4),et===r.UNSIGNED_SHORT_5_5_5_1&&(ft=r.RGB5_A1)}return(ft===r.R16F||ft===r.R32F||ft===r.RG16F||ft===r.RG32F||ft===r.RGBA16F||ft===r.RGBA32F)&&t.get("EXT_color_buffer_float"),ft}function F(L,E){let et;return L?E===null||E===ji||E===al?et=r.DEPTH24_STENCIL8:E===Wi?et=r.DEPTH32F_STENCIL8:E===il&&(et=r.DEPTH24_STENCIL8,ie("DepthTexture: 16 bit depth attachment is not supported with stencil. Using 24-bit attachment.")):E===null||E===ji||E===al?et=r.DEPTH_COMPONENT24:E===Wi?et=r.DEPTH_COMPONENT32F:E===il&&(et=r.DEPTH_COMPONENT16),et}function O(L,E){return S(L)===!0||L.isFramebufferTexture&&L.minFilter!==Ln&&L.minFilter!==Bn?Math.log2(Math.max(E.width,E.height))+1:L.mipmaps!==void 0&&L.mipmaps.length>0?L.mipmaps.length:L.isCompressedTexture&&Array.isArray(L.image)?E.mipmaps.length:1}function I(L){const E=L.target;E.removeEventListener("dispose",I),N(E),E.isVideoTexture&&v.delete(E),E.isHTMLTexture&&_.delete(E)}function T(L){const E=L.target;E.removeEventListener("dispose",T),V(E)}function N(L){const E=s.get(L);if(E.__webglInit===void 0)return;const et=L.source,rt=y.get(et);if(rt){const mt=rt[E.__cacheKey];mt.usedTimes--,mt.usedTimes===0&&X(L),Object.keys(rt).length===0&&y.delete(et)}s.remove(L)}function X(L){const E=s.get(L);r.deleteTexture(E.__webglTexture);const et=L.source,rt=y.get(et);delete rt[E.__cacheKey],f.memory.textures--}function V(L){const E=s.get(L);if(L.depthTexture&&(L.depthTexture.dispose(),s.remove(L.depthTexture)),L.isWebGLCubeRenderTarget)for(let rt=0;rt<6;rt++){if(Array.isArray(E.__webglFramebuffer[rt]))for(let mt=0;mt<E.__webglFramebuffer[rt].length;mt++)r.deleteFramebuffer(E.__webglFramebuffer[rt][mt]);else r.deleteFramebuffer(E.__webglFramebuffer[rt]);E.__webglDepthbuffer&&r.deleteRenderbuffer(E.__webglDepthbuffer[rt])}else{if(Array.isArray(E.__webglFramebuffer))for(let rt=0;rt<E.__webglFramebuffer.length;rt++)r.deleteFramebuffer(E.__webglFramebuffer[rt]);else r.deleteFramebuffer(E.__webglFramebuffer);if(E.__webglDepthbuffer&&r.deleteRenderbuffer(E.__webglDepthbuffer),E.__webglMultisampledFramebuffer&&r.deleteFramebuffer(E.__webglMultisampledFramebuffer),E.__webglColorRenderbuffer)for(let rt=0;rt<E.__webglColorRenderbuffer.length;rt++)E.__webglColorRenderbuffer[rt]&&r.deleteRenderbuffer(E.__webglColorRenderbuffer[rt]);E.__webglDepthRenderbuffer&&r.deleteRenderbuffer(E.__webglDepthRenderbuffer)}const et=L.textures;for(let rt=0,mt=et.length;rt<mt;rt++){const Rt=s.get(et[rt]);Rt.__webglTexture&&(r.deleteTexture(Rt.__webglTexture),f.memory.textures--),s.remove(et[rt])}s.remove(L)}let q=0;function ct(){q=0}function ht(){return q}function j(L){q=L}function B(){const L=q;return L>=l.maxTextures&&ie("WebGLTextures: Trying to use "+L+" texture units while this GPU supports only "+l.maxTextures),q+=1,L}function H(L){const E=[];return E.push(L.wrapS),E.push(L.wrapT),E.push(L.wrapR||0),E.push(L.magFilter),E.push(L.minFilter),E.push(L.anisotropy),E.push(L.internalFormat),E.push(L.format),E.push(L.type),E.push(L.generateMipmaps),E.push(L.premultiplyAlpha),E.push(L.flipY),E.push(L.unpackAlignment),E.push(L.colorSpace),E.join()}function $(L,E){const et=s.get(L);if(L.isVideoTexture&&Z(L),L.isRenderTargetTexture===!1&&L.isExternalTexture!==!0&&L.version>0&&et.__version!==L.version){const rt=L.image;if(rt===null)ie("WebGLRenderer: Texture marked for update but no image data found.");else if(rt.complete===!1)ie("WebGLRenderer: Texture marked for update but image is incomplete");else{It(et,L,E);return}}else L.isExternalTexture&&(et.__webglTexture=L.sourceTexture?L.sourceTexture:null);n.bindTexture(r.TEXTURE_2D,et.__webglTexture,r.TEXTURE0+E)}function dt(L,E){const et=s.get(L);if(L.isRenderTargetTexture===!1&&L.version>0&&et.__version!==L.version){It(et,L,E);return}else L.isExternalTexture&&(et.__webglTexture=L.sourceTexture?L.sourceTexture:null);n.bindTexture(r.TEXTURE_2D_ARRAY,et.__webglTexture,r.TEXTURE0+E)}function Mt(L,E){const et=s.get(L);if(L.isRenderTargetTexture===!1&&L.version>0&&et.__version!==L.version){It(et,L,E);return}n.bindTexture(r.TEXTURE_3D,et.__webglTexture,r.TEXTURE0+E)}function U(L,E){const et=s.get(L);if(L.isCubeDepthTexture!==!0&&L.version>0&&et.__version!==L.version){jt(et,L,E);return}n.bindTexture(r.TEXTURE_CUBE_MAP,et.__webglTexture,r.TEXTURE0+E)}const J={[_d]:r.REPEAT,[Ea]:r.CLAMP_TO_EDGE,[xd]:r.MIRRORED_REPEAT},bt={[Ln]:r.NEAREST,[oM]:r.NEAREST_MIPMAP_NEAREST,[Ec]:r.NEAREST_MIPMAP_LINEAR,[Bn]:r.LINEAR,[Ah]:r.LINEAR_MIPMAP_NEAREST,[Hs]:r.LINEAR_MIPMAP_LINEAR},pt={[uM]:r.NEVER,[mM]:r.ALWAYS,[fM]:r.LESS,[fp]:r.LEQUAL,[hM]:r.EQUAL,[hp]:r.GEQUAL,[dM]:r.GREATER,[pM]:r.NOTEQUAL};function At(L,E){if(E.type===Wi&&t.has("OES_texture_float_linear")===!1&&(E.magFilter===Bn||E.magFilter===Ah||E.magFilter===Ec||E.magFilter===Hs||E.minFilter===Bn||E.minFilter===Ah||E.minFilter===Ec||E.minFilter===Hs)&&ie("WebGLRenderer: Unable to use linear filtering with floating point textures. OES_texture_float_linear not supported on this device."),r.texParameteri(L,r.TEXTURE_WRAP_S,J[E.wrapS]),r.texParameteri(L,r.TEXTURE_WRAP_T,J[E.wrapT]),(L===r.TEXTURE_3D||L===r.TEXTURE_2D_ARRAY)&&r.texParameteri(L,r.TEXTURE_WRAP_R,J[E.wrapR]),r.texParameteri(L,r.TEXTURE_MAG_FILTER,bt[E.magFilter]),r.texParameteri(L,r.TEXTURE_MIN_FILTER,bt[E.minFilter]),E.compareFunction&&(r.texParameteri(L,r.TEXTURE_COMPARE_MODE,r.COMPARE_REF_TO_TEXTURE),r.texParameteri(L,r.TEXTURE_COMPARE_FUNC,pt[E.compareFunction])),t.has("EXT_texture_filter_anisotropic")===!0){if(E.magFilter===Ln||E.minFilter!==Ec&&E.minFilter!==Hs||E.type===Wi&&t.has("OES_texture_float_linear")===!1)return;if(E.anisotropy>1||s.get(E).__currentAnisotropy){const et=t.get("EXT_texture_filter_anisotropic");r.texParameterf(L,et.TEXTURE_MAX_ANISOTROPY_EXT,Math.min(E.anisotropy,l.getMaxAnisotropy())),s.get(E).__currentAnisotropy=E.anisotropy}}}function tt(L,E){let et=!1;L.__webglInit===void 0&&(L.__webglInit=!0,E.addEventListener("dispose",I));const rt=E.source;let mt=y.get(rt);mt===void 0&&(mt={},y.set(rt,mt));const Rt=H(E);if(Rt!==L.__cacheKey){mt[Rt]===void 0&&(mt[Rt]={texture:r.createTexture(),usedTimes:0},f.memory.textures++,et=!0),mt[Rt].usedTimes++;const Nt=mt[L.__cacheKey];Nt!==void 0&&(mt[L.__cacheKey].usedTimes--,Nt.usedTimes===0&&X(E)),L.__cacheKey=Rt,L.__webglTexture=mt[Rt].texture}return et}function _t(L,E,et){return Math.floor(Math.floor(L/et)/E)}function xt(L,E,et,rt){const Rt=L.updateRanges;if(Rt.length===0)n.texSubImage2D(r.TEXTURE_2D,0,0,0,E.width,E.height,et,rt,E.data);else{Rt.sort((Bt,Ot)=>Bt.start-Ot.start);let Nt=0;for(let Bt=1;Bt<Rt.length;Bt++){const Ot=Rt[Nt],Ut=Rt[Bt],Qt=Ot.start+Ot.count,$t=_t(Ut.start,E.width,4),ae=_t(Ot.start,E.width,4);Ut.start<=Qt+1&&$t===ae&&_t(Ut.start+Ut.count-1,E.width,4)===$t?Ot.count=Math.max(Ot.count,Ut.start+Ut.count-Ot.start):(++Nt,Rt[Nt]=Ut)}Rt.length=Nt+1;const ft=n.getParameter(r.UNPACK_ROW_LENGTH),gt=n.getParameter(r.UNPACK_SKIP_PIXELS),wt=n.getParameter(r.UNPACK_SKIP_ROWS);n.pixelStorei(r.UNPACK_ROW_LENGTH,E.width);for(let Bt=0,Ot=Rt.length;Bt<Ot;Bt++){const Ut=Rt[Bt],Qt=Math.floor(Ut.start/4),$t=Math.ceil(Ut.count/4),ae=Qt%E.width,W=Math.floor(Qt/E.width),Ct=$t,St=1;n.pixelStorei(r.UNPACK_SKIP_PIXELS,ae),n.pixelStorei(r.UNPACK_SKIP_ROWS,W),n.texSubImage2D(r.TEXTURE_2D,0,ae,W,Ct,St,et,rt,E.data)}L.clearUpdateRanges(),n.pixelStorei(r.UNPACK_ROW_LENGTH,ft),n.pixelStorei(r.UNPACK_SKIP_PIXELS,gt),n.pixelStorei(r.UNPACK_SKIP_ROWS,wt)}}function It(L,E,et){let rt=r.TEXTURE_2D;(E.isDataArrayTexture||E.isCompressedArrayTexture)&&(rt=r.TEXTURE_2D_ARRAY),E.isData3DTexture&&(rt=r.TEXTURE_3D);const mt=tt(L,E),Rt=E.source;n.bindTexture(rt,L.__webglTexture,r.TEXTURE0+et);const Nt=s.get(Rt);if(Rt.version!==Nt.__version||mt===!0){if(n.activeTexture(r.TEXTURE0+et),(typeof ImageBitmap<"u"&&E.image instanceof ImageBitmap)===!1){const St=Ee.getPrimaries(Ee.workingColorSpace),Dt=E.colorSpace===os?null:Ee.getPrimaries(E.colorSpace),Ft=E.colorSpace===os||St===Dt?r.NONE:r.BROWSER_DEFAULT_WEBGL;n.pixelStorei(r.UNPACK_FLIP_Y_WEBGL,E.flipY),n.pixelStorei(r.UNPACK_PREMULTIPLY_ALPHA_WEBGL,E.premultiplyAlpha),n.pixelStorei(r.UNPACK_COLORSPACE_CONVERSION_WEBGL,Ft)}n.pixelStorei(r.UNPACK_ALIGNMENT,E.unpackAlignment);let gt=M(E.image,!1,l.maxTextureSize);gt=Fe(E,gt);const wt=c.convert(E.format,E.colorSpace),Bt=c.convert(E.type);let Ot=A(E.internalFormat,wt,Bt,E.normalized,E.colorSpace,E.isVideoTexture);At(rt,E);let Ut;const Qt=E.mipmaps,$t=E.isVideoTexture!==!0,ae=Nt.__version===void 0||mt===!0,W=Rt.dataReady,Ct=O(E,gt);if(E.isDepthTexture)Ot=F(E.format===Gs,E.type),ae&&($t?n.texStorage2D(r.TEXTURE_2D,1,Ot,gt.width,gt.height):n.texImage2D(r.TEXTURE_2D,0,Ot,gt.width,gt.height,0,wt,Bt,null));else if(E.isDataTexture)if(Qt.length>0){$t&&ae&&n.texStorage2D(r.TEXTURE_2D,Ct,Ot,Qt[0].width,Qt[0].height);for(let St=0,Dt=Qt.length;St<Dt;St++)Ut=Qt[St],$t?W&&n.texSubImage2D(r.TEXTURE_2D,St,0,0,Ut.width,Ut.height,wt,Bt,Ut.data):n.texImage2D(r.TEXTURE_2D,St,Ot,Ut.width,Ut.height,0,wt,Bt,Ut.data);E.generateMipmaps=!1}else $t?(ae&&n.texStorage2D(r.TEXTURE_2D,Ct,Ot,gt.width,gt.height),W&&xt(E,gt,wt,Bt)):n.texImage2D(r.TEXTURE_2D,0,Ot,gt.width,gt.height,0,wt,Bt,gt.data);else if(E.isCompressedTexture)if(E.isCompressedArrayTexture){$t&&ae&&n.texStorage3D(r.TEXTURE_2D_ARRAY,Ct,Ot,Qt[0].width,Qt[0].height,gt.depth);for(let St=0,Dt=Qt.length;St<Dt;St++)if(Ut=Qt[St],E.format!==Pi)if(wt!==null)if($t){if(W)if(E.layerUpdates.size>0){const Ft=n_(Ut.width,Ut.height,E.format,E.type);for(const Tt of E.layerUpdates){const Yt=Ut.data.subarray(Tt*Ft/Ut.data.BYTES_PER_ELEMENT,(Tt+1)*Ft/Ut.data.BYTES_PER_ELEMENT);n.compressedTexSubImage3D(r.TEXTURE_2D_ARRAY,St,0,0,Tt,Ut.width,Ut.height,1,wt,Yt)}E.clearLayerUpdates()}else n.compressedTexSubImage3D(r.TEXTURE_2D_ARRAY,St,0,0,0,Ut.width,Ut.height,gt.depth,wt,Ut.data)}else n.compressedTexImage3D(r.TEXTURE_2D_ARRAY,St,Ot,Ut.width,Ut.height,gt.depth,0,Ut.data,0,0);else ie("WebGLRenderer: Attempt to load unsupported compressed texture format in .uploadTexture()");else $t?W&&n.texSubImage3D(r.TEXTURE_2D_ARRAY,St,0,0,0,Ut.width,Ut.height,gt.depth,wt,Bt,Ut.data):n.texImage3D(r.TEXTURE_2D_ARRAY,St,Ot,Ut.width,Ut.height,gt.depth,0,wt,Bt,Ut.data)}else{$t&&ae&&n.texStorage2D(r.TEXTURE_2D,Ct,Ot,Qt[0].width,Qt[0].height);for(let St=0,Dt=Qt.length;St<Dt;St++)Ut=Qt[St],E.format!==Pi?wt!==null?$t?W&&n.compressedTexSubImage2D(r.TEXTURE_2D,St,0,0,Ut.width,Ut.height,wt,Ut.data):n.compressedTexImage2D(r.TEXTURE_2D,St,Ot,Ut.width,Ut.height,0,Ut.data):ie("WebGLRenderer: Attempt to load unsupported compressed texture format in .uploadTexture()"):$t?W&&n.texSubImage2D(r.TEXTURE_2D,St,0,0,Ut.width,Ut.height,wt,Bt,Ut.data):n.texImage2D(r.TEXTURE_2D,St,Ot,Ut.width,Ut.height,0,wt,Bt,Ut.data)}else if(E.isDataArrayTexture)if($t){if(ae&&n.texStorage3D(r.TEXTURE_2D_ARRAY,Ct,Ot,gt.width,gt.height,gt.depth),W)if(E.layerUpdates.size>0){const St=n_(gt.width,gt.height,E.format,E.type);for(const Dt of E.layerUpdates){const Ft=gt.data.subarray(Dt*St/gt.data.BYTES_PER_ELEMENT,(Dt+1)*St/gt.data.BYTES_PER_ELEMENT);n.texSubImage3D(r.TEXTURE_2D_ARRAY,0,0,0,Dt,gt.width,gt.height,1,wt,Bt,Ft)}E.clearLayerUpdates()}else n.texSubImage3D(r.TEXTURE_2D_ARRAY,0,0,0,0,gt.width,gt.height,gt.depth,wt,Bt,gt.data)}else n.texImage3D(r.TEXTURE_2D_ARRAY,0,Ot,gt.width,gt.height,gt.depth,0,wt,Bt,gt.data);else if(E.isData3DTexture)$t?(ae&&n.texStorage3D(r.TEXTURE_3D,Ct,Ot,gt.width,gt.height,gt.depth),W&&n.texSubImage3D(r.TEXTURE_3D,0,0,0,0,gt.width,gt.height,gt.depth,wt,Bt,gt.data)):n.texImage3D(r.TEXTURE_3D,0,Ot,gt.width,gt.height,gt.depth,0,wt,Bt,gt.data);else if(E.isFramebufferTexture){if(ae)if($t)n.texStorage2D(r.TEXTURE_2D,Ct,Ot,gt.width,gt.height);else{let St=gt.width,Dt=gt.height;for(let Ft=0;Ft<Ct;Ft++)n.texImage2D(r.TEXTURE_2D,Ft,Ot,St,Dt,0,wt,Bt,null),St>>=1,Dt>>=1}}else if(E.isHTMLTexture){if("texElementImage2D"in r){const St=r.canvas;if(St.hasAttribute("layoutsubtree")||St.setAttribute("layoutsubtree","true"),gt.parentNode!==St){St.appendChild(gt),_.add(E),St.onpaint=Dt=>{const Ft=Dt.changedElements;for(const Tt of _)Ft.includes(Tt.image)&&(Tt.needsUpdate=!0)},St.requestPaint();return}if(r.texElementImage2D.length===3)r.texElementImage2D(r.TEXTURE_2D,r.RGBA8,gt);else{const Ft=r.RGBA,Tt=r.RGBA,Yt=r.UNSIGNED_BYTE;r.texElementImage2D(r.TEXTURE_2D,0,Ft,Tt,Yt,gt)}r.texParameteri(r.TEXTURE_2D,r.TEXTURE_MIN_FILTER,r.LINEAR),r.texParameteri(r.TEXTURE_2D,r.TEXTURE_WRAP_S,r.CLAMP_TO_EDGE),r.texParameteri(r.TEXTURE_2D,r.TEXTURE_WRAP_T,r.CLAMP_TO_EDGE)}}else if(Qt.length>0){if($t&&ae){const St=Ce(Qt[0]);n.texStorage2D(r.TEXTURE_2D,Ct,Ot,St.width,St.height)}for(let St=0,Dt=Qt.length;St<Dt;St++)Ut=Qt[St],$t?W&&n.texSubImage2D(r.TEXTURE_2D,St,0,0,wt,Bt,Ut):n.texImage2D(r.TEXTURE_2D,St,Ot,wt,Bt,Ut);E.generateMipmaps=!1}else if($t){if(ae){const St=Ce(gt);n.texStorage2D(r.TEXTURE_2D,Ct,Ot,St.width,St.height)}W&&n.texSubImage2D(r.TEXTURE_2D,0,0,0,wt,Bt,gt)}else n.texImage2D(r.TEXTURE_2D,0,Ot,wt,Bt,gt);S(E)&&P(rt),Nt.__version=Rt.version,E.onUpdate&&E.onUpdate(E)}L.__version=E.version}function jt(L,E,et){if(E.image.length!==6)return;const rt=tt(L,E),mt=E.source;n.bindTexture(r.TEXTURE_CUBE_MAP,L.__webglTexture,r.TEXTURE0+et);const Rt=s.get(mt);if(mt.version!==Rt.__version||rt===!0){n.activeTexture(r.TEXTURE0+et);const Nt=Ee.getPrimaries(Ee.workingColorSpace),ft=E.colorSpace===os?null:Ee.getPrimaries(E.colorSpace),gt=E.colorSpace===os||Nt===ft?r.NONE:r.BROWSER_DEFAULT_WEBGL;n.pixelStorei(r.UNPACK_FLIP_Y_WEBGL,E.flipY),n.pixelStorei(r.UNPACK_PREMULTIPLY_ALPHA_WEBGL,E.premultiplyAlpha),n.pixelStorei(r.UNPACK_ALIGNMENT,E.unpackAlignment),n.pixelStorei(r.UNPACK_COLORSPACE_CONVERSION_WEBGL,gt);const wt=E.isCompressedTexture||E.image[0].isCompressedTexture,Bt=E.image[0]&&E.image[0].isDataTexture,Ot=[];for(let Tt=0;Tt<6;Tt++)!wt&&!Bt?Ot[Tt]=M(E.image[Tt],!0,l.maxCubemapSize):Ot[Tt]=Bt?E.image[Tt].image:E.image[Tt],Ot[Tt]=Fe(E,Ot[Tt]);const Ut=Ot[0],Qt=c.convert(E.format,E.colorSpace),$t=c.convert(E.type),ae=A(E.internalFormat,Qt,$t,E.normalized,E.colorSpace),W=E.isVideoTexture!==!0,Ct=Rt.__version===void 0||rt===!0,St=mt.dataReady;let Dt=O(E,Ut);At(r.TEXTURE_CUBE_MAP,E);let Ft;if(wt){W&&Ct&&n.texStorage2D(r.TEXTURE_CUBE_MAP,Dt,ae,Ut.width,Ut.height);for(let Tt=0;Tt<6;Tt++){Ft=Ot[Tt].mipmaps;for(let Yt=0;Yt<Ft.length;Yt++){const Vt=Ft[Yt];E.format!==Pi?Qt!==null?W?St&&n.compressedTexSubImage2D(r.TEXTURE_CUBE_MAP_POSITIVE_X+Tt,Yt,0,0,Vt.width,Vt.height,Qt,Vt.data):n.compressedTexImage2D(r.TEXTURE_CUBE_MAP_POSITIVE_X+Tt,Yt,ae,Vt.width,Vt.height,0,Vt.data):ie("WebGLRenderer: Attempt to load unsupported compressed texture format in .setTextureCube()"):W?St&&n.texSubImage2D(r.TEXTURE_CUBE_MAP_POSITIVE_X+Tt,Yt,0,0,Vt.width,Vt.height,Qt,$t,Vt.data):n.texImage2D(r.TEXTURE_CUBE_MAP_POSITIVE_X+Tt,Yt,ae,Vt.width,Vt.height,0,Qt,$t,Vt.data)}}}else{if(Ft=E.mipmaps,W&&Ct){Ft.length>0&&Dt++;const Tt=Ce(Ot[0]);n.texStorage2D(r.TEXTURE_CUBE_MAP,Dt,ae,Tt.width,Tt.height)}for(let Tt=0;Tt<6;Tt++)if(Bt){W?St&&n.texSubImage2D(r.TEXTURE_CUBE_MAP_POSITIVE_X+Tt,0,0,0,Ot[Tt].width,Ot[Tt].height,Qt,$t,Ot[Tt].data):n.texImage2D(r.TEXTURE_CUBE_MAP_POSITIVE_X+Tt,0,ae,Ot[Tt].width,Ot[Tt].height,0,Qt,$t,Ot[Tt].data);for(let Yt=0;Yt<Ft.length;Yt++){const Ke=Ft[Yt].image[Tt].image;W?St&&n.texSubImage2D(r.TEXTURE_CUBE_MAP_POSITIVE_X+Tt,Yt+1,0,0,Ke.width,Ke.height,Qt,$t,Ke.data):n.texImage2D(r.TEXTURE_CUBE_MAP_POSITIVE_X+Tt,Yt+1,ae,Ke.width,Ke.height,0,Qt,$t,Ke.data)}}else{W?St&&n.texSubImage2D(r.TEXTURE_CUBE_MAP_POSITIVE_X+Tt,0,0,0,Qt,$t,Ot[Tt]):n.texImage2D(r.TEXTURE_CUBE_MAP_POSITIVE_X+Tt,0,ae,Qt,$t,Ot[Tt]);for(let Yt=0;Yt<Ft.length;Yt++){const Vt=Ft[Yt];W?St&&n.texSubImage2D(r.TEXTURE_CUBE_MAP_POSITIVE_X+Tt,Yt+1,0,0,Qt,$t,Vt.image[Tt]):n.texImage2D(r.TEXTURE_CUBE_MAP_POSITIVE_X+Tt,Yt+1,ae,Qt,$t,Vt.image[Tt])}}}S(E)&&P(r.TEXTURE_CUBE_MAP),Rt.__version=mt.version,E.onUpdate&&E.onUpdate(E)}L.__version=E.version}function Jt(L,E,et,rt,mt,Rt){const Nt=c.convert(et.format,et.colorSpace),ft=c.convert(et.type),gt=A(et.internalFormat,Nt,ft,et.normalized,et.colorSpace),wt=s.get(E),Bt=s.get(et);if(Bt.__renderTarget=E,!wt.__hasExternalTextures){const Ot=Math.max(1,E.width>>Rt),Ut=Math.max(1,E.height>>Rt);mt===r.TEXTURE_3D||mt===r.TEXTURE_2D_ARRAY?n.texImage3D(mt,Rt,gt,Ot,Ut,E.depth,0,Nt,ft,null):n.texImage2D(mt,Rt,gt,Ot,Ut,0,Nt,ft,null)}n.bindFramebuffer(r.FRAMEBUFFER,L),rn(E)?d.framebufferTexture2DMultisampleEXT(r.FRAMEBUFFER,rt,mt,Bt.__webglTexture,0,We(E)):(mt===r.TEXTURE_2D||mt>=r.TEXTURE_CUBE_MAP_POSITIVE_X&&mt<=r.TEXTURE_CUBE_MAP_NEGATIVE_Z)&&r.framebufferTexture2D(r.FRAMEBUFFER,rt,mt,Bt.__webglTexture,Rt),n.bindFramebuffer(r.FRAMEBUFFER,null)}function qe(L,E,et){if(r.bindRenderbuffer(r.RENDERBUFFER,L),E.depthBuffer){const rt=E.depthTexture,mt=rt&&rt.isDepthTexture?rt.type:null,Rt=F(E.stencilBuffer,mt),Nt=E.stencilBuffer?r.DEPTH_STENCIL_ATTACHMENT:r.DEPTH_ATTACHMENT;rn(E)?d.renderbufferStorageMultisampleEXT(r.RENDERBUFFER,We(E),Rt,E.width,E.height):et?r.renderbufferStorageMultisample(r.RENDERBUFFER,We(E),Rt,E.width,E.height):r.renderbufferStorage(r.RENDERBUFFER,Rt,E.width,E.height),r.framebufferRenderbuffer(r.FRAMEBUFFER,Nt,r.RENDERBUFFER,L)}else{const rt=E.textures;for(let mt=0;mt<rt.length;mt++){const Rt=rt[mt],Nt=c.convert(Rt.format,Rt.colorSpace),ft=c.convert(Rt.type),gt=A(Rt.internalFormat,Nt,ft,Rt.normalized,Rt.colorSpace);rn(E)?d.renderbufferStorageMultisampleEXT(r.RENDERBUFFER,We(E),gt,E.width,E.height):et?r.renderbufferStorageMultisample(r.RENDERBUFFER,We(E),gt,E.width,E.height):r.renderbufferStorage(r.RENDERBUFFER,gt,E.width,E.height)}}r.bindRenderbuffer(r.RENDERBUFFER,null)}function he(L,E,et){const rt=E.isWebGLCubeRenderTarget===!0;if(n.bindFramebuffer(r.FRAMEBUFFER,L),!(E.depthTexture&&E.depthTexture.isDepthTexture))throw new Error("THREE.WebGLTextures: renderTarget.depthTexture must be an instance of THREE.DepthTexture.");const mt=s.get(E.depthTexture);if(mt.__renderTarget=E,(!mt.__webglTexture||E.depthTexture.image.width!==E.width||E.depthTexture.image.height!==E.height)&&(E.depthTexture.image.width=E.width,E.depthTexture.image.height=E.height,E.depthTexture.needsUpdate=!0),rt){if(mt.__webglInit===void 0&&(mt.__webglInit=!0,E.depthTexture.addEventListener("dispose",I)),mt.__webglTexture===void 0){mt.__webglTexture=r.createTexture(),n.bindTexture(r.TEXTURE_CUBE_MAP,mt.__webglTexture),At(r.TEXTURE_CUBE_MAP,E.depthTexture);const wt=c.convert(E.depthTexture.format),Bt=c.convert(E.depthTexture.type);let Ot;E.depthTexture.format===Ra?Ot=r.DEPTH_COMPONENT24:E.depthTexture.format===Gs&&(Ot=r.DEPTH24_STENCIL8);for(let Ut=0;Ut<6;Ut++)r.texImage2D(r.TEXTURE_CUBE_MAP_POSITIVE_X+Ut,0,Ot,E.width,E.height,0,wt,Bt,null)}}else $(E.depthTexture,0);const Rt=mt.__webglTexture,Nt=We(E),ft=rt?r.TEXTURE_CUBE_MAP_POSITIVE_X+et:r.TEXTURE_2D,gt=E.depthTexture.format===Gs?r.DEPTH_STENCIL_ATTACHMENT:r.DEPTH_ATTACHMENT;if(E.depthTexture.format===Ra)rn(E)?d.framebufferTexture2DMultisampleEXT(r.FRAMEBUFFER,gt,ft,Rt,0,Nt):r.framebufferTexture2D(r.FRAMEBUFFER,gt,ft,Rt,0);else if(E.depthTexture.format===Gs)rn(E)?d.framebufferTexture2DMultisampleEXT(r.FRAMEBUFFER,gt,ft,Rt,0,Nt):r.framebufferTexture2D(r.FRAMEBUFFER,gt,ft,Rt,0);else throw new Error("THREE.WebGLTextures: Unknown depthTexture format.")}function Se(L){const E=s.get(L),et=L.isWebGLCubeRenderTarget===!0;if(E.__boundDepthTexture!==L.depthTexture){const rt=L.depthTexture;if(E.__depthDisposeCallback&&E.__depthDisposeCallback(),rt){const mt=()=>{delete E.__boundDepthTexture,delete E.__depthDisposeCallback,rt.removeEventListener("dispose",mt)};rt.addEventListener("dispose",mt),E.__depthDisposeCallback=mt}E.__boundDepthTexture=rt}if(L.depthTexture&&!E.__autoAllocateDepthBuffer)if(et)for(let rt=0;rt<6;rt++)he(E.__webglFramebuffer[rt],L,rt);else{const rt=L.texture.mipmaps;rt&&rt.length>0?he(E.__webglFramebuffer[0],L,0):he(E.__webglFramebuffer,L,0)}else if(et){E.__webglDepthbuffer=[];for(let rt=0;rt<6;rt++)if(n.bindFramebuffer(r.FRAMEBUFFER,E.__webglFramebuffer[rt]),E.__webglDepthbuffer[rt]===void 0)E.__webglDepthbuffer[rt]=r.createRenderbuffer(),qe(E.__webglDepthbuffer[rt],L,!1);else{const mt=L.stencilBuffer?r.DEPTH_STENCIL_ATTACHMENT:r.DEPTH_ATTACHMENT,Rt=E.__webglDepthbuffer[rt];r.bindRenderbuffer(r.RENDERBUFFER,Rt),r.framebufferRenderbuffer(r.FRAMEBUFFER,mt,r.RENDERBUFFER,Rt)}}else{const rt=L.texture.mipmaps;if(rt&&rt.length>0?n.bindFramebuffer(r.FRAMEBUFFER,E.__webglFramebuffer[0]):n.bindFramebuffer(r.FRAMEBUFFER,E.__webglFramebuffer),E.__webglDepthbuffer===void 0)E.__webglDepthbuffer=r.createRenderbuffer(),qe(E.__webglDepthbuffer,L,!1);else{const mt=L.stencilBuffer?r.DEPTH_STENCIL_ATTACHMENT:r.DEPTH_ATTACHMENT,Rt=E.__webglDepthbuffer;r.bindRenderbuffer(r.RENDERBUFFER,Rt),r.framebufferRenderbuffer(r.FRAMEBUFFER,mt,r.RENDERBUFFER,Rt)}}n.bindFramebuffer(r.FRAMEBUFFER,null)}function ye(L,E,et){const rt=s.get(L);E!==void 0&&Jt(rt.__webglFramebuffer,L,L.texture,r.COLOR_ATTACHMENT0,r.TEXTURE_2D,0),et!==void 0&&Se(L)}function de(L){const E=L.texture,et=s.get(L),rt=s.get(E);L.addEventListener("dispose",T);const mt=L.textures,Rt=L.isWebGLCubeRenderTarget===!0,Nt=mt.length>1;if(Nt||(rt.__webglTexture===void 0&&(rt.__webglTexture=r.createTexture()),rt.__version=E.version,f.memory.textures++),Rt){et.__webglFramebuffer=[];for(let ft=0;ft<6;ft++)if(E.mipmaps&&E.mipmaps.length>0){et.__webglFramebuffer[ft]=[];for(let gt=0;gt<E.mipmaps.length;gt++)et.__webglFramebuffer[ft][gt]=r.createFramebuffer()}else et.__webglFramebuffer[ft]=r.createFramebuffer()}else{if(E.mipmaps&&E.mipmaps.length>0){et.__webglFramebuffer=[];for(let ft=0;ft<E.mipmaps.length;ft++)et.__webglFramebuffer[ft]=r.createFramebuffer()}else et.__webglFramebuffer=r.createFramebuffer();if(Nt)for(let ft=0,gt=mt.length;ft<gt;ft++){const wt=s.get(mt[ft]);wt.__webglTexture===void 0&&(wt.__webglTexture=r.createTexture(),f.memory.textures++)}if(L.samples>0&&rn(L)===!1){et.__webglMultisampledFramebuffer=r.createFramebuffer(),et.__webglColorRenderbuffer=[],n.bindFramebuffer(r.FRAMEBUFFER,et.__webglMultisampledFramebuffer);for(let ft=0;ft<mt.length;ft++){const gt=mt[ft];et.__webglColorRenderbuffer[ft]=r.createRenderbuffer(),r.bindRenderbuffer(r.RENDERBUFFER,et.__webglColorRenderbuffer[ft]);const wt=c.convert(gt.format,gt.colorSpace),Bt=c.convert(gt.type),Ot=A(gt.internalFormat,wt,Bt,gt.normalized,gt.colorSpace,L.isXRRenderTarget===!0),Ut=We(L);r.renderbufferStorageMultisample(r.RENDERBUFFER,Ut,Ot,L.width,L.height),r.framebufferRenderbuffer(r.FRAMEBUFFER,r.COLOR_ATTACHMENT0+ft,r.RENDERBUFFER,et.__webglColorRenderbuffer[ft])}r.bindRenderbuffer(r.RENDERBUFFER,null),L.depthBuffer&&(et.__webglDepthRenderbuffer=r.createRenderbuffer(),qe(et.__webglDepthRenderbuffer,L,!0)),n.bindFramebuffer(r.FRAMEBUFFER,null)}}if(Rt){n.bindTexture(r.TEXTURE_CUBE_MAP,rt.__webglTexture),At(r.TEXTURE_CUBE_MAP,E);for(let ft=0;ft<6;ft++)if(E.mipmaps&&E.mipmaps.length>0)for(let gt=0;gt<E.mipmaps.length;gt++)Jt(et.__webglFramebuffer[ft][gt],L,E,r.COLOR_ATTACHMENT0,r.TEXTURE_CUBE_MAP_POSITIVE_X+ft,gt);else Jt(et.__webglFramebuffer[ft],L,E,r.COLOR_ATTACHMENT0,r.TEXTURE_CUBE_MAP_POSITIVE_X+ft,0);S(E)&&P(r.TEXTURE_CUBE_MAP),n.unbindTexture()}else if(Nt){for(let ft=0,gt=mt.length;ft<gt;ft++){const wt=mt[ft],Bt=s.get(wt);let Ot=r.TEXTURE_2D;(L.isWebGL3DRenderTarget||L.isWebGLArrayRenderTarget)&&(Ot=L.isWebGL3DRenderTarget?r.TEXTURE_3D:r.TEXTURE_2D_ARRAY),n.bindTexture(Ot,Bt.__webglTexture),At(Ot,wt),Jt(et.__webglFramebuffer,L,wt,r.COLOR_ATTACHMENT0+ft,Ot,0),S(wt)&&P(Ot)}n.unbindTexture()}else{let ft=r.TEXTURE_2D;if((L.isWebGL3DRenderTarget||L.isWebGLArrayRenderTarget)&&(ft=L.isWebGL3DRenderTarget?r.TEXTURE_3D:r.TEXTURE_2D_ARRAY),n.bindTexture(ft,rt.__webglTexture),At(ft,E),E.mipmaps&&E.mipmaps.length>0)for(let gt=0;gt<E.mipmaps.length;gt++)Jt(et.__webglFramebuffer[gt],L,E,r.COLOR_ATTACHMENT0,ft,gt);else Jt(et.__webglFramebuffer,L,E,r.COLOR_ATTACHMENT0,ft,0);S(E)&&P(ft),n.unbindTexture()}L.depthBuffer&&Se(L)}function nn(L){const E=L.textures;for(let et=0,rt=E.length;et<rt;et++){const mt=E[et];if(S(mt)){const Rt=D(L),Nt=s.get(mt).__webglTexture;n.bindTexture(Rt,Nt),P(Rt),n.unbindTexture()}}}const an=[],sn=[];function fn(L){if(L.samples>0){if(rn(L)===!1){const E=L.textures,et=L.width,rt=L.height;let mt=r.COLOR_BUFFER_BIT;const Rt=L.stencilBuffer?r.DEPTH_STENCIL_ATTACHMENT:r.DEPTH_ATTACHMENT,Nt=s.get(L),ft=E.length>1;if(ft)for(let wt=0;wt<E.length;wt++)n.bindFramebuffer(r.FRAMEBUFFER,Nt.__webglMultisampledFramebuffer),r.framebufferRenderbuffer(r.FRAMEBUFFER,r.COLOR_ATTACHMENT0+wt,r.RENDERBUFFER,null),n.bindFramebuffer(r.FRAMEBUFFER,Nt.__webglFramebuffer),r.framebufferTexture2D(r.DRAW_FRAMEBUFFER,r.COLOR_ATTACHMENT0+wt,r.TEXTURE_2D,null,0);n.bindFramebuffer(r.READ_FRAMEBUFFER,Nt.__webglMultisampledFramebuffer);const gt=L.texture.mipmaps;gt&&gt.length>0?n.bindFramebuffer(r.DRAW_FRAMEBUFFER,Nt.__webglFramebuffer[0]):n.bindFramebuffer(r.DRAW_FRAMEBUFFER,Nt.__webglFramebuffer);for(let wt=0;wt<E.length;wt++){if(L.resolveDepthBuffer&&(L.depthBuffer&&(mt|=r.DEPTH_BUFFER_BIT),L.stencilBuffer&&L.resolveStencilBuffer&&(mt|=r.STENCIL_BUFFER_BIT)),ft){r.framebufferRenderbuffer(r.READ_FRAMEBUFFER,r.COLOR_ATTACHMENT0,r.RENDERBUFFER,Nt.__webglColorRenderbuffer[wt]);const Bt=s.get(E[wt]).__webglTexture;r.framebufferTexture2D(r.DRAW_FRAMEBUFFER,r.COLOR_ATTACHMENT0,r.TEXTURE_2D,Bt,0)}r.blitFramebuffer(0,0,et,rt,0,0,et,rt,mt,r.NEAREST),m===!0&&(an.length=0,sn.length=0,an.push(r.COLOR_ATTACHMENT0+wt),L.depthBuffer&&L.resolveDepthBuffer===!1&&(an.push(Rt),sn.push(Rt),r.invalidateFramebuffer(r.DRAW_FRAMEBUFFER,sn)),r.invalidateFramebuffer(r.READ_FRAMEBUFFER,an))}if(n.bindFramebuffer(r.READ_FRAMEBUFFER,null),n.bindFramebuffer(r.DRAW_FRAMEBUFFER,null),ft)for(let wt=0;wt<E.length;wt++){n.bindFramebuffer(r.FRAMEBUFFER,Nt.__webglMultisampledFramebuffer),r.framebufferRenderbuffer(r.FRAMEBUFFER,r.COLOR_ATTACHMENT0+wt,r.RENDERBUFFER,Nt.__webglColorRenderbuffer[wt]);const Bt=s.get(E[wt]).__webglTexture;n.bindFramebuffer(r.FRAMEBUFFER,Nt.__webglFramebuffer),r.framebufferTexture2D(r.DRAW_FRAMEBUFFER,r.COLOR_ATTACHMENT0+wt,r.TEXTURE_2D,Bt,0)}n.bindFramebuffer(r.DRAW_FRAMEBUFFER,Nt.__webglMultisampledFramebuffer)}else if(L.depthBuffer&&L.resolveDepthBuffer===!1&&m){const E=L.stencilBuffer?r.DEPTH_STENCIL_ATTACHMENT:r.DEPTH_ATTACHMENT;r.invalidateFramebuffer(r.DRAW_FRAMEBUFFER,[E])}}}function We(L){return Math.min(l.maxSamples,L.samples)}function rn(L){const E=s.get(L);return L.samples>0&&t.has("WEBGL_multisampled_render_to_texture")===!0&&E.__useRenderToTexture!==!1}function Z(L){const E=f.render.frame;v.get(L)!==E&&(v.set(L,E),L.update())}function Fe(L,E){const et=L.colorSpace,rt=L.format,mt=L.type;return L.isCompressedTexture===!0||L.isVideoTexture===!0||et!==au&&et!==os&&(Ee.getTransfer(et)===ze?(rt!==Pi||mt!==di)&&ie("WebGLTextures: sRGB encoded textures have to use RGBAFormat and UnsignedByteType."):be("WebGLTextures: Unsupported texture color space:",et)),E}function Ce(L){return typeof HTMLImageElement<"u"&&L instanceof HTMLImageElement?(p.width=L.naturalWidth||L.width,p.height=L.naturalHeight||L.height):typeof VideoFrame<"u"&&L instanceof VideoFrame?(p.width=L.displayWidth,p.height=L.displayHeight):(p.width=L.width,p.height=L.height),p}this.allocateTextureUnit=B,this.resetTextureUnits=ct,this.getTextureUnits=ht,this.setTextureUnits=j,this.setTexture2D=$,this.setTexture2DArray=dt,this.setTexture3D=Mt,this.setTextureCube=U,this.rebindTextures=ye,this.setupRenderTarget=de,this.updateRenderTargetMipmap=nn,this.updateMultisampleRenderTarget=fn,this.setupDepthRenderbuffer=Se,this.setupFrameBufferTexture=Jt,this.useMultisampledRTT=rn,this.isReversedDepthBuffer=function(){return n.buffers.depth.getReversed()}}function x2(r,t){function n(s,l=os){let c;const f=Ee.getTransfer(l);if(s===di)return r.UNSIGNED_BYTE;if(s===rp)return r.UNSIGNED_SHORT_4_4_4_4;if(s===op)return r.UNSIGNED_SHORT_5_5_5_1;if(s===q_)return r.UNSIGNED_INT_5_9_9_9_REV;if(s===Y_)return r.UNSIGNED_INT_10F_11F_11F_REV;if(s===X_)return r.BYTE;if(s===W_)return r.SHORT;if(s===il)return r.UNSIGNED_SHORT;if(s===sp)return r.INT;if(s===ji)return r.UNSIGNED_INT;if(s===Wi)return r.FLOAT;if(s===Aa)return r.HALF_FLOAT;if(s===Z_)return r.ALPHA;if(s===K_)return r.RGB;if(s===Pi)return r.RGBA;if(s===Ra)return r.DEPTH_COMPONENT;if(s===Gs)return r.DEPTH_STENCIL;if(s===j_)return r.RED;if(s===lp)return r.RED_INTEGER;if(s===ks)return r.RG;if(s===cp)return r.RG_INTEGER;if(s===up)return r.RGBA_INTEGER;if(s===jc||s===Jc||s===Qc||s===$c)if(f===ze)if(c=t.get("WEBGL_compressed_texture_s3tc_srgb"),c!==null){if(s===jc)return c.COMPRESSED_SRGB_S3TC_DXT1_EXT;if(s===Jc)return c.COMPRESSED_SRGB_ALPHA_S3TC_DXT1_EXT;if(s===Qc)return c.COMPRESSED_SRGB_ALPHA_S3TC_DXT3_EXT;if(s===$c)return c.COMPRESSED_SRGB_ALPHA_S3TC_DXT5_EXT}else return null;else if(c=t.get("WEBGL_compressed_texture_s3tc"),c!==null){if(s===jc)return c.COMPRESSED_RGB_S3TC_DXT1_EXT;if(s===Jc)return c.COMPRESSED_RGBA_S3TC_DXT1_EXT;if(s===Qc)return c.COMPRESSED_RGBA_S3TC_DXT3_EXT;if(s===$c)return c.COMPRESSED_RGBA_S3TC_DXT5_EXT}else return null;if(s===Sd||s===yd||s===Md||s===Ed)if(c=t.get("WEBGL_compressed_texture_pvrtc"),c!==null){if(s===Sd)return c.COMPRESSED_RGB_PVRTC_4BPPV1_IMG;if(s===yd)return c.COMPRESSED_RGB_PVRTC_2BPPV1_IMG;if(s===Md)return c.COMPRESSED_RGBA_PVRTC_4BPPV1_IMG;if(s===Ed)return c.COMPRESSED_RGBA_PVRTC_2BPPV1_IMG}else return null;if(s===bd||s===Td||s===Ad||s===Rd||s===Cd||s===nu||s===wd)if(c=t.get("WEBGL_compressed_texture_etc"),c!==null){if(s===bd||s===Td)return f===ze?c.COMPRESSED_SRGB8_ETC2:c.COMPRESSED_RGB8_ETC2;if(s===Ad)return f===ze?c.COMPRESSED_SRGB8_ALPHA8_ETC2_EAC:c.COMPRESSED_RGBA8_ETC2_EAC;if(s===Rd)return c.COMPRESSED_R11_EAC;if(s===Cd)return c.COMPRESSED_SIGNED_R11_EAC;if(s===nu)return c.COMPRESSED_RG11_EAC;if(s===wd)return c.COMPRESSED_SIGNED_RG11_EAC}else return null;if(s===Dd||s===Nd||s===Ud||s===Ld||s===Od||s===Pd||s===Id||s===zd||s===Fd||s===Bd||s===Hd||s===Gd||s===Vd||s===kd)if(c=t.get("WEBGL_compressed_texture_astc"),c!==null){if(s===Dd)return f===ze?c.COMPRESSED_SRGB8_ALPHA8_ASTC_4x4_KHR:c.COMPRESSED_RGBA_ASTC_4x4_KHR;if(s===Nd)return f===ze?c.COMPRESSED_SRGB8_ALPHA8_ASTC_5x4_KHR:c.COMPRESSED_RGBA_ASTC_5x4_KHR;if(s===Ud)return f===ze?c.COMPRESSED_SRGB8_ALPHA8_ASTC_5x5_KHR:c.COMPRESSED_RGBA_ASTC_5x5_KHR;if(s===Ld)return f===ze?c.COMPRESSED_SRGB8_ALPHA8_ASTC_6x5_KHR:c.COMPRESSED_RGBA_ASTC_6x5_KHR;if(s===Od)return f===ze?c.COMPRESSED_SRGB8_ALPHA8_ASTC_6x6_KHR:c.COMPRESSED_RGBA_ASTC_6x6_KHR;if(s===Pd)return f===ze?c.COMPRESSED_SRGB8_ALPHA8_ASTC_8x5_KHR:c.COMPRESSED_RGBA_ASTC_8x5_KHR;if(s===Id)return f===ze?c.COMPRESSED_SRGB8_ALPHA8_ASTC_8x6_KHR:c.COMPRESSED_RGBA_ASTC_8x6_KHR;if(s===zd)return f===ze?c.COMPRESSED_SRGB8_ALPHA8_ASTC_8x8_KHR:c.COMPRESSED_RGBA_ASTC_8x8_KHR;if(s===Fd)return f===ze?c.COMPRESSED_SRGB8_ALPHA8_ASTC_10x5_KHR:c.COMPRESSED_RGBA_ASTC_10x5_KHR;if(s===Bd)return f===ze?c.COMPRESSED_SRGB8_ALPHA8_ASTC_10x6_KHR:c.COMPRESSED_RGBA_ASTC_10x6_KHR;if(s===Hd)return f===ze?c.COMPRESSED_SRGB8_ALPHA8_ASTC_10x8_KHR:c.COMPRESSED_RGBA_ASTC_10x8_KHR;if(s===Gd)return f===ze?c.COMPRESSED_SRGB8_ALPHA8_ASTC_10x10_KHR:c.COMPRESSED_RGBA_ASTC_10x10_KHR;if(s===Vd)return f===ze?c.COMPRESSED_SRGB8_ALPHA8_ASTC_12x10_KHR:c.COMPRESSED_RGBA_ASTC_12x10_KHR;if(s===kd)return f===ze?c.COMPRESSED_SRGB8_ALPHA8_ASTC_12x12_KHR:c.COMPRESSED_RGBA_ASTC_12x12_KHR}else return null;if(s===Xd||s===Wd||s===qd)if(c=t.get("EXT_texture_compression_bptc"),c!==null){if(s===Xd)return f===ze?c.COMPRESSED_SRGB_ALPHA_BPTC_UNORM_EXT:c.COMPRESSED_RGBA_BPTC_UNORM_EXT;if(s===Wd)return c.COMPRESSED_RGB_BPTC_SIGNED_FLOAT_EXT;if(s===qd)return c.COMPRESSED_RGB_BPTC_UNSIGNED_FLOAT_EXT}else return null;if(s===Yd||s===Zd||s===iu||s===Kd)if(c=t.get("EXT_texture_compression_rgtc"),c!==null){if(s===Yd)return c.COMPRESSED_RED_RGTC1_EXT;if(s===Zd)return c.COMPRESSED_SIGNED_RED_RGTC1_EXT;if(s===iu)return c.COMPRESSED_RED_GREEN_RGTC2_EXT;if(s===Kd)return c.COMPRESSED_SIGNED_RED_GREEN_RGTC2_EXT}else return null;return s===al?r.UNSIGNED_INT_24_8:r[s]!==void 0?r[s]:null}return{convert:n}}const S2=`
void main() {

	gl_Position = vec4( position, 1.0 );

}`,y2=`
uniform sampler2DArray depthColor;
uniform float depthWidth;
uniform float depthHeight;

void main() {

	vec2 coord = vec2( gl_FragCoord.x / depthWidth, gl_FragCoord.y / depthHeight );

	if ( coord.x >= 1.0 ) {

		gl_FragDepth = texture( depthColor, vec3( coord.x - 1.0, coord.y, 1 ) ).r;

	} else {

		gl_FragDepth = texture( depthColor, vec3( coord.x, coord.y, 0 ) ).r;

	}

}`;class M2{constructor(){this.texture=null,this.mesh=null,this.depthNear=0,this.depthFar=0}init(t,n){if(this.texture===null){const s=new ax(t.texture);(t.depthNear!==n.depthNear||t.depthFar!==n.depthFar)&&(this.depthNear=t.depthNear,this.depthFar=t.depthFar),this.texture=s}}getMesh(t){if(this.texture!==null&&this.mesh===null){const n=t.cameras[0].viewport,s=new Ti({vertexShader:S2,fragmentShader:y2,uniforms:{depthColor:{value:this.texture},depthWidth:{value:n.z},depthHeight:{value:n.w}}});this.mesh=new un(new fl(20,20),s)}return this.mesh}reset(){this.texture=null,this.mesh=null}getDepthTexture(){return this.texture}}class E2 extends Ws{constructor(t,n){super();const s=this;let l=null,c=1,f=null,d="local-floor",m=1,p=null,v=null,_=null,g=null,y=null,b=null;const w=typeof XRWebGLBinding<"u",M=new M2,S={},P=n.getContextAttributes();let D=null,A=null;const F=[],O=[],I=new qt;let T=null;const N=new bi;N.viewport=new $e;const X=new bi;X.viewport=new $e;const V=[N,X],q=new LE;let ct=null,ht=null;this.cameraAutoUpdate=!0,this.enabled=!1,this.isPresenting=!1,this.getController=function(tt){let _t=F[tt];return _t===void 0&&(_t=new Oh,F[tt]=_t),_t.getTargetRaySpace()},this.getControllerGrip=function(tt){let _t=F[tt];return _t===void 0&&(_t=new Oh,F[tt]=_t),_t.getGripSpace()},this.getHand=function(tt){let _t=F[tt];return _t===void 0&&(_t=new Oh,F[tt]=_t),_t.getHandSpace()};function j(tt){const _t=O.indexOf(tt.inputSource);if(_t===-1)return;const xt=F[_t];xt!==void 0&&(xt.update(tt.inputSource,tt.frame,p||f),xt.dispatchEvent({type:tt.type,data:tt.inputSource}))}function B(){l.removeEventListener("select",j),l.removeEventListener("selectstart",j),l.removeEventListener("selectend",j),l.removeEventListener("squeeze",j),l.removeEventListener("squeezestart",j),l.removeEventListener("squeezeend",j),l.removeEventListener("end",B),l.removeEventListener("inputsourceschange",H);for(let tt=0;tt<F.length;tt++){const _t=O[tt];_t!==null&&(O[tt]=null,F[tt].disconnect(_t))}ct=null,ht=null,M.reset();for(const tt in S)delete S[tt];t.setRenderTarget(D),y=null,g=null,_=null,l=null,A=null,At.stop(),s.isPresenting=!1,t.setPixelRatio(T),t.setSize(I.width,I.height,!1),s.dispatchEvent({type:"sessionend"})}this.setFramebufferScaleFactor=function(tt){c=tt,s.isPresenting===!0&&ie("WebXRManager: Cannot change framebuffer scale while presenting.")},this.setReferenceSpaceType=function(tt){d=tt,s.isPresenting===!0&&ie("WebXRManager: Cannot change reference space type while presenting.")},this.getReferenceSpace=function(){return p||f},this.setReferenceSpace=function(tt){p=tt},this.getBaseLayer=function(){return g!==null?g:y},this.getBinding=function(){return _===null&&w&&(_=new XRWebGLBinding(l,n)),_},this.getFrame=function(){return b},this.getSession=function(){return l},this.setSession=async function(tt){if(l=tt,l!==null){if(D=t.getRenderTarget(),l.addEventListener("select",j),l.addEventListener("selectstart",j),l.addEventListener("selectend",j),l.addEventListener("squeeze",j),l.addEventListener("squeezestart",j),l.addEventListener("squeezeend",j),l.addEventListener("end",B),l.addEventListener("inputsourceschange",H),P.xrCompatible!==!0&&await n.makeXRCompatible(),T=t.getPixelRatio(),t.getSize(I),w&&"createProjectionLayer"in XRWebGLBinding.prototype){let xt=null,It=null,jt=null;P.depth&&(jt=P.stencil?n.DEPTH24_STENCIL8:n.DEPTH_COMPONENT24,xt=P.stencil?Gs:Ra,It=P.stencil?al:ji);const Jt={colorFormat:n.RGBA8,depthFormat:jt,scaleFactor:c};_=this.getBinding(),g=_.createProjectionLayer(Jt),l.updateRenderState({layers:[g]}),t.setPixelRatio(1),t.setSize(g.textureWidth,g.textureHeight,!1),A=new Zi(g.textureWidth,g.textureHeight,{format:Pi,type:di,depthTexture:new Xr(g.textureWidth,g.textureHeight,It,void 0,void 0,void 0,void 0,void 0,void 0,xt),stencilBuffer:P.stencil,colorSpace:t.outputColorSpace,samples:P.antialias?4:0,resolveDepthBuffer:g.ignoreDepthValues===!1,resolveStencilBuffer:g.ignoreDepthValues===!1})}else{const xt={antialias:P.antialias,alpha:!0,depth:P.depth,stencil:P.stencil,framebufferScaleFactor:c};y=new XRWebGLLayer(l,n,xt),l.updateRenderState({baseLayer:y}),t.setPixelRatio(1),t.setSize(y.framebufferWidth,y.framebufferHeight,!1),A=new Zi(y.framebufferWidth,y.framebufferHeight,{format:Pi,type:di,colorSpace:t.outputColorSpace,stencilBuffer:P.stencil,resolveDepthBuffer:y.ignoreDepthValues===!1,resolveStencilBuffer:y.ignoreDepthValues===!1})}A.isXRRenderTarget=!0,this.setFoveation(m),p=null,f=await l.requestReferenceSpace(d),At.setContext(l),At.start(),s.isPresenting=!0,s.dispatchEvent({type:"sessionstart"})}},this.getEnvironmentBlendMode=function(){if(l!==null)return l.environmentBlendMode},this.getDepthTexture=function(){return M.getDepthTexture()};function H(tt){for(let _t=0;_t<tt.removed.length;_t++){const xt=tt.removed[_t],It=O.indexOf(xt);It>=0&&(O[It]=null,F[It].disconnect(xt))}for(let _t=0;_t<tt.added.length;_t++){const xt=tt.added[_t];let It=O.indexOf(xt);if(It===-1){for(let Jt=0;Jt<F.length;Jt++)if(Jt>=O.length){O.push(xt),It=Jt;break}else if(O[Jt]===null){O[Jt]=xt,It=Jt;break}if(It===-1)break}const jt=F[It];jt&&jt.connect(xt)}}const $=new K,dt=new K;function Mt(tt,_t,xt){$.setFromMatrixPosition(_t.matrixWorld),dt.setFromMatrixPosition(xt.matrixWorld);const It=$.distanceTo(dt),jt=_t.projectionMatrix.elements,Jt=xt.projectionMatrix.elements,qe=jt[14]/(jt[10]-1),he=jt[14]/(jt[10]+1),Se=(jt[9]+1)/jt[5],ye=(jt[9]-1)/jt[5],de=(jt[8]-1)/jt[0],nn=(Jt[8]+1)/Jt[0],an=qe*de,sn=qe*nn,fn=It/(-de+nn),We=fn*-de;if(_t.matrixWorld.decompose(tt.position,tt.quaternion,tt.scale),tt.translateX(We),tt.translateZ(fn),tt.matrixWorld.compose(tt.position,tt.quaternion,tt.scale),tt.matrixWorldInverse.copy(tt.matrixWorld).invert(),jt[10]===-1)tt.projectionMatrix.copy(_t.projectionMatrix),tt.projectionMatrixInverse.copy(_t.projectionMatrixInverse);else{const rn=qe+fn,Z=he+fn,Fe=an-We,Ce=sn+(It-We),L=Se*he/Z*rn,E=ye*he/Z*rn;tt.projectionMatrix.makePerspective(Fe,Ce,L,E,rn,Z),tt.projectionMatrixInverse.copy(tt.projectionMatrix).invert()}}function U(tt,_t){_t===null?tt.matrixWorld.copy(tt.matrix):tt.matrixWorld.multiplyMatrices(_t.matrixWorld,tt.matrix),tt.matrixWorldInverse.copy(tt.matrixWorld).invert()}this.updateCamera=function(tt){if(l===null)return;let _t=tt.near,xt=tt.far;M.texture!==null&&(M.depthNear>0&&(_t=M.depthNear),M.depthFar>0&&(xt=M.depthFar)),q.near=X.near=N.near=_t,q.far=X.far=N.far=xt,(ct!==q.near||ht!==q.far)&&(l.updateRenderState({depthNear:q.near,depthFar:q.far}),ct=q.near,ht=q.far),q.layers.mask=tt.layers.mask|6,N.layers.mask=q.layers.mask&-5,X.layers.mask=q.layers.mask&-3;const It=tt.parent,jt=q.cameras;U(q,It);for(let Jt=0;Jt<jt.length;Jt++)U(jt[Jt],It);jt.length===2?Mt(q,N,X):q.projectionMatrix.copy(N.projectionMatrix),J(tt,q,It)};function J(tt,_t,xt){xt===null?tt.matrix.copy(_t.matrixWorld):(tt.matrix.copy(xt.matrixWorld),tt.matrix.invert(),tt.matrix.multiply(_t.matrixWorld)),tt.matrix.decompose(tt.position,tt.quaternion,tt.scale),tt.updateMatrixWorld(!0),tt.projectionMatrix.copy(_t.projectionMatrix),tt.projectionMatrixInverse.copy(_t.projectionMatrixInverse),tt.isPerspectiveCamera&&(tt.fov=Jd*2*Math.atan(1/tt.projectionMatrix.elements[5]),tt.zoom=1)}this.getCamera=function(){return q},this.getFoveation=function(){if(!(g===null&&y===null))return m},this.setFoveation=function(tt){m=tt,g!==null&&(g.fixedFoveation=tt),y!==null&&y.fixedFoveation!==void 0&&(y.fixedFoveation=tt)},this.hasDepthSensing=function(){return M.texture!==null},this.getDepthSensingMesh=function(){return M.getMesh(q)},this.getCameraTexture=function(tt){return S[tt]};let bt=null;function pt(tt,_t){if(v=_t.getViewerPose(p||f),b=_t,v!==null){const xt=v.views;y!==null&&(t.setRenderTargetFramebuffer(A,y.framebuffer),t.setRenderTarget(A));let It=!1;xt.length!==q.cameras.length&&(q.cameras.length=0,It=!0);for(let he=0;he<xt.length;he++){const Se=xt[he];let ye=null;if(y!==null)ye=y.getViewport(Se);else{const nn=_.getViewSubImage(g,Se);ye=nn.viewport,he===0&&(t.setRenderTargetTextures(A,nn.colorTexture,nn.depthStencilTexture),t.setRenderTarget(A))}let de=V[he];de===void 0&&(de=new bi,de.layers.enable(he),de.viewport=new $e,V[he]=de),de.matrix.fromArray(Se.transform.matrix),de.matrix.decompose(de.position,de.quaternion,de.scale),de.projectionMatrix.fromArray(Se.projectionMatrix),de.projectionMatrixInverse.copy(de.projectionMatrix).invert(),de.viewport.set(ye.x,ye.y,ye.width,ye.height),he===0&&(q.matrix.copy(de.matrix),q.matrix.decompose(q.position,q.quaternion,q.scale)),It===!0&&q.cameras.push(de)}const jt=l.enabledFeatures;if(jt&&jt.includes("depth-sensing")&&l.depthUsage=="gpu-optimized"&&w){_=s.getBinding();const he=_.getDepthInformation(xt[0]);he&&he.isValid&&he.texture&&M.init(he,l.renderState)}if(jt&&jt.includes("camera-access")&&w){t.state.unbindTexture(),_=s.getBinding();for(let he=0;he<xt.length;he++){const Se=xt[he].camera;if(Se){let ye=S[Se];ye||(ye=new ax,S[Se]=ye);const de=_.getCameraImage(Se);ye.sourceTexture=de}}}}for(let xt=0;xt<F.length;xt++){const It=O[xt],jt=F[xt];It!==null&&jt!==void 0&&jt.update(It,_t,p||f)}bt&&bt(tt,_t),_t.detectedPlanes&&s.dispatchEvent({type:"planesdetected",data:_t}),b=null}const At=new vx;At.setAnimationLoop(pt),this.setAnimationLoop=function(tt){bt=tt},this.dispose=function(){}}}const b2=new en,bx=new re;bx.set(-1,0,0,0,1,0,0,0,1);function T2(r,t){function n(M,S){M.matrixAutoUpdate===!0&&M.updateMatrix(),S.value.copy(M.matrix)}function s(M,S){S.color.getRGB(M.fogColor.value,px(r)),S.isFog?(M.fogNear.value=S.near,M.fogFar.value=S.far):S.isFogExp2&&(M.fogDensity.value=S.density)}function l(M,S,P,D,A){S.isNodeMaterial?S.uniformsNeedUpdate=!1:S.isMeshBasicMaterial?c(M,S):S.isMeshLambertMaterial?(c(M,S),S.envMap&&(M.envMapIntensity.value=S.envMapIntensity)):S.isMeshToonMaterial?(c(M,S),_(M,S)):S.isMeshPhongMaterial?(c(M,S),v(M,S),S.envMap&&(M.envMapIntensity.value=S.envMapIntensity)):S.isMeshStandardMaterial?(c(M,S),g(M,S),S.isMeshPhysicalMaterial&&y(M,S,A)):S.isMeshMatcapMaterial?(c(M,S),b(M,S)):S.isMeshDepthMaterial?c(M,S):S.isMeshDistanceMaterial?(c(M,S),w(M,S)):S.isMeshNormalMaterial?c(M,S):S.isLineBasicMaterial?(f(M,S),S.isLineDashedMaterial&&d(M,S)):S.isPointsMaterial?m(M,S,P,D):S.isSpriteMaterial?p(M,S):S.isShadowMaterial?(M.color.value.copy(S.color),M.opacity.value=S.opacity):S.isShaderMaterial&&(S.uniformsNeedUpdate=!1)}function c(M,S){M.opacity.value=S.opacity,S.color&&M.diffuse.value.copy(S.color),S.emissive&&M.emissive.value.copy(S.emissive).multiplyScalar(S.emissiveIntensity),S.map&&(M.map.value=S.map,n(S.map,M.mapTransform)),S.alphaMap&&(M.alphaMap.value=S.alphaMap,n(S.alphaMap,M.alphaMapTransform)),S.bumpMap&&(M.bumpMap.value=S.bumpMap,n(S.bumpMap,M.bumpMapTransform),M.bumpScale.value=S.bumpScale,S.side===Vn&&(M.bumpScale.value*=-1)),S.normalMap&&(M.normalMap.value=S.normalMap,n(S.normalMap,M.normalMapTransform),M.normalScale.value.copy(S.normalScale),S.side===Vn&&M.normalScale.value.negate()),S.displacementMap&&(M.displacementMap.value=S.displacementMap,n(S.displacementMap,M.displacementMapTransform),M.displacementScale.value=S.displacementScale,M.displacementBias.value=S.displacementBias),S.emissiveMap&&(M.emissiveMap.value=S.emissiveMap,n(S.emissiveMap,M.emissiveMapTransform)),S.specularMap&&(M.specularMap.value=S.specularMap,n(S.specularMap,M.specularMapTransform)),S.alphaTest>0&&(M.alphaTest.value=S.alphaTest);const P=t.get(S),D=P.envMap,A=P.envMapRotation;D&&(M.envMap.value=D,M.envMapRotation.value.setFromMatrix4(b2.makeRotationFromEuler(A)).transpose(),D.isCubeTexture&&D.isRenderTargetTexture===!1&&M.envMapRotation.value.premultiply(bx),M.reflectivity.value=S.reflectivity,M.ior.value=S.ior,M.refractionRatio.value=S.refractionRatio),S.lightMap&&(M.lightMap.value=S.lightMap,M.lightMapIntensity.value=S.lightMapIntensity,n(S.lightMap,M.lightMapTransform)),S.aoMap&&(M.aoMap.value=S.aoMap,M.aoMapIntensity.value=S.aoMapIntensity,n(S.aoMap,M.aoMapTransform))}function f(M,S){M.diffuse.value.copy(S.color),M.opacity.value=S.opacity,S.map&&(M.map.value=S.map,n(S.map,M.mapTransform))}function d(M,S){M.dashSize.value=S.dashSize,M.totalSize.value=S.dashSize+S.gapSize,M.scale.value=S.scale}function m(M,S,P,D){M.diffuse.value.copy(S.color),M.opacity.value=S.opacity,M.size.value=S.size*P,M.scale.value=D*.5,S.map&&(M.map.value=S.map,n(S.map,M.uvTransform)),S.alphaMap&&(M.alphaMap.value=S.alphaMap,n(S.alphaMap,M.alphaMapTransform)),S.alphaTest>0&&(M.alphaTest.value=S.alphaTest)}function p(M,S){M.diffuse.value.copy(S.color),M.opacity.value=S.opacity,M.rotation.value=S.rotation,S.map&&(M.map.value=S.map,n(S.map,M.mapTransform)),S.alphaMap&&(M.alphaMap.value=S.alphaMap,n(S.alphaMap,M.alphaMapTransform)),S.alphaTest>0&&(M.alphaTest.value=S.alphaTest)}function v(M,S){M.specular.value.copy(S.specular),M.shininess.value=Math.max(S.shininess,1e-4)}function _(M,S){S.gradientMap&&(M.gradientMap.value=S.gradientMap)}function g(M,S){M.metalness.value=S.metalness,S.metalnessMap&&(M.metalnessMap.value=S.metalnessMap,n(S.metalnessMap,M.metalnessMapTransform)),M.roughness.value=S.roughness,S.roughnessMap&&(M.roughnessMap.value=S.roughnessMap,n(S.roughnessMap,M.roughnessMapTransform)),S.envMap&&(M.envMapIntensity.value=S.envMapIntensity)}function y(M,S,P){M.ior.value=S.ior,S.sheen>0&&(M.sheenColor.value.copy(S.sheenColor).multiplyScalar(S.sheen),M.sheenRoughness.value=S.sheenRoughness,S.sheenColorMap&&(M.sheenColorMap.value=S.sheenColorMap,n(S.sheenColorMap,M.sheenColorMapTransform)),S.sheenRoughnessMap&&(M.sheenRoughnessMap.value=S.sheenRoughnessMap,n(S.sheenRoughnessMap,M.sheenRoughnessMapTransform))),S.clearcoat>0&&(M.clearcoat.value=S.clearcoat,M.clearcoatRoughness.value=S.clearcoatRoughness,S.clearcoatMap&&(M.clearcoatMap.value=S.clearcoatMap,n(S.clearcoatMap,M.clearcoatMapTransform)),S.clearcoatRoughnessMap&&(M.clearcoatRoughnessMap.value=S.clearcoatRoughnessMap,n(S.clearcoatRoughnessMap,M.clearcoatRoughnessMapTransform)),S.clearcoatNormalMap&&(M.clearcoatNormalMap.value=S.clearcoatNormalMap,n(S.clearcoatNormalMap,M.clearcoatNormalMapTransform),M.clearcoatNormalScale.value.copy(S.clearcoatNormalScale),S.side===Vn&&M.clearcoatNormalScale.value.negate())),S.dispersion>0&&(M.dispersion.value=S.dispersion),S.iridescence>0&&(M.iridescence.value=S.iridescence,M.iridescenceIOR.value=S.iridescenceIOR,M.iridescenceThicknessMinimum.value=S.iridescenceThicknessRange[0],M.iridescenceThicknessMaximum.value=S.iridescenceThicknessRange[1],S.iridescenceMap&&(M.iridescenceMap.value=S.iridescenceMap,n(S.iridescenceMap,M.iridescenceMapTransform)),S.iridescenceThicknessMap&&(M.iridescenceThicknessMap.value=S.iridescenceThicknessMap,n(S.iridescenceThicknessMap,M.iridescenceThicknessMapTransform))),S.transmission>0&&(M.transmission.value=S.transmission,M.transmissionSamplerMap.value=P.texture,M.transmissionSamplerSize.value.set(P.width,P.height),S.transmissionMap&&(M.transmissionMap.value=S.transmissionMap,n(S.transmissionMap,M.transmissionMapTransform)),M.thickness.value=S.thickness,S.thicknessMap&&(M.thicknessMap.value=S.thicknessMap,n(S.thicknessMap,M.thicknessMapTransform)),M.attenuationDistance.value=S.attenuationDistance,M.attenuationColor.value.copy(S.attenuationColor)),S.anisotropy>0&&(M.anisotropyVector.value.set(S.anisotropy*Math.cos(S.anisotropyRotation),S.anisotropy*Math.sin(S.anisotropyRotation)),S.anisotropyMap&&(M.anisotropyMap.value=S.anisotropyMap,n(S.anisotropyMap,M.anisotropyMapTransform))),M.specularIntensity.value=S.specularIntensity,M.specularColor.value.copy(S.specularColor),S.specularColorMap&&(M.specularColorMap.value=S.specularColorMap,n(S.specularColorMap,M.specularColorMapTransform)),S.specularIntensityMap&&(M.specularIntensityMap.value=S.specularIntensityMap,n(S.specularIntensityMap,M.specularIntensityMapTransform))}function b(M,S){S.matcap&&(M.matcap.value=S.matcap)}function w(M,S){const P=t.get(S).light;M.referencePosition.value.setFromMatrixPosition(P.matrixWorld),M.nearDistance.value=P.shadow.camera.near,M.farDistance.value=P.shadow.camera.far}return{refreshFogUniforms:s,refreshMaterialUniforms:l}}function A2(r,t,n,s){let l={},c={},f=[];const d=r.getParameter(r.MAX_UNIFORM_BUFFER_BINDINGS);function m(A,F){const O=F.program;s.uniformBlockBinding(A,O)}function p(A,F){let O=l[A.id];O===void 0&&(M(A),O=v(A),l[A.id]=O,A.addEventListener("dispose",P));const I=F.program;s.updateUBOMapping(A,I);const T=t.render.frame;c[A.id]!==T&&(g(A),c[A.id]=T)}function v(A){const F=_();A.__bindingPointIndex=F;const O=r.createBuffer(),I=A.__size,T=A.usage;return r.bindBuffer(r.UNIFORM_BUFFER,O),r.bufferData(r.UNIFORM_BUFFER,I,T),r.bindBuffer(r.UNIFORM_BUFFER,null),r.bindBufferBase(r.UNIFORM_BUFFER,F,O),O}function _(){for(let A=0;A<d;A++)if(f.indexOf(A)===-1)return f.push(A),A;return be("WebGLRenderer: Maximum number of simultaneously usable uniforms groups reached."),0}function g(A){const F=l[A.id],O=A.uniforms,I=A.__cache;r.bindBuffer(r.UNIFORM_BUFFER,F);for(let T=0,N=O.length;T<N;T++){const X=O[T];if(Array.isArray(X))for(let V=0,q=X.length;V<q;V++)y(X[V],T,V,I);else y(X,T,0,I)}r.bindBuffer(r.UNIFORM_BUFFER,null)}function y(A,F,O,I){if(w(A,F,O,I)===!0){const T=A.__offset,N=A.value;if(Array.isArray(N)){let X=0;for(let V=0;V<N.length;V++){const q=N[V],ct=S(q);b(q,A.__data,X),typeof q!="number"&&typeof q!="boolean"&&!q.isMatrix3&&!ArrayBuffer.isView(q)&&(X+=ct.storage/Float32Array.BYTES_PER_ELEMENT)}}else b(N,A.__data,0);r.bufferSubData(r.UNIFORM_BUFFER,T,A.__data)}}function b(A,F,O){typeof A=="number"||typeof A=="boolean"?F[0]=A:A.isMatrix3?(F[0]=A.elements[0],F[1]=A.elements[1],F[2]=A.elements[2],F[3]=0,F[4]=A.elements[3],F[5]=A.elements[4],F[6]=A.elements[5],F[7]=0,F[8]=A.elements[6],F[9]=A.elements[7],F[10]=A.elements[8],F[11]=0):ArrayBuffer.isView(A)?F.set(new A.constructor(A.buffer,A.byteOffset,F.length)):A.toArray(F,O)}function w(A,F,O,I){const T=A.value,N=F+"_"+O;if(I[N]===void 0)return typeof T=="number"||typeof T=="boolean"?I[N]=T:ArrayBuffer.isView(T)?I[N]=T.slice():I[N]=T.clone(),!0;{const X=I[N];if(typeof T=="number"||typeof T=="boolean"){if(X!==T)return I[N]=T,!0}else{if(ArrayBuffer.isView(T))return!0;if(X.equals(T)===!1)return X.copy(T),!0}}return!1}function M(A){const F=A.uniforms;let O=0;const I=16;for(let N=0,X=F.length;N<X;N++){const V=Array.isArray(F[N])?F[N]:[F[N]];for(let q=0,ct=V.length;q<ct;q++){const ht=V[q],j=Array.isArray(ht.value)?ht.value:[ht.value];for(let B=0,H=j.length;B<H;B++){const $=j[B],dt=S($),Mt=O%I,U=Mt%dt.boundary,J=Mt+U;O+=U,J!==0&&I-J<dt.storage&&(O+=I-J),ht.__data=new Float32Array(dt.storage/Float32Array.BYTES_PER_ELEMENT),ht.__offset=O,O+=dt.storage}}}const T=O%I;return T>0&&(O+=I-T),A.__size=O,A.__cache={},this}function S(A){const F={boundary:0,storage:0};return typeof A=="number"||typeof A=="boolean"?(F.boundary=4,F.storage=4):A.isVector2?(F.boundary=8,F.storage=8):A.isVector3||A.isColor?(F.boundary=16,F.storage=12):A.isVector4?(F.boundary=16,F.storage=16):A.isMatrix3?(F.boundary=48,F.storage=48):A.isMatrix4?(F.boundary=64,F.storage=64):A.isTexture?ie("WebGLRenderer: Texture samplers can not be part of an uniforms group."):ArrayBuffer.isView(A)?(F.boundary=16,F.storage=A.byteLength):ie("WebGLRenderer: Unsupported uniform value type.",A),F}function P(A){const F=A.target;F.removeEventListener("dispose",P);const O=f.indexOf(F.__bindingPointIndex);f.splice(O,1),r.deleteBuffer(l[F.id]),delete l[F.id],delete c[F.id]}function D(){for(const A in l)r.deleteBuffer(l[A]);f=[],l={},c={}}return{bind:m,update:p,dispose:D}}const R2=new Uint16Array([12469,15057,12620,14925,13266,14620,13807,14376,14323,13990,14545,13625,14713,13328,14840,12882,14931,12528,14996,12233,15039,11829,15066,11525,15080,11295,15085,10976,15082,10705,15073,10495,13880,14564,13898,14542,13977,14430,14158,14124,14393,13732,14556,13410,14702,12996,14814,12596,14891,12291,14937,11834,14957,11489,14958,11194,14943,10803,14921,10506,14893,10278,14858,9960,14484,14039,14487,14025,14499,13941,14524,13740,14574,13468,14654,13106,14743,12678,14818,12344,14867,11893,14889,11509,14893,11180,14881,10751,14852,10428,14812,10128,14765,9754,14712,9466,14764,13480,14764,13475,14766,13440,14766,13347,14769,13070,14786,12713,14816,12387,14844,11957,14860,11549,14868,11215,14855,10751,14825,10403,14782,10044,14729,9651,14666,9352,14599,9029,14967,12835,14966,12831,14963,12804,14954,12723,14936,12564,14917,12347,14900,11958,14886,11569,14878,11247,14859,10765,14828,10401,14784,10011,14727,9600,14660,9289,14586,8893,14508,8533,15111,12234,15110,12234,15104,12216,15092,12156,15067,12010,15028,11776,14981,11500,14942,11205,14902,10752,14861,10393,14812,9991,14752,9570,14682,9252,14603,8808,14519,8445,14431,8145,15209,11449,15208,11451,15202,11451,15190,11438,15163,11384,15117,11274,15055,10979,14994,10648,14932,10343,14871,9936,14803,9532,14729,9218,14645,8742,14556,8381,14461,8020,14365,7603,15273,10603,15272,10607,15267,10619,15256,10631,15231,10614,15182,10535,15118,10389,15042,10167,14963,9787,14883,9447,14800,9115,14710,8665,14615,8318,14514,7911,14411,7507,14279,7198,15314,9675,15313,9683,15309,9712,15298,9759,15277,9797,15229,9773,15166,9668,15084,9487,14995,9274,14898,8910,14800,8539,14697,8234,14590,7790,14479,7409,14367,7067,14178,6621,15337,8619,15337,8631,15333,8677,15325,8769,15305,8871,15264,8940,15202,8909,15119,8775,15022,8565,14916,8328,14804,8009,14688,7614,14569,7287,14448,6888,14321,6483,14088,6171,15350,7402,15350,7419,15347,7480,15340,7613,15322,7804,15287,7973,15229,8057,15148,8012,15046,7846,14933,7611,14810,7357,14682,7069,14552,6656,14421,6316,14251,5948,14007,5528,15356,5942,15356,5977,15353,6119,15348,6294,15332,6551,15302,6824,15249,7044,15171,7122,15070,7050,14949,6861,14818,6611,14679,6349,14538,6067,14398,5651,14189,5311,13935,4958,15359,4123,15359,4153,15356,4296,15353,4646,15338,5160,15311,5508,15263,5829,15188,6042,15088,6094,14966,6001,14826,5796,14678,5543,14527,5287,14377,4985,14133,4586,13869,4257,15360,1563,15360,1642,15358,2076,15354,2636,15341,3350,15317,4019,15273,4429,15203,4732,15105,4911,14981,4932,14836,4818,14679,4621,14517,4386,14359,4156,14083,3795,13808,3437,15360,122,15360,137,15358,285,15355,636,15344,1274,15322,2177,15281,2765,15215,3223,15120,3451,14995,3569,14846,3567,14681,3466,14511,3305,14344,3121,14037,2800,13753,2467,15360,0,15360,1,15359,21,15355,89,15346,253,15325,479,15287,796,15225,1148,15133,1492,15008,1749,14856,1882,14685,1886,14506,1783,14324,1608,13996,1398,13702,1183]);let ki=null;function C2(){return ki===null&&(ki=new HM(R2,16,16,ks,Aa),ki.name="DFG_LUT",ki.minFilter=Bn,ki.magFilter=Bn,ki.wrapS=Ea,ki.wrapT=Ea,ki.generateMipmaps=!1,ki.needsUpdate=!0),ki}class w2{constructor(t={}){const{canvas:n=vM(),context:s=null,depth:l=!0,stencil:c=!1,alpha:f=!1,antialias:d=!1,premultipliedAlpha:m=!0,preserveDrawingBuffer:p=!1,powerPreference:v="default",failIfMajorPerformanceCaveat:_=!1,reversedDepthBuffer:g=!1,outputBufferType:y=di}=t;this.isWebGLRenderer=!0;let b;if(s!==null){if(typeof WebGLRenderingContext<"u"&&s instanceof WebGLRenderingContext)throw new Error("THREE.WebGLRenderer: WebGL 1 is not supported since r163.");b=s.getContextAttributes().alpha}else b=f;const w=y,M=new Set([up,cp,lp]),S=new Set([di,ji,il,al,rp,op]),P=new Uint32Array(4),D=new Int32Array(4),A=new K;let F=null,O=null;const I=[],T=[];let N=null;this.domElement=n,this.debug={checkShaderErrors:!0,onShaderError:null},this.autoClear=!0,this.autoClearColor=!0,this.autoClearDepth=!0,this.autoClearStencil=!0,this.sortObjects=!0,this.clippingPlanes=[],this.localClippingEnabled=!1,this.toneMapping=Yi,this.toneMappingExposure=1,this.transmissionResolutionScale=1;const X=this;let V=!1,q=null,ct=null,ht=null,j=null;this._outputColorSpace=hi;let B=0,H=0,$=null,dt=-1,Mt=null;const U=new $e,J=new $e;let bt=null;const pt=new fe(0);let At=0,tt=n.width,_t=n.height,xt=1,It=null,jt=null;const Jt=new $e(0,0,tt,_t),qe=new $e(0,0,tt,_t);let he=!1;const Se=new gp;let ye=!1,de=!1;const nn=new en,an=new K,sn=new $e,fn={background:null,fog:null,environment:null,overrideMaterial:null,isScene:!0};let We=!1;function rn(){return $===null?xt:1}let Z=s;function Fe(R,Y){return n.getContext(R,Y)}try{const R={alpha:!0,depth:l,stencil:c,antialias:d,premultipliedAlpha:m,preserveDrawingBuffer:p,powerPreference:v,failIfMajorPerformanceCaveat:_};if("setAttribute"in n&&n.setAttribute("data-engine",`three.js r${ap}`),n.addEventListener("webglcontextlost",Ke,!1),n.addEventListener("webglcontextrestored",Ne,!1),n.addEventListener("webglcontextcreationerror",$n,!1),Z===null){const Y="webgl2";if(Z=Fe(Y,R),Z===null)throw Fe(Y)?new Error("THREE.WebGLRenderer: Error creating WebGL context with your selected attributes."):new Error("THREE.WebGLRenderer: Error creating WebGL context.")}}catch(R){throw be("WebGLRenderer: "+R.message),R}let Ce,L,E,et,rt,mt,Rt,Nt,ft,gt,wt,Bt,Ot,Ut,Qt,$t,ae,W,Ct,St,Dt,Ft,Tt;function Yt(){Ce=new CT(Z),Ce.init(),Dt=new x2(Z,Ce),L=new ST(Z,Ce,t,Dt),E=new v2(Z,Ce),L.reversedDepthBuffer&&g&&E.buffers.depth.setReversed(!0),ct=Z.createFramebuffer(),ht=Z.createFramebuffer(),j=Z.createFramebuffer(),et=new NT(Z),rt=new i2,mt=new _2(Z,Ce,E,rt,L,Dt,et),Rt=new RT(X),Nt=new PE(Z),Ft=new _T(Z,Nt),ft=new wT(Z,Nt,et,Ft),gt=new LT(Z,ft,Nt,Ft,et),W=new UT(Z,L,mt),Qt=new yT(rt),wt=new n2(X,Rt,Ce,L,Ft,Qt),Bt=new T2(X,rt),Ot=new s2,Ut=new f2(Ce),ae=new vT(X,Rt,E,gt,b,m),$t=new g2(X,gt,L),Tt=new A2(Z,et,L,E),Ct=new xT(Z,Ce,et),St=new DT(Z,Ce,et),et.programs=wt.programs,X.capabilities=L,X.extensions=Ce,X.properties=rt,X.renderLists=Ot,X.shadowMap=$t,X.state=E,X.info=et}Yt(),w!==di&&(N=new PT(w,n.width,n.height,d,l,c));const Vt=new E2(X,Z);this.xr=Vt,this.getContext=function(){return Z},this.getContextAttributes=function(){return Z.getContextAttributes()},this.forceContextLoss=function(){const R=Ce.get("WEBGL_lose_context");R&&R.loseContext()},this.forceContextRestore=function(){const R=Ce.get("WEBGL_lose_context");R&&R.restoreContext()},this.getPixelRatio=function(){return xt},this.setPixelRatio=function(R){R!==void 0&&(xt=R,this.setSize(tt,_t,!1))},this.getSize=function(R){return R.set(tt,_t)},this.setSize=function(R,Y,ot=!0){if(Vt.isPresenting){ie("WebGLRenderer: Can't change size while VR device is presenting.");return}tt=R,_t=Y,n.width=Math.floor(R*xt),n.height=Math.floor(Y*xt),ot===!0&&(n.style.width=R+"px",n.style.height=Y+"px"),N!==null&&N.setSize(n.width,n.height),this.setViewport(0,0,R,Y)},this.getDrawingBufferSize=function(R){return R.set(tt*xt,_t*xt).floor()},this.setDrawingBufferSize=function(R,Y,ot){tt=R,_t=Y,xt=ot,n.width=Math.floor(R*ot),n.height=Math.floor(Y*ot),this.setViewport(0,0,R,Y)},this.setEffects=function(R){if(w===di){be("WebGLRenderer: setEffects() requires outputBufferType set to HalfFloatType or FloatType.");return}if(R){for(let Y=0;Y<R.length;Y++)if(R[Y].isOutputPass===!0){ie("WebGLRenderer: OutputPass is not needed in setEffects(). Tone mapping and color space conversion are applied automatically.");break}}N.setEffects(R||[])},this.getCurrentViewport=function(R){return R.copy(U)},this.getViewport=function(R){return R.copy(Jt)},this.setViewport=function(R,Y,ot,at){R.isVector4?Jt.set(R.x,R.y,R.z,R.w):Jt.set(R,Y,ot,at),E.viewport(U.copy(Jt).multiplyScalar(xt).round())},this.getScissor=function(R){return R.copy(qe)},this.setScissor=function(R,Y,ot,at){R.isVector4?qe.set(R.x,R.y,R.z,R.w):qe.set(R,Y,ot,at),E.scissor(J.copy(qe).multiplyScalar(xt).round())},this.getScissorTest=function(){return he},this.setScissorTest=function(R){E.setScissorTest(he=R)},this.setOpaqueSort=function(R){It=R},this.setTransparentSort=function(R){jt=R},this.getClearColor=function(R){return R.copy(ae.getClearColor())},this.setClearColor=function(){ae.setClearColor(...arguments)},this.getClearAlpha=function(){return ae.getClearAlpha()},this.setClearAlpha=function(){ae.setClearAlpha(...arguments)},this.clear=function(R=!0,Y=!0,ot=!0){let at=0;if(R){let st=!1;if($!==null){const Pt=$.texture.format;st=M.has(Pt)}if(st){const Pt=$.texture.type,Gt=S.has(Pt),Lt=ae.getClearColor(),Xt=ae.getClearAlpha(),kt=Lt.r,te=Lt.g,oe=Lt.b;Gt?(P[0]=kt,P[1]=te,P[2]=oe,P[3]=Xt,Z.clearBufferuiv(Z.COLOR,0,P)):(D[0]=kt,D[1]=te,D[2]=oe,D[3]=Xt,Z.clearBufferiv(Z.COLOR,0,D))}else at|=Z.COLOR_BUFFER_BIT}Y&&(at|=Z.DEPTH_BUFFER_BIT,this.state.buffers.depth.setMask(!0)),ot&&(at|=Z.STENCIL_BUFFER_BIT,this.state.buffers.stencil.setMask(4294967295)),at!==0&&Z.clear(at)},this.clearColor=function(){this.clear(!0,!1,!1)},this.clearDepth=function(){this.clear(!1,!0,!1)},this.clearStencil=function(){this.clear(!1,!1,!0)},this.setNodesHandler=function(R){R.setRenderer(this),q=R},this.dispose=function(){n.removeEventListener("webglcontextlost",Ke,!1),n.removeEventListener("webglcontextrestored",Ne,!1),n.removeEventListener("webglcontextcreationerror",$n,!1),ae.dispose(),Ot.dispose(),Ut.dispose(),rt.dispose(),Rt.dispose(),gt.dispose(),Ft.dispose(),Tt.dispose(),wt.dispose(),Vt.dispose(),Vt.removeEventListener("sessionstart",pn),Vt.removeEventListener("sessionend",Cn),Wn.stop()};function Ke(R){R.preventDefault(),bv("WebGLRenderer: Context Lost."),V=!0}function Ne(){bv("WebGLRenderer: Context Restored."),V=!1;const R=et.autoReset,Y=$t.enabled,ot=$t.autoUpdate,at=$t.needsUpdate,st=$t.type;Yt(),et.autoReset=R,$t.enabled=Y,$t.autoUpdate=ot,$t.needsUpdate=at,$t.type=st}function $n(R){be("WebGLRenderer: A WebGL context could not be created. Reason: ",R.statusMessage)}function ti(R){const Y=R.target;Y.removeEventListener("dispose",ti),jr(Y)}function jr(R){Jr(R),rt.remove(R)}function Jr(R){const Y=rt.get(R).programs;Y!==void 0&&(Y.forEach(function(ot){wt.releaseProgram(ot)}),R.isShaderMaterial&&wt.releaseShaderCache(R))}this.renderBufferDirect=function(R,Y,ot,at,st,Pt){Y===null&&(Y=fn);const Gt=st.isMesh&&st.matrixWorld.determinantAffine()<0,Lt=Da(R,Y,ot,at,st);E.setMaterial(at,Gt);let Xt=ot.index,kt=1;if(at.wireframe===!0){if(Xt=ft.getWireframeAttribute(ot),Xt===void 0)return;kt=2}const te=ot.drawRange,oe=ot.attributes.position;let Kt=te.start*kt,Te=(te.start+te.count)*kt;Pt!==null&&(Kt=Math.max(Kt,Pt.start*kt),Te=Math.min(Te,(Pt.start+Pt.count)*kt)),Xt!==null?(Kt=Math.max(Kt,0),Te=Math.min(Te,Xt.count)):oe!=null&&(Kt=Math.max(Kt,0),Te=Math.min(Te,oe.count));const je=Te-Kt;if(je<0||je===1/0)return;Ft.setup(st,at,Lt,ot,Xt);let Ve,Ue=Ct;if(Xt!==null&&(Ve=Nt.get(Xt),Ue=St,Ue.setIndex(Ve)),st.isMesh)at.wireframe===!0?(E.setLineWidth(at.wireframeLinewidth*rn()),Ue.setMode(Z.LINES)):Ue.setMode(Z.TRIANGLES);else if(st.isLine){let Le=at.linewidth;Le===void 0&&(Le=1),E.setLineWidth(Le*rn()),st.isLineSegments?Ue.setMode(Z.LINES):st.isLineLoop?Ue.setMode(Z.LINE_LOOP):Ue.setMode(Z.LINE_STRIP)}else st.isPoints?Ue.setMode(Z.POINTS):st.isSprite&&Ue.setMode(Z.TRIANGLES);if(st.isBatchedMesh)if(Ce.get("WEBGL_multi_draw"))Ue.renderMultiDraw(st._multiDrawStarts,st._multiDrawCounts,st._multiDrawCount);else{const Le=st._multiDrawStarts,Ht=st._multiDrawCounts,Pn=st._multiDrawCount,pe=Xt?Nt.get(Xt).bytesPerElement:1,yn=rt.get(at).currentProgram.getUniforms();for(let ei=0;ei<Pn;ei++)yn.setValue(Z,"_gl_DrawID",ei),Ue.render(Le[ei]/pe,Ht[ei])}else if(st.isInstancedMesh)Ue.renderInstances(Kt,je,st.count);else if(ot.isInstancedBufferGeometry){const Le=ot._maxInstanceCount!==void 0?ot._maxInstanceCount:1/0,Ht=Math.min(ot.instanceCount,Le);Ue.renderInstances(Kt,je,Ht)}else Ue.render(Kt,je)};function Qr(R,Y,ot){R.transparent===!0&&R.side===Ma&&R.forceSinglePass===!1?(R.side=Vn,R.needsUpdate=!0,wa(R,Y,ot),R.side=us,R.needsUpdate=!0,wa(R,Y,ot),R.side=Ma):wa(R,Y,ot)}this.compile=function(R,Y,ot=null){ot===null&&(ot=R),O=Ut.get(ot),O.init(Y),T.push(O),ot.traverseVisible(function(st){st.isLight&&st.layers.test(Y.layers)&&(O.pushLight(st),st.castShadow&&O.pushShadow(st))}),R!==ot&&R.traverseVisible(function(st){st.isLight&&st.layers.test(Y.layers)&&(O.pushLight(st),st.castShadow&&O.pushShadow(st))}),O.setupLights();const at=new Set;return R.traverse(function(st){if(!(st.isMesh||st.isPoints||st.isLine||st.isSprite))return;const Pt=st.material;if(Pt)if(Array.isArray(Pt))for(let Gt=0;Gt<Pt.length;Gt++){const Lt=Pt[Gt];Qr(Lt,ot,st),at.add(Lt)}else Qr(Pt,ot,st),at.add(Pt)}),O=T.pop(),at},this.compileAsync=function(R,Y,ot=null){const at=this.compile(R,Y,ot);return new Promise(st=>{function Pt(){if(at.forEach(function(Gt){rt.get(Gt).currentProgram.isReady()&&at.delete(Gt)}),at.size===0){st(R);return}setTimeout(Pt,10)}Ce.get("KHR_parallel_shader_compile")!==null?Pt():setTimeout(Pt,10)})};let qs=null;function Ii(R){qs&&qs(R)}function pn(){Wn.stop()}function Cn(){Wn.start()}const Wn=new vx;Wn.setAnimationLoop(Ii),typeof self<"u"&&Wn.setContext(self),this.setAnimationLoop=function(R){qs=R,Vt.setAnimationLoop(R),R===null?Wn.stop():Wn.start()},Vt.addEventListener("sessionstart",pn),Vt.addEventListener("sessionend",Cn),this.render=function(R,Y){if(Y!==void 0&&Y.isCamera!==!0){be("WebGLRenderer.render: camera is not an instance of THREE.Camera.");return}if(V===!0)return;q!==null&&q.renderStart(R,Y);const ot=Vt.enabled===!0&&Vt.isPresenting===!0,at=N!==null&&($===null||ot)&&N.begin(X,$);if(R.matrixWorldAutoUpdate===!0&&R.updateMatrixWorld(),Y.parent===null&&Y.matrixWorldAutoUpdate===!0&&Y.updateMatrixWorld(),Vt.enabled===!0&&Vt.isPresenting===!0&&(N===null||N.isCompositing()===!1)&&(Vt.cameraAutoUpdate===!0&&Vt.updateCamera(Y),Y=Vt.getCamera()),R.isScene===!0&&R.onBeforeRender(X,R,Y,$),O=Ut.get(R,T.length),O.init(Y),O.state.textureUnits=mt.getTextureUnits(),T.push(O),nn.multiplyMatrices(Y.projectionMatrix,Y.matrixWorldInverse),Se.setFromProjectionMatrix(nn,qi,Y.reversedDepth),de=this.localClippingEnabled,ye=Qt.init(this.clippingPlanes,de),F=Ot.get(R,I.length),F.init(),I.push(F),Vt.enabled===!0&&Vt.isPresenting===!0){const Gt=X.xr.getDepthSensingMesh();Gt!==null&&hs(Gt,Y,-1/0,X.sortObjects)}hs(R,Y,0,X.sortObjects),F.finish(),X.sortObjects===!0&&F.sort(It,jt,Y.reversedDepth),We=Vt.enabled===!1||Vt.isPresenting===!1||Vt.hasDepthSensing()===!1,We&&ae.addToRenderList(F,R),this.info.render.frame++,this.info.autoReset===!0&&this.info.reset(),ye===!0&&Qt.beginShadows();const st=O.state.shadowsArray;if($t.render(st,R,Y),ye===!0&&Qt.endShadows(),(at&&N.hasRenderPass())===!1){const Gt=F.opaque,Lt=F.transmissive;if(O.setupLights(),Y.isArrayCamera){const Xt=Y.cameras;if(Lt.length>0)for(let kt=0,te=Xt.length;kt<te;kt++){const oe=Xt[kt];dl(Gt,Lt,R,oe)}We&&ae.render(R);for(let kt=0,te=Xt.length;kt<te;kt++){const oe=Xt[kt];hl(F,R,oe,oe.viewport)}}else Lt.length>0&&dl(Gt,Lt,R,Y),We&&ae.render(R),hl(F,R,Y)}$!==null&&H===0&&(mt.updateMultisampleRenderTarget($),mt.updateRenderTargetMipmap($)),at&&N.end(X),R.isScene===!0&&R.onAfterRender(X,R,Y),Ft.resetDefaultState(),dt=-1,Mt=null,T.pop(),T.length>0?(O=T[T.length-1],mt.setTextureUnits(O.state.textureUnits),ye===!0&&Qt.setGlobalState(X.clippingPlanes,O.state.camera)):O=null,I.pop(),I.length>0?F=I[I.length-1]:F=null,q!==null&&q.renderEnd()};function hs(R,Y,ot,at){if(R.visible===!1)return;if(R.layers.test(Y.layers)){if(R.isGroup)ot=R.renderOrder;else if(R.isLOD)R.autoUpdate===!0&&R.update(Y);else if(R.isLightProbeGrid)O.pushLightProbeGrid(R);else if(R.isLight)O.pushLight(R),R.castShadow&&O.pushShadow(R);else if(R.isSprite){if(!R.frustumCulled||Se.intersectsSprite(R)){at&&sn.setFromMatrixPosition(R.matrixWorld).applyMatrix4(nn);const Gt=gt.update(R),Lt=R.material;Lt.visible&&F.push(R,Gt,Lt,ot,sn.z,null)}}else if((R.isMesh||R.isLine||R.isPoints)&&(!R.frustumCulled||Se.intersectsObject(R))){const Gt=gt.update(R),Lt=R.material;if(at&&(R.boundingSphere!==void 0?(R.boundingSphere===null&&R.computeBoundingSphere(),sn.copy(R.boundingSphere.center)):(Gt.boundingSphere===null&&Gt.computeBoundingSphere(),sn.copy(Gt.boundingSphere.center)),sn.applyMatrix4(R.matrixWorld).applyMatrix4(nn)),Array.isArray(Lt)){const Xt=Gt.groups;for(let kt=0,te=Xt.length;kt<te;kt++){const oe=Xt[kt],Kt=Lt[oe.materialIndex];Kt&&Kt.visible&&F.push(R,Gt,Kt,ot,sn.z,oe)}}else Lt.visible&&F.push(R,Gt,Lt,ot,sn.z,null)}}const Pt=R.children;for(let Gt=0,Lt=Pt.length;Gt<Lt;Gt++)hs(Pt[Gt],Y,ot,at)}function hl(R,Y,ot,at){const{opaque:st,transmissive:Pt,transparent:Gt}=R;O.setupLightsView(ot),ye===!0&&Qt.setGlobalState(X.clippingPlanes,ot),at&&E.viewport(U.copy(at)),st.length>0&&ds(st,Y,ot),Pt.length>0&&ds(Pt,Y,ot),Gt.length>0&&ds(Gt,Y,ot),E.buffers.depth.setTest(!0),E.buffers.depth.setMask(!0),E.buffers.color.setMask(!0),E.setPolygonOffset(!1)}function dl(R,Y,ot,at){if((ot.isScene===!0?ot.overrideMaterial:null)!==null)return;if(O.state.transmissionRenderTarget[at.id]===void 0){const Kt=Ce.has("EXT_color_buffer_half_float")||Ce.has("EXT_color_buffer_float");O.state.transmissionRenderTarget[at.id]=new Zi(1,1,{generateMipmaps:!0,type:Kt?Aa:di,minFilter:Hs,samples:Math.max(4,L.samples),stencilBuffer:c,resolveDepthBuffer:!1,resolveStencilBuffer:!1,colorSpace:Ee.workingColorSpace})}const Pt=O.state.transmissionRenderTarget[at.id],Gt=at.viewport||U;Pt.setSize(Gt.z*X.transmissionResolutionScale,Gt.w*X.transmissionResolutionScale);const Lt=X.getRenderTarget(),Xt=X.getActiveCubeFace(),kt=X.getActiveMipmapLevel();X.setRenderTarget(Pt),X.getClearColor(pt),At=X.getClearAlpha(),At<1&&X.setClearColor(16777215,.5),X.clear(),We&&ae.render(ot);const te=X.toneMapping;X.toneMapping=Yi;const oe=at.viewport;if(at.viewport!==void 0&&(at.viewport=void 0),O.setupLightsView(at),ye===!0&&Qt.setGlobalState(X.clippingPlanes,at),ds(R,ot,at),mt.updateMultisampleRenderTarget(Pt),mt.updateRenderTargetMipmap(Pt),Ce.has("WEBGL_multisampled_render_to_texture")===!1){let Kt=!1;for(let Te=0,je=Y.length;Te<je;Te++){const Ve=Y[Te],{object:Ue,geometry:Le,material:Ht,group:Pn}=Ve;if(Ht.side===Ma&&Ue.layers.test(at.layers)){const pe=Ht.side;Ht.side=Vn,Ht.needsUpdate=!0,Ca(Ue,ot,at,Le,Ht,Pn),Ht.side=pe,Ht.needsUpdate=!0,Kt=!0}}Kt===!0&&(mt.updateMultisampleRenderTarget(Pt),mt.updateRenderTargetMipmap(Pt))}X.setRenderTarget(Lt,Xt,kt),X.setClearColor(pt,At),oe!==void 0&&(at.viewport=oe),X.toneMapping=te}function ds(R,Y,ot){const at=Y.isScene===!0?Y.overrideMaterial:null;for(let st=0,Pt=R.length;st<Pt;st++){const Gt=R[st],{object:Lt,geometry:Xt,group:kt}=Gt;let te=Gt.material;te.allowOverride===!0&&at!==null&&(te=at),Lt.layers.test(ot.layers)&&Ca(Lt,Y,ot,Xt,te,kt)}}function Ca(R,Y,ot,at,st,Pt){R.onBeforeRender(X,Y,ot,at,st,Pt),R.modelViewMatrix.multiplyMatrices(ot.matrixWorldInverse,R.matrixWorld),R.normalMatrix.getNormalMatrix(R.modelViewMatrix),st.onBeforeRender(X,Y,ot,at,R,Pt),st.transparent===!0&&st.side===Ma&&st.forceSinglePass===!1?(st.side=Vn,st.needsUpdate=!0,X.renderBufferDirect(ot,Y,at,st,R,Pt),st.side=us,st.needsUpdate=!0,X.renderBufferDirect(ot,Y,at,st,R,Pt),st.side=Ma):X.renderBufferDirect(ot,Y,at,st,R,Pt),R.onAfterRender(X,Y,ot,at,st,Pt)}function wa(R,Y,ot){Y.isScene!==!0&&(Y=fn);const at=rt.get(R),st=O.state.lights,Pt=O.state.shadowsArray,Gt=st.state.version,Lt=wt.getParameters(R,st.state,Pt,Y,ot,O.state.lightProbeGridArray),Xt=wt.getProgramCacheKey(Lt);let kt=at.programs;at.environment=R.isMeshStandardMaterial||R.isMeshLambertMaterial||R.isMeshPhongMaterial?Y.environment:null,at.fog=Y.fog;const te=R.isMeshStandardMaterial||R.isMeshLambertMaterial&&!R.envMap||R.isMeshPhongMaterial&&!R.envMap;at.envMap=Rt.get(R.envMap||at.environment,te),at.envMapRotation=at.environment!==null&&R.envMap===null?Y.environmentRotation:R.envMapRotation,kt===void 0&&(R.addEventListener("dispose",ti),kt=new Map,at.programs=kt);let oe=kt.get(Xt);if(oe!==void 0){if(at.currentProgram===oe&&at.lightsStateVersion===Gt)return $i(R,Lt),oe}else Lt.uniforms=wt.getUniforms(R),q!==null&&R.isNodeMaterial&&q.build(R,ot,Lt),R.onBeforeCompile(Lt,X),oe=wt.acquireProgram(Lt,Xt),kt.set(Xt,oe),at.uniforms=Lt.uniforms;const Kt=at.uniforms;return(!R.isShaderMaterial&&!R.isRawShaderMaterial||R.clipping===!0)&&(Kt.clippingPlanes=Qt.uniform),$i(R,Lt),at.needsLights=pl(R),at.lightsStateVersion=Gt,at.needsLights&&(Kt.ambientLightColor.value=st.state.ambient,Kt.lightProbe.value=st.state.probe,Kt.directionalLights.value=st.state.directional,Kt.directionalLightShadows.value=st.state.directionalShadow,Kt.spotLights.value=st.state.spot,Kt.spotLightShadows.value=st.state.spotShadow,Kt.rectAreaLights.value=st.state.rectArea,Kt.ltc_1.value=st.state.rectAreaLTC1,Kt.ltc_2.value=st.state.rectAreaLTC2,Kt.pointLights.value=st.state.point,Kt.pointLightShadows.value=st.state.pointShadow,Kt.hemisphereLights.value=st.state.hemi,Kt.directionalShadowMatrix.value=st.state.directionalShadowMatrix,Kt.spotLightMatrix.value=st.state.spotLightMatrix,Kt.spotLightMap.value=st.state.spotLightMap,Kt.pointShadowMatrix.value=st.state.pointShadowMatrix),at.lightProbeGrid=O.state.lightProbeGridArray.length>0,at.currentProgram=oe,at.uniformsList=null,oe}function Qi(R){if(R.uniformsList===null){const Y=R.currentProgram.getUniforms();R.uniformsList=tu.seqWithValue(Y.seq,R.uniforms)}return R.uniformsList}function $i(R,Y){const ot=rt.get(R);ot.outputColorSpace=Y.outputColorSpace,ot.batching=Y.batching,ot.batchingColor=Y.batchingColor,ot.instancing=Y.instancing,ot.instancingColor=Y.instancingColor,ot.instancingMorph=Y.instancingMorph,ot.skinning=Y.skinning,ot.morphTargets=Y.morphTargets,ot.morphNormals=Y.morphNormals,ot.morphColors=Y.morphColors,ot.morphTargetsCount=Y.morphTargetsCount,ot.numClippingPlanes=Y.numClippingPlanes,ot.numIntersection=Y.numClipIntersection,ot.vertexAlphas=Y.vertexAlphas,ot.vertexTangents=Y.vertexTangents,ot.toneMapping=Y.toneMapping}function ps(R,Y){if(R.length===0)return null;if(R.length===1)return R[0].texture!==null?R[0]:null;A.setFromMatrixPosition(Y.matrixWorld);for(let ot=0,at=R.length;ot<at;ot++){const st=R[ot];if(st.texture!==null&&st.boundingBox.containsPoint(A))return st}return null}function Da(R,Y,ot,at,st){Y.isScene!==!0&&(Y=fn),mt.resetTextureUnits();const Pt=Y.fog,Gt=at.isMeshStandardMaterial||at.isMeshLambertMaterial||at.isMeshPhongMaterial?Y.environment:null,Lt=$===null?X.outputColorSpace:$.isXRRenderTarget===!0?$.texture.colorSpace:Ee.workingColorSpace,Xt=at.isMeshStandardMaterial||at.isMeshLambertMaterial&&!at.envMap||at.isMeshPhongMaterial&&!at.envMap,kt=Rt.get(at.envMap||Gt,Xt),te=at.vertexColors===!0&&!!ot.attributes.color&&ot.attributes.color.itemSize===4,oe=!!ot.attributes.tangent&&(!!at.normalMap||at.anisotropy>0),Kt=!!ot.morphAttributes.position,Te=!!ot.morphAttributes.normal,je=!!ot.morphAttributes.color;let Ve=Yi;at.toneMapped&&($===null||$.isXRRenderTarget===!0)&&(Ve=X.toneMapping);const Ue=ot.morphAttributes.position||ot.morphAttributes.normal||ot.morphAttributes.color,Le=Ue!==void 0?Ue.length:0,Ht=rt.get(at),Pn=O.state.lights;if(ye===!0&&(de===!0||R!==Mt)){const De=R===Mt&&at.id===dt;Qt.setState(at,R,De)}let pe=!1;at.version===Ht.__version?(Ht.needsLights&&Ht.lightsStateVersion!==Pn.state.version||Ht.outputColorSpace!==Lt||st.isBatchedMesh&&Ht.batching===!1||!st.isBatchedMesh&&Ht.batching===!0||st.isBatchedMesh&&Ht.batchingColor===!0&&st.colorTexture===null||st.isBatchedMesh&&Ht.batchingColor===!1&&st.colorTexture!==null||st.isInstancedMesh&&Ht.instancing===!1||!st.isInstancedMesh&&Ht.instancing===!0||st.isSkinnedMesh&&Ht.skinning===!1||!st.isSkinnedMesh&&Ht.skinning===!0||st.isInstancedMesh&&Ht.instancingColor===!0&&st.instanceColor===null||st.isInstancedMesh&&Ht.instancingColor===!1&&st.instanceColor!==null||st.isInstancedMesh&&Ht.instancingMorph===!0&&st.morphTexture===null||st.isInstancedMesh&&Ht.instancingMorph===!1&&st.morphTexture!==null||Ht.envMap!==kt||at.fog===!0&&Ht.fog!==Pt||Ht.numClippingPlanes!==void 0&&(Ht.numClippingPlanes!==Qt.numPlanes||Ht.numIntersection!==Qt.numIntersection)||Ht.vertexAlphas!==te||Ht.vertexTangents!==oe||Ht.morphTargets!==Kt||Ht.morphNormals!==Te||Ht.morphColors!==je||Ht.toneMapping!==Ve||Ht.morphTargetsCount!==Le||!!Ht.lightProbeGrid!=O.state.lightProbeGridArray.length>0)&&(pe=!0):(pe=!0,Ht.__version=at.version);let yn=Ht.currentProgram;pe===!0&&(yn=wa(at,Y,st),q&&at.isNodeMaterial&&q.onUpdateProgram(at,yn,Ht));let ei=!1,Ai=!1,ni=!1;const Oe=yn.getUniforms(),Je=Ht.uniforms;if(E.useProgram(yn.program)&&(ei=!0,Ai=!0,ni=!0),at.id!==dt&&(dt=at.id,Ai=!0),Ht.needsLights){const De=ps(O.state.lightProbeGridArray,st);Ht.lightProbeGrid!==De&&(Ht.lightProbeGrid=De,Ai=!0)}if(ei||Mt!==R){E.buffers.depth.getReversed()&&R.reversedDepth!==!0&&(R._reversedDepth=!0,R.updateProjectionMatrix()),Oe.setValue(Z,"projectionMatrix",R.projectionMatrix),Oe.setValue(Z,"viewMatrix",R.matrixWorldInverse);const zi=Oe.map.cameraPosition;zi!==void 0&&zi.setValue(Z,an.setFromMatrixPosition(R.matrixWorld)),L.logarithmicDepthBuffer&&Oe.setValue(Z,"logDepthBufFC",2/(Math.log(R.far+1)/Math.LN2)),(at.isMeshPhongMaterial||at.isMeshToonMaterial||at.isMeshLambertMaterial||at.isMeshBasicMaterial||at.isMeshStandardMaterial||at.isShaderMaterial)&&Oe.setValue(Z,"isOrthographic",R.isOrthographicCamera===!0),Mt!==R&&(Mt=R,Ai=!0,ni=!0)}if(Ht.needsLights&&(Pn.state.directionalShadowMap.length>0&&Oe.setValue(Z,"directionalShadowMap",Pn.state.directionalShadowMap,mt),Pn.state.spotShadowMap.length>0&&Oe.setValue(Z,"spotShadowMap",Pn.state.spotShadowMap,mt),Pn.state.pointShadowMap.length>0&&Oe.setValue(Z,"pointShadowMap",Pn.state.pointShadowMap,mt)),st.isSkinnedMesh){Oe.setOptional(Z,st,"bindMatrix"),Oe.setOptional(Z,st,"bindMatrixInverse");const De=st.skeleton;De&&(De.boneTexture===null&&De.computeBoneTexture(),Oe.setValue(Z,"boneTexture",De.boneTexture,mt))}st.isBatchedMesh&&(Oe.setOptional(Z,st,"batchingTexture"),Oe.setValue(Z,"batchingTexture",st._matricesTexture,mt),Oe.setOptional(Z,st,"batchingIdTexture"),Oe.setValue(Z,"batchingIdTexture",st._indirectTexture,mt),Oe.setOptional(Z,st,"batchingColorTexture"),st._colorsTexture!==null&&Oe.setValue(Z,"batchingColorTexture",st._colorsTexture,mt));const Ri=ot.morphAttributes;if((Ri.position!==void 0||Ri.normal!==void 0||Ri.color!==void 0)&&W.update(st,ot,yn),(Ai||Ht.receiveShadow!==st.receiveShadow)&&(Ht.receiveShadow=st.receiveShadow,Oe.setValue(Z,"receiveShadow",st.receiveShadow)),(at.isMeshStandardMaterial||at.isMeshLambertMaterial||at.isMeshPhongMaterial)&&at.envMap===null&&Y.environment!==null&&(Je.envMapIntensity.value=Y.environmentIntensity),Je.dfgLUT!==void 0&&(Je.dfgLUT.value=C2()),Ai){if(Oe.setValue(Z,"toneMappingExposure",X.toneMappingExposure),Ht.needsLights&&mn(Je,ni),Pt&&at.fog===!0&&Bt.refreshFogUniforms(Je,Pt),Bt.refreshMaterialUniforms(Je,at,xt,_t,O.state.transmissionRenderTarget[R.id]),Ht.needsLights&&Ht.lightProbeGrid){const De=Ht.lightProbeGrid;Je.probesSH.value=De.texture,Je.probesMin.value.copy(De.boundingBox.min),Je.probesMax.value.copy(De.boundingBox.max),Je.probesResolution.value.copy(De.resolution)}tu.upload(Z,Qi(Ht),Je,mt)}if(at.isShaderMaterial&&at.uniformsNeedUpdate===!0&&(tu.upload(Z,Qi(Ht),Je,mt),at.uniformsNeedUpdate=!1),at.isSpriteMaterial&&Oe.setValue(Z,"center",st.center),Oe.setValue(Z,"modelViewMatrix",st.modelViewMatrix),Oe.setValue(Z,"normalMatrix",st.normalMatrix),Oe.setValue(Z,"modelMatrix",st.matrixWorld),at.uniformsGroups!==void 0){const De=at.uniformsGroups;for(let zi=0,Na=De.length;zi<Na;zi++){const ms=De[zi];Tt.update(ms,yn),Tt.bind(ms,yn)}}return yn}function mn(R,Y){R.ambientLightColor.needsUpdate=Y,R.lightProbe.needsUpdate=Y,R.directionalLights.needsUpdate=Y,R.directionalLightShadows.needsUpdate=Y,R.pointLights.needsUpdate=Y,R.pointLightShadows.needsUpdate=Y,R.spotLights.needsUpdate=Y,R.spotLightShadows.needsUpdate=Y,R.rectAreaLights.needsUpdate=Y,R.hemisphereLights.needsUpdate=Y}function pl(R){return R.isMeshLambertMaterial||R.isMeshToonMaterial||R.isMeshPhongMaterial||R.isMeshStandardMaterial||R.isShadowMaterial||R.isShaderMaterial&&R.lights===!0}this.getActiveCubeFace=function(){return B},this.getActiveMipmapLevel=function(){return H},this.getRenderTarget=function(){return $},this.setRenderTargetTextures=function(R,Y,ot){const at=rt.get(R);at.__autoAllocateDepthBuffer=R.resolveDepthBuffer===!1,at.__autoAllocateDepthBuffer===!1&&(at.__useRenderToTexture=!1),rt.get(R.texture).__webglTexture=Y,rt.get(R.depthTexture).__webglTexture=at.__autoAllocateDepthBuffer?void 0:ot,at.__hasExternalTextures=!0},this.setRenderTargetFramebuffer=function(R,Y){const ot=rt.get(R);ot.__webglFramebuffer=Y,ot.__useDefaultFramebuffer=Y===void 0},this.setRenderTarget=function(R,Y=0,ot=0){$=R,B=Y,H=ot;let at=null,st=!1,Pt=!1;if(R){const Lt=rt.get(R);if(Lt.__useDefaultFramebuffer!==void 0){E.bindFramebuffer(Z.FRAMEBUFFER,Lt.__webglFramebuffer),U.copy(R.viewport),J.copy(R.scissor),bt=R.scissorTest,E.viewport(U),E.scissor(J),E.setScissorTest(bt),dt=-1;return}else if(Lt.__webglFramebuffer===void 0)mt.setupRenderTarget(R);else if(Lt.__hasExternalTextures)mt.rebindTextures(R,rt.get(R.texture).__webglTexture,rt.get(R.depthTexture).__webglTexture);else if(R.depthBuffer){const te=R.depthTexture;if(Lt.__boundDepthTexture!==te){if(te!==null&&rt.has(te)&&(R.width!==te.image.width||R.height!==te.image.height))throw new Error("THREE.WebGLRenderer: Attached DepthTexture is initialized to the incorrect size.");mt.setupDepthRenderbuffer(R)}}const Xt=R.texture;(Xt.isData3DTexture||Xt.isDataArrayTexture||Xt.isCompressedArrayTexture)&&(Pt=!0);const kt=rt.get(R).__webglFramebuffer;R.isWebGLCubeRenderTarget?(Array.isArray(kt[Y])?at=kt[Y][ot]:at=kt[Y],st=!0):R.samples>0&&mt.useMultisampledRTT(R)===!1?at=rt.get(R).__webglMultisampledFramebuffer:Array.isArray(kt)?at=kt[ot]:at=kt,U.copy(R.viewport),J.copy(R.scissor),bt=R.scissorTest}else U.copy(Jt).multiplyScalar(xt).floor(),J.copy(qe).multiplyScalar(xt).floor(),bt=he;if(ot!==0&&(at=ct),E.bindFramebuffer(Z.FRAMEBUFFER,at)&&E.drawBuffers(R,at),E.viewport(U),E.scissor(J),E.setScissorTest(bt),st){const Lt=rt.get(R.texture);Z.framebufferTexture2D(Z.FRAMEBUFFER,Z.COLOR_ATTACHMENT0,Z.TEXTURE_CUBE_MAP_POSITIVE_X+Y,Lt.__webglTexture,ot)}else if(Pt){const Lt=Y;for(let Xt=0;Xt<R.textures.length;Xt++){const kt=rt.get(R.textures[Xt]);Z.framebufferTextureLayer(Z.FRAMEBUFFER,Z.COLOR_ATTACHMENT0+Xt,kt.__webglTexture,ot,Lt)}}else if(R!==null&&ot!==0){const Lt=rt.get(R.texture);Z.framebufferTexture2D(Z.FRAMEBUFFER,Z.COLOR_ATTACHMENT0,Z.TEXTURE_2D,Lt.__webglTexture,ot)}dt=-1},this.readRenderTargetPixels=function(R,Y,ot,at,st,Pt,Gt,Lt=0){if(!(R&&R.isWebGLRenderTarget)){be("WebGLRenderer.readRenderTargetPixels: renderTarget is not THREE.WebGLRenderTarget.");return}let Xt=rt.get(R).__webglFramebuffer;if(R.isWebGLCubeRenderTarget&&Gt!==void 0&&(Xt=Xt[Gt]),Xt){E.bindFramebuffer(Z.FRAMEBUFFER,Xt);try{const kt=R.textures[Lt],te=kt.format,oe=kt.type;if(R.textures.length>1&&Z.readBuffer(Z.COLOR_ATTACHMENT0+Lt),!L.textureFormatReadable(te)){be("WebGLRenderer.readRenderTargetPixels: renderTarget is not in RGBA or implementation defined format.");return}if(!L.textureTypeReadable(oe)){be("WebGLRenderer.readRenderTargetPixels: renderTarget is not in UnsignedByteType or implementation defined type.");return}Y>=0&&Y<=R.width-at&&ot>=0&&ot<=R.height-st&&Z.readPixels(Y,ot,at,st,Dt.convert(te),Dt.convert(oe),Pt)}finally{const kt=$!==null?rt.get($).__webglFramebuffer:null;E.bindFramebuffer(Z.FRAMEBUFFER,kt)}}},this.readRenderTargetPixelsAsync=async function(R,Y,ot,at,st,Pt,Gt,Lt=0){if(!(R&&R.isWebGLRenderTarget))throw new Error("THREE.WebGLRenderer.readRenderTargetPixels: renderTarget is not THREE.WebGLRenderTarget.");let Xt=rt.get(R).__webglFramebuffer;if(R.isWebGLCubeRenderTarget&&Gt!==void 0&&(Xt=Xt[Gt]),Xt)if(Y>=0&&Y<=R.width-at&&ot>=0&&ot<=R.height-st){E.bindFramebuffer(Z.FRAMEBUFFER,Xt);const kt=R.textures[Lt],te=kt.format,oe=kt.type;if(R.textures.length>1&&Z.readBuffer(Z.COLOR_ATTACHMENT0+Lt),!L.textureFormatReadable(te))throw new Error("THREE.WebGLRenderer.readRenderTargetPixelsAsync: renderTarget is not in RGBA or implementation defined format.");if(!L.textureTypeReadable(oe))throw new Error("THREE.WebGLRenderer.readRenderTargetPixelsAsync: renderTarget is not in UnsignedByteType or implementation defined type.");const Kt=Z.createBuffer();Z.bindBuffer(Z.PIXEL_PACK_BUFFER,Kt),Z.bufferData(Z.PIXEL_PACK_BUFFER,Pt.byteLength,Z.STREAM_READ),Z.readPixels(Y,ot,at,st,Dt.convert(te),Dt.convert(oe),0);const Te=$!==null?rt.get($).__webglFramebuffer:null;E.bindFramebuffer(Z.FRAMEBUFFER,Te);const je=Z.fenceSync(Z.SYNC_GPU_COMMANDS_COMPLETE,0);return Z.flush(),await _M(Z,je,4),Z.bindBuffer(Z.PIXEL_PACK_BUFFER,Kt),Z.getBufferSubData(Z.PIXEL_PACK_BUFFER,0,Pt),Z.deleteBuffer(Kt),Z.deleteSync(je),Pt}else throw new Error("THREE.WebGLRenderer.readRenderTargetPixelsAsync: requested read bounds are out of range.")},this.copyFramebufferToTexture=function(R,Y=null,ot=0){const at=Math.pow(2,-ot),st=Math.floor(R.image.width*at),Pt=Math.floor(R.image.height*at),Gt=Y!==null?Y.x:0,Lt=Y!==null?Y.y:0;mt.setTexture2D(R,0),Z.copyTexSubImage2D(Z.TEXTURE_2D,ot,0,0,Gt,Lt,st,Pt),E.unbindTexture()},this.copyTextureToTexture=function(R,Y,ot=null,at=null,st=0,Pt=0){let Gt,Lt,Xt,kt,te,oe,Kt,Te,je;const Ve=R.isCompressedTexture?R.mipmaps[Pt]:R.image;if(ot!==null)Gt=ot.max.x-ot.min.x,Lt=ot.max.y-ot.min.y,Xt=ot.isBox3?ot.max.z-ot.min.z:1,kt=ot.min.x,te=ot.min.y,oe=ot.isBox3?ot.min.z:0;else{const Je=Math.pow(2,-st);Gt=Math.floor(Ve.width*Je),Lt=Math.floor(Ve.height*Je),R.isDataArrayTexture?Xt=Ve.depth:R.isData3DTexture?Xt=Math.floor(Ve.depth*Je):Xt=1,kt=0,te=0,oe=0}at!==null?(Kt=at.x,Te=at.y,je=at.z):(Kt=0,Te=0,je=0);const Ue=Dt.convert(Y.format),Le=Dt.convert(Y.type);let Ht;Y.isData3DTexture?(mt.setTexture3D(Y,0),Ht=Z.TEXTURE_3D):Y.isDataArrayTexture||Y.isCompressedArrayTexture?(mt.setTexture2DArray(Y,0),Ht=Z.TEXTURE_2D_ARRAY):(mt.setTexture2D(Y,0),Ht=Z.TEXTURE_2D),E.activeTexture(Z.TEXTURE0),E.pixelStorei(Z.UNPACK_FLIP_Y_WEBGL,Y.flipY),E.pixelStorei(Z.UNPACK_PREMULTIPLY_ALPHA_WEBGL,Y.premultiplyAlpha),E.pixelStorei(Z.UNPACK_ALIGNMENT,Y.unpackAlignment);const Pn=E.getParameter(Z.UNPACK_ROW_LENGTH),pe=E.getParameter(Z.UNPACK_IMAGE_HEIGHT),yn=E.getParameter(Z.UNPACK_SKIP_PIXELS),ei=E.getParameter(Z.UNPACK_SKIP_ROWS),Ai=E.getParameter(Z.UNPACK_SKIP_IMAGES);E.pixelStorei(Z.UNPACK_ROW_LENGTH,Ve.width),E.pixelStorei(Z.UNPACK_IMAGE_HEIGHT,Ve.height),E.pixelStorei(Z.UNPACK_SKIP_PIXELS,kt),E.pixelStorei(Z.UNPACK_SKIP_ROWS,te),E.pixelStorei(Z.UNPACK_SKIP_IMAGES,oe);const ni=R.isDataArrayTexture||R.isData3DTexture,Oe=Y.isDataArrayTexture||Y.isData3DTexture;if(R.isDepthTexture){const Je=rt.get(R),Ri=rt.get(Y),De=rt.get(Je.__renderTarget),zi=rt.get(Ri.__renderTarget);E.bindFramebuffer(Z.READ_FRAMEBUFFER,De.__webglFramebuffer),E.bindFramebuffer(Z.DRAW_FRAMEBUFFER,zi.__webglFramebuffer);for(let Na=0;Na<Xt;Na++)ni&&(Z.framebufferTextureLayer(Z.READ_FRAMEBUFFER,Z.COLOR_ATTACHMENT0,rt.get(R).__webglTexture,st,oe+Na),Z.framebufferTextureLayer(Z.DRAW_FRAMEBUFFER,Z.COLOR_ATTACHMENT0,rt.get(Y).__webglTexture,Pt,je+Na)),Z.blitFramebuffer(kt,te,Gt,Lt,Kt,Te,Gt,Lt,Z.DEPTH_BUFFER_BIT,Z.NEAREST);E.bindFramebuffer(Z.READ_FRAMEBUFFER,null),E.bindFramebuffer(Z.DRAW_FRAMEBUFFER,null)}else if(st!==0||R.isRenderTargetTexture||rt.has(R)){const Je=rt.get(R),Ri=rt.get(Y);E.bindFramebuffer(Z.READ_FRAMEBUFFER,ht),E.bindFramebuffer(Z.DRAW_FRAMEBUFFER,j);for(let De=0;De<Xt;De++)ni?Z.framebufferTextureLayer(Z.READ_FRAMEBUFFER,Z.COLOR_ATTACHMENT0,Je.__webglTexture,st,oe+De):Z.framebufferTexture2D(Z.READ_FRAMEBUFFER,Z.COLOR_ATTACHMENT0,Z.TEXTURE_2D,Je.__webglTexture,st),Oe?Z.framebufferTextureLayer(Z.DRAW_FRAMEBUFFER,Z.COLOR_ATTACHMENT0,Ri.__webglTexture,Pt,je+De):Z.framebufferTexture2D(Z.DRAW_FRAMEBUFFER,Z.COLOR_ATTACHMENT0,Z.TEXTURE_2D,Ri.__webglTexture,Pt),st!==0?Z.blitFramebuffer(kt,te,Gt,Lt,Kt,Te,Gt,Lt,Z.COLOR_BUFFER_BIT,Z.NEAREST):Oe?Z.copyTexSubImage3D(Ht,Pt,Kt,Te,je+De,kt,te,Gt,Lt):Z.copyTexSubImage2D(Ht,Pt,Kt,Te,kt,te,Gt,Lt);E.bindFramebuffer(Z.READ_FRAMEBUFFER,null),E.bindFramebuffer(Z.DRAW_FRAMEBUFFER,null)}else Oe?R.isDataTexture||R.isData3DTexture?Z.texSubImage3D(Ht,Pt,Kt,Te,je,Gt,Lt,Xt,Ue,Le,Ve.data):Y.isCompressedArrayTexture?Z.compressedTexSubImage3D(Ht,Pt,Kt,Te,je,Gt,Lt,Xt,Ue,Ve.data):Z.texSubImage3D(Ht,Pt,Kt,Te,je,Gt,Lt,Xt,Ue,Le,Ve):R.isDataTexture?Z.texSubImage2D(Z.TEXTURE_2D,Pt,Kt,Te,Gt,Lt,Ue,Le,Ve.data):R.isCompressedTexture?Z.compressedTexSubImage2D(Z.TEXTURE_2D,Pt,Kt,Te,Ve.width,Ve.height,Ue,Ve.data):Z.texSubImage2D(Z.TEXTURE_2D,Pt,Kt,Te,Gt,Lt,Ue,Le,Ve);E.pixelStorei(Z.UNPACK_ROW_LENGTH,Pn),E.pixelStorei(Z.UNPACK_IMAGE_HEIGHT,pe),E.pixelStorei(Z.UNPACK_SKIP_PIXELS,yn),E.pixelStorei(Z.UNPACK_SKIP_ROWS,ei),E.pixelStorei(Z.UNPACK_SKIP_IMAGES,Ai),Pt===0&&Y.generateMipmaps&&Z.generateMipmap(Ht),E.unbindTexture()},this.initRenderTarget=function(R){rt.get(R).__webglFramebuffer===void 0&&mt.setupRenderTarget(R)},this.initTexture=function(R){R.isCubeTexture?mt.setTextureCube(R,0):R.isData3DTexture?mt.setTexture3D(R,0):R.isDataArrayTexture||R.isCompressedArrayTexture?mt.setTexture2DArray(R,0):mt.setTexture2D(R,0),E.unbindTexture()},this.resetState=function(){B=0,H=0,$=null,E.reset(),Ft.reset()},typeof __THREE_DEVTOOLS__<"u"&&__THREE_DEVTOOLS__.dispatchEvent(new CustomEvent("observe",{detail:this}))}get coordinateSystem(){return qi}get outputColorSpace(){return this._outputColorSpace}set outputColorSpace(t){this._outputColorSpace=t;const n=this.getContext();n.drawingBufferColorSpace=Ee._getDrawingBufferColorSpace(t),n.unpackColorSpace=Ee._getUnpackColorSpace()}}/**
 * @license lucide-react v0.468.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const D2=r=>r.replace(/([a-z0-9])([A-Z])/g,"$1-$2").toLowerCase(),Tx=(...r)=>r.filter((t,n,s)=>!!t&&t.trim()!==""&&s.indexOf(t)===n).join(" ").trim();/**
 * @license lucide-react v0.468.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */var N2={xmlns:"http://www.w3.org/2000/svg",width:24,height:24,viewBox:"0 0 24 24",fill:"none",stroke:"currentColor",strokeWidth:2,strokeLinecap:"round",strokeLinejoin:"round"};/**
 * @license lucide-react v0.468.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const U2=cn.forwardRef(({color:r="currentColor",size:t=24,strokeWidth:n=2,absoluteStrokeWidth:s,className:l="",children:c,iconNode:f,...d},m)=>cn.createElement("svg",{ref:m,...N2,width:t,height:t,stroke:r,strokeWidth:s?Number(n)*24/Number(t):n,className:Tx("lucide",l),...d},[...f.map(([p,v])=>cn.createElement(p,v)),...Array.isArray(c)?c:[c]]));/**
 * @license lucide-react v0.468.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const Rn=(r,t)=>{const n=cn.forwardRef(({className:s,...l},c)=>cn.createElement(U2,{ref:c,iconNode:t,className:Tx(`lucide-${D2(r)}`,s),...l}));return n.displayName=`${r}`,n};/**
 * @license lucide-react v0.468.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const L2=Rn("Anchor",[["path",{d:"M12 22V8",key:"qkxhtm"}],["path",{d:"M5 12H2a10 10 0 0 0 20 0h-3",key:"1hv3nh"}],["circle",{cx:"12",cy:"5",r:"3",key:"rqqgnr"}]]);/**
 * @license lucide-react v0.468.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const A_=Rn("ArrowLeft",[["path",{d:"m12 19-7-7 7-7",key:"1l729n"}],["path",{d:"M19 12H5",key:"x3x0zl"}]]);/**
 * @license lucide-react v0.468.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const R_=Rn("FileText",[["path",{d:"M15 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7Z",key:"1rqfz7"}],["path",{d:"M14 2v4a2 2 0 0 0 2 2h4",key:"tnqrlb"}],["path",{d:"M10 9H8",key:"b1mrlr"}],["path",{d:"M16 13H8",key:"t4e002"}],["path",{d:"M16 17H8",key:"z1uh3a"}]]);/**
 * @license lucide-react v0.468.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const O2=Rn("FileWarning",[["path",{d:"M15 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7Z",key:"1rqfz7"}],["path",{d:"M12 9v4",key:"juzpu7"}],["path",{d:"M12 17h.01",key:"p32p05"}]]);/**
 * @license lucide-react v0.468.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const C_=Rn("Folder",[["path",{d:"M20 20a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-7.9a2 2 0 0 1-1.69-.9L9.6 3.9A2 2 0 0 0 7.93 3H4a2 2 0 0 0-2 2v13a2 2 0 0 0 2 2Z",key:"1kt360"}]]);/**
 * @license lucide-react v0.468.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const P2=Rn("HardDrive",[["line",{x1:"22",x2:"2",y1:"12",y2:"12",key:"1y58io"}],["path",{d:"M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z",key:"oot6mr"}],["line",{x1:"6",x2:"6.01",y1:"16",y2:"16",key:"sgf278"}],["line",{x1:"10",x2:"10.01",y1:"16",y2:"16",key:"1l4acy"}]]);/**
 * @license lucide-react v0.468.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const I2=Rn("LockKeyhole",[["circle",{cx:"12",cy:"16",r:"1",key:"1au0dj"}],["rect",{x:"3",y:"10",width:"18",height:"12",rx:"2",key:"6s8ecr"}],["path",{d:"M7 10V7a5 5 0 0 1 10 0v3",key:"1pqi11"}]]);/**
 * @license lucide-react v0.468.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const Ax=Rn("Power",[["path",{d:"M12 2v10",key:"mnfbl"}],["path",{d:"M18.4 6.6a9 9 0 1 1-12.77.04",key:"obofu9"}]]);/**
 * @license lucide-react v0.468.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const z2=Rn("Radio",[["path",{d:"M4.9 19.1C1 15.2 1 8.8 4.9 4.9",key:"1vaf9d"}],["path",{d:"M7.8 16.2c-2.3-2.3-2.3-6.1 0-8.5",key:"u1ii0m"}],["circle",{cx:"12",cy:"12",r:"2",key:"1c9p78"}],["path",{d:"M16.2 7.8c2.3 2.3 2.3 6.1 0 8.5",key:"1j5fej"}],["path",{d:"M19.1 4.9C23 8.8 23 15.1 19.1 19",key:"10b0cb"}]]);/**
 * @license lucide-react v0.468.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const F2=Rn("RotateCcw",[["path",{d:"M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8",key:"1357e3"}],["path",{d:"M3 3v5h5",key:"1xhq8a"}]]);/**
 * @license lucide-react v0.468.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const B2=Rn("Server",[["rect",{width:"20",height:"8",x:"2",y:"2",rx:"2",ry:"2",key:"ngkwjq"}],["rect",{width:"20",height:"8",x:"2",y:"14",rx:"2",ry:"2",key:"iecqi9"}],["line",{x1:"6",x2:"6.01",y1:"6",y2:"6",key:"16zg32"}],["line",{x1:"6",x2:"6.01",y1:"18",y2:"18",key:"nzw8ys"}]]);/**
 * @license lucide-react v0.468.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const w_=Rn("ShieldCheck",[["path",{d:"M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z",key:"oel41y"}],["path",{d:"m9 12 2 2 4-4",key:"dzmm74"}]]);/**
 * @license lucide-react v0.468.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const eu=Rn("Skull",[["path",{d:"m12.5 17-.5-1-.5 1h1z",key:"3me087"}],["path",{d:"M15 22a1 1 0 0 0 1-1v-1a2 2 0 0 0 1.56-3.25 8 8 0 1 0-11.12 0A2 2 0 0 0 8 20v1a1 1 0 0 0 1 1z",key:"1o5pge"}],["circle",{cx:"15",cy:"12",r:"1",key:"1tmaij"}],["circle",{cx:"9",cy:"12",r:"1",key:"1vctgf"}]]);/**
 * @license lucide-react v0.468.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const H2=Rn("Smartphone",[["rect",{width:"14",height:"20",x:"5",y:"2",rx:"2",ry:"2",key:"1yt0o3"}],["path",{d:"M12 18h.01",key:"mhygvu"}]]);/**
 * @license lucide-react v0.468.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const D_=Rn("Terminal",[["polyline",{points:"4 17 10 11 4 5",key:"akl6gq"}],["line",{x1:"12",x2:"20",y1:"19",y2:"19",key:"q2wloq"}]]);/**
 * @license lucide-react v0.468.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const np=Rn("TriangleAlert",[["path",{d:"m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3",key:"wmoenq"}],["path",{d:"M12 9v4",key:"juzpu7"}],["path",{d:"M12 17h.01",key:"p32p05"}]]);/**
 * @license lucide-react v0.468.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const G2=Rn("Wifi",[["path",{d:"M12 20h.01",key:"zekei9"}],["path",{d:"M2 8.82a15 15 0 0 1 20 0",key:"dnpr2z"}],["path",{d:"M5 12.859a10 10 0 0 1 14 0",key:"1x1e6c"}],["path",{d:"M8.5 16.429a5 5 0 0 1 7 0",key:"1bycff"}]]);/**
 * @license lucide-react v0.468.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const N_=Rn("X",[["path",{d:"M18 6 6 18",key:"1bl5f8"}],["path",{d:"m6 6 12 12",key:"d8bk6v"}]]);function U_({variant:r,size:t,...n}){return z.jsx("button",{...n})}function V2(r){return z.jsx("input",{...r})}const od="maritime-incident-lock-v2",k2="0e1d1e8830347f97aa6323eb5a1f56b12a2df5af87dab59bf15be773bd3a6bfb";async function X2(r){const t=new TextEncoder().encode(r);if(!crypto.subtle){let s=2166136261;for(const l of t)s=Math.imul(s^l,16777619)>>>0;return s===410724115}return[...new Uint8Array(await crypto.subtle.digest("SHA-256",t))].map(s=>s.toString(16).padStart(2,"0")).join("")===k2}function W2(){const r=new URLSearchParams(location.search).get("feed");if(r)try{const t=new URL(r);if(t.protocol==="https:"&&t.pathname==="/api/state"&&!t.username&&!t.password)return t.href}catch{}return new URL("../api/state",location.href).href}function q2({phase:r}){const t=cn.useRef(null);return cn.useEffect(()=>{const n=t.current;if(!n)return;const s=new Pv;s.background=new fe("#7eb8d5"),s.fog=new pp("#9ec5d6",.006);const l=new bi(56,1,.1,1e3);l.position.set(0,5.2,14),l.lookAt(0,-8.5,-48);const c=new w2({antialias:!0});c.setPixelRatio(Math.min(window.devicePixelRatio,window.innerWidth<950?1.25:1.6)),c.outputColorSpace=hi,c.shadowMap.enabled=!0,c.shadowMap.type=O_,n.appendChild(c.domElement);const f=new Pv,d=new fu(0,100,100,0,-40,40);d.position.z=20;const m=new Kv("#b7d5dc","#071012",1.35),p=new t_("#d8edf0",2.3);p.position.set(-25,70,30),f.add(m,p);const v=new Ei({color:"#27363a",roughness:.52,metalness:.68}),_=new Ei({color:"#10191c",roughness:.45,metalness:.78}),g=new Ei({color:"#253538",roughness:.66,metalness:.42}),y=new Ei({color:"#05090a",roughness:.88,metalness:.12}),b=new Ei({color:"#9d7337",roughness:.34,metalness:.82}),w=new Ei({color:"#111b1e",roughness:.92,metalness:.18}),M=new Ei({color:"#17353a",emissive:"#07181b",roughness:.18,metalness:.42}),S=new $o({color:"#56f0c5"}),P=new $o({color:"#ffb92e"}),D=(pt,At,tt,_t,xt,It)=>{const jt=new un(new cs(tt,_t,xt),It);return jt.position.set(pt,At,0),jt.castShadow=!0,jt.receiveShadow=!0,f.add(jt),jt},A=(pt,At,tt=0)=>{const _t=new cx;pt.forEach(([It,jt],Jt)=>Jt?_t.lineTo(It,jt):_t.moveTo(It,jt)),_t.closePath();const xt=new un(new yp(_t),At);return xt.position.z=tt,xt.receiveShadow=!0,f.add(xt),xt};D(50,96,100,12,2.4,_),D(1.7,71,3.4,44,3.2,_),D(98.3,71,3.4,44,3.2,_),D(30.2,73.5,2.15,37,3.4,v),D(68.3,73.5,2.15,37,3.4,v),D(50,56.2,100,3.4,3.5,v),D(50,91.2,100,2.4,2.8,v),D(15.5,74,.5,34,.7,new Ei({color:"#78898c",roughness:.22,metalness:.9})),D(84.5,74,.5,34,.7,new Ei({color:"#78898c",roughness:.22,metalness:.9})),A([[0,0],[0,43],[7,54.5],[93,54.5],[100,43],[100,0]],g,1),A([[4,24],[8,57],[92,57],[96,24]],_,1.4),D(50,32.4,94,2.1,2.5,v),D(50,5.5,100,11,4,_),A([[1.5,2],[4.5,27],[37.5,27],[42,2]],g,2.1),A([[58,2],[62.5,27],[95.5,27],[98.5,2]],g,2.1),A([[42,1],[44.5,22],[55.5,22],[58,1]],w,2.2),D(21.3,22.5,29.5,1.25,2.5,v),D(78.7,22.5,29.5,1.25,2.5,v),D(20.5,14.4,24,8.8,2,M),D(79.5,14.4,24,8.8,2,M),[46,50,54].forEach(pt=>D(pt,5.7,1.6,8.5,1.1,y)),[44.5,48.2,51.8,55.5].forEach(pt=>D(pt,1.2,2.1,.42,.7,v)),[[10,10.5,7],[67.5,10.5,7]].forEach(([pt,At,tt],_t)=>{for(let xt=0;xt<tt;xt+=1){const It=D(pt+xt*3.45,At,1.25,.72,.7,(xt+_t)%4===0?P:S);It.position.z=3.35,D(pt+xt*3.45,At-2.1,1.55,.62,.8,y).position.z=3.2}}),[14,21,28].forEach((pt,At)=>{const tt=new un(new Sp(2.05,2.45,32),v);tt.position.set(pt,17.1,3.35),f.add(tt);const _t=new un(new vp(1.98,32),y);_t.position.set(pt,17.1,3.3),f.add(_t);const xt=D(pt,17.1,1.75,.16,.18,At===1?P:S);xt.position.z=3.75,xt.rotation.z=-.7+At*.55}),[[10.25,17.9],[29.2,18],[48.3,17.7],[68.15,18.1],[88.6,20.2]].forEach(([pt,At])=>{D(pt,47.2,At+1.45,25.1,2.8,y),D(pt,34.1,At*.58,1.2,3.4,_);const tt=D(pt+At*.39,34.15,.32,.32,.5,S);tt.position.z=2.1}),[-17,0,17].forEach((pt,At)=>{D(50+pt,94.1,13.2,3.8,1.8,y);for(let tt=0;tt<4;tt+=1){const _t=D(45.8+pt+tt*2.8,94.05,.35,.35,.5,(tt+At)%3===0?P:S);_t.position.z=1.35}});const I=new un(new Mp(6.1,.55,12,48),_);I.position.set(50,15.6,4),f.add(I);for(let pt=0;pt<8;pt+=1){const At=D(50,15.6,5.5,.42,.65,b);At.position.z=3.8,At.rotation.z=pt*Math.PI/4}const T=new un(new ou(1.25,1.25,1.4,24),b);T.rotation.x=Math.PI/2,T.position.set(50,15.6,4.3),f.add(T),D(50,8.2,5.2,11,3.8,_),[-1,1].forEach(pt=>{const At=D(89+pt*2.1,17,.65,8.5,.7,b);At.rotation.z=pt*-.16;const tt=D(89+pt*2.75,21.1,2.2,1.25,1.6,y);tt.rotation.z=pt*-.16}),s.add(new Kv("#e7f6ff","#173142",2.4));const N=new t_("#fff1d0",3.1);N.position.set(-40,60,-30),s.add(N);const X=new lu(450,32,16),V=new Ti({side:Vn,uniforms:{topColor:{value:new fe("#3787b7")},bottomColor:{value:new fe("#d4ebee")}},vertexShader:"varying vec3 vPos; void main(){ vPos=position; gl_Position=projectionMatrix*modelViewMatrix*vec4(position,1.0); }",fragmentShader:"uniform vec3 topColor; uniform vec3 bottomColor; varying vec3 vPos; void main(){ float h=normalize(vPos).y; gl_FragColor=vec4(mix(bottomColor,topColor,smoothstep(-0.12,0.72,h)),1.0); }"});s.add(new un(X,V));const q=new fl(620,620,120,120);q.rotateX(-Math.PI/2);const ct=new Ti({uniforms:{time:{value:0},deep:{value:new fe("#073f5d")},crest:{value:new fe("#2f91ad")},sunDirection:{value:new K(-.4,.8,-.2).normalize()}},vertexShader:`
        uniform float time;
        varying float vWave;
        varying vec2 vSeaPosition;
        varying vec3 vNormalW;
        void main() {
          vec3 p = position;
          float a = sin(p.x * .105 + time * 1.38) * .48;
          float b = sin(p.z * .085 - time * 1.02 + p.x * .035) * .34;
          float c = sin((p.x + p.z) * .16 + time * 1.92) * .14;
          p.y += a + b + c;
          vWave = p.y;
          vSeaPosition = p.xz;
          vNormalW = normalize(vec3(-.105*cos(p.x*.105+time*1.15), 1.0, .085*cos(p.z*.085-time*.82+p.x*.035)));
          gl_Position = projectionMatrix * modelViewMatrix * vec4(p, 1.0);
        }
      `,fragmentShader:`
        uniform float time;
        uniform vec3 deep;
        uniform vec3 crest;
        uniform vec3 sunDirection;
        varying float vWave;
        varying vec2 vSeaPosition;
        varying vec3 vNormalW;
        void main() {
          float light = pow(max(dot(normalize(vNormalW), sunDirection), 0.0), 2.0);
          float travellingRipple = sin(vSeaPosition.x * .31 + vSeaPosition.y * .18 + time * 2.2);
          float crossRipple = sin(vSeaPosition.x * -.16 + vSeaPosition.y * .27 - time * 1.55);
          float foam = smoothstep(.49, .76, vWave + travellingRipple * .07 + crossRipple * .04);
          float glint = pow(max(travellingRipple * crossRipple, 0.0), 7.0) * .13;
          vec3 color = mix(deep, crest, clamp(vWave + .5, 0.0, 1.0));
          color += light * vec3(.15,.23,.25) + foam * vec3(.32,.48,.51) + glint;
          gl_FragColor = vec4(color, 1.0);
        }
      `}),ht=new un(q,ct);ht.position.y=-.2,s.add(ht);const j=new Fr,B=new un(new cs(7.5,1.4,22),new Ei({color:"#26343b",roughness:.78}));B.position.y=.65,j.add(B);const H=new un(new cs(5.8,3.2,5.5),new Ei({color:"#e1e5e4",roughness:.7}));H.position.set(0,2.8,5.5),j.add(H),j.position.set(35,0,-112),j.scale.setScalar(.7),s.add(j);const $=new Ei({color:"#e84b35",emissive:"#4b0700"});for(const[pt,At]of[[-15,-46],[18,-72],[-32,-112]]){const tt=new Fr,_t=new un(new ou(.32,.5,1.5,12),$),xt=new un(new lu(.22,12,8),new $o({color:"#ff684e"}));xt.position.y=1,tt.add(_t,xt),tt.position.set(pt,.45,At),s.add(tt)}const dt=()=>{const pt=n.clientWidth,At=n.clientHeight;c.setSize(pt,At,!1),l.aspect=pt/At,l.updateProjectionMatrix()};dt();const Mt=new ResizeObserver(dt);Mt.observe(n);const U=performance.now();let J=0;const bt=()=>{J=requestAnimationFrame(bt);const pt=(performance.now()-U)/1e3;ct.uniforms.time.value=pt,j.position.x=35-pt%120*.16,l.position.y=5.2+Math.sin(pt*.55)*.09,l.position.x=Math.sin(pt*.19)*.025,l.rotation.z=Math.sin(pt*.42)*.0035,c.autoClear=!0,c.render(s,l),c.autoClear=!1,c.clearDepth(),c.render(f,d)};return bt(),()=>{cancelAnimationFrame(J),Mt.disconnect(),c.dispose(),q.dispose(),ct.dispose(),X.dispose(),V.dispose(),f.traverse(pt=>{pt instanceof un&&pt.geometry.dispose()}),[v,_,g,y,b,w,M,S,P].forEach(pt=>pt.dispose()),n.removeChild(c.domElement)}},[]),z.jsx("div",{ref:t,className:`bridge-scene phase-${r}`,"aria-label":"움직이는 바다가 보이는 선박 조타실"})}function Y2({failed:r}){return z.jsxs("div",{className:`radar ${r?"radar-failed":""}`,"aria-label":r?"추적 신호가 손실된 X-band 레이더":"정상 작동 중인 X-band 레이더",children:[z.jsx("span",{className:"radar-sweep"}),z.jsx("span",{className:"radar-ring radar-ring-a"}),z.jsx("span",{className:"radar-ring radar-ring-b"}),z.jsx("span",{className:"radar-line radar-line-x"}),z.jsx("span",{className:"radar-line radar-line-y"}),z.jsx("i",{className:"contact contact-a"}),z.jsx("i",{className:"contact contact-b"}),z.jsx("i",{className:"contact contact-c"}),z.jsx("span",{className:"own-ship",children:"▲"})]})}function Z2({failed:r,lab:t}){var n,s;return z.jsxs("div",{className:"ecdis-map",children:[z.jsxs("svg",{viewBox:"0 0 240 150","aria-label":"부산항 접근 항로 전자해도",children:[z.jsx("title",{children:"부산항 접근 항로 전자해도"}),z.jsx("path",{className:"land",d:"M0 0H92L78 28 105 52 89 74 105 101 86 150H0Z"}),z.jsx("path",{className:"depth",d:"M88 0C130 35 105 52 145 83s18 50 61 67"}),z.jsx("path",{className:"route",d:"M212 12 176 44 151 72 124 109 102 139"}),z.jsx("circle",{className:"waypoint",cx:"176",cy:"44",r:"4"}),z.jsx("circle",{className:"waypoint",cx:"151",cy:"72",r:"4"}),z.jsx("circle",{className:"waypoint",cx:"124",cy:"109",r:"4"}),z.jsx("path",{className:"ship-mark",d:"M142 83l-6 16 12-3z"})]}),z.jsx("span",{className:"ecdis-label",children:r?"POSITION SOURCE INVALID":(n=t==null?void 0:t.selected_source)!=null&&n.includes("aux")?`GPS 2 · XTE ${(((s=t.metrics)==null?void 0:s.actual_xte_m)??0).toFixed(1)} M`:"BUSAN APPROACH · ROUTE 04"})]})}function Yc({station:r}){return z.jsxs("div",{className:"monitor-lock-screen",children:[z.jsx(eu,{}),z.jsx("span",{children:"HAEYANG LOCKER"}),z.jsxs("strong",{children:["YOUR BRIDGE SYSTEM",z.jsx("br",{}),"HAS BEEN ENCRYPTED"]}),z.jsx("p",{children:"Navigation workstation and voyage data are unavailable."}),z.jsxs("div",{className:"monitor-lock-metrics",children:[z.jsxs("b",{children:["05",z.jsx("small",{children:"LOCKED"})]}),z.jsxs("b",{children:["27",z.jsx("small",{children:"ALARMS"})]}),z.jsxs("b",{children:["00:59:48",z.jsx("small",{children:"WINDOW"})]})]}),z.jsxs("em",{children:[z.jsx(I2,{})," DO NOT RESTART BRIDGE EQUIPMENT"]}),z.jsxs("small",{children:[r," · OFFLINE TRAINING MODE"]})]})}function K2(){return z.jsxs("div",{className:"system-down-screen",children:[z.jsx(Ax,{}),z.jsx("strong",{children:"SYSTEM DOWN"}),z.jsx("span",{children:"RADAR WORKSTATION UNAVAILABLE"}),z.jsx("i",{})]})}const L_=["NORMAL VOYAGE","GPS PRIMARY SOURCE INVALID","ARPA TARGET PROCESSING LOST","CONNING DATA BUS FROZEN","PROPULSION MONITOR OFFLINE","INTEGRATED BRIDGE COMPROMISED","SYSTEMS ENCRYPTED"];let Is=null;function Zc(r=680,t=.13){try{Is??(Is=new AudioContext);const n=Is.createOscillator(),s=Is.createGain();n.frequency.value=r,n.type="square",s.gain.setValueAtTime(.055,Is.currentTime),s.gain.exponentialRampToValueAtTime(.001,Is.currentTime+t),n.connect(s).connect(Is.destination),n.start(),n.stop(Is.currentTime+t)}catch{}}function ld({code:r,children:t}){return z.jsxs("div",{className:"failure-screen",children:[z.jsx(np,{}),z.jsx("strong",{children:t}),z.jsxs("span",{children:["FAULT CODE ",r]})]})}function j2(){var V,q,ct,ht,j,B;const[r,t]=cn.useState(!1),[n,s]=cn.useState(()=>sessionStorage.getItem(od)==="locked"?6:0),[l,c]=cn.useState(""),[f,d]=cn.useState(""),[m,p]=cn.useState(null),[v,_]=cn.useState({heading:72,speed:12.4,rpm:72,temp:81}),[g,y]=cn.useState(null),b=cn.useRef([]),w=new URL("../index.html",location.href),M=new URL("../gnss-simulator/index.html",location.href),S=new URL("../index.html",location.href);S.searchParams.set("view","workstation");const P=new URLSearchParams(location.search).get("feed");P&&(w.searchParams.set("feed",P),M.searchParams.set("feed",P),S.searchParams.set("feed",P));const D=cn.useCallback(()=>{b.current.forEach(window.clearTimeout),b.current=[]},[]),A=cn.useCallback(()=>n>0?!1:(D(),t(!1),sessionStorage.setItem(od,"locked"),Zc(920,.18),[1,2,3,4,5,6].forEach((H,$)=>{const dt=window.setTimeout(()=>{s(H),Zc(H>=5?360:760-H*55,H>=5?.34:.13)},$===0?250:250+$*1450);b.current.push(dt)}),!0),[n,D]),F=cn.useCallback(async H=>await X2(H)?(D(),sessionStorage.removeItem(od),s(0),t(!1),c(""),d(""),_({heading:72,speed:12.4,rpm:72,temp:81}),Zc(1080,.12),!0):!1,[D]);cn.useEffect(()=>()=>D(),[D]),cn.useEffect(()=>{const H=W2();let $=!0;const dt=async()=>{try{const U=await fetch(H,{cache:"no-store"});if(!U.ok)throw new Error(`HTTP ${U.status}`);const J=await U.json();$&&y(J)}catch{$&&y(null)}};dt();const Mt=window.setInterval(()=>void dt(),1500);return()=>{$=!1,window.clearInterval(Mt)}},[]),cn.useEffect(()=>{const H=window.setInterval(()=>{var $,dt;if(p(new Date),n<2){const Mt=Date.now()/1e3;_({heading:(($=g==null?void 0:g.turn_effect)==null?void 0:$.heading_deg)??72+Math.sin(Mt*.22)*.8,speed:((dt=g==null?void 0:g.navigation)==null?void 0:dt.speed_over_ground_knots)??12.4+Math.sin(Mt*.31)*.12,rpm:Math.round(72+Math.sin(Mt*.44)*2),temp:Math.round(81+Math.sin(Mt*.09))})}},400);return()=>window.clearInterval(H)},[n,g]),cn.useEffect(()=>{const H=document.modelContext;if(!(H!=null&&H.registerTool))return;const $=new AbortController;return(async()=>{await H.registerTool({name:"start_maritime_cyber_incident",title:"Start maritime cyber incident",description:"Start the visible staged ransomware simulation on the local training bridge.",inputSchema:{type:"object",properties:{},additionalProperties:!1},annotations:{readOnlyHint:!1,untrustedContentHint:!1},execute:()=>({started:A(),mode:"authorized-training-simulation"})},{signal:$.signal}),await H.registerTool({name:"restore_maritime_bridge_systems",title:"Restore maritime bridge systems",description:"Restore the visible training bridge using its recovery key.",inputSchema:{type:"object",properties:{recoveryKey:{type:"string"}},required:["recoveryKey"],additionalProperties:!1},annotations:{readOnlyHint:!1,untrustedContentHint:!1},execute:async Mt=>({restored:await F(typeof Mt.recoveryKey=="string"?Mt.recoveryKey:"")})},{signal:$.signal})})().catch(()=>{}),()=>$.abort()},[A,F]);const O=async H=>{H.preventDefault(),await F(l)||(d("INVALID RECOVERY KEY · ACCESS DENIED"),Zc(190,.28))},I=n===5,T=n===0&&(g==null?void 0:g.phase)!==void 0&&g.phase!=="baseline",N=n?L_[n]:T?(g==null?void 0:g.phase)==="deviating"?"GNSS ROUTE DEVIATION":"GNSS DATA ANOMALY":"NORMAL VOYAGE",X=(m==null?void 0:m.toLocaleTimeString("en-GB",{hour12:!1}))??"--:--:--";return z.jsxs("main",{className:`simulator-shell incident-phase-${n}`,children:[z.jsxs("output",{className:"portrait-notice",children:[z.jsx(H2,{}),z.jsx("strong",{children:"가로 모드로 회전해주세요"}),z.jsx("span",{children:"조타실 시뮬레이터는 가로 화면에 최적화되어 있습니다."})]}),z.jsx(q2,{phase:n}),z.jsx("div",{className:"glass-reflection","aria-hidden":"true"}),z.jsx("div",{className:"emergency-wash","aria-hidden":"true"}),z.jsxs("header",{className:"bridge-header",children:[z.jsxs("div",{className:"vessel-id",children:[z.jsx(L2,{size:17}),z.jsx("span",{children:"SPACE XsHip"}),z.jsx("small",{children:"BRIDGE · CONNING POSITION 1"})]}),z.jsxs("div",{className:`system-health ${n?"system-danger":T?"system-gnss":""}`,children:[n||T?z.jsx(np,{size:15}):z.jsx(w_,{size:15}),N]}),z.jsxs("time",{children:[X," KST"]})]}),z.jsxs("nav",{className:"sim-nav","aria-label":"시연 이동",children:[z.jsx("a",{href:w.href,children:"시연 시작 화면"}),z.jsx("a",{href:S.href,children:"선내 PC 문서함"}),z.jsx("a",{href:M.href,children:"GNSS 전자해도"})]}),z.jsxs("div",{className:`lab-readout ${(V=g==null?void 0:g.selected_source)!=null&&V.includes("aux")?"affected":""}`,"aria-live":"polite",children:[z.jsx("span",{children:g?"LIVE GNSS LAB":"GNSS LAB STANDBY"}),z.jsx("b",{children:(q=g==null?void 0:g.selected_source)!=null&&q.includes("aux")?"GPS 2 · AUX":g?"GPS 1 · PRIMARY":"FEED DISCONNECTED"}),z.jsxs("small",{children:["HDG ",v.heading.toFixed(1),"° · SOG ",v.speed.toFixed(1)," kn · RUDDER ",(((ct=g==null?void 0:g.turn_effect)==null?void 0:ct.rudder_actual_deg)??0).toFixed(1),"° · XTE ",(((ht=g==null?void 0:g.metrics)==null?void 0:ht.actual_xte_m)??0).toFixed(1)," m"]})]}),n>0&&z.jsxs("aside",{className:"incident-timeline",children:[z.jsx("span",{children:"INCIDENT PROGRESSION"}),L_.slice(1,6).map((H,$)=>z.jsxs("div",{className:n>$?"reached":"",children:[z.jsx("i",{}),H]},H))]}),z.jsxs("section",{className:"monitor-bank","aria-label":"선박 통합 조타 모니터",children:[z.jsxs("article",{className:`monitor radar-monitor ${n>=2?"failed":""}`,children:[z.jsxs("div",{className:"monitor-title",children:[z.jsx("span",{children:"X-BAND RADAR"}),z.jsx("b",{children:n>=2?"ERR":"TX"})]}),z.jsx(Y2,{failed:n>=2}),n>=2&&z.jsx(ld,{code:"RDR-109",children:"ARPA PROCESSOR LOST"}),z.jsxs("div",{className:"monitor-foot",children:[z.jsx("span",{children:"RNG 6 NM"}),z.jsx("span",{children:n>=2?"TRACK LOST":"ARPA 3"})]}),n>=6&&z.jsx(K2,{})]}),z.jsxs("article",{className:`monitor ecdis-monitor ${n>=1?"failed":""}`,children:[z.jsxs("div",{className:"monitor-title",children:[z.jsx("span",{children:"ECDIS 01"}),z.jsx("b",{children:n>=1?"NO FIX":(j=g==null?void 0:g.selected_source)!=null&&j.includes("aux")?"GPS 2":"GPS 1"})]}),z.jsx(Z2,{failed:n>=1,lab:g}),n>=1&&z.jsx("div",{className:"ecdis-alert",children:"⚠ NAVIGATION POSITION UNAVAILABLE"}),z.jsxs("div",{className:"monitor-foot",children:[z.jsxs("span",{children:["HDG ",v.heading.toFixed(0),"°"]}),z.jsx("span",{children:n>=1?"POS LOST":`SOG ${v.speed.toFixed(1)} kn`})]}),n>=6&&z.jsx(Yc,{station:"ECDIS-01"})]}),z.jsxs("article",{className:`monitor conning-monitor ${n>=3?"failed":""}`,children:[z.jsxs("div",{className:"monitor-title",children:[z.jsx("span",{children:"CONNING"}),z.jsx("b",{children:n>=3?"FROZEN":"AUTO"})]}),n>=3?z.jsx(ld,{code:"NAV-771",children:"NMEA DATA BUS FROZEN"}):z.jsxs(z.Fragment,{children:[z.jsxs("div",{className:"heading-value",children:[v.heading.toFixed(0),z.jsx("span",{children:"°T"})]}),z.jsxs("div",{className:"heading-scale",children:[z.jsx("span",{children:"060"}),z.jsx("i",{}),z.jsx("i",{}),z.jsx("b",{children:"072"}),z.jsx("i",{}),z.jsx("i",{}),z.jsx("span",{children:"080"})]}),z.jsxs("div",{className:"conning-grid",children:[z.jsxs("span",{children:["SOG",z.jsxs("b",{children:[v.speed.toFixed(1)," kn"]})]}),z.jsxs("span",{children:["ROT",z.jsx("b",{children:"+0.2°/m"})]}),z.jsxs("span",{children:["RUDDER",z.jsxs("b",{children:[(((B=g==null?void 0:g.turn_effect)==null?void 0:B.rudder_actual_deg)??0).toFixed(1),"°"]})]})]})]}),n>=6&&z.jsx(Yc,{station:"CONNING-01"})]}),z.jsxs("article",{className:`monitor engine-monitor ${n>=4?"failed":""}`,children:[z.jsxs("div",{className:"monitor-title",children:[z.jsx("span",{children:"PROPULSION"}),z.jsx("b",{children:n>=4?"OFFLINE":"RUN"})]}),n>=4?z.jsx(ld,{code:"IAS-451",children:"REMOTE I/O TIMEOUT"}):z.jsxs(z.Fragment,{children:[z.jsxs("div",{className:"engine-dials",children:[z.jsxs("div",{className:"dial",children:[z.jsx("span",{className:"needle needle-a"}),z.jsx("strong",{children:v.rpm}),z.jsx("small",{children:"RPM"})]}),z.jsxs("div",{className:"dial",children:[z.jsx("span",{className:"needle needle-b"}),z.jsx("strong",{children:v.temp}),z.jsx("small",{children:"°C"})]})]}),z.jsxs("div",{className:"engine-bars",children:[z.jsx("span",{style:{"--level":"76%"},children:"FUEL"}),z.jsx("span",{style:{"--level":"63%"},children:"LOAD"})]})]}),n>=6&&z.jsx(Yc,{station:"PROP-01"})]}),z.jsxs("article",{className:`monitor alarm-monitor ${n>=1?"failed":""}`,children:[z.jsxs("div",{className:"monitor-title",children:[z.jsx("span",{children:"ALARM / IAS"}),z.jsx("b",{className:n?"alarm-count":"healthy",children:n?Math.min(27,n*5):0})]}),n?z.jsxs("div",{className:"alarm-stack",children:[z.jsx("strong",{children:"CRITICAL ALARMS"}),z.jsx("span",{children:"GPS-1 SIGNAL FAILURE"}),n>=2&&z.jsx("span",{children:"RADAR PROC OFFLINE"}),n>=3&&z.jsx("span",{children:"IBS NETWORK TIMEOUT"}),n>=4&&z.jsx("span",{children:"PROP MONITOR LOST"})]}):z.jsxs("div",{className:"alarm-ok",children:[z.jsx(w_,{}),z.jsx("strong",{children:"NO ACTIVE ALARMS"}),z.jsxs("span",{children:["Last check ",X]})]}),z.jsxs("div",{className:"network-row",children:[z.jsx(z2,{size:13})," NMEA 2000 BUS ",z.jsx("b",{children:n>=3?"OFFLINE":"ONLINE"})]}),n>=6&&z.jsx(Yc,{station:"ALARM-IAS"})]})]}),I&&z.jsxs("div",{className:"compromise-banner",children:[z.jsx(eu,{}),z.jsx("span",{children:"INTEGRATED BRIDGE NETWORK COMPROMISED"}),z.jsx(eu,{})]}),z.jsxs("aside",{className:`demo-controls ${n?"controls-danger":""}`,children:[z.jsxs("div",{children:[z.jsx("span",{className:"eyebrow",children:"CYBER RANGE CONTROL"}),z.jsx("strong",{children:n?`STAGE ${n}/6 · RUNNING`:N})]}),(n===0||n>=6)&&z.jsxs(U_,{variant:"outline",size:"lg",onClick:()=>t(!0),className:"server-button",children:[z.jsx(B2,{})," ",n>=6?"Recovery server":"Server"]}),n>0&&n<6&&z.jsxs("div",{className:"live-indicator",children:[z.jsx("i",{})," LIVE"]})]}),z.jsx("div",{className:"training-badge",children:"AUTHORIZED TRAINING SIMULATION · NO LIVE VESSEL CONNECTION"}),r&&z.jsxs("section",{className:"ubuntu-screen","aria-label":"훈련용 우분투 서버 화면",children:[z.jsxs("header",{className:"ubuntu-topbar",children:[z.jsx("button",{type:"button",children:"Activities"}),z.jsx("span",{children:"SPACE XsHip · Server Operations"}),z.jsx("time",{children:X}),z.jsx(G2,{}),z.jsx(Ax,{})]}),z.jsxs("nav",{className:"ubuntu-dock","aria-label":"Ubuntu applications",children:[z.jsx("button",{type:"button","aria-label":"Files",children:z.jsx(C_,{})}),z.jsx("button",{type:"button","aria-label":"Terminal",children:z.jsx(D_,{})}),z.jsx("button",{type:"button","aria-label":"Server status",children:z.jsx(P2,{})}),z.jsx("i",{}),z.jsx("button",{type:"button","aria-label":"Back to bridge",onClick:()=>t(!1),children:z.jsx(A_,{})})]}),z.jsxs("div",{className:"ubuntu-wallpaper",children:[z.jsx("span",{children:"24.04"}),z.jsx("b",{children:"SPACE XsHip"}),z.jsx("small",{children:"VESSEL OPERATIONS SERVER"})]}),n===0?z.jsxs("article",{className:"ubuntu-files",children:[z.jsxs("header",{children:[z.jsxs("div",{children:[z.jsx("button",{type:"button","aria-label":"Back",children:z.jsx(A_,{})}),z.jsx("span",{children:"Downloads"})]}),z.jsx("button",{type:"button","aria-label":"Close",onClick:()=>t(!1),children:z.jsx(N_,{})})]}),z.jsxs("div",{className:"ubuntu-path",children:[z.jsx("span",{children:"woot"}),z.jsx("b",{children:"/"}),z.jsx("span",{children:"Downloads"})]}),z.jsxs("div",{className:"ubuntu-file-grid",children:[z.jsxs("div",{className:"ubuntu-file",children:[z.jsx(C_,{}),z.jsx("span",{children:"Vessel Reports"})]}),z.jsxs("div",{className:"ubuntu-file",children:[z.jsx(R_,{}),z.jsx("span",{children:"Crew_Rotation.pdf"})]}),z.jsxs("div",{className:"ubuntu-file",children:[z.jsx(R_,{}),z.jsx("span",{children:"Port_Clearance.pdf"})]}),z.jsxs("button",{type:"button",className:"payload-file",onClick:A,"aria-label":"훈련용 의심 파일 실행",children:[z.jsx("span",{className:"pdf-badge",children:"PDF"}),z.jsx(O2,{}),z.jsxs("span",{children:["Voyage_Safety_",z.jsx("br",{}),"Notice.pdf.run"]}),z.jsx("small",{children:"Downloaded 09:42"})]})]}),z.jsxs("footer",{children:[z.jsx("span",{children:"4 items"}),z.jsx("strong",{children:"TRAINING SERVER · ISOLATED"})]})]}):z.jsxs("article",{className:"ubuntu-recovery-terminal",children:[z.jsxs("header",{children:[z.jsxs("div",{children:[z.jsx(D_,{}),z.jsx("span",{children:"root@space-xship: ~/incident-response"})]}),z.jsx("button",{type:"button","aria-label":"Back to bridge",onClick:()=>t(!1),children:z.jsx(N_,{})})]}),z.jsxs("div",{className:"terminal-log",children:[z.jsx("span",{children:"[CRITICAL] Integrated Bridge network heartbeat lost"}),z.jsx("span",{children:"[FAILED] radar-01.service · navigation-data.service"}),z.jsx("span",{children:"[LOCKED] ECDIS-01 · CONNING-01 · PROP-01 · ALARM-IAS"}),z.jsx("span",{children:"[READY] Offline recovery controller mounted"})]}),z.jsxs("div",{className:"server-ransom-card",children:[z.jsx(eu,{}),z.jsx("span",{children:"HAEYANG LOCKER · RECOVERY CONSOLE"}),z.jsx("strong",{children:"BRIDGE NETWORK ENCRYPTED"}),z.jsx("p",{children:"Use the authorized recovery key to unlock all simulated bridge workstations."}),z.jsxs("form",{onSubmit:O,children:[z.jsx("label",{htmlFor:"server-recovery-key",children:"RECOVERY KEY"}),z.jsxs("div",{children:[z.jsx(V2,{id:"server-recovery-key",type:"password",value:l,onChange:H=>{c(H.target.value),d("")},autoComplete:"off",placeholder:"Enter recovery key"}),z.jsxs(U_,{type:"submit",variant:"destructive",children:[z.jsx(F2,{})," Restore bridge"]})]}),f&&z.jsx("output",{"aria-live":"polite",children:f})]})]}),z.jsx("footer",{children:"ISOLATED TRAINING HOST · NO LIVE VESSEL CONNECTION"})]}),n===0&&z.jsxs("div",{className:"ubuntu-hint",children:[z.jsx(np,{})," Open the newly downloaded voyage safety notice"]})]})]})}Fy.createRoot(document.getElementById("root")).render(z.jsx(j2,{}));
