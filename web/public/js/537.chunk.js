"use strict";(self.webpackChunkisland_install_front=self.webpackChunkisland_install_front||[]).push([[537,858,911],{9678:(e,t,a)=>{a.d(t,{Z:()=>l});var n=a(7294),r=a(3411),o=a(4494),c=a(5477);const l=(0,o.$j)((function(e){return e}))((function(e){var t=r.Z.getState().common.loading;return n.createElement("div",{className:" circular-progress ".concat(t?"show-progress":"")},n.createElement(c.Z,{size:60,color:"primary"}))}))},6105:(e,t,a)=>{a.d(t,{Z:()=>m});var n=a(7462),r=a(7294),o=a(6912),c=a(2285),l=a(3411),i=a(5347),s=a(4494),u=function(e){return r.createElement(c.Z,(0,n.Z)({},e,{direction:"up"}))};const m=(0,s.$j)((function(e){return e}))((function(e){return r.createElement("div",{className:"snackbar-container"},r.createElement(o.Z,{open:Boolean(l.Z.getState().common.snackbar),anchorOrigin:{vertical:"bottom",horizontal:"center"},autoHideDuration:5e3,onClose:function(){l.Z.dispatch({type:i.Sn,val:""})},TransitionComponent:u,message:l.Z.getState().common.snackbar}))}))},9537:(e,t,a)=>{a.r(t),a.d(t,{default:()=>d});var n=a(8390),r=a(7294),o=a(4494),c=a(9669),l=a.n(c),i=a(3411),s=a(5347),u=a(9678),m=a(6105);const d=(0,o.$j)((function(e){return e}))((function(e){var t=(0,r.useRef)(null),a=(0,r.useState)(""),o=(0,n.Z)(a,2),c=o[0],d=o[1],p=(0,r.useState)(""),v=(0,n.Z)(p,2),f=v[0],h=v[1];(0,r.useEffect)((function(){h(e.match.params.name),Z(e.match.params.type,e.match.params.name)}),[]);var Z=function(e,a){i.Z.dispatch({type:s.br,val:!0});var n="";switch(e){case"trait":n="/api/online/gettrait",d("Trait");break;case"workloadtype":n="/api/online/getworkloadtype",d("WorkloadType");break;case"workloadvendor":n="/api/online/getworkloadvendor",d("WorkloadVendor")}n?l()({method:"GET",url:n,params:{name:a}}).then((function(e){0==e.data.code?t.current.innerText=e.data.result&&e.data.result.value?e.data.result.value:"":i.Z.dispatch({type:s.Sn,val:e.data.result})})).catch((function(e){console.log(e),i.Z.dispatch({type:s.Sn,val:"请求错误"})})).finally((function(){i.Z.dispatch({type:s.br,val:!1})})):i.Z.dispatch({type:s.br,val:!1})};return r.createElement("section",{className:"online-container"},r.createElement("header",{className:"online-header"},r.createElement("div",{className:"header-logo"},"Crab")),r.createElement("div",{className:"online-preview-content"},r.createElement("div",{className:"oltitle"},"查看 ",c," : ",f),r.createElement("pre",{ref:t})),r.createElement(u.Z,null),r.createElement(m.Z,null))}))}}]);