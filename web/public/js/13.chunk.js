"use strict";(self.webpackChunkisland_install_front=self.webpackChunkisland_install_front||[]).push([[13,858,126,911],{6381:(t,e,n)=>{n.d(e,{Z:()=>h});var a=n(5671),i=n(3144),r=n(7326),o=n(9611),c=n(1002);function s(t,e){return!e||"object"!==(0,c.Z)(e)&&"function"!=typeof e?(0,r.Z)(t):e}function l(t){return(l=Object.setPrototypeOf?Object.getPrototypeOf:function(t){return t.__proto__||Object.getPrototypeOf(t)})(t)}var u=n(7294);var h=function(t){!function(t,e){if("function"!=typeof e&&null!==e)throw new TypeError("Super expression must either be null or a function");t.prototype=Object.create(e&&e.prototype,{constructor:{value:t,writable:!0,configurable:!0}}),e&&(0,o.Z)(t,e)}(h,t);var e,n,c=(e=h,n=function(){if("undefined"==typeof Reflect||!Reflect.construct)return!1;if(Reflect.construct.sham)return!1;if("function"==typeof Proxy)return!0;try{return Boolean.prototype.valueOf.call(Reflect.construct(Boolean,[],(function(){}))),!0}catch(t){return!1}}(),function(){var t,a=l(e);if(n){var i=l(this).constructor;t=Reflect.construct(a,arguments,i)}else t=a.apply(this,arguments);return s(this,t)});function h(t){var e;return(0,a.Z)(this,h),(e=c.call(this,t)).state={value:""},e.txaRef=u.createRef(),e.setData=e.setData.bind((0,r.Z)(e)),e.getData=e.getData.bind((0,r.Z)(e)),e.lineHeight=0,e.padding=0,e.pasteData=!1,e.ctrlKey=!1,e}return(0,i.Z)(h,[{key:"componentDidMount",value:function(){this.lineHeight=parseInt(getComputedStyle(this.txaRef.current).lineHeight),this.padding=2*parseInt(getComputedStyle(this.txaRef.current).paddingTop),this.txaRef.current.style.height=this.padding+this.lineHeight+"px"}},{key:"setData",value:function(t){var e=this;this.setState({value:t},(function(){""===e.state.value.trim()?e.txaRef.current.style.height=e.padding+e.lineHeight+"px":e.txaRef.current.style.height=e.txaRef.current.scrollHeight+"px"}))}},{key:"getData",value:function(){return this.state.value}},{key:"changeValue",value:function(t){this.setState({value:t.target.value})}},{key:"keyDown",value:function(t){var e=this;if(13===t.keyCode)this.txaRef.current.style.height=this.txaRef.current.offsetHeight+this.lineHeight+"px";else if(9===t.keyCode){t.preventDefault();var n=this.txaRef.current.selectionStart,a=this.state.value.substring(0,n)+"    "+this.state.value.substring(n);this.setState({value:a},(function(){e.txaRef.current.selectionStart=n+4,e.txaRef.current.selectionEnd=n+4}))}else 91!=t.keyCode&&17!==t.keyCode||(this.ctrlKey=!0)}},{key:"keyUp",value:function(t){if(8===t.keyCode){var e=t.target.value.split("\n").length*this.lineHeight;e+this.padding<this.txaRef.current.offsetHeight&&(this.txaRef.current.style.height=e+"px")}else if(13===t.keyCode){var n=t.target.value.split("\n").length*this.lineHeight;this.txaRef.current.style.height=n+"px"}else if(9===t.keyCode)t.preventDefault();else if(88===t.keyCode&&this.ctrlKey){var a=t.target.value.split("\n").length*this.lineHeight;this.txaRef.current.style.height=a+"px",this.ctrlKey=!1}}},{key:"autoTxaClick",value:function(){this.txaRef.current.focus()}},{key:"paste",value:function(){this.pasteData=!0}},{key:"componentDidUpdate",value:function(){if(this.pasteData){var t=this.txaRef.current.value.split("\n").length*this.lineHeight;this.txaRef.current.style.height=t+"px",this.pasteData=!1}}},{key:"render",value:function(){return u.createElement("div",{className:"auto-textarea ".concat(this.props.class),onClick:this.autoTxaClick.bind(this)},u.createElement("textarea",{ref:this.txaRef,className:"auto-input",placeholder:"请输入...",value:this.state.value,onChange:this.changeValue.bind(this),onKeyDown:this.keyDown.bind(this),onKeyUp:this.keyUp.bind(this),onPaste:this.paste.bind(this)}))}}]),h}(u.Component)},9678:(t,e,n)=>{n.d(e,{Z:()=>c});var a=n(7294),i=n(3411),r=n(4494),o=n(5477);const c=(0,r.$j)((function(t){return t}))((function(t){var e=i.Z.getState().common.loading;return a.createElement("div",{className:" circular-progress ".concat(e?"show-progress":"")},a.createElement(o.Z,{size:60,color:"primary"}))}))},6105:(t,e,n)=>{n.d(e,{Z:()=>h});var a=n(7462),i=n(7294),r=n(6912),o=n(2285),c=n(3411),s=n(5347),l=n(4494),u=function(t){return i.createElement(o.Z,(0,a.Z)({},t,{direction:"up"}))};const h=(0,l.$j)((function(t){return t}))((function(t){return i.createElement("div",{className:"snackbar-container"},i.createElement(r.Z,{open:Boolean(c.Z.getState().common.snackbar),anchorOrigin:{vertical:"bottom",horizontal:"center"},autoHideDuration:5e3,onClose:function(){c.Z.dispatch({type:s.Sn,val:""})},TransitionComponent:u,message:c.Z.getState().common.snackbar}))}))},8013:(t,e,n)=>{n.r(e),n.d(e,{default:()=>d});var a=n(8390),i=n(7294),r=n(4494),o=n(282),c=n(9669),s=n.n(c),l=n(3411),u=n(5347),h=n(9678),p=n(6105),f=n(6381);const d=(0,r.$j)((function(t){return t}))((function(t){var e=(0,i.useRef)(null),n=(0,i.useState)(""),r=(0,a.Z)(n,2),c=r[0],d=r[1],v=(0,i.useState)(null),y=(0,a.Z)(v,2),g=y[0],m=y[1],k=(0,i.useState)(!1),Z=(0,a.Z)(k,2),b=Z[0],x=Z[1];(0,i.useEffect)((function(){var t=function(){var t="";if(window.location.search){var e=window.location.search.substring(1);if(e.indexOf("&"))for(var n=e.split("&"),a=0,i=n.length;a<i;a++){var r=n[a].split("=");if(r&&"name"===r[0]){t=r[1];break}}}return t}();t?(d(t),w(t)):e.current.setData('apiVersion: aam.globalsphare.com/v1alpha1\nkind: WorkloadType\nmetadata:\n    name: example\nspec:\n    parameter: |\n        image: *"example" | string')}),[]);var w=function(t){l.Z.dispatch({type:u.br,val:!0}),s()({method:"GET",url:"/api/online/getworkloadtype",params:{name:t}}).then((function(t){0==t.data.code?(m(t.data.result||{}),e.current.setData(t.data.result.value||"")):l.Z.dispatch({type:u.Sn,val:t.data.result})})).catch((function(t){console.log(t),l.Z.dispatch({type:u.Sn,val:"请求错误"})})).finally((function(){l.Z.dispatch({type:u.br,val:!1})}))};return i.createElement("section",{className:"page-container online-container"},i.createElement("header",{className:"online-header"},i.createElement("div",{className:"header-logo"},"Crab")),i.createElement("div",{className:"online-content"},i.createElement("div",{className:"oltitle"},c?"修改":"创建"," WorkloadType ",c?" : "+c:""),i.createElement("section",{className:"trait-content"},i.createElement(f.Z,{ref:e,class:"trait-textarea"}),i.createElement("div",{className:"online-btns"},c?i.createElement(o.Z,{disabled:b,className:"online-btn",variant:"contained",color:"primary",onClick:function(){l.Z.dispatch({type:u.br,val:!0});var t="/api/cluster/editworkload?id=".concat(g.id||"");x(!0),s()({url:t,method:"POST",headers:{"Content-Type":"application/json"},data:{value:e.current.getData()}}).then((function(t){0==t.data.code?setTimeout((function(){x(!1),window.opener.postMessage("workloadtype",window.location.origin),window.close()}),1e3):x(!1),l.Z.dispatch({type:u.Sn,val:t.data.result||""})})).catch((function(t){console.error(t),x(!1),l.Z.dispatch({type:u.Sn,val:"请求错误"})})).finally((function(){l.Z.dispatch({type:u.br,val:!1})}))}},"确认修改"):i.createElement(o.Z,{disabled:b,className:"online-btn",variant:"contained",color:"primary",onClick:function(){if(""!==e.current.getData().trim()||(l.Z.dispatch({type:u.Sn,val:"请输入trait内容"}),0)){l.Z.dispatch({type:u.br,val:!0}),x(!0);var t=e.current.getData();s()({method:"POST",url:"/api/online/createworkloadtype",data:{value:t},headers:{"Content-Type":"application/json"}}).then((function(t){l.Z.dispatch({type:u.Sn,val:t.data.result}),0==t.data.code&&setTimeout((function(){x(!1),window.opener.postMessage("workloadtype",window.location.origin),window.close()}),1e3)})).catch((function(t){console.log(t),x(!1),l.Z.dispatch({type:u.Sn,val:"请求错误"})})).finally((function(){l.Z.dispatch({type:u.br,val:!1})}))}}},"保存")))),i.createElement(h.Z,null),i.createElement(p.Z,null))}))},5671:(t,e,n)=>{function a(t,e){if(!(t instanceof e))throw new TypeError("Cannot call a class as a function")}n.d(e,{Z:()=>a})}}]);