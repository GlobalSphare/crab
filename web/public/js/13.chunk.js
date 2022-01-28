"use strict";(self.webpackChunkisland_install_front=self.webpackChunkisland_install_front||[]).push([[13,858,126,911],{5597:(e,t,n)=>{n.d(t,{Z:()=>h});var a=n(5671),i=n(3144),r=n(7326),o=n(136),c=n(2963),l=n(1120),s=n(7294),u=n(4981);n(2477),n(6588);var h=function(e){(0,o.Z)(d,e);var t,n,h=(t=d,n=function(){if("undefined"==typeof Reflect||!Reflect.construct)return!1;if(Reflect.construct.sham)return!1;if("function"==typeof Proxy)return!0;try{return Boolean.prototype.valueOf.call(Reflect.construct(Boolean,[],(function(){}))),!0}catch(e){return!1}}(),function(){var e,a=(0,l.Z)(t);if(n){var i=(0,l.Z)(this).constructor;e=Reflect.construct(a,arguments,i)}else e=a.apply(this,arguments);return(0,c.Z)(this,e)});function d(e){var t;return(0,a.Z)(this,d),(t=h.call(this,e)).state={value:"",height:19,cursorStyle:"ace-cursor"},t.change=t.change.bind((0,r.Z)(t)),t.focus=t.focus.bind((0,r.Z)(t)),t.blur=t.blur.bind((0,r.Z)(t)),t.lineHeight=0,t.propsHeight=19,t}return(0,i.Z)(d,[{key:"focus",value:function(){this.setState({cursorStyle:""})}},{key:"blur",value:function(){this.setState({cursorStyle:"ace-cursor"})}},{key:"change",value:function(e){var t=this;this.setState({value:e},(function(){t.resize()}))}},{key:"getData",value:function(){return this.state.value}},{key:"setData",value:function(e){var t=this;this.setState({value:e},(function(){t.resize()}))}},{key:"setHeight",value:function(e){this.propsHeight=e,this.setState({height:e})}},{key:"resize",value:function(){this.lineHeight||(this.lineHeight=parseInt(getComputedStyle(document.querySelector(".ace_line")).lineHeight.replace("px","")));var e=this.state.value.split("\n").length;e*this.lineHeight>this.propsHeight?this.setState({height:e*this.lineHeight}):this.setState({height:this.propsHeight})}},{key:"aceLoaded",value:function(e){e.renderer.setPadding(0)}},{key:"render",value:function(){return s.createElement(u.ZP,{mode:"yaml",theme:"xcode",width:"100%",height:this.state.height+"px",style:{margin:0},placeholder:"请输入...",fontSize:14,tabSize:2,value:this.state.value,onLoad:this.aceLoaded,onChange:this.change,name:this.props.uniqueName,showGutter:!1,showPrintMargin:!1,highlightActiveLine:!1,onFocus:this.focus,onBlur:this.blur,editorProps:{$blockScrolling:!0}})}}]),d}(s.Component)},9678:(e,t,n)=>{n.d(t,{Z:()=>c});var a=n(7294),i=n(3411),r=n(4494),o=n(5477);const c=(0,r.$j)((function(e){return e}))((function(e){var t=i.Z.getState().common.loading;return a.createElement("div",{className:" circular-progress ".concat(t?"show-progress":"")},a.createElement(o.Z,{size:60,color:"primary"}))}))},6105:(e,t,n)=>{n.d(t,{Z:()=>h});var a=n(7462),i=n(7294),r=n(6912),o=n(2285),c=n(3411),l=n(5347),s=n(4494),u=function(e){return i.createElement(o.Z,(0,a.Z)({},e,{direction:"up"}))};const h=(0,s.$j)((function(e){return e}))((function(e){return i.createElement("div",{className:"snackbar-container"},i.createElement(r.Z,{open:Boolean(c.Z.getState().common.snackbar),anchorOrigin:{vertical:"bottom",horizontal:"center"},autoHideDuration:5e3,onClose:function(){c.Z.dispatch({type:l.Sn,val:""})},TransitionComponent:u,message:c.Z.getState().common.snackbar}))}))},8013:(e,t,n)=>{n.r(t),n.d(t,{default:()=>f});var a=n(8390),i=n(7294),r=n(4494),o=n(282),c=n(9669),l=n.n(c),s=n(3411),u=n(5347),h=n(9678),d=n(6105),p=n(5597);const f=(0,r.$j)((function(e){return e}))((function(e){var t=(0,i.useRef)(null),n=(0,i.useRef)(null),r=(0,i.useState)(""),c=(0,a.Z)(r,2),f=c[0],m=c[1],v=(0,i.useState)(null),g=(0,a.Z)(v,2),y=g[0],Z=g[1],S=(0,i.useState)(!1),b=(0,a.Z)(S,2),k=b[0],w=b[1];(0,i.useEffect)((function(){var e=function(){var e="";if(window.location.search){var t=window.location.search.substring(1);if(t.indexOf("&"))for(var n=t.split("&"),a=0,i=n.length;a<i;a++){var r=n[a].split("=");if(r&&"name"===r[0]){e=r[1];break}}}return e}();t.current.setHeight(parseInt(getComputedStyle(n.current).height.replace("px",""))),e?(m(e),E(e)):t.current.setData('apiVersion: aam.globalsphare.com/v1alpha1\nkind: WorkloadType\nmetadata:\n  name: example\nspec:\n  parameter: |\n    image: *"example" | string')}),[]);var E=function(e){s.Z.dispatch({type:u.br,val:!0}),l()({method:"GET",url:"/api/online/getworkloadtype",params:{name:e}}).then((function(e){0==e.data.code?(Z(e.data.result||{}),t.current.setData(e.data.result.value||"")):s.Z.dispatch({type:u.Sn,val:e.data.result})})).catch((function(e){console.log(e),s.Z.dispatch({type:u.Sn,val:"请求错误"})})).finally((function(){s.Z.dispatch({type:u.br,val:!1})}))};return i.createElement("section",{className:"page-container online-container"},i.createElement("header",{className:"online-header"},i.createElement("div",{className:"header-logo"},"Crab")),i.createElement("div",{className:"online-content"},i.createElement("div",{className:"oltitle"},f?"修改":"创建"," WorkloadType ",f?" : "+f:""),i.createElement("section",{className:"trait-content"},i.createElement("div",{className:"trait-textarea",ref:n},i.createElement(p.Z,{ref:t,uniqueName:"autoTxRef"})),i.createElement("div",{className:"online-btns"},f?i.createElement(o.Z,{disabled:k,className:"online-btn",variant:"contained",color:"primary",onClick:function(){s.Z.dispatch({type:u.br,val:!0});var e="/api/cluster/editworkload?id=".concat(y.id||"");w(!0),l()({url:e,method:"POST",headers:{"Content-Type":"application/json"},data:{value:t.current.getData()}}).then((function(e){0==e.data.code?setTimeout((function(){w(!1),window.opener.postMessage("workloadtype",window.location.origin),window.close()}),1e3):w(!1),s.Z.dispatch({type:u.Sn,val:e.data.result||""})})).catch((function(e){console.error(e),w(!1),s.Z.dispatch({type:u.Sn,val:"请求错误"})})).finally((function(){s.Z.dispatch({type:u.br,val:!1})}))}},"确认修改"):i.createElement(o.Z,{disabled:k,className:"online-btn",variant:"contained",color:"primary",onClick:function(){if(""!==t.current.getData().trim()||(s.Z.dispatch({type:u.Sn,val:"请输入trait内容"}),0)){s.Z.dispatch({type:u.br,val:!0}),w(!0);var e=t.current.getData();l()({method:"POST",url:"/api/online/createworkloadtype",data:{value:e},headers:{"Content-Type":"application/json"}}).then((function(e){s.Z.dispatch({type:u.Sn,val:e.data.result}),0==e.data.code&&setTimeout((function(){w(!1),window.opener.postMessage("workloadtype",window.location.origin),window.close()}),1e3)})).catch((function(e){console.log(e),w(!1),s.Z.dispatch({type:u.Sn,val:"请求错误"})})).finally((function(){s.Z.dispatch({type:u.br,val:!1})}))}}},"保存")))),i.createElement(h.Z,null),i.createElement(d.Z,null))}))}}]);