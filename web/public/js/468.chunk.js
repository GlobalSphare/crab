(self.webpackChunkisland_install_front=self.webpackChunkisland_install_front||[]).push([[468],{7577:(e,t,n)=>{"use strict";n.d(t,{Z:()=>c});var a=n(7294);const c=function(e){return a.createElement("div",{className:"input-cmp-container"},a.createElement("div",{className:"input-cmp-content"},e.label?a.createElement("div",{className:"input-cmp-label"},a.createElement("label",{className:"input-label"},e.label)):null,a.createElement("div",{className:"input-context"},a.createElement("input",{type:e.type||"text",className:"".concat(e.inputErr?"input-border-hl":""," input-cmp-input"),value:e.value,onChange:function(){e.change&&e.change(event.target.value)},onBlur:blur,placeholder:e.placeholder||"请输入"}),e.inputErr?a.createElement("div",{className:"input-cmp-error"},a.createElement("p",null,e.inputErr)):null)))}},9678:(e,t,n)=>{"use strict";n.d(t,{Z:()=>r});var a=n(7294),c=n(124),l=n(4494),s=n(5477);const r=(0,l.$j)((function(e){return e}))((function(e){var t=c.Z.getState().common.loading;return a.createElement("div",{className:" circular-progress ".concat(t?"show-progress":"")},a.createElement(s.Z,{size:60,color:"primary"}))}))},6105:(e,t,n)=>{"use strict";n.d(t,{Z:()=>u});var a=n(7462),c=n(7294),l=n(6912),s=n(2285),r=n(124),i=n(5347),o=n(4494),m=function(e){return c.createElement(s.Z,(0,a.Z)({},e,{direction:"up"}))};const u=(0,o.$j)((function(e){return e}))((function(e){return c.createElement("div",{className:"snackbar-container"},c.createElement(l.Z,{open:Boolean(r.Z.getState().common.snackbar),anchorOrigin:{vertical:"bottom",horizontal:"center"},autoHideDuration:5e5,onClose:function(){r.Z.dispatch({type:i.Sn,val:""})},TransitionComponent:m,message:r.Z.getState().common.snackbar}))}))},8502:(e,t,n)=>{"use strict";n.r(t),n.d(t,{default:()=>A});var a=n(7294),c=n(8390),l=n(5977),s=n(4494),r=n(124),i=n(5347),o=n(9669),m=n.n(o),u=[{name:"应用管理",url:"/home",sub:[]},{name:"工作负载",url:"/home/workload",sub:[]},{name:"根域设置",url:"/home/domain",sub:[]},{name:"密码设置",url:"/home/reset",sub:[]}];const d=(0,s.$j)((function(e){return e}))((0,l.EN)((function(e){sessionStorage.getItem("curNav")||sessionStorage.setItem("curNav","/home");var t=(0,a.useState)(sessionStorage.getItem("curNav")),n=(0,c.Z)(t,2),l=n[0],s=n[1],o=(0,a.useState)([]),m=(0,c.Z)(o,2),d=m[0],p=m[1];function h(t){var n=t.currentTarget.dataset,a=n.id,c=n.path,l="https://"+n.href;if(""===c){var o=d.slice();!function e(t,n){if(t&&Array.isArray(t))for(var a=0,c=t.length;a<c;a++){if(t[a].id===n){t[a].showChild=!t[a].showChild;break}t[a].children&&e(t[a].children,n)}}(o,a),p(o)}else s(c),sessionStorage.setItem("curNav",c),c.indexOf(".")>-1?(e.change("/system"),r.Z.dispatch({type:i.nj,val:l})):e.change(c)}return console.log("leftNav props=",e),(0,a.useEffect)((function(){var e=function(e){return function e(t,n){Array.isArray(t)&&t.forEach((function(t,a){t.id=n+"."+a,t.sub&&e(t.sub,a+1)}))}(e,1),e}(u);p(e)}),[]),(0,a.useEffect)((function(){sessionStorage.setItem("curNav",e.common.curNav),s(e.common.curNav)}),[e.common.curNav]),a.createElement("div",{className:"nav-container"},a.createElement("div",{className:"logo"},a.createElement("p",{className:"logo-title"},"Crab")),a.createElement("div",{className:"nav-list"},d.map((function(e,t){return a.createElement("div",{className:"list-item",key:e.id},a.createElement("div",{className:"item-content ".concat(l==e.url?"blueBorder":""),"data-id":e.id,"data-path":e.url,onClick:h},a.createElement("i",{className:"iconfont ".concat(e.icon||"")}),a.createElement("span",null,e.name)),e.sub&&e.showChild?e.sub.map((function(t,n){return a.createElement("div",{className:"list-item",key:t.id},a.createElement("div",{className:"item-content item-content-child ".concat(l==e.url?"blueBorder":""),"data-id":t.id,"data-path":t.url,"data-href":t.url||"",onClick:h},a.createElement("i",{className:"iconfont ".concat(t.icon||"")}),a.createElement("span",null,t.name)))})):null)}))))})));var p=n(9678),h=n(6105),f=n(282),v=n(2387),E=n(6134),y=n(1581),j=n(5932),b=n(381),g=n.n(b),Z=n(8623),N=n(4313),k=n(9525),S=n(6856);const C=function(e){var t=(0,a.useState)(!1),n=(0,c.Z)(t,2),l=n[0],s=n[1],r=(0,a.useState)([]),i=(0,c.Z)(r,2),o=i[0],m=i[1],u=(0,a.useState)(),d=(0,c.Z)(u,2),p=d[0],h=d[1];(0,a.useEffect)((function(){b(e.data)}),[e.data]);var v,E,y,j,b=function(e){if(e&&e.dependencies&&(Object.keys(e.dependencies).forEach((function(t){var n=[];e.dependencies[t].instances.forEach((function(a,c){0==c&&"mutable"===e.dependencies[t].type?n.push({instance:a,selected:!0}):n.push({instance:a,selected:!1})})),e.dependencies[t].instances&&e.dependencies[t].instances.length&&"immutable"!==e.dependencies[t].type?e.dependencies[t].location={location:e.dependencies[t].location,selected:!1}:e.dependencies[t].location={location:e.dependencies[t].location,selected:!0},e.dependencies[t].instances=n})),console.log("data===",e),h(e),e.userconfigs&&Object.keys(e.userconfigs).length)){var t=[];!function e(n,a,c,l){n&&("object"==n.type&&n.properties?("userconfigs"!==a&&t.push({key:a,type:n.type,val:"",required:!1,error:"",level:l}),l+=1,Object.keys(n.properties).forEach((function(t){e(n.properties[t],t,n.required,l)}))):t.push({key:a,type:n.type,val:"",required:!!c&&-1!==c.indexOf(a),error:"",level:l}))}(e.userconfigs,"userconfigs",!1,-1),s(!0),m(t)}};function g(){e.close()}function C(e,t,n){if("immutable"!==p.dependencies[t].type||"instance"!=e){var a=Object.assign({},p);"instance"===e?(a.dependencies[t].location.selected=!1,a.dependencies[t].instances.forEach((function(e,t){t==n?(e.selected=!e.selected,e.selected):e.selected=!1}))):"location"===e&&(a.dependencies[t].instances.forEach((function(e,t){e.selected=!1})),a.dependencies[t].location.selected=!a.dependencies[t].location.selected,a.dependencies[t].location.selected),h(a)}}function w(){var e=event.target.dataset.key,t=Object.assign({},p);t.dependencies[e].location.location=event.target.value,h(t)}function z(){var e=event.target.dataset.index,t=o.slice();t[e].val=event.target.value,t[e].error="",m(t)}return a.createElement(Z.Z,{open:e.open,onClose:g,"aria-labelledby":"upload-file-title"},a.createElement(N.Z,{id:"upload-file-title"},e.title),a.createElement(k.Z,null,a.createElement("div",{className:"instance-content"},(v=e.data,y=[],j=-34,(E=v.dependencies||null)&&(j+=34,Object.keys(E).forEach((function(e,t){y.push(a.createElement("div",{style:{paddingLeft:j+"px"},className:"app-item",key:t},a.createElement("div",{className:"app-label"},a.createElement("span",{style:{backgroundColor:"#54CACB"},className:"label-icon app-icon"},a.createElement("i",{className:"iconfont icon_grey600"})," "),a.createElement("span",{className:"label-name"},e)),(E[e].instances||[]).map((function(t,n){return a.createElement("div",{key:n,className:"app-item-versions"},a.createElement("div",{className:"app-label",key:n},a.createElement("span",{className:"label-icon version-icon",onClick:function(){C("instance",e,n)}},a.createElement("i",{style:{color:"mutable"===E[e].type?"#54CACB":"#e0e0e0"},className:"".concat(t.selected?"iconfont icon_d-pass":"")})),a.createElement("span",{className:"label-name",style:{color:"mutable"===E[e].type?"#262626":"gray"}},"实例：",t.instance&&t.instance.id?t.instance.id:"","  ",t.instance&&t.instance.name?t.instance.name:"")))})),E[e].location?a.createElement("div",{className:"app-item-versions"},a.createElement("div",{className:"app-label"},a.createElement("span",{className:"label-icon version-icon",onClick:function(){C("location",e,"")}},a.createElement("i",{style:{color:"mutable"===E[e].type?"#54CACB":"#e0e0e0"},className:"".concat(E[e].location.selected?"iconfont icon_d-pass":"")})),a.createElement("span",{className:"label-name",style:{color:"mutable"===E[e].type?"#262626":"gray"}},"服务地址：",a.createElement("input",{"data-key":e,onChange:w,value:E[e].location.location,disabled:"immutable"===E[e].type,style:{color:"mutable"===E[e].type?"#262626":"gray"}})))):null,E[e].instances.length||E[e].location?null:a.createElement("div",{className:"app-item-versions"},a.createElement("div",{className:"app-label"},a.createElement("span",{className:"label-icon version-icon"}),a.createElement("span",{className:"label-name"},"暂无，需创建")))))}))),y).map((function(e,t){return e}))),a.createElement(Z.Z,{open:l,"aria-labelledby":"config-title"},a.createElement(N.Z,{id:"config-title"},"实例配置"),a.createElement(k.Z,null,a.createElement("div",{className:"appconfig-content"},o.map((function(e,t){return"object"===e.type?a.createElement("div",{key:e.key,className:"config-item",style:{marginLeft:40*e.level+"px"}},a.createElement("div",{className:"item-input"},a.createElement("label",null,e.key,":"))):a.createElement("div",{key:e.key,className:"config-item",style:{marginLeft:40*e.level+"px"}},a.createElement("div",{className:"item-input"},a.createElement("label",null,e.required?a.createElement("span",null,"* "):null,e.key,":"),a.createElement("input",{type:"number"==e.type?"number":"text",className:e.error?"red-border":"",placeholder:"number"===e.type?"请输入number类型":"请输入string类型","data-index":t,onChange:z,value:e.val})),e.error?a.createElement("p",{className:"item-error"},e.error):null)})))),a.createElement(S.Z,null,a.createElement(f.Z,{className:"common-btn",color:"primary",onClick:function(){var e=!0,t=o.slice();if(t.forEach((function(t){"object"!==t.type&&t.required&&""==t.val.trim()&&(t.error="请输入",e=!1)})),e){var n=Object.assign({},p);!function e(t,n){if(t)if("object"==t.type&&t.properties)Object.keys(t.properties).forEach((function(n){e(t.properties[n],n)}));else{console.log(222);var a=o.findIndex((function(e){return e.key===n}));t.val="number"===o[a].type?Number(o[a].val):o[a].val}}(n.userconfigs,"userconfigs"),console.log("--newAppInfo--",n),h(n),s(!1)}else m(t)}},"确定")))),a.createElement(S.Z,null,a.createElement(f.Z,{className:"common-btn",onClick:g},"取消"),a.createElement(f.Z,{className:"common-btn",color:"primary",onClick:function(){var t,n,a,c;e.submit((t=function(e){var t,n=[];return t=e,Object.keys(t).length&&Object.keys(t).forEach((function(e){var a=!1;t[e].location.selected?a=!0:t[e].instances.forEach((function(e){e.selected&&(a=!0)})),a||n.push(e)})),n}(p.dependencies||{}),console.log("--getData-0",p),{appInfo:p,notHadServe:(n=p.dependencies||[],c=[],a=n,Object.keys(a).length&&Object.keys(a).forEach((function(e){a[e].instances.length||a[e].location||c.push(e)})),c||[]),allAppSelectServe:t}))}},"确定")))},w=function(e){function t(){e.close()}return a.createElement(Z.Z,{open:e.open,onClose:t,"aria-labelledby":"read-log-title"},a.createElement(N.Z,{id:"read-log-title"},e.title),a.createElement(k.Z,null,a.createElement("div",{className:"log-list"},e.data.map((function(e,t){return a.createElement("div",{key:e.name,className:"log-item"},a.createElement("p",null,e.name,"："),a.createElement("p",{className:"item-desc"},e.message))})))),a.createElement(S.Z,null,a.createElement(f.Z,{className:"common-btn",color:"primary",onClick:t},"关闭")))},z=(0,s.$j)((function(e){return e}))((0,l.EN)((function(e){var t=(0,a.useRef)(null),n=(0,a.useState)(!1),l=(0,c.Z)(n,2),s=l[0],o=l[1],u=(0,a.useState)({}),d=(0,c.Z)(u,2),p=d[0],h=d[1],b=(0,a.useState)([]),Z=(0,c.Z)(b,2),N=Z[0],k=Z[1],S=(0,a.useState)(0),z=(0,c.Z)(S,2),O=z[0],x=z[1],T=(0,a.useState)(),_=(0,c.Z)(T,2),A=_[0],I=_[1],P=Boolean(A),D=(0,a.useState)(!1),H=(0,c.Z)(D,2),M=H[0],B=H[1],Y=(0,a.useState)("日志"),q=(0,c.Z)(Y,2),G=q[0],$=q[1],L=(0,a.useState)([]),W=(0,c.Z)(L,2),F=W[0],R=W[1],U=(0,a.useState)(1),J=(0,c.Z)(U,2),K=J[0],Q=J[1],V=(0,a.useState)(),X=(0,c.Z)(V,2),ee=X[0],te=X[1],ne=(0,a.useState)(-1),ae=(0,c.Z)(ne,2),ce=ae[0],le=ae[1];(0,a.useEffect)((function(){se()}),[]),(0,a.useEffect)((function(){re()}),[K]);var se=function(){m()({method:"GET",url:"/api/cluster/domain"}).then((function(e){0===e.data.code&&""!==e.data.result?(le(1),re()):le(0)})).catch((function(e){console.log(e),r.Z.dispatch({type:i.Sn,val:"请求错误"})}))},re=function(){r.Z.dispatch({type:i.br,val:!0}),m()({url:"/api/app/list",method:"GET",params:{offset:8*(K-1),limit:8}}).then((function(e){0===e.data.code?(k(e.data.result.rows||[]),x(e.data.result.total||0)):r.Z.dispatch({type:i.Sn,val:e.data.result||""}),r.Z.dispatch({type:i.br,val:!1})})).catch((function(e){console.error(e),r.Z.dispatch({type:i.Sn,val:"请求错误"}),r.Z.dispatch({type:i.br,val:!1})}))},ie=function(){o(!1)};return a.createElement("div",{className:"page-container manager-container"},a.createElement("div",{className:"page-title"},"应用管理"),0===ce?a.createElement("div",{className:"move-to-domain"},a.createElement("p",{className:"move-text"},"未设置根域，跳转设置页面"),a.createElement(f.Z,{className:"input-btn",variant:"contained",color:"primary",onClick:function(){e.history.push("/home/domain"),r.Z.dispatch({type:i.zR,val:"/home/domain"})}},"点击跳转")):null,1===ce?a.createElement(a.Fragment,null,a.createElement("div",{className:"upload-content"},a.createElement(f.Z,{className:"input-btn",variant:"contained",color:"primary",onClick:function(){t&&t.current.click()}},"上传"),a.createElement("input",{className:"upload-file",type:"file",ref:t,onChange:function(){r.Z.dispatch({type:i.br,val:!0});var e=event.target.files[0],n=new FormData;n.append("file",e),m()({url:"/api/app/upload",method:"POST",data:n,headers:{"Content-Type":"multipart/form-data"}}).then((function(e){0===e.data.code?(o(!0),h(e.data.result)):r.Z.dispatch({type:i.Sn,val:e.data.result||""}),r.Z.dispatch({type:i.br,val:!1}),t.current.value=""})).catch((function(e){console.error(e),r.Z.dispatch({type:i.Sn,val:"请求错误"}),r.Z.dispatch({type:i.br,val:!1}),t.current.value=""}))}})),a.createElement("div",{className:"instance-list"},a.createElement("table",{className:"table"},a.createElement("thead",null,a.createElement("tr",null,a.createElement("th",{width:"12%"},"实例名称"),a.createElement("th",{width:"10%"},"所属应用"),a.createElement("th",{width:"8%"},"版本"),a.createElement("th",{width:"25%"},"访问链接"),a.createElement("th",{width:"10%"},"状态"),a.createElement("th",{width:"15%"},"创建时间"),a.createElement("th",{width:"15%"},"更新时间"),a.createElement("th",{width:"5%"},"操作"))),a.createElement("tbody",{style:{position:"relative"}},N.map((function(e,t){return a.createElement("tr",{key:e.id},a.createElement("td",null,a.createElement("div",{className:"app-td"},e.id)),a.createElement("td",null,e.name),a.createElement("td",null,e.version),a.createElement("td",{className:"list-entry"},a.createElement("a",{href:e.entry,target:"_blank"},e.entry)),a.createElement("td",null,e.status),a.createElement("td",null,g()(e.created_at).format("YYYY-MM-DD hh:mm:ss")),a.createElement("td",null,g()(e.updated_at).format("YYYY-MM-DD hh:mm:ss")),a.createElement("td",{"data-item":e,onClick:function(){!function(e){te(e),console.log("sdlfjlksd===",ee),I(event.target)}(e)}},a.createElement("i",{className:"iconfont icon_navigation_more",style:{cursor:"pointer"}})))})))),a.createElement("div",{className:"pagination-content"},a.createElement(j.Z,{count:Math.ceil(O/8),page:K,shape:"rounded",onChange:function(e,t){Q(t)}})))):null,a.createElement(v.ZP,{open:P,anchorEl:A,anchorOrigin:{horizontal:"left",vertical:"bottom"},transformOrigin:{horizontal:"right",vertical:"top"},onClose:function(){I(null)}},a.createElement(E.Z,null,a.createElement(y.Z,{key:"1",style:{minHeight:"40px",lineHeight:"40px"},onClick:function(){I(null),r.Z.dispatch({type:i.br,val:!0}),m()({url:"/api/app/logs",method:"GET",params:{id:ee.id}}).then((function(e){0===e.data.code?(B(!0),$("实例 "+ee.name),R(e.data.result)):r.Z.dispatch({type:i.Sn,val:e.data.result||""}),r.Z.dispatch({type:i.br,val:!1})})).catch((function(e){console.error(e),r.Z.dispatch({type:i.Sn,val:"请求错误"}),r.Z.dispatch({type:i.br,val:!1})}))}},a.createElement("div",{className:"staticPopoverMenu"},a.createElement("i",{className:"iconfont icon_view"}),"  查看日志")),a.createElement(y.Z,{key:"2",style:{minHeight:"40px",lineHeight:"40px"},onClick:function(){I(null),window.open("/api/app/output?id="+ee.id)}},a.createElement("div",{className:"staticPopoverMenu"},a.createElement("i",{className:"iconfont icon_daochu"}),"  导出配置")),a.createElement(y.Z,{key:"3",style:{minHeight:"40px",lineHeight:"40px"},onClick:function(){I(null),r.Z.dispatch({type:i.br,val:!0}),m()({method:"GET",url:"/api/delete/instance",params:{id:ee.id}}).then((function(e){r.Z.dispatch({type:i.br,val:!1}),r.Z.dispatch({type:i.Sn,val:e.data.result||""})})).catch((function(e){r.Z.dispatch({type:i.Sn,val:"请求错误"}),r.Z.dispatch({type:i.br,val:!1})}))}},a.createElement("div",{className:"staticPopoverMenu"},a.createElement("i",{className:"iconfont icon_baseline_delete"}),"  删除")))),a.createElement(C,{open:s,title:"配置实例",data:p,close:ie,submit:function(e){if(e.notHadServe.length)r.Z.dispatch({type:i.Sn,val:e.notHadServe.join("、")+"以上应用中不存在服务，请创建"});else if(e.allAppSelectServe.length)r.Z.dispatch({type:i.Sn,val:e.allAppSelectServe.join("、")+"以上应用未选择服务，请选择"});else{r.Z.dispatch({type:i.br,val:!0});var t=function(e){var t=[],n={};return e&&e.dependencies&&Object.keys(e.dependencies).forEach((function(n){e.dependencies[n].location.selected?t.push({name:n,location:e.dependencies[n].location.location}):e.dependencies[n].instances.forEach((function(e){e.selected&&t.push({name:e.instance.name,id:e.instance.id})}))})),e.userconfigs&&function e(t,n,a){t&&("object"==t.type&&t.properties?(a[n]={},Object.keys(t.properties).forEach((function(c){e(t.properties[c],c,a[n])}))):a[n]=t.val)}(e.userconfigs,"userconfigs",n),{id:e.id,dependencies:t,userconfigs:n.userconfigs||null}}(e.appInfo);t.status=1,console.log("selectData===",t),m()({method:"POST",url:"api/app/run",headers:{"Content-Type":"application/json"},data:t}).then((function(e){console.log("res==",e),0===e.data.code&&(re(),ie()),r.Z.dispatch({type:i.Sn,val:e.data.result||""}),r.Z.dispatch({type:i.br,val:!1})})).catch((function(e){r.Z.dispatch({type:i.Sn,val:"请求错误"}),r.Z.dispatch({type:i.br,val:!1})}))}}}),a.createElement(w,{open:M,title:G,data:F,close:function(){B(!1)}}))})));var O=n(7577);const x=(0,s.$j)((function(e){return e}))((function(e){var t=(0,a.useState)(""),n=(0,c.Z)(t,2),l=n[0],s=n[1],o=(0,a.useState)(""),u=(0,c.Z)(o,2),d=u[0],p=u[1];(0,a.useEffect)((function(){h()}),[]);var h=function(){r.Z.dispatch({type:i.br,val:!0}),m()({method:"GET",url:"/api/cluster/mirror"}).then((function(e){0===e.data.code?s(e.data.result):r.Z.dispatch({type:i.Sn,val:e.data.result}),r.Z.dispatch({type:i.br,val:!1})})).catch((function(e){console.log(e),r.Z.dispatch({type:i.br,val:!1})}))};return a.createElement("div",{className:"page-container workload-container"},a.createElement("div",{className:"page-title"},a.createElement("p",null,"设置")),a.createElement("div",{className:"workload-content"},a.createElement("div",{className:"host-input"},a.createElement(O.Z,{change:function(e){p(""),s(e)},inputErr:d,value:l})),a.createElement("div",{className:"host-btn"},a.createElement(f.Z,{variant:"contained",color:"primary",className:"btn-item",onClick:function(){""!=l.trim()?(r.Z.dispatch({type:i.br,val:!0}),m()({method:"POST",url:"/api/cluster/mirror",headers:{"Content-Type":"application/json"},data:{mirror:l}}).then((function(e){r.Z.dispatch({type:i.Sn,val:e.data.result||""}),r.Z.dispatch({type:i.br,val:!1})})).catch((function(e){console.log(e),r.Z.dispatch({type:i.br,val:!1})}))):p("请输入")}},"保存"))))})),T=(0,s.$j)((function(e){return e}))((0,l.EN)((function(e){var t=(0,a.useState)(""),n=(0,c.Z)(t,2),l=n[0],s=n[1],o=(0,a.useState)([]),u=(0,c.Z)(o,2),d=u[0],p=u[1],h=(0,a.useState)(""),v=(0,c.Z)(h,2),E=v[0],y=v[1];(0,a.useEffect)((function(){j(),r.Z.dispatch({type:i.br,val:!0}),m()({method:"GET",url:"/api/cluster/addrs"}).then((function(e){0===e.data.code&&p(e.data.result),r.Z.dispatch({type:i.br,val:!1})})).catch((function(e){console.log(e),r.Z.dispatch({type:i.br,val:!1}),r.Z.dispatch({type:i.Sn,val:"请求错误"})}))}),[]);var j=function(){m()({method:"GET",url:"/api/cluster/domain"}).then((function(e){0===e.data.code&&(y(e.data.result),s(""))})).catch((function(e){console.log(e),r.Z.dispatch({type:i.Sn,val:"请求错误"})}))};return a.createElement("div",{className:"page-container  domain-container"},a.createElement("div",{className:"page-title"},"根域设置"),a.createElement("div",{className:"domain-desc"},a.createElement("p",{className:"desc-text"},"为此集群设置根域，集群会用根域的二级域名来设置应用的访问域名，请先配置域名范解析到 下列所列出的IP中一个或多个地址，再点击[检测并保存]按钮")),a.createElement("div",{className:"addr-list"},d&&Array.isArray(d)?d.map((function(e,t){return a.createElement("ul",{className:"addr-item",key:e.name},a.createElement("li",{className:"item-li"},e.name),e.addrs.map((function(e,t){return a.createElement("li",{className:"item-li",key:e},e)})))})):null),a.createElement("div",{className:"domain-input"},a.createElement(O.Z,{placeholder:"请输入根域",value:E,change:function(e){y(e),s("")},inputErr:l}),a.createElement(f.Z,{className:"input-btn",variant:"contained",color:"primary",onClick:function(){""!==E.trim()?(r.Z.dispatch({type:i.br,val:!0}),m()({method:"POST",url:"/api/cluster/domain",headers:{"Content-Type":"application/json"},data:{domain:E}}).then((function(e){r.Z.dispatch({type:i.Sn,val:e.data.result.message||""}),r.Z.dispatch({type:i.br,val:!1})})).catch((function(e){console.log("---err---",e),r.Z.dispatch({type:i.br,val:!1}),r.Z.dispatch({type:i.Sn,val:"请求错误"})}))):s("请输入")}},"检测并保存")))}))),_=(0,s.$j)((function(e){return e}))((0,l.EN)((function(e){var t=(0,a.useState)(""),n=(0,c.Z)(t,2),l=n[0],s=n[1],o=(0,a.useState)(""),u=(0,c.Z)(o,2),d=u[0],p=u[1],h=(0,a.useState)(""),v=(0,c.Z)(h,2),E=v[0],y=v[1],j=(0,a.useState)(""),b=(0,c.Z)(j,2),g=b[0],Z=b[1];return a.createElement("div",{className:"page-container reset-container"},a.createElement("div",{className:"page-title"},a.createElement("p",null,"密码设置")),a.createElement("div",{className:"input-item"},a.createElement(O.Z,{type:"password",label:"原密码：",value:l,placeholder:"请输入原密码",change:function(e){p(""),s(e)},inputErr:d})),a.createElement("div",{className:"input-item"},a.createElement(O.Z,{type:"password",label:"新密码：",value:E,placeholder:"请输入新密码",change:function(e){Z(""),y(e)},inputErr:g})),a.createElement("div",{className:"form-btn"},a.createElement(f.Z,{variant:"contained",className:"btn",color:"primary",onClick:function(){""!==l.trim()?""!==E.trim()?(console.log(l,"-----",E),r.Z.dispatch({type:i.br,val:!0}),m()({method:"POST",url:"/api/user/reset",data:{oldPassword:l,password:E}}).then((function(e){r.Z.dispatch({type:i.Sn,val:e.data.result||""}),r.Z.dispatch({type:i.br,val:!1}),0===e.data.code&&setTimeout((function(){sessionStorage.setItem("user",""),window.location.replace("/")}))})).catch((function(e){console.log("err===",e),r.Z.dispatch({type:i.br,val:!1})}))):Z("请输入新密码"):p("请输入原密码")}},"保存")))}))),A=function(e){var t=(0,l.k6)();return a.createElement("div",{className:"home-container"},a.createElement("div",{className:"content-left"},a.createElement(d,{change:function(e){t.push(e)}})),a.createElement("div",{className:"content-right"},a.createElement(l.rs,null,a.createElement(l.AW,{path:"/home/workload",component:x}),a.createElement(l.AW,{path:"/home/domain",component:T}),a.createElement(l.AW,{path:"/home/reset",component:_}),a.createElement(l.AW,{path:"/home",component:z}))),a.createElement(p.Z,null),a.createElement(h.Z,null))}},6700:(e,t,n)=>{var a={"./af":2786,"./af.js":2786,"./ar":867,"./ar-dz":4130,"./ar-dz.js":4130,"./ar-kw":6135,"./ar-kw.js":6135,"./ar-ly":6440,"./ar-ly.js":6440,"./ar-ma":7702,"./ar-ma.js":7702,"./ar-sa":6040,"./ar-sa.js":6040,"./ar-tn":7100,"./ar-tn.js":7100,"./ar.js":867,"./az":1083,"./az.js":1083,"./be":9808,"./be.js":9808,"./bg":8338,"./bg.js":8338,"./bm":7438,"./bm.js":7438,"./bn":8905,"./bn-bd":6225,"./bn-bd.js":6225,"./bn.js":8905,"./bo":1560,"./bo.js":1560,"./br":1278,"./br.js":1278,"./bs":622,"./bs.js":622,"./ca":2468,"./ca.js":2468,"./cs":5822,"./cs.js":5822,"./cv":877,"./cv.js":877,"./cy":7373,"./cy.js":7373,"./da":4780,"./da.js":4780,"./de":9740,"./de-at":217,"./de-at.js":217,"./de-ch":894,"./de-ch.js":894,"./de.js":9740,"./dv":5300,"./dv.js":5300,"./el":837,"./el.js":837,"./en-au":8348,"./en-au.js":8348,"./en-ca":7925,"./en-ca.js":7925,"./en-gb":2243,"./en-gb.js":2243,"./en-ie":6436,"./en-ie.js":6436,"./en-il":7207,"./en-il.js":7207,"./en-in":4175,"./en-in.js":4175,"./en-nz":6319,"./en-nz.js":6319,"./en-sg":1662,"./en-sg.js":1662,"./eo":2915,"./eo.js":2915,"./es":7093,"./es-do":5251,"./es-do.js":5251,"./es-mx":6112,"./es-mx.js":6112,"./es-us":1146,"./es-us.js":1146,"./es.js":7093,"./et":5603,"./et.js":5603,"./eu":7763,"./eu.js":7763,"./fa":6959,"./fa.js":6959,"./fi":1897,"./fi.js":1897,"./fil":2549,"./fil.js":2549,"./fo":4694,"./fo.js":4694,"./fr":4470,"./fr-ca":3049,"./fr-ca.js":3049,"./fr-ch":2330,"./fr-ch.js":2330,"./fr.js":4470,"./fy":5044,"./fy.js":5044,"./ga":9295,"./ga.js":9295,"./gd":2101,"./gd.js":2101,"./gl":8794,"./gl.js":8794,"./gom-deva":7884,"./gom-deva.js":7884,"./gom-latn":3168,"./gom-latn.js":3168,"./gu":5349,"./gu.js":5349,"./he":4206,"./he.js":4206,"./hi":94,"./hi.js":94,"./hr":316,"./hr.js":316,"./hu":2138,"./hu.js":2138,"./hy-am":1423,"./hy-am.js":1423,"./id":9218,"./id.js":9218,"./is":135,"./is.js":135,"./it":7060,"./it-ch":150,"./it-ch.js":150,"./it.js":7060,"./ja":9183,"./ja.js":9183,"./jv":4286,"./jv.js":4286,"./ka":2105,"./ka.js":2105,"./kk":7772,"./kk.js":7772,"./km":8758,"./km.js":8758,"./kn":9282,"./kn.js":9282,"./ko":3730,"./ko.js":3730,"./ku":1408,"./ku.js":1408,"./ky":9787,"./ky.js":9787,"./lb":6841,"./lb.js":6841,"./lo":5466,"./lo.js":5466,"./lt":7010,"./lt.js":7010,"./lv":7595,"./lv.js":7595,"./me":9861,"./me.js":9861,"./mi":5493,"./mi.js":5493,"./mk":5966,"./mk.js":5966,"./ml":7341,"./ml.js":7341,"./mn":5115,"./mn.js":5115,"./mr":370,"./mr.js":370,"./ms":9847,"./ms-my":1237,"./ms-my.js":1237,"./ms.js":9847,"./mt":2126,"./mt.js":2126,"./my":6165,"./my.js":6165,"./nb":4924,"./nb.js":4924,"./ne":6744,"./ne.js":6744,"./nl":3901,"./nl-be":9814,"./nl-be.js":9814,"./nl.js":3901,"./nn":3877,"./nn.js":3877,"./oc-lnc":2135,"./oc-lnc.js":2135,"./pa-in":5858,"./pa-in.js":5858,"./pl":4495,"./pl.js":4495,"./pt":9520,"./pt-br":7971,"./pt-br.js":7971,"./pt.js":9520,"./ro":6459,"./ro.js":6459,"./ru":238,"./ru.js":238,"./sd":950,"./sd.js":950,"./se":490,"./se.js":490,"./si":6994,"./si.js":6994,"./sk":4249,"./sk.js":4249,"./sl":4985,"./sl.js":4985,"./sq":1104,"./sq.js":1104,"./sr":9131,"./sr-cyrl":9915,"./sr-cyrl.js":9915,"./sr.js":9131,"./ss":5893,"./ss.js":5893,"./sv":8760,"./sv.js":8760,"./sw":1172,"./sw.js":1172,"./ta":7333,"./ta.js":7333,"./te":3110,"./te.js":3110,"./tet":2095,"./tet.js":2095,"./tg":7321,"./tg.js":7321,"./th":9041,"./th.js":9041,"./tk":9005,"./tk.js":9005,"./tl-ph":5768,"./tl-ph.js":5768,"./tlh":9444,"./tlh.js":9444,"./tr":2397,"./tr.js":2397,"./tzl":8254,"./tzl.js":8254,"./tzm":1106,"./tzm-latn":699,"./tzm-latn.js":699,"./tzm.js":1106,"./ug-cn":9288,"./ug-cn.js":9288,"./uk":7691,"./uk.js":7691,"./ur":3795,"./ur.js":3795,"./uz":6791,"./uz-latn":588,"./uz-latn.js":588,"./uz.js":6791,"./vi":5666,"./vi.js":5666,"./x-pseudo":4378,"./x-pseudo.js":4378,"./yo":5805,"./yo.js":5805,"./zh-cn":3839,"./zh-cn.js":3839,"./zh-hk":5726,"./zh-hk.js":5726,"./zh-mo":9807,"./zh-mo.js":9807,"./zh-tw":4152,"./zh-tw.js":4152};function c(e){var t=l(e);return n(t)}function l(e){if(!n.o(a,e)){var t=new Error("Cannot find module '"+e+"'");throw t.code="MODULE_NOT_FOUND",t}return a[e]}c.keys=function(){return Object.keys(a)},c.resolve=l,e.exports=c,c.id=6700}}]);