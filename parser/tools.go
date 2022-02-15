package parser

import (
	"crab/aam/v1alpha1"
	"cuelang.org/go/cue"
	"cuelang.org/go/cue/cuecontext"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gojek/heimdall/v7/httpclient"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"k8s.io/klog/v2"
	"net"
	"net/url"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var HTTPClient = httpclient.NewClient(httpclient.WithHTTPTimeout(time.Second * 30))

//由manifest.yaml生成vale.yaml
func GenValeYaml(instanceId string, application v1alpha1.Application, userconfigs string, host string, dependencies Dependency) (VelaYaml, Error) {
	var vela = VelaYaml{"", make(map[string]interface{}, 0)}
	vela.Name = application.Metadata.Name

	authorization, serviceEntry, err := parseDependencies(application, dependencies)
	if err.Err != nil {
		return vela, err
	}
	//应用内部的授权
	//为每个 service 创建一个 authorization，授权当前应用下的其他服务有访问的权限
	for _, workload := range application.Spec.Workloads {
		authorization = append(authorization,
			Authorization{
				Namespace: instanceId,
				Service:   workload.Name,
				Resources: make([]DependencyUseItem, 0),
			},
		)
	}
	//依赖内部应用的host
	dependHost := make(dependencyHost, 0)
	for _, v := range dependencies.Internal {

		//解析依赖items
		resources := make([]DependencyUseItem, 0)
		for _, depend := range application.Spec.Dependencies {
			if strings.HasPrefix(depend.Location, "user-defined(") && strings.HasSuffix(depend.Location, ")"){
				location := depend.Location[len("user-defined("): len(depend.Location)-1]
				arr, err := url.ParseRequestURI(location)
				if err != nil {
					err = errors.New("dependencies.location解析失败 " +err.Error())
					klog.Errorln(err.Error())
					return vela, Error{err, ErrBadRequest}
				}
				if strings.ToLower(arr.Scheme) == "tcp" {
					fmt.Println("内部 tcp service:", v.EntryService)
					v.EntryService = location[len("tcp://"):]
					depend.Items = make(map[string][]string, 0)
				}
			}
			ItemsResult, err := ApiParse(depend.Items)
			if depend.Name == v.Name {
				if err.Err != nil {
					klog.Errorln(err.Error())
					return vela, err
				}
				for _, item := range ItemsResult{
					resources = append(resources, DependencyUseItem{item.Uri, item.Actions})
				}
			}
			//host
			dependHost[v.Name] = dependencyHostItem{
				fmt.Sprintf("%s.%s.svc.cluster.local", v.EntryService, v.Instanceid),
			}
		}
		//授权
		authorization = append(authorization,
			Authorization{
				Namespace: v.Instanceid,
				Service:   v.EntryService,
				Resources: resources,
			},
		)
	}
	for _, workload := range application.Spec.Workloads {
		properties := GetProperties(workload.Properties)
		properties["authorization"] = authorization
		properties["serviceEntry"] = serviceEntry
		properties["userconfigs"] = userconfigs
		properties["dependencies"] = dependHost
		//整合trait参数
		if len(workload.Traits) > 0 {
			for _, trait := range workload.Traits {
				if trait.Type == "ingress" {
					ingressProperties := GetProperties(trait.Properties)
					ingressProperties["host"] = host
					ingressProperties["path"] = []string{"/*"}
					properties[trait.Type] = ingressProperties
				} else {
					properties[trait.Type] = GetProperties(trait.Properties)
				}
			}
		}
		vela.Services[workload.Name] = properties
	}
	return vela, Error{}
}

//由vale.yaml生成k8s
func GenK8sYaml(instanceId string, vela VelaYaml, workloadParam map[string]WorkloadParam) (string, Error) {
	finalContext := ""
	//自动追加的部分
	//处理workload
	for k, v := range vela.Services {
		ctx := ContextObj{
			vela.Name,
			k,
			instanceId,
		}
		k8sStr, err := Export(ctx, workloadParam[k], v)
		if err.Err != nil {
			return "", err
		}
		finalContext += k8sStr + "\n---\n"
	}
	finalContext = strings.Trim(strings.TrimSpace(finalContext), "---")
	finalContext = fmt.Sprintf("# appName: %s\n%s", vela.Name, finalContext)
	return finalContext, Error{}
}

func Export(ctxObj ContextObj, workloadParam WorkloadParam, workload interface{}) (string, Error) {
	var k8s = ""
	template := workloadParam.VendorCue
	ctxData := make(map[string]interface{}, 0)
	ctxData["context"] = ctxObj
	ctxObjData, err := json.Marshal(ctxData)
	if err != nil {
		klog.Errorln("ctxObj 序列化失败: ", err.Error())
		return "", Error{errors.New("ctxObj 序列化失败"), ErrInternalServer}
	}
	serviceData, err := json.Marshal(workload)
	if err != nil {
		klog.Errorln("vela.Services 序列化失败: ", err.Error())
		return "", Error{errors.New("vela.Services 序列化失败"), ErrInternalServer}
	}
	cueStr := fmt.Sprintf("%s\nparameter:%s\n%s", ctxObjData, serviceData, template)
	err = ioutil.WriteFile(fmt.Sprintf("/tmp/%s-%s.cue", ctxObj.Namespace, ctxObj.WorkloadName), []byte(cueStr), 0644)
	if err != nil {
		klog.Errorln("保存cue文件错误: ", err.Error())
		return "", Error{errors.New("保存cue文件错误"), ErrInternalServer}
	}
	//处理cue内置的pkg
	cueStr = MoveCuePkgToTop(cueStr)
	var ctx *cue.Context
	var value cue.Value
	ctx = cuecontext.New()
	value = ctx.CompileString(cueStr)
	if value.Err() != nil {
		err := fmt.Errorf("cue生成yaml失败 %s", value.Err().Error())
		klog.Errorln(err.Error())
		return "", Error{err, ErrInternalServer}
	}
	context := make(map[string]interface{}, 0)
	err = value.Decode(&context)
	for k,v := range context {
		if k != "context" && k != "parameter" {
			b, err := yaml.Marshal(v)
			if err != nil {
				klog.Errorln("解析CUE失败: ", err)
				return "", Error{err, ErrInternalServer}
			}
			if k == "namespace" {
				k8s = fmt.Sprintf("%s\n---\n%s", string(b), k8s)
			}else{
				k8s = fmt.Sprintf("%s\n---\n%s", k8s, string(b))
			}
		}
	}
	return strings.TrimSpace(k8s), Error{}
}

//处理依赖
func parseDependencies(application v1alpha1.Application, dependencies Dependency) ([]Authorization, []ServiceEntry, Error) {
	auth := make([]Authorization, 0)
	//外部服务调用
	svcEntry := make([]ServiceEntry, 0)
	//检查是否有全部的访问权限all
	//isAllowAll := false
	//for _, item := range dependencies.External {
	//	if strings.ToLower(strings.TrimSpace(item.Location)) == "*" {
	//		isAllowAll = true
	//	}
	//}
	fmt.Println(strings.Contains(application.Metadata.Version, "+dev"))
	if strings.Contains(application.Metadata.Version, "+dev") { //开放所有外部访问
		svcEntry = append(svcEntry, ServiceEntry{"com-http", "", "*.com", 80, "HTTP"})
		svcEntry = append(svcEntry, ServiceEntry{"com-https", "", "*.com", 443, "TLS"})
		svcEntry = append(svcEntry, ServiceEntry{"cn-http", "", "*.cn", 80, "HTTP"})
		svcEntry = append(svcEntry, ServiceEntry{"cn-https", "", "*.cn", 443, "TLS"})
		svcEntry = append(svcEntry, ServiceEntry{"org-http", "", "*.org", 80, "HTTP"})
		svcEntry = append(svcEntry, ServiceEntry{"org-https", "", "*.org", 443, "TLS"})
		svcEntry = append(svcEntry, ServiceEntry{"net-http", "", "*.net", 80, "HTTP"})
		svcEntry = append(svcEntry, ServiceEntry{"net-https", "", "*.net", 443, "TLS"})
		svcEntry = append(svcEntry, ServiceEntry{"edu-http", "", "*.edu", 80, "HTTP"})
		svcEntry = append(svcEntry, ServiceEntry{"edu-https", "", "*.edu", 443, "TLS"})
		svcEntry = append(svcEntry, ServiceEntry{"gov-http", "", "*.gov", 80, "HTTP"})
		svcEntry = append(svcEntry, ServiceEntry{"gov-https", "", "*.gov", 443, "TLS"})
		svcEntry = append(svcEntry, ServiceEntry{"ssh", "", "ssh", 22, "tcp"})
	}

	for _, item := range dependencies.External {
		var host, address string
		arr, err := url.ParseRequestURI(item.Location)
		if err != nil {
			klog.Errorln("dependencies.location解析失败", err.Error())
			return auth, svcEntry, Error{err, ErrBadRequest}
		}
		var protocol string
		if arr.Scheme == "https" {
			protocol = "TLS"
		} else if arr.Scheme == "http" {
			protocol = "HTTP"
		} else if strings.ToLower(arr.Scheme) == "tcp" {
			protocol = "TCP"
		} else {
			err = fmt.Errorf("location不支持协议: %s", arr.Scheme)
			klog.Errorln(err.Error())
			return auth, svcEntry, Error{err, ErrBadRequest}
		}
		hostArr := strings.Split(arr.Host, ":")
		var port int
		if len(hostArr) == 1 { //没有指定端口号
			if protocol == "http" {
				port = 80
			} else {
				port = 443
			}
		} else { //指定端口号
			port, err = strconv.Atoi(hostArr[1])
			if err != nil {
				err2 := fmt.Errorf("端口号错误 Error: %s", hostArr[1])
				return auth, svcEntry, Error{err2, ErrBadRequest}
			}
		}
		ipAddress := net.ParseIP(hostArr[0])
		if ipAddress != nil { //ip
			host = fmt.Sprintf("serviceEntry-%s-%s", application.Metadata.Name, item.Name)
			address = ipAddress.String()
		} else {
			host = arr.Host
		}
		svcEntry = append(svcEntry, ServiceEntry{item.Name, address, host, port, protocol})
	}

	return auth, svcEntry, Error{}
}

//获取WorkloadType
func GetWorkloadType(typeName string) (v1alpha1.WorkloadType, Error) {
	var t v1alpha1.WorkloadType
	value, err := GetWorkloadDef("workloadType", typeName)
	if err.Err != nil {
		klog.Errorln("获取workloadType失败 Error:", err.Error())
		return t, err
	}
	err2 := yaml.Unmarshal([]byte(value), &t)
	if err2 != nil {
		klog.Errorln("workloadType反序列化失败 Error:", err.Error())
		return t, Error{fmt.Errorf("解析workloadType:%s失败", typeName), ErrInternalServer}
	}
	return t, Error{}
}

//获取trait
func GetTrait(name string) (v1alpha1.Trait, Error) {
	var t v1alpha1.Trait
	value, err := GetWorkloadDef("trait", name)
	if err.Err != nil {
		klog.Errorln("获取trait失败 Error:", err.Error())
		return t, err
	}
	//解析为结构体
	err2 := yaml.Unmarshal([]byte(value), &t)
	if err2 != nil {
		klog.Errorln("trait反序列化失败 Error:", err.Error())
		return t, Error{fmt.Errorf("解析trait: %s失败", name), ErrInternalServer}
	}
	return t, Error{}
}

//获取WorkloadVendor
func GetWorkloadVendor(name string) (v1alpha1.WorkloadVendor, Error) {
	var v v1alpha1.WorkloadVendor
	value, err := GetWorkloadDef("workloadVendor", name)
	if err.Err != nil {
		klog.Errorln("获取workloadVendor失败 Error:", err.Error())
		return v, err
	}
	err2 := yaml.Unmarshal([]byte(value), &v)
	if err2 != nil {
		klog.Errorln("workloadVendor反序列化失败 %s Error", err.Error())
		return v, Error{fmt.Errorf("workloadVendor反序列化失败 %s", name), ErrInternalServer}
	}
	return v, err
	//path := fmt.Sprintf("%s%s.yaml", workloadPath, vendorName)
	//content, err := ioutil.ReadFile(path)
	//if err != nil {
	//	err = errors.New(fmt.Sprintf("workload.vendor: %s 不存在\n", path))
	//	return v, err
	//}
	//err = yaml.Unmarshal(content, &v)
	//cuefile := v.Spec
	//替换import为真实内容
	//re, _ := regexp.Compile("import\\s*\"([^\"]*)\"")
	//matchResult := re.FindAllStringSubmatch(cuefile, -1)
	//for _, vv := range matchResult {
	//	if len(matchResult) > 0 {
	//		if _, ok := cuePkg[vv[1]]; ok {
	//			continue
	//		}
	//		includeMod, err := modTemplate(workloadPath, vendorName, vv[1])
	//		if err != nil {
	//			klog.Errorln(err.Error())
	//			return v, err
	//		}
	//		cuefile = strings.ReplaceAll(cuefile, vv[0], includeMod)
	//	}
	//}
	//v.Spec = cuefile
}

//获取cue模板
func modTemplate(workloadPath, vendorDir, mod string) (string, error) {
	var err error
	pos := strings.LastIndex(vendorDir, "/")
	path := fmt.Sprintf("%s%s%s.cue", workloadPath, vendorDir[:pos+1], mod)
	if !FileExist(path) {
		return "", errors.New(fmt.Sprintf("文件：%s 不存在", path))
	}
	t, err := ioutil.ReadFile(path)
	if err != nil {
		klog.Errorln(err.Error())
		return "", err
	}
	content := string(t)
	//替换import为真实内容
	re, _ := regexp.Compile("import\\s*\"([^\"]*)\"")
	matchResult := re.FindAllStringSubmatch(content, -1)
	for _, v := range matchResult {
		if len(matchResult) > 0 {
			if _, ok := cuePkg[v[1]]; ok {
				continue
			}
			includeMod, err := modTemplate(workloadPath, vendorDir, v[1])
			if err != nil {
				klog.Errorln(err.Error())
				return "", err
			}
			content = strings.ReplaceAll(content, v[0], includeMod)
		}
	}
	return content, nil
}

//解析数据
func GetValue(v interface{}) interface{} {
	vType := reflect.TypeOf(v)
	if vType.Kind() == reflect.String {
		after := v.(string)
		return after
	} else if vType.Kind() == reflect.Int {
		after := v.(int)
		return after
	} else if vType.Kind() == reflect.Slice {
		var after []interface{}
		for _, item := range v.([]interface{}) {
			itemValue := GetValue(item)
			after = append(after, itemValue)
		}
		return after
	} else if vType.Kind() == reflect.Struct {
		//todo
		var after interface{}
		return after
	} else if vType.Kind() == reflect.Map {
		after := make(map[string]interface{}, 0)
		for key, val := range v.(map[interface{}]interface{}) {
			newKey := fmt.Sprintf("%s", key)
			newValue := GetValue(val)
			after[newKey] = newValue
		}
		return after
	}
	//todo
	klog.Errorln("其他类型")
	return nil
}

//cue内置的pkg，放到cue文件第一行
func MoveCuePkgToTop(str string) string {
	pkg := make([]string, 0)
	re, _ := regexp.Compile("import\\s*\"([^\"]*)\"")
	matchResult := re.FindAllStringSubmatch(str, -1)
	for _, v := range matchResult {
		if len(matchResult) > 0 {
			if _, ok := cuePkg[v[1]]; ok {
				pkg = append(pkg, v[0])
				str = strings.ReplaceAll(str, v[0], "")
			}
		}
	}
	return strings.Join(pkg, "\n") + "\n" + str
}

func ApiParse(items map[string][]string) ([]DependencyUseItem, Error) {
	rtn := make([]DependencyUseItem, 0)
	for k, v := range items {
		count := 0
		actions := make([]string, 0)
		for _, option := range v {
			if option == "create" {
				actions = append(actions, "POST")
			} else if option == "read" {
				actions = append(actions, "GET", "HEAD", "OPTIONS")
			} else if option == "update" {
				actions = append(actions, "PUT", "PATCH")
			} else if option == "delete" {
				actions = append(actions, "DELETE")
			} else {
				err := fmt.Errorf("依赖资源的操作类型(%s)不存在\n", option)
				klog.Errorln(err.Error())
				return rtn, Error{err, ErrBadRequest}
			}
			count++
		}
		if count == 0 {
			err := errors.New("依赖资源的操作类型不能为空")
			return rtn, Error{err, ErrBadRequest}
		}
		rtn = append(rtn, DependencyUseItem{k, actions})
	}
	return rtn, Error{}
}

//校验trait参数
func CheckTraitParam(workloadTrait Trait) Error {
	properties := GetProperties(workloadTrait.Properties)
	properties2, err := json.Marshal(properties)
	if err != nil {
		klog.Errorln(err)
		return Error{errors.New("trait参数序列化失败"), ErrInternalServer}
	}
	file, err2 := GetTrait(workloadTrait.Type)
	if err2.Err != nil {
		klog.Errorln(err2)
		return err2
	}
	cueStr := fmt.Sprintf("parameter:%s\nparameter: {\n%s\n}", string(properties2), file.Spec.Parameter)
	var ctx *cue.Context
	var value cue.Value
	ctx = cuecontext.New()
	value = ctx.CompileString(cueStr)
	err = value.Validate(cue.Concrete(true))
	if err != nil {
		klog.Errorln(err)
		return Error{err, ErrInternalServer}
	}
	return Error{}
}

//校验type参数
func CheckTypeParam(workload v1alpha1.Workload) Error {
	var t v1alpha1.WorkloadType
	properties := GetProperties(workload.Properties)
	t, err := GetWorkloadType(workload.Type)
	if err.Err != nil {
		klog.Errorln(err.Error())
		return err
	}
	properties2, err2 := json.Marshal(properties)
	if err2 != nil {
		klog.Errorln(err2.Error())
		return Error{err2, ErrInternalServer}
	}
	parameterStr := fmt.Sprintf("parameter:{ \n%s\n}\nparameter:{\n%s\n}", t.Spec.Parameter, string(properties2))
	var ctx *cue.Context
	var value cue.Value
	ctx = cuecontext.New()
	value = ctx.CompileString(parameterStr)
	validateErr := value.Validate(cue.Concrete(true))
	if validateErr != nil {
		klog.Errorln(validateErr.Error())
		return Error{validateErr,ErrInternalServer}
	}
	return Error{}
}

func CheckParams(application v1alpha1.Application) (map[string]WorkloadParam, Error) {
	returnData := make(map[string]WorkloadParam, 0)
	if len(application.Spec.Workloads) == 0 {
		klog.Errorln("spec.workloads 不能为空")
		return returnData, Error{errors.New("spec.workloads 不能为空"), ErrBadRequest}
	}
	ingressCount := 0
	for _, workload := range application.Spec.Workloads {
		if workload.Name == "" {
			klog.Errorln("spec.workloads.name 不能为空")
			return returnData, Error{errors.New("spec.workloads.name 不能为空"), ErrBadRequest}
		}
		if workload.Type == "" {
			klog.Errorln("spec.workloads.type 不能为空")
			return returnData, Error{errors.New("spec.workloads.type 不能为空"), ErrBadRequest}
		}
		if workload.Vendor == "" {
			klog.Errorln("spec.workloads.vendor 不能为空")
			return returnData, Error{errors.New("spec.workloads.vendor 不能为空"), ErrBadRequest}
		}
		//检查type参数
		err := CheckTypeParam(workload)
		if err.Err != nil {
			klog.Errorln("检查type参数 Error:", err)
			return returnData, err
		}
		workloadType, err := GetWorkloadType(workload.Type)
		if err.Err != nil {
			return returnData, err
		}
		//检查trait参数
		if len(workload.Traits) > 0 {
			for _, trait := range workload.Traits {
				//检查workloadType是否支持trait
				exist := false
				for _, typeTrait := range workloadType.Spec.Traits{
					if trait.Type == typeTrait {
						exist = true
					}
				}
				if exist == false {
					err := fmt.Errorf("workloadType:%s不支持trait:%s", workload.Type, trait.Type)
					klog.Errorln(err.Error())
					return returnData, Error{err, ErrInternalServer}
				}
				err = CheckTraitParam(trait)
				if err.Err != nil {
					klog.Errorln("检查trait参数 Error:", err)
					return returnData, err
				}
				if trait.Type == "ingress" {
					ingressCount++
				}
			}
		}
		var workloadParams WorkloadParam
		workloadParams.Type = workload.Type
		workloadParams.Vendor = workload.Vendor

		properties := GetProperties(workload.Properties)
		workloadParams.Parameter = properties

		t, _ := GetWorkloadType(workload.Type)
		workloadParams.Traits = t.Spec.Traits

		var v v1alpha1.WorkloadVendor
		v, err = GetWorkloadVendor(workload.Vendor)
		if err.Err != nil {
			klog.Errorln(err.Error())
			return returnData, err
		}
		workloadParams.VendorCue = v.Spec
		returnData[workload.Name] = workloadParams
	}
	//trait:ingress最多一个
	if ingressCount > 1 {
		err := errors.New("不能有多个ingress")
		return returnData, Error{err, ErrInternalServer}
	}
	return returnData, Error{}
}
func GetProperties(properties map[string]interface{}) map[string]interface{} {
	ret := make(map[string]interface{}, 0)
	for k, v := range properties {
		ret[k] = GetValue(v)
	}
	return ret
}

func FileExist(path string) bool {
	_, err := os.Lstat(path)
	return !os.IsNotExist(err)
}

//获取workload定义
func GetWorkloadDef(kind, name string) (string, Error) {
	type def struct {
		Id         int `json:"id"`
		Name       string `json:"name"`
		ApiVersion string `json:"apiVersion"`
		Value      string `json:"value"`
		Type       int `json:"type"`
	}
	var err error
	kind = strings.TrimSpace(kind)
	if kind == "" {
		klog.Errorln("kind不能为空")
		return "", Error{errors.New("kind不能为空"), ErrInternalServer}
	}
	name = strings.TrimSpace(name)
	if name == "" {
		klog.Errorln("名称不能为空")
		return "", Error{errors.New("名称不能为空"), ErrBadRequest}
	}
	res, err := HTTPClient.Get(fmt.Sprintf("http://127.0.0.1:3000/%s/%s", kind, name), nil)
	if err != nil {
		klog.Errorln("请求api失败", err.Error())
		return "", Error{errors.New(err.Error()), ErrBadRequest}
	}
	bodyBytes, err := ioutil.ReadAll(res.Body)
	if err != nil {
		klog.Errorln("读取响应内容失败", err.Error())
		return "", Error{fmt.Errorf("读取响应内容失败 %w", err), ErrInternalServer}
	}
	var reply struct {
		Code   int `json:"code"`
		Result def `json:"result"`
	}
	err = json.Unmarshal(bodyBytes, &reply)
	if err != nil {
		klog.Errorln("响应内容反序列化失败", err.Error())
		return "", Error{fmt.Errorf("反序列化失败: %w", err), ErrInternalServer}
	}
	if reply.Code != 0 {
		klog.Errorln("请求api错误", reply.Result)
		return "", Error{fmt.Errorf("请求api错误: %v", reply.Result),ErrInternalServer}
	}
	return reply.Result.Value, Error{}
}