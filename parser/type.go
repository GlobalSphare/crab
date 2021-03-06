package parser

import "crab/aam/v1alpha1"

type ContextObj struct {
	AppName      string `json:"appName"`
	WorkloadName string `json:"workloadName"`
	Namespace    string `json:"namespace"`
}
type Dependency struct {
	Internal []InternalDependency `json:"Internal"`
	External []ExternalDependency `json:"External"`
}
type InternalDependency struct {
	Name         string `json:"Name"`
	Instanceid   string `json:"InstanceId"`
	EntryService string `json:"EntryService"`
}
type ExternalDependency struct {
	Name     string `json:"Name"`
	Location string `json:"Location"`
}

//验证type,vendor返回的数据
type WorkloadParam struct {
	Parameter map[string]interface{} `json:"parameter"`
	Type      string                 `json:"type"`
	Vendor    string                 `json:"vendor"`
	VendorCue string                 `json:"vendorCue"`
	Traits    []string               `json:"traits"`
}
type VelaYaml struct {
	Name     string                 `json:"name"`
	Services map[string]interface{} `json:"services"`
}

//返回的中间格式
type ParserData struct {
	Name      string              `yaml:"name"`
	Init      string              `yaml:"init"`
	Workloads map[string]Workload `yaml:"workloads"`
}
type Workload struct {
	Parameter string            `yaml:"parameter"`
	Construct map[string]string `yaml:"construct"`
	Traits    map[string]string `yaml:"traits"`
}
type ConfigItem struct {
	Path    string               `yaml:"path" json:"path"`
	SubPath string               `yaml:"subPath" json:"subPath,omitempty"`
	Data    []ConfigItemDataItem `yaml:"data" json:"data"`
}
type ConfigItemDataItem struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}
type Storage struct {
	Capacity string `yaml:"capacity" json:"capacity"`
	Path     string `yaml:"path" json:"path"`
}

//内部应用授权
type Authorization struct {
	Namespace string              `json:"namespace"`
	Service   string              `json:"service"`
	Resources []DependencyUseItem `json:"resources,omitempty"`
}

//外部应用授权
type ServiceEntry struct {
	Name     string `json:"name"`
	Address  string `json:"address,omitempty"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
}

//解析后的依赖use
type DependencyUseItem struct {
	Uri     string   `json:"uri"`
	Actions []string `json:"actions"`
}
type EnvItem struct {
	Name      string `json:"name"`
	Value     string `json:"value"`
	valueFrom map[string]struct {
		Name string `json:"name"`
		Key  string `json:"key"`
	}
}
type Entry struct {
	Host string   `json:"host"`
	Path []string `json:"path"`
}
type DependencyVela struct {
	Instanceid   string              `json:"instanceid"`
	Name         string              `json:"name"`
	Location     string              `json:"location"`
	EntryService string              `json:"entryservice"`
	Resource     []DependencyUseItem `json:"resource"`
}
type Trait struct {
	Type       string              `yaml:"type"`
	Properties v1alpha1.Properties `yaml:"properties"`
}

const (
	//参数错误
	ErrBadRequest     = 20101
	//内部错误
	ErrInternalServer = 20102
)

var cuePkg = map[string]bool{
	"crypto/hmac":     true,
	"crypto/md5":      true,
	"crypto/sha1":     true,
	"crypto/sha256":   true,
	"crypto/sha512":   true,
	"encoding/base64": true,
	"encoding/csv":    true,
	"encoding/hex":    true,
	"encoding/json":   true,
	"encoding/yaml":   true,
	"encoding/html":   true,
	"list":            true,
	"math":            true,
	"math/bits":       true,
	"net":             true,
	"path":            true,
	"regexp":          true,
	"strconv":         true,
	"strings":         true,
	"text/tabwriter":  true,
	"text/template":   true,
	"time":            true,
	"tool":            true,
	"tool/cli":        true,
	"tool/exec":       true,
	"tool/file":       true,
	"tool/http":       true,
	"tool/os":         true,
	"tool/uuid":       true,
}

//依赖内部应用的host
type dependencyHostItem struct {
	Host string `json:"host"`
}
type dependencyHost map[string]dependencyHostItem