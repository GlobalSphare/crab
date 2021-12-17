package workloadVendor

import (
	"crab/aam/v1alpha1"
	"crab/db"
	"crab/utils"
	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v3"
	"k8s.io/klog/v2"
	"strconv"
)

type Pagination struct {
	Total int64         `json:"total"`
	Rows  interface{} `json:"rows"`
}

func GetVendorsHandlerFunc(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "10"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	var vendors []WorkloadVendor
	var total int64
	err := db.Client.Limit(limit).Offset(offset).Find(&vendors).Error
	if err != nil {
		klog.Errorln("数据库查询错误:", err.Error())
		c.JSON(200, utils.ErrorResponse(utils.ErrDatabaseInternalServer, "数据库查询错误"))
		return
	}
	err = db.Client.Model(&WorkloadVendor{}).Count(&total).Error
	if err != nil {
		klog.Errorln("数据库查询错误:", err.Error())
		c.JSON(200, utils.ErrorResponse(utils.ErrDatabaseInternalServer, "数据库查询错误"))
		return
	}
	c.JSON(200, utils.SuccessResponse(Pagination{
		Total: total,
		Rows:  vendors,
	}))
}

func GetVendorHandlerFunc(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		c.JSON(200, utils.ErrorResponse(utils.ErrBadRequest, "参数错误"))
		return
	}
	var val WorkloadVendor
	err := db.Client.Where("id = ?", id).Find(&val).Error
	if err != nil {
		klog.Errorln("数据库查询错误:", err.Error())
		c.JSON(200, utils.ErrorResponse(utils.ErrDatabaseBadRequest, "该资源不存在"))
		return
	}
	if val.Id == 0 {
		err = db.Client.Where("name = ?", id).Find(&val).Error
		if err != nil {
			klog.Errorln("数据库查询错误:", err.Error())
			c.JSON(200, utils.ErrorResponse(utils.ErrDatabaseBadRequest, "该资源不存在"))
			return
		}
	}
	c.JSON(200, utils.SuccessResponse(val))
}

func PostVendorHandlerFunc(c *gin.Context) {
	var param struct {
		Value string `json:"value"`
	}
	err := c.ShouldBindJSON(&param)
	if err != nil {
		klog.Errorln("参数错误", err.Error())
		c.JSON(200, utils.ErrorResponse(utils.ErrBadRequest, "参数错误"))
		return
	}
	var val v1alpha1.WorkloadVendor
	err = yaml.Unmarshal([]byte(param.Value), &val)
	if err != nil {
		klog.Errorln("反序列化错误", err.Error())
		c.JSON(200, utils.ErrorResponse(utils.ErrBadRequest, "参数错误"))
		return
	}
	err = db.Client.Model(WorkloadVendor{}).Create(&WorkloadVendor{
		Name:      val.Metadata.Name,
		Ver:       val.ApiVersion,
		Value:     param.Value,
		Type:      1,
	}).Error
	if err != nil {
		klog.Errorln("保存到数据库错误", err.Error())
		c.JSON(200, utils.ErrorResponse(utils.ErrBadRequest, "保存到数据库错误"))
		return
	}
	c.JSON(200, utils.SuccessResponse("创建成功"))
	return
}
func PutVendorHandlerFunc(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	if id == 0 {
		c.JSON(200, utils.ErrorResponse(utils.ErrBadRequest, "参数错误"))
		return
	}
	var param struct {
		Value string `json:"value"`
	}
	err := c.ShouldBindJSON(&param)
	if err != nil {
		klog.Errorln("参数错误", err.Error())
		c.JSON(200, utils.ErrorResponse(utils.ErrBadRequest, "参数错误"))
		return
	}
	var val v1alpha1.WorkloadVendor
	err = yaml.Unmarshal([]byte(param.Value), &val)
	if err != nil {
		klog.Errorln("反序列化错误", err.Error())
		c.JSON(200, utils.ErrorResponse(utils.ErrBadRequest, "参数错误"))
		return
	}
	err = db.Client.Model(WorkloadVendor{Id: int64(id)}).Updates(WorkloadVendor{
		Name:      val.Metadata.Name,
		Ver:       val.ApiVersion,
		Value:     param.Value,
		Type:      1,
	}).Error
	if err != nil {
		klog.Errorln("保存到数据库错误", err.Error())
		c.JSON(200, utils.ErrorResponse(utils.ErrBadRequest, "保存到数据库错误"))
		return
	}
	c.JSON(200, utils.SuccessResponse("修改成功"))
	return
}

func DeleteVendorHandlerFunc(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		c.JSON(200, utils.ErrorResponse(utils.ErrBadRequest, "参数错误"))
		return
	}
	// todo 不能删除内置
	err := db.Client.Delete(&WorkloadVendor{}, id).Error
	if err != nil {
		klog.Errorln("删除错误", err.Error())
		c.JSON(200, utils.ErrorResponse(utils.ErrBadRequest, "删除错误"))
		return
	}
	c.JSON(200, utils.SuccessResponse("删除完成"))
}
