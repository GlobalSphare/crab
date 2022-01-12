import React, { useState, useEffect, useRef } from 'react'
import { connect } from 'react-redux'
import { withRouter } from 'react-router-dom'
import store from '../../store/store'
import * as TYPE from '../../store/actions'
import Button from '@material-ui/core/Button'
import Popover from '@material-ui/core/Popover'
import MenuList from '@material-ui/core/MenuList'
import MenuItem from '@material-ui/core/MenuItem'
import Pagination from '@material-ui/lab/Pagination'
import '../../style/sass/manager.scss'
import moment from 'moment'

import AddFile from '../../components/AddFile'
import ReadLog from '../../components/ReadLog'
import axios from 'axios'
import copy from 'copy-to-clipboard'
import Input from '../../components/Input'

const testConfigData = {
    "id": "ins1635146904",
    "dependencies": {
      "github": {
        "instances": [
          {
            "id": "ins1634971790",
            "name": "github"
          }
        ],
        "location": "https://www.github.com",
        "type": "immutable"
      }
    },
    "userconfigs": {
      "properties": {
        "param1": {
          "type": "integer"
        },
        "param2": {
          "type": "string"
        },
        "param3": {
          "properties": {
            "param3_1": {
              "type": "number"
            },
            "param3_2": {
              "type": "number"
            }
          },
          "required": [
            "param3_1"
          ],
          "type": "object"
        },
        "param4": {
          "items": {
            "type": "string"
          },
          "minItems": 1,
          "type": "array",
          "uniqueItems": true
        }
      },
      "required": [
        "param2"
      ],
      "type": "object"
    }
  }

  const testAppList = [
    {
        "id": "ins1634971791",
        "name": "harbor",
        "version": "2.0.0",
        "status": "未部署",
        "entry": "http://ins1634971791.example.com",
        "created_at": "2021-10-23T06:49:51.498Z",
        "updated_at": "2021-10-23T06:49:51.498Z"
      },
      {
        "id": "ins1634971792",
        "name": "harbor",
        "version": "2.0.0",
        "status": "未部署",
        "entry": "http://ins1634971791.example.com",
        "created_at": "2021-10-23T06:49:51.498Z",
        "updated_at": "2021-10-23T06:49:51.498Z"
      }
]

const Manager = (props) => {
    const uploadRef = useRef(null)
    const [showConfigDialog, setShowConfigDialog] = useState(false)
    const [configData, setConfigData] = useState({})
    const [appList, setAppList] = useState(testAppList)
    const [total, setTotal] = useState(0)
    const [anchorEl, setAnchorEl] = useState()
    const openMenu = Boolean(anchorEl);
    const [showLog, setShowLog] = useState(false)
    const [logTitle, setLogTitle] = useState('日志')
    const [logList, setLogList] = useState([])
    const [page, setPage] = useState(1) // 当前页
    const limit = 8 // 每页多少条
    const [curInstance, setCurInstance ]= useState()
    const [hadDomain, setHadDomain] = useState(-1)
    const [searchTimer, setSearchTimer] = useState(null)
    const [searchName, setSearchName] = useState('')
    const inputRef = useRef(null)

    useEffect(() => {
        getDomain()
        getAppList('', 1)
    }, [])

    const receiveMessage = (e) => {
        if(e.origin === window.location.origin && (e.data === 'createapp')) {
           
            inputRef.current.setValue('')
            setSearchName('')
            setPage(1)
            getAppList('', 1)
        } 
    }

    useEffect(() => {
        window.addEventListener('message', receiveMessage, false)

        return () => {
            window.removeEventListener('message', receiveMessage)
        }
    }, [])

    const getDomain = () => {
        axios({
            method: 'GET',
            url: '/api/cluster/domain'
        }).then((res) => {
            if(res.data.code === 0 && res.data.result !== '') {
                setHadDomain(1)
                // getAppList()
            }else {
                setHadDomain(0)
            }
        }).catch((err) => {
            console.log(err)
            store.dispatch({
                type: TYPE.SNACKBAR,
                val: '请求错误'
            })
        })
    }

    const getAppList = (sname, curPage) => {
        store.dispatch({
            type: TYPE.LOADING,
            val: true
        })

        axios({
            url: '/api/app/list',
            method: 'GET',
            params: {name: sname, offset: (curPage-1)*limit, limit: limit}
        }).then((res) => {
            if(res.data.code === 0) {
                setAppList(res.data.result.rows || [])
                setTotal(res.data.result.total || 0)
            }else {
                store.dispatch({
                    type: TYPE.SNACKBAR,
                    val: res.data.result || ''
                })
            }
            store.dispatch({
                type: TYPE.LOADING,
                val: false
            })
        
        }).catch((err) => {
            console.error(err)
            store.dispatch({
                type: TYPE.SNACKBAR,
                val: '请求错误'
            })
            store.dispatch({
                type: TYPE.LOADING,
                val: false
            })
        })
    }


    const search = (val) => {
        clearTimeout(searchTimer)
        setSearchTimer(setTimeout(() => {
            setPage(1)
            setSearchName(val)
            setSearchTimer(null)
            getAppList(val, 1)
        }, 500))
    }

    const changePage = (event, page) => {
        setPage(page)
        getAppList(searchName, page)
    }

    const upload = () => {
        if(uploadRef) {
            uploadRef.current.click()
        }
    }

    const addApp = () => {
        window.open('/createapp', '_blank')
    }

    // 上传文件
    const uploadFileChange = () => {

        store.dispatch({
            type: TYPE.LOADING,
            val: true
        })

        const file = event.target.files[0]

        let formData = new FormData()
        formData.append('file', file)

        axios({
            url: '/api/app/upload',
            method: 'POST',
            data: formData,
            headers: {'Content-Type': 'multipart/form-data'}
        }).then((res) => {
            if(res.data.code === 0) {
                setShowConfigDialog(true)
                setConfigData(res.data.result)
            }else {
                store.dispatch({
                    type: TYPE.SNACKBAR,
                    val: res.data.result || ''
                })
            }
            store.dispatch({
                type: TYPE.LOADING,
                val: false
            })
            uploadRef.current.value = ''
        }).catch((err) => {
            console.error(err)
            store.dispatch({
                type: TYPE.SNACKBAR,
                val: '请求错误'
            })
            store.dispatch({
                type: TYPE.LOADING,
                val: false
            })
            uploadRef.current.value = ''
        })
    }

    // 关闭弹框回调
    const closeDialog = () => {
        setShowConfigDialog(false)
    }

    // 弹框确认按钮回调
    const submitDialog = (data) => {
        if(data.notHadServe.length) {
            // 依赖中存在某些应用没有服务的情况
            store.dispatch({
                type: TYPE.SNACKBAR,
                val: data.notHadServe.join('、') + '以上应用中不存在服务，请创建'
            })
            return 
        }
        if(data.allAppSelectServe.length) {
            // 依赖中存在没有选择服务的应用
            store.dispatch({
                type: TYPE.SNACKBAR,
                val: data.allAppSelectServe.join('、') + '以上应用未选择服务，请选择'
            })
            return
        }

        store.dispatch({
            type: TYPE.LOADING,
            val: true
        })

        let selectData = getAppSelect(data.appInfo)

        selectData['status'] = 1

        axios({
            method: "POST",
            url: `/api/app/run`,
            headers: {'Content-Type': 'application/json'},
            data: selectData
        }).then((res) => {
            if(res.data.code === 0) {
                inputRef.current.setValue('')
                setSearchName('')
                setPage(1)
                getAppList('', 1)
                closeDialog()
            }

            store.dispatch({
                type: TYPE.SNACKBAR,
                val: res.data.result || ''
            })

            store.dispatch({
                type: TYPE.LOADING,
                val: false
            })
            
        }).catch((err) => {
            store.dispatch({
                type: TYPE.SNACKBAR,
                val: '请求错误'
            })
            store.dispatch({
                type: TYPE.LOADING,
                val: false
            })
        })

    }

    const getAppSelect = (data) => {
        // 遍历找到所有应用的所有选择的版本
        let selectData = []
        let appConfig = {}
        const configs = (config, attr, obj) => {
            if(config) {
                if(config.type == 'object' && config.properties) {
                    obj[attr] = {}
                    Object.keys(config.properties).forEach((key) => {
                        configs(config.properties[key], key, obj[attr])
                    })
                }else {
                    obj[attr] = config.val
                }
            }
        }

        if(data && data.dependencies ) {
            Object.keys(data.dependencies).forEach((key) => {
                if(data.dependencies[key].location.selected) {
                    selectData.push({
                        "name": key,
                        "location": data.dependencies[key].location.location
                    })

                    
                }else {
                    data.dependencies[key].instances.forEach((item) => {
                        if(item.selected) {
                            selectData.push({
                                "name": item.instance.name,
                                "id": item.instance.id
                            })
                        }
                    })
                }
            })

        }
        if(data.userconfigs) {
            configs(data.userconfigs, 'userconfigs', appConfig)
        }
       
        return {
            id: data.id,
            dependencies: selectData,
            userconfigs: appConfig.userconfigs || null
        }
    }
 
    const closePopover = () => {
        // if(auto) {
        //     this.setState({
        //         currentItem: {}
        //     })
        // }

        setAnchorEl(null)
    }

    const clickMenu = (item) => {
        setCurInstance(item)
        setAnchorEl(event.target)
    }

    // 查看日志
    const readLogs = () => {
        closePopover()

        // 测试数据
        // setShowLog(true)
        // setLogList([
        //     {
        //       "name": "cache",
        //       "message": "春江潮水连海平，海上明月共潮生"
        //     },
        //     {
        //       "name": "nginx",
        //       "message": "滟滟随波千万里，何处春江无月明"
        //     }
        //   ])

        // return 

        store.dispatch({
            type: TYPE.LOADING,
            val: true
        })
        axios({
            url: '/api/app/logs',
            method: 'GET',
            params: {id: curInstance.id}
        }).then((res) => {
            if(res.data.code === 0) {
                setShowLog(true)
                setLogTitle('实例 '+curInstance.name)
                setLogList(res.data.result)
            }else {
                store.dispatch({
                    type: TYPE.SNACKBAR,
                    val: res.data.result || ''
                })
            }
            store.dispatch({
                type: TYPE.LOADING,
                val: false
            })
        }).catch((err) => {
            console.error(err)
            store.dispatch({
                type: TYPE.SNACKBAR,
                val: '请求错误'
            })
            store.dispatch({
                type: TYPE.LOADING,
                val: false
            })
        })

    }

    const goDetailPage = (id, name) => {
        closePopover()
        window.open(`${window.location.origin}/detail/${id}/${name}`,'_blank')
    }  

    const viewApp = () => {
        closePopover()
        window.open(`${window.location.origin}/managerview/${curInstance.id}/${curInstance.name}`,'_blank')
    }
    
    // 部署链接
    const copyLink = () => {
        closePopover()
        copy(window.location.origin + '/api/deployment/'+curInstance.id)
        store.dispatch({
            type: TYPE.SNACKBAR,
            val: '部署链接已复制到剪切板'
        })
    }  

    // 导出配置
    const outputFile = () => {
        closePopover()
        window.open('/api/app/output?id='+curInstance.id)
    }

    // 删除实例
    const deleteInstance = () => {
        closePopover()

        store.dispatch({
            type: TYPE.LOADING,
            val: true
        })

        axios({
            method: "GET",
            url: `/api/delete/instance`,
            params: {id: curInstance.id}
        }).then((res) => {

            store.dispatch({
                type: TYPE.LOADING,
                val: false
            })
            store.dispatch({
                type: TYPE.SNACKBAR,
                val: res.data.result || ''
            })
            
        }).catch((err) => {
            store.dispatch({
                type: TYPE.SNACKBAR,
                val: '请求错误'
            })
            store.dispatch({
                type: TYPE.LOADING,
                val: false
            })
        })
    }

    const closeLog = () => {
        setShowLog(false)
    }

    const moveto = () => {
        props.history.push('/home/domain')
        store.dispatch({
            type: TYPE.CUR_NAV,
            val: '/home/domain'
        })
    }


    
    return (
        <div className="page-container manager-container">
            <div className="page-title">应用管理</div>
           
            {
                hadDomain === 0 ? (
                    <div className="move-to-domain">
                        <p className="move-text">未设置根域，跳转设置页面</p>
                        <Button className="input-btn" variant="contained" color="primary" onClick={moveto}>点击跳转</Button>
                    </div> 
                ) : null
            }
            {
                hadDomain === 1 ? (
                    <React.Fragment>
                    <div className="addapp-content">
                        <div className="upload-content">
                            <Button className="input-btn" variant="contained" color="primary" onClick={upload}>上传应用</Button>
                            <input className="upload-file" type="file" ref={uploadRef} onChange={uploadFileChange}/>
                        </div>
                        <Button className="input-btn addapp-btn" variant="contained" color="primary" onClick={addApp}>添加应用</Button>
                        <div className='mg-search'>
                            <Input ref={inputRef} placeholder="搜索应用" icon="icon_baseline_search" change={search}/>
                        </div>
                        
                    </div>
                   <div className="instance-list">
                        <table className="table">
                            <thead>
                                <tr>
                                    <th width="11%">实例名称</th>
                                    <th width="15%">所属应用</th>
                                    <th width="5%">版本</th>
                                    <th width="34%">访问链接</th>
                                    {/* <th width="10%">状态</th> */}
                                    <th width="15%">创建时间</th>
                                    <th width="15%">更新时间</th>
                                    <th width="5%">操作</th>
                                </tr>
                            </thead>
                            <tbody style={{position: 'relative'}}>
                            {
                                appList.map((item, index) => {
                                    return (    
                                        <tr key={item.id}>
                                            <td className='cursorPointer' onClick={() => {goDetailPage(item.id, item.name)}}>
                                                <div className="app-td">
                                                    {item.id}
                                                </div>
                                            </td>
                                            <td title={item.name}>{item.name}</td>
                                            <td>{item.version}</td>
                                            <td title={item.entry} className="list-entry"><a href={item.entry} target="_blank">{item.entry}</a></td>
                                            {/* <td>{item.status}</td> */}
                                            <td>{moment(item.created_at).format('YYYY-MM-DD hh:mm:ss')}</td>
                                            <td>{moment(item.updated_at).format('YYYY-MM-DD hh:mm:ss')}</td>
                                            <td data-item={item} onClick={() => {clickMenu(item)}}><i className="iconfont icon_navigation_more" style={{cursor: "pointer"}}></i></td>
                                        </tr>
                                    )
                                })
                            }
                            {/* {
                                    showTipPop ? (
                                        <div
                                            className="showTablePop"
                                            style={{
                                                left: tableTipEl.x + 10 + 'px',
                                                top: tableTipEl.y - 20 + 'px',
                                            }}
                                        >
                                        {tableTipDesc}
                                        </div>
                                    ) : null
                                } */}
                            </tbody>
                        </table>
        
                        <div className="pagination-content">
                            <Pagination 
                                count={Math.ceil(total/limit)} 
                                page={page} 
                                shape="rounded" 
                                onChange={changePage} />
                        </div>
                    
                    </div>
                    </React.Fragment>
                ) : null
            }

            <Popover
                open={openMenu}
                anchorEl={anchorEl}
                anchorOrigin={{horizontal: 'left', vertical: 'bottom'}}
                transformOrigin={{horizontal: 'right', vertical: 'top'}}
                onClose={closePopover}
            >
                <MenuList>
                    {/* <MenuItem key='1' style={{minHeight: '40px', lineHeight: '40px'}} onClick={readLogs}>
                        <div className="staticPopoverMenu"><i className="iconfont icon_view"></i>  查看日志</div>
                    </MenuItem>
                    <MenuItem key='2' style={{minHeight: '40px', lineHeight: '40px'}} onClick={outputFile}>
                        <div className="staticPopoverMenu"><i className="iconfont icon_daochu"></i>  导出配置</div>
                    </MenuItem>
                    <MenuItem key='3' style={{minHeight: '40px', lineHeight: '40px'}} onClick={deleteInstance}>
                        <div className="staticPopoverMenu"><i className="iconfont icon_baseline_delete"></i>  删除</div>
                    </MenuItem> */}

                    {/* <MenuItem key='1' style={{minHeight: '40px', lineHeight: '40px'}} onClick={goDetailPage}>
                        <div className="staticPopoverMenu"><i className="iconfont icon_view"></i>  部署详情</div>
                    </MenuItem> */}

                    <MenuItem key='11' style={{minHeight: '40px', lineHeight: '40px'}} onClick={viewApp}>
                        <div className="staticPopoverMenu"><i className="iconfont icon_view"></i>  查看应用描述文件</div>
                    </MenuItem>
                    <MenuItem key='2' style={{minHeight: '40px', lineHeight: '40px'}} onClick={copyLink}>
                        <div className="staticPopoverMenu" ><i className="iconfont icon_baseline_copy"></i>  部署链接</div>
                    </MenuItem>
                    <MenuItem key='3' style={{minHeight: '40px', lineHeight: '40px'}} onClick={outputFile}>
                        <div className="staticPopoverMenu"><i className="iconfont icon_daochu"></i>  导出K8S描述文件</div>
                    </MenuItem>
                    <MenuItem key='4' style={{minHeight: '40px', lineHeight: '40px'}} onClick={deleteInstance}>
                        <div className="staticPopoverMenu"><i className="iconfont icon_baseline_delete"></i>  删除</div>
                    </MenuItem>
                </MenuList>
            </Popover>

            <AddFile open={showConfigDialog} title="配置实例" data={configData} close={closeDialog} submit={submitDialog}/>
            <ReadLog open={showLog} title={logTitle} data={logList} close={closeLog} />
        
        </div>
    )
}

function mapPropsToState(state) {
    return state
}

export default connect(mapPropsToState)(withRouter(Manager))