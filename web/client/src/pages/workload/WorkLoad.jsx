import React, { useState, useEffect, useRef } from 'react'
import Input from '../../components/Input'
import Button from '@material-ui/core/Button'
import Popover from '@material-ui/core/Popover'
import MenuList from '@material-ui/core/MenuList'
import MenuItem from '@material-ui/core/MenuItem'
import Pagination from '@material-ui/lab/Pagination'
import moment from 'moment'
import store from '../../store/store'
import * as TYPE from '../../store/actions'
import axios from 'axios'
import { connect } from 'react-redux'
import '../../style/sass/workload.scss'

import ViewAndEdit from './ViewAndEdit'

const defaultMetadata = `apiVersion: aam.globalsphare.com/v1alpha1
kind: Application
metadata:
  name: example
  version: 0.0.1
  description: 样例应用
  keywords:
    - 样例应用
  author: example@example.com
  maintainers:
    - email: example@example.com
      name: example
      web: https://example.com
  repositories: ["https://github.com/example/example.git"]
  bugs: https://github.com/example/example/issues
  licenses:
    - type: LGPL
      url: https://license.spec.com`
const defaultList = [
    {
        "id": 1,
        "name": "ingress", 
        "apiVersion": "aam.globalsphare.com/v1alpha1",
        "value": defaultMetadata,
        "type": 0, 
        "created_at": "2021-10-23T06:49:51.498Z",
        "updated_at": "2021-10-23T06:49:51.498Z"
      },{
        "id": 2,
        "name": "ingress", 
        "apiVersion": "aam.globalsphare.com/v1alpha1",
        "value": "具体定义",
        "type": 0, 
        "created_at": "2021-10-23T06:49:51.498Z",
        "updated_at": "2021-10-23T06:49:51.498Z"
      },
      {
        "id": 3,
        "name": "ingress", 
        "apiVersion": "aam.globalsphare.com/v1alpha1",
        "value": "具体定义",
        "type": 0, 
        "created_at": "2021-10-23T06:49:51.498Z",
        "updated_at": "2021-10-23T06:49:51.498Z"
      },
]

const WorkLoad = (props) => {
    const [host, setHost] = useState('')
    const [inputErr, setInputErr] = useState('')
    const [traitList, setTraitList] = useState([])
    const [traitPage, setTraitPage] = useState(1)    
    const [traitTotal, setTraitTotal] = useState(0)

    const [workloadList, setWorkloadList] = useState([])
    const [workloadPage, setWorkloadPage] = useState(1)
    const [workloadTotal, setWorkloadTotal] = useState(0)

    const [vendorList, setVendorList] = useState([])
    const [vendorPage, setVendorPage] = useState(1)
    const [vendorTotal, setVendorTotal] = useState(0)

    const limit = 3 // 每页多少条
    const [anchorEl, setAnchorEl] = useState()
    const openMenu = Boolean(anchorEl);
    const [curInstance, setCurInstance ]= useState()
    const [openDialog, setOpenDialog] = useState(false)
    const [dialogTitle, setDialogTitle] = useState('')
    const [dialogType, setDialogType] = useState('')
    const [curClickDialogType, setCurClickDialogType] = useState('')

    const [traitTimer, setTraitTimer] = useState(null)
    const [typeTimer, setTypeTimer] = useState(null)
    const [vendorTimer, setVendorTimer] = useState(null)

    const traitInputRef = useRef(null)
    const typeInputRef = useRef(null)
    const vendorInputRef = useRef(null)

    const [searchTraitValue, setSearchTraitValue] = useState('')
    const [searchTypeValue, setSearchTypeValue] = useState('')
    const [searchVendorValue, setSearchVendorValue] = useState('')

    const receiveMessage = (e) => {
        if(e.origin === window.location.origin && (typeof e.data === 'string')) {
            if(e.data === 'trait') {
                traitInputRef.current.setValue('')
                setTraitPage(1)
                setSearchTraitValue('')
                getTraitList('', 1)

            }else if(e.data === 'workloadtype') {
                typeInputRef.current.setValue('')
                setWorkloadPage(1)
                setSearchTypeValue('')
                getWorkloadList('', 1)
            }else if(e.data === 'workloadvendor') {
                vendorInputRef.current.setValue('')
                setVendorPage(1)
                setSearchVendorValue('')
                getVendorList('', 1)
            }
        } 
    }

    useEffect(() => {
        window.addEventListener('message', receiveMessage, false)

        return () => {
            window.removeEventListener('message', receiveMessage)
        }
    }, [])


    const getTraitList = (name, page) => {
        store.dispatch({
            type: TYPE.LOADING,
            val: true
        })
        axios({
            method: 'GET',
            url: '/api/cluster/traitlist',
            params: {
                name: name, 
                limit,
                offset: (page-1)*limit 
            }
        }).then((res) => {
            if(res.data.code === 0) {
                setTraitTotal(res.data.result.total || 0)
                setTraitList(res.data.result.rows || [])
            }else {
                store.dispatch({
                    type: TYPE.SNACKBAR,
                    val: res.data.result || ''
                })
            }
        }).catch((err) => {
            console.log(err)
           
        }).finally(() => {
            store.dispatch({
                type: TYPE.LOADING,
                val: false
            })
        })
    }
    const getWorkloadList = (name, page) => {
        store.dispatch({
            type: TYPE.LOADING,
            val: true
        })
        axios({
            method: 'GET',
            url: '/api/cluster/workloadlist',
            params: {
                name: name,
                limit,
                offset: (page-1)*limit
            }
        }).then((res) => {
            if(res.data.code === 0) {
                setWorkloadTotal(res.data.result.total || 0)
                setWorkloadList(res.data.result.rows || [])
            }else {
                store.dispatch({
                    type: TYPE.SNACKBAR,
                    val: res.data.result || ''
                })
            }
        }).catch((err) => {
            console.log(err)
           
        }).finally(() => {
            store.dispatch({
                type: TYPE.LOADING,
                val: false
            })
        })
    }
    const getVendorList = (name, page) => {
        store.dispatch({
            type: TYPE.LOADING,
            val: true
        })
        axios({
            method: 'GET',
            url: '/api/cluster/vendorlist',
            params: {
                name: name,
                limit,
                offset: (page-1)*limit
            }
        }).then((res) => {
            if(res.data.code === 0) {
                setVendorTotal(res.data.result.total || 0)
                setVendorList(res.data.result.rows || [])
            }else {
                store.dispatch({
                    type: TYPE.SNACKBAR,
                    val: res.data.result || ''
                })
            }
        }).catch((err) => {
            console.log(err)
           
        }).finally(() => {
            store.dispatch({
                type: TYPE.LOADING,
                val: false
            })
        })
    }

    useEffect(() => {
        getClusterMirror()
        getTraitList('', 1)
        getWorkloadList('', 1)
        getVendorList('', 1)

    }, [])

    const searchTrait = (val) => {
        clearTimeout(traitTimer)
        setTraitTimer(setTimeout(() => {
            setTraitPage(1)
            setSearchTraitValue(val)
            setTraitTimer(null)

            getTraitList(val, 1)

        }, 500))
    }
    const searchType = (val) => {
        clearTimeout(typeTimer)
        setTypeTimer(setTimeout(() => {
            setWorkloadPage(1)
            setSearchTypeValue(val)
            setTypeTimer(null)
            getWorkloadList(val, 1)
        }, 500))
    }
    const searchVendor = (val) => {
        clearTimeout(vendorTimer)
        setVendorTimer(setTimeout(() => {
            setVendorPage(1)
            setSearchVendorValue(val)
            setVendorTimer(null)
            getVendorList(val, 1)
        }, 500))
    }


    const getClusterMirror = () => {
        store.dispatch({
            type: TYPE.LOADING,
            val: true
        })

        axios({
            method: 'GET',
            url: '/api/cluster/mirror'
        }).then((res) => {
            if(res.data.code === 0) {
                setHost(res.data.result)
            }else {
                store.dispatch({
                    type: TYPE.SNACKBAR,
                    val: res.data.result
                })
            }
            store.dispatch({
                type: TYPE.LOADING,
                val: false
            })
        }).catch((err) => {
            console.log(err)
            store.dispatch({
                type: TYPE.LOADING,
                val: false
            })
        })
    }

    function changeHost(data) {
        setInputErr('')
        setHost(data)
    }

    function changeOrigin(){
        if(host.trim() == '') {
            setInputErr('请输入')
            return
        }

        store.dispatch({
            type: TYPE.LOADING,
            val: true
        })

        axios({
            method: 'POST',
            url: '/api/cluster/mirror',
            headers: {"Content-Type": "application/json"},
            data: {
                mirror: host
            }
        }).then((res) => {
            store.dispatch({
                type: TYPE.SNACKBAR,
                val: res.data.result || ''
            })
            store.dispatch({
                type: TYPE.LOADING,
                val: false
            })
        }).catch((err) => {
            console.log(err)
            store.dispatch({
                type: TYPE.LOADING,
                val: false
            })
        })
    }

    const changeTraitPage = (event, page) => {
        setTraitPage(page)

        getTraitList(searchTraitValue, page)

    }
    const changeWorkloadPage = (event, page) => {
        setWorkloadPage(page)
        getWorkloadList(searchTypeValue, page)
    }
    const changeVendorPage = (event, page) => {
        setVendorPage(page)
        getVendorList(searchVendorValue, page)
    }
    

    const closePopover = () => {
        setAnchorEl(null)
    }

    const clickMenu = (item, type) => {
        setCurClickDialogType(type)
        setCurInstance(item)
        setAnchorEl(event.target)
    }

    // 查看弹窗
    const view = (type, name) => {
        setAnchorEl(null)
        window.open(`/workloadview/${type}/${name}`, '_blank')
        
        return
        setOpenDialog(true)
        setDialogType('view')
        setDialogTitle('查看内容')
    }

    // 编辑弹窗
    const edit = () => {
        setAnchorEl(null)
        window.open(`/${curClickDialogType}?name=${curInstance.name}`, '_blank')

        return 

        setOpenDialog(true)
        setDialogType('edit')
        setDialogTitle('编辑内容')
    }

    // 删除实例
    const deleteItem = () => {
        setAnchorEl(null)

        store.dispatch({
            type: TYPE.LOADING,
            val: true
        })

        let url = ''
        if(curClickDialogType === 'trait') {
            url = '/api/cluster/deletetrait'
        }else if(curClickDialogType === 'workloadtype') {
            url = '/api/cluster/deleteworkload'
        }else if(curClickDialogType === 'workloadvendor') {
            url = '/api/cluster/deletevendor'
        }else {
            console.error('--程序错误--无法确定当前点击的是哪个列表类型--')
            store.dispatch({
                type: TYPE.LOADING,
                val: false
            })
        }

        axios({
            method: "GET",
            url: url,
            params: {id: curInstance.id}
        }).then((res) => {
            if(res.data.code === 0) {
                if(curClickDialogType === 'trait') {
                    getTraitList(searchTraitValue, traitPage)
                }else if(curClickDialogType === 'workloadtype') {
                    getWorkloadList(searchTypeValue, workloadPage)
                }else if(curClickDialogType === 'workloadvendor') {
                    getVendorList(searchVendorValue, vendorPage)
                }
            }
            store.dispatch({
                type: TYPE.SNACKBAR,
                val: res.data.result || ''
            })
            
        }).catch((err) => {
            console.log(err)
            store.dispatch({
                type: TYPE.SNACKBAR,
                val: '请求错误'
            })
        }).finally(() => {

            store.dispatch({
                type: TYPE.LOADING,
                val: false
            })
        })
    }

    const closeDialog = () => {
        setOpenDialog(false)
        setDialogType('')
        setDialogTitle('')
    }

    const confirmDialog = (value) => {
        // edit value 
        console.log(value)
        store.dispatch({
            type: TYPE.LOADING,
            val: true
        })


        let url = ''
        if(curClickDialogType === 'trait') {
            url = `/api/cluster/edittrait?id=${curInstance.id || ''}`
        }else if(curClickDialogType === 'workloadtype') {
            url = `/api/cluster/editworkload?id=${curInstance.id || ''}`
        }else if(curClickDialogType === 'workloadvendor') {
            url = `/api/cluster/editvendor?id=${curInstance.id || ''}`
        }else {
            console.error('--程序错误--无法确定当前点击的是哪个列表类型--')
            store.dispatch({
                type: TYPE.LOADING,
                val: false
            })
            return
        }

        axios({
            url: url,
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            data: {value}
        }).then((res) => {
            if(res.data.code === 0) {
                closeDialog()

                if(curClickDialogType === 'trait') {
                    getTraitList(searchTraitValue, traitPage)
                }else if(curClickDialogType === 'workloadtype') {
                    getWorkloadList(searchTypeValue, workloadPage)
                }else if(curClickDialogType === 'workloadvendor') {
                    getVendorList(searchVendorValue, vendorPage)
                }
            }
            store.dispatch({
                type: TYPE.SNACKBAR,
                val: res.data.result || ''
            })
        }).catch((err) => {
            console.error(err)
            store.dispatch({
                type: TYPE.SNACKBAR,
                val: '请求错误'
            })
        }).finally(() => {
            store.dispatch({
                type: TYPE.LOADING,
                val: false
            })
        })

    }

    const addTrait = () => {
        window.open('/trait', '_blank')
    }
    const addWorkloadType = () => {
        window.open('/workloadtype', '_blank')
    }
    const addVendor = () => {
        window.open('/workloadvendor', '_blank')
    }

    return (
        <div className="page-container workload-container">
            <div className="page-title">
                <p>工作负载</p>
            </div>

            <div className="workload-content" style={{display: 'none'}}>
                <div className="host-input">
                    <Input change={changeHost} inputErr={inputErr} value={host} />
                </div> 
                <div className="host-btn">
                    <Button variant="contained" color="primary" className="btn-item" onClick={changeOrigin}>保存</Button>
                </div> 
            </div>

            <div className="table-list">
                <div className="table-title">
                    <div className='table-search'>
                        Trait 管理 
                        <div className='workload-search' style={{width: '200px'}}>
                            <Input ref={traitInputRef} placeholder="搜索 Trait" icon="icon_baseline_search" change={searchTrait}/>
                        </div>
                    </div>
                    <Button variant="contained" color="primary" className="btn-item right-btn" onClick={addTrait}>添加</Button>
                </div>
                <div className="instance-list">
                    <table className="table">
                        <thead>
                            <tr>
                                <th width="6%">主键</th>
                                <th width="24%">名称</th>
                                <th width="30%">版本</th>
                                <th width="5%">类型</th>
                                <th width="15%">创建时间</th>
                                <th width="15%">更新时间</th>
                                <th width="5%">操作</th>
                            </tr>
                        </thead>
                        <tbody style={{position: 'relative'}}>
                        {
                            traitList.map((item, index) => {
                                return (    
                                    <tr key={item.id}>
                                        <td >
                                            <div className="app-td">
                                                {item.id}
                                            </div>
                                        </td>
                                        <td title={item.name} className='cursorPointer' onClick={() => {view('trait',item.name || '')}}>{item.name || ''}</td>
                                        <td title={item.apiVersion || ''}>{item.apiVersion || ''}</td>
                                        <td>{item.type ? '自定义' : '系统'}</td>
                                        <td>{moment(item.created_at).format('YYYY-MM-DD hh:mm:ss')}</td>
                                        <td>{moment(item.updated_at).format('YYYY-MM-DD hh:mm:ss')}</td>
                                        <td data-item={item} onClick={() => {clickMenu(item, 'trait')}}><i className="iconfont icon_navigation_more" style={{cursor: "pointer"}}></i></td>
                                    </tr>
                                )
                            })
                        }
                        </tbody>
                    </table>
    
                    <div className="pagination-content">
                        <Pagination 
                            count={Math.ceil(traitTotal/limit)} 
                            page={traitPage} 
                            shape="rounded" 
                            onChange={changeTraitPage} />
                    </div>
                    
                </div>
            </div>

            <div className="table-list">
                <div className="table-title">
                    <div className='table-search'>
                        WorkloadType 管理
                        <div className='workload-search' style={{width: '200px'}}>
                            <Input ref={typeInputRef} placeholder="搜索 WorkloadType" icon="icon_baseline_search" change={searchType}/>
                        </div>
                    </div>
                   
                    <Button variant="contained" color="primary" className="btn-item right-btn" onClick={addWorkloadType}>添加</Button>
                </div>
                <div className="instance-list">
                    <table className="table">
                        <thead>
                            <tr>
                                <th width="6%">主键</th>
                                <th width="24%">名称</th>
                                <th width="30%">版本</th>
                                <th width="5%">类型</th>
                                <th width="15%">创建时间</th>
                                <th width="15%">更新时间</th>
                                <th width="5%">操作</th>
                            </tr>
                        </thead>
                        <tbody style={{position: 'relative'}}>
                        {
                            workloadList.map((item, index) => {
                                return (    
                                    <tr key={item.id}>
                                        <td >
                                            <div className="app-td">
                                                {item.id}
                                            </div>
                                        </td>
                                        <td title={item.name} className='cursorPointer' onClick={() => {view('workloadtype',item.name || '')}}>{item.name || ''}</td>
                                        <td title={item.apiVersion || ''}>{item.apiVersion || ''}</td>
                                        <td>{item.type ? '自定义' : '系统'}</td>
                                        <td>{moment(item.created_at).format('YYYY-MM-DD hh:mm:ss')}</td>
                                        <td>{moment(item.updated_at).format('YYYY-MM-DD hh:mm:ss')}</td>
                                        <td data-item={item} onClick={() => {clickMenu(item, 'workloadtype')}}><i className="iconfont icon_navigation_more" style={{cursor: "pointer"}}></i></td>
                                    </tr>
                                )
                            })
                        }
                        </tbody>
                    </table>
    
                    <div className="pagination-content">
                        <Pagination 
                            count={Math.ceil(workloadTotal/limit)} 
                            page={workloadPage} 
                            shape="rounded" 
                            onChange={changeWorkloadPage} />
                    </div>
                    
                </div>
            </div>

            <div className="table-list">
                <div className="table-title">
                    <div className='table-search'>
                        WorkloadVendor 管理
                        <div className='workload-search' style={{width: '200px'}}>
                            <Input ref={vendorInputRef} placeholder="搜索 WorkloadVendor" icon="icon_baseline_search" change={searchVendor}/>
                        </div>
                    </div>
                    <Button variant="contained" color="primary" className="btn-item right-btn" onClick={addVendor}>添加</Button>
                </div>
                <div className="instance-list">
                    <table className="table">
                        <thead>
                            <tr>
                            <th width="6%">主键</th>
                                <th width="24%">名称</th>
                                <th width="30%">版本</th>
                                <th width="5%">类型</th>
                                <th width="15%">创建时间</th>
                                <th width="15%">更新时间</th>
                                <th width="5%">操作</th>
                            </tr>
                        </thead>
                        <tbody style={{position: 'relative'}}>
                        {
                            vendorList.map((item, index) => {
                                return (    
                                    <tr key={item.id}>
                                        <td >
                                            <div className="app-td">
                                                {item.id}
                                            </div>
                                        </td>
                                        <td title={item.name} className='cursorPointer' onClick={() => {view('workloadvendor',item.name||'')}}>{item.name || ''}</td>
                                        <td title={item.apiVersion || ''}>{item.apiVersion || ''}</td>
                                        <td>{item.type ? '自定义' : '系统'}</td>
                                        <td>{moment(item.created_at).format('YYYY-MM-DD hh:mm:ss')}</td>
                                        <td>{moment(item.updated_at).format('YYYY-MM-DD hh:mm:ss')}</td>
                                        <td data-item={item} onClick={() => {clickMenu(item, 'workloadvendor')}}><i className="iconfont icon_navigation_more" style={{cursor: "pointer"}}></i></td>
                                    </tr>
                                )
                            })
                        }
                        </tbody>
                    </table>
    
                    <div className="pagination-content">
                        <Pagination 
                            count={Math.ceil(vendorTotal/limit)} 
                            page={vendorPage} 
                            shape="rounded" 
                            onChange={changeVendorPage} />
                    </div>
                    
                </div>
            </div>


            <Popover
                open={openMenu}
                anchorEl={anchorEl}
                anchorOrigin={{horizontal: 'left', vertical: 'bottom'}}
                transformOrigin={{horizontal: 'right', vertical: 'top'}}
                onClose={closePopover}
            >
                <MenuList>
                    {/* <MenuItem key='1' style={{minHeight: '40px', lineHeight: '40px'}} onClick={view}>
                        <div className="staticPopoverMenu"><i className="iconfont icon_view"></i>  查看</div>
                    </MenuItem> */}
                    <MenuItem key='2' style={{minHeight: '40px', lineHeight: '40px'}} onClick={edit}>
                        <div className="staticPopoverMenu"><i className="iconfont icon_daochu"></i>  编辑</div>
                    </MenuItem>
                    <MenuItem key='3' style={{minHeight: '40px', lineHeight: '40px'}} onClick={deleteItem}>
                        <div className="staticPopoverMenu"><i className="iconfont icon_baseline_delete"></i>  删除</div>
                    </MenuItem>
                </MenuList>
            </Popover>

            <ViewAndEdit open={openDialog} title={dialogTitle} type={dialogType} data={curInstance} close={closeDialog} confirm={confirmDialog} />

        </div> 
    )

}

function mapPropsToState(state) { return state }

export default connect(mapPropsToState)(WorkLoad)