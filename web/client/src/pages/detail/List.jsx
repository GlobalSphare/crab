import React, { useState, useEffect } from 'react'
import { connect } from 'react-redux'
import moment from 'moment'
import store from '../../store/store'
import * as TYPE from '../../store/actions'
import Popover from '@material-ui/core/Popover'
import MenuList from '@material-ui/core/MenuList'
import MenuItem from '@material-ui/core/MenuItem'
import Pagination from '@material-ui/lab/Pagination'
import DetailEdit from './detailEdit'

const defaultList = [
    {
        "id": 1,
        "name": "ingress", 
        "apiVersion": "aam.globalsphare.com/v1alpha1",
        "value": 'sfdfdsfdsf',
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

const List = (props) => {

    const [list, setList] = useState(defaultList)
    const [curService, setCurService] = useState()
    const [anchorEl, setAnchorEl] = useState()
    const openMenu = Boolean(anchorEl);
    const [openDialog, setOpenDialog] = useState(false)
    const [page, setPage] = useState(1)
    const limit = 10
    const [podName, setPodName] = useState('')


    const getData = () => {

        store.dispatch({
            type: TYPE.LOADING,
            val: true
        })

        axios({
            method: "GET",
            url: '/api/app/detail_list',
            params: {id: props.data.name}
        }).then((res) => {
            if(res.data.code === 0) {
                setList(res.data.result)
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

    const changePage = (event, page) => {
        setPage(page)
    }


    useEffect(() => {
        // getData()
        setList(props.data)
    }, [props.data])

    const closePopover = () => {
        setAnchorEl(null)
    }

    const clickMenu = (item) => {
        setCurService(item)
        setAnchorEl(event.target)
        store.dispatch({
            type: TYPE.SET_SERVICE_DETAIL,
            val: item.name
        })
    }


    // 查看弹窗
    const view = () => {
        props.goTail(curService)
    }

    // 编辑弹窗
    const edit = () => {
        setAnchorEl(null)
        setOpenDialog(true)
        setDialogTitle('编辑内容')
    }

    // 删除实例
    const deleteItem = () => {
        setAnchorEl(null)

        return 

        store.dispatch({
            type: TYPE.LOADING,
            val: true
        })

        let url = ''
        if(curClickDialogType === 'trait') {
            url = '/api/cluster/deletetrait'
        }else if(curClickDialogType === 'workload') {
            url = '/api/cluster/deleteworkload'
        }else if(curClickDialogType === 'vendor') {
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
            params: {id: curService.id}
        }).then((res) => {
            if(res.data.code === 0) {
                if(curClickDialogType === 'trait') {
                    getTraitList()
                }else if(curClickDialogType === 'workload') {
                    getWorkloadList()
                }else if(curClickDialogType === 'vendor') {
                    getVendorList()
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
    }

    const confirmDialog = (value) => {
      
        closeDialog()
        return 


        store.dispatch({
            type: TYPE.LOADING,
            val: true
        })

        axios({
            url: `/api/cluster/edittrait?id=${curService.id || ''}`,
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            data: {value}
        }).then((res) => {
            if(res.data.code === 0) {
                closeDialog()
                getData()
            }else {
                store.dispatch({
                    type: TYPE.SNACKBAR,
                    val: res.data.result || ''
                })
            }
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

    const changeToDetail = (name) => {
        props.toDesc(name)
    }

    const goLog = (name, ctnName) => {
        props.goLog(name, ctnName)
    }

    const showContainers = (pName) => {
        if(podName === pName) {
            setPodName('')
        }else {
            setPodName(pName)
        }
       
    }
    
    return (
        <div className="detail-list">
            <p className="list-title">{props.data.name || ''}</p>
            <div className="list-content">
                <div className='list-table'>
                    <div className='table-head'>
                        <div className='table-tr'>
                            {
                                (list.header || []).map((item) => {
                                    return  <div key={item} className={`table-td ${item === '操作' ? 'small-td' : ''} `}>{item == '操作' ? ' ' : item}</div>
                                })
                            }
                        </div>
                       
                    </div>
                    <div className="table-body">
                        {
                            (list.body || []).map((item, index) => {
                                if(props.curNav === 'pod') {
                                    return (
                                        <div className={`${podName === item[0] ? 'tr-border' : ''}`} key={index}>
                                            <div className="table-tr tr-pod" key={index} onClick={() => {showContainers(item[0])}} >
                                                {
                                                    (item || []).map((el, idx) => {
                                                        if(typeof el !== 'object') {
                                                            if(idx === 0) {
                                                                return <div className='table-td cursorPointer' onClick={() => {changeToDetail(el)}} key={idx}>{el}</div>
                                                            }else if(el === 'log'){
                                                                return <div className='table-td small-td' key={idx}> </div>
                                                            }else {
                                                                return <div className='table-td' key={idx}>{el}</div>
                                                            }
                                                        }
                                                    })
                                                }
                                                
                                            </div>
                                            {
                                                (podName === item[0] &&  Array.isArray(item[item.length-1])) ? (item[item.length-1].map((el, idx) => {
                                                    return <div key={el.name} className='table-tr'>
                                                        <div className='table-td'> </div>
                                                        <div className='table-td'>{el.name}</div>
                                                        <div className='table-td big-td'>{el.image}</div>
                                                        <div className='table-td cursorPointer highlight small-td' key={idx} onClick={() => {goLog(item[0], el.name)}}>查看日志</div>
                                                    </div>
                                                })) : null
                                            }
                                        </div>
                                    )
                                }else {
                                    return (
                                        <div className='table-tr' key={index}>
                                            {
                                                (item || []).map((el, idx) => {
                                                    if(typeof el !== 'object') {
                                                        if(idx === 0) {
                                                            return <div className='table-td cursorPointer' onClick={() => {changeToDetail(el)}} key={idx}>{el}</div>
                                                        }else if(el === 'log'){
                                                            return <div className='table-td cursorPointer highlight small-td' key={idx} onClick={() => {goLog(item[0])}}>查看日志</div>
                                                        }else {
                                                            return <div className='table-td' key={idx}>{el}</div>
                                                        }
                                                    }
                                                    
                                                })
                                            }
                                        </div>
                                    )
                                }
                                
                            
                            })
                        }
                    </div> 
                </div>

                {/* <div className="pagination-content">
                    <Pagination 
                        count={Math.ceil(list.length/limit)} 
                        page={page} 
                        shape="rounded" 
                        onChange={changePage} />
                </div> */}
                
            </div>

            <Popover
                open={openMenu}
                anchorEl={anchorEl}
                anchorOrigin={{horizontal: 'left', vertical: 'bottom'}}
                transformOrigin={{horizontal: 'right', vertical: 'top'}}
                onClose={closePopover}
            >
                <MenuList>
                    <MenuItem key='1' style={{minHeight: '40px', lineHeight: '40px'}} onClick={view}>
                        <div className="staticPopoverMenu"><i className="iconfont icon_view"></i>  查看</div>
                    </MenuItem>
                    <MenuItem key='2' style={{minHeight: '40px', lineHeight: '40px'}} onClick={edit}>
                        <div className="staticPopoverMenu"><i className="iconfont icon_daochu"></i>  编辑</div>
                    </MenuItem>
                    <MenuItem key='3' style={{minHeight: '40px', lineHeight: '40px'}} onClick={deleteItem}>
                        <div className="staticPopoverMenu"><i className="iconfont icon_baseline_delete"></i>  删除</div>
                    </MenuItem>
                </MenuList>
            </Popover>

            <DetailEdit open={openDialog} title={`编辑`} data={curService} close={closeDialog} confirm={confirmDialog} />
        </div>
    )
}

function mapStateToProps (state) {
    return state
} 
export default connect(mapStateToProps)(List)