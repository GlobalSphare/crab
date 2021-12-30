import React, { useState, useEffect, useRef } from 'react'
import { connect } from 'react-redux'
import Button from '@material-ui/core/Button'
import '../../style/sass/online.scss'
import axios from 'axios'
import store from '../../store/store'
import * as TYPE from '../../store/actions'
import Loading from '../../components/Loading'
import SnackbarCmp from '../../components/Snackbar'
import AutoTextarea from '../../components/AutoTextarea'

const defaultMetadata = `apiVersion: aam.globalsphare.com/v1alpha1
kind: WorkloadType
metadata:
    name: example
spec:
    parameter: |
        image: *"example" | string`


const WorkloadType = (props) => {
    const autoTxRef = useRef(null)
    const [name, setName] = useState('')
    const [workloadInfo, setWorkloatTypeInfo] = useState(null)

    const [btnDisable, setBtnDisable] = useState(false)

    const getName = () => {
        let name = ''
        if(window.location.search) {
            const params = window.location.search.substring(1, )
            if(params.indexOf('&')) {
                const kvs =  params.split('&')
            
                for(let i = 0, len = kvs.length; i < len; i++) {
                    const kv = kvs[i].split('=')
                    if(kv && kv[0] === 'name') {
                        name = kv[1]
                        break;
                    }
                }
            }
           
        }

        return name
    }

    useEffect(() => {
        const name = getName()
        if(name) {
            setName(name)
            getWorkloadTypeInfo(name)
        }else {
            autoTxRef.current.setData(defaultMetadata)
        }
    }, [])

    const getWorkloadTypeInfo = (name) => {
        store.dispatch({
            type: TYPE.LOADING,
            val: true
        })
        axios({
            method: 'GET',
            url: '/api/online/getworkloadtype',
            params: {name}
        }).then(res => {
           
            if(res.data.code == 0) {
                setWorkloatTypeInfo(res.data.result || {})
                autoTxRef.current.setData(res.data.result.value || '')

            }else {
                store.dispatch({
                    type: TYPE.SNACKBAR,
                    val: res.data.result
                })
            }
           
        }).catch(err => {
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


    const editWorkloadType = () => {
        store.dispatch({
            type: TYPE.LOADING,
            val: true
        })

        let url = `/api/cluster/editworkload?id=${workloadInfo.id || ''}`
       

        setBtnDisable(true)
        axios({
            url: url,
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            data: {value: autoTxRef.current.getData()}
        }).then((res) => {
            if(res.data.code == 0) {
                setTimeout(() => {
                    setBtnDisable(false)
                    window.opener.postMessage('workloadtype', window.location.origin)
                    window.close()
                }, 1000)    
              
            }else {
                setBtnDisable(false)
            }
            store.dispatch({
                type: TYPE.SNACKBAR,
                val: res.data.result || ''
            })
        }).catch((err) => {
            console.error(err)
            setBtnDisable(false)
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


    // useEffect(() => {
    //     autoTxRef.current.setData(defaultMetadata)
    // }, [])

    const checkRule = () => {
        const value = autoTxRef.current.getData()
        if(value.trim() === '') {
            store.dispatch({
                type: TYPE.SNACKBAR,
                val: '请输入trait内容'
            })
            return false
        }

        return true
    }

    const save = () => {
        if(!(checkRule())) { return }

        store.dispatch({
            type: TYPE.LOADING,
            val: true
        })
        setBtnDisable(true)
        const value = autoTxRef.current.getData()
        axios({
            method: 'POST',
            url: '/api/online/createworkloadtype',
            data: {value},
            headers: { 'Content-Type': 'application/json'}
        }).then(res => {
            store.dispatch({
                type: TYPE.SNACKBAR,
                val: res.data.result
            })
            if(res.data.code == 0) {
                setTimeout(() => {
                    setBtnDisable(false)
                    window.opener.postMessage('workloadtype', window.location.origin)
                    window.close()
                }, 1000)
               
            }
        }).catch(err => {
            console.log(err)
            setBtnDisable(false)
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


    return (
        <section className="page-container online-container">
            <header className="online-header">
                <div className="header-logo">Crab</div>
                {/* <div className="header-user">userinfo</div> */}
            </header>
            <div className="online-content">
                <div className="oltitle">创建WorkloadType</div>
                <section className="trait-content">
                    <AutoTextarea ref={autoTxRef} class="trait-textarea" />
                    <div className="online-btns">
                        {
                            name ? (
                                <Button disabled={btnDisable} className="online-btn" variant="contained" color="primary" onClick={editWorkloadType}>修改</Button>
                            ) : (
                                <Button disabled={btnDisable} className="online-btn" variant="contained" color="primary" onClick={save}>保存</Button>
                            )
                        }
                    </div>
                </section>
            </div>
           
            <Loading />
            <SnackbarCmp />
            
        </section>
    )
}

function mapStateToProps(state) {
    return state
}

export default connect(mapStateToProps)(WorkloadType)