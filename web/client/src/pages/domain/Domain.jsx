import React, { useState, useEffect, useRef } from 'react'
import { connect } from 'react-redux'
import { withRouter } from 'react-router-dom'
import Button from '@material-ui/core/Button'
import Input from '../../components/Input'
import axios from 'axios'
import * as TYPE from '../../store/actions'
import store from '../../store/store'
import '../../style/sass/domain.scss'

const Domain = (props) => {
    const [domainErr, setDomainErr] = useState('')
    const [address, setAddress] = useState([])
    const [domain, setDomain] = useState('')

    useEffect(() => {
        getDomain()
        // getAddr()
    }, [])

    const getDomain = () => {
        axios({
            method: 'GET',
            url: '/api/cluster/domain'
        }).then((res) => {
            if(res.data.code === 0) {
                setDomain(res.data.result)
                setDomainErr('')
            }
        }).catch((err) => {
            console.log(err)
            store.dispatch({
                type: TYPE.SNACKBAR,
                val: '请求错误'
            })
        })
    }

    function getAddr(){
        store.dispatch({
            type: TYPE.LOADING,
            val: true
        })
        axios({
            method: 'GET',
            url: '/api/cluster/addrs'
        }).then((res) => {
            if(res.data.code === 0) {
                setAddress(res.data.result)
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
            store.dispatch({
                type: TYPE.SNACKBAR,
                val: '请求错误'
            })
        })
    }

    function changeDomain(value) {
        setDomain(value)
        setDomainErr('')
    }

    function save() {

        if(domain.trim() === '') {
            setDomainErr('请输入')
            return
        }

        store.dispatch({
            type: TYPE.LOADING,
            val: true
        })
        axios({
            method: 'POST',
            url: '/api/cluster/domain',
            headers: {'Content-Type': 'application/json'},
            data: {domain}
        }).then((res) => {
            store.dispatch({
                type: TYPE.SNACKBAR,
                val: res.data.result.message || ''
            })
            store.dispatch({
                type: TYPE.LOADING,
                val: false
            })
        }).catch((err) => {
            console.log('---err---', err)
            store.dispatch({
                type: TYPE.LOADING,
                val: false
            })
            store.dispatch({
                type: TYPE.SNACKBAR,
                val: '请求错误'
            })
        })
    }


    return (
        <div className="page-container  domain-container">
            <div className="page-title">根域设置</div>
            {
                false ? (
                    <React.Fragment>
                        <div className="domain-desc">
                            <p className="desc-text">
                                为此集群设置根域，集群会用根域的二级域名来设置应用的访问域名，请先配置域名范解析到
                                下列所列出的IP中一个或多个地址，再点击[检测并保存]按钮
                            </p>
                        </div>
                        
                        <div className="addr-list">
                            {
                                address && Array.isArray(address) ? (address.map((item, index) => {
                                    return (
                                        <ul className="addr-item" key={item.name}>
                                            <li className="item-li">{item.name}</li>
                                            {
                                                item.addrs.map((el, idx) => {
                                                    return <li className="item-li" key={el}>{el}</li>
                                                })
                                            }
                                        </ul>
                                    )
                                })) : null
                            }
                        </div> 
                    </React.Fragment>
                ) : null
            }
            
            <div className="domain-input">
                <Input placeholder="请输入根域" value={domain} change={changeDomain} inputErr={domainErr} />
                <Button className="input-btn" variant="contained" color="primary" onClick={save}>保存</Button>
            </div>
        </div>
    )



}

function mapPropsToState(state) {
    return state
}

export default connect(mapPropsToState)(withRouter(Domain))