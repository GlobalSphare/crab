import React from 'react'
import RouterDOM from './router/router'
import './style/sass/common.scss'
import { createTheme, ThemeProvider  } from '@material-ui/core/styles'
import axios from 'axios'

// 添加请求拦截器
axios.interceptors.request.use(function (config) {
    // 在发送请求之前做些什么
    config.headers['Auth'] = window.sessionStorage.getItem('token') || ''
    return config;
}, function (error) {
    // 对请求错误做些什么
    return Promise.reject(error);
});

// // 添加响应拦截器
// axios.interceptors.response.use(function (response) {
//     // 对响应数据做点什么
//     if(response.data.code === -10) {
//         window.location.href = '/login'
//     }
//     return response;
//   }, function (error) {
//     // 对响应错误做点什么
//     return Promise.reject(error);
// });

const mytheme = createTheme({
    palette: {
        primary: {
            main: '#3986FF'
        },
        secondary: {
            main: '#EC5858'
        }
    }
})

const APP = () => (
    <ThemeProvider theme={mytheme} >
        <div className="root-container">
            <RouterDOM />
        </div>
    </ThemeProvider>
 
)

export default APP